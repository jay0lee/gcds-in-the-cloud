package ca

import (
	"container/list"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jay0lee/gcds-in-the-cloud/internal/config"
	"github.com/jay0lee/gcds-in-the-cloud/internal/keystore"
)

type cachedLeaf struct {
	host      string
	cert      *tls.Certificate
	expiresAt time.Time
}

// Authority manages a local Root CA whose private signing key resides inside a hardware-backed
// crypto.Signer, dynamically minting short-lived in-memory TLS leaf certificates ONLY for
// allowlisted Google endpoints during HTTP CONNECT interception.
type Authority struct {
	caCert   *x509.Certificate
	caPEM    []byte
	caSigner crypto.Signer
	leafTTL  time.Duration
	maxCache int

	mu    sync.Mutex
	ll    *list.List
	cache map[string]*list.Element
}

// InitOrLoad ensures the Root CA key exists in ks, loads (and public-key-verifies) an existing
// Root CA certificate if cfg.CertPath exists, or mints a new Root CA certificate signed by ks.
// Only the public CA certificate PEM is ever written to disk.
func InitOrLoad(ctx context.Context, cfg config.CAConfig, ks keystore.KeyProvider) (*Authority, error) {
	if ks == nil {
		return nil, errors.New("ca: keystore KeyProvider is required")
	}
	keyID := cfg.KeyID
	if keyID == "" {
		keyID = "go-oauth-proxy-ca-p256"
	}
	caSigner, _, err := ks.EnsureKey(ctx, keystore.KeySpec{
		KeyID:      keyID,
		Algorithm:  keystore.AlgES256,
		Persistent: true,
	})
	if err != nil {
		return nil, fmt.Errorf("ca: ensure hardware CA key %q: %w", keyID, err)
	}

	var caCert *x509.Certificate
	var caPEM []byte

	if cfg.CertPath != "" {
		if raw, readErr := os.ReadFile(cfg.CertPath); readErr == nil {
			certs, parseErr := keystore.ParsePEMCertificates(raw)
			if parseErr != nil {
				return nil, fmt.Errorf("ca: parse existing CA cert %q: %w", cfg.CertPath, parseErr)
			}
			if publicKeysEqual(certs[0].PublicKey, caSigner.Public()) {
				caCert = certs[0]
				caPEM = raw
			}
		}
	}

	if caCert == nil {
		cn := cfg.CommonName
		if cn == "" {
			cn = "go-oauth-proxy Local Root CA"
		}
		serial, err := randomSerial()
		if err != nil {
			return nil, err
		}
		pubDER, err := x509.MarshalPKIXPublicKey(caSigner.Public())
		if err != nil {
			return nil, err
		}
		ski := sha256.Sum256(pubDER)
		now := time.Now()
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject: pkix.Name{
				CommonName:   cn,
				Organization: []string{"go-oauth-proxy Local Security Authority"},
			},
			NotBefore:             now.Add(-10 * time.Minute),
			NotAfter:              now.Add(5 * 365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            0,
			MaxPathLenZero:        true,
			SubjectKeyId:          ski[:20],
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, caSigner.Public(), caSigner)
		if err != nil {
			return nil, fmt.Errorf("ca: sign Root CA certificate with hardware signer: %w", err)
		}
		caCert, err = x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		if cfg.CertPath != "" {
			if err := os.MkdirAll(filepath.Dir(cfg.CertPath), 0o755); err != nil {
				return nil, fmt.Errorf("ca: mkdir for cert_path: %w", err)
			}
			if err := os.WriteFile(cfg.CertPath, caPEM, 0o644); err != nil {
				return nil, fmt.Errorf("ca: write public Root CA cert %q: %w", cfg.CertPath, err)
			}
		}
	}

	leafTTL := cfg.LeafTTL
	if leafTTL <= 0 {
		leafTTL = 24 * time.Hour
	}
	maxCache := cfg.MaxCacheLen
	if maxCache <= 0 {
		maxCache = 256
	}

	return &Authority{
		caCert:   caCert,
		caPEM:    caPEM,
		caSigner: caSigner,
		leafTTL:  leafTTL,
		maxCache: maxCache,
		ll:       list.New(),
		cache:    make(map[string]*list.Element, maxCache),
	}, nil
}

// RootCertificate returns the parsed X.509 Root CA certificate.
func (a *Authority) RootCertificate() *x509.Certificate { return a.caCert }

// RootPEM returns the PEM-encoded public Root CA certificate.
func (a *Authority) RootPEM() []byte { return append([]byte(nil), a.caPEM...) }

// TLSConfigForTunnel returns a TLS 1.3+ server configuration that dynamically serves in-memory
// leaf certificates matching SNI (or defaultHost if SNI is omitted).
func (a *Authority) TLSConfigForTunnel(defaultHost string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = defaultHost
			}
			return a.GetCertificateForHost(name)
		},
	}
}

// GetCertificateForHost returns a cached or freshly minted ephemeral TLS certificate for host.
func (a *Authority) GetCertificateForHost(host string) (*tls.Certificate, error) {
	cleanHost := normalizeCertHost(host)
	if cleanHost == "" {
		return nil, errors.New("ca: empty hostname for leaf certificate")
	}

	now := time.Now()
	a.mu.Lock()
	if elem, ok := a.cache[cleanHost]; ok {
		ent := elem.Value.(*cachedLeaf)
		if now.Add(5 * time.Minute).Before(ent.expiresAt) {
			a.ll.MoveToFront(elem)
			cert := ent.cert
			a.mu.Unlock()
			return cert, nil
		}
		a.ll.Remove(elem)
		delete(a.cache, cleanHost)
	}
	a.mu.Unlock()

	// Mint ephemeral P-256 leaf key strictly in volatile memory; sign cert via hardware Root CA.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generate ephemeral leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	exp := now.Add(a.leafTTL)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: cleanHost,
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              exp,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		AuthorityKeyId:        a.caCert.SubjectKeyId,
	}
	if ip := net.ParseIP(cleanHost); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{cleanHost}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.caCert, &leafKey.PublicKey, a.caSigner)
	if err != nil {
		return nil, fmt.Errorf("ca: sign leaf certificate for %q: %w", cleanHost, err)
	}
	parsedLeaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{der, a.caCert.Raw},
		PrivateKey:  leafKey,
		Leaf:        parsedLeaf,
	}

	a.mu.Lock()
	for a.ll.Len() >= a.maxCache {
		back := a.ll.Back()
		if back == nil {
			break
		}
		ev := a.ll.Remove(back).(*cachedLeaf)
		delete(a.cache, ev.host)
	}
	elem := a.ll.PushFront(&cachedLeaf{
		host:      cleanHost,
		cert:      tlsCert,
		expiresAt: exp,
	})
	a.cache[cleanHost] = elem
	a.mu.Unlock()

	return tlsCert, nil
}

func normalizeCertHost(h string) string {
	if hostOnly, _, err := net.SplitHostPort(h); err == nil {
		h = hostOnly
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface {
		Equal(crypto.PublicKey) bool
	}
	if eq, ok := a.(equaler); ok {
		return eq.Equal(b)
	}
	return false
}
