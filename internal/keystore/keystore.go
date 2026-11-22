package keystore

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"cloud.google.com/go/auth"
	"github.com/jay0lee/gcds-in-the-cloud/internal/config"
	"github.com/jay0lee/gcds-in-the-cloud/internal/jws"
)

// ErrKeyNotFound is returned when a requested key ID does not exist in the keystore.
var ErrKeyNotFound = errors.New("keystore: key not found")

// ErrUnsupportedPlatform is returned when a platform-specific hardware keystore is invoked on another OS.
var ErrUnsupportedPlatform = errors.New("keystore: backend not supported on this operating system/build")

// KeyAlgorithm enumerates asymmetric signing algorithms supported by hardware keystores.
type KeyAlgorithm string

const (
	AlgES256 KeyAlgorithm = "ES256" // NIST P-256 ECDSA with SHA-256
	AlgRS256 KeyAlgorithm = "RS256" // RSA-2048+ PKCS#1 v1.5 with SHA-256
)

// KeySpec specifies parameters when provisioning a new non-exportable key inside a hardware keystore.
type KeySpec struct {
	KeyID      string
	Algorithm  KeyAlgorithm
	RSABits    int // Defaults to 2048 when Algorithm == AlgRS256
	Persistent bool
}

// KeyMetadata describes a non-exportable key managed by a KeyProvider.
type KeyMetadata struct {
	KeyID          string
	Backend        string
	Algorithm      KeyAlgorithm
	ThumbprintJKT  string // RFC 7638 SHA-256 JWK thumbprint
	HardwareBacked bool
}

// KeyProvider provides opaque crypto.Signer handles to hardware-backed keys without ever
// exposing raw private key material outside the security boundary.
type KeyProvider interface {
	Backend() string
	Signer(ctx context.Context, keyID string) (crypto.Signer, error)
	Certificate(ctx context.Context, keyID string) (*x509.Certificate, error)
	EnsureKey(ctx context.Context, spec KeySpec) (crypto.Signer, KeyMetadata, error)
	Close() error
}

// Open initializes the configured hardware KeyProvider.
// kmsCreds is optional and only required when cfg.Backend == "cloud_hsm".
func Open(ctx context.Context, cfg config.KeystoreConfig, kmsCreds *auth.Credentials) (KeyProvider, error) {
	switch cfg.Backend {
	case "secure_enclave":
		return NewSecureEnclaveProvider()
	case "tpm2":
		return NewTPM2Provider(cfg.TPM2)
	case "windows_cng":
		return NewWindowsCNGProvider(cfg.WindowsCNG)
	case "pkcs11":
		return NewPKCS11Provider(cfg.PKCS11)
	case "cloud_hsm":
		return NewCloudHSMProvider(ctx, cfg.CloudHSM, kmsCreds)
	case "ecp":
		return NewECPProvider(cfg.ECP)
	case "ephemeral_memory":
		if !cfg.AllowEphemeralKeys {
			return nil, errors.New("keystore: ephemeral_memory backend is disabled unless allow_ephemeral_keys=true")
		}
		return NewMemoryProvider(), nil
	default:
		return nil, fmt.Errorf("keystore: unknown backend %q", cfg.Backend)
	}
}

// DescribeSigner builds non-sensitive KeyMetadata (including RFC 7638 JWK thumbprint) from a crypto.Signer.
func DescribeSigner(keyID, backend string, hardwareBacked bool, signer crypto.Signer) (KeyMetadata, error) {
	pubJWK, alg, err := jws.PublicJWKFromKey(signer.Public())
	if err != nil {
		return KeyMetadata{}, err
	}
	jkt, err := pubJWK.ThumbprintSHA256()
	if err != nil {
		return KeyMetadata{}, err
	}
	return KeyMetadata{
		KeyID:          keyID,
		Backend:        backend,
		Algorithm:      KeyAlgorithm(alg),
		ThumbprintJKT:  jkt,
		HardwareBacked: hardwareBacked,
	}, nil
}

// LoadPEMCertificates parses one or more X.509 certificates from a PEM file.
func LoadPEMCertificates(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certificate PEM %q: %w", path, err)
	}
	return ParsePEMCertificates(raw)
}

// ParsePEMCertificates parses one or more X.509 certificates from PEM bytes.
func ParsePEMCertificates(raw []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := raw
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse X.509 certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no CERTIFICATE PEM blocks found")
	}
	return certs, nil
}
