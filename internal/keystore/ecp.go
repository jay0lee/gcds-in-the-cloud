package keystore

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	ecpclient "github.com/googleapis/enterprise-certificate-proxy/client"
	"github.com/jay0lee/gcds-in-the-cloud/internal/config"
)

// ECPProvider integrates Google's official Enterprise Certificate Proxy (ECP),
// delegating private key operations to OS-protected hardware keystores (macOS Keychain/Secure Enclave,
// Windows CNG/MY store, Linux PKCS#11) via the EnterpriseCertSigner subprocess.
type ECPProvider struct {
	key  *ecpclient.Key
	leaf *x509.Certificate
}

func NewECPProvider(cfg config.ECPConfig) (*ECPProvider, error) {
	if cfg.ConfigPath == "" {
		return nil, errors.New("keystore/ecp: config_path is required")
	}
	k, err := ecpclient.Cred(cfg.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("keystore/ecp: load enterprise certificate credential: %w", err)
	}
	var leaf *x509.Certificate
	chain := k.CertificateChain()
	if len(chain) > 0 {
		leaf, err = x509.ParseCertificate(chain[0])
		if err != nil {
			_ = k.Close()
			return nil, fmt.Errorf("keystore/ecp: parse leaf certificate: %w", err)
		}
	}
	return &ECPProvider{key: k, leaf: leaf}, nil
}

func (p *ECPProvider) Backend() string { return "ecp" }

func (p *ECPProvider) Signer(_ context.Context, _ string) (crypto.Signer, error) {
	return p.key, nil
}

func (p *ECPProvider) Certificate(_ context.Context, _ string) (*x509.Certificate, error) {
	if p.leaf == nil {
		return nil, ErrKeyNotFound
	}
	return p.leaf, nil
}

// Chain returns the full DER certificate chain exposed by Google Enterprise Certificate Proxy.
func (p *ECPProvider) Chain() [][]byte {
	return p.key.CertificateChain()
}

func (p *ECPProvider) EnsureKey(_ context.Context, spec KeySpec) (crypto.Signer, KeyMetadata, error) {
	meta, err := DescribeSigner(spec.KeyID, p.Backend(), true, p.key)
	if err != nil {
		return nil, KeyMetadata{}, err
	}
	return p.key, meta, nil
}

func (p *ECPProvider) Close() error {
	if p.key != nil {
		return p.key.Close()
	}
	return nil
}
