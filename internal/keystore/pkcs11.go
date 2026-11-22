//go:build cgo

package keystore

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/ThalesGroup/crypto11"
	"github.com/jay0lee/gcds-in-the-cloud/internal/config"
)

// PKCS11Provider implements KeyProvider over PKCS#11 v2.40+ hardware tokens (YubiKey PIV, HSMs, SoftHSM2).
type PKCS11Provider struct {
	ctx       *crypto11.Context
	certPaths map[string]string
}

func NewPKCS11Provider(cfg config.PKCS11Config) (*PKCS11Provider, error) {
	if cfg.ModulePath == "" {
		return nil, errors.New("keystore/pkcs11: module_path is required")
	}
	pin := ""
	if cfg.PinEnv != "" {
		pin = os.Getenv(cfg.PinEnv)
	}
	c11Cfg := &crypto11.Config{
		Path:       cfg.ModulePath,
		TokenLabel: cfg.TokenLabel,
		SlotNumber: cfg.SlotNumber,
		Pin:        pin,
	}
	if pin == "" {
		c11Cfg.LoginNotSupported = true
	}
	c11Ctx, err := crypto11.Configure(c11Cfg)
	if err != nil {
		return nil, fmt.Errorf("keystore/pkcs11: configure token: %w", err)
	}
	return &PKCS11Provider{
		ctx:       c11Ctx,
		certPaths: cfg.CertPaths,
	}, nil
}

func (p *PKCS11Provider) Backend() string { return "pkcs11" }

func (p *PKCS11Provider) Signer(_ context.Context, keyID string) (crypto.Signer, error) {
	s, err := p.ctx.FindKeyPair(nil, []byte(keyID))
	if err != nil {
		return nil, fmt.Errorf("keystore/pkcs11: FindKeyPair(%q): %w", keyID, err)
	}
	if s == nil {
		idHash := sha256.Sum256([]byte(keyID))
		s, err = p.ctx.FindKeyPair(idHash[:16], nil)
		if err != nil {
			return nil, fmt.Errorf("keystore/pkcs11: FindKeyPair by id(%q): %w", keyID, err)
		}
	}
	if s == nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
	}
	return s, nil
}

func (p *PKCS11Provider) Certificate(_ context.Context, keyID string) (*x509.Certificate, error) {
	if path, ok := p.certPaths[keyID]; ok && path != "" {
		certs, err := LoadPEMCertificates(path)
		if err != nil {
			return nil, err
		}
		return certs[0], nil
	}
	cert, err := p.ctx.FindCertificate(nil, []byte(keyID), nil)
	if err != nil {
		return nil, fmt.Errorf("keystore/pkcs11: FindCertificate(%q): %w", keyID, err)
	}
	if cert == nil {
		return nil, fmt.Errorf("%w: certificate for %s", ErrKeyNotFound, keyID)
	}
	return cert, nil
}

func (p *PKCS11Provider) EnsureKey(ctx context.Context, spec KeySpec) (crypto.Signer, KeyMetadata, error) {
	if existing, err := p.Signer(ctx, spec.KeyID); err == nil {
		meta, mErr := DescribeSigner(spec.KeyID, p.Backend(), true, existing)
		return existing, meta, mErr
	}

	idHash := sha256.Sum256([]byte(spec.KeyID))
	var created crypto11.Signer
	var err error
	switch spec.Algorithm {
	case AlgES256, "":
		created, err = p.ctx.GenerateECDSAKeyPairWithLabel(idHash[:16], []byte(spec.KeyID), elliptic.P256())
	case AlgRS256:
		bits := 2048
		if spec.RSABits >= 2048 {
			bits = spec.RSABits
		}
		created, err = p.ctx.GenerateRSAKeyPairWithLabel(idHash[:16], []byte(spec.KeyID), bits)
	default:
		return nil, KeyMetadata{}, fmt.Errorf("keystore/pkcs11: unsupported algorithm %q", spec.Algorithm)
	}
	if err != nil {
		return nil, KeyMetadata{}, fmt.Errorf("keystore/pkcs11: generate keypair %q: %w", spec.KeyID, err)
	}
	meta, err := DescribeSigner(spec.KeyID, p.Backend(), true, created)
	if err != nil {
		return nil, KeyMetadata{}, err
	}
	return created, meta, nil
}

func (p *PKCS11Provider) Close() error {
	if p.ctx != nil {
		return p.ctx.Close()
	}
	return nil
}
