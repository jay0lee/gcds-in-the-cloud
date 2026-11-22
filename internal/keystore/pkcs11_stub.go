//go:build !cgo

package keystore

import (
	"context"
	"crypto"
	"crypto/x509"

	"github.com/jay0lee/gcds-in-the-cloud/internal/config"
)

type PKCS11Provider struct{}

func NewPKCS11Provider(_ config.PKCS11Config) (*PKCS11Provider, error) {
	return nil, ErrUnsupportedPlatform
}

func (p *PKCS11Provider) Backend() string                                                { return "pkcs11" }
func (p *PKCS11Provider) Signer(_ context.Context, _ string) (crypto.Signer, error)      { return nil, ErrUnsupportedPlatform }
func (p *PKCS11Provider) Certificate(_ context.Context, _ string) (*x509.Certificate, error) { return nil, ErrUnsupportedPlatform }
func (p *PKCS11Provider) EnsureKey(_ context.Context, _ KeySpec) (crypto.Signer, KeyMetadata, error) {
	return nil, KeyMetadata{}, ErrUnsupportedPlatform
}
func (p *PKCS11Provider) Close() error { return nil }
