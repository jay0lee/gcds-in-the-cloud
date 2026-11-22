//go:build !windows

package keystore

import (
	"context"
	"crypto"
	"crypto/x509"

	"github.com/jay0lee/gcds-in-the-cloud/internal/config"
)

type WindowsCNGProvider struct{}

func NewWindowsCNGProvider(_ config.CNGConfig) (*WindowsCNGProvider, error) {
	return nil, ErrUnsupportedPlatform
}

func (p *WindowsCNGProvider) Backend() string                                                { return "windows_cng" }
func (p *WindowsCNGProvider) Signer(_ context.Context, _ string) (crypto.Signer, error)      { return nil, ErrUnsupportedPlatform }
func (p *WindowsCNGProvider) Certificate(_ context.Context, _ string) (*x509.Certificate, error) { return nil, ErrUnsupportedPlatform }
func (p *WindowsCNGProvider) EnsureKey(_ context.Context, _ KeySpec) (crypto.Signer, KeyMetadata, error) {
	return nil, KeyMetadata{}, ErrUnsupportedPlatform
}
func (p *WindowsCNGProvider) Close() error { return nil }
