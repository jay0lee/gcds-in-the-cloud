package keystore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"sync"
)

// opaqueSigner wraps an in-memory crypto.Signer so callers cannot type-assert it back to
// *ecdsa.PrivateKey or *rsa.PrivateKey, mirroring hardware boundary semantics in tests.
type opaqueSigner struct {
	inner crypto.Signer
}

func (s *opaqueSigner) Public() crypto.PublicKey {
	return s.inner.Public()
}

func (s *opaqueSigner) Sign(randReader io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.inner.Sign(randReader, digest, opts)
}

// MemoryProvider is a volatile, non-exportable-interface keystore strictly for testing/dev when explicitly gated.
type MemoryProvider struct {
	mu      sync.RWMutex
	signers map[string]*opaqueSigner
	certs   map[string]*x509.Certificate
}

func NewMemoryProvider() *MemoryProvider {
	return &MemoryProvider{
		signers: make(map[string]*opaqueSigner),
		certs:   make(map[string]*x509.Certificate),
	}
}

func (m *MemoryProvider) Backend() string { return "ephemeral_memory" }

func (m *MemoryProvider) Signer(_ context.Context, keyID string) (crypto.Signer, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.signers[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
	}
	return s, nil
}

func (m *MemoryProvider) Certificate(_ context.Context, keyID string) (*x509.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.certs[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: certificate for %s", ErrKeyNotFound, keyID)
	}
	return c, nil
}

// SetCertificate associates a public certificate with keyID in the ephemeral store (used in tests/CA init).
func (m *MemoryProvider) SetCertificate(keyID string, cert *x509.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certs[keyID] = cert
}

func (m *MemoryProvider) EnsureKey(_ context.Context, spec KeySpec) (crypto.Signer, KeyMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.signers[spec.KeyID]; ok {
		meta, err := DescribeSigner(spec.KeyID, m.Backend(), false, existing)
		return existing, meta, err
	}

	var rawSigner crypto.Signer
	switch spec.Algorithm {
	case AlgES256, "":
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, KeyMetadata{}, fmt.Errorf("generate P-256 key: %w", err)
		}
		rawSigner = priv
	case AlgRS256:
		bits := spec.RSABits
		if bits == 0 {
			bits = 2048
		}
		if bits < 2048 {
			return nil, KeyMetadata{}, fmt.Errorf("RSA bits %d < 2048", bits)
		}
		priv, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, KeyMetadata{}, fmt.Errorf("generate RSA-%d key: %w", bits, err)
		}
		rawSigner = priv
	default:
		return nil, KeyMetadata{}, fmt.Errorf("unsupported algorithm %q", spec.Algorithm)
	}

	wrapped := &opaqueSigner{inner: rawSigner}
	m.signers[spec.KeyID] = wrapped
	meta, err := DescribeSigner(spec.KeyID, m.Backend(), false, wrapped)
	if err != nil {
		return nil, KeyMetadata{}, err
	}
	return wrapped, meta, nil
}

func (m *MemoryProvider) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	clear(m.signers)
	clear(m.certs)
	return nil
}
