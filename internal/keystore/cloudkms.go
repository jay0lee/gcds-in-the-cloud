package keystore

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"sync"
	"time"

	"cloud.google.com/go/auth"
	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/jay0lee/gcds-in-the-cloud/internal/config"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// CloudHSMProvider implements KeyProvider backed by Google Cloud KMS / Cloud HSM (FIPS 140-3 Level 3),
// authenticated via keyless Application Default Credentials.
type CloudHSMProvider struct {
	client      *kms.KeyManagementClient
	keyVersions map[string]string
	certPaths   map[string]string

	mu      sync.RWMutex
	signers map[string]*cloudKMSSigner
}

type cloudKMSSigner struct {
	client     *kms.KeyManagementClient
	versionURI string
	pub        crypto.PublicKey
}

func NewCloudHSMProvider(ctx context.Context, cfg config.HSMConfig, creds *auth.Credentials) (*CloudHSMProvider, error) {
	if len(cfg.KeyVersions) == 0 {
		return nil, errors.New("keystore/cloud_hsm: key_versions map must contain at least one KMS CryptoKeyVersion URI")
	}
	var opts []option.ClientOption
	if creds != nil {
		opts = append(opts, option.WithAuthCredentials(creds))
	}
	c, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("keystore/cloud_hsm: init KMS client: %w", err)
	}
	return &CloudHSMProvider{
		client:      c,
		keyVersions: cfg.KeyVersions,
		certPaths:   cfg.CertPaths,
		signers:     make(map[string]*cloudKMSSigner),
	}, nil
}

func (p *CloudHSMProvider) Backend() string { return "cloud_hsm" }

func (p *CloudHSMProvider) Signer(ctx context.Context, keyID string) (crypto.Signer, error) {
	p.mu.RLock()
	if s, ok := p.signers[keyID]; ok {
		p.mu.RUnlock()
		return s, nil
	}
	p.mu.RUnlock()

	versionURI, ok := p.keyVersions[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s not mapped in cloud_hsm.key_versions", ErrKeyNotFound, keyID)
	}

	pubResp, err := p.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: versionURI})
	if err != nil {
		return nil, fmt.Errorf("keystore/cloud_hsm: get public key %q: %w", versionURI, err)
	}
	if pubResp.ProtectionLevel != kmspb.ProtectionLevel_HSM && pubResp.ProtectionLevel != kmspb.ProtectionLevel_HSM_SINGLE_TENANT {
		return nil, fmt.Errorf("keystore/cloud_hsm: key %q protection level is %v (expected HSM)", versionURI, pubResp.ProtectionLevel)
	}
	if int64(crc32.Checksum([]byte(pubResp.Pem), crc32cTable)) != pubResp.PemCrc32C.GetValue() {
		return nil, fmt.Errorf("keystore/cloud_hsm: public key PEM CRC32C mismatch for %q", versionURI)
	}

	block, _ := pem.Decode([]byte(pubResp.Pem))
	if block == nil {
		return nil, fmt.Errorf("keystore/cloud_hsm: invalid public key PEM from %q", versionURI)
	}
	parsedPub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keystore/cloud_hsm: parse PKIX public key: %w", err)
	}

	s := &cloudKMSSigner{
		client:     p.client,
		versionURI: versionURI,
		pub:        parsedPub,
	}
	p.mu.Lock()
	p.signers[keyID] = s
	p.mu.Unlock()
	return s, nil
}

func (p *CloudHSMProvider) Certificate(_ context.Context, keyID string) (*x509.Certificate, error) {
	path, ok := p.certPaths[keyID]
	if !ok || path == "" {
		return nil, fmt.Errorf("%w: no cert_paths entry for %s", ErrKeyNotFound, keyID)
	}
	certs, err := LoadPEMCertificates(path)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

func (p *CloudHSMProvider) EnsureKey(ctx context.Context, spec KeySpec) (crypto.Signer, KeyMetadata, error) {
	s, err := p.Signer(ctx, spec.KeyID)
	if err != nil {
		return nil, KeyMetadata{}, err
	}
	meta, err := DescribeSigner(spec.KeyID, p.Backend(), true, s)
	if err != nil {
		return nil, KeyMetadata{}, err
	}
	return s, meta, nil
}

func (p *CloudHSMProvider) Close() error {
	return p.client.Close()
}

func (s *cloudKMSSigner) Public() crypto.PublicKey {
	return s.pub
}

func (s *cloudKMSSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("keystore/cloud_hsm: unsupported hash %v (only SHA-256 is supported)", opts.HashFunc())
	}
	if len(digest) != 32 {
		return nil, fmt.Errorf("keystore/cloud_hsm: invalid SHA-256 digest length %d", len(digest))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	digestCRC := int64(crc32.Checksum(digest, crc32cTable))
	resp, err := s.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name:         s.versionURI,
		Digest:       &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest}},
		DigestCrc32C: wrapperspb.Int64(digestCRC),
	})
	if err != nil {
		return nil, fmt.Errorf("keystore/cloud_hsm: AsymmetricSign failed: %w", err)
	}
	if !resp.VerifiedDigestCrc32C || resp.Name != s.versionURI {
		return nil, errors.New("keystore/cloud_hsm: KMS response failed server-side digest/name verification")
	}
	if int64(crc32.Checksum(resp.Signature, crc32cTable)) != resp.SignatureCrc32C.GetValue() {
		return nil, errors.New("keystore/cloud_hsm: KMS signature CRC32C integrity check failed")
	}
	return resp.Signature, nil
}
