package keystore

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jay0lee/gcds-in-the-cloud/internal/config"
)

// TPM2Provider implements KeyProvider backed by a hardware TPM 2.0 chip (/dev/tpmrm0 or Windows TBS)
// using Google's go-tpm v0.9+ Direct API. Keys are created with FixedTPM | FixedParent | SensitiveDataOrigin
// so private key material can never leave the TPM boundary.
type TPM2Provider struct {
	mu        sync.Mutex
	tpm       transport.TPMCloser
	handles   map[string]uint32
	certPaths map[string]string
	transient map[string]tpm2.TPMHandle
	signers   map[string]*tpm2Signer
}

type tpm2Signer struct {
	provider *TPM2Provider
	handle   tpm2.TPMHandle
	name     tpm2.TPM2BName
	pub      crypto.PublicKey
	isRSA    bool
}

// NewTPM2Provider opens the OS TPM 2.0 resource manager device.
func NewTPM2Provider(cfg config.TPM2Config) (*TPM2Provider, error) {
	tpm, err := openTPMDevice(cfg.DevicePath)
	if err != nil {
		return nil, fmt.Errorf("keystore/tpm2: open TPM device: %w", err)
	}
	return NewTPM2ProviderFromTransport(tpm, cfg), nil
}

// NewTPM2ProviderFromTransport constructs a TPM2Provider over any transport.TPMCloser
// (enabling deterministic unit testing against an emulated TPM transport).
func NewTPM2ProviderFromTransport(tpm transport.TPMCloser, cfg config.TPM2Config) *TPM2Provider {
	handlesCopy := make(map[string]uint32, len(cfg.Handles))
	for k, v := range cfg.Handles {
		handlesCopy[k] = v
	}
	return &TPM2Provider{
		tpm:       tpm,
		handles:   handlesCopy,
		certPaths: cfg.CertPaths,
		transient: make(map[string]tpm2.TPMHandle),
		signers:   make(map[string]*tpm2Signer),
	}
}

func (p *TPM2Provider) Backend() string { return "tpm2" }

func (p *TPM2Provider) Signer(_ context.Context, keyID string) (crypto.Signer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if s, ok := p.signers[keyID]; ok {
		return s, nil
	}
	rawHandle, ok := p.handles[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s not mapped in tpm2.handles", ErrKeyNotFound, keyID)
	}

	s, err := p.readHandleLocked(tpm2.TPMHandle(rawHandle))
	if err != nil {
		return nil, err
	}
	p.signers[keyID] = s
	return s, nil
}

func (p *TPM2Provider) Certificate(_ context.Context, keyID string) (*x509.Certificate, error) {
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

func (p *TPM2Provider) EnsureKey(_ context.Context, spec KeySpec) (crypto.Signer, KeyMetadata, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if existing, ok := p.signers[spec.KeyID]; ok {
		meta, err := DescribeSigner(spec.KeyID, p.Backend(), true, existing)
		return existing, meta, err
	}
	if rawHandle, ok := p.handles[spec.KeyID]; ok {
		if s, err := p.readHandleLocked(tpm2.TPMHandle(rawHandle)); err == nil {
			p.signers[spec.KeyID] = s
			meta, mErr := DescribeSigner(spec.KeyID, p.Backend(), true, s)
			return s, meta, mErr
		}
	}

	pubTemplate, isRSA, err := buildTPMPublicTemplate(spec)
	if err != nil {
		return nil, KeyMetadata{}, err
	}

	cpResp, err := (tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(pubTemplate),
	}).Execute(p.tpm)
	if err != nil {
		return nil, KeyMetadata{}, fmt.Errorf("keystore/tpm2: TPM2_CreatePrimary failed: %w", err)
	}

	outPub, err := cpResp.OutPublic.Contents()
	if err != nil {
		return nil, KeyMetadata{}, fmt.Errorf("keystore/tpm2: decode OutPublic: %w", err)
	}
	cryptoPub, err := tpm2.Pub(*outPub)
	if err != nil {
		return nil, KeyMetadata{}, fmt.Errorf("keystore/tpm2: convert TPMTPublic: %w", err)
	}

	finalHandle := cpResp.ObjectHandle
	if spec.Persistent {
		if targetPersist, hasPersist := p.handles[spec.KeyID]; hasPersist {
			_, err := (tpm2.EvictControl{
				Auth: tpm2.TPMRHOwner,
				ObjectHandle: &tpm2.NamedHandle{
					Handle: cpResp.ObjectHandle,
					Name:   cpResp.Name,
				},
				PersistentHandle: tpm2.TPMHandle(targetPersist),
			}).Execute(p.tpm)
			_, _ = (tpm2.FlushContext{FlushHandle: cpResp.ObjectHandle}).Execute(p.tpm)
			if err != nil {
				return nil, KeyMetadata{}, fmt.Errorf("keystore/tpm2: TPM2_EvictControl(0x%x): %w", targetPersist, err)
			}
			finalHandle = tpm2.TPMHandle(targetPersist)
		} else {
			p.transient[spec.KeyID] = cpResp.ObjectHandle
		}
	} else {
		p.transient[spec.KeyID] = cpResp.ObjectHandle
	}

	s := &tpm2Signer{
		provider: p,
		handle:   finalHandle,
		name:     cpResp.Name,
		pub:      cryptoPub,
		isRSA:    isRSA,
	}
	p.signers[spec.KeyID] = s
	meta, err := DescribeSigner(spec.KeyID, p.Backend(), true, s)
	if err != nil {
		return nil, KeyMetadata{}, err
	}
	return s, meta, nil
}

func (p *TPM2Provider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, h := range p.transient {
		_, _ = (tpm2.FlushContext{FlushHandle: h}).Execute(p.tpm)
	}
	clear(p.transient)
	clear(p.signers)
	if p.tpm != nil {
		return p.tpm.Close()
	}
	return nil
}

func (p *TPM2Provider) readHandleLocked(h tpm2.TPMHandle) (*tpm2Signer, error) {
	rpResp, err := (tpm2.ReadPublic{ObjectHandle: h}).Execute(p.tpm)
	if err != nil {
		return nil, fmt.Errorf("keystore/tpm2: TPM2_ReadPublic(0x%x): %w", uint32(h), err)
	}
	pubContents, err := rpResp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("keystore/tpm2: parse public contents: %w", err)
	}
	cryptoPub, err := tpm2.Pub(*pubContents)
	if err != nil {
		return nil, fmt.Errorf("keystore/tpm2: convert public key: %w", err)
	}
	return &tpm2Signer{
		provider: p,
		handle:   h,
		name:     rpResp.Name,
		pub:      cryptoPub,
		isRSA:    pubContents.Type == tpm2.TPMAlgRSA,
	}, nil
}

func buildTPMPublicTemplate(spec KeySpec) (tpm2.TPMTPublic, bool, error) {
	objAttrs := tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		SignEncrypt:         true,
	}
	switch spec.Algorithm {
	case AlgES256, "":
		return tpm2.TPMTPublic{
			Type:             tpm2.TPMAlgECC,
			NameAlg:          tpm2.TPMAlgSHA256,
			ObjectAttributes: objAttrs,
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					Scheme: tpm2.TPMTECCScheme{
						Scheme: tpm2.TPMAlgECDSA,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgECDSA,
							&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256},
						),
					},
					CurveID: tpm2.TPMECCNistP256,
				},
			),
		}, false, nil

	case AlgRS256:
		bits := uint16(2048)
		if spec.RSABits >= 2048 {
			bits = uint16(spec.RSABits)
		}
		return tpm2.TPMTPublic{
			Type:             tpm2.TPMAlgRSA,
			NameAlg:          tpm2.TPMAlgSHA256,
			ObjectAttributes: objAttrs,
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					Scheme: tpm2.TPMTRSAScheme{
						Scheme: tpm2.TPMAlgRSASSA,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgRSASSA,
							&tpm2.TPMSSigSchemeRSASSA{HashAlg: tpm2.TPMAlgSHA256},
						),
					},
					KeyBits: tpm2.TPMKeyBits(bits),
				},
			),
		}, true, nil

	default:
		return tpm2.TPMTPublic{}, false, fmt.Errorf("keystore/tpm2: unsupported algorithm %q", spec.Algorithm)
	}
}

func (s *tpm2Signer) Public() crypto.PublicKey {
	return s.pub
}

func (s *tpm2Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != 0 && opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("keystore/tpm2: unsupported hash %v (only SHA-256 is supported)", opts.HashFunc())
	}
	if len(digest) != 32 {
		return nil, fmt.Errorf("keystore/tpm2: invalid SHA-256 digest length %d", len(digest))
	}

	var scheme tpm2.TPMTSigScheme
	if s.isRSA {
		scheme = tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256},
			),
		}
	} else {
		scheme = tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256},
			),
		}
	}

	s.provider.mu.Lock()
	signResp, err := (tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: s.handle,
			Name:   s.name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digest:   tpm2.TPM2BDigest{Buffer: digest},
		InScheme: scheme,
		Validation: tpm2.TPMTTKHashCheck{
			Tag:       tpm2.TPMSTHashCheck,
			Hierarchy: tpm2.TPMRHNull,
		},
	}).Execute(s.provider.tpm)
	s.provider.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("keystore/tpm2: TPM2_Sign failed: %w", err)
	}

	if s.isRSA {
		rsaSig, err := signResp.Signature.Signature.RSASSA()
		if err != nil {
			return nil, fmt.Errorf("keystore/tpm2: extract RSASSA signature: %w", err)
		}
		return rsaSig.Sig.Buffer, nil
	}

	eccSig, err := signResp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("keystore/tpm2: extract ECDSA signature: %w", err)
	}
	if len(eccSig.SignatureR.Buffer) == 0 || len(eccSig.SignatureS.Buffer) == 0 {
		return nil, errors.New("keystore/tpm2: empty ECDSA R/S signature buffer")
	}
	type derSig struct {
		R, S *big.Int
	}
	return asn1.Marshal(derSig{
		R: new(big.Int).SetBytes(eccSig.SignatureR.Buffer),
		S: new(big.Int).SetBytes(eccSig.SignatureS.Buffer),
	})
}
