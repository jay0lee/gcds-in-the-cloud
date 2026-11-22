//go:build windows

package keystore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"syscall"
	"unsafe"

	"github.com/jay0lee/gcds-in-the-cloud/internal/config"
	"github.com/jay0lee/gcds-in-the-cloud/internal/jws"
)

var (
	modNCrypt                    = syscall.NewLazyDLL("ncrypt.dll")
	procNCryptOpenStorageProvider = modNCrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptOpenKey             = modNCrypt.NewProc("NCryptOpenKey")
	procNCryptCreatePersistedKey  = modNCrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptFinalizeKey         = modNCrypt.NewProc("NCryptFinalizeKey")
	procNCryptExportKey           = modNCrypt.NewProc("NCryptExportKey")
	procNCryptSignHash            = modNCrypt.NewProc("NCryptSignHash")
	procNCryptSetProperty         = modNCrypt.NewProc("NCryptSetProperty")
	procNCryptFreeObject          = modNCrypt.NewProc("NCryptFreeObject")
)

const (
	ncryptMachineKeyFlag = 0x00000020
	ncryptSilentFlag     = 0x00000040
	bcryptPadPKCS1       = 0x00000002
	bcryptECSP256Magic   = 0x31534345 // "ECS1"
	bcryptRSAPublicMagic = 0x31415352 // "RSA1"
)

type bcryptPKCS1PaddingInfo struct {
	pszAlgId *uint16
}

// WindowsCNGProvider implements KeyProvider backed by Windows Cryptography API: Next Generation (CNG),
// defaulting to "Microsoft Platform Crypto Provider" (hardware TPM 2.0 on Windows Server/GCDS hosts).
type WindowsCNGProvider struct {
	mu           sync.Mutex
	hProvider     uintptr
	providerName string
	machineKey   bool
	certPaths    map[string]string
	signers      map[string]*cngKeySigner
}

type cngKeySigner struct {
	hKey  uintptr
	pub   crypto.PublicKey
	isRSA bool
}

func NewWindowsCNGProvider(cfg config.CNGConfig) (*WindowsCNGProvider, error) {
	provName := cfg.ProviderName
	if provName == "" {
		provName = "Microsoft Platform Crypto Provider"
	}
	provUTF16, err := syscall.UTF16PtrFromString(provName)
	if err != nil {
		return nil, err
	}
	var hProv uintptr
	r0, _, _ := procNCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&hProv)),
		uintptr(unsafe.Pointer(provUTF16)),
		0,
	)
	if r0 != 0 {
		return nil, fmt.Errorf("keystore/windows_cng: NCryptOpenStorageProvider(%q) failed: 0x%x", provName, uint32(r0))
	}
	return &WindowsCNGProvider{
		hProvider:    hProv,
		providerName: provName,
		machineKey:   cfg.MachineKey,
		certPaths:    cfg.CertPaths,
		signers:      make(map[string]*cngKeySigner),
	}, nil
}

func (p *WindowsCNGProvider) Backend() string { return "windows_cng" }

func (p *WindowsCNGProvider) Signer(_ context.Context, keyID string) (crypto.Signer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if s, ok := p.signers[keyID]; ok {
		return s, nil
	}
	s, err := p.openCNGKeyLocked(keyID)
	if err != nil {
		return nil, err
	}
	p.signers[keyID] = s
	return s, nil
}

func (p *WindowsCNGProvider) Certificate(_ context.Context, keyID string) (*x509.Certificate, error) {
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

func (p *WindowsCNGProvider) EnsureKey(_ context.Context, spec KeySpec) (crypto.Signer, KeyMetadata, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if s, ok := p.signers[spec.KeyID]; ok {
		meta, err := DescribeSigner(spec.KeyID, p.Backend(), true, s)
		return s, meta, err
	}
	if existing, err := p.openCNGKeyLocked(spec.KeyID); err == nil {
		p.signers[spec.KeyID] = existing
		meta, mErr := DescribeSigner(spec.KeyID, p.Backend(), true, existing)
		return existing, meta, mErr
	}

	algName := "ECDSA_P256"
	isRSA := false
	if spec.Algorithm == AlgRS256 {
		algName = "RSA"
		isRSA = true
	}
	algUTF16, _ := syscall.UTF16PtrFromString(algName)
	var keyNamePtr *uint16
	if spec.Persistent && spec.KeyID != "" {
		var err error
		keyNamePtr, err = syscall.UTF16PtrFromString(spec.KeyID)
		if err != nil {
			return nil, KeyMetadata{}, err
		}
	}

	flags := uintptr(0)
	if p.machineKey {
		flags |= ncryptMachineKeyFlag
	}
	var hKey uintptr
	r0, _, _ := procNCryptCreatePersistedKey.Call(
		p.hProvider,
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(algUTF16)),
		uintptr(unsafe.Pointer(keyNamePtr)),
		0,
		flags,
	)
	if r0 != 0 {
		return nil, KeyMetadata{}, fmt.Errorf("keystore/windows_cng: NCryptCreatePersistedKey(%q) failed: 0x%x", spec.KeyID, uint32(r0))
	}

	if isRSA {
		bits := uint32(2048)
		if spec.RSABits >= 2048 {
			bits = uint32(spec.RSABits)
		}
		propLen, _ := syscall.UTF16PtrFromString("Length")
		rLen, _, _ := procNCryptSetProperty.Call(
			hKey,
			uintptr(unsafe.Pointer(propLen)),
			uintptr(unsafe.Pointer(&bits)),
			4,
			ncryptSilentFlag,
		)
		if rLen != 0 {
			_, _, _ = procNCryptFreeObject.Call(hKey)
			return nil, KeyMetadata{}, fmt.Errorf("keystore/windows_cng: set RSA Length failed: 0x%x", uint32(rLen))
		}
	}

	rFin, _, _ := procNCryptFinalizeKey.Call(hKey, ncryptSilentFlag)
	if rFin != 0 {
		_, _, _ = procNCryptFreeObject.Call(hKey)
		return nil, KeyMetadata{}, fmt.Errorf("keystore/windows_cng: NCryptFinalizeKey failed: 0x%x", uint32(rFin))
	}

	pub, parsedIsRSA, err := exportCNGPublicKey(hKey)
	if err != nil {
		_, _, _ = procNCryptFreeObject.Call(hKey)
		return nil, KeyMetadata{}, err
	}
	signer := &cngKeySigner{hKey: hKey, pub: pub, isRSA: parsedIsRSA}
	p.signers[spec.KeyID] = signer
	meta, err := DescribeSigner(spec.KeyID, p.Backend(), true, signer)
	if err != nil {
		return nil, KeyMetadata{}, err
	}
	return signer, meta, nil
}

func (p *WindowsCNGProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.signers {
		if s.hKey != 0 {
			_, _, _ = procNCryptFreeObject.Call(s.hKey)
			s.hKey = 0
		}
	}
	clear(p.signers)
	if p.hProvider != 0 {
		_, _, _ = procNCryptFreeObject.Call(p.hProvider)
		p.hProvider = 0
	}
	return nil
}

func (p *WindowsCNGProvider) openCNGKeyLocked(keyID string) (*cngKeySigner, error) {
	nameUTF16, err := syscall.UTF16PtrFromString(keyID)
	if err != nil {
		return nil, err
	}
	flags := uintptr(ncryptSilentFlag)
	if p.machineKey {
		flags |= ncryptMachineKeyFlag
	}
	var hKey uintptr
	r0, _, _ := procNCryptOpenKey.Call(
		p.hProvider,
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(nameUTF16)),
		0,
		flags,
	)
	if r0 != 0 {
		return nil, fmt.Errorf("%w: NCryptOpenKey(%q) status 0x%x", ErrKeyNotFound, keyID, uint32(r0))
	}
	pub, isRSA, err := exportCNGPublicKey(hKey)
	if err != nil {
		_, _, _ = procNCryptFreeObject.Call(hKey)
		return nil, err
	}
	return &cngKeySigner{hKey: hKey, pub: pub, isRSA: isRSA}, nil
}

func exportCNGPublicKey(hKey uintptr) (crypto.PublicKey, bool, error) {
	for _, blobType := range []string{"ECCPUBLICBLOB", "RSAPUBLICBLOB"} {
		btUTF16, _ := syscall.UTF16PtrFromString(blobType)
		var cbResult uint32
		r0, _, _ := procNCryptExportKey.Call(
			hKey, 0, uintptr(unsafe.Pointer(btUTF16)), 0, 0, 0,
			uintptr(unsafe.Pointer(&cbResult)), ncryptSilentFlag,
		)
		if r0 != 0 || cbResult == 0 {
			continue
		}
		buf := make([]byte, cbResult)
		r1, _, _ := procNCryptExportKey.Call(
			hKey, 0, uintptr(unsafe.Pointer(btUTF16)), 0,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(cbResult),
			uintptr(unsafe.Pointer(&cbResult)), ncryptSilentFlag,
		)
		if r1 != 0 {
			continue
		}
		buf = buf[:cbResult]
		if len(buf) >= 8 {
			magic := binary.LittleEndian.Uint32(buf[0:4])
			switch magic {
			case bcryptECSP256Magic:
				cbKey := int(binary.LittleEndian.Uint32(buf[4:8]))
				if len(buf) < 8+2*cbKey {
					return nil, false, errors.New("keystore/windows_cng: truncated BCRYPT_ECCKEY_BLOB")
				}
				x := new(big.Int).SetBytes(buf[8 : 8+cbKey])
				y := new(big.Int).SetBytes(buf[8+cbKey : 8+2*cbKey])
				return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, false, nil
			case bcryptRSAPublicMagic:
				if len(buf) < 24 {
					return nil, false, errors.New("keystore/windows_cng: truncated BCRYPT_RSAKEY_BLOB")
				}
				cbPubExp := int(binary.LittleEndian.Uint32(buf[8:12]))
				cbModulus := int(binary.LittleEndian.Uint32(buf[12:16]))
				if len(buf) < 24+cbPubExp+cbModulus {
					return nil, false, errors.New("keystore/windows_cng: invalid BCRYPT_RSAKEY_BLOB lengths")
				}
				exp := int(new(big.Int).SetBytes(buf[24 : 24+cbPubExp]).Int64())
				mod := new(big.Int).SetBytes(buf[24+cbPubExp : 24+cbPubExp+cbModulus])
				return &rsa.PublicKey{N: mod, E: exp}, true, nil
			}
		}
	}
	return nil, false, errors.New("keystore/windows_cng: unsupported public key blob format")
}

func (s *cngKeySigner) Public() crypto.PublicKey {
	return s.pub
}

func (s *cngKeySigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != 0 && opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("keystore/windows_cng: unsupported hash %v (only SHA-256 is supported)", opts.HashFunc())
	}
	if len(digest) != 32 {
		return nil, fmt.Errorf("keystore/windows_cng: invalid SHA-256 digest length %d", len(digest))
	}

	var padPtr uintptr
	flags := uintptr(ncryptSilentFlag)
	var padInfo bcryptPKCS1PaddingInfo
	if s.isRSA {
		sha256UTF16, _ := syscall.UTF16PtrFromString("SHA256")
		padInfo.pszAlgId = sha256UTF16
		padPtr = uintptr(unsafe.Pointer(&padInfo))
		flags |= bcryptPadPKCS1
	}

	var cbSig uint32
	r0, _, _ := procNCryptSignHash.Call(
		s.hKey, padPtr,
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		0, 0, uintptr(unsafe.Pointer(&cbSig)), flags,
	)
	if r0 != 0 || cbSig == 0 {
		return nil, fmt.Errorf("keystore/windows_cng: NCryptSignHash size query failed: 0x%x", uint32(r0))
	}

	sig := make([]byte, cbSig)
	r1, _, _ := procNCryptSignHash.Call(
		s.hKey, padPtr,
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(cbSig),
		uintptr(unsafe.Pointer(&cbSig)), flags,
	)
	if r1 != 0 {
		return nil, fmt.Errorf("keystore/windows_cng: NCryptSignHash failed: 0x%x", uint32(r1))
	}
	sig = sig[:cbSig]
	if s.isRSA {
		return sig, nil
	}
	// CNG ECDSA outputs concatenated fixed-width R || S; convert to ASN.1 DER per Go crypto.Signer contract.
	return jws.RawECDSAToASN1DER(sig)
}
