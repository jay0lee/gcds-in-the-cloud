//go:build darwin && cgo

package keystore

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>

typedef struct {
    SecKeyRef key;
    int is_se;
    OSStatus status;
} se_key_result_t;

typedef struct {
    unsigned char* data;
    size_t len;
    OSStatus status;
} se_bytes_result_t;

static CFDataRef make_cfdata(const unsigned char* buf, size_t len) {
    return CFDataCreate(kCFAllocatorDefault, buf, (CFIndex)len);
}

static se_key_result_t find_key_by_tag(const unsigned char* tag, size_t tag_len) {
    se_key_result_t res = {NULL, 0, errSecItemNotFound};
    CFDataRef tagData = make_cfdata(tag, tag_len);
    if (!tagData) {
        res.status = errSecAllocate;
        return res;
    }

    // 1. Search Secure Enclave / Data Protection Keychain first
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassKey);
    CFDictionarySetValue(query, kSecAttrApplicationTag, tagData);
    CFDictionarySetValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);

    CFTypeRef item = NULL;
    OSStatus st = SecItemCopyMatching(query, &item);
    CFRelease(query);
    CFRelease(tagData);

    if (st == errSecSuccess && item != NULL) {
        SecKeyRef keyRef = (SecKeyRef)item;
        CFDictionaryRef attrs = SecKeyCopyAttributes(keyRef);
        int isSE = 0;
        if (attrs != NULL) {
            CFTypeRef tokenID = CFDictionaryGetValue(attrs, kSecAttrTokenID);
            if (tokenID != NULL && CFEqual(tokenID, kSecAttrTokenIDSecureEnclave)) {
                isSE = 1;
            }
            CFRelease(attrs);
        }
        res.key = keyRef;
        res.is_se = isSE;
        res.status = errSecSuccess;
        return res;
    }

    res.status = st;
    return res;
}

static se_key_result_t create_non_extractable_key(
    const unsigned char* tag,
    size_t tag_len,
    int is_rsa,
    int rsa_bits,
    int persistent
) {
    se_key_result_t res = {NULL, 0, errSecParam};
    CFDataRef tagData = make_cfdata(tag, tag_len);
    if (!tagData) {
        res.status = errSecAllocate;
        return res;
    }

    // Attempt 1: Hardware Secure Enclave (P-256 only)
    if (!is_rsa) {
        CFErrorRef err = NULL;
        SecAccessControlRef ac = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAccessControlPrivateKeyUsage,
            &err);
        if (ac != NULL) {
            CFMutableDictionaryRef privAttrs = CFDictionaryCreateMutable(
                kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            CFDictionarySetValue(privAttrs, kSecAttrIsPermanent, persistent ? kCFBooleanTrue : kCFBooleanFalse);
            CFDictionarySetValue(privAttrs, kSecAttrApplicationTag, tagData);
            CFDictionarySetValue(privAttrs, kSecAttrAccessControl, ac);

            CFMutableDictionaryRef params = CFDictionaryCreateMutable(
                kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            CFDictionarySetValue(params, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
            int bits = 256;
            CFNumberRef bitsNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits);
            CFDictionarySetValue(params, kSecAttrKeySizeInBits, bitsNum);
            CFDictionarySetValue(params, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
            CFDictionarySetValue(params, kSecPrivateKeyAttrs, privAttrs);

            CFErrorRef createErr = NULL;
            SecKeyRef seKey = SecKeyCreateRandomKey(params, &createErr);

            CFRelease(bitsNum);
            CFRelease(privAttrs);
            CFRelease(params);
            CFRelease(ac);

            if (seKey != NULL) {
                CFRelease(tagData);
                res.key = seKey;
                res.is_se = 1;
                res.status = errSecSuccess;
                return res;
            }
            if (createErr != NULL) {
                OSStatus code = (OSStatus)CFErrorGetCode(createErr);
                CFRelease(createErr);
                // Fall through to non-extractable device Keychain if unsigned CLI lacks SE entitlement (-34018)
                // or running on virtualized Darwin without SEP (-25293 / -50).
                (void)code;
            }
        } else if (err != NULL) {
            CFRelease(err);
        }
    }

    // Attempt 2: Non-extractable device-bound macOS Keychain key (kSecAttrIsExtractable = false)
    CFMutableDictionaryRef privAttrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(privAttrs, kSecAttrIsPermanent, persistent ? kCFBooleanTrue : kCFBooleanFalse);
    CFDictionarySetValue(privAttrs, kSecAttrApplicationTag, tagData);
    CFDictionarySetValue(privAttrs, kSecAttrIsExtractable, kCFBooleanFalse);

    CFMutableDictionaryRef params = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    int bits = is_rsa ? rsa_bits : 256;
    CFNumberRef bitsNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits);
    CFDictionarySetValue(params, kSecAttrKeyType, is_rsa ? kSecAttrKeyTypeRSA : kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(params, kSecAttrKeySizeInBits, bitsNum);
    CFDictionarySetValue(params, kSecAttrIsExtractable, kCFBooleanFalse);
    CFDictionarySetValue(params, kSecPrivateKeyAttrs, privAttrs);

    CFErrorRef kcErr = NULL;
    SecKeyRef kcKey = SecKeyCreateRandomKey(params, &kcErr);

    CFRelease(bitsNum);
    CFRelease(privAttrs);
    CFRelease(params);
    CFRelease(tagData);

    if (kcKey != NULL) {
        res.key = kcKey;
        res.is_se = 0;
        res.status = errSecSuccess;
        return res;
    }
    if (kcErr != NULL) {
        res.status = (OSStatus)CFErrorGetCode(kcErr);
        CFRelease(kcErr);
    }
    return res;
}

static se_bytes_result_t export_public_key_bytes(SecKeyRef privKey) {
    se_bytes_result_t out = {NULL, 0, errSecParam};
    SecKeyRef pubKey = SecKeyCopyPublicKey(privKey);
    if (!pubKey) {
        out.status = errSecInvalidKeyRef;
        return out;
    }
    CFErrorRef err = NULL;
    CFDataRef ext = SecKeyCopyExternalRepresentation(pubKey, &err);
    CFRelease(pubKey);
    if (!ext) {
        if (err) {
            out.status = (OSStatus)CFErrorGetCode(err);
            CFRelease(err);
        }
        return out;
    }
    CFIndex length = CFDataGetLength(ext);
    unsigned char* buf = (unsigned char*)malloc((size_t)length);
    if (!buf) {
        CFRelease(ext);
        out.status = errSecAllocate;
        return out;
    }
    CFDataGetBytes(ext, CFRangeMake(0, length), buf);
    CFRelease(ext);
    out.data = buf;
    out.len = (size_t)length;
    out.status = errSecSuccess;
    return out;
}

static se_bytes_result_t sign_digest_sha256(SecKeyRef privKey, int is_rsa, const unsigned char* digest, size_t digest_len) {
    se_bytes_result_t out = {NULL, 0, errSecParam};
    CFDataRef digestData = make_cfdata(digest, digest_len);
    if (!digestData) {
        out.status = errSecAllocate;
        return out;
    }

    SecKeyAlgorithm alg = is_rsa
        ? kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
        : kSecKeyAlgorithmECDSASignatureDigestX962SHA256;

    if (!SecKeyIsAlgorithmSupported(privKey, kSecKeyOperationTypeSign, alg)) {
        CFRelease(digestData);
        out.status = errSecAlgorithmMismatch;
        return out;
    }

    CFErrorRef err = NULL;
    CFDataRef sig = SecKeyCreateSignature(privKey, alg, digestData, &err);
    CFRelease(digestData);
    if (!sig) {
        if (err) {
            out.status = (OSStatus)CFErrorGetCode(err);
            CFRelease(err);
        }
        return out;
    }

    CFIndex length = CFDataGetLength(sig);
    unsigned char* buf = (unsigned char*)malloc((size_t)length);
    if (!buf) {
        CFRelease(sig);
        out.status = errSecAllocate;
        return out;
    }
    CFDataGetBytes(sig, CFRangeMake(0, length), buf);
    CFRelease(sig);
    out.data = buf;
    out.len = (size_t)length;
    out.status = errSecSuccess;
    return out;
}

static OSStatus delete_key_by_tag(const unsigned char* tag, size_t tag_len) {
    CFDataRef tagData = make_cfdata(tag, tag_len);
    if (!tagData) {
        return errSecAllocate;
    }
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassKey);
    CFDictionarySetValue(query, kSecAttrApplicationTag, tagData);
    OSStatus st = SecItemDelete(query);
    CFRelease(query);
    CFRelease(tagData);
    return st;
}
*/
import "C"

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"unsafe"
)

// SecureEnclaveProvider manages non-exportable keys inside macOS Secure Enclave (P-256)
// and device-bound macOS Keychain via Apple's Security.framework.
type SecureEnclaveProvider struct {
	mu      sync.RWMutex
	signers map[string]*darwinSecKeySigner
	certs   map[string]*x509.Certificate
}

type darwinSecKeySigner struct {
	mu          sync.Mutex
	keyRef      C.SecKeyRef
	pub         crypto.PublicKey
	isRSA       bool
	isHardware  bool
	released    bool
}

func NewSecureEnclaveProvider() (*SecureEnclaveProvider, error) {
	return &SecureEnclaveProvider{
		signers: make(map[string]*darwinSecKeySigner),
		certs:   make(map[string]*x509.Certificate),
	}, nil
}

func (p *SecureEnclaveProvider) Backend() string { return "secure_enclave" }

func (p *SecureEnclaveProvider) Signer(_ context.Context, keyID string) (crypto.Signer, error) {
	p.mu.RLock()
	if s, ok := p.signers[keyID]; ok {
		p.mu.RUnlock()
		return s, nil
	}
	p.mu.RUnlock()

	s, err := lookupDarwinKey(keyID)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.signers[keyID] = s
	p.mu.Unlock()
	return s, nil
}

func (p *SecureEnclaveProvider) Certificate(_ context.Context, keyID string) (*x509.Certificate, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	c, ok := p.certs[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
	}
	return c, nil
}

func (p *SecureEnclaveProvider) EnsureKey(_ context.Context, spec KeySpec) (crypto.Signer, KeyMetadata, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if existing, ok := p.signers[spec.KeyID]; ok {
		meta, err := DescribeSigner(spec.KeyID, p.Backend(), existing.isHardware, existing)
		return existing, meta, err
	}

	if spec.Persistent {
		if found, err := lookupDarwinKey(spec.KeyID); err == nil {
			p.signers[spec.KeyID] = found
			meta, mErr := DescribeSigner(spec.KeyID, p.Backend(), found.isHardware, found)
			return found, meta, mErr
		}
	}

	isRSA := 0
	rsaBits := 2048
	if spec.Algorithm == AlgRS256 {
		isRSA = 1
		if spec.RSABits >= 2048 {
			rsaBits = spec.RSABits
		}
	}
	persistFlag := 0
	if spec.Persistent {
		persistFlag = 1
	}

	tagBytes := []byte(spec.KeyID)
	res := C.create_non_extractable_key(
		(*C.uchar)(unsafe.Pointer(&tagBytes[0])),
		C.size_t(len(tagBytes)),
		C.int(isRSA),
		C.int(rsaBits),
		C.int(persistFlag),
	)
	if res.status != C.errSecSuccess || res.key == 0 {
		return nil, KeyMetadata{}, fmt.Errorf("keystore/secure_enclave: SecKeyCreateRandomKey failed with OSStatus %d", int(res.status))
	}

	signer, err := wrapSecKeyRef(res.key, res.is_se == 1)
	if err != nil {
		C.CFRelease(C.CFTypeRef(res.key))
		return nil, KeyMetadata{}, err
	}
	p.signers[spec.KeyID] = signer
	meta, err := DescribeSigner(spec.KeyID, p.Backend(), signer.isHardware, signer)
	if err != nil {
		return nil, KeyMetadata{}, err
	}
	return signer, meta, nil
}

// DeleteKey removes a persistent key tag from macOS Keychain/Secure Enclave (useful for rotation/tests).
func (p *SecureEnclaveProvider) DeleteKey(keyID string) error {
	p.mu.Lock()
	if s, ok := p.signers[keyID]; ok {
		s.release()
		delete(p.signers, keyID)
	}
	p.mu.Unlock()

	if keyID == "" {
		return nil
	}
	tagBytes := []byte(keyID)
	st := C.delete_key_by_tag((*C.uchar)(unsafe.Pointer(&tagBytes[0])), C.size_t(len(tagBytes)))
	if st != C.errSecSuccess && st != C.errSecItemNotFound {
		return fmt.Errorf("keystore/secure_enclave: SecItemDelete OSStatus %d", int(st))
	}
	return nil
}

func (p *SecureEnclaveProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.signers {
		s.release()
	}
	clear(p.signers)
	return nil
}

func lookupDarwinKey(keyID string) (*darwinSecKeySigner, error) {
	if keyID == "" {
		return nil, ErrKeyNotFound
	}
	tagBytes := []byte(keyID)
	res := C.find_key_by_tag((*C.uchar)(unsafe.Pointer(&tagBytes[0])), C.size_t(len(tagBytes)))
	if res.status == C.errSecItemNotFound || res.key == 0 {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
	}
	if res.status != C.errSecSuccess {
		return nil, fmt.Errorf("keystore/secure_enclave: SecItemCopyMatching OSStatus %d", int(res.status))
	}
	s, err := wrapSecKeyRef(res.key, res.is_se == 1)
	if err != nil {
		C.CFRelease(C.CFTypeRef(res.key))
		return nil, err
	}
	return s, nil
}

func wrapSecKeyRef(ref C.SecKeyRef, isSE bool) (*darwinSecKeySigner, error) {
	pubRes := C.export_public_key_bytes(ref)
	if pubRes.status != C.errSecSuccess || pubRes.data == nil {
		return nil, fmt.Errorf("keystore/secure_enclave: export public key OSStatus %d", int(pubRes.status))
	}
	rawPub := C.GoBytes(unsafe.Pointer(pubRes.data), C.int(pubRes.len))
	C.free(unsafe.Pointer(pubRes.data))

	// SecKeyCopyExternalRepresentation outputs:
	// - ANSI X9.63 uncompressed point (0x04 || X || Y, 65 bytes) for P-256 EC keys
	// - PKCS#1 ASN.1 DER RSAPublicKey for RSA keys
	if len(rawPub) == 65 && rawPub[0] == 0x04 {
		x := new(big.Int).SetBytes(rawPub[1:33])
		y := new(big.Int).SetBytes(rawPub[33:65])
		if !elliptic.P256().IsOnCurve(x, y) {
			return nil, errors.New("keystore/secure_enclave: exported P-256 point is not on curve")
		}
		return &darwinSecKeySigner{
			keyRef:     ref,
			pub:        &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
			isRSA:      false,
			isHardware: isSE,
		}, nil
	}

	rsaPub, err := x509.ParsePKCS1PublicKey(rawPub)
	if err != nil {
		return nil, fmt.Errorf("keystore/secure_enclave: parse exported public key (%d bytes): %w", len(rawPub), err)
	}
	return &darwinSecKeySigner{
		keyRef:     ref,
		pub:        rsaPub,
		isRSA:      true,
		isHardware: isSE,
	}, nil
}

func (s *darwinSecKeySigner) Public() crypto.PublicKey {
	return s.pub
}

func (s *darwinSecKeySigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != 0 && opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("keystore/secure_enclave: unsupported hash %v (only SHA-256 is supported)", opts.HashFunc())
	}
	if len(digest) != 32 {
		return nil, fmt.Errorf("keystore/secure_enclave: invalid SHA-256 digest length %d", len(digest))
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released {
		return nil, errors.New("keystore/secure_enclave: signer already closed")
	}

	isRSA := C.int(0)
	if s.isRSA {
		isRSA = 1
	}
	sigRes := C.sign_digest_sha256(
		s.keyRef,
		isRSA,
		(*C.uchar)(unsafe.Pointer(&digest[0])),
		C.size_t(len(digest)),
	)
	if sigRes.status != C.errSecSuccess || sigRes.data == nil {
		return nil, fmt.Errorf("keystore/secure_enclave: SecKeyCreateSignature failed with OSStatus %d", int(sigRes.status))
	}
	sig := C.GoBytes(unsafe.Pointer(sigRes.data), C.int(sigRes.len))
	C.free(unsafe.Pointer(sigRes.data))
	return sig, nil
}

func (s *darwinSecKeySigner) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.released && s.keyRef != 0 {
		C.CFRelease(C.CFTypeRef(s.keyRef))
		s.keyRef = 0
		s.released = true
	}
}
