package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// PublicJWK represents an RFC 7517 public JSON Web Key (never containing private parameters).
type PublicJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

type ecdsaDERSig struct {
	R, S *big.Int
}

// PublicJWKFromKey converts an *ecdsa.PublicKey (P-256) or *rsa.PublicKey into an RFC 7517 PublicJWK
// and returns the corresponding JWS "alg" identifier ("ES256" or "RS256").
func PublicJWKFromKey(pub crypto.PublicKey) (PublicJWK, string, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return PublicJWK{}, "", fmt.Errorf("jws: unsupported ECDSA curve %q (only P-256 / ES256 is supported)", k.Curve.Params().Name)
		}
		byteLen := (k.Curve.Params().BitSize + 7) / 8 // 32 bytes for P-256
		xBytes := k.X.FillBytes(make([]byte, byteLen))
		yBytes := k.Y.FillBytes(make([]byte, byteLen))
		return PublicJWK{
			Kty: "EC",
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(xBytes),
			Y:   base64.RawURLEncoding.EncodeToString(yBytes),
		}, "ES256", nil

	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return PublicJWK{}, "", fmt.Errorf("jws: RSA key size %d bits is below minimum 2048 bits", k.N.BitLen())
		}
		eBytes := big.NewInt(int64(k.E)).Bytes()
		return PublicJWK{
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(eBytes),
		}, "RS256", nil

	default:
		return PublicJWK{}, "", fmt.Errorf("jws: unsupported public key type %T", pub)
	}
}

// ThumbprintSHA256 computes the RFC 7638 JWK SHA-256 Thumbprint (base64url without padding),
// used for DPoP key confirmation ("jkt" / "dpop_jkt") and non-sensitive audit logging.
func (j PublicJWK) ThumbprintSHA256() (string, error) {
	var canonical []byte
	var err error
	switch j.Kty {
	case "EC":
		// RFC 7638 Section 3.2: lexicographical order of required members {"crv","kty","x","y"}
		type canonicalEC struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}
		canonical, err = json.Marshal(canonicalEC{Crv: j.Crv, Kty: j.Kty, X: j.X, Y: j.Y})
	case "RSA":
		// RFC 7638 Section 3.2: lexicographical order of required members {"e","kty","n"}
		type canonicalRSA struct {
			E   string `json:"e"`
			Kty string `json:"kty"`
			N   string `json:"n"`
		}
		canonical, err = json.Marshal(canonicalRSA{E: j.E, Kty: j.Kty, N: j.N})
	default:
		return "", fmt.Errorf("jws: cannot compute thumbprint for kty %q", j.Kty)
	}
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// SignJWT serializes header and claims as JSON, signs the compact JWS signing input
// using the hardware-backed crypto.Signer (supporting ES256 and RS256), and returns the compact JWT.
func SignJWT(signer crypto.Signer, header map[string]any, claims any) (string, error) {
	if signer == nil {
		return "", errors.New("jws: nil crypto.Signer")
	}
	_, alg, err := PublicJWKFromKey(signer.Public())
	if err != nil {
		return "", err
	}

	hdrCopy := make(map[string]any, len(header)+1)
	for k, v := range header {
		hdrCopy[k] = v
	}
	hdrCopy["alg"] = alg

	hdrJSON, err := json.Marshal(hdrCopy)
	if err != nil {
		return "", fmt.Errorf("jws: marshal header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("jws: marshal claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(hdrJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))

	rawSig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("jws: hardware signer failed: %w", err)
	}

	jwsSig, err := normalizeSignatureForJWS(alg, rawSig)
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(jwsSig), nil
}

// VerifyCompactJWT verifies an ES256 or RS256 compact JWT against pub and returns raw header and payload JSON.
func VerifyCompactJWT(token string, pub crypto.PublicKey) ([]byte, []byte, error) {
	parts := splitThree(token)
	if parts == nil {
		return nil, nil, errors.New("jws: malformed compact JWT")
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("jws: decode header: %w", err)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("jws: decode payload: %w", err)
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, fmt.Errorf("jws: decode signature: %w", err)
	}

	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))

	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if len(sigBytes) != 64 {
			return nil, nil, fmt.Errorf("jws: invalid ES256 signature length %d (expected 64)", len(sigBytes))
		}
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:])
		if !ecdsa.Verify(k, digest[:], r, s) {
			return nil, nil, errors.New("jws: ES256 signature verification failed")
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sigBytes); err != nil {
			return nil, nil, fmt.Errorf("jws: RS256 signature verification failed: %w", err)
		}
	default:
		return nil, nil, fmt.Errorf("jws: unsupported verification public key %T", pub)
	}
	return hdrBytes, payloadBytes, nil
}

// normalizeSignatureForJWS converts Go crypto.Signer output (ASN.1 DER for ECDSA)
// into RFC 7515 Section 3.4 fixed-width R || S format (64 bytes for ES256).
func normalizeSignatureForJWS(alg string, sig []byte) ([]byte, error) {
	if alg == "RS256" {
		return sig, nil
	}
	if alg != "ES256" {
		return nil, fmt.Errorf("jws: unsupported alg %q", alg)
	}
	var parsed ecdsaDERSig
	rest, err := asn1.Unmarshal(sig, &parsed)
	if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil {
		return nil, errors.New("jws: invalid ASN.1 DER ECDSA signature from crypto.Signer")
	}
	if parsed.R.BitLen() > 256 || parsed.S.BitLen() > 256 {
		return nil, errors.New("jws: ECDSA R/S component exceeds P-256 field size")
	}
	out := make([]byte, 64)
	parsed.R.FillBytes(out[:32])
	parsed.S.FillBytes(out[32:])
	return out, nil
}

// RawECDSAToASN1DER converts raw fixed-width R || S ECDSA signature bytes (e.g., returned by
// Windows CNG or PKCS#11) into standard Go crypto.Signer ASN.1 DER format.
func RawECDSAToASN1DER(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw)%2 != 0 {
		return nil, fmt.Errorf("jws: invalid raw ECDSA signature length %d", len(raw))
	}
	half := len(raw) / 2
	r := new(big.Int).SetBytes(raw[:half])
	s := new(big.Int).SetBytes(raw[half:])
	return asn1.Marshal(ecdsaDERSig{R: r, S: s})
}

func splitThree(s string) []string {
	i := -1
	j := -1
	for idx := 0; idx < len(s); idx++ {
		if s[idx] == '.' {
			if i == -1 {
				i = idx
			} else if j == -1 {
				j = idx
			} else {
				return nil
			}
		}
	}
	if i <= 0 || j <= i+1 || j >= len(s)-1 {
		return nil
	}
	return []string{s[:i], s[i+1 : j], s[j+1:]}
}
