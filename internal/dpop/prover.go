package dpop

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/jay0lee/gcds-in-the-cloud/internal/jws"
)

// ProofClaims defines the RFC 9449 Section 4.2 DPoP JWT payload claims.
type ProofClaims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	Nonce string `json:"nonce,omitempty"`
	ATH   string `json:"ath,omitempty"`
}

// Prover generates RFC 9449 DPoP proofs signed by a hardware-backed crypto.Signer.
type Prover struct {
	signer  crypto.Signer
	pubJWK  jws.PublicJWK
	jkt     string
	nowFunc func() time.Time
}

func NewProver(signer crypto.Signer) (*Prover, error) {
	if signer == nil {
		return nil, errors.New("dpop: nil crypto.Signer")
	}
	pubJWK, _, err := jws.PublicJWKFromKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("dpop: inspect public key: %w", err)
	}
	jkt, err := pubJWK.ThumbprintSHA256()
	if err != nil {
		return nil, fmt.Errorf("dpop: compute RFC 7638 thumbprint: %w", err)
	}
	return &Prover{
		signer:  signer,
		pubJWK:  pubJWK,
		jkt:     jkt,
		nowFunc: time.Now,
	}, nil
}

// ThumbprintJKT returns the RFC 7638 SHA-256 JWK thumbprint (used for dpop_jkt and safe audit logs).
func (p *Prover) ThumbprintJKT() string {
	return p.jkt
}

// PublicJWK returns the RFC 7517 public key structure embedded in DPoP proof headers.
func (p *Prover) PublicJWK() jws.PublicJWK {
	return p.pubJWK
}

// MintTokenProof creates a signed dpop+jwt proof for an OAuth 2.0 token endpoint request.
// Per Google's DPoP Adoption Guide:
//   - For grant_type=authorization_code, jti MUST equal BASE64URL(SHA256(authorization_code)).
//   - For grant_type=refresh_token (and other grants), jti is a unique CSPRNG identifier.
func (p *Prover) MintTokenProof(target *url.URL, method, grantType, authCode, nonce string) (string, string, error) {
	htu, err := CanonicalHTU(target)
	if err != nil {
		return "", "", err
	}
	var jti string
	if grantType == "authorization_code" && authCode != "" {
		sum := sha256.Sum256([]byte(authCode))
		jti = base64.RawURLEncoding.EncodeToString(sum[:])
	} else {
		jti, err = randomJTI()
		if err != nil {
			return "", "", err
		}
	}

	claims := ProofClaims{
		JTI:   jti,
		HTM:   strings.ToUpper(method),
		HTU:   htu,
		IAT:   p.nowFunc().Unix(),
		Nonce: nonce,
	}
	header := map[string]any{
		"typ": "dpop+jwt",
		"jwk": p.pubJWK,
	}
	jwtStr, err := jws.SignJWT(p.signer, header, claims)
	if err != nil {
		return "", "", err
	}
	return jwtStr, jti, nil
}

// MintResourceProof creates a signed dpop+jwt proof bound to a specific access token ("ath")
// for downstream RFC 9449 resource server requests.
func (p *Prover) MintResourceProof(target *url.URL, method, accessToken, nonce string) (string, string, error) {
	if accessToken == "" {
		return "", "", errors.New("dpop: empty access token for resource proof")
	}
	htu, err := CanonicalHTU(target)
	if err != nil {
		return "", "", err
	}
	jti, err := randomJTI()
	if err != nil {
		return "", "", err
	}
	atHash := sha256.Sum256([]byte(accessToken))
	claims := ProofClaims{
		JTI:   jti,
		HTM:   strings.ToUpper(method),
		HTU:   htu,
		IAT:   p.nowFunc().Unix(),
		Nonce: nonce,
		ATH:   base64.RawURLEncoding.EncodeToString(atHash[:]),
	}
	header := map[string]any{
		"typ": "dpop+jwt",
		"jwk": p.pubJWK,
	}
	jwtStr, err := jws.SignJWT(p.signer, header, claims)
	if err != nil {
		return "", "", err
	}
	return jwtStr, jti, nil
}

// CanonicalHTU normalizes an HTTP target URI per RFC 9449 Section 4.2 (scheme, host, and path
// without query or fragment components, normalizing default 80/443 ports).
func CanonicalHTU(u *url.URL) (string, error) {
	if u == nil || u.Scheme == "" || u.Host == "" {
		return "", errors.New("dpop: target URL must contain scheme and host")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	if h, port, err := net.SplitHostPort(host); err == nil {
		if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
			host = h
		}
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, nil
}

func randomJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("dpop: read CSPRNG for jti: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
