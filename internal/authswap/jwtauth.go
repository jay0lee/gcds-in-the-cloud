package authswap

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jay0lee/gcds-in-the-cloud/internal/adc"
	"github.com/jay0lee/gcds-in-the-cloud/internal/config"
	"github.com/jay0lee/gcds-in-the-cloud/internal/jws"
	"golang.org/x/sync/singleflight"
)

const (
	jwtLifetime     = 1 * time.Hour
	jwtEarlyRefresh = 5 * time.Minute
)

type cachedJWT struct {
	token     string
	expiresAt time.Time
}

type selfSignedClaims struct {
	ISS   string `json:"iss"`
	SUB   string `json:"sub"`
	AUD   string `json:"aud,omitempty"`
	Scope string `json:"scope,omitempty"`
	IAT   int64  `json:"iat"`
	EXP   int64  `json:"exp"`
}

// JWTAuthStrategy implements "Service account authorization without OAuth"
// (https://developers.google.com/identity/protocols/oauth2/service-account#jwt-auth / AIP-4111),
// stripping incoming 3LO headers and injecting a self-signed Service Account JWT directly as
// Authorization: Bearer <jwt>, signed either by Google-managed keys via IAM signJwt (ADC) or
// a local non-exportable RSA-2048 hardware key.
type JWTAuthStrategy struct {
	serviceAccount string
	signingMethod  string
	hwSigner       crypto.Signer
	publicKeyID    string
	iamSigner      *adc.IAMJWTSigner
	explicitAud    string
	useScopeClaim  bool
	scopeClaim     string
	nowFunc        func() time.Time

	sf    singleflight.Group
	mu    sync.RWMutex
	cache map[string]cachedJWT
}

type JWTAuthOptions struct {
	Policy         config.PolicyConfig
	HardwareSigner crypto.Signer // Required when Policy.SigningMethod == "hardware_key"
	IAMSigner      *adc.IAMJWTSigner // Required when Policy.SigningMethod == "iam_sign_jwt"
}

func NewJWTAuthStrategy(opts JWTAuthOptions) (*JWTAuthStrategy, error) {
	p := opts.Policy
	if p.ServiceAccount == "" {
		return nil, errors.New("authswap/jwt_auth: service_account is required")
	}
	switch p.SigningMethod {
	case "iam_sign_jwt":
		if opts.IAMSigner == nil {
			return nil, errors.New("authswap/jwt_auth: IAMJWTSigner (ADC) is required for signing_method=iam_sign_jwt")
		}
	case "hardware_key":
		if opts.HardwareSigner == nil {
			return nil, errors.New("authswap/jwt_auth: hardware RSA-2048 signer is required for signing_method=hardware_key")
		}
		_, alg, err := jws.PublicJWKFromKey(opts.HardwareSigner.Public())
		if err != nil {
			return nil, err
		}
		if alg != "RS256" {
			return nil, fmt.Errorf("authswap/jwt_auth: Google Service Account self-signed JWTs require RS256 (RSA-2048+); hardware key is %s (use signing_method=iam_sign_jwt on P-256-only hardware like Secure Enclave)", alg)
		}
	default:
		return nil, fmt.Errorf("authswap/jwt_auth: unsupported signing_method %q", p.SigningMethod)
	}

	return &JWTAuthStrategy{
		serviceAccount: p.ServiceAccount,
		signingMethod:  p.SigningMethod,
		hwSigner:       opts.HardwareSigner,
		publicKeyID:    p.PublicKeyID,
		iamSigner:      opts.IAMSigner,
		explicitAud:    p.Audience,
		useScopeClaim:  p.UseScopeClaim,
		scopeClaim:     strings.Join(p.Scopes, " "),
		nowFunc:        time.Now,
		cache:          make(map[string]cachedJWT),
	}, nil
}

func (s *JWTAuthStrategy) Name() string                 { return "jwt_auth" }
func (s *JWTAuthStrategy) InterceptTokenEndpoint() bool { return true }

func (s *JWTAuthStrategy) Apply(ctx context.Context, req *http.Request) error {
	SanitizeInbound3LO(req)

	audOrScopeKey, audValue := s.resolveAudience(req)
	jwtToken, err := s.getOrMintJWT(ctx, audOrScopeKey, audValue)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	return nil
}

func (s *JWTAuthStrategy) resolveAudience(req *http.Request) (cacheKey string, aud string) {
	if s.useScopeClaim {
		return "scope:" + s.scopeClaim, ""
	}
	if s.explicitAud != "" {
		return "aud:" + s.explicitAud, s.explicitAud
	}
	host := strings.ToLower(req.URL.Host)
	if host == "" {
		host = strings.ToLower(req.Host)
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// Map legacy multiplexer paths on www.googleapis.com (used by older Java/GCDS clients)
	// to their canonical Google API service audience URIs per AIP-4111.
	if host == "www.googleapis.com" && req.URL != nil {
		switch {
		case strings.HasPrefix(req.URL.Path, "/admin/"):
			host = "admin.googleapis.com"
		case strings.HasPrefix(req.URL.Path, "/groups/"):
			host = "groupssettings.googleapis.com"
		case strings.HasPrefix(req.URL.Path, "/apps/licensing/"):
			host = "licensing.googleapis.com"
		}
	}
	derived := "https://" + host + "/"
	return "aud:" + derived, derived
}

func (s *JWTAuthStrategy) getOrMintJWT(ctx context.Context, cacheKey, aud string) (string, error) {
	now := s.nowFunc()
	s.mu.RLock()
	if ent, ok := s.cache[cacheKey]; ok && now.Add(jwtEarlyRefresh).Before(ent.expiresAt) {
		s.mu.RUnlock()
		return ent.token, nil
	}
	s.mu.RUnlock()

	val, err, _ := s.sf.Do(cacheKey, func() (any, error) {
		nowInner := s.nowFunc()
		s.mu.RLock()
		if ent, ok := s.cache[cacheKey]; ok && nowInner.Add(jwtEarlyRefresh).Before(ent.expiresAt) {
			s.mu.RUnlock()
			return ent.token, nil
		}
		s.mu.RUnlock()

		exp := nowInner.Add(jwtLifetime)
		claims := selfSignedClaims{
			ISS: s.serviceAccount,
			SUB: s.serviceAccount,
			IAT: nowInner.Unix(),
			EXP: exp.Unix(),
		}
		if s.useScopeClaim {
			claims.Scope = s.scopeClaim
		} else {
			claims.AUD = aud
		}

		var signed string
		var signErr error
		if s.signingMethod == "hardware_key" {
			hdr := map[string]any{"typ": "JWT"}
			if s.publicKeyID != "" {
				hdr["kid"] = s.publicKeyID
			}
			signed, signErr = jws.SignJWT(s.hwSigner, hdr, claims)
		} else {
			signed, _, signErr = s.iamSigner.SignJWT(ctx, s.serviceAccount, claims)
		}
		if signErr != nil {
			return "", fmt.Errorf("authswap/jwt_auth: mint self-signed JWT: %w", signErr)
		}

		s.mu.Lock()
		s.cache[cacheKey] = cachedJWT{token: signed, expiresAt: exp}
		s.mu.Unlock()
		return signed, nil
	})
	if err != nil {
		return "", err
	}
	return val.(string), nil
}
