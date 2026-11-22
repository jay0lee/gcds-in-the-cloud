package authswap

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jay0lee/gcds-in-the-cloud/internal/adc"
	"github.com/jay0lee/gcds-in-the-cloud/internal/config"
	"github.com/jay0lee/gcds-in-the-cloud/internal/jws"
	"golang.org/x/sync/singleflight"
)

type dwdAssertionClaims struct {
	ISS   string `json:"iss"`
	SUB   string `json:"sub"`
	Scope string `json:"scope"`
	AUD   string `json:"aud"`
	IAT   int64  `json:"iat"`
	EXP   int64  `json:"exp"`
}

// DWDStrategy implements keyless Service Account Domain-Wide Delegation (required for Google
// Workspace APIs such as admin.googleapis.com used by GCDS, which reject raw self-signed JWTs).
// It strips incoming 3LO credentials, mints a short-lived DWD assertion via IAM signJwt (ADC)
// or a hardware RSA-2048 key, exchanges it at the OAuth token endpoint, and caches the access token.
type DWDStrategy struct {
	serviceAccount string
	dwdSubject     string
	scopeStr       string
	tokenURL       string
	signingMethod  string
	hwSigner       crypto.Signer
	publicKeyID    string
	iamSigner      *adc.IAMJWTSigner
	httpClient     *http.Client
	nowFunc        func() time.Time

	sf     singleflight.Group
	mu     sync.RWMutex
	cached cachedJWT
}

type DWDOptions struct {
	Policy         config.PolicyConfig
	TokenURL       string
	HardwareSigner crypto.Signer
	IAMSigner      *adc.IAMJWTSigner
	HTTPClient     *http.Client // May wrap dpop.Transport if EnableDPoP is true
}

func NewDWDStrategy(opts DWDOptions) (*DWDStrategy, error) {
	p := opts.Policy
	if p.ServiceAccount == "" || p.DWDSubject == "" || len(p.Scopes) == 0 {
		return nil, errors.New("authswap/dwd_oauth: service_account, dwd_subject, and scopes are required")
	}
	switch p.SigningMethod {
	case "iam_sign_jwt":
		if opts.IAMSigner == nil {
			return nil, errors.New("authswap/dwd_oauth: IAMJWTSigner (ADC) is required for signing_method=iam_sign_jwt")
		}
	case "hardware_key":
		if opts.HardwareSigner == nil {
			return nil, errors.New("authswap/dwd_oauth: hardware RSA-2048 signer is required for signing_method=hardware_key")
		}
	default:
		return nil, fmt.Errorf("authswap/dwd_oauth: unsupported signing_method %q", p.SigningMethod)
	}
	tokURL := opts.TokenURL
	if tokURL == "" {
		tokURL = "https://oauth2.googleapis.com/token"
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	return &DWDStrategy{
		serviceAccount: p.ServiceAccount,
		dwdSubject:     p.DWDSubject,
		scopeStr:       strings.Join(p.Scopes, " "),
		tokenURL:       tokURL,
		signingMethod:  p.SigningMethod,
		hwSigner:       opts.HardwareSigner,
		publicKeyID:    p.PublicKeyID,
		iamSigner:      opts.IAMSigner,
		httpClient:     hc,
		nowFunc:        time.Now,
	}, nil
}

func (s *DWDStrategy) Name() string                 { return "dwd_oauth" }
func (s *DWDStrategy) InterceptTokenEndpoint() bool { return true }

func (s *DWDStrategy) Apply(ctx context.Context, req *http.Request) error {
	SanitizeInbound3LO(req)
	tok, err := s.getOrExchangeAccessToken(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return nil
}

func (s *DWDStrategy) getOrExchangeAccessToken(ctx context.Context) (string, error) {
	now := s.nowFunc()
	s.mu.RLock()
	if s.cached.token != "" && now.Add(jwtEarlyRefresh).Before(s.cached.expiresAt) {
		tok := s.cached.token
		s.mu.RUnlock()
		return tok, nil
	}
	s.mu.RUnlock()

	val, err, _ := s.sf.Do("dwd_token", func() (any, error) {
		nowInner := s.nowFunc()
		s.mu.RLock()
		if s.cached.token != "" && nowInner.Add(jwtEarlyRefresh).Before(s.cached.expiresAt) {
			tok := s.cached.token
			s.mu.RUnlock()
			return tok, nil
		}
		s.mu.RUnlock()

		claims := dwdAssertionClaims{
			ISS:   s.serviceAccount,
			SUB:   s.dwdSubject,
			Scope: s.scopeStr,
			AUD:   s.tokenURL,
			IAT:   nowInner.Unix(),
			EXP:   nowInner.Add(jwtLifetime).Unix(),
		}

		var assertion string
		var signErr error
		if s.signingMethod == "hardware_key" {
			hdr := map[string]any{"typ": "JWT"}
			if s.publicKeyID != "" {
				hdr["kid"] = s.publicKeyID
			}
			assertion, signErr = jws.SignJWT(s.hwSigner, hdr, claims)
		} else {
			assertion, _, signErr = s.iamSigner.SignJWT(ctx, s.serviceAccount, claims)
		}
		if signErr != nil {
			return "", fmt.Errorf("authswap/dwd_oauth: sign assertion: %w", signErr)
		}

		form := url.Values{}
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
		form.Set("assertion", assertion)
		encoded := form.Encode()

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURL, strings.NewReader(encoded))
		if err != nil {
			return "", err
		}
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := s.httpClient.Do(httpReq)
		if err != nil {
			return "", fmt.Errorf("authswap/dwd_oauth: token exchange failed: %w", err)
		}
		defer resp.Body.Close()

		raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		if err != nil {
			return "", err
		}
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("authswap/dwd_oauth: token endpoint HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
		}

		var tokResp struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int64  `json:"expires_in"`
		}
		if err := json.Unmarshal(raw, &tokResp); err != nil || tokResp.AccessToken == "" {
			return "", errors.New("authswap/dwd_oauth: invalid token endpoint JSON response")
		}
		ttl := time.Duration(tokResp.ExpiresIn) * time.Second
		if ttl <= 0 {
			ttl = jwtLifetime
		}

		s.mu.Lock()
		s.cached = cachedJWT{
			token:     tokResp.AccessToken,
			expiresAt: nowInner.Add(ttl),
		}
		s.mu.Unlock()
		return tokResp.AccessToken, nil
	})
	if err != nil {
		return "", err
	}
	return val.(string), nil
}
