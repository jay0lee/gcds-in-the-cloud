package authswap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"cloud.google.com/go/auth"
)

// SyntheticPlaceholderToken is returned to legacy 3LO applications (like GCDS) when they
// call oauth2.googleapis.com/token under an auth_replace policy. It is never forwarded upstream.
const SyntheticPlaceholderToken = "go-oauth-proxy-synthetic-3lo-bypass"

// ADCBearerStrategy strips incoming 3LO credentials and injects short-lived keyless
// Application Default Credentials (WIF X.509 mTLS, GCE metadata, or impersonated SA).
type ADCBearerStrategy struct {
	creds *auth.Credentials
}

func NewADCBearerStrategy(creds *auth.Credentials) (*ADCBearerStrategy, error) {
	if creds == nil {
		return nil, errors.New("authswap/adc_bearer: keyless ADC credentials are required")
	}
	return &ADCBearerStrategy{creds: creds}, nil
}

func (s *ADCBearerStrategy) Name() string                 { return "adc_bearer" }
func (s *ADCBearerStrategy) InterceptTokenEndpoint() bool { return true }

func (s *ADCBearerStrategy) Apply(ctx context.Context, req *http.Request) error {
	SanitizeInbound3LO(req)
	tok, err := s.creds.Token(ctx)
	if err != nil {
		return fmt.Errorf("authswap/adc_bearer: fetch ADC token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.Value)
	return nil
}

// IsOAuthControlEndpoint reports whether req targets Google's OAuth 2.0 token, tokeninfo,
// or revocation endpoints (which legacy 3LO apps like GCDS call to manage their local token state).
func IsOAuthControlEndpoint(req *http.Request, configuredTokenURL string) bool {
	if req == nil || req.URL == nil {
		return false
	}
	host := strings.ToLower(req.URL.Hostname())
	matchHost := host == "oauth2.googleapis.com" || host == "www.googleapis.com" || host == "accounts.google.com"
	if !matchHost && configuredTokenURL != "" {
		if u, err := url.Parse(configuredTokenURL); err == nil && strings.EqualFold(u.Hostname(), host) {
			matchHost = true
		}
	}
	if !matchHost {
		return false
	}

	switch req.URL.Path {
	case "/token", "/o/oauth2/token", "/oauth2/v4/token", "/oauth2/v3/token":
		return strings.EqualFold(req.Method, http.MethodPost)
	case "/tokeninfo", "/oauth2/v3/tokeninfo", "/oauth2/v1/tokeninfo":
		return true
	case "/revoke", "/o/oauth2/revoke":
		return strings.EqualFold(req.Method, http.MethodPost)
	default:
		return false
	}
}

// BuildSynthetic3LOResponse constructs an in-memory HTTP 200 response emulating Google's
// OAuth 2.0 token/tokeninfo/revoke endpoints so 3LO clients (e.g., GCDS) succeed without
// possessing a live human administrator refresh token.
func BuildSynthetic3LOResponse(req *http.Request, scopes []string) (*http.Response, error) {
	if req.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(req.Body, 64*1024))
		_ = req.Body.Close()
	}

	scopeStr := strings.Join(scopes, " ")
	if scopeStr == "" {
		scopeStr = "https://www.googleapis.com/auth/cloud-platform"
	}

	var payload any
	switch {
	case strings.Contains(req.URL.Path, "tokeninfo"):
		payload = map[string]any{
			"expires_in":  3600,
			"scope":       scopeStr,
			"access_type": "offline",
		}
	case strings.Contains(req.URL.Path, "revoke"):
		payload = map[string]any{}
	default:
		payload = map[string]any{
			"access_token":  SyntheticPlaceholderToken,
			"refresh_token": "go-oauth-proxy-synthetic-refresh-token",
			"expires_in":    3600,
			"token_type":    "Bearer",
			"scope":         scopeStr,
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	hdr := make(http.Header)
	hdr.Set("Content-Type", "application/json; charset=utf-8")
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("Pragma", "no-cache")
	hdr.Set("Content-Length", strconv.Itoa(len(body)))

	return &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        hdr,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}, nil
}
