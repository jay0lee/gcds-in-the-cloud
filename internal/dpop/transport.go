package dpop

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jay0lee/gcds-in-the-cloud/internal/config"
)

const maxTokenBodyBytes = 64 * 1024

// Transport is an http.RoundTripper that transparently injects hardware-backed RFC 9449 DPoP
// proofs into Google OAuth token requests, handles server-side DPoP-Nonce challenges via
// automatic single-retry, and bridges DPoP-bound access tokens for DPoP-unaware local apps.
type Transport struct {
	base       http.RoundTripper
	prover     *Prover
	nonces     *NonceStore
	cfg        config.DPoPConfig
	tokenHosts map[string]struct{}
	logger     *slog.Logger

	mu          sync.RWMutex
	boundTokens map[[32]byte]time.Time // SHA-256(access_token) -> expiry for token_type=="DPoP" responses
}

type TransportOptions struct {
	Base       http.RoundTripper
	Prover     *Prover
	NonceStore *NonceStore
	Config     config.DPoPConfig
	TokenURL   string
	Logger     *slog.Logger
}

func NewTransport(opts TransportOptions) (*Transport, error) {
	if opts.Prover == nil {
		return nil, fmt.Errorf("dpop: Prover is required")
	}
	base := opts.Base
	if base == nil {
		base = http.DefaultTransport
	}
	nonces := opts.NonceStore
	if nonces == nil {
		nonces = NewNonceStore(128, 15*time.Minute)
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	hosts := map[string]struct{}{
		"oauth2.googleapis.com": {},
	}
	if opts.TokenURL != "" {
		if u, err := url.Parse(opts.TokenURL); err == nil && u.Host != "" {
			hosts[strings.ToLower(u.Host)] = struct{}{}
		}
	}
	if opts.Config.Enforcement == "" {
		opts.Config.Enforcement = "enforce"
	}
	return &Transport{
		base:        base,
		prover:      opts.Prover,
		nonces:      nonces,
		cfg:         opts.Config,
		tokenHosts:  hosts,
		logger:      logger,
		boundTokens: make(map[[32]byte]time.Time),
	}, nil
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.cfg.InjectAuthURLThumb && isGoogleAuthRedirectRequest(req) {
		cloned := req.Clone(req.Context())
		q := cloned.URL.Query()
		if q.Get("dpop_jkt") == "" {
			q.Set("dpop_jkt", t.prover.ThumbprintJKT())
			cloned.URL.RawQuery = q.Encode()
		}
		req = cloned
	}

	if t.isTokenEndpointRequest(req) {
		return t.roundTripTokenEndpoint(req)
	}
	return t.roundTripResourceEndpoint(req)
}

func (t *Transport) roundTripTokenEndpoint(req *http.Request) (*http.Response, error) {
	if req.Header.Get("DPoP") != "" && !t.cfg.ForceResignExisting {
		resp, err := t.base.RoundTrip(req)
		if resp != nil {
			t.captureResponseNonce(req.URL, resp)
		}
		return resp, err
	}

	var bodyBytes []byte
	if req.Body != nil {
		limited := io.LimitReader(req.Body, maxTokenBodyBytes+1)
		var err error
		bodyBytes, err = io.ReadAll(limited)
		_ = req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("dpop: read token request body: %w", err)
		}
		if len(bodyBytes) > maxTokenBodyBytes {
			return nil, fmt.Errorf("dpop: token request body exceeds %d bytes", maxTokenBodyBytes)
		}
	}

	var grantType, authCode string
	ct := strings.ToLower(req.Header.Get("Content-Type"))
	if strings.Contains(ct, "application/x-www-form-urlencoded") || ct == "" {
		if vals, err := url.ParseQuery(string(bodyBytes)); err == nil {
			grantType = vals.Get("grant_type")
			authCode = vals.Get("code")
		}
	}

	origin := OriginKey(req.URL)
	cachedNonce := t.nonces.Get(origin)

	resp, jti, err := t.sendTokenAttempt(req, bodyBytes, grantType, authCode, cachedNonce, true)
	if err != nil {
		return nil, err
	}

	challengeNonce, isNonceChallenge, isDPoPBindingError := inspectTokenFailure(resp)
	if challengeNonce != "" {
		t.nonces.Put(origin, challengeNonce)
	}

	// RFC 9449 / Google DPoP: transparently absorb 400 use_dpop_nonce and replay once with fresh proof.
	if isNonceChallenge && challengeNonce != "" {
		_ = resp.Body.Close()
		t.logger.Info("dpop: absorbed use_dpop_nonce challenge; retrying token request",
			"origin", origin,
			"grant_type", grantType,
			"dpop_jkt", t.prover.ThumbprintJKT(),
		)
		resp, jti, err = t.sendTokenAttempt(req, bodyBytes, grantType, authCode, challengeNonce, true)
		if err != nil {
			return nil, err
		}
		t.captureResponseNonce(req.URL, resp)
	} else if t.cfg.Enforcement == "opportunistic" && grantType == "refresh_token" && isDPoPBindingError {
		// Opportunistic rollout fallback for legacy refresh tokens created before hardware DPoP deployment.
		_ = resp.Body.Close()
		t.logger.Warn("dpop: legacy unbound refresh token detected in opportunistic mode; falling back without DPoP (re-authorize client to bind refresh token)",
			"origin", origin,
			"dpop_jkt", t.prover.ThumbprintJKT(),
		)
		resp, _, err = t.sendTokenAttempt(req, bodyBytes, grantType, authCode, "", false)
		if err != nil {
			return nil, err
		}
	}

	t.logger.Debug("dpop: completed token exchange",
		"origin", origin,
		"grant_type", grantType,
		"jti", jti,
		"dpop_jkt", t.prover.ThumbprintJKT(),
		"status", resp.StatusCode,
	)

	return t.rewriteTokenResponseIfDPoPBound(resp)
}

func (t *Transport) sendTokenAttempt(
	orig *http.Request,
	bodyBytes []byte,
	grantType, authCode, nonce string,
	attachDPoP bool,
) (*http.Response, string, error) {
	attempt := orig.Clone(orig.Context())
	attempt.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	attempt.ContentLength = int64(len(bodyBytes))
	attempt.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bodyBytes)), nil
	}

	var jti string
	if attachDPoP {
		proof, mintedJTI, err := t.prover.MintTokenProof(attempt.URL, attempt.Method, grantType, authCode, nonce)
		if err != nil {
			return nil, "", err
		}
		jti = mintedJTI
		attempt.Header.Set("DPoP", proof)
	} else {
		attempt.Header.Del("DPoP")
	}

	resp, err := t.base.RoundTrip(attempt)
	if err != nil {
		return nil, jti, err
	}
	t.captureResponseNonce(attempt.URL, resp)
	return resp, jti, nil
}

func (t *Transport) roundTripResourceEndpoint(req *http.Request) (*http.Response, error) {
	bearerToken := extractBearerToken(req.Header.Get("Authorization"))
	if bearerToken == "" || !t.isAccessTokenDPoPBound(bearerToken) {
		return t.base.RoundTrip(req)
	}

	origin := OriginKey(req.URL)
	nonce := t.nonces.Get(origin)

	attempt := req.Clone(req.Context())
	proof, _, err := t.prover.MintResourceProof(attempt.URL, attempt.Method, bearerToken, nonce)
	if err != nil {
		return nil, err
	}
	attempt.Header.Set("Authorization", "DPoP "+bearerToken)
	attempt.Header.Set("DPoP", proof)

	resp, err := t.base.RoundTrip(attempt)
	if err != nil {
		return nil, err
	}
	t.captureResponseNonce(attempt.URL, resp)

	// RFC 9449 Section 9: Resource server nonce challenge (401 + WWW-Authenticate: DPoP error="use_dpop_nonce")
	if resp.StatusCode == http.StatusUnauthorized && strings.Contains(resp.Header.Get("WWW-Authenticate"), `error="use_dpop_nonce"`) {
		newNonce := resp.Header.Get("DPoP-Nonce")
		if newNonce != "" && (req.Body == nil || req.GetBody != nil) {
			_ = resp.Body.Close()
			t.nonces.Put(origin, newNonce)
			retryReq := req.Clone(req.Context())
			if req.GetBody != nil {
				rc, gErr := req.GetBody()
				if gErr != nil {
					return nil, gErr
				}
				retryReq.Body = rc
			}
			retryProof, _, pErr := t.prover.MintResourceProof(retryReq.URL, retryReq.Method, bearerToken, newNonce)
			if pErr != nil {
				return nil, pErr
			}
			retryReq.Header.Set("Authorization", "DPoP "+bearerToken)
			retryReq.Header.Set("DPoP", retryProof)
			return t.base.RoundTrip(retryReq)
		}
	}
	return resp, nil
}

// rewriteTokenResponseIfDPoPBound ensures legacy local apps that only understand token_type=="Bearer"
// continue working if an RFC 9449 server returns token_type=="DPoP", while tracking the access token
// hash so outbound resource API requests automatically upgrade to Authorization: DPoP.
func (t *Transport) rewriteTokenResponseIfDPoPBound(resp *http.Response) (*http.Response, error) {
	if resp == nil || resp.StatusCode != http.StatusOK || resp.Body == nil {
		return resp, nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenBodyBytes))
	_ = resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("dpop: read token response: %w", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		return resp, nil
	}

	tokenType, _ := doc["token_type"].(string)
	accessToken, _ := doc["access_token"].(string)
	if strings.EqualFold(tokenType, "DPoP") && accessToken != "" {
		ttl := 3600 * time.Second
		if expSec, ok := doc["expires_in"].(float64); ok && expSec > 0 {
			ttl = time.Duration(expSec) * time.Second
		}
		t.trackBoundToken(accessToken, ttl)
		doc["token_type"] = "Bearer"
		if rewritten, mErr := json.Marshal(doc); mErr == nil {
			raw = rewritten
			resp.ContentLength = int64(len(raw))
			resp.Header.Set("Content-Length", strconv.Itoa(len(raw)))
			resp.Header.Del("Content-Encoding")
		}
	}

	resp.Body = io.NopCloser(bytes.NewReader(raw))
	return resp, nil
}

func (t *Transport) trackBoundToken(accessToken string, ttl time.Duration) {
	sum := sha256.Sum256([]byte(accessToken))
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, exp := range t.boundTokens {
		if now.After(exp) {
			delete(t.boundTokens, k)
		}
	}
	t.boundTokens[sum] = now.Add(ttl + 2*time.Minute)
}

func (t *Transport) isAccessTokenDPoPBound(accessToken string) bool {
	sum := sha256.Sum256([]byte(accessToken))
	t.mu.RLock()
	exp, ok := t.boundTokens[sum]
	t.mu.RUnlock()
	return ok && time.Now().Before(exp)
}

func (t *Transport) captureResponseNonce(u *url.URL, resp *http.Response) {
	if n := resp.Header.Get("DPoP-Nonce"); n != "" {
		t.nonces.Put(OriginKey(u), n)
	}
}

func (t *Transport) isTokenEndpointRequest(req *http.Request) bool {
	if req == nil || req.URL == nil || !strings.EqualFold(req.Method, http.MethodPost) {
		return false
	}
	host := strings.ToLower(req.URL.Host)
	if _, ok := t.tokenHosts[host]; !ok && !strings.HasPrefix(host, "oauth2.googleapis.com:") {
		return false
	}
	p := req.URL.Path
	return p == "/token" || p == "/o/oauth2/token"
}

func isGoogleAuthRedirectRequest(req *http.Request) bool {
	if req == nil || req.URL == nil || !strings.EqualFold(req.Method, http.MethodGet) {
		return false
	}
	host := strings.ToLower(req.URL.Hostname())
	if host != "accounts.google.com" {
		return false
	}
	return strings.HasPrefix(req.URL.Path, "/o/oauth2/") && strings.HasSuffix(req.URL.Path, "/auth")
}

func inspectTokenFailure(resp *http.Response) (nonce string, isNonceChallenge bool, isDPoPBindingError bool) {
	if resp == nil {
		return "", false, false
	}
	nonce = resp.Header.Get("DPoP-Nonce")
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		return nonce, false, false
	}
	if strings.Contains(resp.Header.Get("WWW-Authenticate"), `error="use_dpop_nonce"`) {
		return nonce, true, false
	}
	if resp.Body == nil {
		return nonce, false, false
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenBodyBytes))
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	if err != nil {
		return nonce, false, false
	}

	var errDoc struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if json.Unmarshal(raw, &errDoc) == nil {
		if errDoc.Error == "use_dpop_nonce" {
			return nonce, true, false
		}
		descLower := strings.ToLower(errDoc.ErrorDescription)
		if errDoc.Error == "invalid_dpop_proof" ||
			(errDoc.Error == "invalid_grant" && strings.Contains(descLower, "dpop")) {
			return nonce, false, true
		}
	}
	return nonce, false, false
}

func extractBearerToken(authHeader string) string {
	const prefix = "bearer "
	if len(authHeader) > len(prefix) && strings.EqualFold(authHeader[:len(prefix)], prefix) {
		return strings.TrimSpace(authHeader[len(prefix):])
	}
	return ""
}
