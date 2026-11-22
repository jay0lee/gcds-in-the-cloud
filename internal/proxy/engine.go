package proxy

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/auth"
	"github.com/jay0lee/gcds-in-the-cloud/internal/adc"
	"github.com/jay0lee/gcds-in-the-cloud/internal/authswap"
	"github.com/jay0lee/gcds-in-the-cloud/internal/config"
	"github.com/jay0lee/gcds-in-the-cloud/internal/dpop"
	"github.com/jay0lee/gcds-in-the-cloud/internal/keystore"
)

// ErrProxyAuthRequired indicates missing or invalid Proxy-Authorization credentials.
var ErrProxyAuthRequired = errors.New("proxy authentication required")

type compiledClientAuth struct {
	profileName string
	username    string
	passSHA256  [32]byte
}

type compiledPolicy struct {
	cfg           config.PolicyConfig
	dpopTransport *dpop.Transport
	strategy      authswap.Strategy
}

// Engine evaluates routing policies, caller authentication, transparent DPoP injection,
// and 3LO-to-Service-Account authentication replacement.
type Engine struct {
	cfg           *config.Config
	baseTransport http.RoundTripper
	prover        *dpop.Prover
	nonces        *dpop.NonceStore
	policies      []compiledPolicy
	clientsByUser map[string]compiledClientAuth
	logger        *slog.Logger
}

type EngineOptions struct {
	Config        *config.Config
	Keystore      keystore.KeyProvider
	ADCCreds      *auth.Credentials
	UpstreamTLS   *tls.Config
	DialContext   func(ctx context.Context, network, addr string) (net.Conn, error)
	BaseTransport http.RoundTripper
	Logger        *slog.Logger
}

func NewEngine(ctx context.Context, opts EngineOptions) (*Engine, error) {
	if opts.Config == nil {
		return nil, errors.New("proxy: Config is required")
	}
	if opts.Keystore == nil {
		return nil, errors.New("proxy: Keystore is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	baseRT := opts.BaseTransport
	if baseRT == nil {
		var tlsCfg *tls.Config
		if opts.UpstreamTLS != nil {
			tlsCfg = opts.UpstreamTLS.Clone()
		} else {
			tlsCfg = &tls.Config{}
		}
		if tlsCfg.MinVersion == 0 {
			tlsCfg.MinVersion = tls.VersionTLS12
		}
		baseRT = &http.Transport{
			TLSClientConfig:       tlsCfg,
			DialContext:           opts.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          128,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}

	// Provision or open the hardware-backed DPoP key if any policy uses DPoP.
	var prover *dpop.Prover
	nonces := dpop.NewNonceStore(256, 15*time.Minute)
	needsDPoP := false
	for _, p := range opts.Config.Policies {
		if p.Mode == "dpop_passthrough" || p.EnableDPoP {
			needsDPoP = true
			break
		}
	}
	if needsDPoP {
		dpopSigner, meta, err := opts.Keystore.EnsureKey(ctx, keystore.KeySpec{
			KeyID:      opts.Config.Keystore.DPoPKeyID,
			Algorithm:  keystore.AlgES256,
			Persistent: true,
		})
		if err != nil {
			return nil, fmt.Errorf("proxy: ensure hardware DPoP key %q: %w", opts.Config.Keystore.DPoPKeyID, err)
		}
		prover, err = dpop.NewProver(dpopSigner)
		if err != nil {
			return nil, err
		}
		logger.Info("proxy: initialized hardware-backed DPoP key",
			"key_id", meta.KeyID,
			"backend", meta.Backend,
			"alg", meta.Algorithm,
			"dpop_jkt", meta.ThumbprintJKT,
			"hardware_backed", meta.HardwareBacked,
		)
	}

	upstreamHTTP := &http.Client{
		Transport: baseRT,
		Timeout:   15 * time.Second,
	}

	var iamSigner *adc.IAMJWTSigner
	if opts.ADCCreds != nil {
		var err error
		iamSigner, err = adc.NewIAMJWTSigner(opts.ADCCreds, opts.Config.Upstream.IAMCredentialsURL, upstreamHTTP)
		if err != nil {
			return nil, err
		}
	}

	compiled := make([]compiledPolicy, 0, len(opts.Config.Policies))
	for _, p := range opts.Config.Policies {
		cp := compiledPolicy{cfg: p}
		switch p.Mode {
		case "dpop_passthrough":
			dt, err := dpop.NewTransport(dpop.TransportOptions{
				Base:       baseRT,
				Prover:     prover,
				NonceStore: nonces,
				Config:     p.DPoP,
				TokenURL:   opts.Config.Upstream.OAuthTokenURL,
				Logger:     logger,
			})
			if err != nil {
				return nil, fmt.Errorf("proxy: init dpop transport for policy %q: %w", p.Name, err)
			}
			cp.dpopTransport = dt

		case "auth_replace":
			strat, err := buildAuthReplaceStrategy(ctx, p, opts.Config.Upstream, opts.Keystore, opts.ADCCreds, iamSigner, baseRT, prover, nonces, logger)
			if err != nil {
				return nil, fmt.Errorf("proxy: init auth_replace policy %q: %w", p.Name, err)
			}
			cp.strategy = strat
		}
		compiled = append(compiled, cp)
	}

	clientsByUser, err := compileClientProfiles(opts.Config.Clients)
	if err != nil {
		return nil, err
	}

	return &Engine{
		cfg:           opts.Config,
		baseTransport: baseRT,
		prover:        prover,
		nonces:        nonces,
		policies:      compiled,
		clientsByUser: clientsByUser,
		logger:        logger,
	}, nil
}

// DPoPThumbprint returns the active RFC 7638 JWK thumbprint (empty if DPoP is unused).
func (e *Engine) DPoPThumbprint() string {
	if e.prover == nil {
		return ""
	}
	return e.prover.ThumbprintJKT()
}

// AuthenticateCaller validates Proxy-Authorization Basic credentials and resolves the named client profile.
func (e *Engine) AuthenticateCaller(proxyAuthHeader string) (string, error) {
	if proxyAuthHeader == "" {
		if e.cfg.Server.RequireProxyAuth {
			return "", ErrProxyAuthRequired
		}
		return "default", nil
	}
	const prefix = "basic "
	if len(proxyAuthHeader) <= len(prefix) || !strings.EqualFold(proxyAuthHeader[:len(prefix)], prefix) {
		return "", ErrProxyAuthRequired
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(proxyAuthHeader[len(prefix):]))
	if err != nil {
		return "", ErrProxyAuthRequired
	}
	user, pass, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return "", ErrProxyAuthRequired
	}
	ent, exists := e.clientsByUser[user]
	if !exists {
		return "", ErrProxyAuthRequired
	}
	gotHash := sha256.Sum256([]byte(pass))
	if subtle.ConstantTimeCompare(gotHash[:], ent.passSHA256[:]) != 1 {
		return "", ErrProxyAuthRequired
	}
	return ent.profileName, nil
}

// HandleRequest applies policy routing, synthetic 3LO token responses, DPoP proof injection,
// or Service Account auth replacement to req and returns the upstream (or synthetic) HTTP response.
func (e *Engine) HandleRequest(req *http.Request, clientProfile string) (*http.Response, string, error) {
	if clientProfile == "" {
		clientProfile = "default"
	}
	targetHost := req.URL.Hostname()
	if targetHost == "" {
		targetHost = stripPort(req.Host)
	}

	isOAuthCtrl := authswap.IsOAuthControlEndpoint(req, e.cfg.Upstream.OAuthTokenURL)
	pol := e.matchPolicy(clientProfile, targetHost, isOAuthCtrl)
	if pol == nil {
		return nil, "passthrough_none", fmt.Errorf("proxy: no policy matched client=%q host=%q", clientProfile, targetHost)
	}

	// If an auth_replace policy governs this client's OAuth control endpoint (e.g., GCDS refreshing
	// its dummy 3LO token at oauth2.googleapis.com/token before calling admin.googleapis.com),
	// respond locally with a synthetic 200 OK token response without contacting Google.
	if pol.cfg.Mode == "auth_replace" && isOAuthCtrl && pol.strategy.InterceptTokenEndpoint() {
		resp, err := authswap.BuildSynthetic3LOResponse(req, pol.cfg.Scopes)
		if err != nil {
			return nil, pol.cfg.Name, err
		}
		e.logger.Info("proxy: served synthetic 3LO OAuth response for auth_replace client",
			"policy", pol.cfg.Name,
			"strategy", pol.strategy.Name(),
			"client", clientProfile,
			"path", req.URL.Path,
		)
		return resp, pol.cfg.Name, nil
	}

	outReq := req.Clone(req.Context())
	outReq.RequestURI = ""
	stripHopByHopHeaders(outReq.Header)

	if pol.cfg.Mode == "dpop_passthrough" {
		resp, err := pol.dpopTransport.RoundTrip(outReq)
		return resp, pol.cfg.Name, err
	}

	if err := pol.strategy.Apply(outReq.Context(), outReq); err != nil {
		return nil, pol.cfg.Name, err
	}
	resp, err := e.baseTransport.RoundTrip(outReq)
	return resp, pol.cfg.Name, err
}

func (e *Engine) matchPolicy(clientProfile, host string, isOAuthCtrl bool) *compiledPolicy {
	// Pass 1: Exact client + host match
	for i := range e.policies {
		p := &e.policies[i]
		if clientMatches(p.cfg.MatchClient, clientProfile, true) && hostMatchesList(host, p.cfg.MatchHosts) {
			return p
		}
	}
	// Pass 2: If this is an OAuth /token call for an authenticated clientProfile that has an
	// auth_replace policy (e.g. match_hosts: ["admin.googleapis.com"]), let that policy synthesize /token.
	if isOAuthCtrl {
		for i := range e.policies {
			p := &e.policies[i]
			if p.cfg.Mode == "auth_replace" && clientMatches(p.cfg.MatchClient, clientProfile, true) {
				return p
			}
		}
	}
	// Pass 3: Wildcard/default client + host match
	for i := range e.policies {
		p := &e.policies[i]
		if clientMatches(p.cfg.MatchClient, clientProfile, false) && hostMatchesList(host, p.cfg.MatchHosts) {
			return p
		}
	}
	// Pass 4: Wildcard/default client OAuth /token synthesis when only host-scoped auth_replace policies exist
	if isOAuthCtrl {
		for i := range e.policies {
			p := &e.policies[i]
			if p.cfg.Mode == "auth_replace" && clientMatches(p.cfg.MatchClient, clientProfile, false) {
				return p
			}
		}
	}
	return nil
}

func buildAuthReplaceStrategy(
	ctx context.Context,
	p config.PolicyConfig,
	upstream config.UpstreamEndpointsConfig,
	ks keystore.KeyProvider,
	adcCreds *auth.Credentials,
	iamSigner *adc.IAMJWTSigner,
	baseRT http.RoundTripper,
	prover *dpop.Prover,
	nonces *dpop.NonceStore,
	logger *slog.Logger,
) (authswap.Strategy, error) {
	switch p.Strategy {
	case "adc_bearer":
		return authswap.NewADCBearerStrategy(adcCreds)

	case "jwt_auth":
		var hwSigner, err = optionalHardwareSigner(ctx, p, ks)
		if err != nil {
			return nil, err
		}
		return authswap.NewJWTAuthStrategy(authswap.JWTAuthOptions{
			Policy:         p,
			HardwareSigner: hwSigner,
			IAMSigner:      iamSigner,
		})

	case "dwd_oauth":
		hwSigner, err := optionalHardwareSigner(ctx, p, ks)
		if err != nil {
			return nil, err
		}
		rt := baseRT
		if p.EnableDPoP {
			dt, err := dpop.NewTransport(dpop.TransportOptions{
				Base:       baseRT,
				Prover:     prover,
				NonceStore: nonces,
				Config:     config.DPoPConfig{Enforcement: "enforce"},
				TokenURL:   upstream.OAuthTokenURL,
				Logger:     logger,
			})
			if err != nil {
				return nil, err
			}
			rt = dt
		}
		return authswap.NewDWDStrategy(authswap.DWDOptions{
			Policy:         p,
			TokenURL:       upstream.OAuthTokenURL,
			HardwareSigner: hwSigner,
			IAMSigner:      iamSigner,
			HTTPClient:     &http.Client{Transport: rt, Timeout: 15 * time.Second},
		})

	default:
		return nil, fmt.Errorf("unknown auth_replace strategy %q", p.Strategy)
	}
}

func optionalHardwareSigner(ctx context.Context, p config.PolicyConfig, ks keystore.KeyProvider) (crypto.Signer, error) {
	if p.SigningMethod != "hardware_key" {
		return nil, nil
	}
	return ks.Signer(ctx, p.SigningKeyID)
}

func compileClientProfiles(clients map[string]config.ClientAuth) (map[string]compiledClientAuth, error) {
	out := make(map[string]compiledClientAuth, len(clients))
	for profile, c := range clients {
		if c.Username == "" {
			return nil, fmt.Errorf("proxy: client profile %q missing username", profile)
		}
		var hash [32]byte
		switch {
		case c.PasswordSHA256 != "":
			raw, err := hex.DecodeString(strings.TrimSpace(c.PasswordSHA256))
			if err != nil || len(raw) != 32 {
				return nil, fmt.Errorf("proxy: client profile %q has invalid password_sha256 hex", profile)
			}
			copy(hash[:], raw)
		case c.PasswordEnv != "":
			val := os.Getenv(c.PasswordEnv)
			if val == "" {
				return nil, fmt.Errorf("proxy: client profile %q password_env %q is empty", profile, c.PasswordEnv)
			}
			hash = sha256.Sum256([]byte(val))
		default:
			return nil, fmt.Errorf("proxy: client profile %q requires password_sha256 or password_env", profile)
		}
		out[c.Username] = compiledClientAuth{
			profileName: profile,
			username:    c.Username,
			passSHA256:  hash,
		}
	}
	return out, nil
}

func clientMatches(policyClient, actualClient string, exactOnly bool) bool {
	if exactOnly {
		return policyClient != "" && policyClient != "*" && strings.EqualFold(policyClient, actualClient)
	}
	return policyClient == "" || policyClient == "*" || (strings.EqualFold(policyClient, "default") && strings.EqualFold(actualClient, "default"))
}

func hostMatchesList(host string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	h := strings.ToLower(strings.TrimSuffix(stripPort(host), "."))
	for _, p := range patterns {
		pClean := strings.ToLower(strings.TrimSuffix(p, "."))
		if pClean == "*" || pClean == h {
			return true
		}
		if strings.HasPrefix(pClean, "*.") {
			suffix := pClean[1:]
			if strings.HasSuffix(h, suffix) && len(h) > len(suffix) {
				return true
			}
		}
	}
	return false
}

func stripPort(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func stripHopByHopHeaders(h http.Header) {
	for _, k := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		h.Del(k)
	}
}
