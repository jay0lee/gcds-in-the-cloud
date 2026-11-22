package test

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jay0lee/gcds-in-the-cloud/internal/adc"
	"github.com/jay0lee/gcds-in-the-cloud/internal/ca"
	"github.com/jay0lee/gcds-in-the-cloud/internal/config"
	"github.com/jay0lee/gcds-in-the-cloud/internal/keystore"
	"github.com/jay0lee/gcds-in-the-cloud/internal/proxy"
	"github.com/jay0lee/gcds-in-the-cloud/test/mockgoogle"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestEndToEndProxy_DPoP_JWTAuth_GCDS_HardwareWIF(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	// Use real macOS Security.framework (Secure Enclave / non-extractable Keychain) on Darwin,
	// or gated opaque MemoryProvider on non-Darwin CI hosts.
	var ks keystore.KeyProvider
	var backendName string
	if runtime.GOOS == "darwin" {
		seProv, err := keystore.NewSecureEnclaveProvider()
		if err == nil {
			ks = seProv
			backendName = "secure_enclave"
			t.Cleanup(func() {
				_ = seProv.DeleteKey("test.e2e.wif.p256")
				_ = seProv.DeleteKey("test.e2e.dpop.p256")
				_ = seProv.DeleteKey("test.e2e.ca.p256")
				_ = seProv.DeleteKey("test.e2e.local.sa.rsa2048")
				_ = seProv.Close()
			})
		}
	}
	if ks == nil {
		ks = keystore.NewMemoryProvider()
		backendName = "ephemeral_memory"
		t.Cleanup(func() { _ = ks.Close() })
	}

	// Provision hardware keys:
	// 1. P-256 key for Workload Identity Federation X.509 mTLS (keyless on-prem ADC)
	wifSigner, _, err := ks.EnsureKey(ctx, keystore.KeySpec{
		KeyID:      "test.e2e.wif.p256",
		Algorithm:  keystore.AlgES256,
		Persistent: false,
	})
	if err != nil {
		t.Fatalf("provision WIF P-256 hardware key: %v", err)
	}
	// 2. RSA-2048 hardware key for zero-network-hop local SA jwt-auth test
	hwSASigner, _, err := ks.EnsureKey(ctx, keystore.KeySpec{
		KeyID:      "test.e2e.local.sa.rsa2048",
		Algorithm:  keystore.AlgRS256,
		RSABits:    2048,
		Persistent: false,
	})
	if err != nil {
		t.Fatalf("provision local SA RSA-2048 hardware key: %v", err)
	}
	hwRSAPub := hwSASigner.Public().(*rsa.PublicKey)

	// Start hermetic TLS 1.3 Mock Google Cloud + Workspace environment
	googleEnv := mockgoogle.Start(t, hwRSAPub)

	// Issue Enterprise X.509 workload certificate for the hardware WIF key (only public cert on disk!)
	wifCertPEM := googleEnv.IssueEnterpriseClientCert(t, "host-01.corp.example.com", wifSigner.Public())
	wifCertPath := filepath.Join(tmpDir, "workload-leaf.crt.pem")
	if err := os.WriteFile(wifCertPath, wifCertPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	gcdsPassHash := sha256.Sum256([]byte("gcds-local-secret"))
	localSAPassHash := sha256.Sum256([]byte("local-rsa-secret"))

	cfg := &config.Config{
		Server: config.ServerConfig{
			ListenConnect:     "127.0.0.1:0",
			ListenReverse:     "127.0.0.1:0",
			AllowedHosts:      []string{"oauth2.googleapis.com", "admin.googleapis.com", "pubsub.googleapis.com"},
			ReadHeaderTimeout: 10 * time.Second,
			LogLevel:          "debug",
		},
		CA: config.CAConfig{
			CertPath: filepath.Join(tmpDir, "proxy-ca.crt.pem"),
			KeyID:    "test.e2e.ca.p256",
		},
		Keystore: config.KeystoreConfig{
			Backend:            backendName,
			AllowEphemeralKeys: backendName == "ephemeral_memory",
			DPoPKeyID:          "test.e2e.dpop.p256",
		},
		ADC: config.ADCConfig{
			Mode:                      "wif_x509_mtls",
			ImpersonateServiceAccount: "proxy-broker@sec.iam.gserviceaccount.com",
			WIFX509: &config.WIFX509Config{
				Audience:        "//iam.googleapis.com/projects/12345/locations/global/workloadIdentityPools/corp/providers/x509",
				KeyID:           "test.e2e.wif.p256",
				LeafCertPath:    wifCertPath,
				STSMTLSEndpoint: "https://sts.mtls.googleapis.com/v1/token",
			},
		},
		Clients: map[string]config.ClientAuth{
			"gcds": {
				Username:       "gcds-user",
				PasswordSHA256: hex.EncodeToString(gcdsPassHash[:]),
			},
			"hw-sa-client": {
				Username:       "hw-sa-user",
				PasswordSHA256: hex.EncodeToString(localSAPassHash[:]),
			},
		},
		Policies: []config.PolicyConfig{
			// Profile 1: GCDS -> Strip 3LO + Synthetic /token + Keyless DWD OAuth (with DPoP!)
			{
				Name:           "gcds-dwd-policy",
				MatchClient:    "gcds",
				MatchHosts:     []string{"admin.googleapis.com"},
				Mode:           "auth_replace",
				Strategy:       "dwd_oauth",
				ServiceAccount: "gcds-sync@sec.iam.gserviceaccount.com",
				SigningMethod:  "iam_sign_jwt",
				DWDSubject:     "workspace-admin@corp.example.com",
				EnableDPoP:     true,
				Scopes:         []string{"https://www.googleapis.com/auth/admin.directory.user"},
			},
			// Profile 2: Zero-Network-Hop Hardware RSA-2048 SA jwt-auth without OAuth
			{
				Name:           "pubsub-hardware-rsa-jwt-auth",
				MatchClient:    "hw-sa-client",
				MatchHosts:     []string{"pubsub.googleapis.com"},
				Mode:           "auth_replace",
				Strategy:       "jwt_auth",
				ServiceAccount: "pubsub-hw@app.iam.gserviceaccount.com",
				SigningMethod:  "hardware_key",
				SigningKeyID:   "test.e2e.local.sa.rsa2048",
				PublicKeyID:    "uploaded-cert-key-id-1",
			},
			// Profile 3: Default Pub/Sub -> Keyless ADC + IAM signJwt SA jwt-auth without OAuth
			{
				Name:           "pubsub-keyless-iam-jwt-auth",
				MatchHosts:     []string{"pubsub.googleapis.com"},
				Mode:           "auth_replace",
				Strategy:       "jwt_auth",
				ServiceAccount: "pubsub-iam@app.iam.gserviceaccount.com",
				SigningMethod:  "iam_sign_jwt",
			},
			// Profile 4: Default OAuth -> Transparent Hardware DPoP Upgrade
			{
				Name: "default-dpop-upgrade",
				Mode: "dpop_passthrough",
				DPoP: config.DPoPConfig{Enforcement: "enforce"},
			},
		},
		Upstream: config.UpstreamEndpointsConfig{
			OAuthTokenURL:     "https://oauth2.googleapis.com/token",
			IAMCredentialsURL: "https://iamcredentials.googleapis.com",
			STSMTLSTokenURL:   "https://sts.mtls.googleapis.com/v1/token",
		},
	}

	upstreamTLS := &tls.Config{
		RootCAs:    googleEnv.ServerCAPool,
		MinVersion: tls.VersionTLS13,
	}
	dialMock := func(_ context.Context, network, addr string) (net.Conn, error) {
		return googleEnv.DialContext(network, addr)
	}

	// Bootstrap keyless ADC via real hardware-backed X.509 mTLS to sts.mtls.googleapis.com!
	adcCreds, err := adc.NewCredentials(ctx, adc.Options{
		ADC:         cfg.ADC,
		Upstream:    cfg.Upstream,
		Keystore:    ks,
		BaseTLS:     upstreamTLS,
		DialContext: dialMock,
	})
	if err != nil {
		t.Fatalf("bootstrap hardware X.509 WIF ADC credentials: %v", err)
	}

	authority, err := ca.InitOrLoad(ctx, cfg.CA, ks)
	if err != nil {
		t.Fatalf("init hardware-backed local Root CA: %v", err)
	}

	var auditBuf syncBuffer
	logger := proxy.NewRedactingLogger(&auditBuf, "debug")

	engine, err := proxy.NewEngine(ctx, proxy.EngineOptions{
		Config:      cfg,
		Keystore:    ks,
		ADCCreds:    adcCreds,
		UpstreamTLS: upstreamTLS,
		DialContext: dialMock,
		Logger:      logger,
	})
	if err != nil {
		t.Fatalf("init proxy engine: %v", err)
	}

	srv, err := proxy.NewServer(proxy.ServerOptions{
		Config:      cfg,
		Engine:      engine,
		Authority:   authority,
		DialContext: dialMock,
		Logger:      logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()

	// Trust store containing ONLY the proxy's local Root CA (simulating GCDS JRE cacerts)
	proxyCAPool := x509.NewCertPool()
	if !proxyCAPool.AppendCertsFromPEM(authority.RootPEM()) {
		t.Fatal("failed to parse proxy Root CA PEM")
	}

	newForwardProxiedClient := func(user, pass string) *http.Client {
		u := &url.URL{Scheme: "http", Host: srv.ConnectAddr()}
		if user != "" {
			u.User = url.UserPassword(user, pass)
		}
		return &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				Proxy:           http.ProxyURL(u),
				TLSClientConfig: &tls.Config{RootCAs: proxyCAPool},
			},
		}
	}

	// =========================================================================
	// CASE 1: Transparent DPoP Injection over HTTP CONNECT (Unaware OAuth App)
	// =========================================================================
	t.Run("TransparentDPoPOverConnect", func(t *testing.T) {
		appClient := newForwardProxiedClient("", "")
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"4/secret-auth-code-for-dpop"},
			"client_id":     {"legacy-desktop-app"},
			"client_secret": {"super-secret-client-secret"},
		}
		resp, err := appClient.Post("https://oauth2.googleapis.com/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("POST /token via CONNECT proxy failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200 OK after transparent DPoP + nonce retry, got %d: %s", resp.StatusCode, raw)
		}
		var tok map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&tok)
		if tok["refresh_token"] != "1//0g-dpop-hardware-bound-refresh-token" {
			t.Fatalf("unexpected token response: %v", tok)
		}
		if googleEnv.DPoPTokenCalls.Load() != 2 {
			t.Fatalf("expected 2 upstream calls (initial + use_dpop_nonce retry), got %d", googleEnv.DPoPTokenCalls.Load())
		}
	})

	// =========================================================================
	// CASE 2: Strip 3LO -> Keyless Service Account Without OAuth (jwt-auth)
	// =========================================================================
	t.Run("Strip3LO_To_KeylessIAM_JWTAuth_WithoutOAuth", func(t *testing.T) {
		appClient := newForwardProxiedClient("", "")
		req, _ := http.NewRequest(http.MethodGet, "https://pubsub.googleapis.com/v1/projects/demo/topics?access_token=human_3lo_query_leak", nil)
		req.Header.Set("Authorization", "Bearer ya29.human-3-legged-oauth-token")
		req.Header.Set("Cookie", "SID=human-browser-cookie")
		req.Header.Set("X-Goog-AuthUser", "0")

		resp, err := appClient.Do(req)
		if err != nil {
			t.Fatalf("GET pubsub via CONNECT proxy failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200 OK from Pub/Sub with self-signed JWT, got %d: %s", resp.StatusCode, raw)
		}
		var doc map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&doc)
		if doc["signed_by"] != "google_managed_iam_signjwt" || doc["principal"] != "pubsub-iam@app.iam.gserviceaccount.com" {
			t.Fatalf("unexpected Pub/Sub auth result: %v", doc)
		}
		if googleEnv.STSMTLSCalls.Load() == 0 || googleEnv.IAMSignJWTCalls.Load() == 0 {
			t.Fatalf("expected hardware X.509 mTLS STS + IAM signJwt calls")
		}
	})

	// =========================================================================
	// CASE 3: Strip 3LO -> Zero-Network-Hop Hardware RSA-2048 SA jwt-auth
	// =========================================================================
	t.Run("Strip3LO_To_LocalHardwareRSA_JWTAuth_ZeroHop", func(t *testing.T) {
		iamBefore := googleEnv.IAMSignJWTCalls.Load()
		oauthBefore := googleEnv.DPoPTokenCalls.Load()

		hwClient := newForwardProxiedClient("hw-sa-user", "local-rsa-secret")
		req, _ := http.NewRequest(http.MethodGet, "https://pubsub.googleapis.com/v1/projects/demo/topics", nil)
		req.Header.Set("Authorization", "Bearer ya29.old-3lo-token")

		resp, err := hwClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200 OK, got %d: %s", resp.StatusCode, raw)
		}
		var doc map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&doc)
		if doc["signed_by"] != "uploaded_local_hardware_rsa2048" {
			t.Fatalf("expected hardware RSA-2048 signature, got %v", doc)
		}
		if googleEnv.IAMSignJWTCalls.Load() != iamBefore || googleEnv.DPoPTokenCalls.Load() != oauthBefore {
			t.Fatalf("expected ZERO IAM or OAuth network hops for local hardware RSA jwt-auth")
		}
	})

	// =========================================================================
	// CASE 4: GCDS Full Lifecycle (Synthetic 3LO /token + Strip 3LO -> SA DWD)
	// =========================================================================
	t.Run("GCDS_Synthetic3LOToken_And_DomainWideDelegation", func(t *testing.T) {
		gcdsClient := newForwardProxiedClient("gcds-user", "gcds-local-secret")
		oauthBefore := googleEnv.DPoPTokenCalls.Load()

		// Step A: GCDS refreshes its dummy/retired 3LO token at oauth2.googleapis.com/token
		tokResp, err := gcdsClient.PostForm("https://oauth2.googleapis.com/token", url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {"retired-super-admin-3lo-refresh-token"},
		})
		if err != nil {
			t.Fatal(err)
		}
		var synthDoc map[string]any
		_ = json.NewDecoder(tokResp.Body).Decode(&synthDoc)
		_ = tokResp.Body.Close()
		if tokResp.StatusCode != http.StatusOK || synthDoc["access_token"] != "go-oauth-proxy-synthetic-3lo-bypass" {
			t.Fatalf("expected synthetic 3LO token response, got status=%d body=%v", tokResp.StatusCode, synthDoc)
		}
		if googleEnv.DPoPTokenCalls.Load() != oauthBefore {
			t.Fatalf("synthetic 3LO /token should NOT contact upstream oauth2.googleapis.com")
		}

		// Step B: GCDS calls Workspace Admin Directory API presenting the synthetic 3LO token
		dirReq, _ := http.NewRequest(http.MethodGet, "https://admin.googleapis.com/admin/directory/v1/users?domain=corp.example.com", nil)
		dirReq.Header.Set("Authorization", "Bearer "+synthDoc["access_token"].(string))
		dirResp, err := gcdsClient.Do(dirReq)
		if err != nil {
			t.Fatal(err)
		}
		defer dirResp.Body.Close()
		if dirResp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(dirResp.Body)
			t.Fatalf("expected 200 OK from Workspace Admin API via DWD, got %d: %s", dirResp.StatusCode, raw)
		}
		if googleEnv.AdminDirCalls.Load() != 1 {
			t.Fatalf("expected 1 Admin Directory call, got %d", googleEnv.AdminDirCalls.Load())
		}
	})

	// =========================================================================
	// CASE 5: Local Reverse Proxy Mode + Host Allowlist + Log Redaction Audit
	// =========================================================================
	t.Run("ReverseProxyMode_Allowlist_And_LogRedaction", func(t *testing.T) {
		revReq, _ := http.NewRequest(http.MethodGet, "http://"+srv.ReverseAddr()+"/https/pubsub.googleapis.com/v1/projects/demo/topics", nil)
		revReq.Header.Set("Authorization", "Bearer ya29.reverse-proxy-3lo-token-must-not-log")
		revResp, err := http.DefaultClient.Do(revReq)
		if err != nil {
			t.Fatal(err)
		}
		_ = revResp.Body.Close()
		if revResp.StatusCode != http.StatusOK {
			t.Fatalf("reverse proxy mode expected 200 OK, got %d", revResp.StatusCode)
		}

		// Non-allowlisted host via CONNECT must return 403 Forbidden
		appClient := newForwardProxiedClient("", "")
		_, blockedErr := appClient.Get("https://untrusted.example.com/secret")
		if blockedErr == nil {
			t.Fatal("expected CONNECT to untrusted.example.com to be blocked with 403")
		}

		// Verify audit logs contain zero sensitive tokens or secrets
		logs := auditBuf.String()
		for _, forbidden := range []string{
			"ya29.human-3-legged-oauth-token",
			"ya29.reverse-proxy-3lo-token-must-not-log",
			"4/secret-auth-code-for-dpop",
			"super-secret-client-secret",
			"gcds-local-secret",
			base64.StdEncoding.EncodeToString([]byte("gcds-user:gcds-local-secret")),
		} {
			if strings.Contains(logs, forbidden) {
				t.Fatalf("SECURITY FAILURE: sensitive secret %q leaked into audit logs!", forbidden)
			}
		}
	})
}
