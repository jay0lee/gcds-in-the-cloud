package mockgoogle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay0lee/gcds-in-the-cloud/internal/dpop"
	"github.com/jay0lee/gcds-in-the-cloud/internal/jws"
)

// Environment hosts local TLS 1.3 mock Google endpoints (oauth2, sts.mtls, iamcredentials,
// pubsub, and admin.googleapis.com) for hermetic end-to-end verification.
type Environment struct {
	ServerCA          *x509.Certificate
	ServerCAPool      *x509.CertPool
	EnterpriseClientCA *x509.Certificate
	EnterpriseCAKey   *ecdsa.PrivateKey
	GoogleManagedSAKey *rsa.PrivateKey
	UploadedHardwareSAPub *rsa.PublicKey

	APIServer  *http.Server
	APIAddr    string
	MTLSServer *http.Server
	MTLSAddr   string

	DPoPTokenCalls   atomic.Int32
	IAMSignJWTCalls  atomic.Int32
	STSMTLSCalls     atomic.Int32
	PubSubCalls      atomic.Int32
	AdminDirCalls    atomic.Int32
}

func Start(t *testing.T, uploadedHardwareSAPub *rsa.PublicKey) *Environment {
	t.Helper()

	// 1. Upstream Google Server Root CA + multi-SAN certificate
	srvCAKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srvCACert := mustSelfSignedCA(t, "Mock Google Trust Services Root", srvCAKey)
	srvPool := x509.NewCertPool()
	srvPool.AddCert(srvCACert)

	srvLeafCert := mustLeafCert(t, srvCACert, srvCAKey, []string{
		"oauth2.googleapis.com",
		"sts.mtls.googleapis.com",
		"iamcredentials.googleapis.com",
		"pubsub.googleapis.com",
		"admin.googleapis.com",
	})

	// 2. Enterprise X.509 Workload Identity Pool Trust Anchor CA (for client mTLS verification)
	entCAKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	entCACert := mustSelfSignedCA(t, "Corp Enterprise Workload Identity CA", entCAKey)
	entPool := x509.NewCertPool()
	entPool.AddCert(entCACert)

	// 3. Mock Google-managed RSA-2048 key used by iamcredentials.googleapis.com :signJwt
	googleSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	env := &Environment{
		ServerCA:              srvCACert,
		ServerCAPool:          srvPool,
		EnterpriseClientCA:    entCACert,
		EnterpriseCAKey:       entCAKey,
		GoogleManagedSAKey:    googleSAKey,
		UploadedHardwareSAPub: uploadedHardwareSAPub,
	}

	apiLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	apiTLS := tls.NewListener(apiLn, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
		Certificates: []tls.Certificate{srvLeafCert},
	})
	env.APIAddr = apiLn.Addr().String()
	env.APIServer = &http.Server{Handler: http.HandlerFunc(env.handleAPI)}
	go func() { _ = env.APIServer.Serve(apiTLS) }()

	mtlsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mtlsTLS := tls.NewListener(mtlsLn, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
		Certificates: []tls.Certificate{srvLeafCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    entPool,
	})
	env.MTLSAddr = mtlsLn.Addr().String()
	env.MTLSServer = &http.Server{Handler: http.HandlerFunc(env.handleSTSMTLS)}
	go func() { _ = env.MTLSServer.Serve(mtlsTLS) }()

	t.Cleanup(func() {
		_ = env.APIServer.Close()
		_ = env.MTLSServer.Close()
	})
	return env
}

// IssueEnterpriseClientCert signs a hardware-backed public key with the mock Enterprise WIF CA.
func (e *Environment) IssueEnterpriseClientCert(t *testing.T, cn string, hwPub any) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Corp"}},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, e.EnterpriseClientCA, hwPub, e.EnterpriseCAKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// DialContext routes *.googleapis.com hostnames to the local TLS 1.3 mock listeners without /etc/hosts.
func (e *Environment) DialContext(network, addr string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(addr)
	if strings.EqualFold(host, "sts.mtls.googleapis.com") {
		return net.DialTimeout(network, e.MTLSAddr, 5*time.Second)
	}
	return net.DialTimeout(network, e.APIAddr, 5*time.Second)
}

func (e *Environment) handleSTSMTLS(w http.ResponseWriter, r *http.Request) {
	e.STSMTLSCalls.Add(1)
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, `{"error":"missing_mtls_client_cert"}`, http.StatusUnauthorized)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	vals, _ := url.ParseQuery(string(raw))
	var subjectTokenType, subjectToken string
	if vals.Get("subject_token_type") != "" {
		subjectTokenType = vals.Get("subject_token_type")
		subjectToken = vals.Get("subject_token")
	} else {
		var bodyDoc map[string]any
		_ = json.Unmarshal(raw, &bodyDoc)
		subjectTokenType, _ = bodyDoc["subjectTokenType"].(string)
		if subjectTokenType == "" {
			subjectTokenType, _ = bodyDoc["subject_token_type"].(string)
		}
		subjectToken, _ = bodyDoc["subjectToken"].(string)
		if subjectToken == "" {
			subjectToken, _ = bodyDoc["subject_token"].(string)
		}
	}
	if subjectTokenType != "urn:ietf:params:oauth:token-type:mtls" {
		http.Error(w, fmt.Sprintf(`{"error":"unexpected subject_token_type %s"}`, subjectTokenType), http.StatusBadRequest)
		return
	}
	var certChain []string
	if err := json.Unmarshal([]byte(subjectToken), &certChain); err != nil || len(certChain) == 0 {
		http.Error(w, `{"error":"invalid x509 chain subject_token"}`, http.StatusBadRequest)
		return
	}
	leafDER, _ := base64.StdEncoding.DecodeString(certChain[0])
	if string(leafDER) != string(r.TLS.PeerCertificates[0].Raw) {
		http.Error(w, `{"error":"tls_cert_subject_token_mismatch"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{
		"access_token": "sts.hardware-x509-federated-token",
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type": "Bearer",
		"expires_in": 3600
	}`))
}

func (e *Environment) handleAPI(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	switch host {
	case "iamcredentials.googleapis.com":
		e.handleIAMCredentials(w, r)
	case "oauth2.googleapis.com":
		e.handleOAuthToken(w, r)
	case "pubsub.googleapis.com":
		e.handlePubSub(w, r)
	case "admin.googleapis.com":
		e.handleWorkspaceAdmin(w, r)
	default:
		http.Error(w, "unknown mock host "+host, http.StatusNotFound)
	}
}

func (e *Environment) handleIAMCredentials(w http.ResponseWriter, r *http.Request) {
	authHdr := r.Header.Get("Authorization")
	if strings.HasSuffix(r.URL.Path, ":generateAccessToken") {
		if authHdr != "Bearer sts.hardware-x509-federated-token" {
			http.Error(w, `{"error":"unauthenticated sts caller"}`, http.StatusUnauthorized)
			return
		}
		exp := time.Now().UTC().Add(1 * time.Hour).Format(time.RFC3339)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"accessToken":"ya29.impersonated-adc-broker-token","expireTime":%q}`, exp)
		return
	}

	if strings.HasSuffix(r.URL.Path, ":signJwt") {
		e.IAMSignJWTCalls.Add(1)
		if authHdr != "Bearer ya29.impersonated-adc-broker-token" {
			http.Error(w, `{"error":"expected impersonated ADC broker token"}`, http.StatusUnauthorized)
			return
		}
		var reqDoc struct {
			Payload string `json:"payload"`
		}
		_ = json.NewDecoder(r.Body).Decode(&reqDoc)
		var claims map[string]any
		if err := json.Unmarshal([]byte(reqDoc.Payload), &claims); err != nil {
			http.Error(w, `{"error":"invalid payload JSON"}`, http.StatusBadRequest)
			return
		}
		signed, err := jws.SignJWT(e.GoogleManagedSAKey, map[string]any{
			"typ": "JWT",
			"kid": "google-managed-sa-key-01",
		}, claims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"keyId":     "google-managed-sa-key-01",
			"signedJwt": signed,
		})
		return
	}
	http.NotFound(w, r)
}

func (e *Environment) handleOAuthToken(w http.ResponseWriter, r *http.Request) {
	e.DPoPTokenCalls.Add(1)
	rawBody, _ := io.ReadAll(r.Body)
	vals, _ := url.ParseQuery(string(rawBody))
	grantType := vals.Get("grant_type")

	proof := r.Header.Get("DPoP")
	if proof == "" {
		http.Error(w, `{"error":"missing_dpop_header"}`, http.StatusBadRequest)
		return
	}

	// Extract public JWK from DPoP header and verify signature + nonce challenge
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		http.Error(w, `{"error":"invalid_dpop_proof"}`, http.StatusBadRequest)
		return
	}
	hdrRaw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var hdr struct {
		Typ string        `json:"typ"`
		Alg string        `json:"alg"`
		JWK jws.PublicJWK `json:"jwk"`
	}
	_ = json.Unmarshal(hdrRaw, &hdr)
	if hdr.Typ != "dpop+jwt" || hdr.Alg != "ES256" {
		http.Error(w, `{"error":"invalid_dpop_header"}`, http.StatusBadRequest)
		return
	}
	xBytes, _ := base64.RawURLEncoding.DecodeString(hdr.JWK.X)
	yBytes, _ := base64.RawURLEncoding.DecodeString(hdr.JWK.Y)
	pubEC := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	_, payloadRaw, err := jws.VerifyCompactJWT(proof, pubEC)
	if err != nil {
		http.Error(w, `{"error":"invalid_dpop_signature"}`, http.StatusBadRequest)
		return
	}
	var claims dpop.ProofClaims
	_ = json.Unmarshal(payloadRaw, &claims)
	if claims.HTM != "POST" || claims.HTU != "https://oauth2.googleapis.com/token" {
		http.Error(w, `{"error":"invalid_htm_or_htu"}`, http.StatusBadRequest)
		return
	}
	if grantType == "authorization_code" {
		codeSum := sha256.Sum256([]byte(vals.Get("code")))
		wantJTI := base64.RawURLEncoding.EncodeToString(codeSum[:])
		if claims.JTI != wantJTI {
			http.Error(w, `{"error":"invalid_code_hash_jti"}`, http.StatusBadRequest)
			return
		}
	}
	if claims.Nonce != "mock-google-dpop-nonce-v1" {
		w.Header().Set("DPoP-Nonce", "mock-google-dpop-nonce-v1")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
		return
	}

	if grantType == "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		assertion := vals.Get("assertion")
		_, dwdPayload, vErr := jws.VerifyCompactJWT(assertion, &e.GoogleManagedSAKey.PublicKey)
		if vErr != nil {
			http.Error(w, `{"error":"invalid_dwd_assertion_signature"}`, http.StatusUnauthorized)
			return
		}
		var dwdClaims map[string]any
		_ = json.Unmarshal(dwdPayload, &dwdClaims)
		if dwdClaims["sub"] != "workspace-admin@corp.example.com" {
			http.Error(w, `{"error":"missing_dwd_sub"}`, http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"access_token": "ya29.workspace-dwd-access-token",
			"token_type": "Bearer",
			"expires_in": 3600
		}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{
		"access_token": "ya29.transparent-dpop-access-token",
		"refresh_token": "1//0g-dpop-hardware-bound-refresh-token",
		"token_type": "Bearer",
		"expires_in": 3600
	}`))
}

func (e *Environment) handlePubSub(w http.ResponseWriter, r *http.Request) {
	e.PubSubCalls.Add(1)
	// Verify all 3LO artifacts were stripped
	if r.URL.Query().Get("access_token") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Goog-AuthUser") != "" {
		http.Error(w, `{"error":"3lo_artifact_leaked"}`, http.StatusBadRequest)
		return
	}
	authHdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHdr, "Bearer ") {
		http.Error(w, `{"error":"missing_bearer"}`, http.StatusUnauthorized)
		return
	}
	jwtStr := strings.TrimPrefix(authHdr, "Bearer ")

	// Accept either Google-managed SA key (iam_sign_jwt) or uploaded hardware RSA-2048 public key
	hdrRaw, payloadRaw, err := jws.VerifyCompactJWT(jwtStr, &e.GoogleManagedSAKey.PublicKey)
	signedBy := "google_managed_iam_signjwt"
	if err != nil && e.UploadedHardwareSAPub != nil {
		hdrRaw, payloadRaw, err = jws.VerifyCompactJWT(jwtStr, e.UploadedHardwareSAPub)
		signedBy = "uploaded_local_hardware_rsa2048"
	}
	if err != nil {
		http.Error(w, `{"error":"self_signed_jwt_verification_failed"}`, http.StatusUnauthorized)
		return
	}
	_ = hdrRaw
	var claims map[string]any
	_ = json.Unmarshal(payloadRaw, &claims)
	if claims["aud"] != "https://pubsub.googleapis.com/" || claims["iss"] != claims["sub"] {
		http.Error(w, fmt.Sprintf(`{"error":"invalid_jwt_auth_claims","claims":%s}`, payloadRaw), http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"topics":    []string{"projects/demo/topics/events"},
		"signed_by": signedBy,
		"principal": claims["iss"],
	})
}

func (e *Environment) handleWorkspaceAdmin(w http.ResponseWriter, r *http.Request) {
	e.AdminDirCalls.Add(1)
	if r.Header.Get("Cookie") != "" || r.Header.Get("X-Goog-AuthUser") != "" {
		http.Error(w, `{"error":"3lo_headers_not_stripped"}`, http.StatusBadRequest)
		return
	}
	if r.Header.Get("Authorization") != "Bearer ya29.workspace-dwd-access-token" {
		http.Error(w, `{"error":"workspace_admin_requires_dwd_oauth_token"}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"users":[{"primaryEmail":"alice@corp.example.com"}]}`))
}

func mustSelfSignedCA(t *testing.T, cn string, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mustLeafCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, dnsNames []string) tls.Certificate {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: dnsNames[0]},
		DNSNames:              dnsNames,
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der, caCert.Raw},
		PrivateKey:  leafKey,
	}
}
