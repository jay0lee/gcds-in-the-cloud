package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jay0lee/gcds-in-the-cloud/internal/config"
	"github.com/jay0lee/gcds-in-the-cloud/internal/jws"
)

func TestGoogleDPoPCodeHashJTIAndNonceChallengeRetry(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	prover, err := NewProver(priv)
	if err != nil {
		t.Fatal(err)
	}

	const authCode = "4/0AVGzR1_sample_google_auth_code_xyz"
	wantCodeHash := sha256.Sum256([]byte(authCode))
	wantAuthCodeJTI := base64.RawURLEncoding.EncodeToString(wantCodeHash[:])

	var tokenCalls atomic.Int32
	var resourceCalls atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		callNum := tokenCalls.Add(1)
		proof := r.Header.Get("DPoP")
		if proof == "" {
			t.Errorf("call %d missing DPoP header", callNum)
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		_, payloadRaw, vErr := jws.VerifyCompactJWT(proof, &priv.PublicKey)
		if vErr != nil {
			t.Errorf("invalid DPoP signature: %v", vErr)
			http.Error(w, `{"error":"invalid_dpop_proof"}`, http.StatusBadRequest)
			return
		}
		var claims ProofClaims
		_ = json.Unmarshal(payloadRaw, &claims)

		bodyBytes, _ := io.ReadAll(r.Body)
		vals, _ := url.ParseQuery(string(bodyBytes))
		if vals.Get("grant_type") == "authorization_code" && claims.JTI != wantAuthCodeJTI {
			t.Errorf("Google DPoP jti mismatch for authorization_code: got %q, want %q", claims.JTI, wantAuthCodeJTI)
		}

		if claims.Nonce != "google-fresh-nonce-1" {
			w.Header().Set("DPoP-Nonce", "google-fresh-nonce-1")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce","error_description":"Nonce required"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"access_token": "ya29.dpop-bound-token",
			"refresh_token": "1//0g-hardware-bound-rt",
			"token_type": "DPoP",
			"expires_in": 3600
		}`))
	})

	mux.HandleFunc("/v1/resource", func(w http.ResponseWriter, r *http.Request) {
		resourceCalls.Add(1)
		if gotAuth := r.Header.Get("Authorization"); gotAuth != "DPoP ya29.dpop-bound-token" {
			t.Errorf("expected upgraded Authorization: DPoP header, got %q", gotAuth)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		proof := r.Header.Get("DPoP")
		_, payloadRaw, err := jws.VerifyCompactJWT(proof, &priv.PublicKey)
		if err != nil {
			t.Errorf("resource DPoP verification failed: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var claims ProofClaims
		_ = json.Unmarshal(payloadRaw, &claims)
		atSum := sha256.Sum256([]byte("ya29.dpop-bound-token"))
		wantATH := base64.RawURLEncoding.EncodeToString(atSum[:])
		if claims.ATH != wantATH {
			t.Errorf("ath mismatch: got %q, want %q", claims.ATH, wantATH)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	dt, err := NewTransport(TransportOptions{
		Base:     srv.Client().Transport,
		Prover:   prover,
		Config:   config.DPoPConfig{Enforcement: "enforce"},
		TokenURL: srv.URL + "/token",
	})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: dt}

	// 1. Authorization code exchange: server challenges with 400 use_dpop_nonce on attempt 1,
	//    Transport transparently retries attempt 2, and rewrites token_type "DPoP" -> "Bearer" for legacy client!
	form := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {authCode},
		"client_id":  {"legacy-app"},
	}
	resp, err := client.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected transparent 200 OK after use_dpop_nonce retry, got %d", resp.StatusCode)
	}
	if tokenCalls.Load() != 2 {
		t.Fatalf("expected 2 upstream /token calls (challenge + retry), got %d", tokenCalls.Load())
	}

	var tokDoc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&tokDoc)
	if tokDoc["token_type"] != "Bearer" {
		t.Fatalf("expected legacy-compatible token_type=Bearer, got %v", tokDoc["token_type"])
	}

	// 2. Subsequent refresh_token request uses cached nonce on first try (1 upstream call, random jti)!
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"1//0g-hardware-bound-rt"},
	}
	resp2, err := client.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(refreshForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK || tokenCalls.Load() != 3 {
		t.Fatalf("expected cached nonce to succeed in 1 call (total=3), got status=%d total=%d", resp2.StatusCode, tokenCalls.Load())
	}

	// 3. Downstream resource call using standard "Authorization: Bearer <token>" from unaware client
	//    is transparently upgraded to "Authorization: DPoP <token>" + "DPoP: <proof-with-ath>"!
	resReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/resource", nil)
	resReq.Header.Set("Authorization", "Bearer ya29.dpop-bound-token")
	resResp, err := client.Do(resReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = resResp.Body.Close()
	if resResp.StatusCode != http.StatusOK || resourceCalls.Load() != 1 {
		t.Fatalf("expected resource call 200 OK, got %d", resResp.StatusCode)
	}
}
