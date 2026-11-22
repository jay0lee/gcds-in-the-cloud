package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRejectPlaintextServiceAccountJSONKey(t *testing.T) {
	dir := t.TempDir()
	saKeyFile := filepath.Join(dir, "downloaded-sa-key.json")
	err := os.WriteFile(saKeyFile, []byte(`{
		"type": "service_account",
		"project_id": "demo",
		"private_key_id": "abc123",
		"private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n",
		"client_email": "bad@demo.iam.gserviceaccount.com"
	}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	rawCfg := []byte(`
server:
  listen_reverse: "127.0.0.1:8080"
keystore:
  backend: "ephemeral_memory"
  allow_ephemeral_keys: true
adc:
  mode: "default"
  credentials_file: "` + saKeyFile + `"
policies:
  - name: "p1"
    mode: "dpop_passthrough"
`)
	_, parseErr := Parse(rawCfg)
	if !errors.Is(parseErr, ErrPlaintextServiceAccountKey) {
		t.Fatalf("expected ErrPlaintextServiceAccountKey, got: %v", parseErr)
	}
}

func TestAcceptKeylessExternalAccountWIFJSON(t *testing.T) {
	dir := t.TempDir()
	wifFile := filepath.Join(dir, "wif-x509.json")
	err := os.WriteFile(wifFile, []byte(`{
		"type": "external_account",
		"audience": "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/x509",
		"subject_token_type": "urn:ietf:params:oauth:token-type:mtls",
		"token_url": "https://sts.mtls.googleapis.com/v1/token"
	}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	rawCfg := []byte(`
server:
  listen_connect: "127.0.0.1:8443"
keystore:
  backend: "secure_enclave"
adc:
  mode: "impersonate"
  credentials_file: "` + wifFile + `"
  impersonate_service_account: "runner@sec.iam.gserviceaccount.com"
policies:
  - name: "pubsub-jwt"
    match_hosts: ["pubsub.googleapis.com"]
    mode: "auth_replace"
    strategy: "jwt_auth"
    service_account: "pubsub@sec.iam.gserviceaccount.com"
`)
	cfg, err := Parse(rawCfg)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
	if !cfg.IsHostAllowed("pubsub.googleapis.com") || !cfg.IsHostAllowed("oauth2.googleapis.com") {
		t.Fatalf("expected default googleapis wildcard allowlist")
	}
	if cfg.IsHostAllowed("evil-googleapis.com") || cfg.IsHostAllowed("example.com") {
		t.Fatalf("allowlist matched unauthorized domain")
	}
}

func TestRejectNonLoopbackBindByDefault(t *testing.T) {
	rawCfg := []byte(`
server:
  listen_connect: "0.0.0.0:8443"
keystore:
  backend: "secure_enclave"
policies:
  - name: "p1"
    mode: "dpop_passthrough"
`)
	if _, err := Parse(rawCfg); err == nil {
		t.Fatal("expected error when binding to 0.0.0.0 without allow_non_loopback")
	}
}
