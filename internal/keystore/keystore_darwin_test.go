//go:build darwin && cgo

package keystore

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jay0lee/gcds-in-the-cloud/internal/jws"
)

func TestDarwinSecureEnclaveAndKeychainSigner(t *testing.T) {
	prov, err := NewSecureEnclaveProvider()
	if err != nil {
		t.Fatalf("NewSecureEnclaveProvider: %v", err)
	}
	defer prov.Close()

	ctx := context.Background()
	ecKeyID := fmt.Sprintf("com.jay.go-oauth-proxy.test.p256.%d", time.Now().UnixNano())
	defer func() { _ = prov.DeleteKey(ecKeyID) }()

	ecSigner, ecMeta, err := prov.EnsureKey(ctx, KeySpec{
		KeyID:      ecKeyID,
		Algorithm:  AlgES256,
		Persistent: false,
	})
	if err != nil {
		t.Fatalf("EnsureKey(AlgES256): %v", err)
	}
	if ecMeta.Algorithm != AlgES256 || ecMeta.ThumbprintJKT == "" {
		t.Fatalf("unexpected ES256 metadata: %+v", ecMeta)
	}
	t.Logf("Provisioned macOS Security.framework P-256 key (hardware_se=%v, jkt=%s)", ecMeta.HardwareBacked, ecMeta.ThumbprintJKT)

	jwtTok, err := jws.SignJWT(ecSigner, map[string]any{"typ": "dpop+jwt"}, map[string]any{"htm": "POST", "htu": "https://oauth2.googleapis.com/token"})
	if err != nil {
		t.Fatalf("SignJWT with macOS P-256 SecKeyRef: %v", err)
	}
	if _, _, err := jws.VerifyCompactJWT(jwtTok, ecSigner.Public()); err != nil {
		t.Fatalf("VerifyCompactJWT failed for macOS P-256 signature: %v", err)
	}

	rsaKeyID := fmt.Sprintf("com.jay.go-oauth-proxy.test.rsa2048.%d", time.Now().UnixNano())
	defer func() { _ = prov.DeleteKey(rsaKeyID) }()

	rsaSigner, rsaMeta, err := prov.EnsureKey(ctx, KeySpec{
		KeyID:      rsaKeyID,
		Algorithm:  AlgRS256,
		RSABits:    2048,
		Persistent: false,
	})
	if err != nil {
		t.Fatalf("EnsureKey(AlgRS256): %v", err)
	}
	if rsaMeta.Algorithm != AlgRS256 {
		t.Fatalf("expected RS256, got %s", rsaMeta.Algorithm)
	}
	rsaJWT, err := jws.SignJWT(rsaSigner, map[string]any{"typ": "JWT"}, map[string]any{"iss": "sa@proj.iam.gserviceaccount.com"})
	if err != nil {
		t.Fatalf("SignJWT with macOS RSA-2048 SecKeyRef: %v", err)
	}
	if _, _, err := jws.VerifyCompactJWT(rsaJWT, rsaSigner.Public()); err != nil {
		t.Fatalf("VerifyCompactJWT failed for macOS RSA-2048 signature: %v", err)
	}
}
