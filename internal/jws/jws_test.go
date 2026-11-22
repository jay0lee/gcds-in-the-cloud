package jws

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"testing"
)

func TestSignAndVerifyES256AndRS256(t *testing.T) {
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubJWK, alg, err := PublicJWKFromKey(&ecPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if alg != "ES256" || pubJWK.Kty != "EC" || pubJWK.Crv != "P-256" {
		t.Fatalf("unexpected EC JWK: %+v alg=%s", pubJWK, alg)
	}
	jkt, err := pubJWK.ThumbprintSHA256()
	if err != nil || len(jkt) != 43 {
		t.Fatalf("expected 43-char base64url SHA-256 thumbprint, got %q (err=%v)", jkt, err)
	}

	tok, err := SignJWT(ecPriv, map[string]any{"typ": "dpop+jwt", "jwk": pubJWK}, map[string]any{"htm": "POST"})
	if err != nil {
		t.Fatal(err)
	}
	hdrBytes, payloadBytes, err := VerifyCompactJWT(tok, &ecPriv.PublicKey)
	if err != nil {
		t.Fatalf("VerifyCompactJWT(ES256) failed: %v", err)
	}
	var hdr map[string]any
	_ = json.Unmarshal(hdrBytes, &hdr)
	if hdr["alg"] != "ES256" || hdr["typ"] != "dpop+jwt" {
		t.Fatalf("unexpected header: %v", hdr)
	}
	if string(payloadBytes) != `{"htm":"POST"}` {
		t.Fatalf("unexpected payload: %s", payloadBytes)
	}

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaTok, err := SignJWT(rsaPriv, map[string]any{"typ": "JWT", "kid": "k1"}, map[string]any{"iss": "sa@proj.iam.gserviceaccount.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyCompactJWT(rsaTok, &rsaPriv.PublicKey); err != nil {
		t.Fatalf("VerifyCompactJWT(RS256) failed: %v", err)
	}
}

func TestECDSALeadingZeroPaddingInJWSNormalization(t *testing.T) {
	// Ensure R/S integers smaller than 32 bytes are left-padded with 0x00 to 32 bytes each.
	rawSmall := make([]byte, 64)
	rawSmall[31] = 0x07 // R = 7
	rawSmall[63] = 0x09 // S = 9
	der, err := RawECDSAToASN1DER(rawSmall)
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizeSignatureForJWS("ES256", der)
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized) != 64 {
		t.Fatalf("expected 64-byte normalized signature, got %d", len(normalized))
	}
	if new(big.Int).SetBytes(normalized[:32]).Int64() != 7 || new(big.Int).SetBytes(normalized[32:]).Int64() != 9 {
		t.Fatalf("corrupted R/S values after DER->JWS roundtrip")
	}
}
