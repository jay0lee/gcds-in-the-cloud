package adc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cloud.google.com/go/auth"
)

// IAMJWTSigner delegates Service Account JWT signing to Google Cloud's IAM Service Account
// Credentials API (projects/-/serviceAccounts/{sa}:signJwt) using Google-managed keys,
// completely eliminating user-managed service account private keys.
type IAMJWTSigner struct {
	creds      *auth.Credentials
	baseURL    string
	httpClient *http.Client
}

func NewIAMJWTSigner(creds *auth.Credentials, iamBaseURL string, httpClient *http.Client) (*IAMJWTSigner, error) {
	if creds == nil {
		return nil, errors.New("adc/iam_signer: keyless ADC credentials are required for iam_sign_jwt")
	}
	if iamBaseURL == "" {
		iamBaseURL = "https://iamcredentials.googleapis.com"
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &IAMJWTSigner{
		creds:      creds,
		baseURL:    strings.TrimRight(iamBaseURL, "/"),
		httpClient: httpClient,
	}, nil
}

// SignJWT serializes claims and requests Google IAM to sign the JWT with the Service Account's
// Google-managed RS256 key. Requires roles/iam.serviceAccountTokenCreator on serviceAccountEmail.
func (s *IAMJWTSigner) SignJWT(ctx context.Context, serviceAccountEmail string, claims any) (signedJWT string, keyID string, err error) {
	if serviceAccountEmail == "" {
		return "", "", errors.New("adc/iam_signer: serviceAccountEmail is empty")
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", "", fmt.Errorf("adc/iam_signer: marshal JWT claims: %w", err)
	}

	tok, err := s.creds.Token(ctx)
	if err != nil {
		return "", "", fmt.Errorf("adc/iam_signer: fetch ADC token: %w", err)
	}

	reqBody, err := json.Marshal(struct {
		Payload string `json:"payload"`
	}{
		Payload: string(claimsBytes),
	})
	if err != nil {
		return "", "", err
	}

	endpoint := fmt.Sprintf("%s/v1/projects/-/serviceAccounts/%s:signJwt",
		s.baseURL, url.PathEscape(serviceAccountEmail))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok.Value)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("adc/iam_signer: call signJwt: %w", err)
	}
	defer resp.Body.Close()

	rawResp, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", "", fmt.Errorf("adc/iam_signer: read signJwt response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("adc/iam_signer: signJwt returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(rawResp)))
	}

	var parsed struct {
		KeyID     string `json:"keyId"`
		SignedJWT string `json:"signedJwt"`
	}
	if err := json.Unmarshal(rawResp, &parsed); err != nil {
		return "", "", fmt.Errorf("adc/iam_signer: decode signJwt JSON: %w", err)
	}
	if parsed.SignedJWT == "" {
		return "", "", errors.New("adc/iam_signer: signJwt returned empty signedJwt")
	}
	return parsed.SignedJWT, parsed.KeyID, nil
}
