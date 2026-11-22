package adc

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/credentials"
	"cloud.google.com/go/auth/credentials/externalaccount"
	"cloud.google.com/go/auth/credentials/impersonate"
	"github.com/jay0lee/gcds-in-the-cloud/internal/config"
	"github.com/jay0lee/gcds-in-the-cloud/internal/keystore"
)

const defaultCloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

// Options configures keyless Google Application Default Credentials creation.
type Options struct {
	ADC         config.ADCConfig
	Upstream    config.UpstreamEndpointsConfig
	Keystore    keystore.KeyProvider
	BaseTLS     *tls.Config // Optional custom root CAs (e.g., for testing or private PKI)
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	HTTPTimeout time.Duration
}

// NewCredentials initializes keyless Google Cloud credentials following Google's
// Service Account security best practices (banning static JSON private keys and supporting
// hardware-backed X.509 mTLS Workload Identity Federation, GCE metadata, and SA impersonation).
func NewCredentials(ctx context.Context, opts Options) (*auth.Credentials, error) {
	if opts.HTTPTimeout <= 0 {
		opts.HTTPTimeout = 15 * time.Second
	}
	scopes := opts.ADC.Scopes
	if len(scopes) == 0 {
		scopes = []string{defaultCloudPlatformScope}
	}

	switch opts.ADC.Mode {
	case "disabled":
		return nil, nil

	case "wif_x509_mtls":
		return newHardwareWIFX509Credentials(ctx, opts, scopes)

	case "default", "impersonate":
		baseCreds, err := detectKeylessBaseCredentials(opts, scopes)
		if err != nil {
			return nil, err
		}
		if opts.ADC.Mode == "impersonate" || opts.ADC.ImpersonateServiceAccount != "" {
			if opts.ADC.ImpersonateServiceAccount == "" {
				return nil, errors.New("adc: impersonate_service_account is required when mode=impersonate")
			}
			var httpClient *http.Client
			if opts.BaseTLS != nil {
				httpClient = &http.Client{
					Timeout:   opts.HTTPTimeout,
					Transport: &http.Transport{TLSClientConfig: opts.BaseTLS.Clone()},
				}
			}
			return impersonate.NewCredentials(&impersonate.CredentialsOptions{
				TargetPrincipal: opts.ADC.ImpersonateServiceAccount,
				Delegates:       opts.ADC.Delegates,
				Scopes:          scopes,
				Credentials:     baseCreds,
				Client:          httpClient,
			})
		}
		return baseCreds, nil

	default:
		return nil, fmt.Errorf("adc: unsupported mode %q", opts.ADC.Mode)
	}
}

func detectKeylessBaseCredentials(opts Options, scopes []string) (*auth.Credentials, error) {
	if envPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); envPath != "" {
		if err := config.InspectCredentialFileForPlaintextKey(envPath); err != nil {
			return nil, err
		}
	}
	var httpClient *http.Client
	if opts.BaseTLS != nil {
		httpClient = &http.Client{
			Timeout:   opts.HTTPTimeout,
			Transport: &http.Transport{TLSClientConfig: opts.BaseTLS.Clone()},
		}
	}

	if opts.ADC.CredentialsFile != "" {
		raw, err := os.ReadFile(opts.ADC.CredentialsFile)
		if err != nil {
			return nil, fmt.Errorf("adc: read credentials_file: %w", err)
		}
		if err := config.InspectCredentialJSONForPlaintextKey(raw); err != nil {
			return nil, err
		}
		var doc struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("adc: parse credential JSON type: %w", err)
		}
		credType := credentials.CredType(doc.Type)
		if credType == credentials.ServiceAccount {
			return nil, config.ErrPlaintextServiceAccountKey
		}
		return credentials.NewCredentialsFromJSON(credType, raw, &credentials.DetectOptions{
			Scopes: scopes,
			Client: httpClient,
		})
	}

	return credentials.DetectDefault(&credentials.DetectOptions{
		Scopes: scopes,
		Client: httpClient,
	})
}

type x509ChainSubjectTokenProvider struct {
	encodedChainJSON string
}

func (p *x509ChainSubjectTokenProvider) SubjectToken(_ context.Context, _ *externalaccount.RequestOptions) (string, error) {
	return p.encodedChainJSON, nil
}

// newHardwareWIFX509Credentials builds AIP-4118 Workload Identity Federation X.509 mTLS credentials
// where the TLS client handshake is performed directly by a non-exportable hardware crypto.Signer.
func newHardwareWIFX509Credentials(ctx context.Context, opts Options, defaultScopes []string) (*auth.Credentials, error) {
	wif := opts.ADC.WIFX509
	if wif == nil {
		return nil, errors.New("adc: wif_x509 config is nil")
	}
	if opts.Keystore == nil {
		return nil, errors.New("adc: hardware keystore is required for wif_x509_mtls")
	}

	hwSigner, err := opts.Keystore.Signer(ctx, wif.KeyID)
	if err != nil {
		return nil, fmt.Errorf("adc/wif_x509: load hardware signer %q: %w", wif.KeyID, err)
	}

	leafCerts, err := keystore.LoadPEMCertificates(wif.LeafCertPath)
	if err != nil {
		return nil, fmt.Errorf("adc/wif_x509: load leaf_cert_path: %w", err)
	}
	leaf := leafCerts[0]

	chainDER := [][]byte{leaf.Raw}
	chainB64 := []string{base64.StdEncoding.EncodeToString(leaf.Raw)}

	for _, extra := range leafCerts[1:] {
		chainDER = append(chainDER, extra.Raw)
		chainB64 = append(chainB64, base64.StdEncoding.EncodeToString(extra.Raw))
	}
	if wif.TrustChainPath != "" {
		intermediates, err := keystore.LoadPEMCertificates(wif.TrustChainPath)
		if err != nil {
			return nil, fmt.Errorf("adc/wif_x509: load trust_chain_path: %w", err)
		}
		for _, ic := range intermediates {
			chainDER = append(chainDER, ic.Raw)
			chainB64 = append(chainB64, base64.StdEncoding.EncodeToString(ic.Raw))
		}
	}

	subjectTokenBytes, err := json.Marshal(chainB64)
	if err != nil {
		return nil, fmt.Errorf("adc/wif_x509: encode X.509 chain subject token: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: chainDER,
		PrivateKey:  hwSigner,
		Leaf:        leaf,
	}

	var tlsCfg *tls.Config
	if opts.BaseTLS != nil {
		tlsCfg = opts.BaseTLS.Clone()
	} else {
		tlsCfg = &tls.Config{}
	}
	tlsCfg.MinVersion = tls.VersionTLS13
	tlsCfg.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return tlsCert, nil
	}

	mtlsClient := &http.Client{
		Timeout: opts.HTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig:     tlsCfg,
			DialContext:         opts.DialContext,
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 8,
		},
	}

	stsURL := wif.STSMTLSEndpoint
	if stsURL == "" {
		stsURL = opts.Upstream.STSMTLSTokenURL
	}
	if stsURL == "" {
		stsURL = "https://sts.mtls.googleapis.com/v1/token"
	}

	scopes := wif.Scopes
	if len(scopes) == 0 {
		scopes = defaultScopes
	}

	targetSA := wif.ServiceAccountEmail
	if targetSA == "" {
		targetSA = opts.ADC.ImpersonateServiceAccount
	}
	var impersonationURL string
	if targetSA != "" {
		iamBase := strings.TrimRight(opts.Upstream.IAMCredentialsURL, "/")
		if iamBase == "" {
			iamBase = "https://iamcredentials.googleapis.com"
		}
		impersonationURL = fmt.Sprintf("%s/v1/projects/-/serviceAccounts/%s:generateAccessToken", iamBase, targetSA)
	}

	return externalaccount.NewCredentials(&externalaccount.Options{
		Audience:                       wif.Audience,
		SubjectTokenType:               "urn:ietf:params:oauth:token-type:mtls",
		TokenURL:                       stsURL,
		ServiceAccountImpersonationURL: impersonationURL,
		Scopes:                         scopes,
		SubjectTokenProvider:           &x509ChainSubjectTokenProvider{encodedChainJSON: string(subjectTokenBytes)},
		Client:                         mtlsClient,
	})
}
