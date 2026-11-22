package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ErrPlaintextServiceAccountKey is returned when a static JSON service account key file is detected.
var ErrPlaintextServiceAccountKey = errors.New("security policy violation: plaintext service account private key files are forbidden; use keyless ADC (Workload Identity Federation X.509 mTLS, impersonation, or metadata server) and hardware-backed key storage")

// Config defines the declarative runtime configuration for go-oauth-proxy.
type Config struct {
	Server   ServerConfig            `yaml:"server" json:"server"`
	CA       CAConfig                `yaml:"ca" json:"ca"`
	Keystore KeystoreConfig          `yaml:"keystore" json:"keystore"`
	ADC      ADCConfig               `yaml:"adc" json:"adc"`
	Clients  map[string]ClientAuth   `yaml:"clients,omitempty" json:"clients,omitempty"`
	Policies []PolicyConfig          `yaml:"policies" json:"policies"`
	Upstream UpstreamEndpointsConfig `yaml:"upstream,omitempty" json:"upstream,omitempty"`
}

// ServerConfig configures local listeners, caller verification, and host allowlists.
type ServerConfig struct {
	ListenConnect        string        `yaml:"listen_connect" json:"listen_connect"`
	ListenReverse        string        `yaml:"listen_reverse" json:"listen_reverse"`
	AllowNonLoopback     bool          `yaml:"allow_non_loopback" json:"allow_non_loopback"`
	AllowedHosts         []string      `yaml:"allowed_hosts" json:"allowed_hosts"`
	PassthroughUnmatched bool          `yaml:"passthrough_unmatched" json:"passthrough_unmatched"`
	AllowedPeerUIDs      []uint32      `yaml:"allowed_peer_uids,omitempty" json:"allowed_peer_uids,omitempty"`
	RequireProxyAuth     bool          `yaml:"require_proxy_auth" json:"require_proxy_auth"`
	ReadHeaderTimeout    time.Duration `yaml:"read_header_timeout" json:"read_header_timeout"`
	LogLevel             string        `yaml:"log_level" json:"log_level"`
}

// ClientAuth maps local Proxy-Authorization Basic credentials to named client profiles (e.g., "gcds").
type ClientAuth struct {
	Username       string `yaml:"username" json:"username"`
	PasswordEnv    string `yaml:"password_env,omitempty" json:"password_env,omitempty"`
	PasswordSHA256 string `yaml:"password_sha256,omitempty" json:"password_sha256,omitempty"`
}

// CAConfig configures the local Root CA used for scoped HTTPS CONNECT interception.
type CAConfig struct {
	CertPath    string        `yaml:"cert_path" json:"cert_path"`
	KeyID       string        `yaml:"key_id" json:"key_id"`
	CommonName  string        `yaml:"common_name" json:"common_name"`
	LeafTTL     time.Duration `yaml:"leaf_ttl" json:"leaf_ttl"`
	MaxCacheLen int           `yaml:"max_cache_len" json:"max_cache_len"`
}

// KeystoreConfig configures hardware-backed asymmetric key storage via crypto.Signer.
type KeystoreConfig struct {
	// Backend options: secure_enclave | tpm2 | windows_cng | pkcs11 | cloud_hsm | ecp | ephemeral_memory
	Backend            string       `yaml:"backend" json:"backend"`
	AllowEphemeralKeys bool         `yaml:"allow_ephemeral_keys" json:"allow_ephemeral_keys"`
	DPoPKeyID          string       `yaml:"dpop_key_id" json:"dpop_key_id"`
	TPM2               TPM2Config   `yaml:"tpm2,omitempty" json:"tpm2,omitempty"`
	WindowsCNG         CNGConfig    `yaml:"windows_cng,omitempty" json:"windows_cng,omitempty"`
	PKCS11             PKCS11Config `yaml:"pkcs11,omitempty" json:"pkcs11,omitempty"`
	CloudHSM           HSMConfig    `yaml:"cloud_hsm,omitempty" json:"cloud_hsm,omitempty"`
	ECP                ECPConfig    `yaml:"ecp,omitempty" json:"ecp,omitempty"`
}

type TPM2Config struct {
	DevicePath string            `yaml:"device_path" json:"device_path"` // Default: /dev/tpmrm0
	Handles    map[string]uint32 `yaml:"handles,omitempty" json:"handles,omitempty"`
	CertPaths  map[string]string `yaml:"cert_paths,omitempty" json:"cert_paths,omitempty"`
}

type CNGConfig struct {
	ProviderName string            `yaml:"provider_name" json:"provider_name"` // Default: Microsoft Platform Crypto Provider
	MachineKey   bool              `yaml:"machine_key" json:"machine_key"`
	CertPaths    map[string]string `yaml:"cert_paths,omitempty" json:"cert_paths,omitempty"`
}

type PKCS11Config struct {
	ModulePath string            `yaml:"module_path" json:"module_path"`
	TokenLabel string            `yaml:"token_label" json:"token_label"`
	SlotNumber *int              `yaml:"slot_number,omitempty" json:"slot_number,omitempty"`
	PinEnv     string            `yaml:"pin_env" json:"pin_env"`
	CertPaths  map[string]string `yaml:"cert_paths,omitempty" json:"cert_paths,omitempty"`
}

type HSMConfig struct {
	// Maps logical keyID -> projects/{p}/locations/{l}/keyRings/{kr}/cryptoKeys/{ck}/cryptoKeyVersions/{v}
	KeyVersions map[string]string `yaml:"key_versions" json:"key_versions"`
	CertPaths   map[string]string `yaml:"cert_paths,omitempty" json:"cert_paths,omitempty"`
}

type ECPConfig struct {
	ConfigPath string `yaml:"config_path" json:"config_path"`
}

// ADCConfig configures keyless Google Application Default Credentials and Workload Identity Federation.
type ADCConfig struct {
	// Mode options: default | impersonate | wif_x509_mtls | disabled
	Mode                      string         `yaml:"mode" json:"mode"`
	CredentialsFile           string         `yaml:"credentials_file,omitempty" json:"credentials_file,omitempty"`
	ImpersonateServiceAccount string         `yaml:"impersonate_service_account,omitempty" json:"impersonate_service_account,omitempty"`
	Delegates                 []string       `yaml:"delegates,omitempty" json:"delegates,omitempty"`
	Scopes                    []string       `yaml:"scopes,omitempty" json:"scopes,omitempty"`
	WIFX509                   *WIFX509Config `yaml:"wif_x509,omitempty" json:"wif_x509,omitempty"`
}

// WIFX509Config configures hardware-backed X.509 mutual TLS Workload Identity Federation (AIP-4118).
type WIFX509Config struct {
	Audience             string   `yaml:"audience" json:"audience"` // //iam.googleapis.com/projects/{num}/locations/global/workloadIdentityPools/{pool}/providers/{prov}
	KeyID                string   `yaml:"key_id" json:"key_id"`     // Hardware key ID in Keystore
	LeafCertPath         string   `yaml:"leaf_cert_path" json:"leaf_cert_path"`
	TrustChainPath       string   `yaml:"trust_chain_path,omitempty" json:"trust_chain_path,omitempty"`
	STSMTLSEndpoint      string   `yaml:"sts_mtls_endpoint,omitempty" json:"sts_mtls_endpoint,omitempty"` // Default: https://sts.mtls.googleapis.com/v1/token
	ServiceAccountEmail  string   `yaml:"service_account_email,omitempty" json:"service_account_email,omitempty"`
	Scopes               []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`
}

// PolicyConfig defines how matching requests are authenticated or upgraded.
type PolicyConfig struct {
	Name          string     `yaml:"name" json:"name"`
	MatchClient   string     `yaml:"match_client,omitempty" json:"match_client,omitempty"`
	MatchHosts    []string   `yaml:"match_hosts,omitempty" json:"match_hosts,omitempty"`
	// Mode options: dpop_passthrough | auth_replace
	Mode          string     `yaml:"mode" json:"mode"`
	DPoP          DPoPConfig `yaml:"dpop,omitempty" json:"dpop,omitempty"`
	// Strategy options (when mode == auth_replace): jwt_auth | dwd_oauth | adc_bearer
	Strategy       string   `yaml:"strategy,omitempty" json:"strategy,omitempty"`
	ServiceAccount string   `yaml:"service_account,omitempty" json:"service_account,omitempty"`
	// SigningMethod options: iam_sign_jwt | hardware_key
	SigningMethod  string   `yaml:"signing_method,omitempty" json:"signing_method,omitempty"`
	SigningKeyID   string   `yaml:"signing_key_id,omitempty" json:"signing_key_id,omitempty"`
	PublicKeyID    string   `yaml:"public_key_id,omitempty" json:"public_key_id,omitempty"` // Optional kid header for uploaded SA cert
	Audience       string   `yaml:"audience,omitempty" json:"audience,omitempty"`           // Optional explicit JWT aud override
	UseScopeClaim  bool     `yaml:"use_scope_claim,omitempty" json:"use_scope_claim,omitempty"`
	DWDSubject     string   `yaml:"dwd_subject,omitempty" json:"dwd_subject,omitempty"` // Super-admin email for Workspace DWD
	Scopes         []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`
	EnableDPoP     bool     `yaml:"enable_dpop,omitempty" json:"enable_dpop,omitempty"` // Also attach DPoP on outbound DWD /token calls
}

type DPoPConfig struct {
	// Enforcement options: enforce | opportunistic
	Enforcement          string `yaml:"enforcement" json:"enforcement"`
	InjectAuthURLThumb   bool   `yaml:"inject_auth_url_jkt" json:"inject_auth_url_jkt"`
	ForceResignExisting  bool   `yaml:"force_resign_existing" json:"force_resign_existing"`
}

// UpstreamEndpointsConfig allows overriding Google endpoints for Sovereign Cloud, Universe Domain, or E2E testing.
type UpstreamEndpointsConfig struct {
	OAuthTokenURL     string `yaml:"oauth_token_url,omitempty" json:"oauth_token_url,omitempty"`
	IAMCredentialsURL string `yaml:"iam_credentials_url,omitempty" json:"iam_credentials_url,omitempty"`
	STSMTLSTokenURL   string `yaml:"sts_mtls_token_url,omitempty" json:"sts_mtls_token_url,omitempty"`
}

// Load reads and validates a YAML or JSON configuration file from disk.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	return Parse(raw)
}

// Parse unmarshals and validates YAML/JSON configuration bytes.
func Parse(raw []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.ReadHeaderTimeout == 0 {
		c.Server.ReadHeaderTimeout = 15 * time.Second
	}
	if c.Server.LogLevel == "" {
		c.Server.LogLevel = "info"
	}
	if len(c.Server.AllowedHosts) == 0 {
		c.Server.AllowedHosts = []string{
			"oauth2.googleapis.com",
			"accounts.google.com",
			"*.googleapis.com",
		}
	}
	if c.CA.CommonName == "" {
		c.CA.CommonName = "go-oauth-proxy Local Root CA"
	}
	if c.CA.KeyID == "" {
		c.CA.KeyID = "go-oauth-proxy-ca-p256"
	}
	if c.CA.LeafTTL == 0 {
		c.CA.LeafTTL = 24 * time.Hour
	}
	if c.CA.MaxCacheLen == 0 {
		c.CA.MaxCacheLen = 256
	}
	if c.Keystore.DPoPKeyID == "" {
		c.Keystore.DPoPKeyID = "go-oauth-proxy-dpop-p256"
	}
	if c.Keystore.TPM2.DevicePath == "" {
		c.Keystore.TPM2.DevicePath = "/dev/tpmrm0"
	}
	if c.Keystore.WindowsCNG.ProviderName == "" {
		c.Keystore.WindowsCNG.ProviderName = "Microsoft Platform Crypto Provider"
	}
	if c.ADC.Mode == "" {
		c.ADC.Mode = "default"
	}
	if c.Upstream.OAuthTokenURL == "" {
		c.Upstream.OAuthTokenURL = "https://oauth2.googleapis.com/token"
	}
	if c.Upstream.IAMCredentialsURL == "" {
		c.Upstream.IAMCredentialsURL = "https://iamcredentials.googleapis.com"
	}
	if c.Upstream.STSMTLSTokenURL == "" {
		c.Upstream.STSMTLSTokenURL = "https://sts.mtls.googleapis.com/v1/token"
	}
	for i := range c.Policies {
		if c.Policies[i].Mode == "dpop_passthrough" && c.Policies[i].DPoP.Enforcement == "" {
			c.Policies[i].DPoP.Enforcement = "enforce"
		}
		if c.Policies[i].Mode == "auth_replace" && c.Policies[i].SigningMethod == "" {
			c.Policies[i].SigningMethod = "iam_sign_jwt"
		}
	}
}

// Validate enforces structural correctness and Google keyless security invariants.
func (c *Config) Validate() error {
	if c.Server.ListenConnect == "" && c.Server.ListenReverse == "" {
		return errors.New("config: at least one of server.listen_connect or server.listen_reverse must be set")
	}
	if !c.Server.AllowNonLoopback {
		for _, addr := range []string{c.Server.ListenConnect, c.Server.ListenReverse} {
			if addr == "" {
				continue
			}
			if err := ensureLoopback(addr); err != nil {
				return fmt.Errorf("config: listener %q rejected: %w (set server.allow_non_loopback=true to override)", addr, err)
			}
		}
	}

	switch c.Keystore.Backend {
	case "secure_enclave", "tpm2", "windows_cng", "pkcs11", "cloud_hsm", "ecp":
	case "ephemeral_memory":
		if !c.Keystore.AllowEphemeralKeys {
			return errors.New("config: keystore.backend=ephemeral_memory requires keystore.allow_ephemeral_keys=true (use hardware backends in production)")
		}
	default:
		return fmt.Errorf("config: unsupported keystore.backend %q", c.Keystore.Backend)
	}

	if err := c.validateADCKeylessPolicy(); err != nil {
		return err
	}

	if len(c.Policies) == 0 {
		return errors.New("config: at least one policy must be configured under policies")
	}
	for i, p := range c.Policies {
		if p.Name == "" {
			return fmt.Errorf("config: policies[%d].name is required", i)
		}
		switch p.Mode {
		case "dpop_passthrough":
			if p.DPoP.Enforcement != "enforce" && p.DPoP.Enforcement != "opportunistic" {
				return fmt.Errorf("config: policy %q dpop.enforcement must be 'enforce' or 'opportunistic'", p.Name)
			}
		case "auth_replace":
			if err := validateAuthReplacePolicy(p); err != nil {
				return err
			}
		default:
			return fmt.Errorf("config: policy %q has unknown mode %q", p.Name, p.Mode)
		}
	}
	return nil
}

func validateAuthReplacePolicy(p PolicyConfig) error {
	switch p.Strategy {
	case "jwt_auth":
		if p.ServiceAccount == "" {
			return fmt.Errorf("config: policy %q (jwt_auth) requires service_account", p.Name)
		}
		if err := validateSigningMethod(p); err != nil {
			return err
		}
		if p.UseScopeClaim && len(p.Scopes) == 0 {
			return fmt.Errorf("config: policy %q (jwt_auth) with use_scope_claim=true requires scopes", p.Name)
		}
	case "dwd_oauth":
		if p.ServiceAccount == "" {
			return fmt.Errorf("config: policy %q (dwd_oauth) requires service_account", p.Name)
		}
		if p.DWDSubject == "" {
			return fmt.Errorf("config: policy %q (dwd_oauth) requires dwd_subject (Workspace super-admin email)", p.Name)
		}
		if len(p.Scopes) == 0 {
			return fmt.Errorf("config: policy %q (dwd_oauth) requires scopes", p.Name)
		}
		if err := validateSigningMethod(p); err != nil {
			return err
		}
	case "adc_bearer":
		// Uses ADC token source directly.
	default:
		return fmt.Errorf("config: policy %q has unsupported auth_replace strategy %q", p.Name, p.Strategy)
	}
	return nil
}

func validateSigningMethod(p PolicyConfig) error {
	switch p.SigningMethod {
	case "iam_sign_jwt":
		return nil
	case "hardware_key":
		if p.SigningKeyID == "" {
			return fmt.Errorf("config: policy %q with signing_method=hardware_key requires signing_key_id", p.Name)
		}
		return nil
	default:
		return fmt.Errorf("config: policy %q has invalid signing_method %q", p.Name, p.SigningMethod)
	}
}

func (c *Config) validateADCKeylessPolicy() error {
	switch c.ADC.Mode {
	case "disabled":
		return nil
	case "default", "impersonate":
		if c.ADC.Mode == "impersonate" && c.ADC.ImpersonateServiceAccount == "" {
			return errors.New("config: adc.mode=impersonate requires adc.impersonate_service_account")
		}
		if c.ADC.CredentialsFile != "" {
			if err := InspectCredentialFileForPlaintextKey(c.ADC.CredentialsFile); err != nil {
				return err
			}
		}
		if envCreds := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); envCreds != "" {
			if err := InspectCredentialFileForPlaintextKey(envCreds); err != nil {
				return fmt.Errorf("GOOGLE_APPLICATION_CREDENTIALS (%s): %w", envCreds, err)
			}
		}
		return nil
	case "wif_x509_mtls":
		if c.ADC.WIFX509 == nil {
			return errors.New("config: adc.mode=wif_x509_mtls requires adc.wif_x509 configuration")
		}
		if c.ADC.WIFX509.Audience == "" || c.ADC.WIFX509.KeyID == "" || c.ADC.WIFX509.LeafCertPath == "" {
			return errors.New("config: adc.wif_x509 requires audience, key_id, and leaf_cert_path")
		}
		return nil
	default:
		return fmt.Errorf("config: unsupported adc.mode %q", c.ADC.Mode)
	}
}

// InspectCredentialFileForPlaintextKey verifies that a GCP credential file does not contain
// a static downloaded service account private key ("type": "service_account" or "private_key").
func InspectCredentialFileForPlaintextKey(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read credential file %q: %w", path, err)
	}
	return InspectCredentialJSONForPlaintextKey(raw)
}

// InspectCredentialJSONForPlaintextKey inspects raw credential JSON bytes and rejects plaintext keys.
func InspectCredentialJSONForPlaintextKey(raw []byte) error {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("invalid JSON credential configuration: %w", err)
	}
	credType, _ := doc["type"].(string)
	if credType == "service_account" {
		return ErrPlaintextServiceAccountKey
	}
	if pk, hasPK := doc["private_key"]; hasPK && pk != "" {
		return ErrPlaintextServiceAccountKey
	}
	if pkID, hasPKID := doc["private_key_id"]; hasPKID && pkID != "" {
		return ErrPlaintextServiceAccountKey
	}
	return nil
}

func ensureLoopback(listenAddr string) error {
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return fmt.Errorf("invalid host:port %q: %w", listenAddr, err)
	}
	if host == "" {
		return errors.New("wildcard bind address (empty host) is not loopback; bind to 127.0.0.1 or [::1]")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("host %q is not a loopback address", host)
	}
	return nil
}

// IsHostAllowed checks whether host (without port) matches any entry in AllowedHosts.
func (c *Config) IsHostAllowed(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if parsedHost, _, err := net.SplitHostPort(h); err == nil {
		h = parsedHost
	}
	for _, pattern := range c.Server.AllowedHosts {
		p := strings.ToLower(strings.TrimSuffix(pattern, "."))
		if p == h {
			return true
		}
		if strings.HasPrefix(p, "*.") {
			suffix := p[1:] // ".googleapis.com"
			if strings.HasSuffix(h, suffix) && len(h) > len(suffix) {
				return true
			}
		}
	}
	return false
}
