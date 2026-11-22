package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"cloud.google.com/go/auth"
	"github.com/jay0lee/gcds-in-the-cloud/internal/adc"
	"github.com/jay0lee/gcds-in-the-cloud/internal/ca"
	"github.com/jay0lee/gcds-in-the-cloud/internal/config"
	"github.com/jay0lee/gcds-in-the-cloud/internal/keystore"
	"github.com/jay0lee/gcds-in-the-cloud/internal/proxy"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	subcmd := os.Args[1]
	switch subcmd {
	case "serve":
		runServe(os.Args[2:])
	case "init-ca":
		runInitCA(os.Args[2:])
	case "init-keys":
		runInitKeys(os.Args[2:])
	case "trust-info":
		runTrustInfo(os.Args[2:])
	case "validate-config":
		runValidateConfig(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", subcmd)
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `go-oauth-proxy - Hardware-backed Google OAuth DPoP & Keyless Auth Translation Proxy

Usage:
  go-oauth-proxy <command> [flags]

Commands:
  serve            Run the local forward CONNECT and/or reverse authentication proxy
  init-ca          Provision hardware-backed Root CA key and export public CA certificate PEM
  init-keys        Provision hardware-backed DPoP (P-256) and optional SA (RSA-2048) keys
  trust-info       Print GCDS Java keytool, proxy settings, and gcloud onboarding commands
  validate-config  Validate configuration syntax and keyless security invariants
`)
}

func openKeystoreAndADC(ctx context.Context, cfg *config.Config) (keystore.KeyProvider, *auth.Credentials, error) {
	if cfg.Keystore.Backend == "cloud_hsm" {
		if cfg.ADC.Mode == "wif_x509_mtls" {
			return nil, nil, errors.New("cannot bootstrap cloud_hsm keystore using wif_x509_mtls on the same keystore; use default/impersonate ADC or a local hardware keystore")
		}
		creds, err := adc.NewCredentials(ctx, adc.Options{
			ADC:      cfg.ADC,
			Upstream: cfg.Upstream,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("init keyless ADC for Cloud HSM: %w", err)
		}
		ks, err := keystore.Open(ctx, cfg.Keystore, creds)
		if err != nil {
			return nil, nil, err
		}
		return ks, creds, nil
	}

	ks, err := keystore.Open(ctx, cfg.Keystore, nil)
	if err != nil {
		return nil, nil, err
	}
	creds, err := adc.NewCredentials(ctx, adc.Options{
		ADC:      cfg.ADC,
		Upstream: cfg.Upstream,
		Keystore: ks,
	})
	if err != nil {
		_ = ks.Close()
		return nil, nil, fmt.Errorf("init keyless ADC: %w", err)
	}
	return ks, creds, nil
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/config.yaml", "Path to YAML/JSON configuration file")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatalf("configuration error: %v", err)
	}

	logger := proxy.NewRedactingLogger(os.Stderr, cfg.Server.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ks, adcCreds, err := openKeystoreAndADC(ctx, cfg)
	if err != nil {
		fatalf("bootstrap keystore/ADC failed: %v", err)
	}
	defer ks.Close()

	var authority *ca.Authority
	if cfg.Server.ListenConnect != "" {
		authority, err = ca.InitOrLoad(ctx, cfg.CA, ks)
		if err != nil {
			fatalf("initialize local Root CA failed: %v", err)
		}
	}

	engine, err := proxy.NewEngine(ctx, proxy.EngineOptions{
		Config:   cfg,
		Keystore: ks,
		ADCCreds: adcCreds,
		Logger:   logger,
	})
	if err != nil {
		fatalf("initialize policy engine failed: %v", err)
	}

	srv, err := proxy.NewServer(proxy.ServerOptions{
		Config:    cfg,
		Engine:    engine,
		Authority: authority,
		Logger:    logger,
	})
	if err != nil {
		fatalf("create proxy server failed: %v", err)
	}
	if err := srv.Start(); err != nil {
		fatalf("start proxy server failed: %v", err)
	}

	logger.Info("go-oauth-proxy listening",
		"connect_addr", srv.ConnectAddr(),
		"reverse_addr", srv.ReverseAddr(),
		"keystore_backend", ks.Backend(),
		"adc_mode", cfg.ADC.Mode,
		"dpop_jkt", engine.DPoPThumbprint(),
	)

	<-ctx.Done()
	logger.Info("shutting down go-oauth-proxy...")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		logger.Error("graceful shutdown error", "err", err)
	}
}

func runInitCA(args []string) {
	fs := flag.NewFlagSet("init-ca", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/config.yaml", "Path to YAML/JSON configuration file")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatalf("configuration error: %v", err)
	}
	if cfg.CA.CertPath == "" {
		fatalf("ca.cert_path must be set in %s to export the public Root CA certificate", *cfgPath)
	}

	ctx := context.Background()
	ks, err := keystore.Open(ctx, cfg.Keystore, nil)
	if err != nil {
		fatalf("open keystore: %v", err)
	}
	defer ks.Close()

	authority, err := ca.InitOrLoad(ctx, cfg.CA, ks)
	if err != nil {
		fatalf("init-ca failed: %v", err)
	}
	fp := sha256.Sum256(authority.RootCertificate().Raw)
	fmt.Printf("Initialized hardware-backed Root CA\n")
	fmt.Printf("  Keystore Backend : %s\n", ks.Backend())
	fmt.Printf("  CA Key ID        : %s\n", cfg.CA.KeyID)
	fmt.Printf("  Public Cert Path : %s\n", cfg.CA.CertPath)
	fmt.Printf("  SHA-256 Thumb    : %s\n", hex.EncodeToString(fp[:]))
}

func runInitKeys(args []string) {
	fs := flag.NewFlagSet("init-keys", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/config.yaml", "Path to YAML/JSON configuration file")
	exportSACertDir := fs.String("export-sa-cert-dir", "", "Optional directory to write public X.509 certs for hardware_key SA policies")
	exportWIFCSR := fs.String("export-wif-csr", "", "Optional file path to write an X.509 CSR PEM for adc.wif_x509.key_id")
	wifCSRCommonName := fs.String("wif-csr-cn", "gcds-proxy-host", "Common Name (CN) for the exported WIF X.509 CSR")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatalf("configuration error: %v", err)
	}

	ctx := context.Background()
	ks, err := keystore.Open(ctx, cfg.Keystore, nil)
	if err != nil {
		fatalf("open keystore: %v", err)
	}
	defer ks.Close()

	var provisioned []keystore.KeyMetadata
	_, dpopMeta, err := ks.EnsureKey(ctx, keystore.KeySpec{
		KeyID:      cfg.Keystore.DPoPKeyID,
		Algorithm:  keystore.AlgES256,
		Persistent: true,
	})
	if err != nil {
		fatalf("provision DPoP key %q: %v", cfg.Keystore.DPoPKeyID, err)
	}
	provisioned = append(provisioned, dpopMeta)

	if cfg.ADC.Mode == "wif_x509_mtls" && cfg.ADC.WIFX509 != nil && cfg.ADC.WIFX509.KeyID != "" {
		wifSigner, wifMeta, wErr := ks.EnsureKey(ctx, keystore.KeySpec{
			KeyID:      cfg.ADC.WIFX509.KeyID,
			Algorithm:  keystore.AlgES256,
			Persistent: true,
		})
		if wErr != nil {
			fatalf("provision WIF X.509 mTLS hardware key %q: %v", cfg.ADC.WIFX509.KeyID, wErr)
		}
		provisioned = append(provisioned, wifMeta)

		if *exportWIFCSR != "" {
			if err := writeWIFCSR(*exportWIFCSR, *wifCSRCommonName, wifSigner); err != nil {
				fatalf("export WIF X.509 CSR: %v", err)
			}
			fmt.Fprintf(os.Stderr, "Exported hardware-signed WIF X.509 CSR: %s\n", *exportWIFCSR)
		}
	}

	for _, pol := range cfg.Policies {
		if pol.Mode == "auth_replace" && pol.SigningMethod == "hardware_key" && pol.SigningKeyID != "" {
			saSigner, saMeta, sErr := ks.EnsureKey(ctx, keystore.KeySpec{
				KeyID:      pol.SigningKeyID,
				Algorithm:  keystore.AlgRS256,
				RSABits:    2048,
				Persistent: true,
			})
			if sErr != nil {
				fatalf("provision hardware RSA-2048 key %q for policy %q: %v", pol.SigningKeyID, pol.Name, sErr)
			}
			provisioned = append(provisioned, saMeta)

			if *exportSACertDir != "" {
				certPath := fmt.Sprintf("%s/%s.crt.pem", *exportSACertDir, pol.SigningKeyID)
				if err := writeSelfSignedPublicSACert(certPath, pol.ServiceAccount, saSigner); err != nil {
					fatalf("export public X.509 cert for %q: %v", pol.SigningKeyID, err)
				}
				fmt.Fprintf(os.Stderr, "Exported public SA upload cert: %s\n", certPath)
			}
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(provisioned)
}

func writeSelfSignedPublicSACert(outPath, saEmail string, signer crypto.Signer) error {
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: saEmail,
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(90 * 24 * time.Hour), // 90-day best-practice rotation window
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return os.WriteFile(outPath, pemBytes, 0o644)
}

func writeWIFCSR(outPath, commonName string, signer crypto.Signer) error {
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
	}, signer)
	if err != nil {
		return err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return os.WriteFile(outPath, csrPEM, 0o644)
}

func runTrustInfo(args []string) {
	fs := flag.NewFlagSet("trust-info", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/config.yaml", "Path to YAML/JSON configuration file")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatalf("configuration error: %v", err)
	}
	certPath := cfg.CA.CertPath
	if certPath == "" {
		certPath = "/etc/go-oauth-proxy/ca.crt"
	}
	proxyAddr := cfg.Server.ListenConnect
	if proxyAddr == "" {
		proxyAddr = "127.0.0.1:8443"
	}

	fmt.Printf(`=== go-oauth-proxy Onboarding & Client Trust Instructions ===

1. Import Local Root CA into GCDS (Google Cloud Directory Sync) Bundled Java Truststore:
   keytool -import -trustcacerts \
     -keystore "/path/to/Google/Cloud Directory Sync/jre/lib/security/cacerts" \
     -storepass changeit \
     -alias go-oauth-proxy-local-ca \
     -file %q

2. Point GCDS to Local Forward Proxy:
   - In GCDS Configuration Manager -> Google Domain Configuration -> Proxy Settings:
       Proxy Host: 127.0.0.1 (from %s)
   - Or via JVM flags (.vmoptions):
       -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=8443

3. (Optional) Zero-Network-Hop Hardware RSA-2048 Service Account Key Upload:
   gcloud iam service-accounts keys upload /path/to/<signing_key_id>.crt.pem \
     --iam-account=<service-account>@<project>.iam.gserviceaccount.com

4. CLI / SDK Environment Variables:
   export HTTPS_PROXY="http://%s"
   export SSL_CERT_FILE=%q
`, certPath, proxyAddr, proxyAddr, certPath)
}

func runValidateConfig(args []string) {
	fs := flag.NewFlagSet("validate-config", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/config.yaml", "Path to YAML/JSON configuration file")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatalf("INVALID: %v", err)
	}
	fmt.Printf("VALID: %s (keystore=%s, adc=%s, policies=%d)\n",
		*cfgPath, cfg.Keystore.Backend, cfg.ADC.Mode, len(cfg.Policies))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "go-oauth-proxy: "+format+"\n", args...)
	os.Exit(1)
}
