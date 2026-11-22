# GCDS in the Cloud (`gcds-in-the-cloud`)

Run **Google Cloud Directory Sync (GCDS)** 100% serverlessly in **Google Cloud Run Jobs**—powered by a local Go authentication proxy (`go-oauth-proxy`) that transparently replaces GCDS's legacy 3-legged human OAuth tokens with **keyless GCP Service Account authentication** (no downloaded JSON keys, no Domain-Wide Delegation required, no persistent Windows/Linux sync pet servers).

👉 **Read the full step-by-step [Migration Wiki](https://github.com/jay0lee/gcds-in-the-cloud/wiki)** for moving an existing on-premises GCDS installation to 100% Google Cloud, including Active Directory connectivity architectures (Cloud VPN, Cloud Interconnect, GCP Read-Only Domain Controllers, and Google Managed Microsoft AD).

---

## Why `gcds-in-the-cloud`?

Traditionally, running GCDS requires:
1. Maintaining a dedicated on-premises Windows or Linux server with a desktop GUI (`config-manager`).
2. Authorizing GCDS as a human **Super Admin** via 3-legged OAuth, leaving a long-lived refresh token encrypted with a machine-bound key (`~/.java/.userPrefs`) inside `sync-config.xml`.
3. Manually running `upgrade-config -exportkeys` / `-importkeys` anytime the server changes.

**`gcds-in-the-cloud` eliminates all three:**
- **Direct Service Account Role Assignment (No DwD, No Human OAuth, No JSON Keys)**: Assign a least-privilege Workspace Custom Admin Role directly to your Cloud Run Job's GCP Service Account (`admin.google.com` -> *Account -> Admin roles -> Assign service accounts*).
- **Transparent OAuth -> Self-Signed JWT Translation**: Inside the ephemeral Cloud Run container, `go-oauth-proxy` intercepts GCDS's `oauth2.googleapis.com/token` calls locally, strips the placeholder 3LO bearer header, and injects a non-OAuth Service Account JWT (`service-account#jwt-auth` / [AIP-4111](https://google.aip.dev/auth/4111)) signed via Google's IAM Credentials API (`:signJwt`) using Google-managed keys.
- **Drop-In `sync-config.xml` Support**: Upload any `sync-config.xml` from an admin workstation into a versioned GCS bucket (`gs://<project>-gcds-configs/`). At container boot, `entrypoint.sh` automatically re-encrypts your Active Directory bind password (from **Secret Manager**) and a synthetic OAuth placeholder in RAM (`/dev/shm`) using GCDS's `encrypt-util`—zero `.key` file exports or manual proxy edits needed.
- **Scales to $0 Between Syncs**: Triggered by **Cloud Scheduler** (or on-demand dry-run simulations from the Cloud Console UI), connecting back to Active Directory over **Direct VPC Egress**.

---

## Architecture

```text
  gs://<project>-gcds-configs/*.xml        Secret Manager (LDAP_BIND_PASSWORD)
                 │                                         │
                 └───────────────────┬─────────────────────┘
                                     ▼
            ┌──────────────────────────────────────────────────┐
            │ Ephemeral Cloud Run Job Container (/dev/shm RAM) │
            │                                                  │
            │  1. entrypoint.sh re-encrypts XML via encrypt-util│
            │  2. GCDS (sync-cmd)                              │
            │       ├── LDAPS (636) ──► Active Directory       │
            │       │                   (Cloud VPN / GCP RODC) │
            │       └── HTTPS Proxy (127.0.0.1:8443)           │
            │                 ▼                                │
            │  3. go-oauth-proxy                               │
            │       ├── Emulates /token locally (kills 3LO)    │
            │       └── Calls IAM :signJwt via Metadata ADC    │
            └─────────────────┬────────────────────────────────┘
                              │ Authorization: Bearer <SA-JWT>
                              ▼
               Google Workspace APIs (*.googleapis.com)
```

---

## Quick Start (Cloud Run Deployment)

```bash
export PROJECT_ID="your-gcp-project"
export REGION="us-central1"
export VPC_NETWORK="your-ad-connected-vpc"
export VPC_SUBNET="your-subnet"

chmod +x deploy/cloud-run/deploy.sh
./deploy/cloud-run/deploy.sh
```

See the **[Wiki Documentation](https://github.com/jay0lee/gcds-in-the-cloud/wiki)** for complete migration guides:
- **[Home & Architecture Overview](https://github.com/jay0lee/gcds-in-the-cloud/wiki)**
- **[1. Connecting Cloud Run to Active Directory](https://github.com/jay0lee/gcds-in-the-cloud/wiki/1.-Connecting-Cloud-Run-to-Active-Directory)** *(Cloud VPN, Interconnect, Read-Only Domain Controller in GCE, LDAPS Trust)*
- **[2. Workspace Service Account & Least-Privilege Admin Roles](https://github.com/jay0lee/gcds-in-the-cloud/wiki/2.-Workspace-Service-Account-and-Admin-Roles)**
- **[3. Migrating Your Existing On-Premises GCDS Config](https://github.com/jay0lee/gcds-in-the-cloud/wiki/3.-Migrating-Your-On-Prem-GCDS-Config)**
- **[4. Day-2 Operations, Scheduling, and Dry-Run Previews](https://github.com/jay0lee/gcds-in-the-cloud/wiki/4.-Day-2-Operations-and-Scheduling)**

---

## Standalone `go-oauth-proxy` Capabilities

Beyond Cloud Run GCDS deployments, `go-oauth-proxy` (`cmd/go-oauth-proxy`) is a full-featured local Go security proxy supporting:
- **Transparent RFC 9449 DPoP Injection** (`oauth2.googleapis.com/token` with Google's `code` SHA-256 `jti` derivation and automatic `400 use_dpop_nonce` single-retry).
- **Pluggable Auth Replacement Strategies**: `jwt_auth` (AIP-4111 Service Account without OAuth), `dwd_oauth` (Domain-Wide Delegation), and `adc_bearer`.
- **Hardware-Backed `crypto.Signer` Backends** (`internal/keystore`): macOS Apple Silicon **Secure Enclave** (`Security.framework`), **TPM 2.0** (`go-tpm`), **Windows CNG** (`ncrypt.dll` Platform Crypto Provider), **PKCS#11** (YubiKey / HSM), **Google Cloud HSM**, and **Google Enterprise Certificate Proxy (ECP)**, plus **Workload Identity Federation X.509 mTLS** (`sts.mtls.googleapis.com`).

### Build & Test Locally

```bash
go build -o bin/go-oauth-proxy ./cmd/go-oauth-proxy
go test -v -race ./...
```
