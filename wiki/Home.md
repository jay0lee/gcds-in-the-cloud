# Migrating On-Premises GCDS to 100% Google Cloud

Welcome to the **`gcds-in-the-cloud`** Wiki! This documentation walks Google Workspace and Active Directory administrators through taking an existing on-premises **Google Cloud Directory Sync (GCDS)** installation (Windows Server or Linux) and moving it to a **100% serverless, keyless Google Cloud Run Job**.

---

## What Changes (and What Stays the Same)

Your **GCDS sync rules, LDAP queries, search bases, org-unit mappings, and safety limits (`sync-config.xml`) stay 100% identical.** You are still running Google's official GCDS engine (`sync-cmd`)—only the server, human OAuth token, and secret-management headaches disappear:

| Capability | Legacy On-Premises GCDS | `gcds-in-the-cloud` (Cloud Run) |
| :--- | :--- | :--- |
| **Compute Infrastructure** | Dedicated Windows/Linux VM + OS/Java patching | Serverless **Cloud Run Job** (scales to **$0** between runs) |
| **Google Workspace Auth** | Long-lived human **Super Admin 3-legged OAuth** refresh token | **Keyless GCP Service Account** assigned a least-privilege Workspace Admin Role |
| **Domain-Wide Delegation** | Often abused if using SA keys | **Not required** (Service Account acts directly as itself via non-OAuth self-signed JWTs) |
| **XML Encryption Keys** | Machine-locked `~/.java/.userPrefs` (`upgrade-config -exportkeys`) | **Automated in RAM (`/dev/shm`)** at container startup via `encrypt-util` |
| **Config Storage & Rollback** | Local XML file on `C:\` or `/etc` | Versioned **Google Cloud Storage** bucket (`gs://...`) with 1-click rollback |
| **AD Bind Password** | Encrypted inside XML (requires GUI re-save to rotate) | Stored in **Secret Manager** (rotate anytime without touching XML) |
| **Scheduling & Alerting** | Windows Task Scheduler / cron + legacy SMTP server | **Cloud Scheduler** + **Cloud Logging / Cloud Monitoring** alerts |

---

## Architecture at a Glance

```text
  [On-Premises or GCP VPC]                       [Google Cloud Run Job]
 ┌─────────────────────────┐                    ┌─────────────────────────────────────────────┐
 │ Active Directory (AD)   │◄─── LDAPS :636 ────┤ 1. GCDS (sync-cmd)                          │
 │  • On-Prem via Cloud VPN│    (Direct VPC     │     • Reads auto-prepared XML in /dev/shm   │
 │  • GCE Replica DC / RODC│     Egress)        │     • Routes Google API calls to :8443      │
 │  • Managed Microsoft AD │                    │                │                            │
 └─────────────────────────┘                    │                ▼                            │
                                                │ 2. go-oauth-proxy (127.0.0.1:8443)          │
                                                │     • Intercepts /token locally (kills 3LO) │
                                                │     • Signs SA JWT via IAM :signJwt (ADC)   │
                                                └────────────────┬────────────────────────────┘
                                                                 │ Bearer <Self-Signed-SA-JWT>
                                                                 ▼
                                                  Google Workspace Admin APIs
                                                    (admin.googleapis.com)
```

---

## Step-by-Step Migration Guides

Follow these four guides in order to migrate safely with **zero downtime** and **zero unintended account changes**:

1. **[1. Connecting Cloud Run to Active Directory](1.-Connecting-Cloud-Run-to-Active-Directory)**
   *Planning private LDAP/LDAPS network connectivity between Cloud Run and Active Directory—comparing HA Cloud VPN, running a Read-Only Domain Controller (RODC) in Compute Engine, Cloud Interconnect, and Managed Microsoft AD, plus LDAPS CA certificate trust.*
2. **[2. Workspace Service Account and Admin Roles](2.-Workspace-Service-Account-and-Admin-Roles)**
   *Creating a keyless GCP Service Account and assigning it a least-privilege Custom Admin Role in Google Workspace (no Super Admin 3LO token, no JSON keys, no Domain-Wide Delegation).*
3. **[3. Migrating Your On-Prem GCDS Config](3.-Migrating-Your-On-Prem-GCDS-Config)**
   *Exporting your existing `sync-config.xml`, pre-flight checks (Windows file paths, LDAPS hostnames), deploying the Cloud Run Job, and running side-by-side dry-run simulations before turning off your old server.*
4. **[4. Day-2 Operations and Scheduling](4.-Day-2-Operations-and-Scheduling)**
   *Configuring Cloud Scheduler, running multiple XML configs on one Cloud Run Job, setting up Cloud Monitoring alerts, and rotating AD passwords.*
