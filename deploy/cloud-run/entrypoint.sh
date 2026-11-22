#!/usr/bin/env bash
set -euo pipefail

: "${CONFIG_URI:?CONFIG_URI must be set (e.g. gs://your-gcds-configs/employees.xml or /path/to/sync-config.xml)}"
: "${GCDS_SA_EMAIL:?GCDS_SA_EMAIL must be set to the Workspace role-assigned Service Account email}"

SYNC_MODE="${SYNC_MODE:-simulate}" # Default to safe dry-run ("simulate"); set SYNC_MODE="apply" to commit changes
GCDS_DIR="/opt/gcds"
GCDS_JRE="${GCDS_DIR}/jre"
KEYTOOL="${GCDS_JRE}/bin/keytool"

echo "[gcds-cloud] Loading GCDS configuration from ${CONFIG_URI} (mode=${SYNC_MODE})..."

if [[ "${CONFIG_URI}" == gs://* ]]; then
  ACCESS_TOKEN="$(curl -sf -H 'Metadata-Flavor: Google' \
    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
  BUCKET="${CONFIG_URI#gs://}"
  BUCKET="${BUCKET%%/*}"
  OBJECT_RAW="${CONFIG_URI#gs://${BUCKET}/}"
  OBJECT_ENC="$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=""))' "${OBJECT_RAW}")"

  curl -fsSL -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    "https://storage.googleapis.com/storage/v1/b/${BUCKET}/o/${OBJECT_ENC}?alt=media" \
    -o /dev/shm/sync-config.xml
else
  cp "${CONFIG_URI}" /dev/shm/sync-config.xml
fi
chmod 0600 /dev/shm/sync-config.xml

# Re-encrypt <oauthRefreshToken> (with a synthetic placeholder) and <authPassword> (if LDAP_BIND_PASSWORD
# is supplied) using THIS container's ephemeral ~/.java/.userPrefs key so XMLs from any admin laptop work as-is.
ENC_OAUTH="$("${GCDS_DIR}/encrypt-util" "proxy-managed-placeholder" | tail -n1 | tr -d '\r\n')"
ENC_LDAP=""
if [[ -n "${LDAP_BIND_PASSWORD:-}" ]]; then
  ENC_LDAP="$("${GCDS_DIR}/encrypt-util" "${LDAP_BIND_PASSWORD}" | tail -n1 | tr -d '\r\n')"
elif [[ -n "${GCDS_ENCRYPTION_KEY_FILE:-}" && -f "${GCDS_ENCRYPTION_KEY_FILE}" ]]; then
  "${GCDS_DIR}/upgrade-config" -importkeys "${GCDS_ENCRYPTION_KEY_FILE}" >/dev/null
fi

python3 - /dev/shm/sync-config.xml "${ENC_OAUTH}" "${ENC_LDAP}" <<'PY'
import sys, xml.etree.ElementTree as ET

xml_path, enc_oauth, enc_ldap = sys.argv[1], sys.argv[2], sys.argv[3]
tree = ET.parse(xml_path)
root = tree.getroot()

for elem in root.iter():
    if elem.tag.endswith("oauthRefreshToken") and enc_oauth:
        elem.text = enc_oauth
    elif elem.tag.endswith("authPassword") and enc_ldap:
        elem.text = enc_ldap
    # Redirect GCDS sync log files to /dev/shm so stdout captures output cleanly on read-only filesystems
    elif elem.tag.endswith("logFileName"):
        elem.text = "/dev/shm/gcds-sync.log"

tree.write(xml_path, encoding="utf-8", xml_declaration=True)
PY

# Render proxy configuration and start go-oauth-proxy in RAM
envsubst < /etc/gcds/proxy-config.yaml.tmpl > /dev/shm/proxy-config.yaml
go-oauth-proxy serve --config /dev/shm/proxy-config.yaml &
PROXY_PID=$!
cleanup() {
  kill "${PROXY_PID}" 2>/dev/null || true
  if [[ -f /dev/shm/gcds-sync.log ]]; then
    echo "=== GCDS Detailed Sync Log ==="
    cat /dev/shm/gcds-sync.log
  fi
}
trap cleanup EXIT

for _ in {1..40}; do
  if curl -sf http://127.0.0.1:8080/healthz >/dev/null; then
    break
  fi
  sleep 0.25
done

# Build an ephemeral Java truststore in /dev/shm trusting:
#   1) go-oauth-proxy's per-run Root CA (for 127.0.0.1:8443 OAuth -> JWT translation)
#   2) Optional internal Active Directory CA certificate (AD_CA_CERT_PEM) for LDAPS (port 636)
cp "${GCDS_JRE}/lib/security/cacerts" /dev/shm/cacerts
chmod 0600 /dev/shm/cacerts

"${KEYTOOL}" -importcert -noprompt -trustcacerts \
  -keystore /dev/shm/cacerts -storepass changeit \
  -alias go-oauth-proxy-ephemeral-ca \
  -file /dev/shm/local-root-ca.crt.pem >/dev/null

if [[ -n "${AD_CA_CERT_PEM:-}" ]]; then
  printf "%s\n" "${AD_CA_CERT_PEM}" > /dev/shm/ad-ldaps-ca.pem
  "${KEYTOOL}" -importcert -noprompt -trustcacerts \
    -keystore /dev/shm/cacerts -storepass changeit \
    -alias active-directory-ldaps-ca \
    -file /dev/shm/ad-ldaps-ca.pem >/dev/null
  echo "[gcds-cloud] Imported custom Active Directory LDAPS Root CA into ephemeral truststore."
fi

# Configure install4j JVM options for sync-cmd so all HTTPS calls to *.googleapis.com route via 127.0.0.1:8443
# while LDAP/LDAPS sockets connect directly over the VPC / VPN to Active Directory.
export INSTALL4J_ADD_VM_PARAMS="-Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=8443 -Dhttp.nonProxyHosts=localhost|127.0.0.1 -Djavax.net.ssl.trustStore=/dev/shm/cacerts -Djavax.net.ssl.trustStorePassword=changeit"

EXTRA_ARGS=()
if [[ "${SYNC_MODE}" == "apply" ]]; then
  EXTRA_ARGS+=("-a")
fi
if [[ -n "${GCDS_EXTRA_FLAGS:-}" ]]; then
  # shellcheck disable=SC2206
  EXTRA_ARGS+=(${GCDS_EXTRA_FLAGS})
fi

echo "[gcds-cloud] Starting GCDS sync-cmd (${EXTRA_ARGS[*]:-simulate})..."
"${GCDS_DIR}/sync-cmd" "${EXTRA_ARGS[@]}" -c /dev/shm/sync-config.xml
