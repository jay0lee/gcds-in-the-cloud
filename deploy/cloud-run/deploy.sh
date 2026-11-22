#!/usr/bin/env bash
# Turnkey deployment script for GCDS-in-the-Cloud on Google Cloud Run Jobs
set -euo pipefail

: "${PROJECT_ID:?Set PROJECT_ID (e.g. export PROJECT_ID=corp-identity)}"
REGION="${REGION:-us-central1}"
VPC_NETWORK="${VPC_NETWORK:-default}"
VPC_SUBNET="${VPC_SUBNET:-default}"
SA_NAME="${SA_NAME:-gcds-sync}"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
BUCKET_NAME="${BUCKET_NAME:-${PROJECT_ID}-gcds-configs}"
AR_REPO="${AR_REPO:-gcds-cloud}"
IMAGE_URI="${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}/gcds-runner:latest"

echo "==> 1. Enabling required Google Cloud APIs..."
gcloud services enable \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  cloudscheduler.googleapis.com \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  run.googleapis.com \
  secretmanager.googleapis.com \
  storage.googleapis.com \
  admin.googleapis.com \
  --project="${PROJECT_ID}"

echo "==> 2. Creating keyless GCDS Service Account (${SA_EMAIL})..."
gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1 || \
  gcloud iam service-accounts create "${SA_NAME}" \
    --display-name="GCDS Cloud Run Sync Service Account" \
    --project="${PROJECT_ID}"

# Grant self-signing permission so go-oauth-proxy can mint non-OAuth JWTs via IAM :signJwt
gcloud iam service-accounts add-iam-policy-binding "${SA_EMAIL}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/iam.serviceAccountTokenCreator" \
  --project="${PROJECT_ID}" >/dev/null

echo "==> 3. Creating versioned GCS bucket gs://${BUCKET_NAME} for GCDS XML configs..."
gcloud storage buckets describe "gs://${BUCKET_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1 || \
  gcloud storage buckets create "gs://${BUCKET_NAME}" \
    --location="${REGION}" \
    --uniform-bucket-level-access \
    --project="${PROJECT_ID}"
gcloud storage buckets update "gs://${BUCKET_NAME}" --versioning >/dev/null
gcloud storage buckets add-iam-policy-binding "gs://${BUCKET_NAME}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/storage.objectViewer" >/dev/null

echo "==> 4. Ensuring Secret Manager secret 'gcds-ldap-password' exists..."
if ! gcloud secrets describe gcds-ldap-password --project="${PROJECT_ID}" >/dev/null 2>&1; then
  printf "CHANGE_ME_LDAP_PASSWORD" | gcloud secrets create gcds-ldap-password \
    --data-file=- --project="${PROJECT_ID}"
  echo "    Created placeholder secret 'gcds-ldap-password' — update with your real AD bind password!"
fi
gcloud secrets add-iam-policy-binding gcds-ldap-password \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/secretmanager.secretAccessor" \
  --project="${PROJECT_ID}" >/dev/null

echo "==> 5. Building & pushing GCDS-in-the-Cloud image via Cloud Build..."
gcloud artifacts repositories describe "${AR_REPO}" --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1 || \
  gcloud artifacts repositories create "${AR_REPO}" \
    --repository-format=docker \
    --location="${REGION}" \
    --project="${PROJECT_ID}"

gcloud builds submit \
  --config=deploy/cloud-run/cloudbuild.yaml \
  --substitutions="_IMAGE=${IMAGE_URI}" \
  --project="${PROJECT_ID}" .

echo "==> 6. Deploying Cloud Run Job 'gcds-runner'..."
gcloud run jobs deploy gcds-runner \
  --image="${IMAGE_URI}" \
  --region="${REGION}" \
  --service-account="${SA_EMAIL}" \
  --network="${VPC_NETWORK}" \
  --subnet="${VPC_SUBNET}" \
  --vpc-egress="private-ranges-only" \
  --set-env-vars="GCDS_SA_EMAIL=${SA_EMAIL},SYNC_MODE=simulate,CONFIG_URI=gs://${BUCKET_NAME}/sync-config.xml" \
  --set-secrets="LDAP_BIND_PASSWORD=gcds-ldap-password:latest" \
  --max-retries=0 \
  --task-timeout=30m \
  --project="${PROJECT_ID}"

cat <<EOF

================================================================================
Deployment Complete! Next Steps:
  1. In Google Workspace Admin Console (admin.google.com -> Account -> Admin roles):
     Assign your GCDS Custom Admin Role directly to Service Account:
       ${SA_EMAIL}
  2. Update your Active Directory bind password in Secret Manager:
       printf '%s' 'YOUR_AD_PASSWORD' | gcloud secrets versions add gcds-ldap-password --data-file=- --project=${PROJECT_ID}
  3. Upload your GCDS XML configuration:
       gcloud storage cp sync-config.xml gs://${BUCKET_NAME}/sync-config.xml
  4. Run a safe dry-run simulation:
       gcloud run jobs execute gcds-runner --region=${REGION} --project=${PROJECT_ID} --wait
================================================================================
EOF
