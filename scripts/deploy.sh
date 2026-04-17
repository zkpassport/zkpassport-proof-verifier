#!/usr/bin/env bash
#
# Deployment helper for zkpassport-proof-verifier.
#
# Usage:
#   ./deploy.sh init     One-time setup: create TF state bucket, init and apply with placeholder image
#   ./deploy.sh deploy   Build and deploy (for local use; CI uses GitHub Actions)
#
set -euo pipefail

PROJECT_ID="proof-verifier"
REGION="europe-west2"
TF_STATE_BUCKET="proof-verifier-tf-state"
REPO_NAME="proof-verifier"
SERVICE_NAME="proof-verifier"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TF_DIR="${REPO_ROOT}/terraform"
TF_DEPLOY_DIR="${REPO_ROOT}/terraform/deploy"

init() {
  echo "==> Creating Terraform state bucket..."
  if gcloud storage buckets describe "gs://${TF_STATE_BUCKET}" --project="${PROJECT_ID}" > /dev/null 2>&1; then
    echo "    Bucket already exists, skipping."
  else
    gcloud storage buckets create "gs://${TF_STATE_BUCKET}" \
      --project="${PROJECT_ID}" \
      --location="${REGION}" \
      --uniform-bucket-level-access
    gcloud storage buckets update "gs://${TF_STATE_BUCKET}" --versioning
  fi

  echo "==> Running Terraform init (bootstrap)..."
  terraform -chdir="${TF_DIR}" init

  echo "==> Running Terraform apply (bootstrap)..."
  terraform -chdir="${TF_DIR}" apply

  echo "==> Running Terraform init (deploy)..."
  terraform -chdir="${TF_DEPLOY_DIR}" init

  echo "==> Running Terraform apply (deploy) with placeholder image..."
  terraform -chdir="${TF_DEPLOY_DIR}" apply \
    -var="image=us-docker.pkg.dev/cloudrun/container/hello:latest"

  echo ""
  echo "============================================"
  echo "  Bootstrap complete!"
  echo "============================================"
  echo ""
  echo "Add these as GitHub repository secrets:"
  echo ""
  echo "  WIF_PROVIDER:"
  terraform -chdir="${TF_DIR}" output -raw workload_identity_provider
  echo ""
  echo ""
  echo "  WIF_SERVICE_ACCOUNT:"
  terraform -chdir="${TF_DIR}" output -raw service_account_email
  echo ""
}

deploy() {
  local image_tag="${1:-$(git rev-parse HEAD)}"
  local image="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/${SERVICE_NAME}:${image_tag}"

  echo "==> Authenticating Docker to Artifact Registry..."
  gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet

  echo "==> Building image: ${image}"
  DOCKER_BUILDKIT=1 docker build \
    --build-context zkp="${REPO_ROOT}/../zkpassport-packages" \
    -t "${image}" "${REPO_ROOT}"
  # NOTE: --build-context zkp is a temporary hack so the Dockerfile can
  # pull in a locally-built ../zkpassport-packages. Remove once the
  # packages are published and package.json references fixed versions.

  echo "==> Pushing image..."
  docker push "${image}"

  echo "==> Running Terraform init..."
  terraform -chdir="${TF_DEPLOY_DIR}" init

  echo "==> Running Terraform apply..."
  terraform -chdir="${TF_DEPLOY_DIR}" apply -var="image=${image}"

  echo ""
  echo "==> Deployed! Service URL:"
  terraform -chdir="${TF_DEPLOY_DIR}" output -raw service_url
  echo ""
}

case "${1:-}" in
  init)   init ;;
  deploy) deploy "${2:-}" ;;
  *)
    echo "Usage: $0 {init|deploy}" >&2
    exit 1
    ;;
esac
