#!/usr/bin/env bash
set -euo pipefail

# Turnkey multi-cloud deployment script for the 24-node Proof of Geography Anchor Grid.
# Prerequisites: `gcloud auth application-default login`, `aws configure`, `az login`.
# Usage:
#   ./scripts/deploy_24_grid.sh <gcp-project-id> <azure-subscription-id>

GCP_PROJECT="${1:?Usage: $0 <gcp-project-id> <azure-subscription-id>}"
AZURE_SUB="${2:?Usage: $0 <gcp-project-id> <azure-subscription-id>}"

cd "$(dirname "$0")/../infra/terraform"

terraform init
terraform apply \
  -var="gcp_project_id=${GCP_PROJECT}" \
  -var="azure_subscription_id=${AZURE_SUB}" \
  -var="enable_gcp=true" \
  -var="enable_aws=true" \
  -var="enable_azure=true"

terraform output -json > /tmp/pog_tf_outputs.json

cd ../..
python3 scripts/collect_registry.py /tmp/pog_tf_outputs.json config/global_grid_24.json config/global_grid_live.json

echo ""
echo "Live grid ready! Start the public Web Explorer & Transparency Log:"
echo "  cargo run --release --bin pog-cli -- serve-log --grid config/global_grid_live.json --listen 0.0.0.0:8090"
