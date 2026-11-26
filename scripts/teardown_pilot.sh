#!/usr/bin/env bash
set -euo pipefail

# Cleanly tear down ALL isolated pilot resources across AWS, GCP, and Azure.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/infra/terraform/pilot"

terraform destroy -auto-approve "$@"
echo "All isolated pilot VMs, VPCs, subnets, and security groups destroyed."
