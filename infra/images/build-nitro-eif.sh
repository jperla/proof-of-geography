#!/usr/bin/env bash
set -euo pipefail

# Build a deterministic AWS Nitro Enclave Image File (.eif) and print its cryptographic
# PCR0 / PCR1 / PCR2 measurements for registration in the public PoG Anchor Registry.
IMAGE_URI="${1:-pog-anchor:v0.1.0}"
OUTPUT_EIF="${2:-pog-anchor.eif}"

docker build -f infra/images/Dockerfile.anchor -t "${IMAGE_URI}" .
nitro-cli build-enclave \
  --docker-uri "${IMAGE_URI}" \
  --output-file "${OUTPUT_EIF}" | tee "${OUTPUT_EIF}.measurements.json"

echo "Built ${OUTPUT_EIF}. Publish PCR0/PCR1/PCR2 from ${OUTPUT_EIF}.measurements.json to the Anchor Registry."
