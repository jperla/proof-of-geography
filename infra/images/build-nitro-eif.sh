#!/usr/bin/env bash
set -euo pipefail

# Build a deterministic AWS Nitro Enclave Image File (.eif) and print its cryptographic
# PCR0 / PCR1 / PCR2 measurements for registration in the public PoG Anchor Registry.
#
# Release Gate: refuses to build if Dockerfile.anchor contains any dev-fallback flag.
IMAGE_URI="${1:-pog-anchor:v0.2.0}"
OUTPUT_EIF="${2:-pog-anchor.eif}"

if grep -qE 'allow-dev-tee|allow-dev-prover' infra/images/Dockerfile.anchor; then
  echo "ERROR: Refusing to build Nitro EIF — dev fallback flags found in infra/images/Dockerfile.anchor!" >&2
  exit 1
fi

docker build --no-cache -f infra/images/Dockerfile.anchor -t "${IMAGE_URI}" .
nitro-cli build-enclave \
  --docker-uri "${IMAGE_URI}" \
  --output-file "${OUTPUT_EIF}" | tee "${OUTPUT_EIF}.measurements.json"

# Validate non-zero PCR0/PCR1/PCR2 measurements were emitted (never deploy --debug-mode all-zero PCRs).
python3 - "${OUTPUT_EIF}.measurements.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
meas = doc.get("Measurements", {})
for k in ("PCR0", "PCR1", "PCR2"):
    v = meas.get(k, "")
    if len(v) != 96 or set(v) == {"0"}:
        sys.exit(f"ERROR: invalid or all-zero {k} in EIF measurements: {v!r}")
print("Verified non-zero EIF PCR0/PCR1/PCR2 measurements:")
for k in ("PCR0", "PCR1", "PCR2"):
    print(f"  {k}: {meas[k]}")
PY

echo "Built ${OUTPUT_EIF}. Publish PCR0/PCR1/PCR2 from ${OUTPUT_EIF}.measurements.json into AttestationPolicy.allowed_measurements."
