#!/usr/bin/env bash
set -euo pipefail

# Verify binaries against a published reproducible measurement_manifest.json
# Usage: ./infra/reproducible/verify_measurement.sh dist/reproducible/measurement_manifest.json dist/reproducible

MANIFEST="${1:?Usage: verify_measurement.sh <measurement_manifest.json> <bin_dir>}"
BIN_DIR="${2:?Usage: verify_measurement.sh <measurement_manifest.json> <bin_dir>}"

python3 - "${MANIFEST}" "${BIN_DIR}" <<'PY'
import hashlib, json, pathlib, sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
bin_dir = pathlib.Path(sys.argv[2])

combined = hashlib.sha256()
all_ok = True
for name, expected in manifest["binaries"].items():
    p = bin_dir / name
    if not p.exists():
        print(f"[FAIL] Missing binary: {p}")
        all_ok = False
        continue
    actual = hashlib.sha256(p.read_bytes()).hexdigest()
    if actual == expected["sha256"]:
        print(f"[PASS] {name:<12} sha256={actual}")
    else:
        print(f"[FAIL] {name:<12} expected={expected['sha256']} actual={actual}")
        all_ok = False
    combined.update(name.encode() + b":" + bytes.fromhex(actual))

bundle_ok = combined.hexdigest() == manifest["bundle_measurement_sha256"]
print(f"[{'PASS' if bundle_ok else 'FAIL'}] bundle_measurement_sha256={combined.hexdigest()}")
if not (all_ok and bundle_ok):
    sys.exit(1)
print("ALL REPRODUCIBLE WORKLOAD MEASUREMENTS VERIFIED!")
PY
