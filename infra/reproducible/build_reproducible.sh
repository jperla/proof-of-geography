#!/usr/bin/env bash
set -euo pipefail

# Build reproducible Proof of Geography binaries and emit measurement_manifest.json
# Usage: ./infra/reproducible/build_reproducible.sh [--docker]

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/dist/reproducible"
mkdir -p "${OUT_DIR}"

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1700000000}"
export TZ=UTC
export LC_ALL=C
export CARGO_INCREMENTAL=0

if [[ "${1:-}" == "--docker" ]]; then
  echo "[1/3] Building reproducible Linux x86_64 binaries inside pinned Rust Docker builder..."
  docker build --platform linux/amd64 --target builder -f "${ROOT_DIR}/infra/reproducible/Dockerfile" -t pog-repro-builder "${ROOT_DIR}"
  CID="$(docker create pog-repro-builder)"
  trap 'docker rm -f "${CID}" >/dev/null 2>&1 || true' EXIT
  docker cp "${CID}:/out/." "${OUT_DIR}/"
else
  echo "[1/3] Building deterministic host binaries with locked Cargo.lock & path remapping..."
  RUSTFLAGS="--remap-path-prefix=${ROOT_DIR}=/pog -C debuginfo=0 -C strip=symbols -C codegen-units=1" \
    cargo build --manifest-path "${ROOT_DIR}/Cargo.toml" --release --locked --bins
  cp "${ROOT_DIR}/target/release/pog-anchor" "${ROOT_DIR}/target/release/pog-prover" "${ROOT_DIR}/target/release/pog-cli" "${OUT_DIR}/"
fi

echo "[2/3] Generating deterministic SHA256SUMS and measurement_manifest.json..."
python3 - "${ROOT_DIR}" "${OUT_DIR}" "${SOURCE_DATE_EPOCH}" <<'PY'
import hashlib, json, pathlib, platform, subprocess, sys

root = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
epoch = int(sys.argv[3])

git_sha = "unknown"
try:
    git_sha = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
except Exception:
    pass

bins = {}
sha_lines = []
combined = hashlib.sha256()
for name in ["pog-anchor", "pog-prover", "pog-cli"]:
    p = out / name
    data = p.read_bytes()
    h = hashlib.sha256(data).hexdigest()
    bins[name] = {"sha256": h, "size_bytes": len(data)}
    sha_lines.append(f"{h}  {name}")
    combined.update(name.encode() + b":" + bytes.fromhex(h))

(out / "SHA256SUMS").write_text("\n".join(sha_lines) + "\n")
manifest = {
    "schema_version": "1.0.0",
    "git_commit": git_sha,
    "source_date_epoch": epoch,
    "build_arch": platform.machine(),
    "binaries": bins,
    "bundle_measurement_sha256": combined.hexdigest(),
    "tee_measurement_notes": {
        "amd_sev_snp": "Pin launch digest with sev-snp-measure over immutable dm-verity rootfs containing these exact SHA256SUMS",
        "intel_tdx": "Pin MRTD + RTMR[0..3] over immutable UKI + dm-verity rootfs containing these exact SHA256SUMS",
        "aws_nitro": "Pin PCR0 from nitro-cli build-enclave over distroless runtime stage in infra/reproducible/Dockerfile",
    },
}
(out / "measurement_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps(manifest, indent=2))
PY

echo "[3/3] Reproducible artifacts written to ${OUT_DIR}/"
