#!/usr/bin/env bash
set -euo pipefail

# Spin up a live local mini-network (4 real pog-anchor TCP/UDP daemons + public Web Explorer)
# so anyone can try the complete live network locally in 10 seconds before cloud deployment!
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

cargo build --release --bin pog-anchor --bin pog-prover --bin pog-cli

echo "Starting 4 live local Anchors + Public Web Explorer on http://127.0.0.1:8090 ..."
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

./target/release/pog-anchor --anchor-id gcp-us-east4-ashburn --cloud-provider gcp --tcp-listen 127.0.0.1:17443 --udp-bind 127.0.0.1:17444 --http-info-listen 127.0.0.1:17445 --allow-dev-tee &
PIDS+=($!)
./target/release/pog-anchor --anchor-id aws-us-east-1-nvirginia --cloud-provider aws --tcp-listen 127.0.0.1:17453 --udp-bind 127.0.0.1:17454 --http-info-listen 127.0.0.1:17455 --allow-dev-tee &
PIDS+=($!)
./target/release/pog-anchor --anchor-id azure-canadacentral-toronto --cloud-provider azure --tcp-listen 127.0.0.1:17463 --udp-bind 127.0.0.1:17464 --http-info-listen 127.0.0.1:17465 --allow-dev-tee &
PIDS+=($!)
./target/release/pog-anchor --anchor-id gcp-us-central1-iowa --cloud-provider gcp --tcp-listen 127.0.0.1:17473 --udp-bind 127.0.0.1:17474 --http-info-listen 127.0.0.1:17475 --allow-dev-tee &
PIDS+=($!)

sleep 1
./target/release/pog-cli serve-log --grid config/global_grid_24.json --listen 127.0.0.1:8090 --allow-dev-tee
