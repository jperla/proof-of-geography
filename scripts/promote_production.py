#!/usr/bin/env python3
"""Fail-Closed Production Constellation Promotion Entrypoint.

Wires `scripts/release_gate.py --authorize-promotion` directly to actual promotion of
the signed production registry (`/.well-known/pog-network.json`) and official web roster
(`web/data/anchors.json`) into a staging/release output directory.

Guarantees:
1. Unconditionally runs `scripts/release_gate.py --authorize-promotion` (real `pog-cli`
   verifier, pinned production trust root, zero-SSH measured software manifest, fresh
   caller-nonce hardware TEE attestation + Ed25519 PoP + live-key endorsement, and
   separately audited physical coordinates).
2. Refuses to write or promote ANY artifact if authorization fails.
3. NEVER modifies or tears down the separate 42-node SoftwareDev diagnostic test fleet.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

OFFICIAL_NETWORK_ID = "proofofgeography.com"
OFFICIAL_PRODUCTION_ROOT_PK_HEX = "fdff6d6d0b8364e459ffbb921430e39411bd812ec3ce766c2904b39bfa996ee1"


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description="Fail-closed production promotion wired to release_gate.py --authorize-promotion")
    ap.add_argument("--signed-registry", type=Path, default=repo_root / "config" / "signed_public_network.json")
    ap.add_argument("--web-roster", type=Path, default=repo_root / "web" / "data" / "anchors.json")
    ap.add_argument("--pinned-root-pk", default=OFFICIAL_PRODUCTION_ROOT_PK_HEX)
    ap.add_argument("--expected-network-id", default=OFFICIAL_NETWORK_ID)
    ap.add_argument("--measured-manifest", type=Path, required=True)
    ap.add_argument("--coordinate-audit", type=Path, required=True)
    ap.add_argument("--pog-cli", type=Path)
    ap.add_argument("--fresh-attest-dir", type=Path, help="Optional fresh attest bundle dir (within max age); default probes live /attest?nonce=")
    ap.add_argument("--stage-dir", type=Path, required=True, help="Output directory to stage promoted production artifacts ONLY after gate passes")
    ap.add_argument("--amd-product", default="Milan", choices=["Milan", "Genoa", "Turin"])
    args = ap.parse_args()

    receipt_tmp = args.stage_dir.parent / f".{args.stage_dir.name}.auth_receipt.tmp.json"
    cmd = [
        sys.executable,
        str(repo_root / "scripts" / "release_gate.py"),
        "--authorize-promotion",
        "--signed-registry",
        str(args.signed_registry),
        "--web-roster",
        str(args.web_roster),
        "--pinned-root-pk",
        args.pinned_root_pk,
        "--expected-network-id",
        args.expected_network_id,
        "--measured-manifest",
        str(args.measured_manifest),
        "--coordinate-audit",
        str(args.coordinate_audit),
        "--amd-product",
        args.amd_product,
        "--out-receipt",
        str(receipt_tmp),
    ]
    if args.pog_cli:
        cmd.extend(["--pog-cli", str(args.pog_cli)])
    if args.fresh_attest_dir:
        cmd.extend(["--fresh-attest-dir", str(args.fresh_attest_dir)])

    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0 or not receipt_tmp.exists():
        if receipt_tmp.exists():
            receipt_tmp.unlink()
        print("PRODUCTION PROMOTION BLOCKED (release_gate.py --authorize-promotion failed; 0 artifacts promoted; SoftwareDev test fleet untouched):", file=sys.stderr)
        print(res.stdout or res.stderr, file=sys.stderr)
        return 1

    receipt = json.loads(receipt_tmp.read_text())
    if receipt.get("authorized") is not True or receipt.get("scope") != "full_fleet_production":
        receipt_tmp.unlink()
        print("PRODUCTION PROMOTION BLOCKED: receipt is not full_fleet_production authorized.", file=sys.stderr)
        return 1

    args.stage_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(args.signed_registry, args.stage_dir / "pog-network.json")
    shutil.copy2(args.web_roster, args.stage_dir / "anchors.json")
    shutil.copy2(args.measured_manifest, args.stage_dir / "measured_manifest.json")
    shutil.copy2(args.coordinate_audit, args.stage_dir / "coordinate_audit.json")
    shutil.move(str(receipt_tmp), str(args.stage_dir / "promotion_authorization.json"))

    print(json.dumps({
        "promoted": True,
        "stage_dir": str(args.stage_dir),
        "anchors_verified_count": receipt["anchors_verified_count"],
        "signed_registry_sha256": receipt["signed_registry_sha256"],
        "authorization_receipt": str(args.stage_dir / "promotion_authorization.json"),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
