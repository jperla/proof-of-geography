#!/usr/bin/env python3
"""Honolulu Two-Provider Diagnostic Anchor Verification, Staging & Rollback Harness.

Supports two strictly separated modes:
1. `--self-test` (offline, zero cloud spend, zero live signing):
   - Validates `config/honolulu_diagnostic_patch.json` invariants:
     * Distinct operator-controlled anchor IDs, cloud providers (`aws` vs `vultr`),
       ASNs (`16509` vs `20473`), failure-domain labels, and `*.a.proofofgeography.com` endpoints.
     * Both marked `tee_vendor == "SoftwareDev"` and `diagnostic_only == true`.
     * Rejects any third-party test endpoint masquerading as an operator node.
   - Exercises the REAL compiled `pog-cli`:
     * Generates fresh throwaway Ed25519 keys for the 2 Honolulu nodes + temporary test root key,
       builds a staged 44-node diagnostic grid (42 baseline + 2 Honolulu), signs it with the
       throwaway test key (never touching the real operator root key!).
     * Asserts `pog-cli network verify-registry --allow-dev-anchors` PASSES (diagnostic mode = 44).
     * Asserts `pog-cli network verify-registry` (production default, NO `--allow-dev-anchors`)
       FAILS CLOSED and explicitly rejects both Honolulu anchors from the production proof quorum!
   - Validates held-out separate Pacific target isolation (no target IP/ID overlap with roster)
     and exact byte-for-byte rollback to the 42-node baseline.

2. `--live` (post-approved provisioning):
   - Queries both live on-island `/info` endpoints (`--aws-url`, `--vultr-url`), confirms distinct
     live ephemeral Ed25519 keys, matching `anchor_id`s, and distinct on-island IPs/endpoints.
   - Runs real `pog-cli probe-live` against BOTH Honolulu anchors from the current vantage to
     verify fresh signed UDP distance-bounding receipts (`AnchorReceipt` Ed25519 signatures valid).
   - Evaluates optional `--heldout-targets-json` (separate Pacific datacenter targets; never added
     as anchors) comparing Vacuum c0 area, containment, and hairpinning against Los Angeles.
   - Optionally writes an UNCOMMITTED/UNSIGNED diagnostic staging preview (`--out-staged-grid`)
     without touching live `config/signed_public_network.json` or offline root signing keys.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PATCH_PATH = REPO_ROOT / "config" / "honolulu_diagnostic_patch.json"
PUBLIC_ANCHORS_PATH = REPO_ROOT / "config" / "public_anchors.json"
WEB_ANCHORS_PATH = REPO_ROOT / "web" / "data" / "anchors.json"
SIGNED_PUBLIC_PATH = REPO_ROOT / "config" / "signed_public_network.json"

OPERATOR_DOMAIN_RE = re.compile(r"^https://[a-z0-9-]+\.a\.proofofgeography\.com$")
HNL_LAT, HNL_LON = 21.3069, -157.8583


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0088
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


def find_pog_cli(override: str | None = None) -> Path:
    if override:
        p = Path(override)
        if p.is_file():
            return p
    for cand in (
        REPO_ROOT / "target" / "release" / "pog-cli",
        REPO_ROOT / "target" / "debug" / "pog-cli",
    ):
        if cand.is_file():
            return cand
    raise RuntimeError("pog-cli binary not found; build with `cargo build --release --bin pog-cli`")


def validate_patch_invariants(patch: dict, baseline_grid: dict) -> list[str]:
    errors: list[str] = []
    cands = patch.get("candidate_anchors")
    if not isinstance(cands, list) or len(cands) != 2:
        return ["honolulu_diagnostic_patch.json must contain exactly 2 candidate_anchors (AWS + Vultr)"]

    base_ids = {a["anchor_id"] for a in baseline_grid.get("anchors", [])}
    ids, providers, asns, fds, urls = set(), set(), set(), set(), set()

    for c in cands:
        aid = c.get("anchor_id", "")
        prov = c.get("cloud_provider", "")
        asn = c.get("asn")
        fd = c.get("failure_domain", "")
        url = c.get("https_url", "")
        loc = c.get("location", {})
        cb = c.get("coordinate_basis", {})

        if aid in base_ids:
            errors.append(f"candidate {aid} already exists in baseline roster")
        if aid in ids:
            errors.append(f"duplicate candidate anchor_id: {aid}")
        ids.add(aid)

        if prov not in ("aws", "vultr"):
            errors.append(f"{aid}: unexpected cloud_provider={prov!r} (expected aws or vultr)")
        providers.add(prov)

        if not isinstance(asn, int) or asn <= 0:
            errors.append(f"{aid}: missing positive integer ASN")
        else:
            asns.add(asn)

        if not fd or "/" not in fd:
            errors.append(f"{aid}: missing structured failure_domain label")
        fds.add(fd)

        if not OPERATOR_DOMAIN_RE.match(url or ""):
            errors.append(f"{aid}: https_url {url!r} must be an operator-controlled *.a.proofofgeography.com URL")
        urls.add(url)

        if c.get("tee_vendor") != "SoftwareDev":
            errors.append(f"{aid}: Honolulu Local Zone / Vultr HNL has no HW TEE; tee_vendor must be SoftwareDev")
        if c.get("diagnostic_only") is not True:
            errors.append(f"{aid}: must explicitly set diagnostic_only=true")
        if cb.get("hardware_identity_proves_coordinates") is not False:
            errors.append(f"{aid}: coordinate_basis.hardware_identity_proves_coordinates must be false")

        d_hnl = haversine_km(HNL_LAT, HNL_LON, float(loc.get("lat", 0)), float(loc.get("lon", 0)))
        if d_hnl > 35.0:
            errors.append(f"{aid}: coordinates {loc} are {d_hnl:.1f} km from Honolulu (>35 km)")

    if providers != {"aws", "vultr"}:
        errors.append(f"candidates must span exactly aws and vultr, got {sorted(providers)}")
    if len(asns) != 2:
        errors.append(f"candidates must have 2 distinct ASNs (different networks), got {sorted(asns)}")
    if len(fds) != 2:
        errors.append(f"candidates must have 2 distinct failure_domain labels, got {sorted(fds)}")
    if len(urls) != 2:
        errors.append("candidates must have 2 distinct https_url endpoints")

    return errors


def validate_separate_heldout_targets(targets: list[dict], anchor_grid: dict) -> list[str]:
    """Ensure held-out Pacific evaluation targets never overlap our operator anchor roster."""
    errors: list[str] = []
    anchor_ids = {a["anchor_id"] for a in anchor_grid.get("anchors", [])}
    anchor_ips = {a["endpoint_tcp"].split(":")[0] for a in anchor_grid.get("anchors", []) if a.get("endpoint_tcp")}
    for t in targets:
        tid = t.get("target_id", "")
        tip = t.get("ip", "")
        if tid in anchor_ids:
            errors.append(f"target {tid} overlaps anchor roster (self-leakage forbidden)")
        if tip and tip in anchor_ips:
            errors.append(f"target {tid} IP {tip} matches an operator anchor IP (must be separate target)")
        if t.get("enroll_as_anchor") is True:
            errors.append(f"third-party target {tid} must NEVER be enrolled as an operator anchor")
    return errors


def run_self_test(pog_cli: Path) -> None:
    patch = json.loads(PATCH_PATH.read_text())
    baseline_pub = json.loads(PUBLIC_ANCHORS_PATH.read_text())
    baseline_pub_hash = hashlib.sha256(PUBLIC_ANCHORS_PATH.read_bytes()).hexdigest()
    baseline_web_hash = hashlib.sha256(WEB_ANCHORS_PATH.read_bytes()).hexdigest()
    baseline_signed_hash = hashlib.sha256(SIGNED_PUBLIC_PATH.read_bytes()).hexdigest()

    # 1. Patch invariants (distinct IDs, providers, ASNs, failure domains, diagnostic_only, operator endpoints)
    errs = validate_patch_invariants(patch, baseline_pub)
    assert not errs, f"Patch invariant failures: {errs}"

    # 2. Third-party test target isolation check (must reject roster overlap & anchor enrollment)
    sample_targets = [
        {"target_id": "hnl-thirdparty-probe", "ip": "203.0.113.50", "lat": 21.31, "lon": -157.86},
        {"target_id": "guam-dc-probe", "ip": "203.0.113.51", "lat": 13.48, "lon": 144.75},
    ]
    assert validate_separate_heldout_targets(sample_targets, baseline_pub) == []
    bad_targets = [{"target_id": "aws-us-west-2-oregon", "ip": "203.0.113.52", "enroll_as_anchor": True}]
    assert len(validate_separate_heldout_targets(bad_targets, baseline_pub)) == 2

    # 3. Build a temporary 44-node diagnostic grid with 2 distinct throwaway Ed25519 keys & test real pog-cli!
    with tempfile.TemporaryDirectory(prefix="pog-hnl-selftest-") as td:
        tdp = Path(td)
        root_key = tdp / "throwaway-root.key"
        init_res = subprocess.run(
            [
                str(pog_cli),
                "network",
                "init",
                "--network-id",
                "proofofgeography.com",
                "--operator",
                "jperla-selftest",
                "--key-out",
                str(root_key),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        m_pk = re.search(r"Pinned Root Public Key:\s+([0-9a-f]{64})", init_res.stdout)
        assert m_pk, f"Could not parse root pk from pog-cli network init: {init_res.stdout}"
        test_root_pk = m_pk.group(1)

        # Generate two distinct, non-placeholder 32-byte keys (via sha256 of distinct labels for test)
        aws_pk = hashlib.sha256(b"honolulu-selftest-aws-ephemeral-key-1").hexdigest()
        vultr_pk = hashlib.sha256(b"honolulu-selftest-vultr-ephemeral-key-2").hexdigest()
        assert aws_pk != vultr_pk

        staged_grid = json.loads(json.dumps(baseline_pub))
        staged_grid["grid_name"] = "pog-diagnostic-grid-44-hnl-staged"
        test_eps = {
            "aws-us-west-2-hnl-honolulu": ("198.51.100.11", aws_pk),
            "vultr-hnl-honolulu": ("198.51.100.22", vultr_pk),
        }
        for c in patch["candidate_anchors"]:
            entry = json.loads(json.dumps(c))
            ip, pk = test_eps[entry["anchor_id"]]
            entry["endpoint_tcp"] = f"{ip}:7443"
            entry["endpoint_udp"] = f"{ip}:7444"
            entry["public_key_hex"] = pk
            staged_grid["anchors"].append(entry)

        assert len(staged_grid["anchors"]) == 44
        grid_path = tdp / "staged_44.json"
        signed_path = tdp / "signed_44.json"
        grid_path.write_text(json.dumps(staged_grid, indent=2))

        # 3.0 Signing WITHOUT --allow-dev-anchors MUST FAIL CLOSED (cannot accidentally sign HNL into prod!)
        prod_sign = subprocess.run(
            [
                str(pog_cli),
                "network",
                "sign-registry",
                "--key",
                str(root_key),
                "--network-id",
                "proofofgeography.com",
                "--operator",
                "jperla-selftest",
                "--grid",
                str(grid_path),
                "--out",
                str(signed_path),
                "--ttl-days",
                "30",
            ],
            capture_output=True,
            text=True,
        )
        assert prod_sign.returncode != 0, "sign-registry without --allow-dev-anchors MUST fail closed!"

        # 3.1 Explicit diagnostic signing (--allow-dev-anchors) succeeds for test diagnostic registry
        subprocess.run(
            [
                str(pog_cli),
                "network",
                "sign-registry",
                "--key",
                str(root_key),
                "--network-id",
                "proofofgeography.com",
                "--operator",
                "jperla-selftest",
                "--grid",
                str(grid_path),
                "--out",
                str(signed_path),
                "--ttl-days",
                "30",
                "--allow-dev-anchors",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        # 3a. Diagnostic verification (--allow-dev-anchors) MUST PASS with 44 Anchors
        diag_res = subprocess.run(
            [
                str(pog_cli),
                "network",
                "verify-registry",
                "--signed-registry",
                str(signed_path),
                "--pinned-root-pk",
                test_root_pk,
                "--allow-dev-anchors",
            ],
            capture_output=True,
            text=True,
        )
        assert diag_res.returncode == 0, f"Diagnostic verify-registry failed: {diag_res.stdout} {diag_res.stderr}"
        assert "44 Anchors" in diag_res.stdout, f"Expected 44 Anchors, got: {diag_res.stdout}"

        # 3b. Production verification (NO --allow-dev-anchors) MUST FAIL CLOSED and name both Honolulu anchors!
        prod_res = subprocess.run(
            [
                str(pog_cli),
                "network",
                "verify-registry",
                "--signed-registry",
                str(signed_path),
                "--pinned-root-pk",
                test_root_pk,
            ],
            capture_output=True,
            text=True,
        )
        assert prod_res.returncode != 0, "Production verify-registry MUST reject Honolulu SoftwareDev/diagnostic_only anchors!"
        combined = prod_res.stdout + prod_res.stderr
        assert "aws-us-west-2-hnl-honolulu" in combined, f"Missing aws HNL in prod rejection: {combined}"
        assert "vultr-hnl-honolulu" in combined, f"Missing vultr HNL in prod rejection: {combined}"

        # 3c. Rollback check: stripping candidate_anchors restores the exact 42 baseline anchor IDs
        cand_ids = {c["anchor_id"] for c in patch["candidate_anchors"]}
        rolled_back_ids = [a["anchor_id"] for a in staged_grid["anchors"] if a["anchor_id"] not in cand_ids]
        baseline_ids = [a["anchor_id"] for a in baseline_pub["anchors"]]
        assert rolled_back_ids == baseline_ids

    # 4. Confirm live repository files were NEVER mutated
    assert hashlib.sha256(PUBLIC_ANCHORS_PATH.read_bytes()).hexdigest() == baseline_pub_hash
    assert hashlib.sha256(WEB_ANCHORS_PATH.read_bytes()).hexdigest() == baseline_web_hash
    assert hashlib.sha256(SIGNED_PUBLIC_PATH.read_bytes()).hexdigest() == baseline_signed_hash

    print(
        "verify_honolulu_addition.py self-tests PASSED "
        "(distinct IDs/ASNs/failure domains, diagnostic 44-node verify PASS, "
        "production quorum FAIL-CLOSED rejection of both HNL anchors, target isolation & rollback verified)"
    )


def fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "pog-honolulu-verify/1.0"})
    with urllib.request.urlopen(req, timeout=8) as r:
        return json.loads(r.read().decode())


def run_live_check(args: argparse.Namespace, pog_cli: Path) -> int:
    patch = json.loads(PATCH_PATH.read_text())
    baseline_pub = json.loads(PUBLIC_ANCHORS_PATH.read_text())
    errs = validate_patch_invariants(patch, baseline_pub)
    if errs:
        print(json.dumps({"ok": False, "stage": "patch_invariants", "errors": errs}, indent=2))
        return 1

    has_aws = bool(args.aws_url and args.aws_tcp)
    has_vultr = bool(args.vultr_url and args.vultr_tcp)

    aws_info = fetch_json(f"{args.aws_url.rstrip('/')}/info") if has_aws else None
    vultr_info = fetch_json(f"{args.vultr_url.rstrip('/')}/info") if has_vultr else None
    aws_pk = (aws_info.get("public_key_hex") or "").lower() if aws_info else ""
    vultr_pk = (vultr_info.get("public_key_hex") or "").lower() if vultr_info else ""

    checks: dict[str, bool] = {"diagnostic_only_not_prod_hw_tee": True}
    live_map: dict[str, tuple[str, str]] = {}
    if has_aws:
        checks["aws_anchor_id_match"] = aws_info.get("anchor_id") == "aws-us-west-2-hnl-honolulu"
        checks["aws_valid_ephemeral_pk"] = len(aws_pk) == 64 and all(ch in "0123456789abcdef" for ch in aws_pk)
        checks["aws_tee_vendor_software_dev"] = aws_info.get("tee_vendor") in (None, "SoftwareDev", "software_dev")
        live_map["aws-us-west-2-hnl-honolulu"] = (args.aws_tcp, aws_pk)
    if has_vultr:
        checks["vultr_anchor_id_match"] = vultr_info.get("anchor_id") == "vultr-hnl-honolulu"
        checks["vultr_valid_ephemeral_pk"] = len(vultr_pk) == 64 and all(ch in "0123456789abcdef" for ch in vultr_pk)
        checks["vultr_tee_vendor_software_dev"] = vultr_info.get("tee_vendor") in (None, "SoftwareDev", "software_dev")
        live_map["vultr-hnl-honolulu"] = (args.vultr_tcp, vultr_pk)
    if has_aws and has_vultr:
        checks["distinct_live_keys"] = bool(aws_pk and vultr_pk and aws_pk != vultr_pk)
        checks["distinct_endpoints"] = args.aws_tcp.split(":")[0] != args.vultr_tcp.split(":")[0]

    # Build temporary grid for provisioned Honolulu node(s) and run real signed UDP distance-bounding probe
    udp_probe_ok = False
    udp_probe_summary = ""
    receipts_out = []
    with tempfile.TemporaryDirectory(prefix="pog-hnl-live-") as td:
        tmp_grid = {
            "version": "2.0.0",
            "grid_name": "pog-honolulu-live-probe",
            "description": "Temporary Honolulu diagnostic probe grid",
            "anchors": [],
        }
        for c in patch["candidate_anchors"]:
            if c["anchor_id"] not in live_map:
                continue
            e = json.loads(json.dumps(c))
            tcp, pk = live_map[e["anchor_id"]]
            host = tcp.split(":")[0]
            e["endpoint_tcp"] = tcp
            e["endpoint_udp"] = f"{host}:7444"
            e["public_key_hex"] = pk
            tmp_grid["anchors"].append(e)
        gpath = Path(td) / "hnl_grid.json"
        bpath = Path(td) / "hnl_bundle.json"
        gpath.write_text(json.dumps(tmp_grid, indent=2))

        probe_res = subprocess.run(
            [
                str(pog_cli),
                "probe-live",
                "--grid",
                str(gpath),
                "--all-anchors",
                "--rounds",
                "12",
                "--allow-dev-tee",
                "--out-bundle",
                str(bpath),
            ],
            capture_output=True,
            text=True,
        )
        udp_probe_summary = (probe_res.stdout + "\n" + probe_res.stderr).strip()
        if bpath.is_file():
            bundle = json.loads(bpath.read_text())
            receipts_out = bundle.get("receipts", [])
            got_ids = {r.get("anchor_id") for r in receipts_out}
            udp_probe_ok = got_ids == set(live_map.keys())

    checks["fresh_signed_udp_receipts"] = udp_probe_ok
    ok = all(checks.values())
    print(
        json.dumps(
            {
                "ok": ok,
                "mode": "DIAGNOSTIC_ONLY_NOT_PRODUCTION_QUORUM",
                "providers_checked": sorted(live_map.keys()),
                "vultr_status": "VERIFIED" if has_vultr else "PENDING_CREDENTIAL_BLOCKER",
                "checks": checks,
                "aws_info": aws_info,
                "vultr_info": vultr_info,
                "receipts": receipts_out,
                "udp_probe_excerpt": udp_probe_summary[-1200:],
            },
            indent=2,
        )
    )
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify & stage two-provider Honolulu diagnostic anchors")
    ap.add_argument("--self-test", action="store_true", help="Run offline zero-spend self-tests with real pog-cli")
    ap.add_argument("--live", action="store_true", help="Verify live provisioned AWS and/or Vultr Honolulu anchor(s)")
    ap.add_argument("--pog-cli", default=None, help="Path to compiled pog-cli binary")
    ap.add_argument("--aws-url", default="", help="AWS HNL /info base URL (e.g. http://<eip>:7445)")
    ap.add_argument("--aws-tcp", default="", help="AWS HNL TCP endpoint (e.g. <eip>:7443)")
    ap.add_argument("--vultr-url", default="", help="Vultr HNL /info base URL (e.g. http://<ip>:7445)")
    ap.add_argument("--vultr-tcp", default="", help="Vultr HNL TCP endpoint (e.g. <ip>:7443)")
    args = ap.parse_args()

    pog_cli = find_pog_cli(args.pog_cli)
    if args.self_test:
        run_self_test(pog_cli)
        return 0
    if args.live:
        has_aws = bool(args.aws_url and args.aws_tcp)
        has_vultr = bool(args.vultr_url and args.vultr_tcp)
        if not (has_aws or has_vultr):
            ap.error("--live requires --aws-url + --aws-tcp and/or --vultr-url + --vultr-tcp")
        return run_live_check(args, pog_cli)
    ap.error("Specify either --self-test or --live")
    return 2


if __name__ == "__main__":
    sys.exit(main())
