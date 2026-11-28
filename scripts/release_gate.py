#!/usr/bin/env python3
"""Proof of Geography Release Gate: Static Lint vs. Fail-Closed Production Promotion Authorization.

CRITICAL DISTINCTION (never conflated):
1. `--lint` (also `--check-repo`):
   STATIC LINT ONLY — NOT RELEASE AUTHORIZATION.
   Checks zero-SSH/shell-less measured image recipes, Terraform flags, and inspects the
   ACTUAL public roster (`config/signed_public_network.json`, `config/public_anchors.json`,
   `web/data/anchors.json`) separately from the simulated 72-node design grid
   (`config/signed_grid_72_network.json`). Keeps the SoftwareDev diagnostic test fleet available.

2. `--authorize-promotion`:
   REAL FAIL-CLOSED PRODUCTION RELEASE AUTHORIZATION GATE.
   Requires ALL of:
   - Real Rust verifier (`pog-cli network verify-registry` + `pog-cli network verify-attest`),
   - Correct pinned production operator trust root (`--pinned-root-pk`) & signed public registry
     (rejects SoftwareDev, placeholder keys like `0101...`, simulated `*.pog.example` hosts,
     invalid signatures, expired TTLs, or wrong `network_id`),
   - Measured software manifest (`--measured-manifest`: verifies zero-SSH/shell-less image recipes
     SHA-256 on disk AND pins allowed hardware measurements / Nitro PCR0/1/2),
   - Fresh hardware attestation & key binding for EVERY promoted node (live `/attest?nonce=<64-hex>`
     with fresh 32-byte caller nonce, Ed25519 Proof-of-Possession, pinned AMD ARK / Intel SGX
     Root CA / AWS Nitro Root-G1 verification, live key == signed registry key, non-stale
     operator endorsement signed by pinned root PK & matching coordinates, DEBUG=0, MIGRATE=0,
     and measurement in `--measured-manifest`),
   - Separately audited physical coordinates (`--coordinate-audit`: 100% anchor coverage,
     coordinates matching signed registry, bounded age & uncertainty, independent audit source &
     evidence ref, and explicit `hardware_identity_proves_coordinates: false`).

Usage:
  python3 scripts/release_gate.py --self-test
  python3 scripts/release_gate.py --lint
  python3 scripts/release_gate.py --authorize-promotion \\
      --signed-registry config/signed_public_network.json \\
      --pinned-root-pk fdff6d6d0b8364e459ffbb921430e39411bd812ec3ce766c2904b39bfa996ee1 \\
      --measured-manifest path/to/measured_manifest.json \\
      --coordinate-audit path/to/coordinate_audit.json \\
      --out-receipt path/to/promotion_authorization.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

OFFICIAL_NETWORK_ID = "proofofgeography.com"
OFFICIAL_PRODUCTION_ROOT_PK_HEX = "fdff6d6d0b8364e459ffbb921430e39411bd812ec3ce766c2904b39bfa996ee1"

FORBIDDEN_PROD_FLAGS = [
    "--allow-dev-tee",
    "--allow-dev-prover",
    "POG_ALLOW_DEV_TEE",
    "allow_software_dev: true",
    "allowSoftwareDev: true",
    "allow_software_dev=True",
]

FORBIDDEN_IMAGE_COMPONENTS = [
    "openssh",
    "sshd",
    "dropbear",
    "google-guest-agent",
    "amazon-ssm-agent",
    "waagent",
    "PermitRootLogin",
    "ssh_authorized_keys",
]

ALLOWED_HARDWARE_TEE_VENDORS = {"AmdSevSnp", "IntelTdx", "AwsNitro"}
PUBLIC_ROSTER_SIGNED_REL = "config/signed_public_network.json"
PUBLIC_ROSTER_GRID_REL = "config/public_anchors.json"
PUBLIC_WEB_ROSTER_REL = "web/data/anchors.json"
SIMULATED_GRID_REL = "config/signed_grid_72_network.json"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def find_pog_cli(repo_root: Path, explicit: Path | None = None) -> Path | None:
    if explicit:
        return explicit if explicit.exists() else None
    for cand in (
        repo_root / "target" / "release" / "pog-cli",
        repo_root / "target" / "debug" / "pog-cli",
    ):
        if cand.exists():
            return cand
    return None


def check_infra_file(path: Path) -> list[str]:
    errors: list[str] = []
    text = path.read_text(errors="replace")
    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        for flag in FORBIDDEN_PROD_FLAGS:
            if flag in line:
                errors.append(f"{path}:{line_no}: forbidden production dev fallback `{flag}`")
    return errors


def check_zero_ssh_image_spec(path: Path) -> list[str]:
    """Substantiate that measured production image recipes contain NO SSH server,
    NO interactive admin shell, and NO cloud remote-exec command path."""
    errors: list[str] = []
    text = path.read_text(errors="replace")
    name = path.name

    errors.extend(check_infra_file(path))
    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        if name.endswith(".nix") and "openssh.enable = false" in stripped:
            continue
        for tok in FORBIDDEN_IMAGE_COMPONENTS:
            if tok in line:
                errors.append(
                    f"{path}:{line_no}: measured production image contains forbidden SSH/remote-exec token `{tok}`"
                )

    if name.startswith("Dockerfile"):
        from_lines = [
            ln.strip()
            for ln in text.splitlines()
            if ln.strip().upper().startswith("FROM ")
        ]
        if not from_lines:
            errors.append(f"{path}: missing FROM stage")
        else:
            final_from = from_lines[-1].lower()
            if not (final_from.startswith("from scratch") or "distroless" in final_from):
                errors.append(
                    f"{path}: final runtime stage `{from_lines[-1]}` is NOT shell-less (`FROM scratch` or `distroless` required)"
                )

    if name.endswith(".nix"):
        required_snippets = [
            "services.openssh.enable = false;",
            "users.mutableUsers = false;",
            "security.sudo.enable = false;",
            'systemd.services."serial-getty@ttyS0".enable = false;',
            'systemd.services."getty@tty1".enable = false;',
        ]
        for req in required_snippets:
            if req not in text:
                errors.append(
                    f"{path}: measured NixOS CVM image missing mandatory zero-SSH/zero-shell directive `{req}`"
                )
    return errors


def check_eif_measurements(eif_path: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = json.loads(eif_path.read_text())
    except Exception as e:
        return [f"{eif_path}: invalid JSON: {e}"]
    meas = data.get("Measurements", data)
    for pcr in ("PCR0", "PCR1", "PCR2"):
        val = meas.get(pcr, "")
        if not isinstance(val, str) or len(val) != 96 or not re.fullmatch(r"[0-9a-fA-F]{96}", val):
            errors.append(f"{eif_path}: {pcr} must be a 96-hex-char SHA-384 digest, got {val!r}")
        elif set(val) == {"0"}:
            errors.append(f"{eif_path}: {pcr} is all-zero (Nitro Enclave debug mode forbidden in production)")
    return errors


def run_real_cli_verify_registry(
    pog_cli: Path,
    reg_path: Path,
    pinned_root_pk: str,
    expected_network_id: str | None = None,
    allow_dev_anchors: bool = False,
) -> tuple[bool, str]:
    cmd = [
        str(pog_cli),
        "network",
        "verify-registry",
        "--signed-registry",
        str(reg_path),
        "--pinned-root-pk",
        pinned_root_pk,
    ]
    if expected_network_id:
        cmd.extend(["--expected-network-id", expected_network_id])
    if allow_dev_anchors:
        cmd.append("--allow-dev-anchors")
    res = subprocess.run(cmd, capture_output=True, text=True)
    msg = (res.stdout + "\n" + res.stderr).strip()
    return (res.returncode == 0, msg)


def validate_measured_manifest(manifest_path: Path, repo_root: Path) -> tuple[dict | None, list[str]]:
    errors: list[str] = []
    try:
        manifest = json.loads(manifest_path.read_text())
    except Exception as e:
        return None, [f"{manifest_path}: invalid JSON: {e}"]

    allowed = manifest.get("allowed_measurements")
    if not isinstance(allowed, dict) or not allowed:
        errors.append(f"{manifest_path}: missing non-empty `allowed_measurements` map by TEE vendor")
    else:
        for vendor, vals in allowed.items():
            if vendor not in ALLOWED_HARDWARE_TEE_VENDORS:
                errors.append(f"{manifest_path}: forbidden/unknown vendor `{vendor}` in allowed_measurements")
                continue
            if not isinstance(vals, list) or not vals:
                errors.append(f"{manifest_path}: vendor `{vendor}` must specify >=1 pinned 96-hex SHA-384 measurement")
                continue
            for v in vals:
                if not isinstance(v, str) or not re.fullmatch(r"[0-9a-fA-F]{96}", v):
                    errors.append(f"{manifest_path}: invalid 96-hex measurement `{v}` for {vendor}")
                elif set(v) == {"0"}:
                    errors.append(f"{manifest_path}: all-zero debug measurement forbidden for {vendor}")

    for pcr_field in ("allowed_pcr1", "allowed_pcr2"):
        vals = manifest.get(pcr_field, [])
        if vals:
            for v in vals:
                if not isinstance(v, str) or not re.fullmatch(r"[0-9a-fA-F]{96}", v) or set(v) == {"0"}:
                    errors.append(f"{manifest_path}: invalid or all-zero {pcr_field} digest `{v}`")

    recipes = manifest.get("image_recipes")
    if not isinstance(recipes, dict) or not recipes:
        errors.append(f"{manifest_path}: missing `image_recipes` SHA-256 bindings for zero-SSH reproducible images")
    else:
        for rel_path, expected_sha in recipes.items():
            if not isinstance(expected_sha, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha):
                errors.append(f"{manifest_path}: invalid 64-hex SHA-256 for image recipe `{rel_path}`")
                continue
            full = (repo_root / rel_path).resolve()
            if not full.exists():
                errors.append(f"{manifest_path}: image recipe `{rel_path}` not found on disk")
                continue
            actual_sha = sha256_file(full)
            if actual_sha.lower() != expected_sha.lower():
                errors.append(
                    f"{manifest_path}: image recipe `{rel_path}` SHA-256 mismatch (disk={actual_sha[:16]}... != manifest={expected_sha[:16]}...)"
                )
            errors.extend(check_zero_ssh_image_spec(full))

    if manifest.get("zero_ssh_verified") is not True:
        errors.append(f"{manifest_path}: must explicitly assert `zero_ssh_verified: true`")
    return manifest, errors


def validate_coordinate_audit(
    audit_path: Path,
    anchors: list[dict],
    now_unix_s: int,
    max_age_days: int = 180,
) -> tuple[dict | None, list[str]]:
    """Verify separately audited physical coordinates for EVERY anchor in the promoted registry.
    Enforces the product invariant: hardware TEE identity NEVER proves physical coordinates.
    """
    errors: list[str] = []
    try:
        dossier = json.loads(audit_path.read_text())
    except Exception as e:
        return None, [f"{audit_path}: invalid JSON: {e}"]

    if dossier.get("hardware_identity_proves_coordinates") is not False:
        errors.append(
            f"{audit_path}: top-level `hardware_identity_proves_coordinates` MUST be explicitly `false`"
        )

    entries = dossier.get("anchors")
    if not isinstance(entries, dict) or not entries:
        return dossier, errors + [f"{audit_path}: missing `anchors` map keyed by anchor_id"]

    max_age_s = max_age_days * 86_400
    for a in anchors:
        aid = a.get("anchor_id", "<missing>")
        rec = entries.get(aid)
        if not isinstance(rec, dict):
            errors.append(f"{audit_path}: missing separate coordinate audit entry for `{aid}`")
            continue
        if rec.get("hardware_identity_proves_coordinates") is not False:
            errors.append(
                f"{audit_path}: `{aid}` must explicitly set `hardware_identity_proves_coordinates: false`"
            )
        for req_str in ("source", "evidence_ref", "auditor"):
            val = rec.get(req_str)
            if not isinstance(val, str) or not val.strip():
                errors.append(f"{audit_path}: `{aid}` missing non-empty `{req_str}`")

        unc = rec.get("uncertainty_km")
        if not isinstance(unc, (int, float)) or unc <= 0 or unc > 250:
            errors.append(f"{audit_path}: `{aid}` uncertainty_km must be in (0, 250], got {unc!r}")

        audited_at = rec.get("audited_at_unix_s")
        if not isinstance(audited_at, int) or audited_at <= 0:
            errors.append(f"{audit_path}: `{aid}` missing valid integer `audited_at_unix_s`")
        elif audited_at > now_unix_s + 300:
            errors.append(f"{audit_path}: `{aid}` audited_at_unix_s is in the future")
        elif now_unix_s - audited_at > max_age_s:
            errors.append(
                f"{audit_path}: `{aid}` coordinate audit expired ({(now_unix_s - audited_at) // 86400}d > {max_age_days}d)"
            )

        reg_loc = a.get("location") or {}
        try:
            dlat = abs(float(rec["lat"]) - float(reg_loc["lat"]))
            dlon = abs(float(rec["lon"]) - float(reg_loc["lon"]))
            if dlat > 0.001 or dlon > 0.001:
                errors.append(
                    f"{audit_path}: `{aid}` audited coords ({rec['lat']},{rec['lon']}) drift from registry ({reg_loc.get('lat')},{reg_loc.get('lon')})"
                )
        except Exception:
            errors.append(f"{audit_path}: `{aid}` invalid numeric lat/lon")

    return dossier, errors


def check_web_roster_parity(web_roster_path: Path, reg: dict) -> list[str]:
    errors: list[str] = []
    try:
        web = json.loads(web_roster_path.read_text())
    except Exception as e:
        return [f"{web_roster_path}: invalid JSON: {e}"]

    reg_anchors = {a["anchor_id"]: a for a in reg.get("grid", {}).get("anchors", [])}
    web_anchors = {a["id"]: a for a in web.get("anchors", [])}
    if set(reg_anchors.keys()) != set(web_anchors.keys()):
        missing = sorted(set(reg_anchors) - set(web_anchors))
        extra = sorted(set(web_anchors) - set(reg_anchors))
        errors.append(
            f"{web_roster_path}: web roster anchor IDs diverge from signed registry (missing={missing[:5]}, extra={extra[:5]})"
        )
    if web.get("hw_tee_count") != len(reg_anchors):
        errors.append(
            f"{web_roster_path}: hw_tee_count={web.get('hw_tee_count')} != {len(reg_anchors)} promoted hardware TEE anchors"
        )
    for aid, wa in web_anchors.items():
        if wa.get("defaultTee") not in ALLOWED_HARDWARE_TEE_VENDORS:
            errors.append(f"{web_roster_path}: `{aid}` defaultTee={wa.get('defaultTee')!r} is not a hardware TEE")
    return errors


def fetch_and_verify_anchor_live(
    repo_root: Path,
    pog_cli: Path,
    reg_path: Path,
    pinned_root_pk: str,
    anchor: dict,
    manifest: dict,
    amd_product: str = "Milan",
) -> tuple[bool, dict]:
    """Fetch a fresh caller-nonce `/attest?nonce=<64-hex>` over HTTPS/HTTP and verify it
    using BOTH `scripts/verify_public_node.py` (fetching AMD KDS certs if needed) AND
    the real Rust cryptographic verifier `pog-cli network verify-attest`!"""
    aid = anchor["anchor_id"]
    vendor = anchor["tee_vendor"]
    allowed_meas = manifest.get("allowed_measurements", {}).get(vendor, [])
    if not allowed_meas:
        return False, {"anchor_id": aid, "error": f"No allowed_measurements pinned for vendor {vendor}"}

    base_url = anchor.get("https_url")
    if not base_url:
        host = anchor.get("endpoint_tcp", "").split(":")[0]
        if not host:
            return False, {"anchor_id": aid, "error": "Missing https_url and endpoint_tcp"}
        base_url = f"http://{host}:7445"

    caller_nonce_hex = os.urandom(32).hex()
    with tempfile.TemporaryDirectory() as td:
        saved_attest = Path(td) / f"{aid}.attest.json"
        if vendor in ("AmdSevSnp", "IntelTdx"):
            vp = subprocess.run(
                [
                    sys.executable,
                    str(repo_root / "scripts" / "verify_public_node.py"),
                    "--url",
                    base_url,
                    "--nonce-hex",
                    caller_nonce_hex,
                    "--amd-product",
                    amd_product,
                    "--require-fresh-attest",
                    "--save-attest-json",
                    str(saved_attest),
                ],
                capture_output=True,
                text=True,
            )
            if not saved_attest.exists():
                return False, {
                    "anchor_id": aid,
                    "url": base_url,
                    "error": f"Live /attest?nonce= fetch failed via verify_public_node.py: {(vp.stderr or vp.stdout).strip()[:400]}",
                }
        else:
            # AwsNitro: fetch fresh /attest?nonce= directly, then verify COSE_Sign1/Root-G1 in Rust pog-cli!
            try:
                req = urllib.request.Request(
                    f"{base_url.rstrip('/')}/attest?nonce={caller_nonce_hex}",
                    headers={"User-Agent": "pog-release-gate/2.0"},
                )
                with urllib.request.urlopen(req, timeout=8.0) as resp:
                    saved_attest.write_bytes(resp.read())
            except Exception as e:
                return False, {"anchor_id": aid, "url": base_url, "error": f"Live /attest?nonce= fetch failed: {e}"}

        return verify_saved_attest_with_rust_cli(
            pog_cli=pog_cli,
            reg_path=reg_path,
            pinned_root_pk=pinned_root_pk,
            anchor_id=aid,
            caller_nonce_hex=caller_nonce_hex,
            attest_json=saved_attest,
            manifest=manifest,
            vendor=vendor,
        )


def verify_saved_attest_with_rust_cli(
    pog_cli: Path,
    reg_path: Path,
    pinned_root_pk: str,
    anchor_id: str,
    caller_nonce_hex: str,
    attest_json: Path,
    manifest: dict,
    vendor: str,
) -> tuple[bool, dict]:
    """Invoke the REAL Rust verifier `pog-cli network verify-attest` (fail-closed, NO --allow-dev-tee!)."""
    allowed_meas = manifest.get("allowed_measurements", {}).get(vendor, [])
    if not allowed_meas:
        return False, {"anchor_id": anchor_id, "error": f"No allowed_measurements pinned for {vendor}"}

    cmd = [
        str(pog_cli),
        "network",
        "verify-attest",
        "--signed-registry",
        str(reg_path),
        "--pinned-root-pk",
        pinned_root_pk,
        "--anchor-id",
        anchor_id,
        "--caller-nonce-hex",
        caller_nonce_hex,
        "--attest-json",
        str(attest_json),
    ]
    for m in allowed_meas:
        cmd.extend(["--expected-measurement", m])
    if vendor == "AwsNitro":
        for p1 in manifest.get("allowed_pcr1", []):
            cmd.extend(["--expected-pcr1", p1])
        for p2 in manifest.get("allowed_pcr2", []):
            cmd.extend(["--expected-pcr2", p2])

    res = subprocess.run(cmd, capture_output=True, text=True)
    try:
        parsed = json.loads(res.stdout) if res.stdout.strip() else {"raw_stderr": res.stderr.strip()}
    except Exception:
        parsed = {"raw_stdout": res.stdout.strip(), "raw_stderr": res.stderr.strip()}
    ok = (
        res.returncode == 0
        and isinstance(parsed, dict)
        and parsed.get("proof_eligible") is True
        and parsed.get("hardware_tee_attested") is True
        and parsed.get("fresh_caller_nonce_verified") is True
        and parsed.get("proof_of_possession_verified") is True
        and parsed.get("key_matches_published_registry") is True
        and parsed.get("endorsement_matches_live_key") is True
        and parsed.get("endorsement_signature_valid") is True
    )
    return ok, parsed


def run_static_lint(repo_root: Path, pog_cli: Path | None, strict_public_roster: bool = False) -> tuple[int, dict]:
    """STATIC LINT ONLY — explicitly NOT production release authorization.
    Audits measured production image specs (`Dockerfile.anchor`, `infra/reproducible/Dockerfile`,
    `infra/images/flake.nix`), separately audits non-production `infra/terraform/pilot/*.tf`,
    and inspects the ACTUAL public roster (`config/signed_public_network.json`,
    `config/public_anchors.json`, `web/data/anchors.json`) rather than only `signed_grid_72_network.json`."""
    measured_image_findings: dict[str, list[str]] = {}
    for rel in [
        "infra/images/Dockerfile.anchor",
        "infra/reproducible/Dockerfile",
        "infra/images/flake.nix",
        "infra/images/build-nitro-eif.sh",
    ]:
        p = repo_root / rel
        if p.exists():
            errs = check_zero_ssh_image_spec(p) if rel.endswith(("Dockerfile", "Dockerfile.anchor", ".nix")) else check_infra_file(p)
            if errs:
                measured_image_findings[rel] = errs

    pilot_tf_findings: dict[str, list[str]] = {}
    tf_dir = repo_root / "infra" / "terraform" / "pilot"
    if tf_dir.exists():
        for p in sorted(tf_dir.rglob("*.tf")):
            errs = check_infra_file(p)
            if errs:
                pilot_tf_findings[str(p.relative_to(repo_root))] = errs

    # Inspect the ACTUAL public roster (signed_public_network.json, public_anchors.json, web/data/anchors.json)
    pub_signed = repo_root / PUBLIC_ROSTER_SIGNED_REL
    web_roster = repo_root / PUBLIC_WEB_ROSTER_REL
    sim_grid = repo_root / SIMULATED_GRID_REL

    roster_audit: dict = {
        "public_signed_registry": PUBLIC_ROSTER_SIGNED_REL,
        "public_grid": PUBLIC_ROSTER_GRID_REL,
        "web_roster": PUBLIC_WEB_ROSTER_REL,
        "simulated_grid_excluded_from_prod": SIMULATED_GRID_REL,
        "software_test_fleet_available": True,
        "production_authorized": False,
        "blockers": [],
    }

    if not pub_signed.exists():
        roster_audit["blockers"].append(f"Missing public signed registry {PUBLIC_ROSTER_SIGNED_REL}")
    else:
        reg = json.loads(pub_signed.read_text())
        anchors = reg.get("grid", {}).get("anchors", [])
        dev_count = sum(1 for a in anchors if a.get("tee_vendor") not in ALLOWED_HARDWARE_TEE_VENDORS)
        roster_audit["public_roster_anchor_count"] = len(anchors)
        roster_audit["public_roster_software_dev_count"] = dev_count
        roster_audit["public_roster_hw_tee_declared_count"] = len(anchors) - dev_count
        roster_audit["public_roster_root_pk_hex"] = reg.get("root_public_key_hex")
        if pog_cli:
            sig_ok, sig_msg = run_real_cli_verify_registry(
                pog_cli, pub_signed, OFFICIAL_PRODUCTION_ROOT_PK_HEX, OFFICIAL_NETWORK_ID, allow_dev_anchors=True
            )
            prod_ok, prod_msg = run_real_cli_verify_registry(
                pog_cli, pub_signed, OFFICIAL_PRODUCTION_ROOT_PK_HEX, OFFICIAL_NETWORK_ID, allow_dev_anchors=False
            )
            roster_audit["public_roster_signature_valid_via_pog_cli"] = sig_ok
            roster_audit["public_roster_signature_note"] = sig_msg
            roster_audit["public_roster_prod_hygiene_via_pog_cli"] = prod_ok
            if not sig_ok:
                roster_audit["blockers"].append(f"Public signed registry signature invalid: {sig_msg}")
            if not prod_ok:
                roster_audit["blockers"].append(f"Public roster fails production membership/hygiene: {prod_msg}")
        else:
            roster_audit["public_roster_signature_valid_via_pog_cli"] = None
            roster_audit["blockers"].append("Compiled `pog-cli` binary not found — cannot cryptographically verify registry")

        # Verify simulated grid_72 is explicitly rejected by production hygiene!
        if sim_grid.exists() and pog_cli:
            sim_ok, _ = run_real_cli_verify_registry(
                pog_cli, sim_grid, OFFICIAL_PRODUCTION_ROOT_PK_HEX, OFFICIAL_NETWORK_ID, allow_dev_anchors=False
            )
            roster_audit["simulated_grid_72_rejected_for_prod"] = not sim_ok
            if sim_ok:
                measured_image_findings[SIMULATED_GRID_REL] = ["Simulated grid_72 unexpectedly passed production hygiene!"]

    if web_roster.exists():
        w = json.loads(web_roster.read_text())
        roster_audit["web_roster_count"] = len(w.get("anchors", []))
        roster_audit["web_roster_hw_tee_count"] = w.get("hw_tee_count")

    report = {
        "mode": "STATIC_LINT_ONLY_NOT_RELEASE_AUTHORIZATION",
        "release_authorized": False,
        "authorization_notice": (
            "Static lint checks measured image recipes and transparently reports non-production pilot Terraform "
            "and public roster blockers while keeping the SoftwareDev diagnostic test fleet available. "
            "It NEVER authorizes production promotion. Run `--authorize-promotion` via `scripts/promote_production.py`."
        ),
        "measured_image_hygiene_passed": len(measured_image_findings) == 0,
        "measured_image_hygiene_findings": measured_image_findings,
        "pilot_test_fleet_non_production_findings": pilot_tf_findings,
        "public_roster_audit": roster_audit,
    }
    exit_code = 0
    if measured_image_findings:
        exit_code = 1
    if strict_public_roster and (roster_audit["blockers"] or pilot_tf_findings):
        exit_code = 1
    return exit_code, report


def run_authorize_promotion(args: argparse.Namespace, repo_root: Path) -> tuple[int, dict]:
    """FAIL-CLOSED PRODUCTION RELEASE AUTHORIZATION GATE."""
    now = int(time.time())
    errors: list[str] = []
    pog_cli = find_pog_cli(repo_root, args.pog_cli)
    if not pog_cli:
        return 1, {
            "mode": "PRODUCTION_RELEASE_AUTHORIZATION",
            "authorized": False,
            "errors": ["Real Rust verifier `pog-cli` not found (build with `cargo build --release --bin pog-cli` or pass `--pog-cli`)."],
        }

    # 1. Require explicit signed registry (default: public roster, NEVER grid_72!) & pinned root PK
    reg_path: Path = args.signed_registry
    if not reg_path.exists():
        return 1, {"mode": "PRODUCTION_RELEASE_AUTHORIZATION", "authorized": False, "errors": [f"Signed registry not found: {reg_path}"]}
    if reg_path.name == "signed_grid_72_network.json":
        return 1, {
            "mode": "PRODUCTION_RELEASE_AUTHORIZATION",
            "authorized": False,
            "errors": ["Refusing simulated `signed_grid_72_network.json` — promotion requires the real production public registry."],
        }

    pinned_root_pk = (args.pinned_root_pk or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", pinned_root_pk):
        errors.append("`--pinned-root-pk` must be a pinned 64-hex Ed25519 operator root public key")
    elif args.expected_network_id == OFFICIAL_NETWORK_ID and pinned_root_pk != OFFICIAL_PRODUCTION_ROOT_PK_HEX:
        errors.append(
            f"Pinned root PK `{pinned_root_pk[:16]}...` does not match official production trust root `{OFFICIAL_PRODUCTION_ROOT_PK_HEX[:16]}...` for `{OFFICIAL_NETWORK_ID}`"
        )

    # 2. Verify signed registry signature, expiry, network_id, and production hygiene via REAL `pog-cli`
    reg_ok, reg_msg = run_real_cli_verify_registry(
        pog_cli=pog_cli,
        reg_path=reg_path,
        pinned_root_pk=pinned_root_pk,
        expected_network_id=args.expected_network_id,
        allow_dev_anchors=False,
    )
    if not reg_ok:
        errors.append(f"Real verifier `pog-cli network verify-registry` REJECTED registry: {reg_msg}")

    reg = json.loads(reg_path.read_text())
    all_anchors = reg.get("grid", {}).get("anchors", [])

    # 3. Validate measured software manifest & zero-SSH image recipes on disk
    manifest, manifest_errs = validate_measured_manifest(args.measured_manifest, repo_root)
    errors.extend(manifest_errs)

    # 4. Validate separately audited physical coordinates for EVERY anchor in the registry
    _, coord_errs = validate_coordinate_audit(
        args.coordinate_audit, all_anchors, now, max_age_days=args.max_coord_audit_age_days
    )
    errors.extend(coord_errs)

    # 5. Optional web roster parity check
    if args.web_roster:
        errors.extend(check_web_roster_parity(args.web_roster, reg))

    # 6. Fresh hardware attestation + fresh key binding + operator endorsement via REAL verifier
    canary_ids = set(args.canary_anchor_id or [])
    target_anchors = [a for a in all_anchors if (not canary_ids or a["anchor_id"] in canary_ids)]
    if canary_ids and len(target_anchors) != len(canary_ids):
        missing = sorted(canary_ids - {a["anchor_id"] for a in target_anchors})
        errors.append(f"Requested --canary-anchor-id not in signed registry: {missing}")

    per_anchor_reports = []
    if manifest is not None and reg_ok:
        if args.fresh_attest_dir:
            nonce_manifest_path = args.fresh_attest_dir / "nonces.json"
            if not nonce_manifest_path.exists():
                errors.append(f"{args.fresh_attest_dir}: missing `nonces.json` mapping anchor_id -> fresh caller_nonce_hex & collected_at_unix_s")
            else:
                nm = json.loads(nonce_manifest_path.read_text())
                collected_at = nm.get("collected_at_unix_s", 0)
                if not isinstance(collected_at, int) or abs(now - collected_at) > args.max_attest_age_seconds:
                    errors.append(
                        f"{nonce_manifest_path}: fresh attestation bundle is stale or missing valid `collected_at_unix_s` (max age {args.max_attest_age_seconds}s)"
                    )
                nonce_map = nm.get("nonces", {})
                for a in target_anchors:
                    aid = a["anchor_id"]
                    att_file = args.fresh_attest_dir / f"{aid}.attest.json"
                    nonce_hex = nonce_map.get(aid, "")
                    if not att_file.exists() or not re.fullmatch(r"[0-9a-fA-F]{64}", nonce_hex):
                        errors.append(f"Missing fresh attestation file or 64-hex nonce for `{aid}` in {args.fresh_attest_dir}")
                        continue
                    ok, detail = verify_saved_attest_with_rust_cli(
                        pog_cli=pog_cli,
                        reg_path=reg_path,
                        pinned_root_pk=pinned_root_pk,
                        anchor_id=aid,
                        caller_nonce_hex=nonce_hex,
                        attest_json=att_file,
                        manifest=manifest,
                        vendor=a["tee_vendor"],
                    )
                    per_anchor_reports.append({"anchor_id": aid, "verified": ok, "detail": detail})
                    if not ok:
                        errors.append(
                            f"Real verifier REJECTED fresh hardware attestation for `{aid}`: {detail.get('failure_reasons') or detail}"
                        )
        else:
            for a in target_anchors:
                ok, detail = fetch_and_verify_anchor_live(
                    repo_root=repo_root,
                    pog_cli=pog_cli,
                    reg_path=reg_path,
                    pinned_root_pk=pinned_root_pk,
                    anchor=a,
                    manifest=manifest,
                    amd_product=args.amd_product,
                )
                per_anchor_reports.append({"anchor_id": a["anchor_id"], "verified": ok, "detail": detail})
                if not ok:
                    errors.append(
                        f"Live fresh hardware attestation FAILED for `{a['anchor_id']}`: {detail.get('failure_reasons') or detail.get('error') or detail}"
                    )

    authorized = len(errors) == 0 and len(per_anchor_reports) == len(target_anchors) and len(target_anchors) > 0
    scope = "canary_subset_only" if canary_ids else "full_fleet_production"
    receipt = {
        "mode": "PRODUCTION_RELEASE_AUTHORIZATION",
        "authorized": authorized,
        "scope": scope,
        "authorized_at_unix_s": now,
        "network_id": reg.get("network_id"),
        "pinned_root_pk_hex": pinned_root_pk,
        "pog_cli_path": str(pog_cli),
        "pog_cli_sha256": sha256_file(pog_cli),
        "signed_registry_path": str(reg_path),
        "signed_registry_sha256": sha256_file(reg_path),
        "measured_manifest_sha256": sha256_file(args.measured_manifest) if args.measured_manifest.exists() else None,
        "coordinate_audit_sha256": sha256_file(args.coordinate_audit) if args.coordinate_audit.exists() else None,
        "anchors_verified_count": sum(1 for r in per_anchor_reports if r["verified"]),
        "anchors_required_count": len(target_anchors),
        "hardware_identity_proves_coordinates": False,
        "errors": errors,
        "per_anchor": per_anchor_reports,
    }
    if authorized and args.out_receipt:
        args.out_receipt.parent.mkdir(parents=True, exist_ok=True)
        args.out_receipt.write_text(json.dumps(receipt, indent=2) + "\n")
    return (0 if authorized else 1), receipt


def run_self_tests() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    pog_cli = find_pog_cli(repo_root)
    assert pog_cli is not None, "pog-cli binary required for real-verifier self-tests (`cargo build --release --bin pog-cli`)"

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        now = int(time.time())

        # 1. Zero-SSH / shell-less measured image checks (positive & negative)
        bad_df = d / "Dockerfile.anchor"
        bad_df.write_text("FROM rust:1.94-alpine AS builder\nFROM alpine:3.20\nRUN apk add openssh\n")
        bad_df_errs = check_zero_ssh_image_spec(bad_df)
        assert any("openssh" in e for e in bad_df_errs) and any("shell-less" in e for e in bad_df_errs), bad_df_errs

        good_df = d / "Dockerfile.prod"
        good_df.write_text('FROM rust:1.94-alpine AS builder\nFROM scratch AS runtime\nENTRYPOINT ["/usr/local/bin/pog-anchor"]\n')
        assert not check_zero_ssh_image_spec(good_df)

        for rel in ("infra/images/Dockerfile.anchor", "infra/reproducible/Dockerfile", "infra/images/flake.nix"):
            assert not check_zero_ssh_image_spec(repo_root / rel), f"Repo image spec failed: {rel}"

        # 2. Real `pog-cli` ACCEPTS our 100% Hardware TEE public roster in strict production mode,
        #    and REJECTS simulated grid_72 and any SoftwareDev roster!
        pub_ok, pub_msg = run_real_cli_verify_registry(
            pog_cli, repo_root / PUBLIC_ROSTER_SIGNED_REL, OFFICIAL_PRODUCTION_ROOT_PK_HEX, OFFICIAL_NETWORK_ID, allow_dev_anchors=False
        )
        assert pub_ok, f"Expected 100% Hardware TEE public roster to pass strict production verify, got: {pub_ok} {pub_msg}"

        sim_ok, sim_msg = run_real_cli_verify_registry(
            pog_cli, repo_root / SIMULATED_GRID_REL, OFFICIAL_PRODUCTION_ROOT_PK_HEX, OFFICIAL_NETWORK_ID, allow_dev_anchors=False
        )
        assert not sim_ok, f"Expected simulated grid_72 rejection, got: {sim_msg}"

        # Also verify a signed SoftwareDev roster is strictly rejected when allow_dev_anchors=False!
        dev_key = d / "dev_op_key.json"
        subprocess.run(
            [str(pog_cli), "network", "init", "--network-id", "dev-test.invalid", "--operator", "test", "--key-out", str(dev_key)],
            check=True, capture_output=True,
        )
        dev_pk = json.loads(dev_key.read_text())["public_key_hex"]
        dev_grid_data = json.loads((repo_root / PUBLIC_ROSTER_SIGNED_REL).read_text())["grid"]
        dev_grid_data["anchors"] = dev_grid_data["anchors"][:1]
        dev_grid_data["anchors"][0]["tee_vendor"] = "SoftwareDev"
        dev_grid_path = d / "dev_grid.json"
        dev_grid_path.write_text(json.dumps(dev_grid_data))
        dev_signed_path = d / "dev_signed.json"
        subprocess.run(
            [
                str(pog_cli), "network", "sign-registry",
                "--key", str(dev_key),
                "--network-id", "dev-test.invalid",
                "--operator", "test",
                "--grid", str(dev_grid_path),
                "--out", str(dev_signed_path),
                "--allow-dev-anchors",
            ],
            check=True, capture_output=True,
        )
        dev_ok, dev_msg = run_real_cli_verify_registry(
            pog_cli, dev_signed_path, dev_pk, "dev-test.invalid", allow_dev_anchors=False
        )
        assert not dev_ok and "SoftwareDev" in dev_msg, f"Expected SoftwareDev rejection, got: {dev_ok} {dev_msg}"
        dev_diag_ok, _ = run_real_cli_verify_registry(
            pog_cli, dev_signed_path, dev_pk, "dev-test.invalid", allow_dev_anchors=True
        )
        assert dev_diag_ok, "SoftwareDev signed registry should verify only when --allow-dev-anchors is set"

        # Also verify an all-HW-TEE simulated grid with placeholder 0101.. keys / *.pog.example is rejected!
        sim_hw_key = d / "sim_op_key.json"
        subprocess.run(
            [str(pog_cli), "network", "init", "--network-id", "sim-test.invalid", "--operator", "test", "--key-out", str(sim_hw_key)],
            check=True, capture_output=True,
        )
        sim_hw_pk = json.loads(sim_hw_key.read_text())["public_key_hex"]
        sim_hw_grid = d / "sim_hw_grid.json"
        sim_hw_grid.write_text(json.dumps({
            "version": "2.0.0",
            "grid_name": "sim-hw-placeholder",
            "description": "sim",
            "anchors": [{
                "anchor_id": "edge-hnl",
                "cloud_provider": "edge",
                "region": "us-hi",
                "city": "Honolulu",
                "tee_vendor": "AmdSevSnp",
                "instance_type": "baremetal",
                "location": {"lat": 21.3, "lon": -157.8},
                "endpoint_tcp": "edge-hnl.pog.example:7443",
                "endpoint_udp": "edge-hnl.pog.example:7444",
                "public_key_hex": "01" * 32,
            }],
        }))
        sim_hw_signed = d / "sim_hw_signed.json"
        subprocess.run(
            [
                str(pog_cli), "network", "sign-registry",
                "--key", str(sim_hw_key),
                "--network-id", "sim-test.invalid",
                "--operator", "test",
                "--grid", str(sim_hw_grid),
                "--out", str(sim_hw_signed),
                "--ttl-days", "30",
            ],
            check=True, capture_output=True,
        )
        sim_hw_ok, sim_hw_msg = run_real_cli_verify_registry(pog_cli, sim_hw_signed, sim_hw_pk, "sim-test.invalid", allow_dev_anchors=False)
        assert not sim_hw_ok and "placeholder" in sim_hw_msg.lower(), f"Expected placeholder rejection, got: {sim_hw_msg}"

        # 3. Real `pog-cli` rejects wrong pinned root PK and tampered registry even with hardware vendor labels!
        key_file = d / "op_key.json"
        subprocess.run(
            [str(pog_cli), "network", "init", "--network-id", "test-constellation.invalid", "--operator", "test", "--key-out", str(key_file)],
            check=True, capture_output=True,
        )
        op_pk = json.loads(key_file.read_text())["public_key_hex"]
        grid_file = d / "grid.json"
        grid_file.write_text(json.dumps({
            "version": "2.0.0",
            "grid_name": "test-hw",
            "description": "test",
            "anchors": [{
                "anchor_id": "gcp-europe-west3-frankfurt",
                "cloud_provider": "gcp",
                "region": "europe-west3",
                "city": "Frankfurt, DE",
                "tee_vendor": "AmdSevSnp",
                "instance_type": "n2d-standard-2",
                "location": {"lat": 50.1109, "lon": 8.6821},
                "endpoint_tcp": "35.207.136.128:7443",
                "endpoint_udp": "35.207.136.128:7444",
                "https_url": "https://fra-gcp.test-constellation.invalid",
                "public_key_hex": "1234567890abcdef" * 4,
            }],
        }))
        signed_reg = d / "signed.json"
        subprocess.run(
            [
                str(pog_cli), "network", "sign-registry",
                "--key", str(key_file),
                "--network-id", "test-constellation.invalid",
                "--operator", "test",
                "--grid", str(grid_file),
                "--out", str(signed_reg),
                "--ttl-days", "30",
            ],
            check=True, capture_output=True,
        )
        ok_reg, _ = run_real_cli_verify_registry(pog_cli, signed_reg, op_pk, "test-constellation.invalid", allow_dev_anchors=False)
        assert ok_reg, "Validly signed real-key HW registry should pass verify-registry"

        wrong_pk_ok, _ = run_real_cli_verify_registry(pog_cli, signed_reg, "ff" * 32, "test-constellation.invalid", allow_dev_anchors=False)
        assert not wrong_pk_ok, "Wrong pinned root PK MUST fail"

        tampered = json.loads(signed_reg.read_text())
        tampered["grid"]["anchors"][0]["location"]["lat"] = 51.0
        tampered_path = d / "tampered.json"
        tampered_path.write_text(json.dumps(tampered))
        tampered_ok, _ = run_real_cli_verify_registry(pog_cli, tampered_path, op_pk, "test-constellation.invalid", allow_dev_anchors=False)
        assert not tampered_ok, "Tampered coordinates MUST invalidate signature"

        # 4. Separate coordinate audit checks: valid passes; hardware_identity_proves_coordinates=true, drift, or stale FAIL!
        coord_ok_file = d / "coords_ok.json"
        coord_ok_file.write_text(json.dumps({
            "audit_version": 1,
            "hardware_identity_proves_coordinates": False,
            "anchors": {
                "gcp-europe-west3-frankfurt": {
                    "lat": 50.1109,
                    "lon": 8.6821,
                    "uncertainty_km": 15.0,
                    "source": "peeringdb_facility_cross_cloud_c0_mesh_audit",
                    "evidence_ref": "audit-2026-11-26-fra",
                    "auditor": "jperla",
                    "audited_at_unix_s": now - 60,
                    "hardware_identity_proves_coordinates": False,
                }
            },
        }))
        anchors_list = json.loads(signed_reg.read_text())["grid"]["anchors"]
        _, c_errs = validate_coordinate_audit(coord_ok_file, anchors_list, now)
        assert not c_errs, f"Clean coordinate audit failed: {c_errs}"

        coord_bad_file = d / "coords_bad.json"
        coord_bad_file.write_text(json.dumps({
            "audit_version": 1,
            "hardware_identity_proves_coordinates": True,
            "anchors": {
                "gcp-europe-west3-frankfurt": {
                    "lat": 55.0,
                    "lon": 8.6821,
                    "uncertainty_km": 15.0,
                    "source": "tee",
                    "evidence_ref": "x",
                    "auditor": "x",
                    "audited_at_unix_s": now - 400 * 86400,
                    "hardware_identity_proves_coordinates": True,
                }
            },
        }))
        _, cb_errs = validate_coordinate_audit(coord_bad_file, anchors_list, now)
        assert len(cb_errs) >= 4, f"Expected multiple coordinate audit failures, got {cb_errs}"

        # 5. Measured software manifest check (verifies exact SHA-256 of repo zero-SSH recipes + forbids zero PCRs)
        manifest_ok = d / "manifest_ok.json"
        manifest_ok.write_text(json.dumps({
            "zero_ssh_verified": True,
            "image_recipes": {
                "infra/images/Dockerfile.anchor": sha256_file(repo_root / "infra/images/Dockerfile.anchor"),
                "infra/reproducible/Dockerfile": sha256_file(repo_root / "infra/reproducible/Dockerfile"),
                "infra/images/flake.nix": sha256_file(repo_root / "infra/images/flake.nix"),
            },
            "allowed_measurements": {"AmdSevSnp": ["ab" * 48]},
        }))
        _, m_errs = validate_measured_manifest(manifest_ok, repo_root)
        assert not m_errs, f"Valid manifest failed: {m_errs}"

        manifest_bad = d / "manifest_bad.json"
        manifest_bad.write_text(json.dumps({
            "zero_ssh_verified": True,
            "image_recipes": {"infra/images/Dockerfile.anchor": "00" * 32},
            "allowed_measurements": {"AwsNitro": ["00" * 48]},
        }))
        _, mb_errs = validate_measured_manifest(manifest_bad, repo_root)
        assert len(mb_errs) >= 2, f"Expected manifest SHA + zero-PCR failures, got {mb_errs}"

        # 6. Full `--authorize-promotion` MUST fail closed when attest payload is fake/SoftwareDev/missing!
        att_dir = d / "attest_fake"
        att_dir.mkdir()
        nonce_hex = "42" * 32
        (att_dir / "nonces.json").write_text(json.dumps({
            "collected_at_unix_s": now,
            "nonces": {"gcp-europe-west3-frankfurt": nonce_hex},
        }))
        (att_dir / "gcp-europe-west3-frankfurt.attest.json").write_text(json.dumps({
            "anchor_id": "gcp-europe-west3-frankfurt",
            "cloud_provider": "gcp",
            "tee_vendor": "AmdSevSnp",
            "fresh_caller_nonce": True,
            "caller_nonce_hex": nonce_hex,
            "public_key_hex": "1234567890abcdef" * 4,
            "proof_of_possession_sig_hex": "00" * 64,
            "tee_quote": None,
            "operator_endorsement": None,
        }))
        fake_args = argparse.Namespace(
            pog_cli=pog_cli,
            signed_registry=signed_reg,
            pinned_root_pk=op_pk,
            expected_network_id="test-constellation.invalid",
            measured_manifest=manifest_ok,
            coordinate_audit=coord_ok_file,
            web_roster=None,
            fresh_attest_dir=att_dir,
            canary_anchor_id=None,
            max_coord_audit_age_days=180,
            max_attest_age_seconds=300,
            amd_product="Milan",
            out_receipt=d / "receipt.json",
        )
        rc, rec = run_authorize_promotion(fake_args, repo_root)
        assert rc == 1 and not rec["authorized"] and not (d / "receipt.json").exists(), (
            f"Forged/missing attestation MUST fail closed! Got rc={rc} rec={rec}"
        )

        # 7. `--lint` succeeds on static hygiene while explicitly reporting `release_authorized: false` on public roster!
        l_rc, l_rep = run_static_lint(repo_root, pog_cli, strict_public_roster=False)
        assert l_rc == 0, f"Static lint failed unexpectedly: {l_rep}"
        assert l_rep["release_authorized"] is False
        assert l_rep["public_roster_audit"]["public_signed_registry"] == PUBLIC_ROSTER_SIGNED_REL
        assert l_rep["public_roster_audit"]["simulated_grid_72_rejected_for_prod"] is True

        # Strict public roster lint MUST fail while 42/42 are SoftwareDev!
        ls_rc, _ = run_static_lint(repo_root, pog_cli, strict_public_roster=True)
        assert ls_rc == 1, "Strict public roster check MUST fail while public roster contains SoftwareDev"

        # 8. Wired promotion entrypoint (`scripts/promote_production.py`) MUST fail closed on current SoftwareDev public roster
        #    and write 0 staged artifacts!
        stage_dir = d / "staged_prod"
        promo = subprocess.run(
            [
                sys.executable,
                str(repo_root / "scripts" / "promote_production.py"),
                "--signed-registry", str(repo_root / PUBLIC_ROSTER_SIGNED_REL),
                "--web-roster", str(repo_root / PUBLIC_WEB_ROSTER_REL),
                "--pinned-root-pk", OFFICIAL_PRODUCTION_ROOT_PK_HEX,
                "--expected-network-id", OFFICIAL_NETWORK_ID,
                "--measured-manifest", str(manifest_ok),
                "--coordinate-audit", str(coord_ok_file),
                "--pog-cli", str(pog_cli),
                "--stage-dir", str(stage_dir),
            ],
            capture_output=True,
            text=True,
        )
        assert promo.returncode == 1 and not stage_dir.exists(), (
            f"promote_production.py MUST fail closed and stage nothing on SoftwareDev public roster! rc={promo.returncode}"
        )

    print("release_gate.py self-tests PASSED (8/8 real-verifier, trust-root, measured-software, coord-audit, promotion-wiring & lint-vs-auth checks)")


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(
        description="Proof of Geography Release Gate (Static Lint vs. Fail-Closed Production Promotion Authorization)"
    )
    ap.add_argument("--self-test", action="store_true", help="Run positive & negative self-tests exercising the real pog-cli verifier")
    ap.add_argument("--lint", "--check-repo", dest="lint", action="store_true", help="STATIC LINT ONLY (not release authorization): check image/infra hygiene and audit public roster status")
    ap.add_argument("--strict-public-roster", action="store_true", help="With --lint, also exit non-zero if public roster is not yet production-authorized")
    ap.add_argument("--authorize-promotion", action="store_true", help="FAIL-CLOSED PRODUCTION RELEASE AUTHORIZATION GATE (requires real verifier, trust root, measured manifest, fresh hardware attestation, and separate coordinate audit)")
    ap.add_argument("--pog-cli", type=Path, help="Path to compiled real `pog-cli` binary")
    ap.add_argument("--signed-registry", type=Path, default=repo_root / PUBLIC_ROSTER_SIGNED_REL, help="Signed public registry JSON (defaults to config/signed_public_network.json)")
    ap.add_argument("--pinned-root-pk", help="Pinned 64-hex Ed25519 operator root public key")
    ap.add_argument("--expected-network-id", default=OFFICIAL_NETWORK_ID, help="Expected network_id inside signed registry")
    ap.add_argument("--measured-manifest", type=Path, help="Measured software manifest JSON pinning expected hardware measurements & zero-SSH image recipe SHA-256s")
    ap.add_argument("--coordinate-audit", type=Path, help="Separate physical coordinate audit dossier JSON (hardware_identity_proves_coordinates: false)")
    ap.add_argument("--web-roster", type=Path, help="Optional web/data/anchors.json parity check")
    ap.add_argument("--fresh-attest-dir", type=Path, help="Optional directory containing freshly captured <anchor_id>.attest.json + nonces.json (within --max-attest-age-seconds); if omitted, probes live /attest?nonce=")
    ap.add_argument("--canary-anchor-id", action="append", help="Optional explicit canary anchor ID(s) for staged canary authorization (scope=canary_subset_only)")
    ap.add_argument("--max-coord-audit-age-days", type=int, default=180)
    ap.add_argument("--max-attest-age-seconds", type=int, default=300)
    ap.add_argument("--amd-product", default="Milan", choices=["Milan", "Genoa", "Turin"])
    ap.add_argument("--eif-measurements", type=Path, help="Standalone Nitro EIF PCR0/1/2 lint check")
    ap.add_argument("--out-receipt", type=Path, help="Write promotion authorization receipt JSON ONLY when all gates pass")
    args = ap.parse_args()

    if args.self_test:
        run_self_tests()
        return 0

    if args.eif_measurements:
        errs = check_eif_measurements(args.eif_measurements)
        if errs:
            print(json.dumps({"eif_lint_passed": False, "errors": errs}, indent=2))
            return 1
        print(json.dumps({"eif_lint_passed": True, "note": "LINT ONLY — NOT RELEASE AUTHORIZATION"}, indent=2))
        return 0

    if args.authorize_promotion:
        missing = []
        if not args.pinned_root_pk:
            missing.append("--pinned-root-pk")
        if not args.measured_manifest:
            missing.append("--measured-manifest")
        if not args.coordinate_audit:
            missing.append("--coordinate-audit")
        if missing:
            print(json.dumps({
                "mode": "PRODUCTION_RELEASE_AUTHORIZATION",
                "authorized": False,
                "errors": [f"Fail-closed: missing mandatory promotion authorization arguments: {', '.join(missing)}"],
            }, indent=2))
            return 1
        rc, receipt = run_authorize_promotion(args, repo_root)
        print(json.dumps(receipt, indent=2))
        return rc

    if args.lint:
        pog_cli = find_pog_cli(repo_root, args.pog_cli)
        rc, report = run_static_lint(repo_root, pog_cli, strict_public_roster=args.strict_public_roster)
        print(json.dumps(report, indent=2))
        return rc

    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
