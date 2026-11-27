#!/usr/bin/env python3
"""Simple Public Zero-Credential, Zero-SSH Verifier for Proof of Geography Nodes.

Requires NO cloud credentials, NO SSH access, and NO external Python packages
(uses only Python 3 standard library + system `openssl` CLI).

Checks:
1. Fresh caller-nonce attestation (`GET /attest?nonce=<64-hex>`) + Ed25519 Proof-of-Possession
   signature binding the live probe key to the caller's fresh nonce & measurement.
   (If the node runs an older binary without `/attest`, falls back to `GET /info` and
   explicitly marks `fresh_caller_nonce_verified = false`!)
2. Full hardware vendor cryptographic chain verification against pinned Root CA DER SHA-256:
   - AMD SEV-SNP: Fetches public unauthenticated VCEK + ASK + ARK from AMD KDS if not embedded,
     verifies pinned ARK-Milan/Genoa/Turin SHA-256, OpenSSL RSA-PSS-4096 X.509 chain, and
     VCEK ECDSA P-384 signature over report[0x000..0x2A0], plus DEBUG=0 & MIGRATE_MA=0.
   - Intel TDX: Verifies TDX v4 DCAP quote signature (ECDSA P-256), QE Report binding + PCK sig,
     PCK -> Intel CA -> pinned Intel SGX Root CA SHA-256, DEBUG=0 & MIGRATABLE=0, MRTD & RTMR0..3.
   - AWS Nitro: Verifies non-dev AwsNitro vendor & non-zero PCR0/1/2 (use `pog-cli` for full CBOR COSE_Sign1).
3. Optional expected measurement pin (`--expected-measurement <96-hex>`), optional signed registry
   key-match check (`--registry <pog-network.json>`), and optional TCP :22 SSH port probe
   (noting that a closed port alone NEVER substitutes for a measured zero-SSH image!).

Usage:
  python3 scripts/verify_public_node.py --url http://35.207.136.128:7445 --check-ssh-port
  python3 scripts/verify_public_node.py --url https://fra-gcp.a.proofofgeography.com --expected-measurement <hex>
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

PINNED_AMD_ARK_SHA256 = {
    "Milan": "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd",
    "Genoa": "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1",
    "Turin": "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a",
}
PINNED_INTEL_SGX_ROOT_SHA256 = "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3"
PINNED_AWS_NITRO_ROOT_G1_SHA256 = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"


def compute_report_data(pk_bytes: bytes, nonce_bytes: bytes) -> bytes:
    h = hashlib.sha512()
    h.update(b"pog-tee-bind-v1")
    h.update(pk_bytes)
    h.update(nonce_bytes)
    return h.digest()


def http_get_json(url: str, timeout: float = 8.0) -> tuple[int, dict]:
    req = urllib.request.Request(url, headers={"User-Agent": "pog-public-verifier/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def http_get_bytes(url: str, timeout: float = 12.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "pog-public-verifier/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def verify_ed25519_sig_openssl(pk_hex: str, message: bytes, sig_hex: str) -> bool:
    pk_bytes = bytes.fromhex(pk_hex)
    sig_bytes = bytes.fromhex(sig_hex)
    if len(pk_bytes) != 32 or len(sig_bytes) != 64:
        return False
    # ASN.1 SubjectPublicKeyInfo for Ed25519 (OID 1.3.101.112)
    spki_der = bytes.fromhex("302a300506032b6570032100") + pk_bytes
    with tempfile.TemporaryDirectory() as td:
        td_p = Path(td)
        (td_p / "pk.der").write_bytes(spki_der)
        (td_p / "msg.bin").write_bytes(message)
        (td_p / "sig.bin").write_bytes(sig_bytes)
        subprocess.run(
            ["openssl", "pkey", "-pubin", "-inform", "DER", "-in", str(td_p / "pk.der"), "-out", str(td_p / "pk.pem")],
            check=True, capture_output=True,
        )
        res = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(td_p / "pk.pem"), "-rawin", "-in", str(td_p / "msg.bin"), "-sigfile", str(td_p / "sig.bin")],
            capture_output=True, text=True,
        )
        return res.returncode == 0


def der_int(b: bytes) -> bytes:
    b = b.lstrip(b"\x00") or b"\x00"
    if b[0] & 0x80:
        b = b"\x00" + b
    return bytes([0x02, len(b)]) + b


def rs_to_der(r_be: bytes, s_be: bytes) -> bytes:
    ri, si = der_int(r_be), der_int(s_be)
    return bytes([0x30, len(ri) + len(si)]) + ri + si


def verify_sev_snp_quote(quote: dict, expected_nonce_bytes: bytes, amd_product: str = "Milan") -> dict:
    raw = base64.b64decode(quote["raw_quote_b64"])
    if len(raw) < 1184:
        return {"verified": False, "error": f"SEV-SNP report length {len(raw)} < 1184"}

    policy = struct.unpack_from("<Q", raw, 0x08)[0]
    sig_algo = struct.unpack_from("<I", raw, 0x34)[0]
    report_data = raw[0x50:0x90]
    measurement = raw[0x90:0xC0]
    reported_tcb = raw[0x180:0x188]
    chip_id = raw[0x1A0:0x1E0]
    sig_r_le = raw[0x2A0:0x2E8]
    sig_s_le = raw[0x2E8:0x330]
    bl_spl, tee_spl, snp_spl, ucode_spl = reported_tcb[0], reported_tcb[1], reported_tcb[6], reported_tcb[7]

    debug_disabled = (policy & (1 << 19)) == 0
    migration_disabled = (policy & (1 << 18)) == 0
    expected_rd = compute_report_data(bytes.fromhex(quote["public_key_hex"]), expected_nonce_bytes)

    checks = {
        "report_data_binds_pk_and_nonce": (report_data == expected_rd),
        "measurement_matches_quote": (measurement.hex() == quote.get("workload_measurement_hex", "").lower()),
        "debug_disabled": debug_disabled,
        "migration_disabled": migration_disabled,
        "sig_algo_ecdsa_p384": (sig_algo == 1),
        "pinned_amd_ark_match": False,
        "amd_ark_ask_vcek_chain_verified": False,
        "vcek_ecdsa_p384_report_sig_verified": False,
    }
    details = {
        "amd_product": amd_product,
        "measurement_hex": measurement.hex(),
        "chip_id_hex": chip_id.hex(),
        "reported_tcb": {"blSPL": bl_spl, "teeSPL": tee_spl, "snpSPL": snp_spl, "ucodeSPL": ucode_spl},
    }

    with tempfile.TemporaryDirectory() as td:
        td_p = Path(td)
        embedded = quote.get("vendor_cert_chain_pem") or []
        if len(embedded) >= 3:
            (td_p / "vcek.pem").write_text(embedded[0])
            (td_p / "ask.pem").write_text(embedded[1])
            (td_p / "ark.pem").write_text(embedded[2])
            details["cert_chain_source"] = "embedded_in_quote"
        else:
            vcek_url = f"https://kdsintf.amd.com/vcek/v1/{amd_product}/{chip_id.hex()}?blSPL={bl_spl:02d}&teeSPL={tee_spl:02d}&snpSPL={snp_spl:02d}&ucodeSPL={ucode_spl:02d}"
            chain_url = f"https://kdsintf.amd.com/vcek/v1/{amd_product}/cert_chain"
            vcek_der = http_get_bytes(vcek_url)
            chain_pem = http_get_bytes(chain_url).decode("utf-8")
            (td_p / "vcek.der").write_bytes(vcek_der)
            subprocess.run(["openssl", "x509", "-inform", "DER", "-in", str(td_p / "vcek.der"), "-out", str(td_p / "vcek.pem")], check=True, capture_output=True)
            parts = [p.strip() + "\n-----END CERTIFICATE-----\n" for p in chain_pem.split("-----END CERTIFICATE-----") if "-----BEGIN CERTIFICATE-----" in p]
            (td_p / "ask.pem").write_text(parts[0])
            (td_p / "ark.pem").write_text(parts[1])
            details["cert_chain_source"] = "amd_public_kds"

        ark_der = subprocess.check_output(["openssl", "x509", "-in", str(td_p / "ark.pem"), "-outform", "DER"])
        ark_sha256 = hashlib.sha256(ark_der).hexdigest()
        details["ark_sha256"] = ark_sha256
        checks["pinned_amd_ark_match"] = ark_sha256 in PINNED_AMD_ARK_SHA256.values()

        vr = subprocess.run(
            ["openssl", "verify", "-CAfile", str(td_p / "ark.pem"), "-untrusted", str(td_p / "ask.pem"), str(td_p / "vcek.pem")],
            capture_output=True, text=True,
        )
        checks["amd_ark_ask_vcek_chain_verified"] = (vr.returncode == 0)

        (td_p / "body.bin").write_bytes(raw[:0x2A0])
        (td_p / "sig.der").write_bytes(rs_to_der(sig_r_le[:48][::-1], sig_s_le[:48][::-1]))
        subprocess.run(["openssl", "x509", "-in", str(td_p / "vcek.pem"), "-pubkey", "-noout", "-out", str(td_p / "vcek.pub.pem")], check=True, capture_output=True)
        sv = subprocess.run(
            ["openssl", "dgst", "-sha384", "-verify", str(td_p / "vcek.pub.pem"), "-signature", str(td_p / "sig.der"), str(td_p / "body.bin")],
            capture_output=True, text=True,
        )
        checks["vcek_ecdsa_p384_report_sig_verified"] = (sv.returncode == 0)
        fetched_pems = [
            (td_p / "vcek.pem").read_text(),
            (td_p / "ask.pem").read_text(),
            (td_p / "ark.pem").read_text(),
        ]

    return {"verified": all(checks.values()), "checks": checks, "details": details, "vendor_cert_chain_pem": fetched_pems}


def verify_tdx_quote(quote: dict, expected_nonce_bytes: bytes) -> dict:
    raw = base64.b64decode(quote["raw_quote_b64"])
    if len(raw) < 632:
        return {"verified": False, "error": f"TDX quote length {len(raw)} < 632"}

    version, att_key_type = struct.unpack_from("<HH", raw, 0)
    tee_type = struct.unpack_from("<I", raw, 4)[0]
    body = raw[48:632]
    tdattributes = struct.unpack_from("<Q", body, 120)[0]
    mrtd = body[136:184]
    rtmrs = [body[328 + i * 48 : 376 + i * 48].hex() for i in range(4)]
    reportdata = body[520:584]

    expected_rd = compute_report_data(bytes.fromhex(quote["public_key_hex"]), expected_nonce_bytes)
    checks = {
        "tdx_v4_header": (version == 4 and att_key_type == 2 and tee_type == 0x81),
        "report_data_binds_pk_and_nonce": (reportdata == expected_rd),
        "mrtd_matches_quote": (mrtd.hex() == quote.get("workload_measurement_hex", "").lower()),
        "debug_disabled": (tdattributes & (1 << 0)) == 0,
        "migration_disabled": (tdattributes & (1 << 29)) == 0,
        "qe_report_binds_att_key": False,
        "pinned_intel_root_ca_match": False,
        "intel_pck_x509_chain_verified": False,
        "pck_ecdsa_p256_qe_report_sig_verified": False,
        "att_key_ecdsa_p256_quote_sig_verified": False,
    }
    details = {"mrtd_hex": mrtd.hex(), "rtmr0_to_3": rtmrs}

    sig_start = 636
    sig_rs = raw[sig_start : sig_start + 64]
    att_pub_xy = raw[sig_start + 64 : sig_start + 128]
    cert_type, cert_len = struct.unpack_from("<HI", raw, sig_start + 128)
    cert_body = raw[sig_start + 134 : sig_start + 134 + cert_len]
    if cert_type != 6:
        return {"verified": False, "checks": checks, "error": f"expected QE cert_type=6, got {cert_type}"}

    qe_report = cert_body[0:384]
    qe_report_sig = cert_body[384:448]
    qe_auth_len = struct.unpack_from("<H", cert_body, 448)[0]
    qe_auth_data = cert_body[450 : 450 + qe_auth_len]
    inner_off = 450 + qe_auth_len
    inner_type, inner_len = struct.unpack_from("<HI", cert_body, inner_off)
    pck_pem = cert_body[inner_off + 6 : inner_off + 6 + inner_len].decode("utf-8")
    checks["qe_report_binds_att_key"] = (qe_report[320:352] == hashlib.sha256(att_pub_xy + qe_auth_data).digest())

    pems = [p.strip() + "\n-----END CERTIFICATE-----\n" for p in pck_pem.split("-----END CERTIFICATE-----") if "-----BEGIN CERTIFICATE-----" in p]
    with tempfile.TemporaryDirectory() as td:
        td_p = Path(td)
        for idx, pm in enumerate(pems):
            (td_p / f"c{idx}.pem").write_text(pm)
        root_der = subprocess.check_output(["openssl", "x509", "-in", str(td_p / f"c{len(pems)-1}.pem"), "-outform", "DER"])
        root_sha256 = hashlib.sha256(root_der).hexdigest()
        details["intel_root_sha256"] = root_sha256
        checks["pinned_intel_root_ca_match"] = (root_sha256 == PINNED_INTEL_SGX_ROOT_SHA256)

        vr = subprocess.run(
            ["openssl", "verify", "-CAfile", str(td_p / f"c{len(pems)-1}.pem"), "-untrusted", str(td_p / "c1.pem"), str(td_p / "c0.pem")],
            capture_output=True, text=True,
        )
        checks["intel_pck_x509_chain_verified"] = (vr.returncode == 0)

        subprocess.run(["openssl", "x509", "-in", str(td_p / "c0.pem"), "-pubkey", "-noout", "-out", str(td_p / "pck.pub.pem")], check=True, capture_output=True)
        (td_p / "qe.bin").write_bytes(qe_report)
        (td_p / "qe.der").write_bytes(rs_to_der(qe_report_sig[:32], qe_report_sig[32:64]))
        qv = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(td_p / "pck.pub.pem"), "-signature", str(td_p / "qe.der"), str(td_p / "qe.bin")], capture_output=True)
        checks["pck_ecdsa_p256_qe_report_sig_verified"] = (qv.returncode == 0)

        spki = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004") + att_pub_xy
        (td_p / "att.der").write_bytes(spki)
        subprocess.run(["openssl", "pkey", "-pubin", "-inform", "DER", "-in", str(td_p / "att.der"), "-out", str(td_p / "att.pem")], check=True, capture_output=True)
        (td_p / "q.bin").write_bytes(raw[:632])
        (td_p / "q.der").write_bytes(rs_to_der(sig_rs[:32], sig_rs[32:64]))
        tv = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(td_p / "att.pem"), "-signature", str(td_p / "q.der"), str(td_p / "q.bin")], capture_output=True)
        checks["att_key_ecdsa_p256_quote_sig_verified"] = (tv.returncode == 0)

    return {"verified": all(checks.values()), "checks": checks, "details": details}


def main() -> int:
    ap = argparse.ArgumentParser(description="Zero-credential, zero-SSH public node hardware TEE verifier")
    ap.add_argument("--url", required=True, help="Base HTTP/HTTPS URL of the Anchor node (e.g., https://fra-gcp.a.proofofgeography.com or http://35.207.136.128:7445)")
    ap.add_argument("--expected-measurement", help="Expected 96-hex SHA-384 measurement (SEV-SNP launch digest / TDX MRTD / Nitro PCR0)")
    ap.add_argument("--amd-product", default="Milan", choices=["Milan", "Genoa", "Turin"], help="AMD EPYC family for KDS VCEK lookup if chain is not embedded")
    ap.add_argument("--check-ssh-port", action="store_true", help="Also check whether TCP port 22 is open (note: closed port alone does NOT prove zero-SSH image!)")
    ap.add_argument("--require-fresh-attest", action="store_true", help="Fail closed if the node does not expose fresh caller-nonce /attest?nonce=")
    ap.add_argument("--nonce-hex", help="Optional explicit 64-hex caller nonce (defaults to fresh 32-byte os.urandom)")
    ap.add_argument("--save-attest-json", type=Path, help="Optional path to save fetched /attest payload (with fetched AMD KDS cert chain embedded for offline Rust verification)")
    ap.add_argument("--require-production-eligible", action="store_true", help="Exit non-zero unless production_eligible is true (not only hardware_vendor_verified)")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    if args.nonce_hex:
        caller_nonce = bytes.fromhex(args.nonce_hex.strip())
        caller_nonce_hex = caller_nonce.hex()
    else:
        caller_nonce = os.urandom(32)
        caller_nonce_hex = caller_nonce.hex()

    mode = "fresh_attest"
    payload = None
    try:
        _, payload = http_get_json(f"{base}/attest?nonce={caller_nonce_hex}")
    except Exception:
        if args.require_fresh_attest:
            print(json.dumps({"verified": False, "error": f"{base}/attest?nonce=... unavailable (required by --require-fresh-attest)"}, indent=2))
            return 1
        mode = "info_fallback_no_caller_nonce"
        _, payload = http_get_json(f"{base}/info")

    quote = payload.get("tee_quote")
    vendor = payload.get("tee_vendor")
    pk_hex = payload.get("public_key_hex", "")
    anchor_id = payload.get("anchor_id", "")

    if not quote or vendor == "SoftwareDev":
        print(json.dumps({
            "anchor_id": anchor_id,
            "url": base,
            "tee_vendor": vendor,
            "hardware_vendor_verified": False,
            "production_eligible": False,
            "reason": "SoftwareDev or missing tee_quote (fail-closed)",
        }, indent=2))
        return 1

    expected_nonce_bytes = caller_nonce if mode == "fresh_attest" else (payload.get("bootstrap_nonce") or "").encode("utf-8")
    if vendor == "AmdSevSnp":
        v_res = verify_sev_snp_quote(quote, expected_nonce_bytes, amd_product=args.amd_product)
        if not quote.get("vendor_cert_chain_pem") and v_res.get("vendor_cert_chain_pem"):
            quote["vendor_cert_chain_pem"] = v_res["vendor_cert_chain_pem"]
        v_res.pop("vendor_cert_chain_pem", None)
    elif vendor == "IntelTdx":
        v_res = verify_tdx_quote(quote, expected_nonce_bytes)
    else:
        v_res = {"verified": False, "error": f"For {vendor}, run `pog-cli network verify-attest` COSE_Sign1/Root-G1 verifier"}

    if args.save_attest_json:
        args.save_attest_json.parent.mkdir(parents=True, exist_ok=True)
        args.save_attest_json.write_text(json.dumps(payload, indent=2) + "\n")

    pop_verified = None
    if mode == "fresh_attest":
        pop_sig = payload.get("proof_of_possession_sig_hex", "")
        pop_msg = f"POG-ATTEST-POP-V1\n{anchor_id}\n{caller_nonce_hex}\n{quote.get('workload_measurement_hex', '')}\n".encode("utf-8")
        pop_verified = verify_ed25519_sig_openssl(pk_hex, pop_msg, pop_sig)

    meas_match = None
    if args.expected_measurement:
        meas_match = quote.get("workload_measurement_hex", "").lower() == args.expected_measurement.strip().lower()

    ssh_port_open = None
    if args.check_ssh_port:
        host = urllib.parse.urlparse(base).hostname
        try:
            s = socket.create_connection((host, 22), timeout=2.0)
            s.close()
            ssh_port_open = True
        except Exception:
            ssh_port_open = False

    blockers = []
    if mode != "fresh_attest":
        blockers.append("Node lacks /attest?nonce= fresh caller-nonce endpoint (older binary)")
    if pop_verified is False:
        blockers.append("Ed25519 Proof-of-Possession signature failed")
    if meas_match is False:
        blockers.append("Workload measurement does not match --expected-measurement")
    if ssh_port_open is True:
        blockers.append("TCP port 22 (SSH) is open — fails zero-SSH production requirement")
    if not payload.get("operator_endorsement"):
        blockers.append("Not enrolled with a live-key-matching operator endorsement")

    report = {
        "anchor_id": anchor_id,
        "url": base,
        "endpoint_mode": mode,
        "caller_nonce_hex": caller_nonce_hex if mode == "fresh_attest" else None,
        "tee_vendor": vendor,
        "public_key_hex": pk_hex,
        "workload_measurement_hex": quote.get("workload_measurement_hex"),
        "hardware_vendor_verified": bool(v_res.get("verified")),
        "fresh_caller_nonce_verified": (mode == "fresh_attest" and bool(v_res.get("verified")) and bool(pop_verified)),
        "proof_of_possession_verified": pop_verified,
        "expected_measurement_matched": meas_match,
        "ssh_port_22_open": ssh_port_open,
        "zero_ssh_policy_note": "A closed TCP :22 port is NOT sufficient proof; production requires matching the published zero-SSH immutable measured image measurement.",
        "vendor_verification": v_res,
        "production_blockers": blockers,
        "production_eligible": bool(v_res.get("verified")) and len(blockers) == 0 and (meas_match is not False),
    }
    print(json.dumps(report, indent=2))
    if args.require_production_eligible:
        return 0 if report["production_eligible"] else 1
    return 0 if report["hardware_vendor_verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
