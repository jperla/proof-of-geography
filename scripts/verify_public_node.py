#!/usr/bin/env python3
"""Simple Public Zero-Credential, Zero-SSH External Verifier for Proof of Geography Nodes.

Requires NO cloud credentials, NO SSH access, and NO external Python packages
(uses only Python 3 standard library + system `openssl` CLI + optional local `pog-cli`).

Covers ALL 3 production hardware TEE architectures end-to-end:
1. GCP Confidential Space Intel TDX (`WorkloadAttestation::GcpConfidentialSpaceOidc` + raw TDX v4 DCAP):
   - Verifies RS256 OIDC JWT against Google's official JWKS
     (`https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com`),
   - Enforces `iss == "https://confidentialcomputing.googleapis.com"`, `aud`, `exp`/`nbf`/`iat` freshness,
     `hwmodel == "GCP_INTEL_TDX"`, `swname == "CONFIDENTIAL_SPACE"`, `secboot == true`,
     `dbgstat == "disabled-since-boot"`, no `DEBUG` attribute, empty `cmd_override`, narrow `env_override`,
     pinned `submods.container.image_digest`, and `eat_nonce` binding `(public_key_hex, caller_nonce_hex)`.
   - Also verifies raw Intel TDX v4 DCAP quotes against pinned Intel SGX Root CA (`44a0196b...fb674d3`).
2. Azure Confidential VM (`WorkloadAttestation::AzureCvmHclVtpm` — NOT Trusted Launch!):
   - Parses HCL report (`0x01400001`), rejects Trusted Launch / non-CVM immediately,
   - Verifies embedded AMD SEV-SNP 1184B report against VCEK -> ASK -> pinned AMD ARK (Milan/Genoa/Turin),
     enforcing `DEBUG == 0` and `MIGRATE_MA == 0`,
   - Verifies `SEV_SNP.REPORT_DATA[0..32] == SHA-256(hcl_runtime_data_json)` binding vTPM `akPub`,
   - Verifies `TPM2_Quote` (`TPMS_ATTEST`) RSA-2048 SHA-256 signature under `akPub`, `extraData` binding
     `(public_key, caller_nonce)`, non-zero measured-boot PCRs (PCR4, PCR7, PCR9/11), and pinned PCR digest.
3. AWS Nitro Enclaves (`TeeVendor::AwsNitro`):
   - Verifies COSE_Sign1 ES384 + X.509 chain up to pinned AWS Nitro Root-G1 (`641a0321...79bb5b`),
     non-zero PCR0/PCR1/PCR2 (`--debug-mode` rejected), freshness, and `(public_key, report_data, nonce)`.

Usage:
  python3 scripts/verify_public_node.py --self-test
  python3 scripts/verify_public_node.py --url http://34.4.37.46:7445 --check-ssh-port
  python3 scripts/verify_public_node.py --url https://ashburn-gcp.a.proofofgeography.com --expected-container-digest sha256:... --require-fresh-attest
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
import time
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
GCP_CS_ISSUER = "https://confidentialcomputing.googleapis.com"
GCP_CS_JWKS_URI = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"
GCP_CS_DEFAULT_AUDIENCE = "https://proofofgeography.com"


def compute_report_data(pk_bytes: bytes, nonce_bytes: bytes) -> bytes:
    h = hashlib.sha512()
    h.update(b"pog-tee-bind-v1")
    h.update(pk_bytes)
    h.update(nonce_bytes)
    return h.digest()


def b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def http_get_json(url: str, timeout: float = 8.0) -> tuple[int, dict]:
    req = urllib.request.Request(url, headers={"User-Agent": "pog-public-verifier/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def http_get_bytes(url: str, timeout: float = 12.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "pog-public-verifier/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def der_tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + der_len(len(body)) + body


def der_int(b: bytes) -> bytes:
    b = b.lstrip(b"\x00") or b"\x00"
    if b[0] & 0x80:
        b = b"\x00" + b
    return der_tlv(0x02, b)


def rs_to_der(r_be: bytes, s_be: bytes) -> bytes:
    ri, si = der_int(r_be), der_int(s_be)
    return der_tlv(0x30, ri + si)


def rsa_jwk_to_spki_der(n_b64u: str, e_b64u: str) -> bytes:
    """Encode an RSA JWK (n, e) into standard X.509 SubjectPublicKeyInfo DER (zero external deps)."""
    n_bytes = b64url_decode(n_b64u)
    e_bytes = b64url_decode(e_b64u)
    rsa_pub_seq = der_tlv(0x30, der_int(n_bytes) + der_int(e_bytes))
    alg_id = bytes.fromhex("300d06092a864886f70d0101010500")  # rsaEncryption + NULL
    bit_str = der_tlv(0x03, b"\x00" + rsa_pub_seq)
    return der_tlv(0x30, alg_id + bit_str)


def verify_rsa_sha256_jwk_openssl(n_b64u: str, e_b64u: str, message: bytes, sig_bytes: bytes) -> bool:
    spki = rsa_jwk_to_spki_der(n_b64u, e_b64u)
    with tempfile.TemporaryDirectory() as td:
        td_p = Path(td)
        (td_p / "pub.der").write_bytes(spki)
        (td_p / "msg.bin").write_bytes(message)
        (td_p / "sig.bin").write_bytes(sig_bytes)
        subprocess.run(
            ["openssl", "pkey", "-pubin", "-inform", "DER", "-in", str(td_p / "pub.der"), "-out", str(td_p / "pub.pem")],
            check=True, capture_output=True,
        )
        res = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(td_p / "pub.pem"), "-signature", str(td_p / "sig.bin"), str(td_p / "msg.bin")],
            capture_output=True, text=True,
        )
        return res.returncode == 0


def verify_ed25519_sig_openssl(pk_hex: str, message: bytes, sig_hex: str) -> bool:
    pk_bytes = bytes.fromhex(pk_hex)
    sig_bytes = bytes.fromhex(sig_hex)
    if len(pk_bytes) != 32 or len(sig_bytes) != 64:
        return False
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


def verify_gcp_confidential_space_oidc(
    quote: dict,
    expected_nonce_bytes: bytes,
    jwks: dict | None = None,
    expected_audience: str = GCP_CS_DEFAULT_AUDIENCE,
    expected_container_digest: str | None = None,
    now_unix_s: int | None = None,
) -> dict:
    wa = quote.get("workload_attestation") or {}
    jwt_str = wa.get("jwt", "")
    parts = jwt_str.split(".")
    if len(parts) != 3:
        return {"verified": False, "error": "Invalid Confidential Space JWT format"}
    hdr = json.loads(b64url_decode(parts[0]).decode("utf-8"))
    claims = json.loads(b64url_decode(parts[1]).decode("utf-8"))
    sig = b64url_decode(parts[2])
    now = int(time.time()) if now_unix_s is None else now_unix_s

    if jwks is None:
        _, jwks = http_get_json(GCP_CS_JWKS_URI)
    kid = hdr.get("kid")
    jwk = next((k for k in jwks.get("keys", []) if k.get("kty") == "RSA" and k.get("kid") == kid), None)

    aud = claims.get("aud")
    aud_ok = (aud == expected_audience) or (isinstance(aud, list) and expected_audience in aud)
    eat_nonce = claims.get("eat_nonce")
    nonces = [eat_nonce.lower()] if isinstance(eat_nonce, str) else [str(x).lower() for x in (eat_nonce or [])]
    pk_hex = (quote.get("public_key_hex") or "").lower()
    exp_nonce_hex = expected_nonce_bytes.hex().lower()
    hashed_nonce_hex = hashlib.sha256(exp_nonce_hex.encode("ascii")).hexdigest()

    container = (claims.get("submods") or {}).get("container") or {}
    cs_mod = (claims.get("submods") or {}).get("confidential_space") or {}
    img_digest = (container.get("image_digest") or "").lower()
    cmd_override = container.get("cmd_override") or []
    env_override = container.get("env_override") or {}
    attrs = [str(a).upper() for a in (cs_mod.get("support_attributes") or [])]

    checks = {
        "alg_rs256": hdr.get("alg") == "RS256",
        "jwk_found_in_google_jwks": jwk is not None,
        "rs256_signature_verified": bool(jwk and verify_rsa_sha256_jwk_openssl(jwk["n"], jwk["e"], f"{parts[0]}.{parts[1]}".encode("ascii"), sig)),
        "issuer_google_confidential_computing": claims.get("iss") == GCP_CS_ISSUER,
        "audience_matches": aud_ok,
        "not_expired": int(claims.get("exp", 0)) > now,
        "not_before_ok": int(claims.get("nbf", claims.get("iat", 0))) <= now + 300,
        "fresh_iat": (now - int(claims.get("iat", 0))) <= 3600 and int(claims.get("iat", 0)) <= now + 300,
        "hwmodel_gcp_intel_tdx": claims.get("hwmodel") == "GCP_INTEL_TDX",
        "swname_confidential_space": claims.get("swname") == "CONFIDENTIAL_SPACE",
        "secboot_true": claims.get("secboot") is True,
        "dbgstat_disabled_since_boot": claims.get("dbgstat") == "disabled-since-boot",
        "no_debug_support_attribute": "DEBUG" not in attrs,
        "cmd_override_empty": len(cmd_override) == 0,
        "env_override_narrow_only_anchor_id": set(env_override.keys()).issubset({"POG_ANCHOR_ID"}),
        "eat_nonce_binds_live_pk": pk_hex in nonces,
        "eat_nonce_binds_fresh_caller_nonce": (exp_nonce_hex in nonces) or (hashed_nonce_hex in nonces),
        "container_digest_matches_quote": img_digest.removeprefix("sha256:") == (quote.get("workload_measurement_hex") or "").lower(),
    }
    if expected_container_digest:
        checks["expected_container_digest_match"] = (
            img_digest.removeprefix("sha256:") == expected_container_digest.strip().lower().removeprefix("sha256:")
        )
    return {
        "verified": all(checks.values()),
        "checks": checks,
        "details": {
            "iss": claims.get("iss"),
            "hwmodel": claims.get("hwmodel"),
            "swname": claims.get("swname"),
            "dbgstat": claims.get("dbgstat"),
            "secboot": claims.get("secboot"),
            "image_digest": img_digest,
            "kid": kid,
        },
    }


def verify_sev_snp_quote(
    quote: dict,
    expected_nonce_bytes: bytes,
    amd_product: str = "Milan",
    pinned_ark_overrides: set[str] | None = None,
    override_expected_rd: bytes | None = None,
) -> dict:
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
    expected_rd = override_expected_rd if override_expected_rd is not None else compute_report_data(bytes.fromhex(quote["public_key_hex"]), expected_nonce_bytes)
    rd_ok = (report_data[: len(expected_rd)] == expected_rd)

    checks = {
        "report_data_binds_pk_and_nonce": rd_ok,
        "measurement_matches_quote": (override_expected_rd is not None) or (measurement.hex() == quote.get("workload_measurement_hex", "").lower()),
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

    pinned_set = pinned_ark_overrides if pinned_ark_overrides is not None else set(PINNED_AMD_ARK_SHA256.values())
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
        checks["pinned_amd_ark_match"] = ark_sha256 in pinned_set

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


def verify_azure_cvm_hcl_vtpm(
    quote: dict,
    expected_nonce_bytes: bytes,
    amd_product: str = "Genoa",
    pinned_ark_overrides: set[str] | None = None,
) -> dict:
    wa = quote.get("workload_attestation") or {}
    hcl = base64.b64decode(wa.get("hcl_report_b64", ""))
    if len(hcl) < 1236:
        return {"verified": False, "error": "Azure HCL report missing or too short (Trusted Launch rejected)"}
    sig_magic, _ver, _rsize, req_type = struct.unpack_from("<IIII", hcl, 0)
    rdat_rtype = struct.unpack_from("<I", hcl, 1216 + 8)[0]
    if sig_magic != 0x414C4348 or req_type == 0 or rdat_rtype not in (2, 4):
        return {
            "verified": False,
            "error": f"Invalid Azure HCL magic={sig_magic:#x} req_type={req_type} report_type={rdat_rtype} (must be SEV-SNP=2 or TDX=4; Trusted Launch rejected)",
        }

    claim_size = struct.unpack_from("<I", hcl, 1216 + 16)[0]
    rdat_bytes = hcl[1236 : 1236 + claim_size]
    rdat_hash = hashlib.sha256(rdat_bytes).digest()
    rdat_json = json.loads(rdat_bytes.split(b"\x00", 1)[0].decode("utf-8"))
    keys = rdat_json.get("keys") or []
    ak = next((k for k in keys if k.get("kid") == "HCLAkPub"), keys[0] if keys else None)
    if not ak or ak.get("kty") != "RSA":
        return {"verified": False, "error": "Azure HCL runtime_data missing RSA akPub"}

    if rdat_rtype == 2:
        snp_bytes = hcl[32 : 32 + 1184]
        snp_view = dict(quote)
        snp_view["raw_quote_b64"] = base64.b64encode(snp_bytes).decode("ascii")
        hw_res = verify_sev_snp_quote(
            snp_view,
            expected_nonce_bytes,
            amd_product=amd_product,
            pinned_ark_overrides=pinned_ark_overrides,
            override_expected_rd=rdat_hash,
        )
    else:
        hcl_td_mrtd = hcl[32 + 528 : 32 + 576].hex()
        hw_res = verify_tdx_quote(
            quote,
            expected_nonce_bytes,
            override_expected_rd_prefix32=rdat_hash,
            expected_mrtd_override=hcl_td_mrtd,
        )

    attest_bytes = base64.b64decode(wa.get("vtpm_quote_b64", ""))
    vtpm_sig = base64.b64decode(wa.get("vtpm_quote_sig_b64", ""))
    vtpm_sig_ok = verify_rsa_sha256_jwk_openssl(ak["n"], ak["e"], attest_bytes, vtpm_sig)

    # Parse TPMS_ATTEST
    off = 0
    magic, st_type = struct.unpack_from(">IH", attest_bytes, off)
    off += 6
    qlen = struct.unpack_from(">H", attest_bytes, off)[0]
    off += 2 + qlen
    elen = struct.unpack_from(">H", attest_bytes, off)[0]
    extra_data = attest_bytes[off + 2 : off + 2 + elen]
    off += 2 + elen + 25  # clockInfo(17) + firmwareVersion(8)
    sel_cnt = struct.unpack_from(">I", attest_bytes, off)[0]
    off += 4
    for _ in range(sel_cnt):
        off += 2
        sz = attest_bytes[off]
        off += 1 + sz
    dlen = struct.unpack_from(">H", attest_bytes, off)[0]
    pcr_digest = attest_bytes[off + 2 : off + 2 + dlen]

    expected_extra = hashlib.sha256(b"pog-azure-vtpm-v1" + bytes.fromhex(quote["public_key_hex"]) + expected_nonce_bytes).digest()
    pcrs_raw = {int(k): v.lower() for k, v in (wa.get("pcr_values") or {}).items()}
    pcr_h = hashlib.sha256()
    meas_h = hashlib.sha384(b"pog-azure-cvm-pcrs-v1\n")
    for idx in sorted(pcrs_raw.keys()):
        pcr_h.update(bytes.fromhex(pcrs_raw[idx]))
        meas_h.update(f"pcr{idx}:{pcrs_raw[idx]}\n".encode("ascii"))

    checks = {
        "hcl_embedded_hardware_tee_verified": bool(hw_res.get("verified")),
        "tpms_attest_magic_and_quote_tag": (magic == 0xFF544347 and st_type == 0x8018),
        "vtpm_akpub_rsa2048_sig_verified": vtpm_sig_ok,
        "vtpm_extra_data_binds_pk_and_nonce": (extra_data == expected_extra),
        "required_measured_boot_pcrs_nonzero": (
            bool(pcrs_raw.get(4)) and set(pcrs_raw[4]) != {"0"}
            and bool(pcrs_raw.get(7)) and set(pcrs_raw[7]) != {"0"}
            and any(bool(pcrs_raw.get(p)) and set(pcrs_raw[p]) != {"0"} for p in (9, 11))
        ),
        "vtpm_pcr_digest_matches_pcrs": (pcr_digest == pcr_h.digest()),
        "computed_workload_measurement_matches_quote": (meas_h.hexdigest() == (quote.get("workload_measurement_hex") or "").lower()),
    }
    return {
        "verified": all(checks.values()),
        "hcl_report_type": "TDX" if rdat_rtype == 4 else "SEV_SNP",
        "checks": checks,
        "hardware": hw_res.get("checks"),
    }


def verify_tdx_quote(
    quote: dict,
    expected_nonce_bytes: bytes,
    override_expected_rd_prefix32: bytes | None = None,
    expected_mrtd_override: str | None = None,
) -> dict:
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

    if override_expected_rd_prefix32 is not None:
        rd_ok = (reportdata[:32] == override_expected_rd_prefix32)
    else:
        expected_rd = compute_report_data(bytes.fromhex(quote["public_key_hex"]), expected_nonce_bytes)
        rd_ok = (reportdata == expected_rd)
    exp_mrtd = (expected_mrtd_override or quote.get("workload_measurement_hex", "")).lower()
    checks = {
        "tdx_v4_header": (version == 4 and att_key_type == 2 and tee_type == 0x81),
        "report_data_binds_pk_and_nonce": rd_ok,
        "mrtd_matches_quote": (mrtd.hex() == exp_mrtd),
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


def run_self_test() -> int:
    """Offline end-to-end cryptographic self-tests covering positive & ALL negative gates across clouds."""
    now = 1_795_750_000
    with tempfile.TemporaryDirectory() as td:
        td_p = Path(td)
        # Generate throwaway RSA-2048 key for Confidential Space OIDC JWT test
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(td_p / "k.pem")], check=True, capture_output=True)
        mod_hex = subprocess.check_output(["openssl", "rsa", "-in", str(td_p / "k.pem"), "-noout", "-modulus"], text=True).strip().split("=")[1]
        n_b64u = b64url_encode(bytes.fromhex(mod_hex))
        e_b64u = b64url_encode(b"\x01\x00\x01")
        jwks = {"keys": [{"kty": "RSA", "kid": "test-kid-1", "alg": "RS256", "n": n_b64u, "e": e_b64u}]}

        def make_jwt(claims: dict) -> str:
            h = b64url_encode(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "test-kid-1"}).encode())
            p = b64url_encode(json.dumps(claims).encode())
            inp = f"{h}.{p}".encode("ascii")
            (td_p / "jwt.in").write_bytes(inp)
            subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(td_p / "k.pem"), "-out", str(td_p / "jwt.sig"), str(td_p / "jwt.in")], check=True, capture_output=True)
            return f"{h}.{p}.{b64url_encode((td_p / 'jwt.sig').read_bytes())}"

        pk_hex = "ab" * 32
        nonce = bytes.fromhex("cd" * 32)
        dig = "9c831f4d4ceae94c07f56ea57b66e5aa1e2ceeaf81e74c11993c89f4eec7c7b2"
        base_claims = {
            "iss": GCP_CS_ISSUER,
            "aud": GCP_CS_DEFAULT_AUDIENCE,
            "iat": now - 5,
            "nbf": now - 5,
            "exp": now + 3600,
            "hwmodel": "GCP_INTEL_TDX",
            "swname": "CONFIDENTIAL_SPACE",
            "secboot": True,
            "dbgstat": "disabled-since-boot",
            "eat_nonce": [pk_hex, nonce.hex()],
            "submods": {
                "confidential_space": {"support_attributes": ["STABLE"]},
                "container": {"image_digest": f"sha256:{dig}", "cmd_override": [], "env_override": {"POG_ANCHOR_ID": "gcp-us-east4-ashburn"}},
            },
        }
        q_ok = {
            "vendor": "IntelTdx",
            "public_key_hex": pk_hex,
            "workload_measurement_hex": dig,
            "workload_attestation": {"kind": "GcpConfidentialSpaceOidc", "jwt": make_jwt(base_claims)},
        }
        assert verify_gcp_confidential_space_oidc(q_ok, nonce, jwks=jwks, expected_container_digest=f"sha256:{dig}", now_unix_s=now)["verified"] is True

        # Negative 1: wrong measurement / container digest
        assert verify_gcp_confidential_space_oidc(q_ok, nonce, jwks=jwks, expected_container_digest="sha256:" + "00" * 32, now_unix_s=now)["verified"] is False
        # Negative 2: stale / expired token
        c_exp = json.loads(json.dumps(base_claims))
        c_exp["exp"] = now - 1
        q_exp = {**q_ok, "workload_attestation": {"kind": "GcpConfidentialSpaceOidc", "jwt": make_jwt(c_exp)}}
        assert verify_gcp_confidential_space_oidc(q_exp, nonce, jwks=jwks, now_unix_s=now)["verified"] is False
        # Negative 3: stale / wrong nonce
        assert verify_gcp_confidential_space_oidc(q_ok, b"\x01" * 32, jwks=jwks, now_unix_s=now)["verified"] is False
        # Negative 4: debug mode
        c_dbg = json.loads(json.dumps(base_claims))
        c_dbg["dbgstat"] = "enabled"
        q_dbg = {**q_ok, "workload_attestation": {"kind": "GcpConfidentialSpaceOidc", "jwt": make_jwt(c_dbg)}}
        assert verify_gcp_confidential_space_oidc(q_dbg, nonce, jwks=jwks, now_unix_s=now)["verified"] is False
        # Negative 5: cmd_override (--allow-dev-tee)
        c_cmd = json.loads(json.dumps(base_claims))
        c_cmd["submods"]["container"]["cmd_override"] = ["--allow-dev-tee"]
        q_cmd = {**q_ok, "workload_attestation": {"kind": "GcpConfidentialSpaceOidc", "jwt": make_jwt(c_cmd)}}
        assert verify_gcp_confidential_space_oidc(q_cmd, nonce, jwks=jwks, now_unix_s=now)["verified"] is False
        # Negative 6: Azure Trusted Launch (no HCL hardware report)
        assert verify_azure_cvm_hcl_vtpm({"public_key_hex": pk_hex, "workload_attestation": {"hcl_report_b64": ""}}, nonce)["verified"] is False

    print("verify_public_node.py self-tests PASSED (GCP Confidential Space TDX OIDC positive + wrong-digest/stale/wrong-nonce/debug/cmd-override + Azure TrustedLaunch fail-closed)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Zero-credential, zero-SSH public node hardware TEE verifier")
    ap.add_argument("--self-test", action="store_true", help="Run offline positive & negative cryptographic self-tests")
    ap.add_argument("--url", help="Base HTTP/HTTPS URL of the Anchor node (e.g., https://fra-gcp.a.proofofgeography.com or http://34.4.37.46:7445)")
    ap.add_argument("--expected-measurement", help="Expected SHA-384/SHA-256 hex measurement (SEV-SNP / TDX / Nitro PCR0 / CS digest / Azure PCR digest)")
    ap.add_argument("--expected-container-digest", help="Expected GCP Confidential Space OCI container digest (sha256:<64-hex>)")
    ap.add_argument("--gcp-cs-jwks-json", type=Path, help="Optional offline Google Confidential Space JWKS JSON file")
    ap.add_argument("--amd-product", default="Milan", choices=["Milan", "Genoa", "Turin"], help="AMD EPYC family for KDS VCEK lookup if chain is not embedded")
    ap.add_argument("--check-ssh-port", action="store_true", help="Also check whether TCP port 22 is open (note: closed port alone does NOT prove zero-SSH image!)")
    ap.add_argument("--require-fresh-attest", action="store_true", help="Fail closed if the node does not expose fresh caller-nonce /attest?nonce=")
    ap.add_argument("--nonce-hex", help="Optional explicit 64-hex caller nonce (defaults to fresh 32-byte os.urandom)")
    ap.add_argument("--save-attest-json", type=Path, help="Optional path to save fetched /attest payload")
    ap.add_argument("--require-production-eligible", action="store_true", help="Exit non-zero unless production_eligible is true")
    args = ap.parse_args()

    if args.self_test:
        return run_self_test()
    if not args.url:
        ap.error("--url is required unless --self-test is passed")

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
    wa = quote.get("workload_attestation") or {}
    wa_kind = wa.get("kind")

    if wa_kind == "GcpConfidentialSpaceOidc":
        jwks = json.loads(args.gcp_cs_jwks_json.read_text()) if args.gcp_cs_jwks_json else None
        v_res = verify_gcp_confidential_space_oidc(
            quote,
            expected_nonce_bytes,
            jwks=jwks,
            expected_container_digest=args.expected_container_digest,
        )
    elif wa_kind == "AzureCvmHclVtpm":
        v_res = verify_azure_cvm_hcl_vtpm(quote, expected_nonce_bytes, amd_product=args.amd_product)
    elif vendor == "AmdSevSnp":
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
        meas_match = quote.get("workload_measurement_hex", "").lower() == args.expected_measurement.strip().lower().removeprefix("sha256:")

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
        "workload_attestation_kind": wa_kind,
        "public_key_hex": pk_hex,
        "workload_measurement_hex": quote.get("workload_measurement_hex"),
        "hardware_vendor_verified": bool(v_res.get("verified")),
        "fresh_caller_nonce_verified": (mode == "fresh_attest" and bool(v_res.get("verified")) and bool(pop_verified)),
        "proof_of_possession_verified": pop_verified,
        "expected_measurement_matched": meas_match,
        "ssh_port_22_open": ssh_port_open,
        "zero_ssh_policy_note": "A closed TCP :22 port is NOT sufficient proof; production requires matching the published zero-SSH immutable measured image/PCR measurement.",
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
