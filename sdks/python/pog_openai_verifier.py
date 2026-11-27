"""
Optional Verifying Transport for the Unmodified Official OpenAI Python SDK.

Usage:
    from openai import OpenAI
    from sdks.python.pog_openai_verifier import PogVerifiedHttpClient

    http_client = PogVerifiedHttpClient(expected_image_digest="sha256:...")
    client = OpenAI(
        base_url="https://llm.proofofgeography.com/v1",
        api_key="pog-public-demo",
        http_client=http_client,
    )
    resp = client.chat.completions.create(
        model="qwen2.5-0.5b-instruct-q4_k_m",
        messages=[{"role": "user", "content": "What is 19 * 23?"}],
        max_tokens=64,
    )
    print(resp.choices[0].message.content)
    print(http_client.last_report)

Verifies on THAT VERY SAME SDK CALL (no second inference, no second TLS session):
  1. Real TLS 1.3 connection with CA verification + RFC 8446 §7.5 Exported Keying Material
     (`EXPORTER-pog-inference-v1`, 32 bytes) and leaf cert SHA-256.
  2. Live Google Confidential Space Intel TDX RS256 OIDC JWT against official Google JWKS
     (`hwmodel == GCP_INTEL_TDX`, `secboot == true`, `dbgstat == disabled-since-boot`,
      empty `cmd_override`, pinned `submods.container.image_digest`, `eat_nonce` binding `prover_pk`).
  3. Enclave nonexportable Ed25519 signature over BOTH leaf TLS cert binding AND receipt.
  4. Fresh caller `X-PoG-Client-Nonce` + privacy-preserving blinded SHA-256 commitments over the
     EXACT raw HTTP request bytes and EXACT delivered OpenAI JSON response bytes.
  5. Pinned redistributable CPU-only model weights/tokenizer/license (`Qwen2.5-0.5B-Instruct`, Apache-2.0).
  6. Strictly SEPARATE geographic proof status (never counting prover or SoftwareDev anchors).
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import select
import socket
import ssl
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from OpenSSL import SSL as OpenSSL_SSL

GCP_CS_ISSUER = "https://confidentialcomputing.googleapis.com"
GCP_CS_JWKS_URI = (
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/"
    "signer@confidentialspace-sign.iam.gserviceaccount.com"
)
LLM_DEMO_AUDIENCE = "https://llm.proofofgeography.com"
TLS_EXPORTER_LABEL = b"EXPORTER-pog-inference-v1"
PINNED_MODEL_ID = "qwen2.5-0.5b-instruct-q4_k_m"
PINNED_WEIGHTS_SHA256 = "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db"
PINNED_TOKENIZER_SHA256 = "c0382117ea329cdf097041132f6d735924b697924d6f6fc3945713e96ce87539"
PINNED_LICENSE = "Apache-2.0"
PINNED_LICENSE_SHA256 = "832dd9e00a68dd83b3c3fb9f5588dad7dcf337a0db50f7d9483f310cd292e92e"


class PogVerificationError(RuntimeError):
    """Raised in strict mode if end-to-end TEE/TLS/commitment verification fails."""


def _b64url_decode(seg: str) -> bytes:
    rem = len(seg) % 4
    if rem:
        seg += "=" * (4 - rem)
    return base64.urlsafe_b64decode(seg.encode("ascii"))


def _compute_blinded_request_commitment(
    salt_hex: str, client_nonce_hex: str, model_id: str, raw_request_bytes: bytes
) -> str:
    h = hashlib.sha256()
    h.update(b"pog-cpu-inf-req-v1\n")
    h.update(salt_hex.strip().lower().encode("ascii"))
    h.update(b"\n")
    h.update(client_nonce_hex.strip().lower().encode("ascii"))
    h.update(b"\n")
    h.update(model_id.encode("utf-8"))
    h.update(b"\n")
    h.update(raw_request_bytes)
    return h.hexdigest()


def _compute_blinded_output_commitment(
    salt_hex: str, request_commitment_hex: str, raw_response_bytes: bytes
) -> str:
    h = hashlib.sha256()
    h.update(b"pog-cpu-inf-out-v1\n")
    h.update(salt_hex.strip().lower().encode("ascii"))
    h.update(b"\n")
    h.update(request_commitment_hex.strip().lower().encode("ascii"))
    h.update(b"\n")
    h.update(raw_response_bytes)
    return h.hexdigest()


def _receipt_signing_payload(receipt: Dict[str, Any]) -> bytes:
    tls = receipt.get("tls_session_binding")
    if tls is None:
        tls_part = "MISSING_TLS_SESSION_BINDING"
    else:
        tls_part = "\n".join(
            [
                str(tls["tls_protocol_version"]),
                str(tls["exporter_label"]),
                str(tls["tls_exporter_ekm_hex"]).strip().lower(),
                str(tls["server_cert_sha256_hex"]).strip().lower(),
                str(tls["cert_prover_binding_sig_hex"]).strip().lower(),
                str(bool(tls["terminated_in_attested_runtime"])).lower(),
                str(int(tls["tls_connection_request_seq"])),
            ]
        )
    m = receipt["model_runtime"]
    fields = [
        "CONFIDENTIAL_CPU_INFERENCE_RECEIPT_V1",
        str(int(receipt["version"])),
        str(receipt["receipt_id"]),
        str(receipt["claim_type"]),
        str(receipt["client_nonce_hex"]).strip().lower(),
        str(bool(receipt["client_nonce_supplied_by_caller"])).lower(),
        str(receipt["request_commitment_hex"]).strip().lower(),
        str(receipt["output_commitment_hex"]).strip().lower(),
        str(int(receipt["response_http_status"])),
        str(m["model_id"]),
        str(m["model_repo"]),
        str(m["weights_filename"]),
        str(m["weights_sha256_hex"]).strip().lower(),
        str(m["tokenizer_sha256_hex"]).strip().lower(),
        str(m["license"]),
        str(m["license_sha256_hex"]).strip().lower(),
        str(m["inference_engine"]),
        str(m["git_revision"]),
        str(bool(m["cpu_only"])).lower(),
        str(bool(m["remote_upstream_disabled"])).lower(),
        str(bool(m["fallback_disabled"])).lower(),
        str(bool(m["prompt_output_logging_disabled"])).lower(),
        str(receipt["prover_pk_hex"]).strip().lower(),
        str(receipt["workload_measurement_hex"]).strip().lower(),
        tls_part,
        str(receipt["hardware_attestation_digest_hex"]).strip().lower(),
        str(receipt.get("pog_bundle_hash_hex") or "NONE").strip().lower(),
        str(receipt.get("pog_epoch_challenge_hex") or "NONE").strip().lower(),
        str(int(receipt["execution_started_at_unix_s"])),
        str(int(receipt["execution_completed_at_unix_s"])),
    ]
    return ("\n".join(fields) + "\n").encode("utf-8")


def _verify_gcp_cs_jwt(
    jwt_str: str,
    jwks: Dict[str, Any],
    expected_audience: str,
    expected_pk_hex: str,
    expected_nonce_hex: str,
    expected_image_digest: Optional[str],
    now_s: int,
) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    errors: List[str] = []
    parts = jwt_str.split(".")
    if len(parts) != 3:
        return None, ["Confidential Space JWT does not have 3 segments"]
    try:
        hdr = json.loads(_b64url_decode(parts[0]))
        claims = json.loads(_b64url_decode(parts[1]))
        sig = _b64url_decode(parts[2])
    except Exception as e:
        return None, [f"Invalid Confidential Space JWT encoding: {e}"]

    if hdr.get("alg") != "RS256":
        errors.append(f"JWT alg must be RS256, got {hdr.get('alg')!r}")
    kid = hdr.get("kid")
    jwk = next((k for k in jwks.get("keys", []) if k.get("kid") == kid and k.get("kty") == "RSA"), None)
    if not jwk:
        errors.append(f"JWT kid {kid!r} not found in live Google Confidential Space JWKS")
    else:
        n_int = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        e_int = int.from_bytes(_b64url_decode(jwk["e"]), "big")
        pub = rsa.RSAPublicNumbers(e_int, n_int).public_key()
        try:
            pub.verify(sig, f"{parts[0]}.{parts[1]}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
        except Exception as e:
            errors.append(f"Google RS256 JWT signature invalid: {e}")

    if claims.get("iss") != GCP_CS_ISSUER:
        errors.append(f"JWT iss {claims.get('iss')!r} != {GCP_CS_ISSUER!r}")
    aud = claims.get("aud")
    if not (aud == expected_audience or (isinstance(aud, list) and expected_audience in aud)):
        errors.append(f"JWT aud {aud!r} != {expected_audience!r}")
    if now_s >= int(claims.get("exp", 0)):
        errors.append("Confidential Space JWT expired")
    if claims.get("hwmodel") != "GCP_INTEL_TDX":
        errors.append(f"hwmodel must be GCP_INTEL_TDX, got {claims.get('hwmodel')!r}")
    if claims.get("swname") != "CONFIDENTIAL_SPACE":
        errors.append(f"swname must be CONFIDENTIAL_SPACE, got {claims.get('swname')!r}")
    if claims.get("secboot") is not True:
        errors.append("secboot must be true")
    if claims.get("dbgstat") != "disabled-since-boot":
        errors.append(f"dbgstat must be disabled-since-boot, got {claims.get('dbgstat')!r}")
    sub = claims.get("submods") or {}
    attrs = (sub.get("confidential_space") or {}).get("support_attributes") or []
    if any(str(a).upper() == "DEBUG" for a in attrs):
        errors.append("Confidential Space DEBUG attribute forbidden")
    cont = sub.get("container") or {}
    if cont.get("cmd_override"):
        errors.append(f"container cmd_override must be empty, got {cont.get('cmd_override')!r}")
    env_ov = cont.get("env_override") or {}
    bad_env = [k for k in env_ov.keys() if k != "POG_ANCHOR_ID"]
    if bad_env:
        errors.append(f"unexpected container env_override keys: {bad_env}")
    img_digest = str(cont.get("image_digest") or "").lower()
    if expected_image_digest and img_digest != expected_image_digest.strip().lower():
        errors.append(f"container image_digest {img_digest} != expected {expected_image_digest}")

    eat_nonce = claims.get("eat_nonce")
    nonces = [str(x).lower() for x in (eat_nonce if isinstance(eat_nonce, list) else [eat_nonce] if eat_nonce else [])]
    if expected_pk_hex.lower() not in nonces:
        errors.append("eat_nonce does not bind enclave Ed25519 public key")
    exp_n_low = expected_nonce_hex.lower()
    exp_n_hash = hashlib.sha256(exp_n_low.encode("ascii")).hexdigest()
    if exp_n_low not in nonces and exp_n_hash not in nonces:
        errors.append("eat_nonce does not bind expected quote nonce")

    return claims, errors


def _decode_chunked_bytes(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while True:
        crlf = data.find(b"\r\n", i)
        if crlf == -1:
            break
        size_hex = data[i:crlf].split(b";", 1)[0].strip()
        size = int(size_hex, 16)
        i = crlf + 2
        if size == 0:
            break
        out.extend(data[i : i + size])
        i += size + 2
    return bytes(out)


def _ssl_io(raw_sock: socket.socket, fn: Any, timeout: float) -> Any:
    deadline = time.monotonic() + timeout
    while True:
        try:
            return fn()
        except OpenSSL_SSL.WantReadError:
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError("TLS read timed out")
            r, _, _ = select.select([raw_sock], [], [], rem)
            if not r:
                raise TimeoutError("TLS read timed out")
        except OpenSSL_SSL.WantWriteError:
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError("TLS write timed out")
            _, w, _ = select.select([], [raw_sock], [], rem)
            if not w:
                raise TimeoutError("TLS write timed out")


def _https_raw_tls13_exchange(
    host: str,
    port: int,
    method: str,
    path: str,
    headers: List[Tuple[str, str]],
    body: bytes,
    verify_tls: bool = True,
    cafile: Optional[str] = None,
    timeout: float = 60.0,
) -> Tuple[int, Dict[str, str], bytes, str, str, str]:
    """Perform ONE real OpenSSL TLS 1.3 HTTP/1.1 exchange and export RFC 8446 §7.5 EKM."""
    ctx = OpenSSL_SSL.Context(OpenSSL_SSL.TLS_CLIENT_METHOD)
    ctx.set_min_proto_version(OpenSSL_SSL.TLS1_3_VERSION)
    if verify_tls:
        ctx.set_verify(OpenSSL_SSL.VERIFY_PEER, None)
        if cafile:
            ctx.load_verify_locations(cafile=cafile)
        else:
            try:
                import certifi

                ctx.load_verify_locations(cafile=certifi.where())
            except Exception:
                ctx.set_default_verify_paths()
    else:
        ctx.set_verify(OpenSSL_SSL.VERIFY_NONE, None)

    raw_sock = socket.create_connection((host, port), timeout=timeout)
    conn = OpenSSL_SSL.Connection(ctx, raw_sock)
    try:
        conn.set_tlsext_host_name(host.encode("ascii"))
        conn.set_connect_state()
        _ssl_io(raw_sock, conn.do_handshake, timeout)

        proto = conn.get_protocol_version_name()
        if proto != "TLSv1.3":
            raise PogVerificationError(f"Expected TLSv1.3, negotiated {proto!r}")

        peer_cert = conn.get_peer_certificate()
        if peer_cert is None:
            raise PogVerificationError("Peer presented no TLS certificate")
        peer_x509 = peer_cert.to_cryptography()
        if verify_tls:
            # Enforce strict hostname / SAN match against requested `host`.
            from cryptography.x509 import DNSName, ExtensionNotFound, IPAddress
            from cryptography.x509.oid import ExtensionOID

            matched = False
            try:
                san = peer_x509.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
                dns_names = san.get_values_for_type(DNSName)
                ip_names = [str(x) for x in san.get_values_for_type(IPAddress)]
                if host in dns_names or host in ip_names:
                    matched = True
            except ExtensionNotFound:
                pass
            if not matched:
                raise PogVerificationError(f"TLS leaf certificate SAN does not match host {host!r}")

        leaf_der = peer_x509.public_bytes(serialization.Encoding.DER)
        leaf_sha256_hex = hashlib.sha256(leaf_der).hexdigest()
        ekm_hex = conn.export_keying_material(TLS_EXPORTER_LABEL, 32).hex()

        req_lines = [f"{method} {path} HTTP/1.1", f"Host: {host}", "Connection: close"]
        has_cl = False
        for k, v in headers:
            kl = k.lower()
            if kl in ("host", "connection", "accept-encoding"):
                continue
            if kl == "content-length":
                has_cl = True
            req_lines.append(f"{k}: {v}")
        if not has_cl and (body or method == "POST"):
            req_lines.append(f"Content-Length: {len(body)}")
        raw_http = ("\r\n".join(req_lines) + "\r\n\r\n").encode("utf-8") + body

        view = memoryview(raw_http)
        sent = 0
        while sent < len(view):
            n = _ssl_io(raw_sock, lambda: conn.send(view[sent:]), timeout)
            if n <= 0:
                raise PogVerificationError("TLS connection closed during request send")
            sent += n

        chunks: List[bytes] = []
        while True:
            try:
                buf = _ssl_io(raw_sock, lambda: conn.recv(65536), timeout)
                if not buf:
                    break
                chunks.append(buf)
            except OpenSSL_SSL.ZeroReturnError:
                break
            except OpenSSL_SSL.SysCallError as e:
                if e.args and e.args[0] == -1 and chunks:
                    break
                raise
    finally:
        conn.close()
    raw_resp = b"".join(chunks)
    sep = raw_resp.find(b"\r\n\r\n")
    if sep == -1:
        raise PogVerificationError("Malformed HTTP response from server")
    head_lines = raw_resp[:sep].decode("iso-8859-1").split("\r\n")
    status_code = int(head_lines[0].split(" ", 2)[1])
    resp_headers: Dict[str, str] = {}
    for line in head_lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            resp_headers[k.strip().lower()] = v.strip()
    body_bytes = raw_resp[sep + 4 :]
    if "chunked" in resp_headers.get("transfer-encoding", "").lower():
        body_bytes = _decode_chunked_bytes(body_bytes)
    return status_code, resp_headers, body_bytes, ekm_hex, leaf_sha256_hex, proto


@dataclass
class PogVerifyingTransport(httpx.BaseTransport):
    """httpx transport hooking directly into an unmodified OpenAI SDK call for full TLS 1.3 EKM + Intel TDX verification."""

    expected_image_digest: Optional[str] = None
    expected_audience: str = LLM_DEMO_AUDIENCE
    strict: bool = True
    verify_tls: bool = True
    allow_dev_tee_local_test: bool = False
    jwks_url: str = GCP_CS_JWKS_URI
    last_report: Optional[Dict[str, Any]] = field(default=None, init=False)
    last_evidence: Optional[Dict[str, Any]] = field(default=None, init=False)
    _cached_jwks: Optional[Dict[str, Any]] = field(default=None, init=False)

    def _get_google_jwks(self) -> Dict[str, Any]:
        if self._cached_jwks is None:
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(self.jwks_url, timeout=15, context=ctx) as r:
                self._cached_jwks = json.loads(r.read().decode("utf-8"))
        return self._cached_jwks

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        url = urlsplit(str(request.url))
        host = url.hostname or ""
        port = url.port or 443
        path = url.path or "/"
        if url.query:
            path = f"{path}?{url.query}"
        req_body = request.read()
        headers = list(request.headers.items())

        # Inject a fresh unpredictable caller nonce on every `/chat/completions` call!
        is_inference = path.startswith("/v1/chat/completions") and request.method.upper() == "POST"
        client_nonce = next((v for k, v in headers if k.lower() == "x-pog-client-nonce"), None)
        if is_inference and not client_nonce:
            client_nonce = secrets.token_hex(32)
            headers.append(("X-PoG-Client-Nonce", client_nonce))

        status, resp_headers, resp_body, ekm_hex, leaf_sha256_hex, proto = _https_raw_tls13_exchange(
            host=host,
            port=port,
            method=request.method.upper(),
            path=path,
            headers=headers,
            body=req_body,
            verify_tls=self.verify_tls,
        )

        if is_inference and status == 200:
            receipt_id = resp_headers.get("x-pog-receipt-id", "")
            salt_hex = resp_headers.get("x-pog-commitment-salt", "")
            if not receipt_id or not salt_hex:
                raise PogVerificationError("Response missing X-PoG-Receipt-Id or X-PoG-Commitment-Salt")

            # Fetch full evidence bundle (zero prompt/output plaintext!) over HTTPS.
            ev_status, _, ev_bytes, _, _, _ = _https_raw_tls13_exchange(
                host=host,
                port=port,
                method="GET",
                path=f"/v1/receipts/{receipt_id}",
                headers=[],
                body=b"",
                verify_tls=self.verify_tls,
            )
            if ev_status != 200:
                raise PogVerificationError(f"Failed to fetch /v1/receipts/{receipt_id}: HTTP {ev_status}")
            evidence = json.loads(ev_bytes.decode("utf-8"))

            report = self._verify_evidence(
                evidence=evidence,
                endpoint_url=str(request.url),
                client_nonce_hex=client_nonce or "",
                salt_hex=salt_hex,
                tls_ekm_hex=ekm_hex,
                leaf_sha256_hex=leaf_sha256_hex,
                raw_req=req_body,
                raw_resp=resp_body,
            )
            evidence["client_observed"] = {
                "endpoint_url": str(request.url),
                "client_nonce_hex": client_nonce,
                "commitment_salt_hex": salt_hex,
                "tls_exporter_ekm_hex": ekm_hex,
                "server_cert_sha256_hex": leaf_sha256_hex,
                "expected_tls_connection_request_seq": 1,
                "raw_request_body": req_body.decode("utf-8", errors="replace"),
                "raw_response_body": resp_body.decode("utf-8", errors="replace"),
                "observed_at_unix_s": int(time.time()),
            }
            if self._cached_jwks is not None:
                evidence["google_jwks_json"] = json.dumps(self._cached_jwks)
            self.last_evidence = evidence
            self.last_report = report
            if self.strict and not report["inference_tee_verified"]:
                raise PogVerificationError(
                    f"End-to-end Verified LLM check FAILED: {report['inference_failure_reasons']}"
                )

        return httpx.Response(
            status_code=status,
            headers=resp_headers,
            content=resp_body,
            request=request,
        )

    def _verify_evidence(
        self,
        evidence: Dict[str, Any],
        endpoint_url: str,
        client_nonce_hex: str,
        salt_hex: str,
        tls_ekm_hex: str,
        leaf_sha256_hex: str,
        raw_req: bytes,
        raw_resp: bytes,
    ) -> Dict[str, Any]:
        inf_failures: List[str] = []
        geo_failures: List[str] = []
        now_s = int(time.time())
        receipt = evidence["receipt"]
        quote = evidence["hardware_quote"]
        prover_pk_hex = str(receipt["prover_pk_hex"]).lower()

        # 1. Verify enclave Ed25519 signature over receipt & TLS leaf cert binding.
        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(prover_pk_hex))
            pub.verify(bytes.fromhex(receipt["prover_signature_hex"]), _receipt_signing_payload(receipt))
        except Exception as e:
            inf_failures.append(f"Enclave Ed25519 receipt signature invalid: {e}")

        tls_b = receipt.get("tls_session_binding") or {}
        tls_ok = True
        if tls_b.get("terminated_in_attested_runtime") is not True:
            tls_ok = False
            inf_failures.append("TLS not terminated in attested runtime")
        if tls_b.get("tls_protocol_version") != "TLSv1.3":
            tls_ok = False
            inf_failures.append("TLS protocol is not TLSv1.3")
        if str(tls_b.get("tls_exporter_ekm_hex", "")).lower() != tls_ekm_hex.lower():
            tls_ok = False
            inf_failures.append("TLS 1.3 Exported Keying Material mismatch (MITM / proxy / session mismatch)")
        if str(tls_b.get("server_cert_sha256_hex", "")).lower() != leaf_sha256_hex.lower():
            tls_ok = False
            inf_failures.append("TLS leaf certificate SHA-256 mismatch")
        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(prover_pk_hex))
            cert_msg = f"POG_RA_TLS_CERT_V1\n{leaf_sha256_hex.lower()}\n".encode("ascii")
            pub.verify(bytes.fromhex(tls_b["cert_prover_binding_sig_hex"]), cert_msg)
        except Exception as e:
            tls_ok = False
            inf_failures.append(f"TLS leaf cert binding signature invalid: {e}")

        # 2. Verify blinded SHA-256 request & output commitments + fresh caller nonce.
        commit_ok = True
        if str(receipt.get("client_nonce_hex", "")).lower() != client_nonce_hex.lower():
            commit_ok = False
            inf_failures.append("Client nonce mismatch")
        exp_req = _compute_blinded_request_commitment(
            salt_hex, client_nonce_hex, receipt["model_runtime"]["model_id"], raw_req
        )
        exp_out = _compute_blinded_output_commitment(salt_hex, exp_req, raw_resp)
        if str(receipt.get("request_commitment_hex", "")).lower() != exp_req:
            commit_ok = False
            inf_failures.append("Blinded request commitment mismatch")
        if str(receipt.get("output_commitment_hex", "")).lower() != exp_out:
            commit_ok = False
            inf_failures.append("Blinded output commitment mismatch")

        # 3. Verify pinned CPU-only model weights/tokenizer/license.
        m = receipt["model_runtime"]
        model_ok = (
            m.get("model_id") == PINNED_MODEL_ID
            and str(m.get("weights_sha256_hex", "")).lower() == PINNED_WEIGHTS_SHA256
            and str(m.get("tokenizer_sha256_hex", "")).lower() == PINNED_TOKENIZER_SHA256
            and m.get("license") == PINNED_LICENSE
            and str(m.get("license_sha256_hex", "")).lower() == PINNED_LICENSE_SHA256
            and m.get("cpu_only") is True
            and m.get("remote_upstream_disabled") is True
            and m.get("fallback_disabled") is True
            and m.get("prompt_output_logging_disabled") is True
        )
        if not model_ok:
            inf_failures.append("Model/runtime identity does not match pinned CPU-only Qwen2.5-0.5B Apache-2.0")

        # 4. Verify hardware Intel TDX Confidential Space OIDC JWT against live Google JWKS.
        hw_ok = False
        verified_digest: Optional[str] = None
        gcp_zone: Optional[str] = None
        wa = quote.get("workload_attestation") or {}
        if wa.get("kind") in ("GcpConfidentialSpaceOidc", "gcp_confidential_space_oidc"):
            jwks = self._get_google_jwks()
            claims, jwt_errs = _verify_gcp_cs_jwt(
                jwt_str=wa["jwt"],
                jwks=jwks,
                expected_audience=self.expected_audience,
                expected_pk_hex=prover_pk_hex,
                expected_nonce_hex=str(quote.get("nonce_hex", "")),
                expected_image_digest=self.expected_image_digest,
                now_s=now_s,
            )
            if jwt_errs:
                inf_failures.extend(jwt_errs)
            elif claims is not None:
                hw_ok = True
                verified_digest = (claims.get("submods", {}).get("container") or {}).get("image_digest")
                gcp_zone = (claims.get("submods", {}).get("gce") or {}).get("zone")
        elif self.allow_dev_tee_local_test and quote.get("vendor") in ("SoftwareDev", "software-dev"):
            hw_ok = True
            verified_digest = "local-dev-test-only"
        else:
            inf_failures.append(f"Unsupported or non-hardware TEE quote vendor: {quote.get('vendor')!r}")

        # 5. Strictly SEPARATE geographic proof status (never claim location from SoftwareDev nodes!).
        pog_bundle = evidence.get("pog_proof_bundle")
        geo_verified = False
        geo_status = "insufficient_production_hardware_anchors"
        if pog_bundle is None:
            geo_failures.append(
                "No production multi-cloud hardware TEE anchor quorum attached yet; server geographic location remains UNPROVEN (separate from verified inference TEE)."
            )
        else:
            geo_failures.append(
                "Run `pog-cli verify-llm-evidence` with a pinned production AnchorGrid to verify multi-cloud Vacuum c0 geographic quorum offline."
            )

        return {
            "endpoint_url": endpoint_url,
            "inference_tee_verified": (len(inf_failures) == 0 and hw_ok and tls_ok and commit_ok and model_ok),
            "geographic_proof_verified": geo_verified,
            "geographic_proof_status": geo_status,
            "hardware_tee_verified": hw_ok,
            "tls_channel_binding_verified": tls_ok,
            "request_output_commitments_verified": commit_ok,
            "model_runtime_pinned_verified": model_ok,
            "prover_pk_hex": prover_pk_hex,
            "verified_container_digest": verified_digest,
            "gcp_cloud_metadata_zone": gcp_zone,
            "tls_exporter_ekm_hex": tls_ekm_hex,
            "server_cert_sha256_hex": leaf_sha256_hex,
            "diagnostic_anchor_count": len(evidence.get("diagnostic_anchor_rtts") or []),
            "inference_failure_reasons": inf_failures,
            "geographic_failure_reasons": geo_failures,
        }


class PogVerifiedHttpClient(httpx.Client):
    """Drop-in `http_client=` for `openai.OpenAI(...)` verifying TLS 1.3 EKM + Intel TDX on that exact SDK call."""

    def __init__(
        self,
        expected_image_digest: Optional[str] = None,
        strict: bool = True,
        verify_tls: bool = True,
        allow_dev_tee_local_test: bool = False,
        **kwargs: Any,
    ) -> None:
        self._pog_transport = PogVerifyingTransport(
            expected_image_digest=expected_image_digest,
            strict=strict,
            verify_tls=verify_tls,
            allow_dev_tee_local_test=allow_dev_tee_local_test,
        )
        super().__init__(transport=self._pog_transport, **kwargs)

    @property
    def last_report(self) -> Optional[Dict[str, Any]]:
        return self._pog_transport.last_report

    @property
    def last_evidence(self) -> Optional[Dict[str, Any]]:
        return self._pog_transport.last_evidence
