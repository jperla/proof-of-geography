"""Offline Proof of Geography verifier with exact O(K^3) Byzantine (K-f)-core spherical geometry."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import struct
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from ._ed25519 import verify_ed25519

EARTH_RADIUS_KM = 6371.0088
C_VACUUM_KM_PER_S = 299792.458
C_FIBER_KM_PER_S = 204000.0
HTTP_HEADER_POG_PROOF = "X-PoG-Proof"

Vec3 = tuple[float, float, float]


@dataclass
class VerificationPolicy:
    allow_software_dev: bool = False
    max_byzantine: int = 1
    min_anchors: int = 4
    min_cloud_providers: int = 2
    max_proof_age_seconds: int = 3900
    enforce_tier: str = "vacuum"  # "vacuum" | "fiber" | "calibrated"


@dataclass
class CoreResult:
    proven_max_radius_km: float
    proven_max_radius_miles: float
    contained_within_target: bool
    witness_centroid: dict[str, float]


@dataclass
class AnchorObservedIp:
    anchor_id: str
    cloud_provider: str
    observed_ip: str
    rtt_min_us: int


@dataclass
class VerificationReport:
    overall_valid: bool
    failure_reasons: list[str]
    distinct_clouds: int
    verified_receipts: int
    prover_public_key_hex: str
    workload_measurement_hex: str
    has_gpu_binding: bool
    observed_prover_ips: list[AnchorObservedIp]
    distinct_observed_ips: list[str]
    ip_view_consistent: bool
    tier1a_vacuum: CoreResult
    tier1b_fiber: CoreResult
    tier2_calibrated: CoreResult


@dataclass
class TrustedNetwork:
    network_id: str
    pinned_root_public_key_hex: str
    signed_registry: dict[str, Any]


@dataclass
class NetworkSource:
    network_id: str
    registry_url: str
    pinned_root_public_key_hex: str


@dataclass
class PerNetworkVerification:
    network_id: str
    operator_name: str
    registry_signature_valid: bool
    proof_valid: bool
    report: VerificationReport | None = None
    error: str | None = None


@dataclass
class FederatedVerificationReport:
    overall_valid: bool
    required_independent_networks: int
    valid_independent_networks: int
    distinct_operators_verified: list[str]
    prover_pk_consistent_across_networks: bool
    observed_prover_ips_across_networks: list[str]
    ip_consistent_across_networks: bool
    consensus_tier1a_vacuum_km: float | None
    consensus_tier1b_fiber_km: float | None
    consensus_tier2_calibrated_km: float | None
    failure_reasons: list[str] = field(default_factory=list)
    per_network: list[PerNetworkVerification] = field(default_factory=list)


def _to_unit(lat: float, lon: float) -> Vec3:
    la = math.radians(lat)
    lo = math.radians(lon)
    c = math.cos(la)
    return (c * math.cos(lo), c * math.sin(lo), math.sin(la))


def _dot(a: Vec3, b: Vec3) -> float:
    return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]


def _cross(a: Vec3, b: Vec3) -> Vec3:
    return (
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    )


def _scale(a: Vec3, s: float) -> Vec3:
    return (a[0] * s, a[1] * s, a[2] * s)


def _add(a: Vec3, b: Vec3) -> Vec3:
    return (a[0] + b[0], a[1] + b[1], a[2] + b[2])


def _sub(a: Vec3, b: Vec3) -> Vec3:
    return (a[0] - b[0], a[1] - b[1], a[2] - b[2])


def _normalize(a: Vec3) -> Vec3 | None:
    n = math.sqrt(_dot(a, a))
    return None if n < 1e-15 else _scale(a, 1.0 / n)


def _to_lat_lon(v: Vec3) -> dict[str, float]:
    u = _normalize(v) or (1.0, 0.0, 0.0)
    return {
        "lat": math.degrees(math.asin(max(-1.0, min(1.0, u[2])))),
        "lon": math.degrees(math.atan2(u[1], u[0])),
    }


def _geodesic_km(a: Vec3, b: Vec3) -> float:
    return math.acos(max(-1.0, min(1.0, _dot(a, b)))) * EARTH_RADIUS_KM


def _intersect_two_circles(u1: Vec3, c1: float, u2: Vec3, c2: float) -> list[Vec3]:
    d = _dot(u1, u2)
    denom = 1.0 - d * d
    if denom < 1e-12:
        return []
    a = (c1 - c2 * d) / denom
    b = (c2 - c1 * d) / denom
    p = _add(_scale(u1, a), _scale(u2, b))
    p_sq = _dot(p, p)
    if p_sq > 1.0 + 1e-11:
        return []
    n = _cross(u1, u2)
    n_sq = _dot(n, n)
    if n_sq < 1e-15:
        return []
    t = math.sqrt(max(0.0, 1.0 - p_sq) / n_sq)
    if t < 1e-12:
        u = _normalize(p)
        return [u] if u else []
    out: list[Vec3] = []
    for cand in (_add(p, _scale(n, t)), _sub(p, _scale(n, t))):
        u = _normalize(cand)
        if u:
            out.append(u)
    return out


def _furthest_on_circle(u: Vec3, theta: float, target: Vec3) -> Vec3:
    if theta >= math.pi - 1e-12:
        return _scale(target, -1.0)
    neg_t = _scale(target, -1.0)
    proj = _sub(neg_t, _scale(u, _dot(neg_t, u)))
    direction = _normalize(proj)
    if direction is None:
        basis = (1.0, 0.0, 0.0) if abs(u[0]) < 0.9 else (0.0, 1.0, 0.0)
        direction = _normalize(_cross(u, basis)) or (0.0, 0.0, 1.0)
    return _normalize(_add(_scale(u, math.cos(theta)), _scale(direction, math.sin(theta)))) or u


def _solve_byzantine_core(
    disks: list[tuple[Vec3, float, float]],
    max_byzantine: int,
    target: dict[str, float],
    required_radius_km: float,
) -> CoreResult:
    k = len(disks)
    if k == 0:
        return CoreResult(math.inf, math.inf, False, target)
    f = min(max_byzantine, k - 1)
    req = k - f
    eps = 1e-9
    target_u = _to_unit(target["lat"], target["lon"])

    def count_in(x: Vec3) -> int:
        return sum(1 for u, _th, c in disks if _dot(u, x) >= c - eps)

    pts: list[Vec3] = []
    for i in range(k):
        for j in range(i + 1, k):
            for p in _intersect_two_circles(disks[i][0], disks[i][2], disks[j][0], disks[j][2]):
                if count_in(p) >= req:
                    pts.append(p)
    for u, th, _c in disks:
        far = _furthest_on_circle(u, th, target_u)
        if count_in(far) >= req:
            pts.append(far)
    antipode = _scale(target_u, -1.0)
    if count_in(antipode) >= req:
        pts.append(antipode)

    if not pts:
        return CoreResult(math.inf, math.inf, False, target)

    worst_km = max(_geodesic_km(target_u, p) for p in pts)
    sum_v = (sum(p[0] for p in pts), sum(p[1] for p in pts), sum(p[2] for p in pts))
    centroid = _to_lat_lon(_normalize(sum_v) or pts[0])
    return CoreResult(
        proven_max_radius_km=worst_km,
        proven_max_radius_miles=worst_km * 0.621371,
        contained_within_target=worst_km <= required_radius_km,
        witness_centroid=centroid,
    )


def receipt_signing_digest(r: dict[str, Any]) -> bytes:
    """Exact canonical SHA-256 signing digest matching `pog_proto::AnchorReceipt::signing_digest()`."""
    h = hashlib.sha256()
    h.update(b"pog-anchor-receipt-v1")
    h.update(r["anchor_id"].encode())
    h.update(b"|")
    h.update(r["cloud_provider"].encode())
    h.update(b"|")
    h.update(r["prover_pk_hex"].encode())
    h.update(b"|")
    h.update(r["workload_measurement_hex"].encode())
    h.update(b"|")
    h.update(r["epoch_challenge_hex"].encode())
    h.update(b"|")
    h.update(r["prover_observed_ip"].encode())
    h.update(b"|")
    h.update(struct.pack("<Q", int(r["rtt_min_us"])))
    h.update(struct.pack("<Q", int(r["rtt_p50_us"])))
    samples = r["rtt_samples_us"]
    h.update(struct.pack("<I", len(samples)))
    for s in samples:
        h.update(struct.pack("<Q", int(s)))
    h.update(struct.pack("<Q", int(r["measured_at_unix_s"])))
    return h.digest()


def decode_proof_header(header_value: str) -> dict[str, Any]:
    s = header_value.strip()
    pad = "=" * ((4 - len(s) % 4) % 4)
    raw = base64.urlsafe_b64decode(s + pad)
    return json.loads(raw.decode("utf-8"))


def verify_proof(
    bundle_or_header: dict[str, Any] | str,
    grid: dict[str, Any],
    policy: VerificationPolicy | None = None,
    now_unix_s: int | None = None,
) -> VerificationReport:
    pol = policy or VerificationPolicy()
    now = int(time.time()) if now_unix_s is None else now_unix_s
    bundle = decode_proof_header(bundle_or_header) if isinstance(bundle_or_header, str) else bundle_or_header

    failures: list[str] = []
    if now > int(bundle["created_at_unix_s"]) + pol.max_proof_age_seconds:
        failures.append("proof expired")

    q = bundle["prover_quote"]
    if q["vendor"] == "SoftwareDev" and not pol.allow_software_dev:
        failures.append("SoftwareDev TEE quotes forbidden in production policy")
    if not q["migration_disabled"]:
        failures.append("TEE MIGRATE_MA not disabled")
    if not q["debug_disabled"]:
        failures.append("TEE debug mode enabled")

    rd = hashlib.sha512()
    rd.update(b"pog-tee-bind-v1")
    rd.update(bytes.fromhex(q["public_key_hex"]))
    rd.update(bytes.fromhex(bundle["epoch_challenge_hex"]))
    if q.get("gpu_binding"):
        rd.update(q["gpu_binding"]["gpu_uuid"].encode())
        rd.update(q["gpu_binding"]["spdm_report_hash_hex"].encode())
    if rd.hexdigest() != q["report_data_hex"]:
        failures.append("TEE report_data binding mismatch")

    anchor_map = {a["anchor_id"]: a for a in grid["anchors"]}
    seen_anchors: set[str] = set()
    seen_clouds: set[str] = set()
    observed_ips: list[AnchorObservedIp] = []
    distinct_ip_set: set[str] = set()
    vac_disks: list[tuple[Vec3, float, float]] = []
    fib_disks: list[tuple[Vec3, float, float]] = []
    cal_disks: list[tuple[Vec3, float, float]] = []
    cal_v = float(bundle.get("calibrated_velocity_km_per_s") or 162000.0)

    for r in bundle["receipts"]:
        aid = r["anchor_id"]
        if aid in seen_anchors:
            failures.append(f"duplicate anchor {aid}")
            continue
        seen_anchors.add(aid)
        a = anchor_map.get(aid)
        if not a:
            failures.append(f"unknown anchor {aid}")
            continue
        digest = receipt_signing_digest(r)
        if not verify_ed25519(
            bytes.fromhex(a["public_key_hex"]),
            digest,
            bytes.fromhex(r["anchor_signature_hex"]),
        ):
            failures.append(f"invalid Ed25519 signature from {aid}")
            continue
        if r["prover_pk_hex"] != q["public_key_hex"] or r["epoch_challenge_hex"] != bundle["epoch_challenge_hex"]:
            failures.append(f"receipt binding mismatch from {aid}")
            continue

        seen_clouds.add(a["cloud_provider"])
        obs_ip = str(r["prover_observed_ip"])
        distinct_ip_set.add(obs_ip)
        observed_ips.append(
            AnchorObservedIp(
                anchor_id=aid,
                cloud_provider=a["cloud_provider"],
                observed_ip=obs_ip,
                rtt_min_us=int(r["rtt_min_us"]),
            )
        )
        u = _to_unit(a["location"]["lat"], a["location"]["lon"])
        rtt_us = int(r["rtt_min_us"])

        def mk(r_km: float) -> tuple[Vec3, float, float]:
            th = min(math.pi, r_km / EARTH_RADIUS_KM)
            return (u, th, math.cos(th))

        vac_disks.append(mk(0.5 * C_VACUUM_KM_PER_S * rtt_us * 1e-6))
        fib_disks.append(mk(0.5 * C_FIBER_KM_PER_S * rtt_us * 1e-6))
        cal_disks.append(mk(0.5 * cal_v * max(0, rtt_us - 600) * 1e-6))

    if len(vac_disks) < pol.min_anchors:
        failures.append(f"insufficient anchors: {len(vac_disks)} < {pol.min_anchors}")
    if len(seen_clouds) < pol.min_cloud_providers:
        failures.append(f"insufficient clouds: {len(seen_clouds)} < {pol.min_cloud_providers}")

    target = bundle["target_location"]
    req_km = float(bundle["required_radius_km"])
    t1a = _solve_byzantine_core(vac_disks, pol.max_byzantine, target, req_km)
    t1b = _solve_byzantine_core(fib_disks, pol.max_byzantine, target, req_km)
    t2 = _solve_byzantine_core(cal_disks, pol.max_byzantine, target, req_km)

    enforced = t1a if pol.enforce_tier == "vacuum" else (t1b if pol.enforce_tier == "fiber" else t2)
    if not enforced.contained_within_target:
        failures.append(f"enforced tier ({pol.enforce_tier}) failed: {enforced.proven_max_radius_km:.1f} km > {req_km:.1f} km")

    distinct_observed = sorted(distinct_ip_set)
    return VerificationReport(
        overall_valid=len(failures) == 0,
        failure_reasons=failures,
        distinct_clouds=len(seen_clouds),
        verified_receipts=len(vac_disks),
        prover_public_key_hex=q["public_key_hex"],
        workload_measurement_hex=q["workload_measurement_hex"],
        has_gpu_binding=bool(q.get("gpu_binding")),
        observed_prover_ips=observed_ips,
        distinct_observed_ips=distinct_observed,
        ip_view_consistent=len(distinct_observed) <= 1,
        tier1a_vacuum=t1a,
        tier1b_fiber=t1b,
        tier2_calibrated=t2,
    )


def signed_registry_digest(reg: dict[str, Any]) -> bytes:
    """Exact canonical SHA-256 digest matching `pog_proto::SignedNetworkRegistry::signing_digest()`."""
    h = hashlib.sha256()
    h.update(b"POG-NETWORK-REGISTRY-V1\n")
    h.update(f"{reg['network_id']}\n".encode())
    h.update(f"{reg['operator_name']}\n".encode())
    h.update(f"{reg['root_public_key_hex']}\n".encode())
    h.update(f"{int(reg['issued_at_unix_s'])}\n".encode())
    h.update(f"{int(reg['expires_at_unix_s'])}\n".encode())
    h.update(f"{reg['grid']['grid_name']}\n".encode())
    anchors = sorted(reg["grid"]["anchors"], key=lambda a: a["anchor_id"])
    for a in anchors:
        lat = float(a["location"]["lat"])
        lon = float(a["location"]["lon"])
        ep = a.get("endpoint_tcp") or ""
        line = f"{a['anchor_id']}|{a['cloud_provider']}|{a['region']}|{lat:.6f}|{lon:.6f}|{ep}|{a['public_key_hex']}\n"
        h.update(line.encode())
    return h.digest()


def anchor_endorsement_digest(cert: dict[str, Any]) -> bytes:
    """Exact canonical SHA-256 digest matching `pog_proto::AnchorEndorsement::signing_digest()`."""
    msg = (
        f"POG-ANCHOR-ENDORSEMENT-V1\n"
        f"{cert['network_id']}\n"
        f"{cert['anchor_id']}\n"
        f"{cert['anchor_public_key_hex']}\n"
        f"{float(cert['lat']):.6f}\n"
        f"{float(cert['lon']):.6f}\n"
        f"{int(cert['issued_at_unix_s'])}\n"
        f"{int(cert['expires_at_unix_s'])}\n"
    )
    return hashlib.sha256(msg.encode()).digest()


def verify_anchor_endorsement(
    cert: dict[str, Any],
    pinned_root_public_key_hex: str,
    now_unix_s: int | None = None,
) -> tuple[bool, str | None]:
    now = int(time.time()) if now_unix_s is None else now_unix_s
    if cert["root_public_key_hex"].lower() != pinned_root_public_key_hex.lower():
        return False, f"endorsement root key mismatch for anchor {cert['anchor_id']}"
    if now > int(cert["expires_at_unix_s"]):
        return False, f"endorsement expired for anchor {cert['anchor_id']}"
    ok = verify_ed25519(
        bytes.fromhex(cert["root_public_key_hex"]),
        anchor_endorsement_digest(cert),
        bytes.fromhex(cert["root_signature_hex"]),
    )
    return (True, None) if ok else (False, f"invalid endorsement signature for anchor {cert['anchor_id']}")


def verify_signed_registry(
    reg: dict[str, Any],
    pinned_root_public_key_hex: str | None = None,
    now_unix_s: int | None = None,
) -> tuple[bool, str | None]:
    now = int(time.time()) if now_unix_s is None else now_unix_s
    if pinned_root_public_key_hex and reg["root_public_key_hex"].lower() != pinned_root_public_key_hex.lower():
        return False, f"root public key mismatch for network {reg['network_id']}"
    if now > int(reg["expires_at_unix_s"]):
        return False, f"signed registry expired for network {reg['network_id']}"
    ok = verify_ed25519(
        bytes.fromhex(reg["root_public_key_hex"]),
        signed_registry_digest(reg),
        bytes.fromhex(reg["operator_signature_hex"]),
    )
    if not ok:
        return False, f"invalid operator Ed25519 signature on network {reg['network_id']}"
    return True, None


def fetch_signed_registry(
    registry_url: str,
    pinned_root_public_key_hex: str | None = None,
    now_unix_s: int | None = None,
    timeout_s: float = 10.0,
) -> dict[str, Any]:
    """Fetch an independent operator's SignedNetworkRegistry over HTTPS and verify its root signature."""
    with urllib.request.urlopen(registry_url, timeout=timeout_s) as resp:
        reg = json.loads(resp.read().decode("utf-8"))
    ok, err = verify_signed_registry(reg, pinned_root_public_key_hex, now_unix_s)
    if not ok:
        raise ValueError(err or "invalid signed network registry")
    return reg


def verify_federated_proof(
    submissions: list[tuple[str, dict[str, Any] | str]],
    trusted_networks: list[TrustedNetwork],
    policy: VerificationPolicy | None = None,
    min_independent_networks: int = 2,
    now_unix_s: int | None = None,
) -> FederatedVerificationReport:
    """Verify proofs across `X` independent operator networks (distinct pinned Ed25519 root keys)."""
    now = int(time.time()) if now_unix_s is None else now_unix_s
    net_by_id = {n.network_id: n for n in trusted_networks}
    seen_nets: set[str] = set()
    seen_roots: set[str] = set()
    distinct_ops: list[str] = []
    prover_pks: set[str] = set()
    all_ips: set[str] = set()
    failures: list[str] = []
    per_network: list[PerNetworkVerification] = []

    min_vac: float | None = None
    min_fib: float | None = None
    min_cal: float | None = None

    for net_id, bundle_or_hdr in submissions:
        if net_id in seen_nets:
            failures.append(f"duplicate network submission: {net_id}")
            continue
        seen_nets.add(net_id)
        net = net_by_id.get(net_id)
        if not net:
            per_network.append(PerNetworkVerification(net_id, "unknown", False, False, None, "untrusted network_id"))
            continue
        root_norm = net.pinned_root_public_key_hex.lower()
        if root_norm in seen_roots:
            failures.append(f"network {net_id} shares root key with another network (not independent)")
            continue
        seen_roots.add(root_norm)

        ok_reg, err_reg = verify_signed_registry(net.signed_registry, net.pinned_root_public_key_hex, now)
        if not ok_reg:
            per_network.append(
                PerNetworkVerification(
                    net_id, net.signed_registry.get("operator_name", "unknown"), False, False, None, err_reg
                )
            )
            continue

        rep = verify_proof(bundle_or_hdr, net.signed_registry["grid"], policy, now)
        if rep.overall_valid:
            distinct_ops.append(net.signed_registry["operator_name"])
            prover_pks.add(rep.prover_public_key_hex)
            all_ips.update(rep.distinct_observed_ips)
            min_vac = rep.tier1a_vacuum.proven_max_radius_km if min_vac is None else min(min_vac, rep.tier1a_vacuum.proven_max_radius_km)
            min_fib = rep.tier1b_fiber.proven_max_radius_km if min_fib is None else min(min_fib, rep.tier1b_fiber.proven_max_radius_km)
            min_cal = rep.tier2_calibrated.proven_max_radius_km if min_cal is None else min(min_cal, rep.tier2_calibrated.proven_max_radius_km)
        per_network.append(
            PerNetworkVerification(net_id, net.signed_registry["operator_name"], True, rep.overall_valid, rep, None)
        )

    pk_consistent = len(prover_pks) <= 1
    ip_consistent = len(all_ips) <= 1
    if len(distinct_ops) < min_independent_networks:
        failures.append(f"insufficient independent networks verified: {len(distinct_ops)} < {min_independent_networks}")
    if not pk_consistent:
        failures.append("prover TEE public key mismatch across independent networks")

    return FederatedVerificationReport(
        overall_valid=len(failures) == 0 and len(distinct_ops) >= min_independent_networks,
        required_independent_networks=min_independent_networks,
        valid_independent_networks=len(distinct_ops),
        distinct_operators_verified=distinct_ops,
        prover_pk_consistent_across_networks=pk_consistent,
        observed_prover_ips_across_networks=sorted(all_ips),
        ip_consistent_across_networks=ip_consistent,
        consensus_tier1a_vacuum_km=min_vac,
        consensus_tier1b_fiber_km=min_fib,
        consensus_tier2_calibrated_km=min_cal,
        failure_reasons=failures,
        per_network=per_network,
    )


def query_federated_networks(
    sources: list[NetworkSource],
    submissions: list[tuple[str, dict[str, Any] | str]],
    policy: VerificationPolicy | None = None,
    min_independent_networks: int = 2,
    now_unix_s: int | None = None,
    timeout_s: float = 10.0,
) -> FederatedVerificationReport:
    """Fetch & root-verify registries from `X` independent operator URLs, then verify federated proofs."""
    trusted: list[TrustedNetwork] = []
    for src in sources:
        try:
            reg = fetch_signed_registry(src.registry_url, src.pinned_root_public_key_hex, now_unix_s, timeout_s)
            trusted.append(TrustedNetwork(src.network_id, src.pinned_root_public_key_hex, reg))
        except Exception:
            continue
    return verify_federated_proof(submissions, trusted, policy, min_independent_networks, now_unix_s)
