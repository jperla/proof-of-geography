"""Offline Proof of Geography verifier with exact O(K^3) Byzantine (K-f)-core spherical geometry.

Security & Physics Invariants:
- Vacuum mode (`tier1a_vacuum`) is a strictly conservative outer bound: zero empirical RTT
  deductions, conservatively accounts for clock resolution, slew, anchor-coordinate uncertainty,
  and WGS84 straight-line chord vs mean-sphere surface arc. No artificial radius cap.
- Production policy fails closed: rejects SoftwareDev provers AND SoftwareDev anchors,
  records every rejected/mismatched receipt explicitly (never silently drops), and returns
  `insufficient_verified_anchors` instead of substituting dev/unverified anchors.
"""

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
WGS84_MIN_CURVATURE_RADIUS_KM = 6335.439327
HALF_CIRCUMFERENCE_KM = math.pi * EARTH_RADIUS_KM
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
    max_future_skew_seconds: int = 300
    enforce_tier: str = "vacuum"  # "vacuum" | "fiber" | "calibrated"
    clock_resolution_us: int = 50
    clock_slew_ppm: int = 500
    anchor_location_uncertainty_km: float = 35.0
    account_for_chord: bool = True
    account_for_wgs84_ellipsoid: bool = True


@dataclass
class CoreResult:
    proven_max_radius_km: float
    proven_max_radius_miles: float
    contained_within_target: bool
    witness_centroid: dict[str, float]
    whole_earth: bool = False
    feasible: bool = True


@dataclass
class AnchorObservedIp:
    anchor_id: str
    cloud_provider: str
    observed_ip: str
    rtt_min_us: int


@dataclass
class UnverifiedReceipt:
    anchor_id: str
    reason: str


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
    proof_status: str = "verified"
    hardware_attested: bool = False
    unverified_receipts: list[UnverifiedReceipt] = field(default_factory=list)


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


def effective_outer_radius_km(
    rtt_us: int,
    tier: str,
    policy: VerificationPolicy,
    anchor_unc_override_km: float | None = None,
    cal_velocity_km_per_s: float = 152000.0,
) -> float:
    """Compute conservative outer-bound radius (km) on S^2 matching Rust `pog-geo::bounds`."""
    unc_km = max(
        policy.anchor_location_uncertainty_km,
        0.0 if anchor_unc_override_km is None else max(0.0, anchor_unc_override_km),
    )
    if tier == "vacuum":
        t_upper_s = (max(0, rtt_us) + max(0, policy.clock_resolution_us)) * (1.0 + policy.clock_slew_ppm * 1e-6) * 1e-6
        one_way_km = 0.5 * C_VACUUM_KM_PER_S * t_upper_s
        ref_r = WGS84_MIN_CURVATURE_RADIUS_KM if (policy.account_for_chord or policy.account_for_wgs84_ellipsoid) else EARTH_RADIUS_KM
        if policy.account_for_chord:
            sin_half = one_way_km / (2.0 * ref_r)
            prop_ang = math.pi if sin_half >= 1.0 else 2.0 * math.asin(sin_half)
        else:
            prop_ang = min(math.pi, one_way_km / ref_r)
        return min(math.pi, prop_ang + unc_km / ref_r) * EARTH_RADIUS_KM
    if tier == "fiber":
        t_upper_s = (max(0, rtt_us) + max(0, policy.clock_resolution_us)) * (1.0 + policy.clock_slew_ppm * 1e-6) * 1e-6
        one_way_km = 0.5 * C_FIBER_KM_PER_S * t_upper_s
        ref_r = WGS84_MIN_CURVATURE_RADIUS_KM if policy.account_for_wgs84_ellipsoid else EARTH_RADIUS_KM
        return min(math.pi, (one_way_km + unc_km) / ref_r) * EARTH_RADIUS_KM
    # Calibrated empirical (non-adversarial)
    adj_us = max(0, rtt_us - 350)
    v = max(50000.0, min(C_VACUUM_KM_PER_S, cal_velocity_km_per_s))
    return min(HALF_CIRCUMFERENCE_KM, 0.5 * v * adj_us * 1e-6)


def _intersect_two_circles(u1: Vec3, c1: float, u2: Vec3, c2: float) -> list[Vec3]:
    n = _cross(u1, u2)
    n_sq = _dot(n, n)
    if n_sq < 1e-24:
        return []
    d = _dot(u1, u2)
    a = (c1 - c2 * d) / n_sq
    b = (c2 - c1 * d) / n_sq
    p = _add(_scale(u1, a), _scale(u2, b))
    p_sq = _dot(p, p)
    if p_sq > 1.0 + 1e-11:
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


def _furthest_points_on_circle(u: Vec3, theta: float, target: Vec3) -> list[Vec3]:
    if theta >= math.pi - 1e-12:
        return [_scale(target, -1.0)]
    if theta <= 1e-12:
        return [u]
    neg_t = _scale(target, -1.0)
    proj = _sub(neg_t, _scale(u, _dot(neg_t, u)))
    direction = _normalize(proj)
    if direction is not None:
        pt = _normalize(_add(_scale(u, math.cos(theta)), _scale(direction, math.sin(theta)))) or u
        return [pt]
    basis = (1.0, 0.0, 0.0) if abs(u[0]) < 0.9 else (0.0, 1.0, 0.0)
    e1 = _normalize(_cross(u, basis)) or (0.0, 0.0, 1.0)
    e2 = _normalize(_cross(u, e1)) or e1
    dirs = [e1, _scale(e1, -1.0), e2, _scale(e2, -1.0)]
    return [_normalize(_add(_scale(u, math.cos(theta)), _scale(dv, math.sin(theta)))) or u for dv in dirs]


def _is_whole_earth_core(disks: list[tuple[Vec3, float, float]], f: int) -> bool:
    excl_req = f + 1
    strict_eps = 1e-11
    comp = [(_scale(u, -1.0), math.pi - th, math.cos(math.pi - th)) for u, th, _c in disks if th < math.pi - 1e-12]
    if len(comp) < excl_req:
        return True

    def count_excl(x: Vec3) -> int:
        return sum(1 for cu, _cth, cc in comp if _dot(cu, x) > cc + strict_eps)

    for cu, _cth, _cc in comp:
        if count_excl(cu) >= excl_req:
            return False
    for i in range(len(comp)):
        for j in range(i + 1, len(comp)):
            mid = _normalize(_add(comp[i][0], comp[j][0]))
            if mid and count_excl(mid) >= excl_req:
                return False
            for pt in _intersect_two_circles(comp[i][0], comp[i][2], comp[j][0], comp[j][2]):
                inward = _normalize(_add(comp[i][0], comp[j][0]))
                if inward:
                    nudged = _normalize(_add(pt, _scale(inward, 1e-7)))
                    if nudged and count_excl(nudged) >= excl_req:
                        return False
    return True


def _solve_byzantine_core(
    disks: list[tuple[Vec3, float, float]],
    max_byzantine: int,
    target: dict[str, float],
    required_radius_km: float,
) -> CoreResult:
    k = len(disks)
    if k == 0:
        return CoreResult(math.inf, math.inf, False, target, whole_earth=False, feasible=False)
    f = min(max_byzantine, k - 1)
    req = k - f
    eps = 1e-9
    target_u = _to_unit(target["lat"], target["lon"])
    whole_earth = _is_whole_earth_core(disks, f)

    def count_in(x: Vec3) -> int:
        return sum(1 for u, _th, c in disks if _dot(u, x) >= c - eps)

    pts: list[Vec3] = []
    for i in range(k):
        for j in range(i + 1, k):
            for p in _intersect_two_circles(disks[i][0], disks[i][2], disks[j][0], disks[j][2]):
                if count_in(p) >= req:
                    pts.append(p)
    for u, th, _c in disks:
        for far in _furthest_points_on_circle(u, th, target_u):
            if count_in(far) >= req:
                pts.append(far)
    antipode = _scale(target_u, -1.0)
    if count_in(antipode) >= req:
        pts.append(antipode)

    interior_cands: list[Vec3] = [target_u] + [u for u, _, _ in disks]
    if pts:
        avg = _normalize((sum(p[0] for p in pts), sum(p[1] for p in pts), sum(p[2] for p in pts)))
        if avg:
            interior_cands.append(avg)
    witness_u = next((c for c in interior_cands if count_in(c) >= req), pts[0] if pts else None)
    if witness_u is None:
        return CoreResult(math.inf, math.inf, False, target, whole_earth=False, feasible=False)

    if not pts:
        pts.append(antipode if (whole_earth or count_in(antipode) >= req) else witness_u)

    worst_km = HALF_CIRCUMFERENCE_KM if whole_earth else max(_geodesic_km(target_u, p) for p in pts)
    sum_v = (sum(p[0] for p in pts), sum(p[1] for p in pts), sum(p[2] for p in pts))
    cent_u = _normalize(sum_v)
    if cent_u is None or count_in(cent_u) < req:
        cent_u = witness_u
    return CoreResult(
        proven_max_radius_km=worst_km,
        proven_max_radius_miles=worst_km * 0.621371,
        contained_within_target=worst_km <= required_radius_km,
        witness_centroid=_to_lat_lon(cent_u),
        whole_earth=whole_earth,
        feasible=True,
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
    unverified_receipts: list[UnverifiedReceipt] = []

    created_at = int(bundle["created_at_unix_s"])
    if now > created_at + pol.max_proof_age_seconds:
        failures.append("proof expired")
    if created_at > now + pol.max_future_skew_seconds:
        failures.append("proof timestamp in future")

    q = bundle["prover_quote"]
    prover_is_hw = q.get("vendor") != "SoftwareDev"
    if not prover_is_hw and not pol.allow_software_dev:
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
    cal_v = float(bundle.get("calibrated_velocity_km_per_s") or 152000.0)
    all_anchors_hw = True

    for r in bundle["receipts"]:
        aid = r["anchor_id"]
        if aid in seen_anchors:
            msg = f"duplicate anchor {aid}"
            unverified_receipts.append(UnverifiedReceipt(aid, msg))
            failures.append(msg)
            continue
        seen_anchors.add(aid)
        a = anchor_map.get(aid)
        if not a:
            msg = f"unknown anchor {aid}"
            unverified_receipts.append(UnverifiedReceipt(aid, msg))
            failures.append(msg)
            continue
        if a.get("tee_vendor") == "SoftwareDev":
            all_anchors_hw = False
            if not pol.allow_software_dev:
                msg = f"anchor {aid} reports SoftwareDev (hardware TEE required)"
                unverified_receipts.append(UnverifiedReceipt(aid, msg))
                failures.append(msg)
                continue
        digest = receipt_signing_digest(r)
        if not verify_ed25519(
            bytes.fromhex(a["public_key_hex"]),
            digest,
            bytes.fromhex(r["anchor_signature_hex"]),
        ):
            msg = f"invalid Ed25519 signature or published key mismatch from {aid}"
            unverified_receipts.append(UnverifiedReceipt(aid, msg))
            failures.append(msg)
            continue
        if r["prover_pk_hex"] != q["public_key_hex"] or r["epoch_challenge_hex"] != bundle["epoch_challenge_hex"]:
            msg = f"receipt binding mismatch from {aid}"
            unverified_receipts.append(UnverifiedReceipt(aid, msg))
            failures.append(msg)
            continue
        if r["workload_measurement_hex"] != q["workload_measurement_hex"]:
            msg = f"receipt workload_measurement_hex mismatch from {aid}"
            unverified_receipts.append(UnverifiedReceipt(aid, msg))
            failures.append(msg)
            continue
        measured_at = int(r["measured_at_unix_s"])
        if now > measured_at + pol.max_proof_age_seconds or measured_at > now + pol.max_future_skew_seconds:
            msg = f"receipt expired or future-dated from {aid}"
            unverified_receipts.append(UnverifiedReceipt(aid, msg))
            failures.append(msg)
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
        cb = a.get("coordinate_basis") or {}
        anc_unc = cb.get("uncertainty_km")

        def mk(r_km: float) -> tuple[Vec3, float, float]:
            th = min(math.pi, max(0.0, r_km / EARTH_RADIUS_KM))
            return (u, th, math.cos(th))

        vac_disks.append(mk(effective_outer_radius_km(rtt_us, "vacuum", pol, anc_unc)))
        fib_disks.append(mk(effective_outer_radius_km(rtt_us, "fiber", pol, anc_unc)))
        cal_disks.append(mk(effective_outer_radius_km(rtt_us, "calibrated", pol, anc_unc, cal_v)))

    if len(vac_disks) < pol.min_anchors:
        failures.append(f"insufficient verified anchors: {len(vac_disks)} < {pol.min_anchors}")
    if len(seen_clouds) < pol.min_cloud_providers:
        failures.append(f"insufficient clouds: {len(seen_clouds)} < {pol.min_cloud_providers}")

    target = bundle["target_location"]
    req_km = float(bundle["required_radius_km"])
    t1a = _solve_byzantine_core(vac_disks, pol.max_byzantine, target, req_km)
    t1b = _solve_byzantine_core(fib_disks, pol.max_byzantine, target, req_km)
    t2 = _solve_byzantine_core(cal_disks, pol.max_byzantine, target, req_km)

    enforced = t1a if pol.enforce_tier == "vacuum" else (t1b if pol.enforce_tier == "fiber" else t2)
    if len(vac_disks) > 0 and not enforced.contained_within_target:
        failures.append(
            f"enforced tier ({pol.enforce_tier}) failed: {enforced.proven_max_radius_km:.1f} km > {req_km:.1f} km"
        )

    if len(vac_disks) < pol.min_anchors or len(seen_clouds) < pol.min_cloud_providers:
        proof_status = "insufficient_verified_anchors"
    elif not t1a.feasible:
        proof_status = "inconsistent_measurements"
    elif t1a.whole_earth and not enforced.contained_within_target:
        proof_status = "no_verified_constraint"
    elif not enforced.contained_within_target:
        proof_status = "containment_failed"
    elif failures:
        proof_status = "policy_rejected"
    else:
        proof_status = "verified"

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
        proof_status=proof_status,
        hardware_attested=bool(prover_is_hw and all_anchors_hw and len(vac_disks) > 0),
        unverified_receipts=unverified_receipts,
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


def verify_anchor_info_identity(
    info: dict[str, Any],
    published_anchor: dict[str, Any],
    pinned_root_public_key_hex: str,
    allow_software_dev: bool = False,
    now_unix_s: int | None = None,
) -> tuple[bool, list[str]]:
    """Strictly verify a live Anchor `/info` response against published registry & pinned root key.

    Rejects key mismatches, stale endorsements from previous boots, SoftwareDev in production,
    and quote public_key mismatches.
    """
    now = int(time.time()) if now_unix_s is None else now_unix_s
    errs: list[str] = []
    if info.get("anchor_id") != published_anchor.get("anchor_id"):
        errs.append("anchor_id mismatch")
    live_pk = str(info.get("public_key_hex") or "")
    pub_pk = str(published_anchor.get("public_key_hex") or "")
    if live_pk.lower() != pub_pk.lower():
        errs.append("live public_key_hex does not match published registry key")
    if info.get("tee_vendor") == "SoftwareDev" and not allow_software_dev:
        errs.append("live anchor reports SoftwareDev (hardware TEE required)")
    cert = info.get("operator_endorsement")
    if not cert:
        errs.append("missing operator_endorsement")
    else:
        if cert.get("anchor_id") != published_anchor.get("anchor_id"):
            errs.append("endorsement anchor_id mismatch")
        if str(cert.get("anchor_public_key_hex") or "").lower() != live_pk.lower():
            errs.append("stale endorsement: anchor_public_key_hex != live public_key_hex")
        ok, err = verify_anchor_endorsement(cert, pinned_root_public_key_hex, now)
        if not ok:
            errs.append(err or "invalid endorsement")
    quote = info.get("tee_quote")
    if not quote:
        errs.append("missing tee_quote")
    elif str(quote.get("public_key_hex") or "").lower() != live_pk.lower():
        errs.append("tee_quote.public_key_hex != live public_key_hex")
    return (len(errs) == 0, errs)


def validate_production_registry(reg: dict[str, Any]) -> tuple[bool, list[str]]:
    """Fail-closed production membership check: reject any registry containing SoftwareDev anchors."""
    dev = [a["anchor_id"] for a in reg.get("grid", {}).get("anchors", []) if a.get("tee_vendor") == "SoftwareDev"]
    if dev:
        return False, [f"production registry contains SoftwareDev anchors: {', '.join(dev)}"]
    return True, []


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
            if rep.tier2_calibrated.feasible:
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
    trusted: list[TrustedNetwork] = []
    for src in sources:
        try:
            reg = fetch_signed_registry(src.registry_url, src.pinned_root_public_key_hex, now_unix_s, timeout_s)
            trusted.append(TrustedNetwork(src.network_id, src.pinned_root_public_key_hex, reg))
        except Exception:
            continue
    return verify_federated_proof(submissions, trusted, policy, min_independent_networks, now_unix_s)


@dataclass
class LikelihoodObservation:
    anchor_id: str
    lat: float
    lon: float
    rtt_ms: float
    rtt_min_ms: float | None = None
    jitter_ms: float = 0.0
    anchor_uncertainty_km: float = 35.0


@dataclass
class SpatialLikelihoodConfig:
    t0_ms: float = 2.0
    v0_km_ms: float = 80.0
    v1_km_ms: float = 143.0
    d_knee_km: float = 3500.0
    sigma_base_ms: float = 1.837
    sigma_rel: float = 0.1267
    sigma_jit: float = 1.5
    rho: float = 0.85
    l_corr_km: float = 2200.0
    asym_slow: float = 1.65
    student_t_nu: float | None = 4.0
    tau_more_likely: float = 1.752
    tau_plausible: float = 3.911
    grid_points: int = 2000
    peak_separation_km: float = 700.0
    vacuum_byzantine_f: int = 0


@dataclass
class LikelihoodPeak:
    lat: float
    lon: float
    delta_nll: float
    relative_likelihood: float
    qualitative_band: str


@dataclass
class SpatialLikelihoodSurface:
    is_empirical_estimate: bool
    is_hard_proof: bool
    qualitative_scale: str
    effective_independent_anchors: float
    anchor_count: int
    peaks: list[LikelihoodPeak]
    more_likely_area_km2: float
    more_likely_area_fraction: float
    plausible_area_km2: float
    plausible_area_fraction: float
    vacuum_outer_area_km2: float
    vacuum_outer_area_fraction: float


def _cholesky_lower(mat: list[list[float]]) -> list[list[float]]:
    n = len(mat)
    L = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i + 1):
            s = sum(L[i][k] * L[j][k] for k in range(j))
            if i == j:
                L[i][j] = math.sqrt(max(1e-12, mat[i][i] - s))
            else:
                L[i][j] = (mat[i][j] - s) / L[j][j]
    return L


def _solve_lower(L: list[list[float]], b: list[float]) -> list[float]:
    n = len(b)
    y = [0.0] * n
    for i in range(n):
        s = b[i]
        row = L[i]
        for k in range(i):
            s -= row[k] * y[k]
        y[i] = s / row[i]
    return y


def compute_spatial_likelihood(
    observations: list[LikelihoodObservation],
    config: SpatialLikelihoodConfig | None = None,
    policy: VerificationPolicy | None = None,
) -> SpatialLikelihoodSurface:
    """Compute a spatially correlated empirical likelihood surface strictly inside the raw Vacuum c0 bound.

    Explicitly an empirical estimate (NEVER a hard exclusion or hardware proof) and NEVER narrows
    the raw Vacuum c0 outer region.
    """
    cfg = config or SpatialLikelihoodConfig()
    pol = policy or VerificationPolicy()
    earth_km2 = 4.0 * math.pi * EARTH_RADIUS_KM * EARTH_RADIUS_KM
    if not observations:
        return SpatialLikelihoodSurface(
            is_empirical_estimate=True,
            is_hard_proof=False,
            qualitative_scale="more_likely_to_less_likely",
            effective_independent_anchors=0.0,
            anchor_count=0,
            peaks=[],
            more_likely_area_km2=earth_km2,
            more_likely_area_fraction=1.0,
            plausible_area_km2=earth_km2,
            plausible_area_fraction=1.0,
            vacuum_outer_area_km2=earth_km2,
            vacuum_outer_area_fraction=1.0,
        )

    k = len(observations)
    units = [_to_unit(o.lat, o.lon) for o in observations]
    vac_cos = []
    for o in observations:
        r_min_ms = o.rtt_min_ms if o.rtt_min_ms is not None else o.rtt_ms
        r_km = effective_outer_radius_km(
            int(math.ceil(max(0.0, r_min_ms) * 1000.0)), "vacuum", pol, o.anchor_uncertainty_km
        )
        vac_cos.append(math.cos(min(math.pi, r_km / EARTH_RADIUS_KM)))
    req_vac = max(1, k - cfg.vacuum_byzantine_f)

    rho = max(0.0, min(0.99, cfg.rho))
    sigmas = [
        max(
            0.25,
            math.sqrt(
                cfg.sigma_base_ms ** 2
                + (cfg.sigma_rel * max(0.0, o.rtt_ms)) ** 2
                + (cfg.sigma_jit * max(0.0, o.jitter_ms)) ** 2
            ),
        )
        for o in observations
    ]
    Sigma = [[0.0] * k for _ in range(k)]
    Corr = [[0.0] * k for _ in range(k)]
    for i in range(k):
        for j in range(i, k):
            if i == j:
                c = 1.0
            else:
                d_ij = math.acos(max(-1.0, min(1.0, _dot(units[i], units[j])))) * EARTH_RADIUS_KM
                c = rho * math.exp(-d_ij / max(1.0, cfg.l_corr_km))
            Corr[i][j] = Corr[j][i] = c
            Sigma[i][j] = Sigma[j][i] = sigmas[i] * sigmas[j] * c

    L_sig = _cholesky_lower(Sigma)
    L_cor = _cholesky_lower(Corr)
    ones_w = _solve_lower(L_cor, [1.0] * k)
    k_eff = sum(v * v for v in ones_w)

    def eval_nll(pt: tuple[float, float, float]) -> float:
        r = []
        for i, o in enumerate(observations):
            d_km = math.acos(max(-1.0, min(1.0, _dot(pt, units[i])))) * EARTH_RADIUS_KM
            v = cfg.v0_km_ms + (cfg.v1_km_ms - cfg.v0_km_ms) * (1.0 - math.exp(-d_km / cfg.d_knee_km))
            pred = cfg.t0_ms + (2.0 * d_km) / max(1.0, v)
            diff = o.rtt_ms - pred
            if diff > 0.0 and cfg.asym_slow > 1.0:
                diff /= cfg.asym_slow
            r.append(diff)
        z = _solve_lower(L_sig, r)
        quad = sum(x * x for x in z)
        if cfg.student_t_nu is not None:
            nu = max(0.5, cfg.student_t_nu)
            return 0.5 * (nu + k_eff) * math.log(1.0 + quad / nu)
        return 0.5 * quad

    n_pts = max(64, cfg.grid_points)
    ga = math.pi * (3.0 - math.sqrt(5.0))
    feasible: list[tuple[tuple[float, float, float], float]] = []
    best_nll = float("inf")
    best_u = units[0]
    for i in range(n_pts):
        y = 1.0 - (2.0 * i + 1.0) / n_pts
        rr = math.sqrt(max(0.0, 1.0 - y * y))
        phi = ga * i
        pt = (math.cos(phi) * rr, math.sin(phi) * rr, y)
        if sum(1 for j in range(k) if _dot(pt, units[j]) >= vac_cos[j] - 1e-12) < req_vac:
            continue
        nll = eval_nll(pt)
        if nll < best_nll:
            best_nll = nll
            best_u = pt
        feasible.append((pt, nll))

    if not feasible:
        return SpatialLikelihoodSurface(
            is_empirical_estimate=True,
            is_hard_proof=False,
            qualitative_scale="more_likely_to_less_likely",
            effective_independent_anchors=k_eff,
            anchor_count=k,
            peaks=[],
            more_likely_area_km2=0.0,
            more_likely_area_fraction=0.0,
            plausible_area_km2=0.0,
            plausible_area_fraction=0.0,
            vacuum_outer_area_km2=0.0,
            vacuum_outer_area_fraction=0.0,
        )

    best_ll = _to_lat_lon(best_u)
    for step_deg in (1.5, 0.4, 0.1):
        c_lat, c_lon = best_ll["lat"], best_ll["lon"]
        for dlat in (-2, -1, 0, 1, 2):
            for dlon in (-2, -1, 0, 1, 2):
                lat = max(-89.5, min(89.5, c_lat + dlat * step_deg))
                lon = ((c_lon + dlon * step_deg + 180.0) % 360.0) - 180.0
                cu = _to_unit(lat, lon)
                if sum(1 for j in range(k) if _dot(cu, units[j]) >= vac_cos[j] - 1e-12) < req_vac:
                    continue
                cn = eval_nll(cu)
                if cn < best_nll:
                    best_nll = cn
                    best_ll = {"lat": lat, "lon": lon}
                    best_u = cu

    ml_pts: list[tuple[float, tuple[float, float, float]]] = []
    pl_count = 0
    for pt, nll in feasible:
        delta = max(0.0, nll - best_nll)
        if delta <= cfg.tau_plausible:
            pl_count += 1
        if delta <= cfg.tau_more_likely:
            ml_pts.append((delta, pt))
    ml_pts.sort(key=lambda x: x[0])

    peak_units: list[tuple[float, tuple[float, float, float]]] = [(0.0, best_u)]
    for delta, pt in ml_pts:
        if all(
            math.acos(max(-1.0, min(1.0, _dot(pt, pu)))) * EARTH_RADIUS_KM >= cfg.peak_separation_km
            for _, pu in peak_units
        ):
            peak_units.append((delta, pt))
            if len(peak_units) >= 4:
                break

    peaks = []
    for delta, pu in peak_units:
        ll = _to_lat_lon(pu)
        peaks.append(
            LikelihoodPeak(
                lat=ll["lat"],
                lon=ll["lon"],
                delta_nll=delta,
                relative_likelihood=math.exp(-delta),
                qualitative_band="more_likely" if delta <= cfg.tau_more_likely else "plausible",
            )
        )

    vac_frac = len(feasible) / n_pts
    ml_frac = max(1, len(ml_pts)) / n_pts
    pl_frac = max(1, max(pl_count, len(ml_pts))) / n_pts
    return SpatialLikelihoodSurface(
        is_empirical_estimate=True,
        is_hard_proof=False,
        qualitative_scale="more_likely_to_less_likely",
        effective_independent_anchors=k_eff,
        anchor_count=k,
        peaks=peaks,
        more_likely_area_km2=ml_frac * earth_km2,
        more_likely_area_fraction=ml_frac,
        plausible_area_km2=pl_frac * earth_km2,
        plausible_area_fraction=pl_frac,
        vacuum_outer_area_km2=vac_frac * earth_km2,
        vacuum_outer_area_fraction=vac_frac,
    )
