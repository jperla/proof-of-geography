import copy
import json
import math
import pathlib
import unittest

from pog_verifier import (
    EARTH_RADIUS_KM,
    HALF_CIRCUMFERENCE_KM,
    LikelihoodObservation,
    SpatialLikelihoodConfig,
    TrustedNetwork,
    VerificationPolicy,
    compute_spatial_likelihood,
    decode_proof_header,
    effective_outer_radius_km,
    validate_production_registry,
    verify_anchor_info_identity,
    verify_federated_proof,
    verify_proof,
    verify_signed_registry,
)
from pog_verifier.verifier import _solve_byzantine_core, _to_unit


class TestPogVerifierPythonSDK(unittest.TestCase):
    def test_verifies_rust_generated_headers_and_observed_ips(self):
        fixture_path = pathlib.Path(__file__).resolve().parents[2] / "testdata" / "fixture.json"
        fx = json.loads(fixture_path.read_text())
        policy = VerificationPolicy(
            allow_software_dev=True,
            max_byzantine=1,
            min_anchors=5,
            min_cloud_providers=3,
        )

        honest = verify_proof(fx["honest_tokyo_header"], fx["grid"], policy, fx["now_unix_s"])
        self.assertTrue(honest.overall_valid, f"Failures: {honest.failure_reasons}")
        self.assertTrue(honest.has_gpu_binding)
        self.assertFalse(honest.hardware_attested)  # SoftwareDev prover is NEVER hardware_attested!
        self.assertLess(honest.tier1a_vacuum.proven_max_radius_miles, 186.0)
        self.assertGreaterEqual(len(honest.observed_prover_ips), 5)
        self.assertTrue(honest.ip_view_consistent)

        # Under production policy (allow_software_dev=False), SoftwareDev bundle MUST be rejected!
        prod_rep = verify_proof(fx["honest_tokyo_header"], fx["grid"], VerificationPolicy(), fx["now_unix_s"])
        self.assertFalse(prod_rep.overall_valid)
        self.assertFalse(prod_rep.hardware_attested)

        spoof = verify_proof(fx["spoofed_singapore_header"], fx["grid"], policy, fx["now_unix_s"])
        self.assertFalse(spoof.overall_valid)
        self.assertGreater(spoof.tier1a_vacuum.proven_max_radius_km, 4000.0)

    def test_geometry_edge_cases_150ms_repro_near_colocated_and_disconnected(self):
        pol = VerificationPolicy()
        # 1. Production v6 repro: San Jose, Frankfurt, Tokyo at 150 ms -> whole Earth!
        r_150 = effective_outer_radius_km(150_000, "vacuum", pol)
        self.assertAlmostEqual(r_150, HALF_CIRCUMFERENCE_KM, places=3)
        th = min(math.pi, r_150 / EARTH_RADIUS_KM)
        disks_150 = [
            (_to_unit(37.4, -121.9), th, math.cos(th)),
            (_to_unit(50.1, 8.7), th, math.cos(th)),
            (_to_unit(35.7, 139.7), th, math.cos(th)),
        ]
        res_150 = _solve_byzantine_core(disks_150, 0, {"lat": 37.4, "lon": -121.9}, 15_000.0)
        self.assertTrue(res_150.whole_earth)
        self.assertAlmostEqual(res_150.proven_max_radius_km, HALF_CIRCUMFERENCE_KM, places=2)
        self.assertFalse(res_150.contained_within_target)

        # 2. Near-co-located anchors (~1 meter apart) MUST NOT suffer 1-d^2 cancellation!
        th300 = 300.0 / EARTH_RADIUS_KM
        near_disks = [
            (_to_unit(50.1109, 8.6821), th300, math.cos(th300)),
            (_to_unit(50.110909, 8.6821), th300, math.cos(th300)),
        ]
        res_near = _solve_byzantine_core(near_disks, 0, {"lat": 50.1109, "lon": 8.6821}, 350.0)
        self.assertTrue(res_near.feasible)
        self.assertTrue(res_near.contained_within_target)
        self.assertAlmostEqual(res_near.proven_max_radius_km, 300.0, delta=1.5)

        # 3. Disconnected 2-of-4 core: centroid MUST lie inside core and max radius reaches far component!
        th400 = 400.0 / EARTH_RADIUS_KM
        disc = [
            (_to_unit(40.71, -74.00), th400, math.cos(th400)),
            (_to_unit(40.80, -74.10), th400, math.cos(th400)),
            (_to_unit(50.11, 8.68), th400, math.cos(th400)),
            (_to_unit(50.20, 8.70), th400, math.cos(th400)),
        ]
        res_disc = _solve_byzantine_core(disc, 2, {"lat": 40.71, "lon": -74.00}, 1000.0)
        self.assertTrue(res_disc.feasible)
        self.assertGreater(res_disc.proven_max_radius_km, 6400.0)
        cu = _to_unit(res_disc.witness_centroid["lat"], res_disc.witness_centroid["lon"])
        in_cnt = sum(1 for u, _t, c in disc if u[0]*cu[0] + u[1]*cu[1] + u[2]*cu[2] >= c - 1e-8)
        self.assertGreaterEqual(in_cnt, 2)

    def test_rejects_software_dev_anchors_workload_tamper_and_stale_endorsement(self):
        fixture_path = pathlib.Path(__file__).resolve().parents[2] / "testdata" / "fixture.json"
        fx = json.loads(fixture_path.read_text())
        bundle = decode_proof_header(fx["honest_tokyo_header"])

        # Tampering workload_measurement_hex on a receipt MUST fail verification!
        tampered_b = copy.deepcopy(bundle)
        tampered_b["receipts"][0]["workload_measurement_hex"] = "ff" * 32
        rep_t = verify_proof(
            tampered_b,
            fx["grid"],
            VerificationPolicy(allow_software_dev=True, max_byzantine=1, min_anchors=6, min_cloud_providers=3),
            fx["now_unix_s"],
        )
        self.assertFalse(rep_t.overall_valid)
        self.assertGreaterEqual(len(rep_t.unverified_receipts), 1)

        # Production registry validator rejects SoftwareDev anchors!
        dev_reg = {"grid": {"anchors": [{"anchor_id": "dev-1", "tee_vendor": "SoftwareDev"}]}}
        ok_prod, errs = validate_production_registry(dev_reg)
        self.assertFalse(ok_prod)
        self.assertTrue(any("SoftwareDev" in e for e in errs))

        # Stale endorsement after restart (live key != published key & != endorsement key) MUST fail!
        ok_id, id_errs = verify_anchor_info_identity(
            {
                "anchor_id": "aws-fra",
                "tee_vendor": "SoftwareDev",
                "public_key_hex": "bb" * 32,
                "operator_endorsement": {
                    "network_id": "pog",
                    "anchor_id": "aws-fra",
                    "anchor_public_key_hex": "aa" * 32,
                    "lat": 50.11,
                    "lon": 8.68,
                    "issued_at_unix_s": 1000,
                    "expires_at_unix_s": 2000,
                    "root_public_key_hex": "cc" * 32,
                    "root_signature_hex": "00" * 64,
                },
                "tee_quote": {"public_key_hex": "bb" * 32},
            },
            {"anchor_id": "aws-fra", "public_key_hex": "aa" * 32},
            "cc" * 32,
            allow_software_dev=False,
            now_unix_s=1500,
        )
        self.assertFalse(ok_id)
        self.assertTrue(any("stale endorsement" in e for e in id_errs))
        self.assertTrue(any("SoftwareDev" in e for e in id_errs))

    def test_cross_verifies_rust_signed_registry_and_federation(self):
        repo_root = pathlib.Path(__file__).resolve().parents[3]
        signed72 = json.loads((repo_root / "config" / "signed_grid_72_network.json").read_text())
        ok, err = verify_signed_registry(
            signed72,
            signed72["root_public_key_hex"],
            int(signed72["issued_at_unix_s"]) + 10,
        )
        self.assertTrue(ok, f"Rust-signed 72-node registry failed in Python: {err}")

        tampered = copy.deepcopy(signed72)
        tampered["grid"]["anchors"][0]["location"]["lat"] += 0.25
        ok_t, _ = verify_signed_registry(
            tampered,
            signed72["root_public_key_hex"],
            int(signed72["issued_at_unix_s"]) + 10,
        )
        self.assertFalse(ok_t)

        fixture_path = repo_root / "sdks" / "testdata" / "fixture.json"
        fx = json.loads(fixture_path.read_text())
        fed_dup = verify_federated_proof(
            [("net-a", fx["honest_tokyo_header"]), ("net-b", fx["honest_tokyo_header"])],
            [
                TrustedNetwork("net-a", signed72["root_public_key_hex"], signed72),
                TrustedNetwork("net-b", signed72["root_public_key_hex"], signed72),
            ],
            VerificationPolicy(allow_software_dev=True, max_byzantine=1, min_anchors=5, min_cloud_providers=3),
            min_independent_networks=2,
            now_unix_s=int(signed72["issued_at_unix_s"]) + 10,
        )
        self.assertFalse(fed_dup.overall_valid)

    def test_spatial_likelihood_correlated_deweighting_and_multipeak(self):
        base = [
            LikelihoodObservation("a1", 40.71, -74.00, 28.0, 27.5, 0.5),
            LikelihoodObservation("a2", 37.34, -121.89, 52.0, 51.4, 0.6),
            LikelihoodObservation("a3", 43.65, -79.38, 19.0, 18.6, 0.4),
            LikelihoodObservation("a4", 29.42, -98.49, 34.0, 33.5, 0.5),
        ]
        dup = list(base) + [LikelihoodObservation(f"dup-{i}", 40.71, -74.00, 28.0, 27.5, 0.5) for i in range(7)]
        s_base = compute_spatial_likelihood(base, SpatialLikelihoodConfig(grid_points=1200))
        s_dup = compute_spatial_likelihood(dup, SpatialLikelihoodConfig(grid_points=1200))
        self.assertTrue(s_base.is_empirical_estimate and not s_base.is_hard_proof)
        self.assertLess(s_dup.effective_independent_anchors, 5.0)
        self.assertGreaterEqual(s_dup.more_likely_area_km2, s_base.more_likely_area_km2 * 0.45)
        self.assertLessEqual(s_base.more_likely_area_km2, s_base.vacuum_outer_area_km2 + 1e-6)

        sym = [
            LikelihoodObservation("west", 0.0, -15.0, 35.0, 34.8, 0.2),
            LikelihoodObservation("east", 0.0, 15.0, 35.0, 34.8, 0.2),
        ]
        s_sym = compute_spatial_likelihood(sym, SpatialLikelihoodConfig(grid_points=1200))
        self.assertGreaterEqual(len(s_sym.peaks), 2)


if __name__ == "__main__":
    unittest.main()
