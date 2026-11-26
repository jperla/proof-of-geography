import copy
import json
import pathlib
import unittest

from pog_verifier import (
    TrustedNetwork,
    VerificationPolicy,
    verify_federated_proof,
    verify_proof,
    verify_signed_registry,
)


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
        self.assertLess(honest.tier1a_vacuum.proven_max_radius_miles, 130.0)
        self.assertGreaterEqual(len(honest.observed_prover_ips), 5)
        self.assertTrue(honest.ip_view_consistent)

        spoof = verify_proof(fx["spoofed_singapore_header"], fx["grid"], policy, fx["now_unix_s"])
        self.assertFalse(spoof.overall_valid)
        self.assertGreater(spoof.tier1a_vacuum.proven_max_radius_km, 4000.0)

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

        # Duplicate root key MUST NOT satisfy min_independent_networks=2
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


if __name__ == "__main__":
    unittest.main()
