import json
import pathlib
import unittest

from pog_verifier import VerificationPolicy, verify_proof


class TestPogVerifierPythonSDK(unittest.TestCase):
    def test_verifies_rust_generated_headers(self):
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

        spoof = verify_proof(fx["spoofed_singapore_header"], fx["grid"], policy, fx["now_unix_s"])
        self.assertFalse(spoof.overall_valid)
        self.assertGreater(spoof.tier1a_vacuum.proven_max_radius_km, 4000.0)


if __name__ == "__main__":
    unittest.main()
