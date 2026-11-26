import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { verifyProof } from "./src/index.ts";

test("verifies Rust-generated honest Tokyo GPU header & rejects Beijing-via-Singapore spoof", () => {
  const fixture = JSON.parse(readFileSync("../testdata/fixture.json", "utf8"));

  const honest = verifyProof(
    fixture.honest_tokyo_header,
    fixture.grid,
    { allowSoftwareDev: true, maxByzantine: 1, minAnchors: 5, minCloudProviders: 3 },
    fixture.now_unix_s
  );
  assert.equal(honest.overallValid, true, `Unexpected failures: ${honest.failureReasons.join(", ")}`);
  assert.equal(honest.hasGpuBinding, true);
  assert.ok(honest.tier1aVacuum.provenMaxRadiusMiles < 130, `Got ${honest.tier1aVacuum.provenMaxRadiusMiles} mi`);

  const spoof = verifyProof(
    fixture.spoofed_singapore_header,
    fixture.grid,
    { allowSoftwareDev: true, maxByzantine: 1, minAnchors: 5, minCloudProviders: 3 },
    fixture.now_unix_s
  );
  assert.equal(spoof.overallValid, false);
  assert.ok(spoof.tier1aVacuum.provenMaxRadiusKm > 4000);
});
