import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  HALF_CIRCUMFERENCE_KM,
  computeSpatialLikelihood,
  decodeProofHeader,
  effectiveOuterRadiusKm,
  signedRegistryDigest,
  solveByzantineCoreFromDisks,
  validateProductionRegistry,
  verifyAnchorInfoIdentity,
  verifyFederatedProof,
  verifyProof,
  verifySignedRegistry,
  type SignedNetworkRegistry,
} from "./src/index.ts";

function signTestRegistry(
  networkId: string,
  operatorName: string,
  grid: any,
  nowUnixS: number
): { reg: SignedNetworkRegistry; rootPkHex: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  const rootPkHex = spki.subarray(spki.length - 32).toString("hex");
  const reg: SignedNetworkRegistry = {
    version: 1,
    network_id: networkId,
    operator_name: operatorName,
    root_public_key_hex: rootPkHex,
    issued_at_unix_s: nowUnixS - 60,
    expires_at_unix_s: nowUnixS + 86400,
    grid,
    operator_signature_hex: "",
  };
  const digest = signedRegistryDigest(reg);
  reg.operator_signature_hex = cryptoSign(null, digest, privateKey).toString("hex");
  return { reg, rootPkHex };
}

test("verifies Rust-generated honest Tokyo GPU header, observed IPs & rejects spoof and SoftwareDev prod", () => {
  const fixture = JSON.parse(readFileSync("../testdata/fixture.json", "utf8"));

  const honest = verifyProof(
    fixture.honest_tokyo_header,
    fixture.grid,
    { allowSoftwareDev: true, maxByzantine: 1, minAnchors: 5, minCloudProviders: 3 },
    fixture.now_unix_s
  );
  assert.equal(honest.overallValid, true, `Unexpected failures: ${honest.failureReasons.join(", ")}`);
  assert.equal(honest.hasGpuBinding, true);
  assert.equal(honest.hardwareAttested, false);
  assert.ok(honest.tier1aVacuum.provenMaxRadiusMiles < 186, `Got ${honest.tier1aVacuum.provenMaxRadiusMiles} mi`);
  assert.ok(honest.observedProverIps.length >= 5);
  assert.ok(honest.distinctObservedIps.length >= 1);
  assert.equal(honest.ipViewConsistent, true);

  // Under production policy (default allowSoftwareDev=false), SoftwareDev MUST fail!
  const prodRep = verifyProof(fixture.honest_tokyo_header, fixture.grid, {}, fixture.now_unix_s);
  assert.equal(prodRep.overallValid, false);
  assert.equal(prodRep.hardwareAttested, false);

  const spoof = verifyProof(
    fixture.spoofed_singapore_header,
    fixture.grid,
    { allowSoftwareDev: true, maxByzantine: 1, minAnchors: 5, minCloudProviders: 3 },
    fixture.now_unix_s
  );
  assert.equal(spoof.overallValid, false);
  assert.ok(spoof.tier1aVacuum.provenMaxRadiusKm > 4000);
});

test("geometry regressions: 150ms whole-Earth repro, 1m near-colocated, disconnected k-of-n, and security checks", () => {
  const r150 = effectiveOuterRadiusKm(150_000, "vacuum");
  assert.ok(Math.abs(r150 - HALF_CIRCUMFERENCE_KM) < 1e-3);
  const res150 = solveByzantineCoreFromDisks(
    [
      { lat: 37.4, lon: -121.9, radiusKm: r150 },
      { lat: 50.1, lon: 8.7, radiusKm: r150 },
      { lat: 35.7, lon: 139.7, radiusKm: r150 },
    ],
    0,
    { lat: 37.4, lon: -121.9 },
    15_000
  );
  assert.equal(res150.wholeEarth, true);
  assert.ok(Math.abs(res150.provenMaxRadiusKm - HALF_CIRCUMFERENCE_KM) < 1e-2);
  assert.equal(res150.containedWithinTarget, false);

  const near = solveByzantineCoreFromDisks(
    [
      { lat: 50.1109, lon: 8.6821, radiusKm: 300 },
      { lat: 50.110909, lon: 8.6821, radiusKm: 300 },
    ],
    0,
    { lat: 50.1109, lon: 8.6821 },
    350
  );
  assert.equal(near.feasible, true);
  assert.equal(near.containedWithinTarget, true);
  assert.ok(Math.abs(near.provenMaxRadiusKm - 300) < 1.5);

  const disc = solveByzantineCoreFromDisks(
    [
      { lat: 40.71, lon: -74.0, radiusKm: 400 },
      { lat: 40.8, lon: -74.1, radiusKm: 400 },
      { lat: 50.11, lon: 8.68, radiusKm: 400 },
      { lat: 50.2, lon: 8.7, radiusKm: 400 },
    ],
    2,
    { lat: 40.71, lon: -74.0 },
    1000
  );
  assert.ok(disc.provenMaxRadiusKm > 6400);

  // Tampered workload_measurement_hex on a receipt MUST fail!
  const fixture = JSON.parse(readFileSync("../testdata/fixture.json", "utf8"));
  const b = decodeProofHeader(fixture.honest_tokyo_header);
  b.receipts[0].workload_measurement_hex = "ff".repeat(32);
  const repT = verifyProof(
    b,
    fixture.grid,
    { allowSoftwareDev: true, maxByzantine: 1, minAnchors: 6, minCloudProviders: 3 },
    fixture.now_unix_s
  );
  assert.equal(repT.overallValid, false);
  assert.ok(repT.unverifiedReceipts.length >= 1);

  // Stale endorsement on restart & SoftwareDev MUST fail verifyAnchorInfoIdentity!
  const idCheck = verifyAnchorInfoIdentity(
    {
      anchor_id: "aws-fra",
      tee_vendor: "SoftwareDev",
      public_key_hex: "bb".repeat(32),
      operator_endorsement: {
        network_id: "pog",
        anchor_id: "aws-fra",
        anchor_public_key_hex: "aa".repeat(32),
        lat: 50.11,
        lon: 8.68,
        issued_at_unix_s: 1000,
        expires_at_unix_s: 2000,
        root_public_key_hex: "cc".repeat(32),
        root_signature_hex: "00".repeat(64),
      },
      tee_quote: { public_key_hex: "bb".repeat(32) },
    },
    {
      anchor_id: "aws-fra",
      cloud_provider: "aws",
      region: "eu-central-1",
      city: "Frankfurt",
      location: { lat: 50.11, lon: 8.68 },
      public_key_hex: "aa".repeat(32),
    },
    "cc".repeat(32),
    false,
    1500
  );
  assert.equal(idCheck.valid, false);
  assert.ok(idCheck.errors.some((e) => e.includes("stale endorsement")));
  assert.ok(idCheck.errors.some((e) => e.includes("SoftwareDev")));
});

test("cross-verifies real Rust-signed operator registry & 2-network federated quorum", () => {
  const signed72 = JSON.parse(
    readFileSync("../../config/signed_grid_72_network.json", "utf8")
  ) as SignedNetworkRegistry;
  assert.equal(verifySignedRegistry(signed72, signed72.root_public_key_hex, signed72.issued_at_unix_s + 10).valid, true);
  // config/signed_grid_72_network.json still lists 4 SoftwareDev AWS anchors -> MUST fail fail-closed production check!
  const prodCheck72 = validateProductionRegistry(signed72);
  assert.equal(prodCheck72.valid, false);
  assert.ok(prodCheck72.errors.some((e) => e.includes("SoftwareDev")));
  // A clean all-hardware-TEE registry MUST pass validateProductionRegistry:
  const cleanHw72 = structuredClone(signed72);
  for (const a of cleanHw72.grid.anchors) {
    if (a.tee_vendor === "SoftwareDev") a.tee_vendor = "AwsNitro";
  }
  assert.equal(validateProductionRegistry(cleanHw72).valid, true);

  const tampered = structuredClone(signed72);
  tampered.grid.anchors[0].location.lat += 0.5;
  assert.equal(verifySignedRegistry(tampered, signed72.root_public_key_hex, signed72.issued_at_unix_s + 10).valid, false);

  const fixture = JSON.parse(readFileSync("../testdata/fixture.json", "utf8"));
  const net1 = signTestRegistry("proofofgeography.com", "jperla", fixture.grid, fixture.now_unix_s);
  const net2 = signTestRegistry("cloudflare-pog", "Cloudflare", fixture.grid, fixture.now_unix_s);

  const fedOk = verifyFederatedProof(
    [
      { networkId: "proofofgeography.com", bundleOrHeader: fixture.honest_tokyo_header },
      { networkId: "cloudflare-pog", bundleOrHeader: fixture.honest_tokyo_header },
    ],
    [
      { networkId: "proofofgeography.com", pinnedRootPublicKeyHex: net1.rootPkHex, signedRegistry: net1.reg },
      { networkId: "cloudflare-pog", pinnedRootPublicKeyHex: net2.rootPkHex, signedRegistry: net2.reg },
    ],
    {
      minIndependentNetworks: 2,
      policy: { allowSoftwareDev: true, maxByzantine: 1, minAnchors: 5, minCloudProviders: 3 },
      nowUnixS: fixture.now_unix_s,
    }
  );
  assert.equal(fedOk.overallValid, true, `Failures: ${fedOk.failureReasons.join(", ")}`);
  assert.equal(fedOk.validIndependentNetworks, 2);
  assert.equal(fedOk.proverPkConsistentAcrossNetworks, true);
  assert.equal(fedOk.ipConsistentAcrossNetworks, true);

  const fakeSecond = verifyFederatedProof(
    [
      { networkId: "net-a", bundleOrHeader: fixture.honest_tokyo_header },
      { networkId: "net-b", bundleOrHeader: fixture.honest_tokyo_header },
    ],
    [
      { networkId: "net-a", pinnedRootPublicKeyHex: net1.rootPkHex, signedRegistry: net1.reg },
      { networkId: "net-b", pinnedRootPublicKeyHex: net1.rootPkHex, signedRegistry: net1.reg },
    ],
    {
      minIndependentNetworks: 2,
      policy: { allowSoftwareDev: true, maxByzantine: 1, minAnchors: 5, minCloudProviders: 3 },
      nowUnixS: fixture.now_unix_s,
    }
  );
  assert.equal(fakeSecond.overallValid, false);
});

test("correlated spatial likelihood surface: shared-path deweighting & multi-peak ambiguity", () => {
  const base = [
    { anchorId: "a1", lat: 40.71, lon: -74.0, rttMs: 28.0, rttMinMs: 27.5, jitterMs: 0.5 },
    { anchorId: "a2", lat: 37.34, lon: -121.89, rttMs: 52.0, rttMinMs: 51.4, jitterMs: 0.6 },
    { anchorId: "a3", lat: 43.65, lon: -79.38, rttMs: 19.0, rttMinMs: 18.6, jitterMs: 0.4 },
    { anchorId: "a4", lat: 29.42, lon: -98.49, rttMs: 34.0, rttMinMs: 33.5, jitterMs: 0.5 },
  ];
  const dup = [...base, ...Array.from({ length: 7 }, (_, i) => ({ ...base[0], anchorId: `dup-${i}` }))];
  const sBase = computeSpatialLikelihood(base, { gridPoints: 1200 });
  const sDup = computeSpatialLikelihood(dup, { gridPoints: 1200 });
  assert.equal(sBase.isEmpiricalEstimate, true);
  assert.equal(sBase.isHardProof, false);
  assert.ok(sDup.effectiveIndependentAnchors < 5.0);
  assert.ok(sDup.moreLikelyAreaKm2 >= sBase.moreLikelyAreaKm2 * 0.45);
  assert.ok(sBase.moreLikelyAreaKm2 <= sBase.vacuumOuterAreaKm2 + 1e-6);

  const sym = computeSpatialLikelihood(
    [
      { anchorId: "west", lat: 0, lon: -15, rttMs: 35, rttMinMs: 34.8, jitterMs: 0.2 },
      { anchorId: "east", lat: 0, lon: 15, rttMs: 35, rttMinMs: 34.8, jitterMs: 0.2 },
    ],
    { gridPoints: 1200 }
  );
  assert.ok(sym.peaks.length >= 2);
});
