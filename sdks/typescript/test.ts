import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  signedRegistryDigest,
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

test("verifies Rust-generated honest Tokyo GPU header, observed IPs & rejects spoof", () => {
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
  assert.ok(honest.observedProverIps.length >= 5);
  assert.ok(honest.distinctObservedIps.length >= 1);
  assert.equal(honest.ipViewConsistent, true);

  const spoof = verifyProof(
    fixture.spoofed_singapore_header,
    fixture.grid,
    { allowSoftwareDev: true, maxByzantine: 1, minAnchors: 5, minCloudProviders: 3 },
    fixture.now_unix_s
  );
  assert.equal(spoof.overallValid, false);
  assert.ok(spoof.tier1aVacuum.provenMaxRadiusKm > 4000);
});

test("cross-verifies real Rust-signed operator registry & 2-network federated quorum", () => {
  const signed72 = JSON.parse(
    readFileSync("../../config/signed_grid_72_network.json", "utf8")
  ) as SignedNetworkRegistry;
  assert.equal(verifySignedRegistry(signed72, signed72.root_public_key_hex, signed72.issued_at_unix_s + 10).valid, true);

  // Tampering with a single Anchor coordinate MUST fail operator signature verification.
  const tampered = structuredClone(signed72);
  tampered.grid.anchors[0].location.lat += 0.5;
  assert.equal(verifySignedRegistry(tampered, signed72.root_public_key_hex, signed72.issued_at_unix_s + 10).valid, false);

  // Federated 2-network verification (e.g. proofofgeography.com + cloudflare-pog).
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

  // Re-using the SAME root key under two network names MUST NOT satisfy minIndependentNetworks=2!
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
