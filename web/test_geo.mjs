import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const geoSrc = readFileSync(new URL("./geo.js", import.meta.url), "utf8");
const constSrc = readFileSync(new URL("./constellation.js", import.meta.url), "utf8");
const sandbox = { window: {}, globalThis: {}, URL };
sandbox.globalThis = sandbox.window;
vm.runInNewContext(geoSrc, sandbox);
vm.runInNewContext(constSrc, sandbox);
const PogGeo = sandbox.window.PogGeo;
const PogConstellation = sandbox.window.PogConstellation;

test("v6 150ms repro (San Jose, Frankfurt, Tokyo) produces Whole Earth (20,015.1 km, 100% area, no cap!)", () => {
  const meas = [
    { anchor: { id: "sjc", lat: 37.4, lon: -121.9 }, rttMs: 150.0 },
    { anchor: { id: "fra", lat: 50.1, lon: 8.7 }, rttMs: 150.0 },
    { anchor: { id: "nrt", lat: 35.7, lon: 139.7 }, rttMs: 150.0 },
  ];
  const sol = PogGeo.solveLocation(meas, "vacuum", { byzantineF: 0 });
  assert.equal(sol.wholeEarth, true);
  assert.equal(sol.feasibleState, "whole_earth");
  assert.ok(Math.abs(sol.maxRadiusKm - PogGeo.HALF_CIRCUMFERENCE_KM) < 0.05, `Got ${sol.maxRadiusKm}`);
  assert.equal(sol.areaFraction, 1.0);
  // Antipodal spoof claim MUST NOT be excluded!
  const sp = PogGeo.evaluateSpoofClaim(-36.85, 174.76, meas, "vacuum", { byzantineF: 0 });
  assert.equal(sp.caught, false);
  assert.equal(sp.caughtByAnyAnchor, false);
});

test("geodesicCircleGeometry has no 19,000 km cap and passes all 7 Mercator cap-fill cases (0 misses, 0 extra, zero false whole-earth outline)", () => {
  const whole = PogGeo.geodesicCircleGeometry(37.4, -121.9, PogGeo.HALF_CIRCUMFERENCE_KM);
  assert.equal(whole.wholeEarth, true);
  assert.equal(whole.stroke.length, 0);
  assert.equal(whole.fill.length, 4);

  const merc = (lat) => Math.log(Math.tan(Math.PI / 4 + (Math.PI / 180) * (lat / 2)));
  const project = (ring) => ring.map(([lat, lon]) => [merc(lat), lon]);
  const contains = (ring, lat, lon) => {
    const y = merc(lat);
    let inside = false;
    for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
      const [a, xi] = ring[i], [b, xj] = ring[j];
      if ((a > y) !== (b > y) && lon < xi + ((xj - xi) * (y - a)) / (b - a)) inside = !inside;
    }
    return inside;
  };
  const cases = [
    ["local", 0, 0, 2000],
    ["dateline", 31, 179, 3200],
    ["north", 72, 17, 3500],
    ["south", -65, 166, 4200],
    ["larger-than-hemisphere", 0, 24, 14500],
    ["near-global", 0, -23, 19500],
    ["whole-earth", 38, -79, 21100],
  ];
  for (const [name, lat, lon, radius] of cases) {
    const rings = [-360, 0, 360].map((shift) => {
      const g = PogGeo.geodesicCircleGeometry(lat, lon, radius, 144, shift);
      assert.ok(
        Array.isArray(g.fill) && g.fill.every((pt) => Array.isArray(pt) && pt.length === 2 && pt.every(Number.isFinite)),
        `${name}: fill must be a flat [lat, lon][] ring`
      );
      if (name === "whole-earth") {
        assert.equal(g.wholeEarth, true);
        assert.equal(g.stroke.length, 0, "whole-earth must have NO false outline");
      }
      return project(g.fill);
    });
    let misses = 0, extra = 0;
    for (let y = -80; y <= 80; y += 5) {
      for (let x = -178; x <= 178; x += 4) {
        const d = PogGeo.haversineKm(lat, lon, y, x);
        if (Math.abs(d - radius) < 200) continue;
        const filled = rings.some((poly) => contains(poly, y, x));
        if (d < radius && !filled) misses++;
        if (d > radius && filled) extra++;
      }
    }
    assert.equal(misses, 0, `${name}: expected 0 misses, got ${misses}`);
    assert.equal(extra, 0, `${name}: expected 0 extra, got ${extra}`);
  }
});

test("vacuum outer bound never subtracts empirical overhead and accounts for chord & uncertainty", () => {
  const rBase = PogGeo.rttToRadiusKm(50.0, "vacuum", { anchorUncertaintyKm: 0, clockResolutionMs: 0, clockSlewPpm: 0, accountForChord: false, accountForWgs84: false });
  const rConservative = PogGeo.rttToRadiusKm(50.0, "vacuum", { isBrowserProbe: true });
  assert.ok(rConservative > rBase + 150.0, `Expected conservative > base, got ${rConservative} vs ${rBase}`);
  // Passing extraOverheadMs must NEVER shrink vacuum!
  const rWithExtra = PogGeo.rttToRadiusKm(50.0, "vacuum", { extraOverheadMs: 25.0 });
  const rNoExtra = PogGeo.rttToRadiusKm(50.0, "vacuum", {});
  assert.equal(rWithExtra, rNoExtra);
});

test("near-colocated 1m anchors, disconnected k-of-n, and dateline crossing solve cleanly", () => {
  const near = PogGeo.solveByzantineCore(
    [
      { anchor: { id: "a" }, lat: 50.1109, lon: 8.6821, rttMs: 2.0, radiusKm: 300 },
      { anchor: { id: "b" }, lat: 50.110909, lon: 8.6821, rttMs: 2.0, radiusKm: 300 },
    ],
    0,
    [50.1109, 8.6821]
  );
  assert.equal(near.feasible, true);
  assert.ok(Math.abs(near.provenMaxRadiusKm - 300) < 2.0);

  const disc = PogGeo.solveByzantineCore(
    [
      { anchor: { id: "n1" }, lat: 40.71, lon: -74.0, rttMs: 2, radiusKm: 400 },
      { anchor: { id: "n2" }, lat: 40.8, lon: -74.1, rttMs: 2, radiusKm: 400 },
      { anchor: { id: "e1" }, lat: 50.11, lon: 8.68, rttMs: 2, radiusKm: 400 },
      { anchor: { id: "e2" }, lat: 50.2, lon: 8.7, rttMs: 2, radiusKm: 400 },
    ],
    2,
    [40.71, -74.0]
  );
  assert.equal(disc.feasible, true);
  assert.ok(disc.provenMaxRadiusKm > 6400);

  // Dateline crossing (Suva, Fiji)
  const dlMeas = [
    { anchor: { id: "syd", lat: -33.87, lon: 151.21 }, rttMs: 48.0 },
    { anchor: { id: "hnl", lat: 21.31, lon: -157.86 }, rttMs: 76.0 },
    { anchor: { id: "nrt", lat: 35.69, lon: 139.69 }, rttMs: 105.0 },
  ];
  const dlSol = PogGeo.solveLocation(dlMeas, "vacuum", { byzantineF: 0, refLatLon: [-18.14, 178.44] });
  assert.equal(dlSol.feasible, true);
  assert.equal(dlSol.wholeEarth, false);
  // Check Suva is inside every vacuum disk!
  const suvaU = PogGeo.toVec3(-18.14, 178.44);
  for (const d of dlSol.core.disks) {
    assert.ok(PogGeo.dot3(suvaU, d.u) >= d.cosTheta);
  }
});

test("correlated spatial likelihood surface: shared-path invariance, multi-peak, and held-out containment", () => {
  const base = [
    { anchor: { id: "a1", lat: 40.71, lon: -74.0 }, rttMs: 27.5, minMs: 27.5, medianMs: 28.0, jitterMs: 0.5 },
    { anchor: { id: "a2", lat: 37.34, lon: -121.89 }, rttMs: 51.4, minMs: 51.4, medianMs: 52.0, jitterMs: 0.6 },
    { anchor: { id: "a3", lat: 43.65, lon: -79.38 }, rttMs: 18.6, minMs: 18.6, medianMs: 19.0, jitterMs: 0.4 },
    { anchor: { id: "a4", lat: 29.42, lon: -98.49 }, rttMs: 33.5, minMs: 33.5, medianMs: 34.0, jitterMs: 0.5 },
  ];
  const dup = [...base, ...Array.from({ length: 7 }, (_, i) => ({ ...base[0], anchor: { ...base[0].anchor, id: `dup-${i}` } }))];
  const sBase = PogGeo.computeSpatialLikelihoodSurface(base);
  const sDup = PogGeo.computeSpatialLikelihoodSurface(dup);
  assert.equal(sBase.isEmpiricalEstimate, true);
  assert.equal(sBase.isHardProof, false);
  assert.ok(sDup.effectiveIndependentAnchors < 5.0);
  assert.ok(sDup.moreLikelyAreaKm2 >= sBase.moreLikelyAreaKm2 * 0.45);
  assert.ok(sBase.moreLikelyAreaKm2 <= sBase.vacuumOuterAreaKm2 + 1e-6);

  // 2 symmetric equatorial anchors -> >= 2 peaks
  const sSym = PogGeo.computeSpatialLikelihoodSurface([
    { anchor: { id: "w", lat: 0, lon: -15 }, rttMs: 34.8, minMs: 34.8, medianMs: 35.0, jitterMs: 0.2 },
    { anchor: { id: "e", lat: 0, lon: 15 }, rttMs: 34.8, minMs: 34.8, medianMs: 35.0, jitterMs: 0.2 },
  ]);
  assert.ok(sSym.peaks.length >= 2);

  // Real held-out test server Chicago (T2) -> Vacuum c0 MUST contain known target Chicago!
  const qa = JSON.parse(readFileSync(new URL("./data/qa_heldout_targets.json", import.meta.url), "utf8"));
  const chi = qa.targets["azure-northcentralus-chicago"];
  const chiMeas = chi.measurements.map((m) => ({
    anchor: { id: m.anchor_id, lat: m.lat, lon: m.lon },
    rttMs: m.min_ms,
    minMs: m.min_ms,
    medianMs: m.median_ms,
    jitterMs: m.jitter_ms,
  }));
  const chiSol = PogGeo.solveLocation(chiMeas, "vacuum", { byzantineF: 0, refLatLon: [chi.target.lat, chi.target.lon] });
  assert.equal(chiSol.feasible, true);
  const chiU = PogGeo.toVec3(chi.target.lat, chi.target.lon);
  for (const d of chiSol.core.disks) {
    assert.ok(PogGeo.dot3(chiU, d.u) >= d.cosTheta, `Vacuum cap missed Chicago on ${d.anchor.id}`);
  }
  assert.ok(chiSol.likelihood.peaks.length >= 1);
  const peakErrKm = PogGeo.haversineKm(chi.target.lat, chi.target.lon, chiSol.likelihood.peaks[0].lat, chiSol.likelihood.peaks[0].lon);
  assert.ok(peakErrKm < 350, `Expected Chicago peak within 350 km, got ${peakErrKm.toFixed(1)} km`);
});

test("Frankfurt AWS live-site repro (Vacuum c0, Closest 5, self-excluded & held-out): zero wrong-side fill and 100% containment", () => {
  const mesh = JSON.parse(readFileSync(new URL("./data/live_mesh_summary.json", import.meta.url), "utf8"));
  const fraAwsLatLon = [50.1167, 8.6833];
  const rtts = mesh.provers["aws-eu-central-1-frankfurt"].rtts_ms;
  assert.equal(rtts["aws-eu-central-1-frankfurt"], 0.83);

  // 1. Live prod 3-AWS-anchor case (where v6 drew a wrong-side southern fill with 355.8° horizontal chord excluding Frankfurt!):
  const aws3 = [
    { anchor: { id: "aws-us-east-1-nvirginia", lat: 39.018, lon: -77.459 }, rttMs: rtts["aws-us-east-1-nvirginia"] },
    { anchor: { id: "aws-us-west-1-sanjose", lat: 37.3382, lon: -121.8863 }, rttMs: rtts["aws-us-west-1-sanjose"] },
    { anchor: { id: "aws-ap-northeast-1-tokyo", lat: 35.6895, lon: 139.6917 }, rttMs: rtts["aws-ap-northeast-1-tokyo"] },
  ];
  const sol3 = PogGeo.solveLocation(aws3, "vacuum", { byzantineF: 0, refLatLon: fraAwsLatLon });
  assert.equal(sol3.wholeEarth, true);
  assert.ok(Math.abs(sol3.maxRadiusKm - PogGeo.HALF_CIRCUMFERENCE_KM) < 0.05);
  // Every circle in Closest 5 for this case is wholeEarth -> zero horizontal wrap stroke!
  for (const c of sol3.circles) {
    const geom = PogGeo.geodesicCircleGeometry(c.lat, c.lon, c.radiusKm);
    assert.equal(geom.wholeEarth, true);
    assert.equal(geom.stroke.length, 0);
  }

  // 2. Full 9-node mesh minus self (8 independent peers): f=0 tightly contains Frankfurt (~298 km); f=1 is Whole Earth!
  const legacy = {
    "aws-us-west-1-sanjose": [37.3382, -121.8863],
    "gcp-us-west1-oregon": [45.5946, -121.1787],
    "gcp-us-central1-iowa": [41.2619, -95.8608],
    "gcp-us-east4-ashburn": [39.0438, -77.4874],
    "aws-us-east-1-nvirginia": [39.018, -77.459],
    "gcp-europe-west3-frankfurt": [50.1109, 8.6821],
    "aws-ap-northeast-1-tokyo": [35.6895, 139.6917],
    "gcp-asia-southeast1-singapore": [1.3521, 103.8198],
  };
  const peers8 = Object.entries(legacy).map(([id, [lat, lon]]) => ({
    anchor: { id, lat, lon },
    rttMs: rtts[id],
  }));
  const sol8f0 = PogGeo.solveLocation(peers8, "vacuum", { byzantineF: 0, refLatLon: fraAwsLatLon });
  assert.equal(sol8f0.wholeEarth, false);
  assert.ok(sol8f0.maxRadiusKm < 320);
  const fraU = PogGeo.toVec3(fraAwsLatLon[0], fraAwsLatLon[1]);
  for (const d of sol8f0.core.disks) {
    assert.ok(PogGeo.dot3(fraU, d.u) >= d.cosTheta - 1e-11);
  }
  const sol8f1 = PogGeo.solveLocation(peers8, "vacuum", { byzantineF: 1, refLatLon: fraAwsLatLon });
  assert.equal(sol8f1.wholeEarth, true);
});

test("official constellation exclusivity: ?registry= selects separate external constellation without altering official roster or hardware counts", () => {
  const officialJson = JSON.parse(readFileSync(new URL("./data/anchors.json", import.meta.url), "utf8"));
  const externalJson = JSON.parse(readFileSync(new URL("../examples/external_constellation_registry.json", import.meta.url), "utf8"));

  const store = PogConstellation.createConstellationStore(officialJson, {
    pageOrigin: "https://proofofgeography.com",
  });

  // 1. Default loads official web/data/anchors.json (49 operated nodes: 7 HW TEE + 42 pilot)
  const initialOfficial = store.getOfficial();
  assert.equal(initialOfficial.isOfficial, true);
  assert.equal(initialOfficial.isExternal, false);
  assert.equal(initialOfficial.anchors.length, 49);
  const officialIdsBefore = initialOfficial.anchors.map((a) => a.id);

  // Record a SoftwareDev response on one official anchor before switching
  assert.equal(store.recordLiveInfo("aws-us-east-1-nvirginia", { tee_vendor: "SoftwareDev", public_key_hex: "aa".repeat(32) }), true);
  const officialAuditBefore = store.getOfficialAudit(null);
  assert.equal(officialAuditBefore.configured, 49);
  assert.equal(officialAuditBefore.reachable, 1);
  assert.equal(officialAuditBefore.hwTee, 0);
  assert.equal(officialAuditBefore.officialHwTee, 0);

  // 2. Selecting an external ?registry=<url> REPLACES active constellation (never merges!)
  const extUrl = "https://pog.example-operator.org/.well-known/pog-network.json";
  const selectedExt = store.selectExternal(externalJson, extUrl);
  assert.equal(selectedExt.isExternal, true);
  assert.equal(selectedExt.isOfficial, false);
  assert.equal(selectedExt.officialMembership, false);
  assert.equal(selectedExt.anchors.length, 2);
  assert.deepEqual(
    Array.from(selectedExt.anchors, (a) => a.id),
    ["ext-aws-iad-01", "ext-gcp-fra-01"]
  );

  // 3. Optional https_url routes external /info and /ping strictly to operator's own HTTPS domain
  assert.equal(
    PogConstellation.resolveAnchorBaseUrl(selectedExt.anchors[0], selectedExt, "https://proofofgeography.com"),
    "https://iad-aws.pog.example-operator.org"
  );
  // External anchor without https_url MUST NOT fall back to *.a.proofofgeography.com!
  const extNoUrl = PogConstellation.normalizeAnchor(
    { id: "ext-no-url", slug: "iad-aws", lat: 39.0, lon: -77.4, cloud: "aws" },
    { isOfficial: false }
  );
  assert.equal(PogConstellation.resolveAnchorBaseUrl(extNoUrl, selectedExt, "https://proofofgeography.com"), null);

  // 4. Keep AwsNitro badge AND count hardware strictly within the selected constellation
  const nitroBadge = PogConstellation.teeBadgeForVendor("AwsNitro", "aws");
  assert.equal(nitroBadge.label, "AWS Nitro");
  assert.equal(nitroBadge.cls, "tee-aws");
  assert.equal(nitroBadge.isHw, true);

  // Simulate live hardware-attested responses on BOTH external nodes (AwsNitro + AmdSevSnp)
  assert.equal(
    store.recordLiveInfo("ext-aws-iad-01", {
      tee_vendor: "AwsNitro",
      public_key_hex: "11".repeat(32),
      operator_endorsement: { anchor_public_key_hex: "11".repeat(32) },
    }),
    true
  );
  assert.equal(
    store.recordLiveInfo("ext-gcp-fra-01", {
      tee_vendor: "AmdSevSnp",
      public_key_hex: "22".repeat(32),
      operator_endorsement: { anchor_public_key_hex: "22".repeat(32) },
    }),
    true
  );
  // Attempting to inject an official node ID while external is active MUST be rejected
  assert.equal(store.recordLiveInfo("aws-us-east-1-nvirginia", { tee_vendor: "AwsNitro", public_key_hex: "ff".repeat(32) }), false);

  const extAudit = store.getActiveAudit(null);
  assert.equal(extAudit.isExternal, true);
  assert.equal(extAudit.configured, 2);
  assert.equal(extAudit.reachable, 2);
  assert.equal(extAudit.hwTee, 2);
  assert.equal(extAudit.hardwareByVendor.AwsNitro, 1);
  assert.equal(extAudit.hardwareByVendor.AmdSevSnp, 1);
  // Hardware verification in external constellation MUST NOT confer official membership or official HW count!
  assert.equal(extAudit.officialHwTee, 0);
  assert.equal(extAudit.officialProofEligible, 0);

  // 5. CRITICAL INVARIANT: Official roster, IDs, count, and HW counts are 100% UNCHANGED!
  const officialAfter = store.getOfficial();
  assert.equal(officialAfter.anchors.length, 49);
  assert.deepEqual(Array.from(officialAfter.anchors, (a) => a.id), Array.from(officialIdsBefore));
  const officialAuditAfter = store.getOfficialAudit(null);
  assert.equal(officialAuditAfter.configured, 49);
  assert.equal(officialAuditAfter.reachable, 1);
  assert.equal(officialAuditAfter.hwTee, 0);
  assert.equal(officialAuditAfter.officialHwTee, 0);
  assert.equal(officialAuditAfter.officialProofEligible, 0);

  // 6. Reject non-HTTPS external registry URLs on production origin
  assert.throws(() => store.selectExternal(externalJson, "http://evil.example/pog.json"));
  assert.throws(() => store.selectExternal(externalJson, "javascript:alert(1)"));
});

test("5-regime route pathology suite (tight, consistently slow, isolated-fast, slow-tail, multimodal) shows less certainty for unstable routes without narrowing Vacuum c0", () => {
  const target = [41.8781, -87.6298];
  const anchors = [
    { id: "tor", lat: 43.6532, lon: -79.3832 },
    { id: "dsm", lat: 41.2619, lon: -95.8608 },
    { id: "iad", lat: 39.0438, lon: -77.4874 },
    { id: "dal", lat: 32.7767, lon: -96.7970 },
    { id: "yul", lat: 45.5017, lon: -73.5673 },
    { id: "chs", lat: 32.7765, lon: -79.9311 },
    { id: "slc", lat: 40.7608, lon: -111.8910 },
    { id: "sjc", lat: 37.3382, lon: -121.8863 },
  ];
  const tightOffs = [-0.15, -0.10, -0.06, -0.04, -0.02, 0.0, 0.02, 0.04, 0.07, 0.10, 0.14, 0.18];
  const baseRtt = (d) => 2.0 + (2.0 * d) / (80.0 + 63.0 * (1.0 - Math.exp(-d / 3500.0)));

  const build = (regime) =>
    anchors.map((a, idx) => {
      const d = PogGeo.haversineKm(target[0], target[1], a.lat, a.lon);
      const b = baseRtt(d);
      let s;
      if (regime === "tight") s = tightOffs.map((o) => b + o);
      else if (regime === "consistently_slow") s = tightOffs.map((o) => b + (idx % 2 === 0 ? 28.0 : 0.0) + o);
      else if (regime === "isolated_fast") {
        s = tightOffs.map((o) => b + o);
        if (idx === 0) s[0] = 3.2;
      } else if (regime === "slow_tail") {
        s = idx < 4 ? [...tightOffs.slice(0, 7).map((o) => b + o), b + 25, b + 42, b + 60, b + 78, b + 95] : tightOffs.map((o) => b + o);
      } else if (regime === "multimodal") {
        s = idx < 4 ? [...tightOffs.slice(0, 6).map((o) => b + o), ...tightOffs.slice(0, 6).map((o) => b + 44 + o)] : tightOffs.map((o) => b + o);
      }
      s.sort((x, y) => x - y);
      const spread = PogGeo.routeInstabilitySpreadMs(s);
      return { anchor: a, rttMs: s[0], minMs: s[0], medianMs: (s[5] + s[6]) / 2, jitterMs: spread, samples: s };
    });

  const mTight = build("tight");
  const mSlow = build("consistently_slow");
  const mIso = build("isolated_fast");
  const mTail = build("slow_tail");
  const mMulti = build("multimodal");

  assert.ok(mTight[0].jitterMs < 0.3);
  assert.ok(mTail[0].jitterMs > 20.0);
  assert.ok(mMulti[0].jitterMs > 25.0);
  assert.ok(mIso[0].jitterMs > 5.0);

  const sTight = PogGeo.computeSpatialLikelihoodSurface(mTight, { byzantineF: 0 });
  const sSlow = PogGeo.computeSpatialLikelihoodSurface(mSlow, { byzantineF: 0 });
  const sTail = PogGeo.computeSpatialLikelihoodSurface(mTail, { byzantineF: 0 });
  const sMulti = PogGeo.computeSpatialLikelihoodSurface(mMulti, { byzantineF: 0 });
  const sIso = PogGeo.computeSpatialLikelihoodSurface(mIso, { byzantineF: 1 });

  // Unstable routes widen uncertainty bands vs tight!
  assert.ok(sTail.plausibleAreaKm2 > sTight.plausibleAreaKm2, `slow_tail ${sTail.plausibleAreaKm2} vs tight ${sTight.plausibleAreaKm2}`);
  assert.ok(sMulti.plausibleAreaKm2 > sTight.plausibleAreaKm2, `multimodal ${sMulti.plausibleAreaKm2} vs tight ${sTight.plausibleAreaKm2}`);
  assert.ok(sSlow.plausibleAreaKm2 > sTight.plausibleAreaKm2, `consistently_slow ${sSlow.plausibleAreaKm2} vs tight ${sTight.plausibleAreaKm2}`);

  // Median center resists isolated-fast single anomaly; Vacuum c0 never narrows on slow routes
  const isoErr = PogGeo.haversineKm(target[0], target[1], sIso.peaks[0].lat, sIso.peaks[0].lon);
  assert.ok(isoErr < 120.0, `isolated_fast peak error ${isoErr.toFixed(1)} km`);
  assert.ok(sSlow.vacuumOuterAreaKm2 >= sTight.vacuumOuterAreaKm2);
});

test("untrusted registry strings, quotes, literal angle brackets, colors, and URLs render strictly as text (never DOM) with zero innerHTML sinks", () => {
  // 1. Static source invariant: ZERO innerHTML / outerHTML / insertAdjacentHTML sinks in web/app.js & web/constellation.js!
  const appSrc = readFileSync(new URL("./app.js", import.meta.url), "utf8");
  assert.equal(/\.(innerHTML|outerHTML)\b|insertAdjacentHTML\b/.test(appSrc), false, "web/app.js must not use innerHTML/outerHTML/insertAdjacentHTML");
  assert.equal(/\.(innerHTML|outerHTML)\b|insertAdjacentHTML\b/.test(constSrc), false, "web/constellation.js must not use innerHTML/outerHTML/insertAdjacentHTML");

  // 2. Color & URL validation reject CSS/URL injection attempts
  assert.equal(PogConstellation.sanitizeHexColor("#38bdf8"), "#38bdf8");
  assert.equal(PogConstellation.sanitizeHexColor("#0f8"), "#0f8");
  assert.equal(PogConstellation.sanitizeHexColor('#123456; background-image: url("https://example.invalid")', "#10b981"), "#10b981");
  assert.equal(PogConstellation.sanitizeHexColor('" onclick="x', "#f59e0b"), "#f59e0b");
  assert.equal(PogConstellation.sanitizeHexColor("rgb(1,2,3)", "#38bdf8"), "#38bdf8");

  assert.equal(PogConstellation.validateHttpsOrLocalUrl("javascript:void(0)", "https://proofofgeography.com"), null);
  assert.equal(PogConstellation.validateHttpsOrLocalUrl("data:text/plain,hello", "https://proofofgeography.com"), null);
  assert.equal(PogConstellation.validateHttpsOrLocalUrl("http://external.example/reg.json", "https://proofofgeography.com"), null);
  assert.equal(PogConstellation.validateHttpsOrLocalUrl("https://user:pass@external.example/reg.json", "https://proofofgeography.com"), null);
  assert.equal(PogConstellation.validateHttpsOrLocalUrl("https://valid.example/reg.json\nX-Inject: 1", "https://proofofgeography.com"), null);
  assert.equal(PogConstellation.validateHttpsOrLocalUrl("https://valid.example/reg.json/", "https://proofofgeography.com"), "https://valid.example/reg.json");

  // 3. Minimal inert DOM harness verifying quotes & literal angle brackets stay strictly text, never parsed tags
  function createMockDocument() {
    class MockNode {
      constructor(nodeType, tagName = null, text = "") {
        this.nodeType = nodeType;
        this.tagName = tagName;
        this.children = [];
        this.className = "";
        this.dataset = {};
        this.style = {};
        this.attributes = {};
        this._text = text;
        Object.defineProperty(this, "innerHTML", {
          get() { throw new Error("innerHTML read forbidden"); },
          set() { throw new Error("innerHTML write forbidden"); },
        });
      }
      set textContent(v) {
        this.children = [];
        this._text = String(v ?? "");
      }
      get textContent() {
        if (this.children.length === 0) return this._text;
        return this.children.map((c) => c.textContent).join("");
      }
      appendChild(child) {
        if (child.nodeType === 11) {
          for (const gc of child.children) this.children.push(gc);
        } else {
          this.children.push(child);
        }
        return child;
      }
      setAttribute(k, v) {
        this.attributes[k] = String(v);
      }
    }
    return {
      createElement: (tag) => new MockNode(1, String(tag).toLowerCase()),
      createTextNode: (t) => new MockNode(3, null, String(t ?? "")),
      createDocumentFragment: () => new MockNode(11, "#fragment"),
    };
  }
  const collectTags = (node, out = []) => {
    if (node.nodeType === 1) out.push(node.tagName);
    for (const c of node.children || []) collectTags(c, out);
    return out;
  };

  const doc = createMockDocument();
  const inertId = 'ext-"node"-<alpha>';
  const inertCity = 'O\'Hare "Terminal" <North>';
  const inertOp = 'Acme "Geo" <Lab>';
  const inertNet = 'net-"quote"-<beta>';
  const inertCloud = 'cloud<"x">';
  const inertReason = 'Mismatch: expected <key> != "other"';
  const inertVendor = 'Custom<Vendor>"v2"';

  const extPayload = {
    network_id: inertNet,
    operator_name: inertOp,
    anchors: [
      {
        id: inertId,
        slug: 'bad"slug<1>',
        city: inertCity,
        cloud: inertCloud,
        lat: 41.97,
        lon: -87.9,
        color: '#ff0000; position:fixed',
        https_url: "https://anchor.example.org/node",
        endpoint_tcp: '198.51.100.1:7443"<tag>',
      },
    ],
  };

  const parsed = PogConstellation.parseConstellationPayload(extPayload, {
    isOfficial: false,
    registryUrl: "https://example.org/registry.json",
    pageOrigin: "https://proofofgeography.com",
  });
  const anchor = parsed.anchors[0];
  assert.equal(anchor.color, "#a78bfa", "malformed registry color must fall back to safe hex");
  assert.equal(anchor.slug, null, "malformed slug must be rejected");
  assert.equal(anchor.id, inertId);
  assert.equal(anchor.city, inertCity);

  const badge = PogConstellation.teeBadgeForVendor("SoftwareDev", anchor.cloud);
  assert.equal(badge.cls, "tee-dev");

  // Anchor row (renderLiveAnchorList / renderMeshAnchorList)
  const row = PogConstellation.buildAnchorRowElement(doc, {
    anchor,
    badge,
    rttText: "14.2 ms",
    metaText: anchor.endpoint_tcp,
    barPct: 50,
    barColor: '#123; evil',
  });
  assert.equal(row.dataset.anchor, inertId);
  assert.ok(row.textContent.includes(inertCity));
  assert.ok(row.textContent.includes(anchor.endpoint_tcp));
  assert.deepEqual(
    Array.from(new Set(collectTags(row))).sort(),
    ["div", "i", "span"],
    "angle brackets in anchor fields must not create any DOM elements"
  );

  // Anchor popup (renderAnchorMarkers)
  const popup = PogConstellation.buildAnchorPopupElement(doc, {
    anchor,
    active: parsed,
    badge,
    baseUrl: anchor.https_url,
    online: false,
    pkMatchesPub: false,
    prodEligible: false,
    pkShort: 'pk"<raw>',
  });
  assert.ok(popup.textContent.includes(inertCity));
  assert.ok(popup.textContent.includes(inertId));
  assert.ok(popup.textContent.includes(inertOp));
  assert.ok(popup.textContent.includes(inertNet));
  assert.deepEqual(Array.from(new Set(collectTags(popup))).sort(), ["code", "div", "span", "strong"]);

  // External constellation banner
  const bannerFrag = PogConstellation.buildExternalBannerElement(doc, { active: parsed, officialCount: 42 });
  assert.ok(bannerFrag.textContent.includes(inertOp));
  assert.ok(bannerFrag.textContent.includes(inertNet));
  assert.deepEqual(Array.from(new Set(collectTags(bannerFrag))).sort(), ["a", "br", "code", "div", "strong"]);

  // Verifier rejected reasons & decoded vendor string (verifyHeaderInput ~1522 / ~1535)
  const rejFrag = PogConstellation.buildVerifyVerdictElement(doc, {
    status: "rejected",
    failureReasons: [inertReason],
  });
  assert.ok(rejFrag.textContent.includes(inertReason));
  assert.deepEqual(Array.from(new Set(collectTags(rejFrag))).sort(), ["br", "strong"]);

  const localFrag = PogConstellation.buildVerifyVerdictElement(doc, {
    status: "local_decoded",
    localVendor: inertVendor,
    receiptCount: 3,
  });
  assert.ok(localFrag.textContent.includes(inertVendor));
  assert.deepEqual(Array.from(new Set(collectTags(localFrag))).sort(), ["br", "code", "strong"]);

  // Spoof verdict & tooltip with quotes/angle brackets
  const spoofFrag = PogConstellation.buildSpoofVerdictElement(doc, {
    caught: true,
    tierLabel: "Vacuum c₀",
    claimLabel: 'Claim "<x>"',
    violationCount: 1,
    totalCount: 1,
    byzantineF: 0,
    worst: { city: inertCity, rttText: "10.0 ms", maxDistText: "1500 km", claimDistText: "5000 km", cMultipleText: "3.33" },
  });
  assert.ok(spoofFrag.textContent.includes(inertCity));
  assert.ok(spoofFrag.textContent.includes('Claim "<x>"'));
  assert.deepEqual(Array.from(new Set(collectTags(spoofFrag))).sort(), ["br", "strong"]);

  const tipNode = PogConstellation.buildTooltipElement(doc, [{ tag: "strong", text: inertCity }, " · ok"]);
  assert.equal(tipNode.textContent, `${inertCity} · ok`);
  assert.deepEqual(Array.from(new Set(collectTags(tipNode))).sort(), ["span", "strong"]);
});

test("index.html displays the prominent network-conditions disclaimer next to the live probe button without mentioning hardware attestations", () => {
  const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
  const probeIdx = html.indexOf('id="btn-probe-live"');
  const discMatch = html.match(/<div id="network-disclaimer"[^>]*>([\s\S]*?)<\/div>/);
  assert.ok(probeIdx > 0, "btn-probe-live must exist");
  assert.ok(discMatch, "network-disclaimer element must exist");
  assert.ok(discMatch.index > probeIdx && discMatch.index - probeIdx < 600, "network-disclaimer must appear right next to btn-probe-live");
  const text = discMatch[1].replace(/\s+/g, " ").trim();
  assert.equal(
    text,
    "This test is designed for high-speed datacenter connections, not home or mobile networks. Mobile connections in particular can be slow and noisy, making location estimates unreliable."
  );
  assert.equal(/attest|hardware|tee|enclave/i.test(text), false, "network-disclaimer must stay strictly about network conditions");
});

test("staged Honolulu two-provider diagnostic anchors carry distinct failure domains/ASNs and never enter production hardware counts", () => {
  const officialJson = JSON.parse(readFileSync(new URL("./data/anchors.json", import.meta.url), "utf8"));
  const hnlPatch = JSON.parse(readFileSync(new URL("../config/honolulu_diagnostic_patch.json", import.meta.url), "utf8"));
  assert.equal(hnlPatch.candidate_anchors.length, 2);

  // Merge strictly in-memory (live official anchors.json remains 49 nodes untouched!)
  const combinedPayload = {
    ...officialJson,
    anchors: [
      ...officialJson.anchors,
      ...hnlPatch.candidate_anchors.map((c) => ({
        id: c.anchor_id,
        slug: c.slug,
        city: c.city,
        cloud: c.cloud_provider,
        region: c.region,
        lat: c.location.lat,
        lon: c.location.lon,
        defaultTee: c.tee_vendor,
        https_url: c.https_url,
        failure_domain: c.failure_domain,
        asn: c.asn,
        diagnostic_only: c.diagnostic_only,
      })),
    ],
  };

  const store = PogConstellation.createConstellationStore(combinedPayload, {
    pageOrigin: "https://proofofgeography.com",
  });
  const active = store.getActive();
  assert.equal(active.anchors.length, 51);
  const awsHnl = active.anchors.find((a) => a.id === "aws-us-west-2-hnl-honolulu");
  const vultrHnl = active.anchors.find((a) => a.id === "vultr-hnl-honolulu");
  assert.ok(awsHnl && vultrHnl);
  assert.equal(awsHnl.asn, 16509);
  assert.equal(vultrHnl.asn, 20473);
  assert.notEqual(awsHnl.failure_domain, vultrHnl.failure_domain);
  assert.equal(awsHnl.diagnostic_only, true);
  assert.equal(vultrHnl.diagnostic_only, true);

  // Even if a live /info endpoint erroneously claimed a hardware vendor string, diagnostic_only=true MUST keep HW & prod counts at 0!
  store.recordLiveInfo("aws-us-west-2-hnl-honolulu", { tee_vendor: "AwsNitro", public_key_hex: "11".repeat(32) });
  store.recordLiveInfo("vultr-hnl-honolulu", { tee_vendor: "AmdSevSnp", public_key_hex: "22".repeat(32) });
  const audit = store.getActiveAudit(null);
  assert.equal(audit.configured, 51);
  assert.equal(audit.reachable, 2);
  assert.equal(audit.hwTee, 0);
  assert.equal(audit.officialHwTee, 0);
  assert.equal(audit.officialProofEligible, 0);
});
