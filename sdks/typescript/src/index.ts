import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";

export const EARTH_RADIUS_KM = 6371.0088;
export const WGS84_MIN_CURVATURE_RADIUS_KM = 6335.439327;
export const HALF_CIRCUMFERENCE_KM = Math.PI * EARTH_RADIUS_KM;
export const C_VACUUM_KM_PER_S = 299792.458;
export const C_FIBER_KM_PER_S = 204000.0;
export const HTTP_HEADER_POG_PROOF = "X-PoG-Proof";

export interface LatLon {
  lat: number;
  lon: number;
}

export interface CoordinateBasis {
  source: string;
  uncertainty_km: number;
  audited_at_unix_s?: number | null;
  hardware_identity_proves_coordinates?: boolean;
  audit_note?: string | null;
}

export interface AnchorDescriptor {
  anchor_id: string;
  cloud_provider: string;
  region: string;
  city: string;
  tee_vendor?: "AmdSevSnp" | "IntelTdx" | "AwsNitro" | "SoftwareDev";
  location: LatLon;
  endpoint_tcp?: string;
  public_key_hex: string;
  coordinate_basis?: CoordinateBasis | null;
}

export interface AnchorGrid {
  version: string;
  grid_name: string;
  anchors: AnchorDescriptor[];
}

export interface SignedNetworkRegistry {
  version: number;
  network_id: string;
  operator_name: string;
  root_public_key_hex: string;
  issued_at_unix_s: number;
  expires_at_unix_s: number;
  grid: AnchorGrid;
  operator_signature_hex: string;
}

export interface AnchorEndorsement {
  network_id: string;
  anchor_id: string;
  anchor_public_key_hex: string;
  lat: number;
  lon: number;
  issued_at_unix_s: number;
  expires_at_unix_s: number;
  root_public_key_hex: string;
  root_signature_hex: string;
}

export interface TrustedNetwork {
  networkId: string;
  pinnedRootPublicKeyHex: string;
  signedRegistry: SignedNetworkRegistry;
}

export interface NetworkSource {
  networkId: string;
  registryUrl: string;
  pinnedRootPublicKeyHex: string;
}

export interface AnchorObservedIp {
  anchorId: string;
  cloudProvider: string;
  observedIp: string;
  rttMinUs: number;
}

export interface UnverifiedReceipt {
  anchorId: string;
  reason: string;
}

export interface TeeAttestationQuote {
  vendor: "AmdSevSnp" | "IntelTdx" | "AwsNitro" | "SoftwareDev";
  public_key_hex: string;
  workload_measurement_hex: string;
  report_data_hex: string;
  nonce_hex: string;
  migration_disabled: boolean;
  debug_disabled: boolean;
  secure_tsc_enabled: boolean;
  gpu_binding?: {
    gpu_model: string;
    gpu_uuid: string;
    spdm_report_hash_hex: string;
    driver_measurement_hex: string;
  } | null;
  raw_quote_b64: string;
  generated_at_unix_s: number;
}

export interface AnchorReceipt {
  anchor_id: string;
  cloud_provider: string;
  prover_pk_hex: string;
  workload_measurement_hex: string;
  epoch_challenge_hex: string;
  prover_observed_ip: string;
  rtt_min_us: number;
  rtt_p50_us: number;
  rtt_samples_us: number[];
  measured_at_unix_s: number;
  anchor_signature_hex: string;
}

export interface GeoProofBundle {
  version: number;
  epoch_challenge_hex: string;
  client_nonce_hex?: string | null;
  target_location: LatLon;
  required_radius_km: number;
  prover_quote: TeeAttestationQuote;
  receipts: AnchorReceipt[];
  calibrated_velocity_km_per_s?: number | null;
  prev_chain_hash_hex?: string | null;
  chain_seq: number;
  created_at_unix_s: number;
}

export interface VerificationPolicy {
  allowSoftwareDev?: boolean;
  maxByzantine?: number;
  minAnchors?: number;
  minCloudProviders?: number;
  maxProofAgeSeconds?: number;
  maxFutureSkewSeconds?: number;
  enforceTier?: "vacuum" | "fiber" | "calibrated";
  clockResolutionUs?: number;
  clockSlewPpm?: number;
  anchorLocationUncertaintyKm?: number;
  accountForChord?: boolean;
  accountForWgs84Ellipsoid?: boolean;
}

export interface CoreResult {
  provenMaxRadiusKm: number;
  provenMaxRadiusMiles: number;
  containedWithinTarget: boolean;
  witnessCentroid: LatLon;
  wholeEarth: boolean;
  feasible: boolean;
}

export interface VerificationReport {
  overallValid: boolean;
  proofStatus:
    | "verified"
    | "insufficient_verified_anchors"
    | "no_verified_constraint"
    | "containment_failed"
    | "inconsistent_measurements"
    | "policy_rejected";
  hardwareAttested: boolean;
  failureReasons: string[];
  unverifiedReceipts: UnverifiedReceipt[];
  distinctClouds: number;
  verifiedReceipts: number;
  proverPublicKeyHex: string;
  workloadMeasurementHex: string;
  hasGpuBinding: boolean;
  observedProverIps: AnchorObservedIp[];
  distinctObservedIps: string[];
  ipViewConsistent: boolean;
  tier1aVacuum: CoreResult;
  tier1bFiber: CoreResult;
  tier2Calibrated: CoreResult;
}

export interface FederatedVerificationReport {
  overallValid: boolean;
  requiredIndependentNetworks: number;
  validIndependentNetworks: number;
  distinctOperatorsVerified: string[];
  proverPkConsistentAcrossNetworks: boolean;
  observedProverIpsAcrossNetworks: string[];
  ipConsistentAcrossNetworks: boolean;
  consensusTier1aVacuumKm: number | null;
  consensusTier1bFiberKm: number | null;
  consensusTier2CalibratedKm: number | null;
  failureReasons: string[];
  perNetwork: Array<{
    networkId: string;
    operatorName: string;
    registrySignatureValid: boolean;
    proofValid: boolean;
    report?: VerificationReport;
    error?: string;
  }>;
}

type Vec3 = [number, number, number];

function toUnitVec(p: LatLon): Vec3 {
  const lat = (p.lat * Math.PI) / 180;
  const lon = (p.lon * Math.PI) / 180;
  const c = Math.cos(lat);
  return [c * Math.cos(lon), c * Math.sin(lon), Math.sin(lat)];
}

function toLatLon(v: Vec3): LatLon {
  const n = norm(v) || 1;
  const x = v[0] / n, y = v[1] / n, z = v[2] / n;
  return {
    lat: (Math.asin(Math.max(-1, Math.min(1, z))) * 180) / Math.PI,
    lon: (Math.atan2(y, x) * 180) / Math.PI,
  };
}

const dot = (a: Vec3, b: Vec3) => a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
const cross = (a: Vec3, b: Vec3): Vec3 => [
  a[1] * b[2] - a[2] * b[1],
  a[2] * b[0] - a[0] * b[2],
  a[0] * b[1] - a[1] * b[0],
];
const scale = (a: Vec3, s: number): Vec3 => [a[0] * s, a[1] * s, a[2] * s];
const add = (a: Vec3, b: Vec3): Vec3 => [a[0] + b[0], a[1] + b[1], a[2] + b[2]];
const sub = (a: Vec3, b: Vec3): Vec3 => [a[0] - b[0], a[1] - b[1], a[2] - b[2]];
const norm = (a: Vec3) => Math.sqrt(dot(a, a));
const normalize = (a: Vec3): Vec3 | null => {
  const n = norm(a);
  return n < 1e-15 ? null : scale(a, 1 / n);
};

function geodesicKm(a: Vec3, b: Vec3): number {
  return Math.acos(Math.max(-1, Math.min(1, dot(a, b)))) * EARTH_RADIUS_KM;
}

function anyOrthogonal(u: Vec3): Vec3 {
  const basis: Vec3 = Math.abs(u[0]) < 0.9 ? [1, 0, 0] : [0, 1, 0];
  return normalize(cross(u, basis)) ?? [0, 0, 1];
}

export function effectiveOuterRadiusKm(
  rttUs: number,
  tier: "vacuum" | "fiber" | "calibrated",
  policy: VerificationPolicy = {},
  anchorUncOverrideKm?: number | null,
  calVelocityKmPerS = 152000.0
): number {
  const clockResUs = policy.clockResolutionUs ?? 50;
  const slewPpm = policy.clockSlewPpm ?? 500;
  const uncKm = Math.max(policy.anchorLocationUncertaintyKm ?? 35.0, Math.max(0, anchorUncOverrideKm ?? 0));
  const useChord = policy.accountForChord ?? true;
  const useWgs84 = policy.accountForWgs84Ellipsoid ?? true;

  if (tier === "vacuum") {
    const tUpperS = (Math.max(0, rttUs) + Math.max(0, clockResUs)) * (1 + slewPpm * 1e-6) * 1e-6;
    const oneWayKm = 0.5 * C_VACUUM_KM_PER_S * tUpperS;
    const refR = useChord || useWgs84 ? WGS84_MIN_CURVATURE_RADIUS_KM : EARTH_RADIUS_KM;
    const propAng = useChord
      ? oneWayKm / (2 * refR) >= 1
        ? Math.PI
        : 2 * Math.asin(oneWayKm / (2 * refR))
      : Math.min(Math.PI, oneWayKm / refR);
    return Math.min(Math.PI, propAng + uncKm / refR) * EARTH_RADIUS_KM;
  }
  if (tier === "fiber") {
    const tUpperS = (Math.max(0, rttUs) + Math.max(0, clockResUs)) * (1 + slewPpm * 1e-6) * 1e-6;
    const oneWayKm = 0.5 * C_FIBER_KM_PER_S * tUpperS;
    const refR = useWgs84 ? WGS84_MIN_CURVATURE_RADIUS_KM : EARTH_RADIUS_KM;
    return Math.min(Math.PI, (oneWayKm + uncKm) / refR) * EARTH_RADIUS_KM;
  }
  const adjUs = Math.max(0, rttUs - 350);
  const v = Math.max(50000, Math.min(C_VACUUM_KM_PER_S, calVelocityKmPerS));
  return Math.min(HALF_CIRCUMFERENCE_KM, 0.5 * v * adjUs * 1e-6);
}

function intersectTwoCircles(u1: Vec3, c1: number, u2: Vec3, c2: number): Vec3[] {
  const n = cross(u1, u2);
  const nSq = dot(n, n);
  if (nSq < 1e-24) return [];
  const d = dot(u1, u2);
  const a = (c1 - c2 * d) / nSq;
  const b = (c2 - c1 * d) / nSq;
  const p = add(scale(u1, a), scale(u2, b));
  const pSq = dot(p, p);
  if (pSq > 1 + 1e-11) return [];
  const t = Math.sqrt(Math.max(0, 1 - pSq) / nSq);
  if (t < 1e-12) {
    const u = normalize(p);
    return u ? [u] : [];
  }
  const out: Vec3[] = [];
  const x1 = normalize(add(p, scale(n, t)));
  const x2 = normalize(sub(p, scale(n, t)));
  if (x1) out.push(x1);
  if (x2) out.push(x2);
  return out;
}

function furthestPointsOnCircle(u: Vec3, theta: number, target: Vec3): Vec3[] {
  if (theta >= Math.PI - 1e-12) return [scale(target, -1)];
  if (theta <= 1e-12) return [u];
  const negT = scale(target, -1);
  const proj = sub(negT, scale(u, dot(negT, u)));
  const dir = normalize(proj);
  if (dir) {
    return [normalize(add(scale(u, Math.cos(theta)), scale(dir, Math.sin(theta)))) ?? u];
  }
  const e1 = anyOrthogonal(u);
  const e2 = normalize(cross(u, e1)) ?? e1;
  return [e1, scale(e1, -1), e2, scale(e2, -1)].map(
    (dv) => normalize(add(scale(u, Math.cos(theta)), scale(dv, Math.sin(theta)))) ?? u
  );
}

interface Disk {
  u: Vec3;
  theta: number;
  cosTheta: number;
}

function isWholeEarthCore(disks: Disk[], f: number): boolean {
  const exclReq = f + 1;
  const strictEps = 1e-11;
  const comp = disks
    .filter((d) => d.theta < Math.PI - 1e-12)
    .map((d) => {
      const cth = Math.PI - d.theta;
      return { cu: scale(d.u, -1), cosCth: Math.cos(cth) };
    });
  if (comp.length < exclReq) return true;
  const countExcl = (x: Vec3) => comp.filter((c) => dot(c.cu, x) > c.cosCth + strictEps).length;
  for (const c of comp) {
    if (countExcl(c.cu) >= exclReq) return false;
  }
  for (let i = 0; i < comp.length; i++) {
    for (let j = i + 1; j < comp.length; j++) {
      const mid = normalize(add(comp[i].cu, comp[j].cu));
      if (mid && countExcl(mid) >= exclReq) return false;
      for (const pt of intersectTwoCircles(comp[i].cu, comp[i].cosCth, comp[j].cu, comp[j].cosCth)) {
        const inward = normalize(add(comp[i].cu, comp[j].cu));
        if (inward) {
          const nudged = normalize(add(pt, scale(inward, 1e-7)));
          if (nudged && countExcl(nudged) >= exclReq) return false;
        }
      }
    }
  }
  return true;
}

export function solveByzantineCoreFromDisks(
  disks: Array<{ lat: number; lon: number; radiusKm: number }>,
  maxByzantine: number,
  target: LatLon,
  requiredRadiusKm: number
): CoreResult {
  const internal: Disk[] = disks.map((d) => {
    const th = Math.min(Math.PI, Math.max(0, d.radiusKm / EARTH_RADIUS_KM));
    return { u: toUnitVec({ lat: d.lat, lon: d.lon }), theta: th, cosTheta: Math.cos(th) };
  });
  return solveByzantineCore(internal, maxByzantine, target, requiredRadiusKm);
}

function solveByzantineCore(
  disks: Disk[],
  maxByzantine: number,
  target: LatLon,
  requiredRadiusKm: number
): CoreResult {
  const k = disks.length;
  if (k === 0) {
    return {
      provenMaxRadiusKm: Number.POSITIVE_INFINITY,
      provenMaxRadiusMiles: Number.POSITIVE_INFINITY,
      containedWithinTarget: false,
      witnessCentroid: target,
      wholeEarth: false,
      feasible: false,
    };
  }
  const f = Math.min(maxByzantine, Math.max(0, k - 1));
  const req = k - f;
  const eps = 1e-9;
  const targetU = toUnitVec(target);
  const wholeEarth = isWholeEarthCore(disks, f);
  const countIn = (x: Vec3) => disks.filter((d) => dot(d.u, x) >= d.cosTheta - eps).length;

  const pts: Vec3[] = [];
  for (let i = 0; i < k; i++) {
    for (let j = i + 1; j < k; j++) {
      for (const p of intersectTwoCircles(disks[i].u, disks[i].cosTheta, disks[j].u, disks[j].cosTheta)) {
        if (countIn(p) >= req) pts.push(p);
      }
    }
  }
  for (let i = 0; i < k; i++) {
    for (const far of furthestPointsOnCircle(disks[i].u, disks[i].theta, targetU)) {
      if (countIn(far) >= req) pts.push(far);
    }
  }
  const antipode = scale(targetU, -1);
  if (countIn(antipode) >= req) pts.push(antipode);

  const interiorCands: Vec3[] = [targetU, ...disks.map((d) => d.u)];
  if (pts.length > 0) {
    let s: Vec3 = [0, 0, 0];
    for (const p of pts) s = add(s, p);
    const avg = normalize(s);
    if (avg) interiorCands.push(avg);
  }
  const witnessU = interiorCands.find((c) => countIn(c) >= req) ?? pts[0] ?? null;
  if (!witnessU) {
    return {
      provenMaxRadiusKm: Number.POSITIVE_INFINITY,
      provenMaxRadiusMiles: Number.POSITIVE_INFINITY,
      containedWithinTarget: false,
      witnessCentroid: target,
      wholeEarth: false,
      feasible: false,
    };
  }
  if (pts.length === 0) {
    pts.push(wholeEarth || countIn(antipode) >= req ? antipode : witnessU);
  }

  let worstKm = wholeEarth ? HALF_CIRCUMFERENCE_KM : 0;
  let sum: Vec3 = [0, 0, 0];
  for (const p of pts) {
    worstKm = Math.max(worstKm, geodesicKm(targetU, p));
    sum = add(sum, p);
  }
  let centU = normalize(sum);
  if (!centU || countIn(centU) < req) centU = witnessU;
  return {
    provenMaxRadiusKm: worstKm,
    provenMaxRadiusMiles: worstKm * 0.621371,
    containedWithinTarget: worstKm <= requiredRadiusKm,
    witnessCentroid: toLatLon(centU),
    wholeEarth,
    feasible: true,
  };
}

function u64LE(n: number): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n));
  return b;
}

function u32LE(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return b;
}

export function receiptSigningDigest(r: AnchorReceipt): Buffer {
  const h = createHash("sha256");
  h.update("pog-anchor-receipt-v1");
  h.update(r.anchor_id);
  h.update("|");
  h.update(r.cloud_provider);
  h.update("|");
  h.update(r.prover_pk_hex);
  h.update("|");
  h.update(r.workload_measurement_hex);
  h.update("|");
  h.update(r.epoch_challenge_hex);
  h.update("|");
  h.update(r.prover_observed_ip);
  h.update("|");
  h.update(u64LE(r.rtt_min_us));
  h.update(u64LE(r.rtt_p50_us));
  h.update(u32LE(r.rtt_samples_us.length));
  for (const s of r.rtt_samples_us) h.update(u64LE(s));
  h.update(u64LE(r.measured_at_unix_s));
  return h.digest();
}

function verifyEd25519(pubkeyHex: string, message: Buffer, sigHex: string): boolean {
  const rawPub = Buffer.from(pubkeyHex, "hex");
  const sig = Buffer.from(sigHex, "hex");
  if (rawPub.length !== 32 || sig.length !== 64) return false;
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const keyObj = createPublicKey({
    key: Buffer.concat([spkiPrefix, rawPub]),
    format: "der",
    type: "spki",
  });
  return cryptoVerify(null, message, keyObj, sig);
}

export function decodeProofHeader(headerValue: string): GeoProofBundle {
  const raw = Buffer.from(headerValue.trim(), "base64url").toString("utf8");
  return JSON.parse(raw) as GeoProofBundle;
}

export function verifyProof(
  bundleOrHeader: GeoProofBundle | string,
  grid: AnchorGrid,
  policy: VerificationPolicy = {},
  nowUnixS: number = Math.floor(Date.now() / 1000)
): VerificationReport {
  const bundle = typeof bundleOrHeader === "string" ? decodeProofHeader(bundleOrHeader) : bundleOrHeader;
  const allowDev = policy.allowSoftwareDev ?? false;
  const maxByzantine = policy.maxByzantine ?? 1;
  const minAnchors = policy.minAnchors ?? 4;
  const minClouds = policy.minCloudProviders ?? 2;
  const maxAge = policy.maxProofAgeSeconds ?? 3900;
  const maxSkew = policy.maxFutureSkewSeconds ?? 300;
  const enforceTier = policy.enforceTier ?? "vacuum";

  const failures: string[] = [];
  const unverifiedReceipts: UnverifiedReceipt[] = [];
  if (nowUnixS > bundle.created_at_unix_s + maxAge) {
    failures.push(`Proof expired (${nowUnixS - bundle.created_at_unix_s}s > ${maxAge}s)`);
  }
  if (bundle.created_at_unix_s > nowUnixS + maxSkew) {
    failures.push("Proof timestamp in future");
  }

  const q = bundle.prover_quote;
  const proverIsHw = q.vendor !== "SoftwareDev";
  if (!proverIsHw && !allowDev) {
    failures.push("SoftwareDev TEE quotes rejected under production policy");
  }
  if (!q.migration_disabled) failures.push("TEE MIGRATE_MA not disabled");
  if (!q.debug_disabled) failures.push("TEE debug mode not disabled");

  const rdHash = createHash("sha512");
  rdHash.update("pog-tee-bind-v1");
  rdHash.update(Buffer.from(q.public_key_hex, "hex"));
  rdHash.update(Buffer.from(bundle.epoch_challenge_hex, "hex"));
  if (q.gpu_binding) {
    rdHash.update(q.gpu_binding.gpu_uuid);
    rdHash.update(q.gpu_binding.spdm_report_hash_hex);
  }
  if (rdHash.digest("hex") !== q.report_data_hex) {
    failures.push("TEE report_data binding mismatch");
  }

  const anchorMap = new Map(grid.anchors.map((a) => [a.anchor_id, a]));
  const seenAnchors = new Set<string>();
  const seenClouds = new Set<string>();
  const observedProverIps: AnchorObservedIp[] = [];
  const distinctIpSet = new Set<string>();
  const vacDisks: Disk[] = [];
  const fibDisks: Disk[] = [];
  const calDisks: Disk[] = [];
  const calV = bundle.calibrated_velocity_km_per_s ?? 152000.0;
  let allAnchorsHw = true;

  for (const r of bundle.receipts) {
    if (seenAnchors.has(r.anchor_id)) {
      const msg = `Duplicate anchor ${r.anchor_id}`;
      unverifiedReceipts.push({ anchorId: r.anchor_id, reason: msg });
      failures.push(msg);
      continue;
    }
    seenAnchors.add(r.anchor_id);
    const a = anchorMap.get(r.anchor_id);
    if (!a) {
      const msg = `Unknown anchor ${r.anchor_id}`;
      unverifiedReceipts.push({ anchorId: r.anchor_id, reason: msg });
      failures.push(msg);
      continue;
    }
    if (a.tee_vendor === "SoftwareDev") {
      allAnchorsHw = false;
      if (!allowDev) {
        const msg = `Anchor ${r.anchor_id} reports SoftwareDev (hardware TEE required)`;
        unverifiedReceipts.push({ anchorId: r.anchor_id, reason: msg });
        failures.push(msg);
        continue;
      }
    }
    const digest = receiptSigningDigest(r);
    if (!verifyEd25519(a.public_key_hex, digest, r.anchor_signature_hex)) {
      const msg = `Invalid Ed25519 signature or published key mismatch from ${r.anchor_id}`;
      unverifiedReceipts.push({ anchorId: r.anchor_id, reason: msg });
      failures.push(msg);
      continue;
    }
    if (r.prover_pk_hex !== q.public_key_hex || r.epoch_challenge_hex !== bundle.epoch_challenge_hex) {
      const msg = `Receipt binding mismatch from ${r.anchor_id}`;
      unverifiedReceipts.push({ anchorId: r.anchor_id, reason: msg });
      failures.push(msg);
      continue;
    }
    if (r.workload_measurement_hex !== q.workload_measurement_hex) {
      const msg = `Receipt workload_measurement_hex mismatch from ${r.anchor_id}`;
      unverifiedReceipts.push({ anchorId: r.anchor_id, reason: msg });
      failures.push(msg);
      continue;
    }
    if (nowUnixS > r.measured_at_unix_s + maxAge || r.measured_at_unix_s > nowUnixS + maxSkew) {
      const msg = `Receipt expired or future-dated from ${r.anchor_id}`;
      unverifiedReceipts.push({ anchorId: r.anchor_id, reason: msg });
      failures.push(msg);
      continue;
    }
    seenClouds.add(a.cloud_provider);
    distinctIpSet.add(r.prover_observed_ip);
    observedProverIps.push({
      anchorId: r.anchor_id,
      cloudProvider: a.cloud_provider,
      observedIp: r.prover_observed_ip,
      rttMinUs: r.rtt_min_us,
    });
    const u = toUnitVec(a.location);
    const ancUnc = a.coordinate_basis?.uncertainty_km;
    const mkDisk = (rKm: number): Disk => {
      const th = Math.min(Math.PI, Math.max(0, rKm / EARTH_RADIUS_KM));
      return { u, theta: th, cosTheta: Math.cos(th) };
    };
    vacDisks.push(mkDisk(effectiveOuterRadiusKm(r.rtt_min_us, "vacuum", policy, ancUnc)));
    fibDisks.push(mkDisk(effectiveOuterRadiusKm(r.rtt_min_us, "fiber", policy, ancUnc)));
    calDisks.push(mkDisk(effectiveOuterRadiusKm(r.rtt_min_us, "calibrated", policy, ancUnc, calV)));
  }

  if (vacDisks.length < minAnchors) failures.push(`Insufficient verified anchors: ${vacDisks.length} < ${minAnchors}`);
  if (seenClouds.size < minClouds) failures.push(`Insufficient clouds: ${seenClouds.size} < ${minClouds}`);

  const tier1aVacuum = solveByzantineCore(vacDisks, maxByzantine, bundle.target_location, bundle.required_radius_km);
  const tier1bFiber = solveByzantineCore(fibDisks, maxByzantine, bundle.target_location, bundle.required_radius_km);
  const tier2Calibrated = solveByzantineCore(calDisks, maxByzantine, bundle.target_location, bundle.required_radius_km);

  const enforced =
    enforceTier === "vacuum" ? tier1aVacuum : enforceTier === "fiber" ? tier1bFiber : tier2Calibrated;
  if (vacDisks.length > 0 && !enforced.containedWithinTarget) {
    failures.push(
      `Enforced tier (${enforceTier}) failed: ${enforced.provenMaxRadiusKm.toFixed(1)} km > ${bundle.required_radius_km} km`
    );
  }

  let proofStatus: VerificationReport["proofStatus"] = "verified";
  if (vacDisks.length < minAnchors || seenClouds.size < minClouds) {
    proofStatus = "insufficient_verified_anchors";
  } else if (!tier1aVacuum.feasible) {
    proofStatus = "inconsistent_measurements";
  } else if (tier1aVacuum.wholeEarth && !enforced.containedWithinTarget) {
    proofStatus = "no_verified_constraint";
  } else if (!enforced.containedWithinTarget) {
    proofStatus = "containment_failed";
  } else if (failures.length > 0) {
    proofStatus = "policy_rejected";
  }

  const distinctObservedIps = Array.from(distinctIpSet).sort();
  return {
    overallValid: failures.length === 0,
    proofStatus,
    hardwareAttested: proverIsHw && allAnchorsHw && vacDisks.length > 0,
    failureReasons: failures,
    unverifiedReceipts,
    distinctClouds: seenClouds.size,
    verifiedReceipts: vacDisks.length,
    proverPublicKeyHex: q.public_key_hex,
    workloadMeasurementHex: q.workload_measurement_hex,
    hasGpuBinding: Boolean(q.gpu_binding),
    observedProverIps,
    distinctObservedIps,
    ipViewConsistent: distinctObservedIps.length <= 1,
    tier1aVacuum,
    tier1bFiber,
    tier2Calibrated,
  };
}

export function signedRegistryDigest(reg: SignedNetworkRegistry): Buffer {
  const h = createHash("sha256");
  h.update("POG-NETWORK-REGISTRY-V1\n");
  h.update(`${reg.network_id}\n`);
  h.update(`${reg.operator_name}\n`);
  h.update(`${reg.root_public_key_hex}\n`);
  h.update(`${reg.issued_at_unix_s}\n`);
  h.update(`${reg.expires_at_unix_s}\n`);
  h.update(`${reg.grid.grid_name}\n`);
  const sorted = [...reg.grid.anchors].sort((a, b) =>
    a.anchor_id < b.anchor_id ? -1 : a.anchor_id > b.anchor_id ? 1 : 0
  );
  for (const a of sorted) {
    h.update(
      `${a.anchor_id}|${a.cloud_provider}|${a.region}|${a.location.lat.toFixed(6)}|${a.location.lon.toFixed(6)}|${a.endpoint_tcp ?? ""}|${a.public_key_hex}\n`
    );
  }
  return h.digest();
}

export function anchorEndorsementDigest(cert: AnchorEndorsement): Buffer {
  const h = createHash("sha256");
  h.update(
    `POG-ANCHOR-ENDORSEMENT-V1\n${cert.network_id}\n${cert.anchor_id}\n${cert.anchor_public_key_hex}\n${cert.lat.toFixed(6)}\n${cert.lon.toFixed(6)}\n${cert.issued_at_unix_s}\n${cert.expires_at_unix_s}\n`
  );
  return h.digest();
}

export function verifyAnchorEndorsement(
  cert: AnchorEndorsement,
  pinnedRootPublicKeyHex: string,
  nowUnixS: number = Math.floor(Date.now() / 1000)
): { valid: boolean; error?: string } {
  if (cert.root_public_key_hex.toLowerCase() !== pinnedRootPublicKeyHex.toLowerCase()) {
    return { valid: false, error: `Endorsement root key mismatch for anchor ${cert.anchor_id}` };
  }
  if (nowUnixS > cert.expires_at_unix_s) {
    return { valid: false, error: `Endorsement expired for anchor ${cert.anchor_id}` };
  }
  if (!verifyEd25519(cert.root_public_key_hex, anchorEndorsementDigest(cert), cert.root_signature_hex)) {
    return { valid: false, error: `Invalid operator endorsement signature for anchor ${cert.anchor_id}` };
  }
  return { valid: true };
}

export function verifyAnchorInfoIdentity(
  info: {
    anchor_id: string;
    tee_vendor: string;
    public_key_hex: string;
    operator_endorsement?: AnchorEndorsement | null;
    tee_quote?: { public_key_hex?: string } | null;
  },
  publishedAnchor: AnchorDescriptor,
  pinnedRootPublicKeyHex: string,
  allowSoftwareDev = false,
  nowUnixS: number = Math.floor(Date.now() / 1000)
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (info.anchor_id !== publishedAnchor.anchor_id) errors.push("anchor_id mismatch");
  if (info.public_key_hex.toLowerCase() !== publishedAnchor.public_key_hex.toLowerCase()) {
    errors.push("live public_key_hex does not match published registry key");
  }
  if (info.tee_vendor === "SoftwareDev" && !allowSoftwareDev) {
    errors.push("live anchor reports SoftwareDev (hardware TEE required)");
  }
  if (!info.operator_endorsement) {
    errors.push("missing operator_endorsement");
  } else {
    if (info.operator_endorsement.anchor_id !== publishedAnchor.anchor_id) {
      errors.push("endorsement anchor_id mismatch");
    }
    if (info.operator_endorsement.anchor_public_key_hex.toLowerCase() !== info.public_key_hex.toLowerCase()) {
      errors.push("stale endorsement: anchor_public_key_hex != live public_key_hex");
    }
    const chk = verifyAnchorEndorsement(info.operator_endorsement, pinnedRootPublicKeyHex, nowUnixS);
    if (!chk.valid) errors.push(chk.error ?? "invalid endorsement");
  }
  if (!info.tee_quote) {
    errors.push("missing tee_quote");
  } else if ((info.tee_quote.public_key_hex ?? "").toLowerCase() !== info.public_key_hex.toLowerCase()) {
    errors.push("tee_quote.public_key_hex != live public_key_hex");
  }
  return { valid: errors.length === 0, errors };
}

export function validateProductionRegistry(reg: SignedNetworkRegistry): { valid: boolean; errors: string[] } {
  const dev = reg.grid.anchors.filter((a) => a.tee_vendor === "SoftwareDev").map((a) => a.anchor_id);
  if (dev.length > 0) {
    return { valid: false, errors: [`production registry contains SoftwareDev anchors: ${dev.join(", ")}`] };
  }
  return { valid: true, errors: [] };
}

export function verifySignedRegistry(
  reg: SignedNetworkRegistry,
  pinnedRootPublicKeyHex?: string,
  nowUnixS: number = Math.floor(Date.now() / 1000)
): { valid: boolean; error?: string } {
  if (pinnedRootPublicKeyHex && reg.root_public_key_hex.toLowerCase() !== pinnedRootPublicKeyHex.toLowerCase()) {
    return { valid: false, error: `Root public key mismatch for network ${reg.network_id}` };
  }
  if (nowUnixS > reg.expires_at_unix_s) {
    return { valid: false, error: `Signed registry expired for network ${reg.network_id}` };
  }
  const digest = signedRegistryDigest(reg);
  if (!verifyEd25519(reg.root_public_key_hex, digest, reg.operator_signature_hex)) {
    return { valid: false, error: `Invalid operator Ed25519 signature on network ${reg.network_id}` };
  }
  return { valid: true };
}

export async function fetchSignedRegistry(
  registryUrl: string,
  pinnedRootPublicKeyHex?: string,
  nowUnixS: number = Math.floor(Date.now() / 1000)
): Promise<SignedNetworkRegistry> {
  const resp = await fetch(registryUrl);
  if (!resp.ok) {
    throw new Error(`Failed to fetch signed registry from ${registryUrl}: HTTP ${resp.status}`);
  }
  const reg = (await resp.json()) as SignedNetworkRegistry;
  const check = verifySignedRegistry(reg, pinnedRootPublicKeyHex, nowUnixS);
  if (!check.valid) {
    throw new Error(check.error ?? "Invalid signed network registry");
  }
  return reg;
}

export async function queryFederatedNetworks(
  sources: NetworkSource[],
  submissions: Array<{ networkId: string; bundleOrHeader: GeoProofBundle | string }>,
  options: {
    minIndependentNetworks?: number;
    policy?: VerificationPolicy;
    nowUnixS?: number;
  } = {}
): Promise<FederatedVerificationReport> {
  const nowUnixS = options.nowUnixS ?? Math.floor(Date.now() / 1000);
  const trusted: TrustedNetwork[] = [];
  await Promise.all(
    sources.map(async (src) => {
      try {
        const signedRegistry = await fetchSignedRegistry(
          src.registryUrl,
          src.pinnedRootPublicKeyHex,
          nowUnixS
        );
        trusted.push({
          networkId: src.networkId,
          pinnedRootPublicKeyHex: src.pinnedRootPublicKeyHex,
          signedRegistry,
        });
      } catch {
        // Unreachable or tampered network fails to join verified quorum.
      }
    })
  );
  return verifyFederatedProof(submissions, trusted, options);
}

export function verifyFederatedProof(
  submissions: Array<{ networkId: string; bundleOrHeader: GeoProofBundle | string }>,
  trustedNetworks: TrustedNetwork[],
  options: {
    minIndependentNetworks?: number;
    policy?: VerificationPolicy;
    nowUnixS?: number;
  } = {}
): FederatedVerificationReport {
  const minNets = options.minIndependentNetworks ?? 2;
  const policy = options.policy ?? {};
  const nowUnixS = options.nowUnixS ?? Math.floor(Date.now() / 1000);
  const netById = new Map(trustedNetworks.map((n) => [n.networkId, n]));
  const seenNetIds = new Set<string>();
  const seenRootKeys = new Set<string>();
  const distinctOperators: string[] = [];
  const proverPks = new Set<string>();
  const allIps = new Set<string>();
  const failureReasons: string[] = [];
  const perNetwork: FederatedVerificationReport["perNetwork"] = [];

  let minVac: number | null = null;
  let minFib: number | null = null;
  let minCal: number | null = null;

  for (const sub of submissions) {
    if (seenNetIds.has(sub.networkId)) {
      failureReasons.push(`Duplicate network submission: ${sub.networkId}`);
      continue;
    }
    seenNetIds.add(sub.networkId);
    const net = netById.get(sub.networkId);
    if (!net) {
      perNetwork.push({
        networkId: sub.networkId,
        operatorName: "unknown",
        registrySignatureValid: false,
        proofValid: false,
        error: "Untrusted networkId",
      });
      continue;
    }
    const rootNorm = net.pinnedRootPublicKeyHex.toLowerCase();
    if (seenRootKeys.has(rootNorm)) {
      failureReasons.push(`Network ${sub.networkId} shares root key with another network (not independent)`);
      continue;
    }
    seenRootKeys.add(rootNorm);

    const regCheck = verifySignedRegistry(net.signedRegistry, net.pinnedRootPublicKeyHex, nowUnixS);
    if (!regCheck.valid) {
      perNetwork.push({
        networkId: sub.networkId,
        operatorName: net.signedRegistry.operator_name,
        registrySignatureValid: false,
        proofValid: false,
        error: regCheck.error,
      });
      continue;
    }

    const report = verifyProof(sub.bundleOrHeader, net.signedRegistry.grid, policy, nowUnixS);
    if (report.overallValid) {
      distinctOperators.push(net.signedRegistry.operator_name);
      proverPks.add(report.proverPublicKeyHex);
      for (const ip of report.distinctObservedIps) allIps.add(ip);
      minVac = minVac === null ? report.tier1aVacuum.provenMaxRadiusKm : Math.min(minVac, report.tier1aVacuum.provenMaxRadiusKm);
      minFib = minFib === null ? report.tier1bFiber.provenMaxRadiusKm : Math.min(minFib, report.tier1bFiber.provenMaxRadiusKm);
      if (report.tier2Calibrated.feasible) {
        minCal = minCal === null ? report.tier2Calibrated.provenMaxRadiusKm : Math.min(minCal, report.tier2Calibrated.provenMaxRadiusKm);
      }
    }
    perNetwork.push({
      networkId: sub.networkId,
      operatorName: net.signedRegistry.operator_name,
      registrySignatureValid: true,
      proofValid: report.overallValid,
      report,
    });
  }

  const proverPkConsistent = proverPks.size <= 1;
  const ipConsistent = allIps.size <= 1;
  if (distinctOperators.length < minNets) {
    failureReasons.push(`Insufficient independent networks verified: ${distinctOperators.length} < ${minNets}`);
  }
  if (!proverPkConsistent) {
    failureReasons.push("Prover TEE public key mismatch across independent networks");
  }

  return {
    overallValid: failureReasons.length === 0 && distinctOperators.length >= minNets,
    requiredIndependentNetworks: minNets,
    validIndependentNetworks: distinctOperators.length,
    distinctOperatorsVerified: distinctOperators,
    proverPkConsistentAcrossNetworks: proverPkConsistent,
    observedProverIpsAcrossNetworks: Array.from(allIps).sort(),
    ipConsistentAcrossNetworks: ipConsistent,
    consensusTier1aVacuumKm: minVac,
    consensusTier1bFiberKm: minFib,
    consensusTier2CalibratedKm: minCal,
    failureReasons,
    perNetwork,
  };
}

export interface LikelihoodObservation {
  anchorId: string;
  lat: number;
  lon: number;
  rttMs: number;
  rttMinMs?: number;
  jitterMs?: number;
  anchorUncertaintyKm?: number;
}

export interface SpatialLikelihoodConfig {
  t0Ms?: number;
  v0KmMs?: number;
  v1KmMs?: number;
  dKneeKm?: number;
  sigmaBaseMs?: number;
  sigmaRel?: number;
  sigmaJit?: number;
  rho?: number;
  lCorrKm?: number;
  asymSlow?: number;
  studentTNu?: number | null;
  tauMoreLikely?: number;
  tauPlausible?: number;
  gridPoints?: number;
  peakSeparationKm?: number;
  vacuumByzantineF?: number;
}

export interface LikelihoodPeak {
  lat: number;
  lon: number;
  deltaNll: number;
  relativeLikelihood: number;
  qualitativeBand: "more_likely" | "plausible" | "less_likely";
}

export interface SpatialLikelihoodSurface {
  isEmpiricalEstimate: boolean;
  isHardProof: boolean;
  qualitativeScale: "more_likely_to_less_likely";
  effectiveIndependentAnchors: number;
  anchorCount: number;
  peaks: LikelihoodPeak[];
  moreLikelyAreaKm2: number;
  moreLikelyAreaFraction: number;
  plausibleAreaKm2: number;
  plausibleAreaFraction: number;
  vacuumOuterAreaKm2: number;
  vacuumOuterAreaFraction: number;
}

function choleskyLower(mat: number[][]): number[][] {
  const n = mat.length;
  const L: number[][] = Array.from({ length: n }, () => new Array(n).fill(0));
  for (let i = 0; i < n; i++) {
    for (let j = 0; j <= i; j++) {
      let s = 0;
      for (let k = 0; k < j; k++) s += L[i][k] * L[j][k];
      L[i][j] = i === j ? Math.sqrt(Math.max(1e-12, mat[i][i] - s)) : (mat[i][j] - s) / L[j][j];
    }
  }
  return L;
}

function solveLower(L: number[][], b: number[]): number[] {
  const n = b.length;
  const y = new Array<number>(n).fill(0);
  for (let i = 0; i < n; i++) {
    let s = b[i];
    const row = L[i];
    for (let k = 0; k < i; k++) s -= row[k] * y[k];
    y[i] = s / row[i];
  }
  return y;
}

export function computeSpatialLikelihood(
  observations: LikelihoodObservation[],
  config: SpatialLikelihoodConfig = {},
  policy: VerificationPolicy = {}
): SpatialLikelihoodSurface {
  const earthKm2 = 4 * Math.PI * EARTH_RADIUS_KM * EARTH_RADIUS_KM;
  if (observations.length === 0) {
    return {
      isEmpiricalEstimate: true,
      isHardProof: false,
      qualitativeScale: "more_likely_to_less_likely",
      effectiveIndependentAnchors: 0,
      anchorCount: 0,
      peaks: [],
      moreLikelyAreaKm2: earthKm2,
      moreLikelyAreaFraction: 1,
      plausibleAreaKm2: earthKm2,
      plausibleAreaFraction: 1,
      vacuumOuterAreaKm2: earthKm2,
      vacuumOuterAreaFraction: 1,
    };
  }
  const t0 = config.t0Ms ?? 2.0;
  const v0 = config.v0KmMs ?? 80.0;
  const v1 = config.v1KmMs ?? 143.0;
  const dKnee = config.dKneeKm ?? 3500.0;
  const sBase = config.sigmaBaseMs ?? 1.837;
  const sRel = config.sigmaRel ?? 0.1267;
  const sJit = config.sigmaJit ?? 1.5;
  const rho = Math.max(0, Math.min(0.99, config.rho ?? 0.85));
  const lCorr = Math.max(1, config.lCorrKm ?? 2200.0);
  const asym = config.asymSlow ?? 1.65;
  const nu = config.studentTNu === undefined ? 4.0 : config.studentTNu;
  const tauMl = config.tauMoreLikely ?? 1.752;
  const tauPl = config.tauPlausible ?? 3.911;
  const nPts = Math.max(64, config.gridPoints ?? 2000);
  const sepKm = config.peakSeparationKm ?? 700.0;
  const vacF = config.vacuumByzantineF ?? 0;

  const k = observations.length;
  const units = observations.map((o) => toUnitVec({ lat: o.lat, lon: o.lon }));
  const vacCos = observations.map((o) => {
    const rMin = o.rttMinMs ?? o.rttMs;
    const rKm = effectiveOuterRadiusKm(Math.ceil(Math.max(0, rMin) * 1000), "vacuum", policy, o.anchorUncertaintyKm ?? 35);
    return Math.cos(Math.min(Math.PI, rKm / EARTH_RADIUS_KM));
  });
  const reqVac = Math.max(1, k - vacF);

  const sigmas = observations.map((o) =>
    Math.max(0.25, Math.hypot(sBase, sRel * Math.max(0, o.rttMs), sJit * Math.max(0, o.jitterMs ?? 0)))
  );
  const Sigma: number[][] = Array.from({ length: k }, () => new Array(k).fill(0));
  const Corr: number[][] = Array.from({ length: k }, () => new Array(k).fill(0));
  for (let i = 0; i < k; i++) {
    for (let j = i; j < k; j++) {
      const c = i === j ? 1.0 : rho * Math.exp(-geodesicKm(units[i], units[j]) / lCorr);
      Corr[i][j] = Corr[j][i] = c;
      Sigma[i][j] = Sigma[j][i] = sigmas[i] * sigmas[j] * c;
    }
  }
  const LSig = choleskyLower(Sigma);
  const LCor = choleskyLower(Corr);
  const onesW = solveLower(LCor, new Array(k).fill(1));
  const kEff = onesW.reduce((acc, v) => acc + v * v, 0);

  const evalNll = (pt: Vec3): number => {
    const r = new Array<number>(k);
    for (let i = 0; i < k; i++) {
      const dKm = geodesicKm(pt, units[i]);
      const v = v0 + (v1 - v0) * (1 - Math.exp(-dKm / dKnee));
      const pred = t0 + (2 * dKm) / Math.max(1, v);
      let diff = observations[i].rttMs - pred;
      if (diff > 0 && asym > 1) diff /= asym;
      r[i] = diff;
    }
    const z = solveLower(LSig, r);
    const quad = z.reduce((acc, x) => acc + x * x, 0);
    return nu !== null ? 0.5 * (Math.max(0.5, nu) + kEff) * Math.log(1 + quad / Math.max(0.5, nu)) : 0.5 * quad;
  };

  const ga = Math.PI * (3 - Math.sqrt(5));
  const feasible: Array<{ pt: Vec3; nll: number }> = [];
  let bestNll = Infinity;
  let bestU = units[0];
  for (let i = 0; i < nPts; i++) {
    const y = 1 - (2 * i + 1) / nPts;
    const rr = Math.sqrt(Math.max(0, 1 - y * y));
    const phi = ga * i;
    const pt: Vec3 = [Math.cos(phi) * rr, Math.sin(phi) * rr, y];
    let inCnt = 0;
    for (let j = 0; j < k; j++) if (dot(pt, units[j]) >= vacCos[j] - 1e-12) inCnt++;
    if (inCnt < reqVac) continue;
    const nll = evalNll(pt);
    if (nll < bestNll) {
      bestNll = nll;
      bestU = pt;
    }
    feasible.push({ pt, nll });
  }
  if (feasible.length === 0) {
    return {
      isEmpiricalEstimate: true,
      isHardProof: false,
      qualitativeScale: "more_likely_to_less_likely",
      effectiveIndependentAnchors: kEff,
      anchorCount: k,
      peaks: [],
      moreLikelyAreaKm2: 0,
      moreLikelyAreaFraction: 0,
      plausibleAreaKm2: 0,
      plausibleAreaFraction: 0,
      vacuumOuterAreaKm2: 0,
      vacuumOuterAreaFraction: 0,
    };
  }

  let bestLL = toLatLon(bestU);
  for (const step of [1.5, 0.4, 0.1]) {
    const cLat = bestLL.lat;
    const cLon = bestLL.lon;
    for (let dl = -2; dl <= 2; dl++) {
      for (let dn = -2; dn <= 2; dn++) {
        const lat = Math.max(-89.5, Math.min(89.5, cLat + dl * step));
        const lon = ((((cLon + dn * step) + 180) % 360) + 360) % 360 - 180;
        const cu = toUnitVec({ lat, lon });
        let inCnt = 0;
        for (let j = 0; j < k; j++) if (dot(cu, units[j]) >= vacCos[j] - 1e-12) inCnt++;
        if (inCnt < reqVac) continue;
        const cn = evalNll(cu);
        if (cn < bestNll) {
          bestNll = cn;
          bestLL = { lat, lon };
          bestU = cu;
        }
      }
    }
  }

  const mlPts: Array<{ delta: number; pt: Vec3 }> = [];
  let plCount = 0;
  for (const { pt, nll } of feasible) {
    const delta = Math.max(0, nll - bestNll);
    if (delta <= tauPl) plCount++;
    if (delta <= tauMl) mlPts.push({ delta, pt });
  }
  mlPts.sort((a, b) => a.delta - b.delta);

  const peakUnits: Array<{ delta: number; pt: Vec3 }> = [{ delta: 0, pt: bestU }];
  for (const cand of mlPts) {
    if (peakUnits.every((p) => geodesicKm(cand.pt, p.pt) >= sepKm)) {
      peakUnits.push(cand);
      if (peakUnits.length >= 4) break;
    }
  }

  const peaks: LikelihoodPeak[] = peakUnits.map(({ delta, pt }) => {
    const ll = toLatLon(pt);
    return {
      lat: ll.lat,
      lon: ll.lon,
      deltaNll: delta,
      relativeLikelihood: Math.exp(-delta),
      qualitativeBand: delta <= tauMl ? "more_likely" : "plausible",
    };
  });

  const vacFrac = feasible.length / nPts;
  const mlFrac = Math.max(1, mlPts.length) / nPts;
  const plFrac = Math.max(1, plCount, mlPts.length) / nPts;
  return {
    isEmpiricalEstimate: true,
    isHardProof: false,
    qualitativeScale: "more_likely_to_less_likely",
    effectiveIndependentAnchors: kEff,
    anchorCount: k,
    peaks,
    moreLikelyAreaKm2: mlFrac * earthKm2,
    moreLikelyAreaFraction: mlFrac,
    plausibleAreaKm2: plFrac * earthKm2,
    plausibleAreaFraction: plFrac,
    vacuumOuterAreaKm2: vacFrac * earthKm2,
    vacuumOuterAreaFraction: vacFrac,
  };
}
