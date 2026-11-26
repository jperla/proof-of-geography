import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";

export const EARTH_RADIUS_KM = 6371.0088;
export const C_VACUUM_KM_PER_S = 299792.458;
export const C_FIBER_KM_PER_S = 204000.0;
export const HTTP_HEADER_POG_PROOF = "X-PoG-Proof";

export interface LatLon {
  lat: number;
  lon: number;
}

export interface AnchorDescriptor {
  anchor_id: string;
  cloud_provider: string;
  region: string;
  city: string;
  location: LatLon;
  public_key_hex: string;
}

export interface AnchorGrid {
  version: string;
  grid_name: string;
  anchors: AnchorDescriptor[];
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
  enforceTier?: "vacuum" | "fiber" | "calibrated";
}

export interface CoreResult {
  provenMaxRadiusKm: number;
  provenMaxRadiusMiles: number;
  containedWithinTarget: boolean;
  witnessCentroid: LatLon;
}

export interface VerificationReport {
  overallValid: boolean;
  failureReasons: string[];
  distinctClouds: number;
  verifiedReceipts: number;
  proverPublicKeyHex: string;
  workloadMeasurementHex: string;
  hasGpuBinding: boolean;
  tier1aVacuum: CoreResult;
  tier1bFiber: CoreResult;
  tier2Calibrated: CoreResult;
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

function intersectTwoCircles(u1: Vec3, c1: number, u2: Vec3, c2: number): Vec3[] {
  const d = dot(u1, u2);
  const denom = 1 - d * d;
  if (denom < 1e-12) return [];
  const a = (c1 - c2 * d) / denom;
  const b = (c2 - c1 * d) / denom;
  const p = add(scale(u1, a), scale(u2, b));
  const pSq = dot(p, p);
  if (pSq > 1 + 1e-11) return [];
  const n = cross(u1, u2);
  const nSq = dot(n, n);
  if (nSq < 1e-15) return [];
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

function furthestOnCircle(u: Vec3, theta: number, target: Vec3): Vec3 {
  if (theta >= Math.PI - 1e-12) return scale(target, -1);
  const negT = scale(target, -1);
  const proj = sub(negT, scale(u, dot(negT, u)));
  const dir = normalize(proj) ?? anyOrthogonal(u);
  return normalize(add(scale(u, Math.cos(theta)), scale(dir, Math.sin(theta)))) ?? u;
}

interface Disk {
  u: Vec3;
  theta: number;
  cosTheta: number;
}

function solveByzantineCore(
  disks: Disk[],
  maxByzantine: number,
  target: LatLon,
  requiredRadiusKm: number
): CoreResult {
  const k = disks.length;
  const f = Math.min(maxByzantine, Math.max(0, k - 1));
  const req = k - f;
  const eps = 1e-9;
  const targetU = toUnitVec(target);
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
    const far = furthestOnCircle(disks[i].u, disks[i].theta, targetU);
    if (countIn(far) >= req) pts.push(far);
  }
  const antipode = scale(targetU, -1);
  if (countIn(antipode) >= req) pts.push(antipode);

  if (pts.length === 0) {
    return {
      provenMaxRadiusKm: Number.POSITIVE_INFINITY,
      provenMaxRadiusMiles: Number.POSITIVE_INFINITY,
      containedWithinTarget: false,
      witnessCentroid: target,
    };
  }

  let worstKm = 0;
  let sum: Vec3 = [0, 0, 0];
  for (const p of pts) {
    worstKm = Math.max(worstKm, geodesicKm(targetU, p));
    sum = add(sum, p);
  }
  const centroid = toLatLon(normalize(sum) ?? pts[0]);
  return {
    provenMaxRadiusKm: worstKm,
    provenMaxRadiusMiles: worstKm * 0.621371,
    containedWithinTarget: worstKm <= requiredRadiusKm,
    witnessCentroid: centroid,
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

/** Compute the exact canonical SHA-256 signing digest matching `pog_proto::AnchorReceipt::signing_digest()`. */
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

/** Verify raw 32-byte Ed25519 signature using Node's native zero-dep `node:crypto` SPKI DER wrapper. */
function verifyEd25519(pubkeyHex: string, message: Buffer, sigHex: string): boolean {
  const rawPub = Buffer.from(pubkeyHex, "hex");
  const sig = Buffer.from(sigHex, "hex");
  if (rawPub.length !== 32 || sig.length !== 64) return false;
  // RFC 8410 Ed25519 SubjectPublicKeyInfo prefix (12 bytes) + 32-byte key.
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const keyObj = createPublicKey({
    key: Buffer.concat([spkiPrefix, rawPub]),
    format: "der",
    type: "spki",
  });
  return cryptoVerify(null, message, keyObj, sig);
}

/** Decode a base64url `X-PoG-Proof` HTTP / RA-TLS header value into a `GeoProofBundle`. */
export function decodeProofHeader(headerValue: string): GeoProofBundle {
  const raw = Buffer.from(headerValue.trim(), "base64url").toString("utf8");
  return JSON.parse(raw) as GeoProofBundle;
}

/** Fully verify a `GeoProofBundle` (or `X-PoG-Proof` header string) offline. */
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
  const enforceTier = policy.enforceTier ?? "vacuum";

  const failures: string[] = [];
  if (nowUnixS > bundle.created_at_unix_s + maxAge) {
    failures.push(`Proof expired (${nowUnixS - bundle.created_at_unix_s}s > ${maxAge}s)`);
  }

  const q = bundle.prover_quote;
  if (q.vendor === "SoftwareDev" && !allowDev) {
    failures.push("SoftwareDev TEE quotes rejected under production policy");
  }
  if (!q.migration_disabled) failures.push("TEE MIGRATE_MA not disabled");
  if (!q.debug_disabled) failures.push("TEE debug mode not disabled");

  // Verify SHA-512 hardware report_data binding.
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
  const vacDisks: Disk[] = [];
  const fibDisks: Disk[] = [];
  const calDisks: Disk[] = [];
  const calV = bundle.calibrated_velocity_km_per_s ?? 162000.0;

  for (const r of bundle.receipts) {
    if (seenAnchors.has(r.anchor_id)) {
      failures.push(`Duplicate anchor ${r.anchor_id}`);
      continue;
    }
    seenAnchors.add(r.anchor_id);
    const a = anchorMap.get(r.anchor_id);
    if (!a) {
      failures.push(`Unknown anchor ${r.anchor_id}`);
      continue;
    }
    const digest = receiptSigningDigest(r);
    if (!verifyEd25519(a.public_key_hex, digest, r.anchor_signature_hex)) {
      failures.push(`Invalid Ed25519 signature from ${r.anchor_id}`);
      continue;
    }
    if (r.prover_pk_hex !== q.public_key_hex || r.epoch_challenge_hex !== bundle.epoch_challenge_hex) {
      failures.push(`Receipt binding mismatch from ${r.anchor_id}`);
      continue;
    }
    seenClouds.add(a.cloud_provider);
    const u = toUnitVec(a.location);
    const mkDisk = (rKm: number): Disk => {
      const th = Math.min(Math.PI, rKm / EARTH_RADIUS_KM);
      return { u, theta: th, cosTheta: Math.cos(th) };
    };
    const rttS = r.rtt_min_us * 1e-6;
    const calRttS = Math.max(0, r.rtt_min_us - 600) * 1e-6;
    vacDisks.push(mkDisk(0.5 * C_VACUUM_KM_PER_S * rttS));
    fibDisks.push(mkDisk(0.5 * C_FIBER_KM_PER_S * rttS));
    calDisks.push(mkDisk(0.5 * calV * calRttS));
  }

  if (vacDisks.length < minAnchors) failures.push(`Insufficient anchors: ${vacDisks.length} < ${minAnchors}`);
  if (seenClouds.size < minClouds) failures.push(`Insufficient clouds: ${seenClouds.size} < ${minClouds}`);

  const tier1aVacuum = solveByzantineCore(vacDisks, maxByzantine, bundle.target_location, bundle.required_radius_km);
  const tier1bFiber = solveByzantineCore(fibDisks, maxByzantine, bundle.target_location, bundle.required_radius_km);
  const tier2Calibrated = solveByzantineCore(calDisks, maxByzantine, bundle.target_location, bundle.required_radius_km);

  const enforced =
    enforceTier === "vacuum" ? tier1aVacuum : enforceTier === "fiber" ? tier1bFiber : tier2Calibrated;
  if (!enforced.containedWithinTarget) {
    failures.push(
      `Enforced tier (${enforceTier}) failed: ${enforced.provenMaxRadiusKm.toFixed(1)} km > ${bundle.required_radius_km} km`
    );
  }

  return {
    overallValid: failures.length === 0,
    failureReasons: failures,
    distinctClouds: seenClouds.size,
    verifiedReceipts: vacDisks.length,
    proverPublicKeyHex: q.public_key_hex,
    workloadMeasurementHex: q.workload_measurement_hex,
    hasGpuBinding: Boolean(q.gpu_binding),
    tier1aVacuum,
    tier1bFiber,
    tier2Calibrated,
  };
}
