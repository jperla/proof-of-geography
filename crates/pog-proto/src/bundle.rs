use crate::committee::AnchorGrid;
use crate::wire::{AnchorReceipt, ProtoError};
use base64::Engine;
use pog_geo::{
    verify_byzantine_core, BoundTier, ByzantineCoreResult, DiskConstraint, LatLon,
};
use pog_tee::{verify_quote, AttestationPolicy, TeeAttestationQuote, VerifiedTeeIdentity};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Standard HTTP header / RA-TLS extension name for attaching handshake-time Proofs of Geography.
pub const HTTP_HEADER_POG_PROOF: &str = "X-PoG-Proof";

/// Complete, self-contained cryptographic Proof of Geography bundle.
/// Can be:
/// 1. Attached directly to an RA-TLS / HTTPS handshake (`X-PoG-Proof` header) for zero-latency, zero-gas client verification.
/// 2. Submitted hourly to the DNS/CT-style transparency log (`pog-log`) to form a continuous residency chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoProofBundle {
    pub version: u8,
    /// Epoch challenge or handshake-bound challenge (`BLAKE3(epoch_id || optional_client_nonce)`).
    pub epoch_challenge_hex: String,
    /// Optional client-supplied connection nonce folded into `epoch_challenge_hex` (handshake mode).
    pub client_nonce_hex: Option<String>,
    /// Claimed target location and required geofence radius (km).
    pub target_location: LatLon,
    pub required_radius_km: f64,
    /// Prover TEE Remote Attestation Quote binding `pk_P`, workload measurement, and `MIGRATE_MA=0`.
    pub prover_quote: TeeAttestationQuote,
    /// K signed RTT receipts from multi-cloud Anchors.
    pub receipts: Vec<AnchorReceipt>,
    /// Optional calibrated corridor velocity (km/s) from the Anchor mesh for Tier 2 reporting.
    pub calibrated_velocity_km_per_s: Option<f64>,
    /// Previous hourly chain record hash (None for standalone connection-time proofs or genesis).
    pub prev_chain_hash_hex: Option<String>,
    pub chain_seq: u64,
    pub created_at_unix_s: u64,
}

impl GeoProofBundle {
    /// Deterministic hash of this proof bundle (used for hourly hash-chaining & Merkle log leaves).
    pub fn record_hash_hex(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        hex::encode(blake3::hash(&bytes).as_bytes())
    }

    /// Encode compactly as base64url for `X-PoG-Proof` HTTP header or RA-TLS certificate extension.
    pub fn to_header_value(&self) -> Result<String, ProtoError> {
        let json = serde_json::to_vec(self)
            .map_err(|e| ProtoError::SerializationError(e.to_string()))?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&json))
    }

    pub fn from_header_value(val: &str) -> Result<Self, ProtoError> {
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(val.trim())
            .map_err(|e| ProtoError::SerializationError(e.to_string()))?;
        serde_json::from_slice(&raw).map_err(|e| ProtoError::SerializationError(e.to_string()))
    }
}

/// Client/verifier policy for validating a `GeoProofBundle`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationPolicy {
    pub tee_policy: AttestationPolicy,
    /// Maximum Byzantine / colluding anchors tolerated (`f`).
    pub max_byzantine: usize,
    /// Minimum required Anchor receipts (`K`).
    pub min_anchors: usize,
    /// Minimum distinct cloud providers required across receipts.
    pub min_cloud_providers: usize,
    /// Maximum proof age in seconds (e.g., 3600s for hourly chain, 120s for live handshake).
    pub max_proof_age_seconds: u64,
    /// Which primary bound tier must satisfy `required_radius_km` to pass `overall_valid`.
    pub enforce_tier: BoundTier,
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            tee_policy: AttestationPolicy::production(),
            max_byzantine: 1,
            min_anchors: 4,
            min_cloud_providers: 2,
            max_proof_age_seconds: 3_900,
            enforce_tier: BoundTier::Vacuum,
        }
    }
}

/// Rich multi-tier verification output showing ALL THREE tiers simultaneously:
/// - Tier 1A: Strict Vacuum (c0 = 299,792 km/s — Starlink & microwave safe!)
/// - Tier 1B: Silica Optical Fiber (c_fiber = 204,000 km/s)
/// - Tier 2:  Calibrated Empirical Radius (IPinfo/CBG-style corridor curve)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofVerificationReport {
    pub overall_valid: bool,
    pub failure_reasons: Vec<String>,
    pub verified_tee: VerifiedTeeIdentity,
    pub distinct_clouds: usize,
    pub verified_receipt_count: usize,
    pub tier1a_vacuum: ByzantineCoreResult,
    pub tier1b_fiber: ByzantineCoreResult,
    pub tier2_calibrated: ByzantineCoreResult,
}

/// Fully verify a `GeoProofBundle` offline against a trusted `AnchorGrid` and `VerificationPolicy`.
pub fn verify_proof_bundle(
    bundle: &GeoProofBundle,
    grid: &AnchorGrid,
    policy: &VerificationPolicy,
    now_unix_s: u64,
) -> Result<ProofVerificationReport, ProtoError> {
    let mut failure_reasons = Vec::new();

    // 1. Freshness check.
    if now_unix_s > bundle.created_at_unix_s + policy.max_proof_age_seconds {
        failure_reasons.push(format!(
            "Proof expired: age {}s > max {}s",
            now_unix_s - bundle.created_at_unix_s,
            policy.max_proof_age_seconds
        ));
    }

    // 2. Verify Prover TEE Remote Attestation Quote & binding to `epoch_challenge_hex`.
    let epoch_bytes = hex::decode(&bundle.epoch_challenge_hex)
        .map_err(|e| ProtoError::SerializationError(format!("bad epoch hex: {e}")))?;
    let verified_tee = verify_quote(
        &bundle.prover_quote,
        &epoch_bytes,
        &policy.tee_policy,
        now_unix_s,
    )
    .map_err(|e| ProtoError::SignatureError(format!("Prover TEE quote invalid: {e}")))?;

    // 3. Verify every Anchor receipt signature, freshness, workload binding, and deduplicate Anchor IDs.
    let mut seen_anchors = HashSet::new();
    let mut seen_clouds = HashSet::new();
    let mut vacuum_disks = Vec::new();
    let mut fiber_disks = Vec::new();
    let mut cal_disks = Vec::new();

    let cal_tier = BoundTier::Calibrated {
        effective_km_per_s: bundle.calibrated_velocity_km_per_s.unwrap_or(145_000.0),
    };

    for r in &bundle.receipts {
        if !seen_anchors.insert(r.anchor_id.clone()) {
            failure_reasons.push(format!("Duplicate anchor receipt: {}", r.anchor_id));
            continue;
        }
        let anchor = match grid.by_id(&r.anchor_id) {
            Some(a) => a,
            None => {
                failure_reasons.push(format!("Unknown anchor not in registry: {}", r.anchor_id));
                continue;
            }
        };
        if let Err(e) = r.verify(&anchor.public_key_hex) {
            failure_reasons.push(format!("Anchor {} signature invalid: {e}", r.anchor_id));
            continue;
        }
        if r.prover_pk_hex != verified_tee.public_key_hex {
            failure_reasons.push(format!("Anchor {} prover_pk mismatch", r.anchor_id));
            continue;
        }
        if r.workload_measurement_hex != verified_tee.workload_measurement_hex {
            failure_reasons.push(format!("Anchor {} workload measurement mismatch", r.anchor_id));
            continue;
        }
        if r.epoch_challenge_hex != bundle.epoch_challenge_hex {
            failure_reasons.push(format!("Anchor {} epoch_challenge mismatch", r.anchor_id));
            continue;
        }
        if now_unix_s > r.measured_at_unix_s + policy.max_proof_age_seconds {
            failure_reasons.push(format!("Anchor {} receipt expired", r.anchor_id));
            continue;
        }

        seen_clouds.insert(anchor.cloud_provider.clone());
        vacuum_disks.push(DiskConstraint::from_rtt(
            &anchor.anchor_id,
            anchor.location,
            r.rtt_min_us,
            BoundTier::Vacuum,
            &anchor.cloud_provider,
        ));
        fiber_disks.push(DiskConstraint::from_rtt(
            &anchor.anchor_id,
            anchor.location,
            r.rtt_min_us,
            BoundTier::Fiber,
            &anchor.cloud_provider,
        ));
        cal_disks.push(DiskConstraint::from_rtt(
            &anchor.anchor_id,
            anchor.location,
            r.rtt_min_us,
            cal_tier,
            &anchor.cloud_provider,
        ));
    }

    if vacuum_disks.len() < policy.min_anchors {
        failure_reasons.push(format!(
            "Insufficient verified anchors: {} < {}",
            vacuum_disks.len(),
            policy.min_anchors
        ));
    }
    if seen_clouds.len() < policy.min_cloud_providers {
        failure_reasons.push(format!(
            "Insufficient cloud diversity: {} < {}",
            seen_clouds.len(),
            policy.min_cloud_providers
        ));
    }

    let f = policy
        .max_byzantine
        .min(vacuum_disks.len().saturating_sub(1));

    let tier1a_vacuum = verify_byzantine_core(
        &vacuum_disks,
        f,
        bundle.target_location,
        bundle.required_radius_km,
        Some(bundle.target_location),
    )
    .map_err(|e| ProtoError::SerializationError(format!("Tier 1A geo error: {e}")))?;

    let tier1b_fiber = verify_byzantine_core(
        &fiber_disks,
        f,
        bundle.target_location,
        bundle.required_radius_km,
        Some(bundle.target_location),
    )
    .map_err(|e| ProtoError::SerializationError(format!("Tier 1B geo error: {e}")))?;

    let tier2_calibrated = verify_byzantine_core(
        &cal_disks,
        f,
        bundle.target_location,
        bundle.required_radius_km,
        Some(bundle.target_location),
    )
    .unwrap_or_else(|_| tier1b_fiber.clone());

    let enforced_ok = match policy.enforce_tier {
        BoundTier::Vacuum => tier1a_vacuum.contained_within_target,
        BoundTier::Fiber => tier1b_fiber.contained_within_target,
        BoundTier::Calibrated { .. } => tier2_calibrated.contained_within_target,
    };

    if !enforced_ok {
        failure_reasons.push(format!(
            "Enforced bound tier ({}) failed containment: proven_max_radius={:.1} km > required {:.1} km",
            policy.enforce_tier.name(),
            match policy.enforce_tier {
                BoundTier::Vacuum => tier1a_vacuum.proven_max_radius_km,
                BoundTier::Fiber => tier1b_fiber.proven_max_radius_km,
                BoundTier::Calibrated { .. } => tier2_calibrated.proven_max_radius_km,
            },
            bundle.required_radius_km
        ));
    }

    Ok(ProofVerificationReport {
        overall_valid: failure_reasons.is_empty(),
        failure_reasons,
        verified_tee,
        distinct_clouds: seen_clouds.len(),
        verified_receipt_count: vacuum_disks.len(),
        tier1a_vacuum,
        tier1b_fiber,
        tier2_calibrated,
    })
}
