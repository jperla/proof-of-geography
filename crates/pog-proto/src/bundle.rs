use crate::committee::AnchorGrid;
use crate::wire::{AnchorReceipt, ProtoError};
use base64::Engine;
use pog_geo::{
    compute_spatial_likelihood, estimate_probabilistic_location, evaluate_geofence,
    verify_byzantine_core, BoundTier, BoundUncertainty, ByzantineCoreResult, DiskConstraint,
    GeofenceEvaluation, GeofencePolicy, LatLon, LikelihoodObservation, ProbabilisticGeoEstimate,
    SpatialLikelihoodConfig, SpatialLikelihoodSurface, C_FIBER_KM_PER_S,
};
use pog_tee::{verify_quote, AttestationPolicy, TeeAttestationQuote, TeeVendor, VerifiedTeeIdentity};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};

/// Standard HTTP header / RA-TLS extension name for attaching handshake-time Proofs of Geography.
pub const HTTP_HEADER_POG_PROOF: &str = "X-PoG-Proof";

/// Complete, self-contained cryptographic Proof of Geography bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoProofBundle {
    pub version: u8,
    pub epoch_challenge_hex: String,
    pub client_nonce_hex: Option<String>,
    pub target_location: LatLon,
    pub required_radius_km: f64,
    pub prover_quote: TeeAttestationQuote,
    pub receipts: Vec<AnchorReceipt>,
    pub calibrated_velocity_km_per_s: Option<f64>,
    pub prev_chain_hash_hex: Option<String>,
    pub chain_seq: u64,
    pub created_at_unix_s: u64,
}

impl GeoProofBundle {
    pub fn record_hash_hex(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        hex::encode(blake3::hash(&bytes).as_bytes())
    }

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

/// Expected deployment entry in a verifier-owned Chip / Asset Registry (Brass & Aarne pp. 6, 29).
/// Binds a hardware identity (`prover_pk_hex` and/or `gpu_uuid`) to its authorized physical facility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredChipPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prover_pk_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_uuid: Option<String>,
    pub facility_label: String,
    pub expected_location: LatLon,
    pub max_radius_km: f64,
    #[serde(default)]
    pub allowed_jurisdictions: Vec<String>,
}

/// Verifier-owned Chip / Asset Registry preventing a smuggled chip from picking its own target location.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChipRegistry {
    pub entries: Vec<RegisteredChipPolicy>,
}

impl ChipRegistry {
    pub fn lookup(&self, prover_pk_hex: &str, gpu_uuid: Option<&str>) -> Option<&RegisteredChipPolicy> {
        self.entries.iter().find(|e| {
            let pk_match = e
                .prover_pk_hex
                .as_deref()
                .map(|pk| pk.eq_ignore_ascii_case(prover_pk_hex))
                .unwrap_or(false);
            let gpu_match = match (e.gpu_uuid.as_deref(), gpu_uuid) {
                (Some(reg), Some(act)) => reg.eq_ignore_ascii_case(act),
                _ => false,
            };
            pk_match || gpu_match
        })
    }
}

/// Client/verifier policy for validating a `GeoProofBundle`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationPolicy {
    pub tee_policy: AttestationPolicy,
    /// Maximum Byzantine / colluding anchors tolerated (`f`).
    pub max_byzantine: usize,
    /// Minimum required verified Anchor receipts (`K`).
    pub min_anchors: usize,
    /// Minimum distinct cloud providers required across verified receipts.
    pub min_cloud_providers: usize,
    /// Maximum proof age in seconds.
    pub max_proof_age_seconds: u64,
    /// Which primary bound tier must satisfy `required_radius_km` to pass `overall_valid`.
    /// Defaults to `BoundTier::Vacuum` (strict outer bound).
    pub enforce_tier: BoundTier,
    /// Conservative timing & anchor-coordinate uncertainty folded into Tier 1 outer bounds.
    #[serde(default)]
    pub bound_uncertainty: BoundUncertainty,
    /// Verifier-enforced expected location: overrides untrusted `bundle.target_location` so a
    /// smuggled Prover cannot claim its own arbitrary coordinates!
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_target_location: Option<LatLon>,
    /// Verifier-enforced maximum containment radius (km): caps untrusted `bundle.required_radius_km`
    /// and blocks universal delay-inflation attacks (Gill et al. / Brass & Aarne p. 22–23).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_allowed_radius_km: Option<f64>,
    /// Optional verifier-owned Chip / Asset Registry binding prover keys / GPU UUIDs to registered facilities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chip_registry: Option<ChipRegistry>,
    /// Optional polygon geofencing policy (negative anti-smuggling exclusion + positive jurisdiction containment).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geofence: Option<GeofencePolicy>,
    /// ISO 3166-1 alpha-2 country codes of Anchors to EXCLUDE from quorum ("striking distance" policy, Brass & Aarne p. 26–27).
    #[serde(default)]
    pub excluded_anchor_countries: Vec<String>,
    /// Optional ISO-2 Anchor country allowlist: if Some and non-empty, ONLY Anchors in these countries count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_anchor_countries: Option<Vec<String>>,
    /// Optional minimum distinct ISO-2 Anchor countries required across verified receipts (default 0).
    #[serde(default)]
    pub min_distinct_countries: usize,
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
            bound_uncertainty: BoundUncertainty::default_datacenter(),
            expected_target_location: None,
            max_allowed_radius_km: None,
            chip_registry: None,
            geofence: None,
            excluded_anchor_countries: Vec::new(),
            allowed_anchor_countries: None,
            min_distinct_countries: 0,
        }
    }
}

/// External IP address observed by a specific verified Anchor when the Prover connected to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorObservedIp {
    pub anchor_id: String,
    pub cloud_provider: String,
    pub observed_ip: String,
    pub rtt_min_us: u64,
}

/// Explicit record of every receipt rejected during verification (NEVER silently dropped!).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnverifiedReceiptRecord {
    pub anchor_id: String,
    pub reason: String,
}

/// Explicit proof eligibility status (distinguishes valid proof from insufficient verified anchors / no proof).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    Verified,
    InsufficientVerifiedAnchors,
    NoVerifiedConstraint,
    ContainmentFailed,
    InconsistentMeasurements,
    PolicyRejected,
}

/// Rich multi-tier verification output keeping raw outer bounds, empirical calibrated overlay,
/// hardware attestation status, and unverified receipts strictly separated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofVerificationReport {
    pub overall_valid: bool,
    pub proof_status: ProofStatus,
    /// True ONLY when BOTH the prover TEE quote verified cryptographically against a hardware vendor
    /// trust root AND every counted Anchor receipt came from a non-dev hardware TEE anchor.
    pub hardware_attested: bool,
    pub failure_reasons: Vec<String>,
    pub verified_tee: VerifiedTeeIdentity,
    pub distinct_clouds: usize,
    #[serde(default)]
    pub distinct_countries: usize,
    pub verified_receipt_count: usize,
    pub submitted_receipt_count: usize,
    /// Authoritative target location actually enforced (verifier override / chip registry, or bundle claim).
    #[serde(default)]
    pub effective_target_location: Option<LatLon>,
    /// Authoritative maximum radius (km) actually enforced (verifier cap / chip registry, or bundle claim).
    #[serde(default)]
    pub effective_required_radius_km: Option<f64>,
    /// Matched facility label when a verifier `ChipRegistry` is configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chip_registry_facility: Option<String>,
    /// Polygon geofence evaluation (negative anti-smuggling exclusion + positive jurisdiction containment).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geofence_evaluation: Option<GeofenceEvaluation>,
    /// Diagnostic warnings when any Anchor RTT implies a speed exceeding standard silica fiber (204,000 km/s),
    /// flagging possible dark-fiber/hollow-core/LEO-ISL shortcuts or clock drift (never falsely excludes under Vacuum c0).
    #[serde(default)]
    pub fast_path_anomalies: Vec<String>,
    /// All receipts that failed signature, key-match, freshness, jurisdiction, or hardware-TEE policy checks.
    pub unverified_receipts: Vec<UnverifiedReceiptRecord>,
    pub observed_prover_ips: Vec<AnchorObservedIp>,
    pub distinct_observed_ips: Vec<String>,
    pub ip_view_consistent: bool,
    /// Tier 1A: Strict Vacuum outer bound (conditional on trusted anchors & audited coordinates).
    /// `None` when fewer than 1 (or insufficient) verified anchors exist -> no proof.
    pub tier1a_vacuum: Option<ByzantineCoreResult>,
    /// Tier 1B: Conservative Optical Fiber bound.
    pub tier1b_fiber: Option<ByzantineCoreResult>,
    /// Tier 2: Empirical calibrated overlay — NEVER silently falls back to Tier 1B when empty!
    pub tier2_calibrated: Option<ByzantineCoreResult>,
    pub tier2_calibrated_error: Option<String>,
    /// Empirical probabilistic MLE estimate (NEVER used for hard exclusions).
    pub probabilistic_estimate: Option<ProbabilisticGeoEstimate>,
    /// Correlated spatial likelihood surface strictly inside raw Vacuum c0 (empirical estimate, NOT proof).
    pub spatial_likelihood: Option<SpatialLikelihoodSurface>,
    /// Explicit reminder that hardware TEE identity does not prove anchor coordinates.
    pub coordinate_provenance_note: String,
}

/// Fully verify a `GeoProofBundle` offline against a trusted `AnchorGrid` and `VerificationPolicy`.
///
/// Fail-closed invariants:
/// 1. Under production policy (`!allow_software_dev`), BOTH Prover and EVERY counted Anchor
///    must be non-`SoftwareDev` hardware TEEs.
/// 2. Unverified/mismatched/dev receipts are NEVER silently dropped and NEVER substituted;
///    they are recorded in `unverified_receipts`.
/// 3. If verified anchors < `min_anchors` (including 0), returns `ProofStatus::InsufficientVerifiedAnchors`
///    with `overall_valid = false` and `tier1a_vacuum = None` ("no proof"), never a fake region.
/// 4. If empirical `tier2_calibrated` is empty/inconsistent, returns `tier2_calibrated = None`
///    and populates `tier2_calibrated_error` — NEVER silently clones `tier1b_fiber`!
pub fn verify_proof_bundle(
    bundle: &GeoProofBundle,
    grid: &AnchorGrid,
    policy: &VerificationPolicy,
    now_unix_s: u64,
) -> Result<ProofVerificationReport, ProtoError> {
    let mut failure_reasons = Vec::new();
    let max_future_skew = policy.tee_policy.max_future_skew_seconds;

    // 1. Freshness & future-skew checks.
    if now_unix_s > bundle.created_at_unix_s.saturating_add(policy.max_proof_age_seconds) {
        failure_reasons.push(format!(
            "Proof expired: age {}s > max {}s",
            now_unix_s.saturating_sub(bundle.created_at_unix_s),
            policy.max_proof_age_seconds
        ));
    }
    if bundle.created_at_unix_s > now_unix_s.saturating_add(max_future_skew) {
        failure_reasons.push(format!(
            "Proof timestamp {}s in future (max skew {}s)",
            bundle.created_at_unix_s - now_unix_s,
            max_future_skew
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

    // 2B. Resolve verifier-authoritative target location & max containment radius (fixes untrusted bundle claim!).
    let gpu_uuid_opt = bundle
        .prover_quote
        .gpu_binding
        .as_ref()
        .map(|g| g.gpu_uuid.as_str());
    let mut chip_registry_facility: Option<String> = None;
    let (mut effective_target, mut effective_radius_km) = (bundle.target_location, bundle.required_radius_km);

    if let Some(ref reg) = policy.chip_registry {
        match reg.lookup(&verified_tee.public_key_hex, gpu_uuid_opt) {
            Some(entry) => {
                chip_registry_facility = Some(entry.facility_label.clone());
                effective_target = entry.expected_location;
                effective_radius_km = entry.max_radius_km;
            }
            None => {
                failure_reasons.push(format!(
                    "Unregistered chip/prover (pk={}…, gpu_uuid={:?}) rejected by verifier ChipRegistry",
                    &verified_tee.public_key_hex[..12.min(verified_tee.public_key_hex.len())],
                    gpu_uuid_opt
                ));
            }
        }
    }
    if let Some(exp_target) = policy.expected_target_location {
        effective_target = exp_target;
    }
    if let Some(max_r) = policy.max_allowed_radius_km {
        effective_radius_km = effective_radius_km.min(max_r);
    }

    // 3. Verify every Anchor receipt strictly against the trusted registry & policy.
    let mut seen_anchors = HashSet::new();
    let mut seen_clouds = HashSet::new();
    let mut seen_countries = HashSet::new();
    let mut observed_prover_ips = Vec::new();
    let mut distinct_ips = BTreeSet::new();
    let mut unverified_receipts = Vec::new();
    let mut fast_path_anomalies = Vec::new();
    let mut vacuum_disks = Vec::new();
    let mut fiber_disks = Vec::new();
    let mut cal_disks = Vec::new();
    let mut likelihood_obs = Vec::new();
    let mut all_anchors_hardware_tee = true;

    // Empirically fit defaults (strictly empirical overlay, never hard exclusion).
    let cal_v = bundle.calibrated_velocity_km_per_s.unwrap_or(152_000.0);
    let cal_tier = BoundTier::CalibratedLinear {
        effective_km_per_s: cal_v,
        fixed_overhead_us: 350,
    };

    for r in &bundle.receipts {
        if !seen_anchors.insert(r.anchor_id.clone()) {
            let msg = format!("Duplicate anchor receipt: {}", r.anchor_id);
            unverified_receipts.push(UnverifiedReceiptRecord {
                anchor_id: r.anchor_id.clone(),
                reason: msg.clone(),
            });
            failure_reasons.push(msg);
            continue;
        }
        let anchor = match grid.by_id(&r.anchor_id) {
            Some(a) => a,
            None => {
                let msg = format!("Unknown anchor not in registry: {}", r.anchor_id);
                unverified_receipts.push(UnverifiedReceiptRecord {
                    anchor_id: r.anchor_id.clone(),
                    reason: msg.clone(),
                });
                failure_reasons.push(msg);
                continue;
            }
        };
        // Fail-closed production fleet invariant: SoftwareDev anchors are NEVER proof-eligible under production policy!
        if anchor.tee_vendor == TeeVendor::SoftwareDev {
            all_anchors_hardware_tee = false;
            if !policy.tee_policy.allow_software_dev {
                let msg = format!(
                    "Anchor {} reports SoftwareDev (hardware TEE required under production policy)",
                    r.anchor_id
                );
                unverified_receipts.push(UnverifiedReceiptRecord {
                    anchor_id: r.anchor_id.clone(),
                    reason: msg.clone(),
                });
                failure_reasons.push(msg);
                continue;
            }
        }
        // Striking-distance / verifier Anchor jurisdiction filtering (Brass & Aarne pp. 26-27).
        let anchor_cc = anchor.effective_country_code();
        if let Some(ref cc) = anchor_cc {
            if policy
                .excluded_anchor_countries
                .iter()
                .any(|ex| ex.eq_ignore_ascii_case(cc))
            {
                let msg = format!(
                    "Anchor {} (country {}) excluded by verifier striking-distance jurisdiction policy",
                    r.anchor_id, cc
                );
                unverified_receipts.push(UnverifiedReceiptRecord {
                    anchor_id: r.anchor_id.clone(),
                    reason: msg,
                });
                continue;
            }
        }
        if let Some(ref allow_cc) = policy.allowed_anchor_countries {
            if !allow_cc.is_empty() {
                let permitted = anchor_cc
                    .as_deref()
                    .map(|cc| allow_cc.iter().any(|al| al.eq_ignore_ascii_case(cc)))
                    .unwrap_or(false);
                if !permitted {
                    let msg = format!(
                        "Anchor {} (country {:?}) not in verifier allowed_anchor_countries",
                        r.anchor_id, anchor_cc
                    );
                    unverified_receipts.push(UnverifiedReceiptRecord {
                        anchor_id: r.anchor_id.clone(),
                        reason: msg,
                    });
                    continue;
                }
            }
        }
        if let Err(e) = r.verify(&anchor.public_key_hex) {
            let msg = format!(
                "Anchor {} signature/key mismatch against published registry key: {e}",
                r.anchor_id
            );
            unverified_receipts.push(UnverifiedReceiptRecord {
                anchor_id: r.anchor_id.clone(),
                reason: msg.clone(),
            });
            failure_reasons.push(msg);
            continue;
        }
        if r.prover_pk_hex != verified_tee.public_key_hex {
            let msg = format!("Anchor {} prover_pk mismatch", r.anchor_id);
            unverified_receipts.push(UnverifiedReceiptRecord {
                anchor_id: r.anchor_id.clone(),
                reason: msg.clone(),
            });
            failure_reasons.push(msg);
            continue;
        }
        if r.workload_measurement_hex != verified_tee.workload_measurement_hex {
            let msg = format!("Anchor {} workload measurement mismatch", r.anchor_id);
            unverified_receipts.push(UnverifiedReceiptRecord {
                anchor_id: r.anchor_id.clone(),
                reason: msg.clone(),
            });
            failure_reasons.push(msg);
            continue;
        }
        if r.epoch_challenge_hex != bundle.epoch_challenge_hex {
            let msg = format!("Anchor {} epoch_challenge mismatch", r.anchor_id);
            unverified_receipts.push(UnverifiedReceiptRecord {
                anchor_id: r.anchor_id.clone(),
                reason: msg.clone(),
            });
            failure_reasons.push(msg);
            continue;
        }
        if now_unix_s > r.measured_at_unix_s.saturating_add(policy.max_proof_age_seconds) {
            let msg = format!("Anchor {} receipt expired", r.anchor_id);
            unverified_receipts.push(UnverifiedReceiptRecord {
                anchor_id: r.anchor_id.clone(),
                reason: msg.clone(),
            });
            failure_reasons.push(msg);
            continue;
        }
        if r.measured_at_unix_s > now_unix_s.saturating_add(max_future_skew) {
            let msg = format!("Anchor {} receipt timestamp in future", r.anchor_id);
            unverified_receipts.push(UnverifiedReceiptRecord {
                anchor_id: r.anchor_id.clone(),
                reason: msg.clone(),
            });
            failure_reasons.push(msg);
            continue;
        }

        // Fold this anchor's audited coordinate uncertainty into its conservative outer bound.
        let mut unc = policy.bound_uncertainty;
        unc.anchor_location_uncertainty_km =
            unc.anchor_location_uncertainty_km.max(anchor.location_uncertainty_km());

        seen_clouds.insert(anchor.cloud_provider.clone());
        if let Some(cc) = anchor_cc {
            seen_countries.insert(cc);
        }
        // Dark-fiber / hollow-core / fast-path diagnostic flag (never falsely excludes under Vacuum c0).
        let dist_to_target = anchor.location.distance_km(effective_target);
        if dist_to_target >= 150.0 && r.rtt_min_us > 0 {
            let implied_v = (2.0 * dist_to_target) / ((r.rtt_min_us as f64) * 1e-6);
            if implied_v > C_FIBER_KM_PER_S * 1.02 {
                fast_path_anomalies.push(format!(
                    "Anchor {} RTT {:.2} ms over {:.0} km implies {:.0} km/s (> silica fiber 204k km/s; dark/hollow-core fiber, LEO-ISL, or clock anomaly suspected)",
                    anchor.anchor_id,
                    (r.rtt_min_us as f64) * 1e-3,
                    dist_to_target,
                    implied_v
                ));
            }
        }
        distinct_ips.insert(r.prover_observed_ip.clone());
        observed_prover_ips.push(AnchorObservedIp {
            anchor_id: anchor.anchor_id.clone(),
            cloud_provider: anchor.cloud_provider.clone(),
            observed_ip: r.prover_observed_ip.clone(),
            rtt_min_us: r.rtt_min_us,
        });
        vacuum_disks.push(DiskConstraint::from_rtt_with_uncertainty(
            &anchor.anchor_id,
            anchor.location,
            r.rtt_min_us,
            BoundTier::Vacuum,
            unc,
            &anchor.cloud_provider,
        ));
        fiber_disks.push(DiskConstraint::from_rtt_with_uncertainty(
            &anchor.anchor_id,
            anchor.location,
            r.rtt_min_us,
            BoundTier::Fiber,
            unc,
            &anchor.cloud_provider,
        ));
        cal_disks.push(DiskConstraint::from_rtt_with_uncertainty(
            &anchor.anchor_id,
            anchor.location,
            r.rtt_min_us,
            cal_tier,
            unc,
            &anchor.cloud_provider,
        ));
        let rtt_min_ms = (r.rtt_min_us as f64) * 1e-3;
        let rtt_p50_ms = (r.rtt_p50_us as f64) * 1e-3;
        let sample_ms: Vec<f64> = r
            .rtt_samples_us
            .iter()
            .filter(|&&u| u > 0)
            .map(|&u| (u as f64) * 1e-3)
            .collect();
        let spread_ms = if sample_ms.len() >= 2 {
            pog_geo::route_instability_spread_ms(&sample_ms)
                .max((rtt_p50_ms - rtt_min_ms).max(0.0))
        } else {
            (rtt_p50_ms - rtt_min_ms).max(0.0)
        };
        likelihood_obs.push(LikelihoodObservation {
            anchor_id: anchor.anchor_id.clone(),
            location: anchor.location,
            rtt_ms: rtt_p50_ms.max(rtt_min_ms),
            rtt_min_ms,
            jitter_ms: spread_ms,
            anchor_uncertainty_km: unc.anchor_location_uncertainty_km,
        });
    }

    let distinct_observed_ips: Vec<String> = distinct_ips.into_iter().collect();
    let ip_view_consistent = distinct_observed_ips.len() <= 1;
    let verified_count = vacuum_disks.len();
    let hardware_attested =
        verified_tee.hardware_attested && all_anchors_hardware_tee && verified_count > 0;
    let coord_note = "Hardware TEE identity proves workload & key custody, NOT physical coordinates; anchor locations rely on separate audited coordinate provenance and cross-cloud mesh consistency.".to_string();

    if verified_count < policy.min_anchors {
        failure_reasons.push(format!(
            "Insufficient verified anchors: {} < {} (no proof; dev/unverified anchors are never substituted)",
            verified_count, policy.min_anchors
        ));
    }
    if seen_clouds.len() < policy.min_cloud_providers {
        failure_reasons.push(format!(
            "Insufficient cloud diversity across verified anchors: {} < {}",
            seen_clouds.len(),
            policy.min_cloud_providers
        ));
    }
    if policy.min_distinct_countries > 0 && seen_countries.len() < policy.min_distinct_countries {
        failure_reasons.push(format!(
            "Insufficient country diversity across verified anchors: {} < {}",
            seen_countries.len(),
            policy.min_distinct_countries
        ));
    }

    // Fail-closed: if zero verified anchors remain (or below quorum), return explicit InsufficientVerifiedAnchors
    // without pretending there is a valid geographic constraint!
    if verified_count == 0 {
        return Ok(ProofVerificationReport {
            overall_valid: false,
            proof_status: ProofStatus::InsufficientVerifiedAnchors,
            hardware_attested: false,
            failure_reasons,
            verified_tee,
            distinct_clouds: 0,
            distinct_countries: 0,
            verified_receipt_count: 0,
            submitted_receipt_count: bundle.receipts.len(),
            effective_target_location: Some(effective_target),
            effective_required_radius_km: Some(effective_radius_km),
            chip_registry_facility,
            geofence_evaluation: None,
            fast_path_anomalies,
            unverified_receipts,
            observed_prover_ips,
            distinct_observed_ips,
            ip_view_consistent,
            tier1a_vacuum: None,
            tier1b_fiber: None,
            tier2_calibrated: None,
            tier2_calibrated_error: Some("no verified anchor receipts".into()),
            probabilistic_estimate: None,
            spatial_likelihood: None,
            coordinate_provenance_note: coord_note,
        });
    }

    let f = policy
        .max_byzantine
        .min(verified_count.saturating_sub(1));

    let tier1a_res = verify_byzantine_core(
        &vacuum_disks,
        f,
        effective_target,
        effective_radius_km,
        Some(effective_target),
    );
    let tier1b_res = verify_byzantine_core(
        &fiber_disks,
        f,
        effective_target,
        effective_radius_km,
        Some(effective_target),
    );
    let tier2_res = verify_byzantine_core(
        &cal_disks,
        f,
        effective_target,
        effective_radius_km,
        Some(effective_target),
    );

    let tier1a_vacuum = match tier1a_res {
        Ok(r) => Some(r),
        Err(e) => {
            failure_reasons.push(format!("Tier 1A Vacuum infeasible/error: {e}"));
            None
        }
    };
    let tier1b_fiber = match tier1b_res {
        Ok(r) => Some(r),
        Err(e) => {
            failure_reasons.push(format!("Tier 1B Fiber infeasible/error: {e}"));
            None
        }
    };
    let (tier2_calibrated, tier2_calibrated_error) = match tier2_res {
        Ok(r) => (Some(r), None),
        Err(e) => (None, Some(format!("Tier 2 Calibrated infeasible/empty: {e}"))),
    };

    let (enforced_core, enforced_disks) = match policy.enforce_tier {
        BoundTier::Vacuum => (tier1a_vacuum.as_ref(), &vacuum_disks),
        BoundTier::Fiber => (tier1b_fiber.as_ref(), &fiber_disks),
        BoundTier::Calibrated { .. } | BoundTier::CalibratedLinear { .. } => {
            (tier2_calibrated.as_ref(), &cal_disks)
        }
    };

    let enforced_ok = match enforced_core {
        Some(core) if core.contained_within_target => true,
        Some(core) => {
            failure_reasons.push(format!(
                "Enforced bound tier ({}) failed containment: proven_max_radius={:.1} km > required {:.1} km{}",
                policy.enforce_tier.name(),
                core.proven_max_radius_km,
                effective_radius_km,
                if core.whole_earth { " (whole Earth feasible — no geographic constraint)" } else { "" }
            ));
            false
        }
        None => {
            failure_reasons.push(format!(
                "Enforced bound tier ({}) has no feasible region",
                policy.enforce_tier.name()
            ));
            false
        }
    };

    // Optional Polygon Geofence Evaluation (negative anti-smuggling exclusion + positive jurisdiction containment).
    let geofence_evaluation = match (&policy.geofence, enforced_core) {
        (Some(gf_pol), Some(core)) if !gf_pol.is_empty() => {
            let eval = evaluate_geofence(enforced_disks, f, core, gf_pol);
            if !eval.passed {
                failure_reasons.extend(eval.failure_reasons.iter().cloned());
            }
            Some(eval)
        }
        (Some(gf_pol), None) if !gf_pol.is_empty() => {
            failure_reasons.push("Geofence evaluation failed: no feasible region".into());
            None
        }
        _ => None,
    };

    let seed_center = tier2_calibrated
        .as_ref()
        .or(tier1b_fiber.as_ref())
        .or(tier1a_vacuum.as_ref())
        .map(|c| c.witness_centroid)
        .unwrap_or(effective_target);
    let probabilistic_estimate = Some(estimate_probabilistic_location(
        &fiber_disks,
        seed_center,
        125_000.0, // empirical median corridor speed from independent fit
        500,
    ));
    let sl_cfg = SpatialLikelihoodConfig {
        vacuum_byzantine_f: f,
        ..Default::default()
    };
    let spatial_likelihood = Some(compute_spatial_likelihood(
        &likelihood_obs,
        &sl_cfg,
        policy.bound_uncertainty,
    ));

    let geofence_failed = geofence_evaluation.as_ref().is_some_and(|g| !g.passed);
    let proof_status = if verified_count < policy.min_anchors
        || seen_clouds.len() < policy.min_cloud_providers
        || (policy.min_distinct_countries > 0 && seen_countries.len() < policy.min_distinct_countries)
    {
        ProofStatus::InsufficientVerifiedAnchors
    } else if tier1a_vacuum.is_none() {
        ProofStatus::InconsistentMeasurements
    } else if tier1a_vacuum.as_ref().is_some_and(|c| c.whole_earth) && (!enforced_ok || geofence_failed) {
        ProofStatus::NoVerifiedConstraint
    } else if !enforced_ok || geofence_failed {
        ProofStatus::ContainmentFailed
    } else if failure_reasons.is_empty() {
        ProofStatus::Verified
    } else {
        ProofStatus::PolicyRejected
    };

    Ok(ProofVerificationReport {
        overall_valid: failure_reasons.is_empty(),
        proof_status,
        hardware_attested,
        failure_reasons,
        verified_tee,
        distinct_clouds: seen_clouds.len(),
        distinct_countries: seen_countries.len(),
        verified_receipt_count: verified_count,
        submitted_receipt_count: bundle.receipts.len(),
        effective_target_location: Some(effective_target),
        effective_required_radius_km: Some(effective_radius_km),
        chip_registry_facility,
        geofence_evaluation,
        fast_path_anomalies,
        unverified_receipts,
        observed_prover_ips,
        distinct_observed_ips,
        ip_view_consistent,
        tier1a_vacuum,
        tier1b_fiber,
        tier2_calibrated,
        tier2_calibrated_error,
        probabilistic_estimate,
        spatial_likelihood,
        coordinate_provenance_note: coord_note,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::AnchorDescriptor;
    use ed25519_dalek::SigningKey;
    use pog_tee::{SoftwareDevProvider, TeeProvider, WorkloadKeypair};
    use rand::rngs::OsRng;

    #[test]
    fn test_zero_verified_anchors_returns_insufficient_not_error() {
        let sk_pub = SigningKey::generate(&mut OsRng);
        let sk_wrong = SigningKey::generate(&mut OsRng);
        let grid = AnchorGrid {
            version: "1".into(),
            grid_name: "test".into(),
            description: "test".into(),
            anchors: vec![AnchorDescriptor {
                anchor_id: "aws-fra".into(),
                cloud_provider: "aws".into(),
                region: "eu-central-1".into(),
                city: "Frankfurt".into(),
                tee_vendor: TeeVendor::AwsNitro,
                instance_type: "c6i.xlarge".into(),
                location: LatLon::new(50.11, 8.68),
                endpoint_tcp: "1.2.3.4:7443".into(),
                endpoint_udp: "1.2.3.4:7444".into(),
                https_url: None,
                public_key_hex: hex::encode(sk_pub.verifying_key().to_bytes()),
                failure_domain: None,
                asn: None,
                diagnostic_only: false,
                country_code: Some("DE".into()),
                coordinate_basis: None,
            }],
        };
        let kp = WorkloadKeypair::generate();
        let epoch = [0x11u8; 32];
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let quote = SoftwareDevProvider::new("aa".repeat(32))
            .attest(&kp.public_key_bytes(), &epoch, None)
            .unwrap();
        let mut r = AnchorReceipt {
            anchor_id: "aws-fra".into(),
            cloud_provider: "aws".into(),
            prover_pk_hex: kp.public_key_hex(),
            workload_measurement_hex: quote.workload_measurement_hex.clone(),
            epoch_challenge_hex: hex::encode(epoch),
            prover_observed_ip: "203.0.113.1".into(),
            rtt_min_us: 2_000,
            rtt_p50_us: 2_100,
            rtt_samples_us: vec![2_000],
            measured_at_unix_s: now,
            anchor_signature_hex: String::new(),
        };
        // Signed by WRONG key (simulates live restart key mismatch!)
        r.sign(&sk_wrong);

        let bundle = GeoProofBundle {
            version: 1,
            epoch_challenge_hex: hex::encode(epoch),
            client_nonce_hex: None,
            target_location: LatLon::new(50.11, 8.68),
            required_radius_km: 500.0,
            prover_quote: quote,
            receipts: vec![r],
            calibrated_velocity_km_per_s: None,
            prev_chain_hash_hex: None,
            chain_seq: 0,
            created_at_unix_s: now,
        };
        let policy = VerificationPolicy {
            tee_policy: AttestationPolicy::allow_dev_software(),
            min_anchors: 1,
            min_cloud_providers: 1,
            max_byzantine: 0,
            ..Default::default()
        };
        let rep = verify_proof_bundle(&bundle, &grid, &policy, now + 1).unwrap();
        assert!(!rep.overall_valid);
        assert_eq!(rep.proof_status, ProofStatus::InsufficientVerifiedAnchors);
        assert_eq!(rep.verified_receipt_count, 0);
        assert_eq!(rep.unverified_receipts.len(), 1);
        assert!(rep.tier1a_vacuum.is_none());
        assert!(!rep.hardware_attested);
    }

    #[test]
    fn test_calibrated_empty_never_silently_clones_fiber() {
        let sk1 = SigningKey::generate(&mut OsRng);
        let sk2 = SigningKey::generate(&mut OsRng);
        let grid = AnchorGrid {
            version: "1".into(),
            grid_name: "test".into(),
            description: "test".into(),
            anchors: vec![
                AnchorDescriptor {
                    anchor_id: "a1".into(),
                    cloud_provider: "aws".into(),
                    region: "r1".into(),
                    city: "NYC".into(),
                    tee_vendor: TeeVendor::AwsNitro,
                    instance_type: "c6i.xlarge".into(),
                    location: LatLon::new(40.71, -74.00),
                    endpoint_tcp: "1.1.1.1:7443".into(),
                    endpoint_udp: "1.1.1.1:7444".into(),
                    https_url: None,
                    public_key_hex: hex::encode(sk1.verifying_key().to_bytes()),
                    failure_domain: None,
                    asn: None,
                    diagnostic_only: false,
                    country_code: Some("US".into()),
                    coordinate_basis: None,
                },
                AnchorDescriptor {
                    anchor_id: "a2".into(),
                    cloud_provider: "gcp".into(),
                    region: "r2".into(),
                    city: "CHI".into(),
                    tee_vendor: TeeVendor::IntelTdx,
                    instance_type: "c3-standard-4".into(),
                    location: LatLon::new(41.88, -87.63),
                    endpoint_tcp: "2.2.2.2:7443".into(),
                    endpoint_udp: "2.2.2.2:7444".into(),
                    https_url: None,
                    public_key_hex: hex::encode(sk2.verifying_key().to_bytes()),
                    failure_domain: None,
                    asn: None,
                    diagnostic_only: false,
                    country_code: Some("US".into()),
                    coordinate_basis: None,
                },
            ],
        };
        let kp = WorkloadKeypair::generate();
        let epoch = [0x22u8; 32];
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let quote = SoftwareDevProvider::new("bb".repeat(32))
            .attest(&kp.public_key_bytes(), &epoch, None)
            .unwrap();
        // NYC-CHI is ~1,146 km. At 6.0 ms each:
        // - Fiber radius ~= 612 + 35 = ~650 km each -> sum 1,300 > 1,146 -> FEASIBLE!
        // - Calibrated at 140k km/s, 350us -> ~395 km each -> sum 790 < 1,146 -> EMPTY!
        let mk_receipt = |id: &str, cloud: &str, sk: &SigningKey| {
            let mut r = AnchorReceipt {
                anchor_id: id.into(),
                cloud_provider: cloud.into(),
                prover_pk_hex: kp.public_key_hex(),
                workload_measurement_hex: quote.workload_measurement_hex.clone(),
                epoch_challenge_hex: hex::encode(epoch),
                prover_observed_ip: "203.0.113.2".into(),
                rtt_min_us: 6_000,
                rtt_p50_us: 6_000,
                rtt_samples_us: vec![6_000],
                measured_at_unix_s: now,
                anchor_signature_hex: String::new(),
            };
            r.sign(sk);
            r
        };
        let receipts = vec![mk_receipt("a1", "aws", &sk1), mk_receipt("a2", "gcp", &sk2)];
        let bundle = GeoProofBundle {
            version: 1,
            epoch_challenge_hex: hex::encode(epoch),
            client_nonce_hex: None,
            target_location: LatLon::new(41.3, -80.8),
            required_radius_km: 1_000.0,
            prover_quote: quote,
            receipts,
            calibrated_velocity_km_per_s: Some(140_000.0),
            prev_chain_hash_hex: None,
            chain_seq: 0,
            created_at_unix_s: now,
        };
        let policy = VerificationPolicy {
            tee_policy: AttestationPolicy::allow_dev_software(),
            min_anchors: 2,
            min_cloud_providers: 2,
            max_byzantine: 0,
            ..Default::default()
        };
        let rep = verify_proof_bundle(&bundle, &grid, &policy, now + 1).unwrap();
        assert!(rep.tier1b_fiber.is_some());
        assert!(
            rep.tier2_calibrated.is_none(),
            "Infeasible calibrated core MUST return None, NEVER silently clone tier1b_fiber!"
        );
        assert!(rep.tier2_calibrated_error.is_some());
    }

    #[test]
    fn test_verifier_enforced_target_chip_registry_geofence_country_exclusion_and_lease() {
        use crate::committee::{select_committee, CommitteeConfig};
        use crate::lease::{issue_coarse_jurisdiction_lease, CoarseJurisdictionLease};
        use pog_geo::{builtin_jurisdiction_polygon, GeofencePolicy};

        // 4 Anchors: Tokyo (JP/aws), Osaka (JP/gcp), Seoul (KR/azure), Hong Kong (HK/aws).
        let specs = [
            ("aws-ap-northeast-1", "aws", "ap-northeast-1", "Tokyo", "JP", 35.6762, 139.6503),
            ("gcp-asia-northeast2", "gcp", "asia-northeast2", "Osaka", "JP", 34.6937, 135.5023),
            ("azure-koreacentral", "azure", "koreacentral", "Seoul", "KR", 37.5665, 126.9780),
            ("aws-ap-east-1", "aws", "ap-east-1", "Hong Kong", "HK", 22.3193, 114.1694),
        ];
        let mut keys = Vec::new();
        let mut anchors = Vec::new();
        for (idx, (id, cloud, reg, city, cc, lat, lon)) in specs.iter().enumerate() {
            let sk = SigningKey::generate(&mut OsRng);
            anchors.push(AnchorDescriptor {
                anchor_id: (*id).into(),
                cloud_provider: (*cloud).into(),
                region: (*reg).into(),
                city: (*city).into(),
                country_code: Some((*cc).into()),
                tee_vendor: TeeVendor::AwsNitro,
                instance_type: "c6i.xlarge".into(),
                location: LatLon::new(*lat, *lon),
                endpoint_tcp: format!("10.0.0.{}:7443", idx + 1),
                endpoint_udp: format!("10.0.0.{}:7444", idx + 1),
                https_url: None,
                public_key_hex: hex::encode(sk.verifying_key().to_bytes()),
                failure_domain: None,
                asn: None,
                diagnostic_only: false,
                coordinate_basis: None,
            });
            keys.push(sk);
        }
        let grid = AnchorGrid {
            version: "2".into(),
            grid_name: "apac-anti-smuggling".into(),
            description: "test".into(),
            anchors,
        };

        // 1. Striking-distance exclusion in CommitteeConfig skips HK ("HK") completely!
        let cfg = CommitteeConfig {
            committee_size: 4,
            min_cloud_providers: 2,
            excluded_anchor_countries: vec!["HK".into()],
            ..Default::default()
        };
        let tokyo = LatLon::new(35.6762, 139.6503);
        let shanghai = LatLon::new(31.2304, 121.4737);
        let sel = select_committee(&grid, "prover-pk", &[0x77u8; 32], tokyo, &cfg);
        assert!(sel.selected.iter().all(|a| a.effective_country_code().as_deref() != Some("HK")));
        assert_eq!(sel.selected.len(), 3);

        // Build honest Tokyo Prover bundle across all 4 Anchors (including HK receipt to test Verifier filtering!).
        let kp = WorkloadKeypair::generate();
        let epoch = [0x33u8; 32];
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let mut quote = SoftwareDevProvider::new("cc".repeat(32))
            .attest(&kp.public_key_bytes(), &epoch, None)
            .unwrap();
        quote.generated_at_unix_s = now;

        let mk_bundle_at = |true_loc: LatLon, claimed_loc: LatLon, claimed_radius: f64| -> GeoProofBundle {
            let receipts = grid
                .anchors
                .iter()
                .zip(keys.iter())
                .map(|(a, sk)| {
                    let d_km = true_loc.distance_km(a.location);
                    let rtt_us = ((2.0 * d_km * 1.25 / 204_000.0 + 0.0005) * 1e6).round().max(500.0) as u64;
                    let mut r = AnchorReceipt {
                        anchor_id: a.anchor_id.clone(),
                        cloud_provider: a.cloud_provider.clone(),
                        prover_pk_hex: kp.public_key_hex(),
                        workload_measurement_hex: quote.workload_measurement_hex.clone(),
                        epoch_challenge_hex: hex::encode(epoch),
                        prover_observed_ip: "203.0.113.50".into(),
                        rtt_min_us: rtt_us,
                        rtt_p50_us: rtt_us + 100,
                        rtt_samples_us: vec![rtt_us, rtt_us + 100],
                        measured_at_unix_s: now,
                        anchor_signature_hex: String::new(),
                    };
                    r.sign(sk);
                    r
                })
                .collect();
            GeoProofBundle {
                version: 1,
                epoch_challenge_hex: hex::encode(epoch),
                client_nonce_hex: None,
                target_location: claimed_loc,
                required_radius_km: claimed_radius,
                prover_quote: quote.clone(),
                receipts,
                calibrated_velocity_km_per_s: None,
                prev_chain_hash_hex: None,
                chain_seq: 0,
                created_at_unix_s: now,
            }
        };

        // 2. Honest Tokyo bundle with verifier-enforced target/radius, ChipRegistry, excluded HK, CN negative geofence!
        let tokyo_bundle = mk_bundle_at(tokyo, tokyo, 9_999.0);
        let chip_reg = ChipRegistry {
            entries: vec![RegisteredChipPolicy {
                prover_pk_hex: Some(kp.public_key_hex()),
                gpu_uuid: None,
                facility_label: "Tokyo-TY2-Export-Controlled".into(),
                expected_location: tokyo,
                max_radius_km: 600.0,
                allowed_jurisdictions: vec!["JP".into()],
            }],
        };
        let cn_poly = builtin_jurisdiction_polygon("CN").unwrap();
        let policy = VerificationPolicy {
            tee_policy: AttestationPolicy::allow_dev_software(),
            min_anchors: 3,
            min_cloud_providers: 3,
            min_distinct_countries: 2,
            max_byzantine: 0,
            enforce_tier: BoundTier::Vacuum,
            chip_registry: Some(chip_reg.clone()),
            excluded_anchor_countries: vec!["HK".into()],
            geofence: Some(GeofencePolicy {
                allowed_polygons: vec![],
                restricted_polygons: vec![cn_poly.clone()],
            }),
            ..Default::default()
        };
        let rep_ok = verify_proof_bundle(&tokyo_bundle, &grid, &policy, now + 1).unwrap();
        assert!(rep_ok.overall_valid, "Expected Tokyo to pass, failures={:?}", rep_ok.failure_reasons);
        // HK receipt MUST have been rejected by excluded_anchor_countries!
        assert_eq!(rep_ok.verified_receipt_count, 3);
        assert_eq!(rep_ok.unverified_receipts.len(), 1);
        assert_eq!(rep_ok.distinct_countries, 2); // JP + KR
        assert_eq!(rep_ok.chip_registry_facility.as_deref(), Some("Tokyo-TY2-Export-Controlled"));
        assert!(rep_ok.geofence_evaluation.as_ref().unwrap().restricted_exclusion_verified);

        // 3. Smuggled chip in Shanghai tries to lie in bundle.target_location=shanghai & bundle.required_radius_km=5000!
        // Verifier-enforced ChipRegistry + CN restricted geofence MUST REJECT!
        let shanghai_bundle = mk_bundle_at(shanghai, shanghai, 5_000.0);
        let rep_smuggled = verify_proof_bundle(&shanghai_bundle, &grid, &policy, now + 1).unwrap();
        assert!(!rep_smuggled.overall_valid, "Smuggled Shanghai chip MUST be rejected!");
        assert!(!rep_smuggled.geofence_evaluation.as_ref().unwrap().restricted_exclusion_verified);

        // 4. Privacy-preserving Coarse Jurisdiction Lease issuance + verification + on-chip monotonic expiry!
        let issuer_sk = SigningKey::generate(&mut OsRng);
        let issuer_pk_hex = hex::encode(issuer_sk.verifying_key().to_bytes());
        let lease = issue_coarse_jurisdiction_lease(
            &tokyo_bundle,
            &rep_ok,
            &issuer_sk,
            "proofofgeography.com",
            vec!["JP".into()],
            vec!["CN".into()],
            "tier1a_vacuum",
            3_600,
            false,
            now + 2,
        )
        .unwrap();
        let hdr = lease.to_header_value().unwrap();
        let decoded = CoarseJurisdictionLease::from_header_value(&hdr).unwrap();
        // Lease exposes ZERO coordinates or IPs yet verifies offline cleanly!
        assert!(decoded
            .verify(
                &issuer_pk_hex,
                Some(&kp.public_key_hex()),
                Some("JP"),
                Some("CN"),
                false,
                now + 100,
                Some(98),
            )
            .is_ok());
        // On-chip monotonic timer past 3600s MUST trigger region lock even if host wall-clock is frozen!
        assert!(decoded
            .verify(
                &issuer_pk_hex,
                Some(&kp.public_key_hex()),
                Some("JP"),
                Some("CN"),
                false,
                now + 100,
                Some(3_601),
            )
            .is_err());
        // Wrong jurisdiction or tampered lease MUST fail!
        assert!(decoded
            .verify(&issuer_pk_hex, None, Some("EU-CORE"), None, false, now + 100, Some(10))
            .is_err());
        let mut tampered = decoded.clone();
        tampered.excluded_restricted_regions.push("RU".into());
        assert!(tampered
            .verify(&issuer_pk_hex, None, None, Some("RU"), false, now + 100, Some(10))
            .is_err());
    }
}
