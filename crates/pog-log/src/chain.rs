use crate::merkle::{MerkleInclusionProof, MerkleLog, SignedTreeHead};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use pog_geo::calibration::{analyze_continuous_chain, MovementReport, TimedGeoSnapshot};
use pog_geo::{BoundTier, DiskConstraint};
use pog_proto::{
    verify_proof_bundle, AnchorGrid, GeoProofBundle, ProofVerificationReport, VerificationPolicy,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LogError {
    #[error("proof verification failed: {0}")]
    InvalidProof(String),
    #[error("hourly chain continuity error: expected prev_hash={expected:?}, got={got:?}")]
    ChainDiscontinuity {
        expected: Option<String>,
        got: Option<String>,
    },
    #[error("sequence error: expected seq={expected}, got={got}")]
    SequenceMismatch { expected: u64, got: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredGeoEntry {
    pub log_index: usize,
    pub record_hash_hex: String,
    pub bundle: GeoProofBundle,
    pub report: ProofVerificationReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAppendReceipt {
    pub record_hash_hex: String,
    pub inclusion_proof: MerkleInclusionProof,
    pub sth: SignedTreeHead,
    pub verification: ProofVerificationReport,
    pub movement_report: MovementReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverStatusView {
    pub prover_pk_hex: String,
    pub chain_length: usize,
    pub latest_record_hash_hex: String,
    pub latest_verification: ProofVerificationReport,
    pub movement_report: MovementReport,
}

/// DNS / Certificate Transparency style append-only log tracking continuous hourly
/// Proof of Geography hash-chains for every attested datacenter / GPU cluster.
pub struct ContinuousGeoLog {
    pub grid: AnchorGrid,
    pub policy: VerificationPolicy,
    signing_key: SigningKey,
    merkle: MerkleLog,
    chains: HashMap<String, Vec<StoredGeoEntry>>,
}

impl ContinuousGeoLog {
    pub fn new(grid: AnchorGrid, policy: VerificationPolicy) -> Self {
        Self {
            grid,
            policy,
            signing_key: SigningKey::generate(&mut OsRng),
            merkle: MerkleLog::new(),
            chains: HashMap::new(),
        }
    }

    pub fn signed_tree_head(&self) -> SignedTreeHead {
        let now = Utc::now().timestamp().max(0) as u64;
        self.merkle.sign_tree_head(&self.signing_key, now)
    }

    /// Verify and append a Prover's hourly (or on-demand) `GeoProofBundle`:
    /// 1. Verifies TEE quote + Anchor quorum + Byzantine (K-f)-core across all tiers.
    /// 2. Enforces strict hash-chain continuity (`prev_chain_hash_hex` & `chain_seq`).
    /// 3. Runs continuous-chain movement / mobile-datacenter analysis (catches boats, trucks, aircraft)
    ///    and computes the tighter multi-hour orthogonal minimum-RTT envelope when stationary!
    pub fn append_bundle(
        &mut self,
        bundle: GeoProofBundle,
        now_unix_s: u64,
    ) -> Result<ChainAppendReceipt, LogError> {
        let report = verify_proof_bundle(&bundle, &self.grid, &self.policy, now_unix_s)
            .map_err(|e| LogError::InvalidProof(e.to_string()))?;

        if !report.overall_valid {
            return Err(LogError::InvalidProof(report.failure_reasons.join("; ")));
        }

        let prover_id = report.verified_tee.public_key_hex.clone();
        let history = self.chains.entry(prover_id.clone()).or_default();

        // Check hash-chain continuity.
        let expected_seq = history.len() as u64;
        if bundle.chain_seq != expected_seq {
            return Err(LogError::SequenceMismatch {
                expected: expected_seq,
                got: bundle.chain_seq,
            });
        }
        let expected_prev = history.last().map(|e| e.record_hash_hex.clone());
        if bundle.prev_chain_hash_hex != expected_prev {
            return Err(LogError::ChainDiscontinuity {
                expected: expected_prev,
                got: bundle.prev_chain_hash_hex.clone(),
            });
        }

        let record_hash_hex = bundle.record_hash_hex();
        let serialized = serde_json::to_vec(&bundle).unwrap_or_default();
        let log_index = self.merkle.append(&serialized);
        let inclusion_proof = self
            .merkle
            .inclusion_proof(log_index)
            .expect("leaf just appended");
        let sth = self.merkle.sign_tree_head(&self.signing_key, now_unix_s);

        history.push(StoredGeoEntry {
            log_index,
            record_hash_hex: record_hash_hex.clone(),
            bundle,
            report: report.clone(),
        });

        let movement_report = self.compute_movement_report(&prover_id);

        Ok(ChainAppendReceipt {
            record_hash_hex,
            inclusion_proof,
            sth,
            verification: report,
            movement_report,
        })
    }

    pub fn prover_status(&self, prover_pk_hex: &str) -> Option<ProverStatusView> {
        let history = self.chains.get(prover_pk_hex)?;
        let latest = history.last()?;
        Some(ProverStatusView {
            prover_pk_hex: prover_pk_hex.to_string(),
            chain_length: history.len(),
            latest_record_hash_hex: latest.record_hash_hex.clone(),
            latest_verification: latest.report.clone(),
            movement_report: self.compute_movement_report(prover_pk_hex),
        })
    }

    pub fn prover_history(&self, prover_pk_hex: &str) -> Vec<StoredGeoEntry> {
        self.chains.get(prover_pk_hex).cloned().unwrap_or_default()
    }

    fn compute_movement_report(&self, prover_pk_hex: &str) -> MovementReport {
        let Some(history) = self.chains.get(prover_pk_hex) else {
            return MovementReport {
                snapshots_analyzed: 0,
                stationary_confirmed: false,
                converged_multi_hour_radius_km: None,
                converged_calibrated_bestline_km: None,
                converged_probabilistic: None,
                anomalies: Vec::new(),
            };
        };

        let snapshots: Vec<TimedGeoSnapshot> = history
            .iter()
            .map(|e| {
                let disks: Vec<DiskConstraint> = e
                    .bundle
                    .receipts
                    .iter()
                    .filter_map(|r| {
                        let a = self.grid.by_id(&r.anchor_id)?;
                        Some(DiskConstraint::from_rtt(
                            &a.anchor_id,
                            a.location,
                            r.rtt_min_us,
                            BoundTier::Vacuum,
                            &a.cloud_provider,
                        ))
                    })
                    .collect();
                TimedGeoSnapshot {
                    seq: e.bundle.chain_seq,
                    timestamp_unix_s: e.bundle.created_at_unix_s,
                    target: e.bundle.target_location,
                    disks,
                    centroid: e.report.tier1a_vacuum.witness_centroid,
                    proven_radius_km: e.report.tier1a_vacuum.proven_max_radius_km,
                }
            })
            .collect();

        analyze_continuous_chain(&snapshots, self.policy.max_byzantine, self.policy.enforce_tier)
    }
}
