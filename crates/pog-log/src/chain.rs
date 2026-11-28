use crate::merkle::{MerkleInclusionProof, MerkleLog, SignedTreeHead};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use pog_geo::calibration::{
    analyze_continuous_chain_with_cadence, MovementReport, TimedGeoSnapshot,
};
use pog_geo::{BoundTier, DiskConstraint, LatLon};
use pog_proto::{
    verify_proof_bundle, AnchorGrid, GeoProofBundle, ProofVerificationReport, VerificationPolicy,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
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

/// Alert emitted when a previously active Prover stops submitting scheduled heartbeats
/// (Brass & Aarne pp. 8, 11: blocking / going-dark attack detection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SilentProverAlert {
    pub prover_pk_hex: String,
    pub last_seen_unix_s: u64,
    pub silent_for_seconds: u64,
    pub max_silence_seconds: u64,
    pub last_known_centroid: LatLon,
}

/// Detected physical co-location cluster of multiple Provers sharing highly correlated
/// Constellation RTT vectors (Brass & Aarne p. 8: undeclared compute cluster detection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterMembership {
    pub cluster_id: String,
    pub prover_pks: Vec<String>,
    pub shared_anchor_count: usize,
    pub max_pairwise_median_rtt_diff_ms: f64,
    pub estimated_centroid: LatLon,
}

/// Alert emitted when a Prover registered as part of an expected rack/cluster suddenly diverges
/// from its rackmates' Constellation RTT vector (catches a single chip smuggled out of a cluster!).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RackDivergenceAlert {
    pub cluster_id: String,
    pub prover_pk_hex: String,
    pub shared_anchor_count: usize,
    pub median_rtt_divergence_ms: f64,
    pub max_anchor_divergence_ms: f64,
    pub max_diverged_anchor_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterAnalysisReport {
    pub total_active_provers: usize,
    pub detected_clusters: Vec<ClusterMembership>,
    pub rack_divergence_alerts: Vec<RackDivergenceAlert>,
}

/// DNS / Certificate Transparency style append-only log tracking continuous hourly
/// Proof of Geography hash-chains for every attested datacenter / GPU cluster.
pub struct ContinuousGeoLog {
    pub grid: AnchorGrid,
    pub policy: VerificationPolicy,
    /// Maximum expected heartbeat interval (seconds) for `ContinuityGapDetected` alerts (default 7,200 s).
    pub max_heartbeat_cadence_seconds: u64,
    signing_key: SigningKey,
    merkle: MerkleLog,
    chains: HashMap<String, Vec<StoredGeoEntry>>,
    /// Optional declared rack/cluster groups (`cluster_id -> [prover_pk_hex...]`) monitored for single-chip divergence.
    expected_clusters: HashMap<String, Vec<String>>,
}

impl ContinuousGeoLog {
    pub fn new(grid: AnchorGrid, policy: VerificationPolicy) -> Self {
        Self {
            grid,
            policy,
            max_heartbeat_cadence_seconds: 7_200,
            signing_key: SigningKey::generate(&mut OsRng),
            merkle: MerkleLog::new(),
            chains: HashMap::new(),
            expected_clusters: HashMap::new(),
        }
    }

    /// Declare a group of provers expected to sit in the same physical rack/cluster so
    /// `analyze_prover_clusters()` flags if any individual chip diverges from its rackmates.
    pub fn register_expected_cluster(&mut self, cluster_id: impl Into<String>, prover_pks: Vec<String>) {
        self.expected_clusters.insert(cluster_id.into(), prover_pks);
    }

    /// Detect registered/active provers that have gone dark for longer than `max_silence_seconds`.
    pub fn detect_silent_provers(
        &self,
        now_unix_s: u64,
        max_silence_seconds: u64,
    ) -> Vec<SilentProverAlert> {
        let mut alerts = Vec::new();
        for (pk, history) in &self.chains {
            let Some(last) = history.last() else {
                continue;
            };
            let last_ts = last.bundle.created_at_unix_s;
            let silent_for = now_unix_s.saturating_sub(last_ts);
            if silent_for > max_silence_seconds {
                let centroid = last
                    .report
                    .tier1a_vacuum
                    .as_ref()
                    .map(|c| c.witness_centroid)
                    .unwrap_or(last.bundle.target_location);
                alerts.push(SilentProverAlert {
                    prover_pk_hex: pk.clone(),
                    last_seen_unix_s: last_ts,
                    silent_for_seconds: silent_for,
                    max_silence_seconds,
                    last_known_centroid: centroid,
                });
            }
        }
        alerts.sort_by_key(|a| std::cmp::Reverse(a.silent_for_seconds));
        alerts
    }

    /// Compare latest Constellation min-RTT vectors across all active provers to:
    /// 1. Detect co-located multi-chip compute clusters (even undeclared ones), where pairwise
    ///    median per-Anchor RTT difference `<= colocation_rtt_threshold_ms` across `>= min_shared_anchors`.
    /// 2. Detect rack divergence if a chip in a registered cluster diverges from its rackmates'
    ///    median RTT vector by `> rack_divergence_threshold_ms`.
    pub fn analyze_prover_clusters(
        &self,
        colocation_rtt_threshold_ms: f64,
        min_shared_anchors: usize,
        rack_divergence_threshold_ms: f64,
    ) -> ClusterAnalysisReport {
        // Build latest Anchor->rtt_ms map and centroid per prover.
        let mut rtt_vecs: HashMap<String, HashMap<String, f64>> = HashMap::new();
        let mut centroids: HashMap<String, LatLon> = HashMap::new();
        for (pk, history) in &self.chains {
            if let Some(last) = history.last() {
                let map: HashMap<String, f64> = last
                    .bundle
                    .receipts
                    .iter()
                    .map(|r| (r.anchor_id.clone(), (r.rtt_min_us as f64) * 1e-3))
                    .collect();
                rtt_vecs.insert(pk.clone(), map);
                let c = last
                    .report
                    .tier1a_vacuum
                    .as_ref()
                    .map(|v| v.witness_centroid)
                    .unwrap_or(last.bundle.target_location);
                centroids.insert(pk.clone(), c);
            }
        }

        let mut pks: Vec<String> = rtt_vecs.keys().cloned().collect();
        pks.sort();
        let n = pks.len();

        let pairwise_diff = |a: &str, b: &str| -> Option<(usize, f64)> {
            let ma = rtt_vecs.get(a)?;
            let mb = rtt_vecs.get(b)?;
            let mut diffs: Vec<f64> = ma
                .iter()
                .filter_map(|(aid, va)| mb.get(aid).map(|vb| (va - vb).abs()))
                .collect();
            if diffs.len() < min_shared_anchors {
                return None;
            }
            diffs.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
            Some((diffs.len(), diffs[diffs.len() / 2]))
        };

        // Connected components over co-located pairs.
        let mut adj: HashMap<usize, Vec<(usize, usize, f64)>> = HashMap::new();
        for i in 0..n {
            for j in (i + 1)..n {
                if let Some((shared, med_diff)) = pairwise_diff(&pks[i], &pks[j]) {
                    if med_diff <= colocation_rtt_threshold_ms {
                        adj.entry(i).or_default().push((j, shared, med_diff));
                        adj.entry(j).or_default().push((i, shared, med_diff));
                    }
                }
            }
        }

        let mut visited = vec![false; n];
        let mut detected_clusters = Vec::new();
        for start in 0..n {
            if visited[start] || !adj.contains_key(&start) {
                continue;
            }
            let mut comp = Vec::new();
            let mut stack = vec![start];
            visited[start] = true;
            let mut min_shared = usize::MAX;
            let mut max_diff = 0.0_f64;
            while let Some(u) = stack.pop() {
                comp.push(u);
                if let Some(nbrs) = adj.get(&u) {
                    for &(v, sh, df) in nbrs {
                        min_shared = min_shared.min(sh);
                        max_diff = max_diff.max(df);
                        if !visited[v] {
                            visited[v] = true;
                            stack.push(v);
                        }
                    }
                }
            }
            if comp.len() >= 2 {
                comp.sort_unstable();
                let members: Vec<String> = comp.iter().map(|&idx| pks[idx].clone()).collect();
                let mut lat_sum = 0.0;
                let mut lon_sum = 0.0;
                for m in &members {
                    if let Some(c) = centroids.get(m) {
                        lat_sum += c.lat;
                        lon_sum += c.lon;
                    }
                }
                let est = LatLon::new(lat_sum / (members.len() as f64), lon_sum / (members.len() as f64));
                detected_clusters.push(ClusterMembership {
                    cluster_id: format!("auto-cluster-{}", detected_clusters.len() + 1),
                    prover_pks: members,
                    shared_anchor_count: if min_shared == usize::MAX { 0 } else { min_shared },
                    max_pairwise_median_rtt_diff_ms: max_diff,
                    estimated_centroid: est,
                });
            }
        }

        // Check declared rack/clusters for single-chip divergence against cluster median RTT vector.
        let mut rack_divergence_alerts = Vec::new();
        for (cid, members) in &self.expected_clusters {
            let active: Vec<&String> = members.iter().filter(|m| rtt_vecs.contains_key(*m)).collect();
            if active.len() < 2 {
                continue;
            }
            let mut all_anchors = BTreeSet::new();
            for m in &active {
                for aid in rtt_vecs[*m].keys() {
                    all_anchors.insert(aid.clone());
                }
            }
            let mut cluster_median: HashMap<String, f64> = HashMap::new();
            for aid in &all_anchors {
                let mut vals: Vec<f64> = active
                    .iter()
                    .filter_map(|m| rtt_vecs[*m].get(aid).copied())
                    .collect();
                if vals.len() >= 2 {
                    vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                    cluster_median.insert(aid.clone(), vals[vals.len() / 2]);
                }
            }

            for m in &active {
                let mut diffs: Vec<(String, f64)> = rtt_vecs[*m]
                    .iter()
                    .filter_map(|(aid, &v)| {
                        cluster_median.get(aid).map(|&med| (aid.clone(), (v - med).abs()))
                    })
                    .collect();
                if diffs.len() < min_shared_anchors {
                    continue;
                }
                diffs.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
                let med_div = diffs[diffs.len() / 2].1;
                let (max_aid, max_div) = diffs.last().cloned().unwrap_or_default();
                if med_div > rack_divergence_threshold_ms {
                    rack_divergence_alerts.push(RackDivergenceAlert {
                        cluster_id: cid.clone(),
                        prover_pk_hex: (*m).clone(),
                        shared_anchor_count: diffs.len(),
                        median_rtt_divergence_ms: med_div,
                        max_anchor_divergence_ms: max_div,
                        max_diverged_anchor_id: max_aid,
                    });
                }
            }
        }

        ClusterAnalysisReport {
            total_active_provers: n,
            detected_clusters,
            rack_divergence_alerts,
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
                let (centroid, proven_radius_km) = match e.report.tier1a_vacuum.as_ref() {
                    Some(v) => (v.witness_centroid, v.proven_max_radius_km),
                    None => (e.bundle.target_location, pog_geo::HALF_CIRCUMFERENCE_KM),
                };
                TimedGeoSnapshot {
                    seq: e.bundle.chain_seq,
                    timestamp_unix_s: e.bundle.created_at_unix_s,
                    target: e.bundle.target_location,
                    disks,
                    centroid,
                    proven_radius_km,
                }
            })
            .collect();

        analyze_continuous_chain_with_cadence(
            &snapshots,
            self.policy.max_byzantine,
            self.policy.enforce_tier,
            self.max_heartbeat_cadence_seconds,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pog_geo::LatLon;
    use pog_proto::{AnchorDescriptor, AnchorReceipt};
    use pog_tee::{AttestationPolicy, SoftwareDevProvider, TeeProvider, TeeVendor, WorkloadKeypair};

    fn make_test_grid() -> (AnchorGrid, Vec<(String, SigningKey)>) {
        let specs = [
            ("aws-iad", "aws", "US", 39.018, -77.459),
            ("gcp-iad", "gcp", "US", 39.0438, -77.4874),
            ("gcp-dsm", "gcp", "US", 41.2619, -95.8608),
            ("aws-sjc", "aws", "US", 37.3382, -121.8863),
        ];
        let mut anchors = Vec::new();
        let mut keys = Vec::new();
        for (id, cloud, cc, lat, lon) in specs {
            let sk = SigningKey::generate(&mut OsRng);
            anchors.push(AnchorDescriptor {
                anchor_id: id.into(),
                cloud_provider: cloud.into(),
                region: id.into(),
                city: id.into(),
                tee_vendor: TeeVendor::AwsNitro,
                instance_type: "c6g.large".into(),
                location: LatLon::new(lat, lon),
                endpoint_tcp: "127.0.0.1:7443".into(),
                endpoint_udp: "127.0.0.1:7444".into(),
                https_url: None,
                public_key_hex: hex::encode(sk.verifying_key().to_bytes()),
                failure_domain: None,
                asn: None,
                diagnostic_only: false,
                country_code: Some(cc.into()),
                coordinate_basis: None,
            });
            keys.push((id.to_string(), sk));
        }
        (
            AnchorGrid {
                version: "1".into(),
                grid_name: "test".into(),
                description: "test".into(),
                anchors,
            },
            keys,
        )
    }

    fn make_bundle(
        kp: &WorkloadKeypair,
        keys: &[(String, SigningKey)],
        rtts_us: &[u64; 4],
        target: LatLon,
        ts: u64,
        seq: u64,
        prev_hash: Option<String>,
    ) -> GeoProofBundle {
        let epoch = [seq as u8; 32];
        let quote = SoftwareDevProvider::new("cc".repeat(32))
            .attest(&kp.public_key_bytes(), &epoch, None)
            .unwrap();
        let mut quote = quote;
        quote.generated_at_unix_s = ts;
        let receipts = keys
            .iter()
            .zip(rtts_us.iter())
            .map(|((aid, sk), &rtt)| {
                let mut r = AnchorReceipt {
                    anchor_id: aid.clone(),
                    cloud_provider: if aid.starts_with("aws") { "aws".into() } else { "gcp".into() },
                    prover_pk_hex: kp.public_key_hex(),
                    workload_measurement_hex: quote.workload_measurement_hex.clone(),
                    epoch_challenge_hex: hex::encode(epoch),
                    prover_observed_ip: "198.51.100.9".into(),
                    rtt_min_us: rtt,
                    rtt_p50_us: rtt,
                    rtt_samples_us: vec![rtt],
                    measured_at_unix_s: ts,
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
            target_location: target,
            required_radius_km: 10_000.0,
            prover_quote: quote,
            receipts,
            calibrated_velocity_km_per_s: None,
            prev_chain_hash_hex: prev_hash,
            chain_seq: seq,
            created_at_unix_s: ts,
        }
    }

    #[test]
    fn test_silent_prover_colocated_clusters_and_rack_divergence_detection() {
        let (grid, keys) = make_test_grid();
        let policy = VerificationPolicy {
            tee_policy: AttestationPolicy::allow_dev_software(),
            min_anchors: 4,
            min_cloud_providers: 2,
            max_byzantine: 1,
            ..Default::default()
        };
        let mut log = ContinuousGeoLog::new(grid, policy);
        let now = 1_800_000_000u64;
        let ashburn = LatLon::new(39.0438, -77.4874);

        let kp_a = WorkloadKeypair::generate();
        let kp_b = WorkloadKeypair::generate();
        let kp_rogue = WorkloadKeypair::generate();

        // Prover A & B sit in the same Ashburn rack (~0.2 ms RTT delta across all 4 Anchors).
        log.append_bundle(
            make_bundle(&kp_a, &keys, &[1_800, 1_900, 24_000, 58_000], ashburn, now, 0, None),
            now + 1,
        )
        .unwrap();
        log.append_bundle(
            make_bundle(&kp_b, &keys, &[1_950, 2_000, 24_300, 58_200], ashburn, now, 0, None),
            now + 1,
        )
        .unwrap();
        // Prover Rogue was registered in the same rack, but actually sits near San Jose!
        log.append_bundle(
            make_bundle(
                &kp_rogue,
                &keys,
                &[58_500, 58_800, 44_000, 1_900],
                LatLon::new(37.3382, -121.8863),
                now,
                0,
                None,
            ),
            now + 1,
        )
        .unwrap();

        log.register_expected_cluster(
            "rack-ashburn-01",
            vec![kp_a.public_key_hex(), kp_b.public_key_hex(), kp_rogue.public_key_hex()],
        );

        // 1. Cluster analysis detects A+B co-located AND flags kp_rogue diverging from rack-ashburn-01!
        let report = log.analyze_prover_clusters(1.5, 4, 5.0);
        assert_eq!(report.total_active_provers, 3);
        assert_eq!(report.detected_clusters.len(), 1);
        assert_eq!(report.detected_clusters[0].prover_pks.len(), 2);
        assert!(report.detected_clusters[0].prover_pks.contains(&kp_a.public_key_hex()));
        assert!(report.detected_clusters[0].prover_pks.contains(&kp_b.public_key_hex()));
        assert_eq!(report.rack_divergence_alerts.len(), 1);
        assert_eq!(report.rack_divergence_alerts[0].prover_pk_hex, kp_rogue.public_key_hex());

        // 2. Silence / going-dark detection: 3 hours later with max_silence=3600s flags all 3 silent provers!
        let silent = log.detect_silent_provers(now + 10_800, 3_600);
        assert_eq!(silent.len(), 3);
        assert!(silent.iter().all(|s| s.silent_for_seconds == 10_800));
    }
}
