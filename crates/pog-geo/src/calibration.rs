use crate::bounds::{BoundTier, C_CALIBRATED_DEFAULT_KM_PER_S, C_VACUUM_KM_PER_S};
use crate::byzantine::{regions_intersect, verify_byzantine_core, DiskConstraint};
use crate::sphere::LatLon;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single peer-to-peer measurement between two Anchors in the global calibration mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorPairMeasurement {
    pub from_anchor: String,
    pub from_location: LatLon,
    pub to_anchor: String,
    pub to_location: LatLon,
    pub rtt_min_us: u64,
    pub measured_at_unix_s: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CalibrationAnomaly {
    /// Measured RTT is faster than speed of light in vacuum -> Anchor coordinates spoofed or clock tampered!
    SpeedOfLightViolation {
        from_anchor: String,
        to_anchor: String,
        geodesic_km: f64,
        rtt_min_us: u64,
        min_physical_rtt_us: u64,
    },
    /// Asymmetric or severe routing anomaly flagging stale coordinates or BGP hijack.
    SevereStretchAnomaly {
        from_anchor: String,
        to_anchor: String,
        implied_velocity_km_per_s: f64,
    },
}

/// Empirical delay-distance model learned continuously from the Anchor-to-Anchor calibration mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationModel {
    pub effective_velocity_km_per_s: f64,
    pub median_stretch_factor: f64,
    pub sample_count: usize,
    pub anomalies: Vec<CalibrationAnomaly>,
    pub suspected_rogue_anchors: Vec<String>,
}

/// All-pairs Anchor calibration mesh enforcing physical self-consistency across clouds.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CalibrationMatrix {
    pub measurements: Vec<AnchorPairMeasurement>,
}

impl CalibrationMatrix {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, m: AnchorPairMeasurement) {
        self.measurements.push(m);
    }

    /// Analyze all-pairs Anchor RTTs:
    /// 1. Detect speed-of-light violations (auto-evicts spoofed or relocated Anchors).
    /// 2. Compute a conservative empirical corridor velocity for Tier 2 confidence bounds.
    pub fn analyze(&self) -> CalibrationModel {
        let mut anomalies = Vec::new();
        let mut violation_counts: HashMap<String, usize> = HashMap::new();
        let mut implied_velocities: Vec<f64> = Vec::new();

        for m in &self.measurements {
            let dist_km = m.from_location.distance_km(m.to_location);
            if dist_km < 5.0 || m.rtt_min_us == 0 {
                continue;
            }
            let min_physical_rtt_us = ((2.0 * dist_km / C_VACUUM_KM_PER_S) * 1e6) as u64;
            // Allow 15 us jitter margin for clock granularity.
            if m.rtt_min_us + 15 < min_physical_rtt_us {
                anomalies.push(CalibrationAnomaly::SpeedOfLightViolation {
                    from_anchor: m.from_anchor.clone(),
                    to_anchor: m.to_anchor.clone(),
                    geodesic_km: dist_km,
                    rtt_min_us: m.rtt_min_us,
                    min_physical_rtt_us,
                });
                *violation_counts.entry(m.from_anchor.clone()).or_insert(0) += 1;
                *violation_counts.entry(m.to_anchor.clone()).or_insert(0) += 1;
                continue;
            }

            let rtt_s = (m.rtt_min_us as f64) * 1e-6;
            let implied_v = (2.0 * dist_km) / rtt_s;
            if implied_v < 25_000.0 {
                anomalies.push(CalibrationAnomaly::SevereStretchAnomaly {
                    from_anchor: m.from_anchor.clone(),
                    to_anchor: m.to_anchor.clone(),
                    implied_velocity_km_per_s: implied_v,
                });
            } else {
                implied_velocities.push(implied_v);
            }
        }

        implied_velocities.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        // Use the 80th-percentile velocity (fast corridor) so Tier 2 stays conservative against route shortcuts.
        let effective_velocity = if implied_velocities.is_empty() {
            C_CALIBRATED_DEFAULT_KM_PER_S
        } else {
            let idx = ((implied_velocities.len() as f64) * 0.80) as usize;
            let idx = idx.min(implied_velocities.len() - 1);
            implied_velocities[idx].clamp(80_000.0, 204_000.0)
        };

        let median_v = if implied_velocities.is_empty() {
            C_CALIBRATED_DEFAULT_KM_PER_S
        } else {
            implied_velocities[implied_velocities.len() / 2]
        };
        let median_stretch_factor = (204_000.0 / median_v).max(1.0);

        // Any anchor implicated in >= 2 distinct speed-of-light violations is flagged rogue.
        let mut suspected_rogue_anchors: Vec<String> = violation_counts
            .into_iter()
            .filter(|(_, count)| *count >= 2)
            .map(|(id, _)| id)
            .collect();
        suspected_rogue_anchors.sort();

        CalibrationModel {
            effective_velocity_km_per_s: effective_velocity,
            median_stretch_factor,
            sample_count: implied_velocities.len(),
            anomalies,
            suspected_rogue_anchors,
        }
    }
}

/// A timestamped geographic proof snapshot from a Prover's continuous hourly chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimedGeoSnapshot {
    pub seq: u64,
    pub timestamp_unix_s: u64,
    pub target: LatLon,
    pub disks: Vec<DiskConstraint>,
    pub centroid: LatLon,
    pub proven_radius_km: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MovementAnomaly {
    /// Two consecutive or historical snapshots have completely disjoint feasible regions on S^2.
    /// Proves the physical hardware relocated (e.g., truck, cargo ship, aircraft, or illicit transfer).
    PhysicalRelocationDetected {
        from_seq: u64,
        to_seq: u64,
        elapsed_seconds: u64,
        centroid_displacement_km: f64,
        implied_speed_km_per_h: f64,
    },
    /// Large sudden jump in RTT envelope consistent with mobile link (e.g., ship-at-sea / Starlink switch).
    MobileLinkJitterJump {
        seq: u64,
        previous_radius_km: f64,
        current_radius_km: f64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MovementReport {
    pub snapshots_analyzed: usize,
    pub stationary_confirmed: bool,
    /// Converged tighter radius obtained by taking the per-anchor minimum RTT across the
    /// stationary continuous chain window (eliminating transient congestion across orthogonal axes).
    pub converged_multi_hour_radius_km: Option<f64>,
    pub anomalies: Vec<MovementAnomaly>,
}

/// Analyze a Prover's continuous hourly chain to:
/// 1. Detect physical hardware relocation (mobile datacenter on a boat, aircraft, or truck).
/// 2. When stationary, fuse the minimum-RTT envelope across hours from 3-4 orthogonal directions
///    to produce an increasingly tight, high-confidence proven geography bound!
pub fn analyze_continuous_chain(
    snapshots: &[TimedGeoSnapshot],
    max_byzantine: usize,
    tier: BoundTier,
) -> MovementReport {
    if snapshots.is_empty() {
        return MovementReport {
            snapshots_analyzed: 0,
            stationary_confirmed: false,
            converged_multi_hour_radius_km: None,
            anomalies: Vec::new(),
        };
    }

    let mut anomalies = Vec::new();
    let baseline = &snapshots[0];

    for pair in snapshots.windows(2) {
        let prev = &pair[0];
        let curr = &pair[1];

        // Check both consecutive disjointness AND drift from the baseline anchor point.
        let disjoint_prev = !regions_intersect(&prev.disks, &curr.disks);
        let disjoint_base = !regions_intersect(&baseline.disks, &curr.disks);

        if disjoint_prev || disjoint_base {
            let ref_snap = if disjoint_prev { prev } else { baseline };
            let elapsed = curr.timestamp_unix_s.saturating_sub(ref_snap.timestamp_unix_s).max(1);
            let disp_km = ref_snap.centroid.distance_km(curr.centroid);
            let speed_kmh = disp_km / (elapsed as f64 / 3600.0);
            anomalies.push(MovementAnomaly::PhysicalRelocationDetected {
                from_seq: ref_snap.seq,
                to_seq: curr.seq,
                elapsed_seconds: elapsed,
                centroid_displacement_km: disp_km,
                implied_speed_km_per_h: speed_kmh,
            });
        } else if curr.proven_radius_km > prev.proven_radius_km * 2.5
            && (curr.proven_radius_km - prev.proven_radius_km) > 300.0
        {
            anomalies.push(MovementAnomaly::MobileLinkJitterJump {
                seq: curr.seq,
                previous_radius_km: prev.proven_radius_km,
                current_radius_km: curr.proven_radius_km,
            });
        }
    }

    let stationary_confirmed = anomalies
        .iter()
        .all(|a| !matches!(a, MovementAnomaly::PhysicalRelocationDetected { .. }));

    // If stationary, build the multi-hour minimum-RTT envelope per Anchor!
    let converged_multi_hour_radius_km = if stationary_confirmed {
        let mut best_per_anchor: HashMap<String, DiskConstraint> = HashMap::new();
        for snap in snapshots {
            for d in &snap.disks {
                best_per_anchor
                    .entry(d.anchor_id.clone())
                    .and_modify(|existing| {
                        if d.rtt_min_us < existing.rtt_min_us {
                            *existing = DiskConstraint::from_rtt(
                                d.anchor_id.clone(),
                                d.anchor_location,
                                d.rtt_min_us,
                                tier,
                                d.cloud_provider.clone(),
                            );
                        }
                    })
                    .or_insert_with(|| {
                        DiskConstraint::from_rtt(
                            d.anchor_id.clone(),
                            d.anchor_location,
                            d.rtt_min_us,
                            tier,
                            d.cloud_provider.clone(),
                        )
                    });
            }
        }
        let merged_disks: Vec<DiskConstraint> = best_per_anchor.into_values().collect();
        let f = max_byzantine.min(merged_disks.len().saturating_sub(1));
        verify_byzantine_core(
            &merged_disks,
            f,
            baseline.target,
            f64::MAX,
            Some(baseline.centroid),
        )
        .ok()
        .map(|r| r.proven_max_radius_km)
    } else {
        None
    };

    MovementReport {
        snapshots_analyzed: snapshots.len(),
        stationary_confirmed,
        converged_multi_hour_radius_km,
        anomalies,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calibration_detects_rogue_anchor_coordinates() {
        let mut mat = CalibrationMatrix::new();
        let tokyo = LatLon::new(35.6762, 139.6503);
        let frankfurt = LatLon::new(50.1109, 8.6821);
        let ashburn = LatLon::new(39.0438, -77.4874);

        // Honest Tokyo <-> Frankfurt (~9,360 km, realistic ~140 ms).
        mat.record(AnchorPairMeasurement {
            from_anchor: "gcp-tokyo".into(),
            from_location: tokyo,
            to_anchor: "aws-fra".into(),
            to_location: frankfurt,
            rtt_min_us: 140_000,
            measured_at_unix_s: 1000,
        });
        // Rogue anchor claims to be in Tokyo, but responds to Frankfurt and Ashburn in 10 ms!
        mat.record(AnchorPairMeasurement {
            from_anchor: "rogue-fake-tokyo".into(),
            from_location: tokyo,
            to_anchor: "aws-fra".into(),
            to_location: frankfurt,
            rtt_min_us: 10_000,
            measured_at_unix_s: 1000,
        });
        mat.record(AnchorPairMeasurement {
            from_anchor: "rogue-fake-tokyo".into(),
            from_location: tokyo,
            to_anchor: "aws-iad".into(),
            to_location: ashburn,
            rtt_min_us: 12_000,
            measured_at_unix_s: 1000,
        });

        let model = mat.analyze();
        assert!(model
            .suspected_rogue_anchors
            .contains(&"rogue-fake-tokyo".to_string()));
    }

    #[test]
    fn test_mobile_boat_airplane_relocation_detection() {
        // Hour 0: Hardware verified in Ashburn, VA (~1 ms to Ashburn anchor).
        let ashburn = LatLon::new(39.0438, -77.4874);
        let london = LatLon::new(51.5074, -0.1278);

        let snap0 = TimedGeoSnapshot {
            seq: 0,
            timestamp_unix_s: 1_700_000_000,
            target: ashburn,
            disks: vec![DiskConstraint::from_rtt(
                "aws-iad",
                ashburn,
                1_200,
                BoundTier::Vacuum,
                "aws",
            )],
            centroid: ashburn,
            proven_radius_km: 180.0,
        };
        // Hour 8: Hardware flown to London (~1.2 ms to London anchor -> disjoint from Ashburn!).
        let snap1 = TimedGeoSnapshot {
            seq: 1,
            timestamp_unix_s: 1_700_000_000 + 8 * 3600,
            target: london,
            disks: vec![DiskConstraint::from_rtt(
                "gcp-lhr",
                london,
                1_200,
                BoundTier::Vacuum,
                "gcp",
            )],
            centroid: london,
            proven_radius_km: 180.0,
        };

        let report = analyze_continuous_chain(&[snap0, snap1], 0, BoundTier::Vacuum);
        assert!(!report.stationary_confirmed);
        assert!(matches!(
            report.anomalies.first(),
            Some(MovementAnomaly::PhysicalRelocationDetected { .. })
        ));
    }
}
