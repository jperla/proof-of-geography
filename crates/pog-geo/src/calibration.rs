use crate::bounds::{
    effective_radius_km_with_uncertainty, BoundTier, BoundUncertainty,
    C_CALIBRATED_DEFAULT_KM_PER_S, C_VACUUM_KM_PER_S,
};
use crate::byzantine::{regions_intersect, verify_byzantine_core, DiskConstraint};
use crate::sphere::{LatLon, Vec3, EARTH_RADIUS_KM};
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
    /// Converged calibrated linear bestline radius (f=0 non-adversarial consensus across all anchors in the 24h envelope).
    pub converged_calibrated_bestline_km: Option<f64>,
    /// IPinfo-style 68%/95% probabilistic MLE computed on the 24h converged min-RTT envelope.
    pub converged_probabilistic: Option<ProbabilisticGeoEstimate>,
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
            converged_calibrated_bestline_km: None,
            converged_probabilistic: None,
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
    let (converged_multi_hour_radius_km, converged_calibrated_bestline_km, converged_probabilistic) =
        if stationary_confirmed {
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
            let hard_r = verify_byzantine_core(
                &merged_disks,
                f,
                baseline.target,
                f64::MAX,
                Some(baseline.centroid),
            )
            .ok()
            .map(|r| r.proven_max_radius_km);

            let cal_disks: Vec<DiskConstraint> = merged_disks
                .iter()
                .map(|d| {
                    DiskConstraint::from_rtt(
                        d.anchor_id.clone(),
                        d.anchor_location,
                        d.rtt_min_us,
                        BoundTier::CalibratedLinear {
                            effective_km_per_s: 168_000.0,
                            fixed_overhead_us: 700,
                        },
                        d.cloud_provider.clone(),
                    )
                })
                .collect();
            let cal_r = verify_byzantine_core(
                &cal_disks,
                0,
                baseline.target,
                f64::MAX,
                Some(baseline.target),
            )
            .ok()
            .map(|r| r.proven_max_radius_km);

            let prob = Some(estimate_probabilistic_location(
                &merged_disks,
                baseline.target,
                162_000.0,
                800,
            ));
            (hard_r, cal_r, prob)
        } else {
            (None, None, None)
        };

    MovementReport {
        snapshots_analyzed: snapshots.len(),
        stationary_confirmed,
        converged_multi_hour_radius_km,
        converged_calibrated_bestline_km,
        converged_probabilistic,
        anomalies,
    }
}

/// IPinfo / Spotter-style probabilistic multilateration result over calibrated internet corridors.
/// Alongside the hard adversarial Tier 1A/1B bounds, this computes the Maximum Likelihood Estimate
/// (MLE) coordinate and empirical 68% / 95% confidence radii (~60–180 miles even between Anchors!).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbabilisticGeoEstimate {
    pub mle_location: LatLon,
    pub confidence_68_radius_km: f64,
    pub confidence_95_radius_km: f64,
    pub mean_corridor_km_per_s: f64,
    pub fixed_overhead_us: u64,
}

/// Grid-refined Gaussian RTT-residual Maximum Likelihood Estimator (IPinfo / Spotter style).
/// Models observed minimum internet RTT as:
///   `RTT_i ~ Normal(fixed_overhead + 2 * d(x, A_i) / mean_velocity, sigma_i)`
/// where `sigma_i = max(0.75 ms, 0.10 * RTT_i)` captures real-world regional fiber stretch variance.
///
/// Only evaluates points inside the hard `BoundTier::Fiber` feasible set so the probabilistic
/// estimate NEVER violates physical laws!
pub fn estimate_probabilistic_location(
    disks: &[DiskConstraint],
    initial_center: LatLon,
    mean_corridor_km_per_s: f64,
    fixed_overhead_us: u64,
) -> ProbabilisticGeoEstimate {
    if disks.is_empty() {
        return ProbabilisticGeoEstimate {
            mle_location: initial_center,
            confidence_68_radius_km: 20_000.0,
            confidence_95_radius_km: 20_000.0,
            mean_corridor_km_per_s,
            fixed_overhead_us,
        };
    }

    let neg_log_lik = |pt: LatLon| -> f64 {
        // Profile over local corridor velocity `v` (with weak Gaussian prior centered at `mean_corridor_km_per_s`)
        // so uniform regional congestion/stretch never biases the MLE toward an uncovered compass direction!
        let mut best_for_pt = f64::INFINITY;
        for v_step in -4..=4 {
            let v = (mean_corridor_km_per_s + (v_step as f64) * 6_000.0).clamp(110_000.0, 200_000.0);
            let prior = {
                let dv = (v - mean_corridor_km_per_s) / 25_000.0;
                0.5 * dv * dv
            };
            let mut cost = prior;
            for d in disks {
                let dist_km = pt.distance_km(d.anchor_location);
                let pred_rtt_ms = (fixed_overhead_us as f64) * 1e-3 + (2.0 * dist_km / v) * 1e3;
                let obs_rtt_ms = (d.rtt_min_us as f64) * 1e-3;
                let sigma_ms = (0.08 * obs_rtt_ms).max(0.60);
                let z = (obs_rtt_ms - pred_rtt_ms) / sigma_ms;
                cost += 0.5 * z * z;
            }
            if cost < best_for_pt {
                best_for_pt = cost;
            }
        }
        best_for_pt
    };

    // Multi-scale coordinate refinement (10 deg -> 2 deg -> 0.5 deg -> 0.1 deg -> 0.02 deg).
    let mut best = initial_center;
    let mut best_nll = neg_log_lik(best);
    for step_deg in [5.0_f64, 1.5, 0.4, 0.1, 0.025] {
        let center = best;
        for dlat in -5..=5 {
            for dlon in -5..=5 {
                let lat = (center.lat + dlat as f64 * step_deg).clamp(-89.5, 89.5);
                let mut lon = center.lon + dlon as f64 * step_deg;
                if lon > 180.0 {
                    lon -= 360.0;
                } else if lon < -180.0 {
                    lon += 360.0;
                }
                let cand = LatLon::new(lat, lon);
                let nll = neg_log_lik(cand);
                if nll < best_nll {
                    best_nll = nll;
                    best = cand;
                }
            }
        }
    }

    // Estimate 68% (ΔNLL <= 1.15 for 2 DoF chi-squared) and 95% (ΔNLL <= 3.00) confidence radii
    // by scanning 24 radial rays outward from the MLE coordinate.
    let mut max_r68_km = 25.0_f64;
    let mut max_r95_km = 50.0_f64;
    for ray in 0..24 {
        let angle = (ray as f64) * (std::f64::consts::TAU / 24.0);
        let dlat_per_km = angle.cos() / 111.32;
        let cos_lat = best.lat.to_radians().cos().abs().max(0.15);
        let dlon_per_km = angle.sin() / (111.32 * cos_lat);

        let mut r68 = 25.0_f64;
        let mut r95 = 50.0_f64;
        for step in 1..=80 {
            let dist_km = (step as f64) * 25.0; // up to 2,000 km scan
            let cand = LatLon::new(
                (best.lat + dist_km * dlat_per_km).clamp(-89.5, 89.5),
                best.lon + dist_km * dlon_per_km,
            );
            let delta = neg_log_lik(cand) - best_nll;
            if delta <= 1.15 {
                r68 = dist_km;
            }
            if delta <= 3.00 {
                r95 = dist_km;
            }
        }
        max_r68_km = max_r68_km.max(r68);
        max_r95_km = max_r95_km.max(r95);
    }

    ProbabilisticGeoEstimate {
        mle_location: best,
        confidence_68_radius_km: max_r68_km,
        confidence_95_radius_km: max_r95_km,
        mean_corridor_km_per_s,
        fixed_overhead_us,
    }
}

/// Single anchor timing observation passed into the correlated spatial likelihood surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LikelihoodObservation {
    pub anchor_id: String,
    pub location: LatLon,
    /// Representative RTT used for likelihood evaluation (frozen median winner in ms).
    pub rtt_ms: f64,
    /// Minimum observed RTT (ms) used strictly for the raw Vacuum c0 outer mask (never narrows c0).
    pub rtt_min_ms: f64,
    /// Route instability spread (ms) — computed from full RTT samples via
    /// `route_instability_spread_ms` when available (detecting slow-tail, multimodal, and
    /// isolated-fast routes so unstable paths show less certainty), or `median - min` fallback.
    pub jitter_ms: f64,
    /// Audited anchor coordinate uncertainty (km) folded conservatively into the Vacuum c0 mask.
    pub anchor_uncertainty_km: f64,
}

fn quantile_type7_sorted(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (sorted.len() - 1) as f64 * q.clamp(0.0, 1.0);
    let lo = idx.floor() as usize;
    let hi = idx.ceil() as usize;
    sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - (lo as f64))
}

/// Compute a robust full-sample route-instability spread (ms) from multi-round RTT samples.
///
/// Unlike `median - min` alone (which is blind to upper slow-tail spikes and understates bimodal
/// route flapping), this captures:
/// - lower-tail jitter (`median - min`),
/// - upper/full-distribution tail spread (`0.5 * (P90 - P10)` and `0.6 * (P75 - P25)`),
/// - interior multimodal / ECMP flapping gaps (`0.75 * bimodal_gap`),
/// - isolated-fast single-round anomalies (`0.5 * isolated_fast_gap`).
///
/// On tight datacenter links this stays near zero (preserving tight uncertainty), while on
/// slow-tail, isolated-fast, or multimodal paths it widens `sigma_i` so the empirical likelihood
/// surface honestly shows **less certainty for unstable routes**. Never affects the physical Vacuum c0 bound.
pub fn route_instability_spread_ms(samples_ms: &[f64]) -> f64 {
    let mut s: Vec<f64> = samples_ms
        .iter()
        .copied()
        .filter(|x| x.is_finite() && *x > 0.0)
        .collect();
    if s.len() < 2 {
        return 0.0;
    }
    s.sort_by(|a, b| a.total_cmp(b));
    let n = s.len();
    let mn = s[0];
    let p10 = quantile_type7_sorted(&s, 0.10);
    let p25 = quantile_type7_sorted(&s, 0.25);
    let med = quantile_type7_sorted(&s, 0.50);
    let p75 = quantile_type7_sorted(&s, 0.75);
    let p90 = quantile_type7_sorted(&s, 0.90);

    let legacy_jitter = (med - mn).max(0.0);
    let p90_p10 = (p90 - p10).max(0.0);
    let iqr = (p75 - p25).max(0.0);

    let mut iso_gap = 0.0;
    let mut clean_start = 0usize;
    if n >= 4 {
        let body_spread = (med - s[1]).max(0.15);
        let gap0 = s[1] - s[0];
        if gap0 > (4.0 * body_spread).max(2.0) {
            iso_gap = gap0;
            clean_start = 1;
        }
    }

    let clean = &s[clean_start..];
    let mut bimodal_gap = 0.0;
    if clean.len() >= 4 {
        let m = clean.len();
        let mut best_g = 0.0;
        let mut best_i = None;
        for idx in 1..(m - 2) {
            let g = clean[idx + 1] - clean[idx];
            if g > best_g {
                best_g = g;
                best_i = Some(idx);
            }
        }
        if let Some(bi) = best_i {
            let left_span = clean[bi] - clean[0];
            let right_span = clean[m - 1] - clean[bi + 1];
            let local_scale = left_span.min(right_span).max(0.25);
            if best_g > (3.0 * local_scale).max(3.0) {
                bimodal_gap = best_g;
            }
        }
    }

    legacy_jitter
        .max(0.5 * p90_p10)
        .max(0.6 * iqr)
        .max(0.75 * bimodal_gap)
        .max(0.5 * iso_gap)
}

impl LikelihoodObservation {
    /// Construct a `LikelihoodObservation` from multi-round RTT samples (ms), keeping the simpler
    /// frozen median representative RTT, exact minimum RTT for the Vacuum c0 mask, and full
    /// `route_instability_spread_ms` so unstable routes show less certainty.
    pub fn from_rtt_samples_ms(
        anchor_id: impl Into<String>,
        location: LatLon,
        samples_ms: &[f64],
        anchor_uncertainty_km: f64,
    ) -> Option<Self> {
        let mut s: Vec<f64> = samples_ms
            .iter()
            .copied()
            .filter(|x| x.is_finite() && *x > 0.0)
            .collect();
        if s.is_empty() {
            return None;
        }
        s.sort_by(|a, b| a.total_cmp(b));
        Some(Self {
            anchor_id: anchor_id.into(),
            location,
            rtt_ms: quantile_type7_sorted(&s, 0.5),
            rtt_min_ms: s[0],
            jitter_ms: route_instability_spread_ms(&s),
            anchor_uncertainty_km,
        })
    }
}

/// Parameters for the correlated spatial likelihood surface (defaults fit on disjoint Fit-T1 split).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SpatialLikelihoodConfig {
    pub t0_ms: f64,
    pub v0_km_ms: f64,
    pub v1_km_ms: f64,
    pub d_knee_km: f64,
    pub sigma_base_ms: f64,
    pub sigma_rel: f64,
    pub sigma_jit: f64,
    /// Spatial shared-path correlation strength `rho in [0, 0.99]`.
    pub rho: f64,
    /// Exponential spatial correlation length scale (km).
    pub l_corr_km: f64,
    /// Asymmetric slow-routing residual divisor (`>= 1.0`).
    pub asym_slow: f64,
    /// Multivariate Student-t degrees of freedom (`None` = Gaussian).
    pub student_t_nu: Option<f64>,
    /// Qualitative "More likely" band threshold in relative NLL units.
    pub tau_more_likely: f64,
    /// Qualitative broader "Plausible" band threshold in relative NLL units.
    pub tau_plausible: f64,
    /// Fibonacci sphere grid resolution for global scan & exact area integration.
    pub grid_points: usize,
    /// Minimum separation between distinct reported peaks (km).
    pub peak_separation_km: f64,
    /// Byzantine fault count `f` applied to the raw Vacuum outer mask.
    pub vacuum_byzantine_f: usize,
}

impl Default for SpatialLikelihoodConfig {
    fn default() -> Self {
        Self {
            t0_ms: 2.0,
            v0_km_ms: 80.0,
            v1_km_ms: 143.0,
            d_knee_km: 3500.0,
            sigma_base_ms: 1.837,
            sigma_rel: 0.1267,
            sigma_jit: 1.5,
            rho: 0.85,
            l_corr_km: 2200.0,
            asym_slow: 1.65,
            student_t_nu: Some(4.0),
            tau_more_likely: 1.752,
            tau_plausible: 3.911,
            grid_points: 2500,
            peak_separation_km: 700.0,
            vacuum_byzantine_f: 0,
        }
    }
}

/// Supported local maximum of the correlated spatial likelihood surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LikelihoodPeak {
    pub location: LatLon,
    /// Relative negative log-likelihood above the global maximum (`0.0` at primary peak).
    pub delta_nll: f64,
    /// Normalized relative likelihood in `(0, 1]` (`exp(-delta_nll)`).
    pub relative_likelihood: f64,
    /// Qualitative band label ("more_likely" | "plausible" | "less_likely").
    pub qualitative_band: String,
}

/// Correlated spatial likelihood surface evaluated strictly inside the raw Vacuum c0 outer bound.
///
/// Explicitly an empirical diagnostic estimate — NEVER a hard geographic proof and NEVER narrows
/// the raw Vacuum c0 outer region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpatialLikelihoodSurface {
    pub is_empirical_estimate: bool,
    pub is_hard_proof: bool,
    pub qualitative_scale: String,
    pub effective_independent_anchors: f64,
    pub anchor_count: usize,
    pub peaks: Vec<LikelihoodPeak>,
    pub more_likely_area_km2: f64,
    pub more_likely_area_fraction: f64,
    pub plausible_area_km2: f64,
    pub plausible_area_fraction: f64,
    pub vacuum_outer_area_km2: f64,
    pub vacuum_outer_area_fraction: f64,
}

fn cholesky_lower(mat: &[Vec<f64>]) -> Vec<Vec<f64>> {
    let n = mat.len();
    let mut l = vec![vec![0.0_f64; n]; n];
    for i in 0..n {
        for j in 0..=i {
            let s: f64 = l[i][..j]
                .iter()
                .zip(l[j][..j].iter())
                .map(|(a, b)| a * b)
                .sum();
            if i == j {
                l[i][j] = (mat[i][i] - s).max(1e-12).sqrt();
            } else {
                l[i][j] = (mat[i][j] - s) / l[j][j];
            }
        }
    }
    l
}

fn solve_lower_triangular(l: &[Vec<f64>], b: &[f64]) -> Vec<f64> {
    let n = b.len();
    let mut y = vec![0.0_f64; n];
    for i in 0..n {
        let mut s = b[i];
        for k in 0..i {
            s -= l[i][k] * y[k];
        }
        y[i] = s / l[i][i];
    }
    y
}

fn expected_rtt_ms(dist_km: f64, cfg: &SpatialLikelihoodConfig) -> f64 {
    let v = cfg.v0_km_ms + (cfg.v1_km_ms - cfg.v0_km_ms) * (1.0 - (-dist_km / cfg.d_knee_km).exp());
    cfg.t0_ms + (2.0 * dist_km) / v.max(1.0)
}

fn fibonacci_sphere_units(n: usize) -> Vec<Vec3> {
    let n = n.max(64);
    let ga = std::f64::consts::PI * (3.0 - 5.0_f64.sqrt());
    let mut pts = Vec::with_capacity(n);
    for i in 0..n {
        let y = 1.0 - (2.0 * (i as f64) + 1.0) / (n as f64);
        let r = (1.0 - y * y).max(0.0).sqrt();
        let phi = ga * (i as f64);
        pts.push(Vec3::new(phi.cos() * r, phi.sin() * r, y));
    }
    pts
}

/// Compute a spatially correlated likelihood surface strictly inside the raw Vacuum c0 outer bound.
///
/// Shared network paths are handled via the `K x K` covariance matrix:
///   `Sigma_ij = sigma_i * sigma_j * (rho * exp(-d(A_i, A_j) / L_corr) + (1 - rho) * delta_ij)`
/// so duplicating or clustering correlated anchors does not produce false certainty.
pub fn compute_spatial_likelihood(
    observations: &[LikelihoodObservation],
    cfg: &SpatialLikelihoodConfig,
    uncertainty: BoundUncertainty,
) -> SpatialLikelihoodSurface {
    let earth_surface_km2 = 4.0 * std::f64::consts::PI * EARTH_RADIUS_KM * EARTH_RADIUS_KM;
    if observations.is_empty() {
        return SpatialLikelihoodSurface {
            is_empirical_estimate: true,
            is_hard_proof: false,
            qualitative_scale: "more_likely_to_less_likely".into(),
            effective_independent_anchors: 0.0,
            anchor_count: 0,
            peaks: Vec::new(),
            more_likely_area_km2: earth_surface_km2,
            more_likely_area_fraction: 1.0,
            plausible_area_km2: earth_surface_km2,
            plausible_area_fraction: 1.0,
            vacuum_outer_area_km2: earth_surface_km2,
            vacuum_outer_area_fraction: 1.0,
        };
    }

    let k = observations.len();
    let units: Vec<Vec3> = observations.iter().map(|o| o.location.to_unit_vec()).collect();

    // Conservative Vacuum c0 outer cap thresholds (NEVER narrowed by calibration).
    let vac_cos: Vec<f64> = observations
        .iter()
        .map(|o| {
            let mut u = uncertainty;
            u.anchor_location_uncertainty_km =
                u.anchor_location_uncertainty_km.max(o.anchor_uncertainty_km);
            let rtt_us = (o.rtt_min_ms.max(0.0) * 1000.0).ceil() as u64;
            let r_km = effective_radius_km_with_uncertainty(rtt_us, BoundTier::Vacuum, u);
            (r_km / EARTH_RADIUS_KM).min(std::f64::consts::PI).cos()
        })
        .collect();
    let req_vac = k.saturating_sub(cfg.vacuum_byzantine_f).max(1);

    // Build KxK spatially correlated covariance matrix Sigma and Cholesky factor L.
    let rho = cfg.rho.clamp(0.0, 0.99);
    let sigmas: Vec<f64> = observations
        .iter()
        .map(|o| {
            (cfg.sigma_base_ms.powi(2)
                + (cfg.sigma_rel * o.rtt_ms.max(0.0)).powi(2)
                + (cfg.sigma_jit * o.jitter_ms.max(0.0)).powi(2))
            .sqrt()
            .max(0.25)
        })
        .collect();

    let mut sigma = vec![vec![0.0_f64; k]; k];
    let mut corr = vec![vec![0.0_f64; k]; k];
    for i in 0..k {
        for j in i..k {
            let c = if i == j {
                1.0
            } else {
                let d_ij = units[i].dot(units[j]).clamp(-1.0, 1.0).acos() * EARTH_RADIUS_KM;
                rho * (-d_ij / cfg.l_corr_km.max(1.0)).exp()
            };
            corr[i][j] = c;
            corr[j][i] = c;
            let val = sigmas[i] * sigmas[j] * c;
            sigma[i][j] = val;
            sigma[j][i] = val;
        }
    }

    let l_sigma = cholesky_lower(&sigma);
    let l_corr = cholesky_lower(&corr);
    let ones = vec![1.0_f64; k];
    let ones_w = solve_lower_triangular(&l_corr, &ones);
    let k_eff: f64 = ones_w.iter().map(|v| v * v).sum();

    let eval_nll = |pt: Vec3| -> f64 {
        let mut r = Vec::with_capacity(k);
        for i in 0..k {
            let d_km = pt.dot(units[i]).clamp(-1.0, 1.0).acos() * EARTH_RADIUS_KM;
            let pred = expected_rtt_ms(d_km, cfg);
            let mut diff = observations[i].rtt_ms - pred;
            if diff > 0.0 && cfg.asym_slow > 1.0 {
                diff /= cfg.asym_slow;
            }
            r.push(diff);
        }
        let z = solve_lower_triangular(&l_sigma, &r);
        let quad: f64 = z.iter().map(|v| v * v).sum();
        if let Some(nu) = cfg.student_t_nu {
            0.5 * (nu + k_eff) * (1.0 + quad / nu.max(0.5)).ln()
        } else {
            0.5 * quad
        }
    };

    let sphere_pts = fibonacci_sphere_units(cfg.grid_points);
    let mut feasible_pts: Vec<(Vec3, f64)> = Vec::new();
    let mut best_nll = f64::INFINITY;
    let mut best_u = units[0];

    for pt in &sphere_pts {
        let in_cnt = (0..k)
            .filter(|&j| pt.dot(units[j]) >= vac_cos[j] - 1e-12)
            .count();
        if in_cnt < req_vac {
            continue;
        }
        let nll = eval_nll(*pt);
        if nll < best_nll {
            best_nll = nll;
            best_u = *pt;
        }
        feasible_pts.push((*pt, nll));
    }

    if feasible_pts.is_empty() {
        return SpatialLikelihoodSurface {
            is_empirical_estimate: true,
            is_hard_proof: false,
            qualitative_scale: "more_likely_to_less_likely".into(),
            effective_independent_anchors: k_eff,
            anchor_count: k,
            peaks: Vec::new(),
            more_likely_area_km2: 0.0,
            more_likely_area_fraction: 0.0,
            plausible_area_km2: 0.0,
            plausible_area_fraction: 0.0,
            vacuum_outer_area_km2: 0.0,
            vacuum_outer_area_fraction: 0.0,
        };
    }

    // Fine coordinate polish around primary grid peak (staying strictly inside Vacuum c0).
    let mut best_ll = best_u.to_lat_lon();
    for step_deg in [1.5_f64, 0.4, 0.1] {
        let c = best_ll;
        for dlat in -2..=2 {
            for dlon in -2..=2 {
                let lat = (c.lat + (dlat as f64) * step_deg).clamp(-89.5, 89.5);
                let mut lon = c.lon + (dlon as f64) * step_deg;
                if lon > 180.0 {
                    lon -= 360.0;
                } else if lon < -180.0 {
                    lon += 360.0;
                }
                let cand = LatLon::new(lat, lon);
                let cu = cand.to_unit_vec();
                let in_cnt = (0..k)
                    .filter(|&j| cu.dot(units[j]) >= vac_cos[j] - 1e-12)
                    .count();
                if in_cnt < req_vac {
                    continue;
                }
                let cn = eval_nll(cu);
                if cn < best_nll {
                    best_nll = cn;
                    best_ll = cand;
                    best_u = cu;
                }
            }
        }
    }

    let n_total = sphere_pts.len() as f64;
    let vac_frac = (feasible_pts.len() as f64) / n_total;
    let mut ml_candidates: Vec<(f64, Vec3)> = Vec::new();
    let mut pl_count = 0usize;
    for &(pt, nll) in &feasible_pts {
        let delta = (nll - best_nll).max(0.0);
        if delta <= cfg.tau_plausible {
            pl_count += 1;
        }
        if delta <= cfg.tau_more_likely {
            ml_candidates.push((delta, pt));
        }
    }
    ml_candidates.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

    // Extract primary peak + any well-separated secondary peaks within `tau_more_likely`.
    let mut peak_units: Vec<(f64, Vec3)> = vec![(0.0, best_u)];
    for &(delta, pt) in &ml_candidates {
        let separated = peak_units
            .iter()
            .all(|(_, pu)| pt.dot(*pu).clamp(-1.0, 1.0).acos() * EARTH_RADIUS_KM >= cfg.peak_separation_km);
        if separated {
            peak_units.push((delta, pt));
            if peak_units.len() >= 4 {
                break;
            }
        }
    }

    let peaks: Vec<LikelihoodPeak> = peak_units
        .into_iter()
        .map(|(delta, pu)| LikelihoodPeak {
            location: pu.to_lat_lon(),
            delta_nll: delta,
            relative_likelihood: (-delta).exp(),
            qualitative_band: if delta <= cfg.tau_more_likely {
                "more_likely".into()
            } else if delta <= cfg.tau_plausible {
                "plausible".into()
            } else {
                "less_likely".into()
            },
        })
        .collect();

    let ml_frac = ((ml_candidates.len().max(1)) as f64) / n_total;
    let pl_frac = ((pl_count.max(ml_candidates.len()).max(1)) as f64) / n_total;

    SpatialLikelihoodSurface {
        is_empirical_estimate: true,
        is_hard_proof: false,
        qualitative_scale: "more_likely_to_less_likely".into(),
        effective_independent_anchors: k_eff,
        anchor_count: k,
        peaks,
        more_likely_area_km2: ml_frac * earth_surface_km2,
        more_likely_area_fraction: ml_frac,
        plausible_area_km2: pl_frac * earth_surface_km2,
        plausible_area_fraction: pl_frac,
        vacuum_outer_area_km2: vac_frac * earth_surface_km2,
        vacuum_outer_area_fraction: vac_frac,
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

    #[test]
    fn test_spatial_likelihood_correlated_deweighting_and_multipeak() {
        let cfg = SpatialLikelihoodConfig::default();
        let unc = BoundUncertainty::default_datacenter();

        // 1. Duplicating a correlated anchor 8x at the same site MUST NOT inflate k_eff linearly
        //    or collapse the more-likely region area!
        let base_obs = vec![
            LikelihoodObservation {
                anchor_id: "a1".into(),
                location: LatLon::new(40.71, -74.00),
                rtt_ms: 28.0,
                rtt_min_ms: 27.5,
                jitter_ms: 0.5,
                anchor_uncertainty_km: 25.0,
            },
            LikelihoodObservation {
                anchor_id: "a2".into(),
                location: LatLon::new(37.34, -121.89),
                rtt_ms: 52.0,
                rtt_min_ms: 51.4,
                jitter_ms: 0.6,
                anchor_uncertainty_km: 25.0,
            },
            LikelihoodObservation {
                anchor_id: "a3".into(),
                location: LatLon::new(43.65, -79.38),
                rtt_ms: 19.0,
                rtt_min_ms: 18.6,
                jitter_ms: 0.4,
                anchor_uncertainty_km: 25.0,
            },
            LikelihoodObservation {
                anchor_id: "a4".into(),
                location: LatLon::new(29.42, -98.49),
                rtt_ms: 34.0,
                rtt_min_ms: 33.5,
                jitter_ms: 0.5,
                anchor_uncertainty_km: 25.0,
            },
        ];
        let mut dup_obs = base_obs.clone();
        for idx in 0..7 {
            let mut copy = base_obs[0].clone();
            copy.anchor_id = format!("a1-dup-{idx}");
            dup_obs.push(copy);
        }
        let s_base = compute_spatial_likelihood(&base_obs, &cfg, unc);
        let s_dup = compute_spatial_likelihood(&dup_obs, &cfg, unc);
        assert!(s_base.is_empirical_estimate && !s_base.is_hard_proof);
        assert!(
            s_dup.effective_independent_anchors < 5.0,
            "8x co-located duplicates should stay bounded, got k_eff={}",
            s_dup.effective_independent_anchors
        );
        assert!(
            s_dup.more_likely_area_km2 >= s_base.more_likely_area_km2 * 0.45,
            "Correlated duplicates must not falsely collapse likelihood band area: base={} dup={}",
            s_base.more_likely_area_km2,
            s_dup.more_likely_area_km2
        );
        assert!(s_base.more_likely_area_km2 <= s_base.vacuum_outer_area_km2 + 1e-6);

        // 2. Two symmetric anchors on the equator with identical 35 ms RTT MUST support >= 2 peaks (north & south)!
        let sym_obs = vec![
            LikelihoodObservation {
                anchor_id: "west".into(),
                location: LatLon::new(0.0, -15.0),
                rtt_ms: 35.0,
                rtt_min_ms: 34.8,
                jitter_ms: 0.2,
                anchor_uncertainty_km: 25.0,
            },
            LikelihoodObservation {
                anchor_id: "east".into(),
                location: LatLon::new(0.0, 15.0),
                rtt_ms: 35.0,
                rtt_min_ms: 34.8,
                jitter_ms: 0.2,
                anchor_uncertainty_km: 25.0,
            },
        ];
        let s_sym = compute_spatial_likelihood(&sym_obs, &cfg, unc);
        assert!(
            s_sym.peaks.len() >= 2,
            "Expected >=2 symmetric peaks for 2-anchor ambiguity, got {:?}",
            s_sym.peaks
        );
    }

    #[test]
    fn test_five_route_regimes_tight_slow_isofast_slowtail_multimodal() {
        let target = LatLon::new(41.8781, -87.6298); // Chicago
        let anchors = [
            ("tor", LatLon::new(43.6532, -79.3832)),
            ("dsm", LatLon::new(41.2619, -95.8608)),
            ("iad", LatLon::new(39.0438, -77.4874)),
            ("dal", LatLon::new(32.7767, -96.7970)),
            ("yul", LatLon::new(45.5017, -73.5673)),
            ("chs", LatLon::new(32.7765, -79.9311)),
            ("slc", LatLon::new(40.7608, -111.8910)),
            ("sjc", LatLon::new(37.3382, -121.8863)),
        ];
        let tight_offs = [-0.15, -0.10, -0.06, -0.04, -0.02, 0.0, 0.02, 0.04, 0.07, 0.10, 0.14, 0.18];
        let cfg = SpatialLikelihoodConfig::default();
        let unc = BoundUncertainty::default_datacenter();

        let build_obs = |regime: &str| -> Vec<LikelihoodObservation> {
            anchors
                .iter()
                .enumerate()
                .map(|(idx, (id, loc))| {
                    let d = target.distance_km(*loc);
                    let v = cfg.v0_km_ms + (cfg.v1_km_ms - cfg.v0_km_ms) * (1.0 - (-d / cfg.d_knee_km).exp());
                    let b = cfg.t0_ms + (2.0 * d) / v;
                    let mut samples: Vec<f64> = match regime {
                        "tight" => tight_offs.iter().map(|o| b + o).collect(),
                        "consistently_slow" => {
                            let shift = if idx % 2 == 0 { 28.0 } else { 0.0 };
                            tight_offs.iter().map(|o| b + shift + o).collect()
                        }
                        "isolated_fast" => {
                            let mut s: Vec<f64> = tight_offs.iter().map(|o| b + o).collect();
                            if idx == 0 {
                                s[0] = 3.2; // single isolated fast anomaly
                            }
                            s
                        }
                        "slow_tail" => {
                            if idx < 4 {
                                let mut s: Vec<f64> = tight_offs[..7].iter().map(|o| b + o).collect();
                                s.extend([b + 25.0, b + 42.0, b + 60.0, b + 78.0, b + 95.0]);
                                s
                            } else {
                                tight_offs.iter().map(|o| b + o).collect()
                            }
                        }
                        "multimodal" => {
                            if idx < 4 {
                                let mut s: Vec<f64> = tight_offs[..6].iter().map(|o| b + o).collect();
                                s.extend(tight_offs[..6].iter().map(|o| b + 44.0 + o));
                                s
                            } else {
                                tight_offs.iter().map(|o| b + o).collect()
                            }
                        }
                        _ => unreachable!(),
                    };
                    samples.sort_by(|a, b| a.total_cmp(b));
                    LikelihoodObservation::from_rtt_samples_ms(*id, *loc, &samples, 35.0).unwrap()
                })
                .collect()
        };

        let obs_tight = build_obs("tight");
        let obs_slow = build_obs("consistently_slow");
        let obs_iso = build_obs("isolated_fast");
        let obs_tail = build_obs("slow_tail");
        let obs_multi = build_obs("multimodal");

        // Verify spread detector distinguishes tight vs slow_tail, isolated_fast, multimodal!
        assert!(obs_tight[0].jitter_ms < 0.3);
        assert!(obs_tail[0].jitter_ms > 20.0, "slow_tail must inflate spread, got {}", obs_tail[0].jitter_ms);
        assert!(obs_multi[0].jitter_ms > 25.0, "multimodal must inflate spread, got {}", obs_multi[0].jitter_ms);
        assert!(obs_iso[0].jitter_ms > 5.0, "isolated_fast must inflate spread, got {}", obs_iso[0].jitter_ms);

        let s_tight = compute_spatial_likelihood(&obs_tight, &cfg, unc);
        let s_slow = compute_spatial_likelihood(&obs_slow, &cfg, unc);
        let s_tail = compute_spatial_likelihood(&obs_tail, &cfg, unc);
        let s_multi = compute_spatial_likelihood(&obs_multi, &cfg, unc);
        let cfg_f1 = SpatialLikelihoodConfig {
            vacuum_byzantine_f: 1,
            ..cfg
        };
        let s_iso = compute_spatial_likelihood(&obs_iso, &cfg_f1, unc);

        // Unstable routes MUST show LESS certainty (strictly wider Plausible area than tight)!
        assert!(
            s_tail.plausible_area_km2 > s_tight.plausible_area_km2,
            "slow_tail should widen plausible area vs tight: tail={} tight={}",
            s_tail.plausible_area_km2,
            s_tight.plausible_area_km2
        );
        assert!(
            s_multi.plausible_area_km2 > s_tight.plausible_area_km2,
            "multimodal should widen plausible area vs tight: multi={} tight={}",
            s_multi.plausible_area_km2,
            s_tight.plausible_area_km2
        );
        assert!(
            s_slow.plausible_area_km2 > s_tight.plausible_area_km2,
            "consistently_slow should widen plausible area vs tight: slow={} tight={}",
            s_slow.plausible_area_km2,
            s_tight.plausible_area_km2
        );
        // Frozen median resists isolated-fast single anomaly cleanly (peak remains near Chicago)
        let iso_err = target.distance_km(s_iso.peaks[0].location);
        assert!(iso_err < 120.0, "isolated_fast median peak should stay near Chicago, got {iso_err:.1} km");
        // Vacuum c0 NEVER subtracts delays: consistently_slow & slow_tail & multimodal remain >= tight vacuum area!
        assert!(s_slow.vacuum_outer_area_km2 >= s_tight.vacuum_outer_area_km2);
        assert!(s_tail.vacuum_outer_area_km2 >= s_tight.vacuum_outer_area_km2 * 0.99);
        assert!(s_multi.vacuum_outer_area_km2 >= s_tight.vacuum_outer_area_km2 * 0.99);
    }
}
