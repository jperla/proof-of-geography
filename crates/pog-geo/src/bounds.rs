use crate::sphere::EARTH_RADIUS_KM;
use serde::{Deserialize, Serialize};

/// Speed of light in vacuum (km/s).
/// Uncheatable upper bound for ALL physical media, including Starlink vacuum laser ISLs,
/// hollow-core fiber (~0.99 c0), line-of-sight microwave links, and hypothetical Earth-chord paths.
pub const C_VACUUM_KM_PER_S: f64 = 299_792.458;

/// Speed of light in standard single-mode silica optical fiber (n ≈ 1.468 -> ~204,218 km/s).
/// Conservative upper bound for terrestrial/subsea silica fiber (including private cloud backbones).
pub const C_FIBER_KM_PER_S: f64 = 204_000.0;

/// Conservative default calibrated empirical speed on typical routed internet fiber.
/// Empirically informed and strictly non-adversarial (NEVER used for hard exclusions).
pub const C_CALIBRATED_DEFAULT_KM_PER_S: f64 = 152_000.0;

/// Exact minimum meridional / chord radius of curvature of the WGS84 reference ellipsoid:
///   M_0 = a * (1 - e^2) = 6378.137 * (1 - 0.006694379990141317) = 6335.439327 km.
///
/// Mathematical guarantee:
/// For ANY two points P1, P2 on the WGS84 ellipsoid at geodetic (lat, lon) with unit-sphere
/// central angle `psi`:
///   1. Straight-line 3D ECEF chord distance `||P1 - P2||_2 >= 2 * M_0 * sin(psi / 2)`.
///   2. Ellipsoidal surface geodesic distance `s_WGS84 >= M_0 * psi`.
///
/// Using `M_0` when mapping a measured propagation length to a spherical cap angle on the
/// mean sphere `S^2` guarantees the outer bound NEVER excludes the true endpoint due to
/// Earth flattening (~0.56% polar/equatorial mismatch) OR straight-line chord shortcuts!
pub const WGS84_MIN_CURVATURE_RADIUS_KM: f64 = 6_335.439_327;

/// Maximum possible great-circle distance on the mean sphere (`pi * R_mean` ≈ 20,015.114 km).
pub const HALF_CIRCUMFERENCE_KM: f64 = std::f64::consts::PI * EARTH_RADIUS_KM;

/// Conservative timing & anchor-coordinate uncertainty budget folded into Tier 1 outer bounds.
///
/// In Vacuum / Fiber outer-bound mode, these terms ONLY WIDEN the feasible region (never narrow it),
/// guaranteeing that clock quantization, clock-frequency slew, anchor coordinate errors (cloud region
/// centroid vs exact rack), and WGS84 chord-vs-surface geometry never cause a false exclusion.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct BoundUncertainty {
    /// Additive clock quantization / timestamping resolution margin (microseconds).
    /// Added to measured RTT before computing the outer bound.
    pub clock_resolution_us: u64,
    /// Multiplicative monotonic clock frequency skew/slew uncertainty in parts-per-million (ppm).
    /// E.g., 500 ppm covers worst-case uncalibrated crystal drift / NTP slewing.
    pub clock_slew_ppm: u32,
    /// Conservative uncertainty in published Anchor coordinates (km).
    /// Hardware TEE identity does NOT prove physical coordinates; anchor coordinates are
    /// audited separately and carry a bounded geographic uncertainty radius.
    pub anchor_location_uncertainty_km: f64,
    /// If true (required for Vacuum outer bound), convert one-way light travel distance as a
    /// 3D WGS84 straight-line chord (`2 * asin(L / (2 * M_0))`) rather than a surface arc.
    pub account_for_chord: bool,
    /// If true (required for Fiber outer bound), map surface travel distance via `M_0` rather than `R_mean`.
    pub account_for_wgs84_ellipsoid: bool,
}

impl Default for BoundUncertainty {
    fn default() -> Self {
        Self::default_datacenter()
    }
}

impl BoundUncertainty {
    /// Conservative defaults for direct UDP datacenter probes with kernel/monotonic timestamps
    /// and metro-audited Anchor coordinates.
    pub const fn default_datacenter() -> Self {
        Self {
            clock_resolution_us: 50,
            clock_slew_ppm: 500,
            anchor_location_uncertainty_km: 35.0,
            account_for_chord: true,
            account_for_wgs84_ellipsoid: true,
        }
    }

    /// Conservative defaults for browser HTTPS `performance.now()` / Resource Timing probes
    /// (coarsened timers up to 1 ms).
    pub const fn default_browser() -> Self {
        Self {
            clock_resolution_us: 1_000,
            clock_slew_ppm: 500,
            anchor_location_uncertainty_km: 35.0,
            account_for_chord: true,
            account_for_wgs84_ellipsoid: true,
        }
    }

    /// Idealized zero-uncertainty budget (still preserves exact chord/WGS84 geometry if toggled,
    /// or pure spherical geometry when both flags are false — used only for physics comparison tests).
    pub const fn zero() -> Self {
        Self {
            clock_resolution_us: 0,
            clock_slew_ppm: 0,
            anchor_location_uncertainty_km: 0.0,
            account_for_chord: true,
            account_for_wgs84_ellipsoid: true,
        }
    }
}

/// Bounding model tier.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum BoundTier {
    /// Tier 1A: Strict vacuum speed of light outer bound (c0 = 299,792.458 km/s).
    /// Zero empirical RTT deductions; conservatively accounts for clock resolution, slew,
    /// anchor-coordinate uncertainty, and WGS84 chord-through-Earth vs surface arc.
    /// No artificial radius cap: expands seamlessly up to whole-Earth (`pi * R_mean`).
    Vacuum,
    /// Tier 1B: Silica optical fiber surface bound (c_fiber = 204,000 km/s).
    /// Zero empirical RTT deductions; accounts for clock resolution, slew, anchor-coordinate
    /// uncertainty, and WGS84 ellipsoid flattening. Conditional on terrestrial/subsea fiber
    /// (satellite vacuum laser ISLs can beat silica fiber over long transoceanic links).
    Fiber,
    /// Tier 2: Empirically calibrated corridor velocity (km/s). Non-adversarial empirical estimate
    /// ONLY — NEVER used to claim a hard physical exclusion.
    Calibrated { effective_km_per_s: f64 },
    /// Tier 2B: Empirically calibrated linear model (`RTT >= fixed_overhead + 2*d / v`).
    /// Strictly empirical — NEVER used for hard exclusions.
    CalibratedLinear {
        effective_km_per_s: f64,
        fixed_overhead_us: u64,
    },
}

impl BoundTier {
    pub fn velocity_km_per_s(self) -> f64 {
        match self {
            BoundTier::Vacuum => C_VACUUM_KM_PER_S,
            BoundTier::Fiber => C_FIBER_KM_PER_S,
            BoundTier::Calibrated { effective_km_per_s }
            | BoundTier::CalibratedLinear {
                effective_km_per_s, ..
            } => effective_km_per_s.clamp(50_000.0, C_VACUUM_KM_PER_S),
        }
    }

    pub fn is_empirical(self) -> bool {
        matches!(
            self,
            BoundTier::Calibrated { .. } | BoundTier::CalibratedLinear { .. }
        )
    }

    pub fn name(self) -> &'static str {
        match self {
            BoundTier::Vacuum => "tier1a_vacuum",
            BoundTier::Fiber => "tier1b_fiber",
            BoundTier::Calibrated { .. } => "tier2_calibrated",
            BoundTier::CalibratedLinear { .. } => "tier2b_calibrated_linear",
        }
    }
}

/// Convert measured round-trip time (microseconds) to maximum spherical-surface radius (km)
/// on the mean sphere `S^2`, incorporating conservative timing, anchor-coordinate, and
/// WGS84 chord/ellipsoid geometry uncertainty.
///
/// Physical Measurement & Relativistic Model Assumptions (see `docs/PHYSICAL_BOUNDS_MODEL.md`):
/// - **Same-clock RTT (NEVER one-way):** Each Anchor measures `RTT = t_recv - t_send` on one
///   local monotonic clock (`CLOCK_MONOTONIC` / `SO_TIMESTAMPNS` / TSC), cancelling inter-host
///   clock offsets and avoiding GPS/GNSS/NTP clock-sync spoofing (`~300 km/ms` error risk).
/// - **Sagnac effect on rotating Earth:** Cancels to first order on symmetric closed round-trip
///   paths; even for a worst-case hemisphere-sized asymmetric loop (`A_eq ~ 1.28e14 m^2`), the
///   residual Sagnac shift `2 * Omega_E * A_eq / c0^2 <= 0.21 us`, strictly absorbed by the
///   conservative `clock_resolution_us` margin (`50 us` datacenter / `1,000 us` browser).
/// - **Satellite & altitude assumptions:** Tier 1A `Vacuum` uses the 3D WGS84 straight-line chord
///   (`M_0 = 6335.439327 km`), so it strictly bounds LEO/MEO/GEO satellite relays (including
///   Starlink vacuum laser ISLs) for surface provers (`h_prover << R_E`). Non-surface airborne or
///   orbital provers require adding prover-altitude margin. Tier 1B `Fiber` (`204 km/ms`) is
///   conditional on terrestrial/subsea silica fiber and does NOT bound vacuum-optical ISLs.
///
/// Guarantees for `BoundTier::Vacuum`:
/// - ZERO empirical speed and ZERO empirical RTT/delay deductions.
/// - Accounts conservatively for clock resolution + slew (`t_upper = (rtt + res) * (1 + slew)`).
/// - Accounts conservatively for straight-line 3D WGS84 chord propagation (`2 * asin(L / (2 * M_0))`)
///   plus anchor-coordinate uncertainty (`anchor_unc / M_0`).
/// - NO artificial radius cap (returns `HALF_CIRCUMFERENCE_KM = pi * R_mean` when whole Earth is feasible).
pub fn effective_radius_km_with_uncertainty(
    rtt_us: u64,
    tier: BoundTier,
    uncertainty: BoundUncertainty,
) -> f64 {
    match tier {
        BoundTier::Vacuum => {
            let t_upper_s = (rtt_us.saturating_add(uncertainty.clock_resolution_us) as f64)
                * (1.0 + (uncertainty.clock_slew_ppm as f64) * 1e-6)
                * 1e-6;
            let one_way_km = 0.5 * C_VACUUM_KM_PER_S * t_upper_s;
            let ref_r = if uncertainty.account_for_wgs84_ellipsoid || uncertainty.account_for_chord {
                WGS84_MIN_CURVATURE_RADIUS_KM
            } else {
                EARTH_RADIUS_KM
            };
            let prop_angle = if uncertainty.account_for_chord {
                let sin_half = one_way_km / (2.0 * ref_r);
                if sin_half >= 1.0 {
                    std::f64::consts::PI
                } else {
                    2.0 * sin_half.asin()
                }
            } else {
                (one_way_km / ref_r).min(std::f64::consts::PI)
            };
            let coord_angle = uncertainty.anchor_location_uncertainty_km.max(0.0) / ref_r;
            let total_angle = (prop_angle + coord_angle).min(std::f64::consts::PI);
            total_angle * EARTH_RADIUS_KM
        }
        BoundTier::Fiber => {
            let t_upper_s = (rtt_us.saturating_add(uncertainty.clock_resolution_us) as f64)
                * (1.0 + (uncertainty.clock_slew_ppm as f64) * 1e-6)
                * 1e-6;
            let one_way_km = 0.5 * C_FIBER_KM_PER_S * t_upper_s;
            let ref_r = if uncertainty.account_for_wgs84_ellipsoid {
                WGS84_MIN_CURVATURE_RADIUS_KM
            } else {
                EARTH_RADIUS_KM
            };
            let total_angle = ((one_way_km + uncertainty.anchor_location_uncertainty_km.max(0.0))
                / ref_r)
                .min(std::f64::consts::PI);
            total_angle * EARTH_RADIUS_KM
        }
        BoundTier::Calibrated { effective_km_per_s } => {
            let rtt_s = (rtt_us as f64) * 1e-6;
            let r_km = 0.5 * effective_km_per_s.clamp(50_000.0, C_VACUUM_KM_PER_S) * rtt_s;
            r_km.min(HALF_CIRCUMFERENCE_KM)
        }
        BoundTier::CalibratedLinear {
            effective_km_per_s,
            fixed_overhead_us,
        } => {
            let adjusted_us = rtt_us.saturating_sub(fixed_overhead_us);
            let rtt_s = (adjusted_us as f64) * 1e-6;
            let r_km = 0.5 * effective_km_per_s.clamp(50_000.0, C_VACUUM_KM_PER_S) * rtt_s;
            r_km.min(HALF_CIRCUMFERENCE_KM)
        }
    }
}

/// Default conservative radius converter using `BoundUncertainty::default_datacenter()`.
pub fn effective_radius_km(rtt_us: u64, tier: BoundTier) -> f64 {
    effective_radius_km_with_uncertainty(rtt_us, tier, BoundUncertainty::default_datacenter())
}

/// Parameters modeling a LEO satellite constellation with vacuum optical inter-satellite links
/// (e.g., Starlink Gen2 / Shell 1 at ~550 km altitude).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct StarlinkModel {
    /// Orbital shell altitude in km (Starlink primary shell ≈ 550 km; VLEO ≈ 340 km).
    pub altitude_km: f64,
    /// Minimum realistic elevation angle in degrees (typically 25°–40°; 90° = directly overhead).
    pub elevation_deg: f64,
    /// Per-ground-hop + satellite switching/framing overhead (round-trip ms, optimistic adversary ≈ 2 ms).
    pub switching_overhead_ms: f64,
}

impl Default for StarlinkModel {
    fn default() -> Self {
        Self {
            altitude_km: 550.0,
            elevation_deg: 40.0,
            switching_overhead_ms: 2.0,
        }
    }
}

/// Optimistic lower bound on round-trip time (ms) over a LEO satellite vacuum laser ISL path
/// between two ground stations separated by `ground_distance_km`.
pub fn starlink_min_rtt_ms(ground_distance_km: f64, model: StarlinkModel) -> f64 {
    let elev_rad = model.elevation_deg.clamp(15.0, 90.0).to_radians();
    let slant_km = model.altitude_km / elev_rad.sin();
    let one_way_km = 2.0 * slant_km + ground_distance_km;
    let propagation_rtt_ms = (2.0 * one_way_km / C_VACUUM_KM_PER_S) * 1_000.0;
    propagation_rtt_ms + model.switching_overhead_ms
}

/// Compute the crossover distance (km) where optimistic Starlink LEO vacuum ISLs become faster
/// than ideal silica fiber (`C_FIBER_KM_PER_S`).
pub fn starlink_vs_fiber_crossover_km(model: StarlinkModel) -> f64 {
    let elev_rad = model.elevation_deg.clamp(15.0, 90.0).to_radians();
    let slant_km = model.altitude_km / elev_rad.sin();
    let overhead_s = model.switching_overhead_ms * 1e-3;
    let lhs_const = (4.0 * slant_km / C_VACUUM_KM_PER_S) + overhead_s;
    let coeff = (2.0 / C_FIBER_KM_PER_S) - (2.0 / C_VACUUM_KM_PER_S);
    lhs_const / coeff
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sphere::LatLon;

    fn wgs84_ecef_km(p: LatLon) -> [f64; 3] {
        const A: f64 = 6_378.137;
        const F: f64 = 1.0 / 298.257_223_563;
        const E2: f64 = F * (2.0 - F);
        let lat = p.lat.to_radians();
        let lon = p.lon.to_radians();
        let s = lat.sin();
        let c = lat.cos();
        let n = A / (1.0 - E2 * s * s).sqrt();
        [n * c * lon.cos(), n * c * lon.sin(), n * (1.0 - E2) * s]
    }

    fn wgs84_chord_km(a: LatLon, b: LatLon) -> f64 {
        let p1 = wgs84_ecef_km(a);
        let p2 = wgs84_ecef_km(b);
        ((p1[0] - p2[0]).powi(2) + (p1[1] - p2[1]).powi(2) + (p1[2] - p2[2]).powi(2)).sqrt()
    }

    #[test]
    fn test_vacuum_outer_bound_never_excludes_any_wgs84_chord_pair() {
        let pts = [
            LatLon::new(0.0, 0.0),
            LatLon::new(0.0, 180.0),
            LatLon::new(0.0, 90.0),
            LatLon::new(0.01, 0.0),
            LatLon::new(89.99, 0.0),
            LatLon::new(-89.99, 120.0),
            LatLon::new(37.4, -121.9),
            LatLon::new(50.1, 8.7),
            LatLon::new(35.7, 139.7),
            LatLon::new(-33.8688, 151.2093),
        ];
        // Even with zero clock/anchor uncertainty, WGS84 chord-to-sphere outer bound MUST contain every point!
        let zero_unc = BoundUncertainty::zero();
        for &a in &pts {
            for &b in &pts {
                let chord = wgs84_chord_km(a, b);
                // Minimum physically possible RTT via straight-line chord through Earth at c0 (rounded up to 1 us)
                let min_rtt_us = ((2.0 * chord / C_VACUUM_KM_PER_S) * 1e6).ceil() as u64;
                let outer_r = effective_radius_km_with_uncertainty(min_rtt_us, BoundTier::Vacuum, zero_unc);
                let sphere_d = a.distance_km(b);
                assert!(
                    outer_r + 1e-6 >= sphere_d,
                    "Vacuum outer bound excluded WGS84 point! a={a:?} b={b:?} chord={chord:.3} rtt={min_rtt_us}us outer={outer_r:.3} < sphere={sphere_d:.3}"
                );
            }
        }
    }

    #[test]
    fn test_vacuum_150ms_covers_whole_earth_no_artificial_cap() {
        let r = effective_radius_km(150_000, BoundTier::Vacuum);
        assert!(
            (r - HALF_CIRCUMFERENCE_KM).abs() < 1e-6,
            "150 ms vacuum RTT must reach full half-circumference ({HALF_CIRCUMFERENCE_KM:.3} km), got {r:.3}"
        );
        // Even 85 ms (> 4*M0/c0 = 84.53 ms chord diameter RTT) covers the entire Earth!
        let r85 = effective_radius_km(85_000, BoundTier::Vacuum);
        assert!((r85 - HALF_CIRCUMFERENCE_KM).abs() < 1e-6);
    }

    #[test]
    fn test_vacuum_always_bounds_starlink() {
        let model = StarlinkModel {
            altitude_km: 340.0,
            elevation_deg: 90.0,
            switching_overhead_ms: 0.0,
        };
        for dist in [100.0, 1000.0, 5000.0, 12000.0] {
            let starlink_rtt_ms = starlink_min_rtt_ms(dist, model);
            let rtt_us = (starlink_rtt_ms * 1000.0) as u64;
            let vacuum_radius = effective_radius_km(rtt_us, BoundTier::Vacuum);
            assert!(
                vacuum_radius >= dist,
                "Vacuum bound {vacuum_radius} must ALWAYS >= true distance {dist}"
            );
        }
    }

    #[test]
    fn test_starlink_beats_fiber_at_long_range() {
        let model = StarlinkModel::default();
        let crossover = starlink_vs_fiber_crossover_km(model);
        assert!(crossover > 2000.0 && crossover < 7000.0, "crossover={crossover}");
        let d = 9000.0;
        let starlink_rtt_ms = starlink_min_rtt_ms(d, model);
        let ideal_fiber_rtt_ms = (2.0 * d / C_FIBER_KM_PER_S) * 1000.0;
        assert!(starlink_rtt_ms < ideal_fiber_rtt_ms);
    }

    #[test]
    fn test_asymmetric_sagnac_upper_bound_is_absorbed_by_clock_resolution_margin() {
        // Earth angular velocity Omega_E = 7.292115e-5 rad/s; max equatorial projection area = pi * a^2
        let omega_e = 7.292_115e-5_f64;
        let a_m = 6_378_137.0_f64;
        let c0_m_per_s = C_VACUUM_KM_PER_S * 1_000.0;
        let max_equatorial_loop_area_m2 = std::f64::consts::PI * a_m * a_m;
        let max_sagnac_us = (2.0 * omega_e * max_equatorial_loop_area_m2 / (c0_m_per_s * c0_m_per_s)) * 1e6;
        assert!(max_sagnac_us > 0.20 && max_sagnac_us < 0.22, "max_sagnac_us={max_sagnac_us}");
        let dc_unc = BoundUncertainty::default_datacenter();
        // Default 50 us datacenter clock-resolution margin absorbs worst-case asymmetric Sagnac by >200x!
        assert!((dc_unc.clock_resolution_us as f64) > 200.0 * max_sagnac_us);
    }
}
