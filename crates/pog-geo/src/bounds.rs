use serde::{Deserialize, Serialize};

/// Speed of light in vacuum (km/s).
/// Uncheatable upper bound for ALL physical media, including Starlink vacuum laser ISLs,
/// hollow-core fiber (~0.99 c0), and line-of-sight microwave links.
pub const C_VACUUM_KM_PER_S: f64 = 299_792.458;

/// Speed of light in standard single-mode silica optical fiber (n ≈ 1.468 -> ~204,218 km/s).
/// Conservative upper bound for terrestrial/subsea silica fiber (including private cloud backbones).
pub const C_FIBER_KM_PER_S: f64 = 204_000.0;

/// Conservative default calibrated empirical speed on typical routed internet fiber
/// (~1.4x fiber path stretch -> ~145,000 km/s). Overridden per-corridor by the Anchor mesh.
pub const C_CALIBRATED_DEFAULT_KM_PER_S: f64 = 145_000.0;

/// Bounding model tier.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum BoundTier {
    /// Tier 1A: Strict vacuum speed of light (c0 = 299,792.458 km/s, ~149.9 km / 93.1 mi per ms RTT).
    /// Uncheatable even with Starlink vacuum optical ISLs, hollow-core fiber, or microwave links.
    Vacuum,
    /// Tier 1B: Silica optical fiber speed (c_fiber = 204,000 km/s, ~102.0 km / 63.4 mi per ms RTT).
    /// Uncheatable over terrestrial/subsea standard optical fiber, including private cloud backbones.
    /// Note: Over transcontinental distances (> ~2,500 km), LEO satellite laser ISLs (Starlink)
    /// can travel closer to c0 once slant-range overhead is amortized; use `Vacuum` when defending
    /// against satellite-laser relays.
    Fiber,
    /// Tier 2: Empirically calibrated corridor velocity (km/s) learned from the Anchor-to-Anchor mesh
    /// (similar to IPinfo ProbeNet / Witness Chain calibration curves). Used for tight city/metro
    /// confidence radii alongside Tier 1 hard physics proofs.
    Calibrated { effective_km_per_s: f64 },
}

impl BoundTier {
    pub fn velocity_km_per_s(self) -> f64 {
        match self {
            BoundTier::Vacuum => C_VACUUM_KM_PER_S,
            BoundTier::Fiber => C_FIBER_KM_PER_S,
            BoundTier::Calibrated { effective_km_per_s } => {
                effective_km_per_s.clamp(50_000.0, C_VACUUM_KM_PER_S)
            }
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            BoundTier::Vacuum => "tier1a_vacuum",
            BoundTier::Fiber => "tier1b_fiber",
            BoundTier::Calibrated { .. } => "tier2_calibrated",
        }
    }
}

/// Convert measured round-trip time (microseconds) to maximum physical radius (km).
/// Always sets assumed processing delay to 0 for soundness: faster adversary hardware
/// can never beat `c_eff * rtt / 2`.
pub fn effective_radius_km(rtt_us: u64, tier: BoundTier) -> f64 {
    let rtt_s = (rtt_us as f64) * 1e-6;
    0.5 * tier.velocity_km_per_s() * rtt_s
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
///
/// Key physics result:
/// 1. Every satellite hop pays a mandatory vertical/slant-range tax (2 × slant_range up + 2 × slant_range down).
///    At 550 km altitude (overhead 90°), minimum vertical round-trip tax is already ~7.34 ms (~11.4 ms at 40° elevation).
/// 2. Along the orbital arc, optical laser ISLs travel in vacuum at `c0` (~300 km/ms), beating silica fiber (~204 km/ms)
///    and real routed terrestrial fiber (~145 km/ms) on long transcontinental / transoceanic hops (> ~2,500 km).
/// 3. Crucially, `starlink_min_rtt_ms(d)` is STILL strictly `> 2 * d / c0`, proving `BoundTier::Vacuum`
///    is mathematically uncheatable even by an adversary with dedicated Starlink laser relays!
pub fn starlink_min_rtt_ms(ground_distance_km: f64, model: StarlinkModel) -> f64 {
    let elev_rad = model.elevation_deg.clamp(15.0, 90.0).to_radians();
    // Slant range approximation from Earth surface to shell altitude at given elevation angle.
    let slant_km = model.altitude_km / elev_rad.sin();
    // One-way path: up to satellite + horizontal laser ISL at altitude + down to destination.
    // Even if we ignore curvature expansion (R+h)/R > 1 (optimistic for attacker), path >= 2*slant + ground_distance.
    let one_way_km = 2.0 * slant_km + ground_distance_km;
    let propagation_rtt_ms = (2.0 * one_way_km / C_VACUUM_KM_PER_S) * 1_000.0;
    propagation_rtt_ms + model.switching_overhead_ms
}

/// Compute the crossover distance (km) where optimistic Starlink LEO vacuum ISLs become faster
/// than ideal silica fiber (`C_FIBER_KM_PER_S`), showing exactly when `BoundTier::Fiber`
/// could theoretically be beaten by satellite lasers while `BoundTier::Vacuum` holds unconditionally.
pub fn starlink_vs_fiber_crossover_km(model: StarlinkModel) -> f64 {
    let elev_rad = model.elevation_deg.clamp(15.0, 90.0).to_radians();
    let slant_km = model.altitude_km / elev_rad.sin();
    // Solve: 2*(2*slant + d)/c0 + overhead_s = 2*d/c_fiber
    let overhead_s = model.switching_overhead_ms * 1e-3;
    let lhs_const = (4.0 * slant_km / C_VACUUM_KM_PER_S) + overhead_s;
    let coeff = (2.0 / C_FIBER_KM_PER_S) - (2.0 / C_VACUUM_KM_PER_S);
    lhs_const / coeff
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vacuum_always_bounds_starlink() {
        let model = StarlinkModel {
            altitude_km: 340.0, // even VLEO!
            elevation_deg: 90.0, // directly overhead best case
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
        // Around ~4,000–5,500 km vs ideal silica fiber (~1,800–2,500 km vs routed 1.4x fiber)
        assert!(crossover > 2000.0 && crossover < 7000.0, "crossover={crossover}");
        let d = 9000.0; // transoceanic (e.g., Tokyo-San Francisco ~8,280 km)
        let starlink_rtt_ms = starlink_min_rtt_ms(d, model);
        let ideal_fiber_rtt_ms = (2.0 * d / C_FIBER_KM_PER_S) * 1000.0;
        assert!(
            starlink_rtt_ms < ideal_fiber_rtt_ms,
            "At {d} km, Starlink ({starlink_rtt_ms:.1} ms) should beat ideal silica fiber ({ideal_fiber_rtt_ms:.1} ms)"
        );
    }
}
