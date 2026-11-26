use crate::bounds::{effective_radius_km, BoundTier};
use crate::sphere::{LatLon, Vec3, EARTH_RADIUS_KM};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GeoError {
    #[error("insufficient anchors: got {got}, need at least {required}")]
    InsufficientAnchors { got: usize, required: usize },
    #[error("invalid fault tolerance: max_byzantine ({f}) must be < anchor count ({k})")]
    InvalidFaultTolerance { k: usize, f: usize },
    #[error("Byzantine (K-f)-core is empty: measurements are physically inconsistent")]
    EmptyFeasibleRegion,
}

/// A single Anchor's geodesic upper-bound disk constraint on S^2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskConstraint {
    pub anchor_id: String,
    pub anchor_location: LatLon,
    pub rtt_min_us: u64,
    pub radius_km: f64,
    pub cloud_provider: String,
}

impl DiskConstraint {
    pub fn from_rtt(
        anchor_id: impl Into<String>,
        anchor_location: LatLon,
        rtt_min_us: u64,
        tier: BoundTier,
        cloud_provider: impl Into<String>,
    ) -> Self {
        let radius_km = effective_radius_km(rtt_min_us, tier);
        Self {
            anchor_id: anchor_id.into(),
            anchor_location,
            rtt_min_us,
            radius_km,
            cloud_provider: cloud_provider.into(),
        }
    }

    #[inline]
    pub fn unit_vec(&self) -> Vec3 {
        self.anchor_location.to_unit_vec()
    }

    #[inline]
    pub fn angular_radius(&self) -> f64 {
        (self.radius_km / EARTH_RADIUS_KM).min(std::f64::consts::PI)
    }

    #[inline]
    pub fn cos_theta(&self) -> f64 {
        self.angular_radius().cos()
    }

    /// Returns true if unit vector `x` lies inside (or within epsilon of) this spherical cap.
    #[inline]
    pub fn contains_vec(&self, x: Vec3, eps: f64) -> bool {
        self.unit_vec().dot(x) >= self.cos_theta() - eps
    }
}

/// Complete output of the exact O(K^3) Byzantine (K-f)-core verification on S^2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByzantineCoreResult {
    pub total_anchors: usize,
    pub max_byzantine: usize,
    pub required_disks: usize,
    /// Estimated center inside the feasible (K-f)-core.
    pub witness_centroid: LatLon,
    /// Exact maximum geodesic distance (km) from `target` to ANY point in the Byzantine (K-f)-core.
    pub proven_max_radius_km: f64,
    /// Exact worst-case boundary point on S^2 maximizing distance from `target`.
    pub worst_case_point: LatLon,
    /// True iff 100% of the Byzantine (K-f)-core lies within `required_radius_km` of `target`.
    pub contained_within_target: bool,
    /// All qualifying boundary points on S^2 (useful for GeoJSON polygon export).
    pub boundary_vertices: Vec<LatLon>,
}

/// Count how many disks contain unit vector `x` (with numerical tolerance `eps`).
fn count_containing(disks: &[DiskConstraint], x: Vec3, eps: f64) -> usize {
    disks.iter().filter(|d| d.contains_vec(x, eps)).count()
}

/// Closed-form intersection of two spherical cap boundary circles on S^2:
///   u1 . x = c1,  u2 . x = c2,  ||x|| = 1
fn intersect_two_circles(u1: Vec3, c1: f64, u2: Vec3, c2: f64) -> Vec<Vec3> {
    let d = u1.dot(u2);
    let denom = 1.0 - d * d;
    if denom < 1e-12 {
        // Co-located or antipodal anchors: circles are concentric (parallel planes).
        return Vec::new();
    }
    let a = (c1 - c2 * d) / denom;
    let b = (c2 - c1 * d) / denom;
    let p = u1.scale(a) + u2.scale(b);
    let p_norm_sq = p.norm_sq();
    if p_norm_sq > 1.0 + 1e-11 {
        // Circles do not intersect.
        return Vec::new();
    }
    let rem = (1.0 - p_norm_sq).max(0.0);
    let n = u1.cross(u2);
    let n_norm_sq = n.norm_sq();
    if n_norm_sq < 1e-15 {
        return Vec::new();
    }
    let t = (rem / n_norm_sq).sqrt();
    if t < 1e-12 {
        // Tangent: single intersection point.
        p.normalize().into_iter().collect()
    } else {
        let mut pts = Vec::with_capacity(2);
        if let Some(x1) = (p + n.scale(t)).normalize() {
            pts.push(x1);
        }
        if let Some(x2) = (p - n.scale(t)).normalize() {
            pts.push(x2);
        }
        pts
    }
}

/// Exact point on circle boundary `u . x = cos(theta)` that maximizes geodesic distance from `target`.
fn furthest_point_on_circle(u: Vec3, theta: f64, target: Vec3) -> Vec3 {
    if theta >= std::f64::consts::PI - 1e-12 {
        return -target;
    }
    // Direction pointing away from target, projected tangent to u.
    let neg_t = -target;
    let proj = neg_t - u.scale(neg_t.dot(u));
    let dir = proj
        .normalize()
        .unwrap_or_else(|| u.any_orthogonal_unit());
    (u.scale(theta.cos()) + dir.scale(theta.sin()))
        .normalize()
        .unwrap_or(u)
}

/// Exact O(K^3) Byzantine (K-f)-core containment verifier on the sphere S^2.
///
/// Guarantees: If at most `max_byzantine` (`f`) anchors out of `K` are malicious/colluding
/// (able to report arbitrary fake tiny RTTs), the prover's true physical location `x*` MUST lie
/// inside at least `K - f` disks (`S_{>= K-f}`).
///
/// This function exhaustively evaluates every possible boundary extremum of `S_{>= K-f}`:
/// 1. Every pairwise circle boundary intersection `∂D_i ∩ ∂D_j` inside >= K - f disks.
/// 2. Every single-circle furthest point from `target` on `∂D_i` inside >= K - f disks.
/// 3. The antipode `-target` itself (handles the degenerate global-coverage case).
///
/// If `proven_max_radius_km <= required_radius_km`, then 100% of `S_{>= K-f}` is mathematically
/// proven to lie inside the geofence disk `B(target, required_radius_km)`.
pub fn verify_byzantine_core(
    disks: &[DiskConstraint],
    max_byzantine: usize,
    target: LatLon,
    required_radius_km: f64,
    optional_witness: Option<LatLon>,
) -> Result<ByzantineCoreResult, GeoError> {
    let k = disks.len();
    if k == 0 {
        return Err(GeoError::InsufficientAnchors { got: 0, required: 1 });
    }
    if max_byzantine >= k {
        return Err(GeoError::InvalidFaultTolerance {
            k,
            f: max_byzantine,
        });
    }
    let req = k - max_byzantine;
    // Slight numerical tolerance so boundary points computed via trig/cross-products are never missed.
    const EPS: f64 = 1e-9;

    let target_u = target.to_unit_vec();
    let unit_vecs: Vec<Vec3> = disks.iter().map(|d| d.unit_vec()).collect();
    let thetas: Vec<f64> = disks.iter().map(|d| d.angular_radius()).collect();
    let cos_thetas: Vec<f64> = thetas.iter().map(|t| t.cos()).collect();

    let mut qualifying_points: Vec<Vec3> = Vec::new();

    // 1. All pairwise boundary circle intersections (at most K*(K-1) points).
    for i in 0..k {
        for j in (i + 1)..k {
            for pt in intersect_two_circles(unit_vecs[i], cos_thetas[i], unit_vecs[j], cos_thetas[j])
            {
                if count_containing(disks, pt, EPS) >= req {
                    qualifying_points.push(pt);
                }
            }
        }
    }

    // 2. Antipodal-facing extrema on each individual circle boundary ∂D_i (at most K points).
    for i in 0..k {
        let far_pt = furthest_point_on_circle(unit_vecs[i], thetas[i], target_u);
        if count_containing(disks, far_pt, EPS) >= req {
            qualifying_points.push(far_pt);
        }
    }

    // 3. Exact antipode of target (covers global-sphere edge case).
    let antipode = -target_u;
    if count_containing(disks, antipode, EPS) >= req {
        qualifying_points.push(antipode);
    }

    // 4. Find/verify at least one feasible witness point (handles interior/degenerate cases too).
    let mut interior_candidates: Vec<Vec3> = Vec::new();
    if let Some(w) = optional_witness {
        interior_candidates.push(w.to_unit_vec());
    }
    interior_candidates.push(target_u);
    for u in &unit_vecs {
        interior_candidates.push(*u);
    }
    // Also try average of qualifying boundary points.
    if !qualifying_points.is_empty() {
        let sum = qualifying_points
            .iter()
            .fold(Vec3::new(0.0, 0.0, 0.0), |acc, v| acc + *v);
        if let Some(avg) = sum.normalize() {
            interior_candidates.push(avg);
        }
    }

    let witness_u = interior_candidates
        .into_iter()
        .find(|pt| count_containing(disks, *pt, EPS) >= req)
        .or_else(|| qualifying_points.first().copied())
        .ok_or(GeoError::EmptyFeasibleRegion)?;

    if qualifying_points.is_empty() {
        // Non-empty feasible set with zero boundary points only happens if every disk is the entire sphere.
        qualifying_points.push(antipode);
    }

    // Evaluate maximum geodesic distance from target across all qualifying boundary extrema.
    let mut worst_dist_km = -1.0_f64;
    let mut worst_pt = witness_u;
    for pt in &qualifying_points {
        let d = target_u.geodesic_km(*pt);
        if d > worst_dist_km {
            worst_dist_km = d;
            worst_pt = *pt;
        }
    }

    // Compute a clean centroid from qualifying boundary points (fallback to witness).
    let centroid_u = {
        let sum = qualifying_points
            .iter()
            .fold(Vec3::new(0.0, 0.0, 0.0), |acc, v| acc + *v);
        sum.normalize()
            .filter(|c| count_containing(disks, *c, EPS) >= req)
            .unwrap_or(witness_u)
    };

    // Sort boundary vertices counterclockwise around centroid for clean GeoJSON polygon export.
    let mut boundary_vertices: Vec<LatLon> = qualifying_points
        .iter()
        .map(|p| p.to_lat_lon())
        .collect();
    let c_ll = centroid_u.to_lat_lon();
    boundary_vertices.sort_by(|a, b| {
        c_ll.bearing_deg(*a)
            .partial_cmp(&c_ll.bearing_deg(*b))
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(ByzantineCoreResult {
        total_anchors: k,
        max_byzantine,
        required_disks: req,
        witness_centroid: c_ll,
        proven_max_radius_km: worst_dist_km,
        worst_case_point: worst_pt.to_lat_lon(),
        contained_within_target: worst_dist_km <= required_radius_km,
        boundary_vertices,
    })
}

/// Checks whether two sets of constraints have ANY point in common on S^2.
/// Used for continuous hourly hardware relocation detection: if `S(t1) ∩ S(t2) == ∅`,
/// the physical server MUST have moved between `t1` and `t2` (e.g., boat/plane/truck)!
pub fn regions_intersect(
    disks_a: &[DiskConstraint],
    disks_b: &[DiskConstraint],
) -> bool {
    let mut combined = Vec::with_capacity(disks_a.len() + disks_b.len());
    combined.extend_from_slice(disks_a);
    combined.extend_from_slice(disks_b);
    let hint = disks_a
        .first()
        .map(|d| d.anchor_location)
        .unwrap_or(LatLon::new(0.0, 0.0));
    verify_byzantine_core(&combined, 0, hint, f64::MAX, None).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_four_orthogonal_circles_shrink_region() {
        // Prover at (0, 0), surrounded by 4 anchors ~500 km away in N/S/E/W (~4.5 deg).
        let center = LatLon::new(0.0, 0.0);
        let anchors = [
            ("north", LatLon::new(4.5, 0.0), "gcp"),
            ("south", LatLon::new(-4.5, 0.0), "aws"),
            ("east", LatLon::new(0.0, 4.5), "azure"),
            ("west", LatLon::new(0.0, -4.5), "ovh"),
        ];
        // 8 ms RTT (~1.4x fiber stretch + overhead for 500 km).
        let disks: Vec<DiskConstraint> = anchors
            .iter()
            .map(|(id, loc, cloud)| {
                DiskConstraint::from_rtt(*id, *loc, 8_000, BoundTier::Fiber, *cloud)
            })
            .collect();

        // Single disk radius is 816 km, but 4-circle intersection should be ~380 km!
        let res = verify_byzantine_core(&disks, 0, center, 450.0, Some(center)).unwrap();
        assert!(res.contained_within_target);
        assert!(
            res.proven_max_radius_km < 400.0 && res.proven_max_radius_km > 340.0,
            "Expected ~370-385 km, got {:.1} km",
            res.proven_max_radius_km
        );
    }

    #[test]
    fn test_byzantine_colluding_anchor_cannot_spoof_singapore() {
        // True prover is in Beijing (39.9042, 116.4074).
        // It tries to spoof Singapore (1.3521, 103.8198) with 1 colluding Singapore anchor
        // reporting fake 0.5 ms RTT, while 5 honest Asia anchors measure real RTTs to Beijing!
        let beijing = LatLon::new(39.9042, 116.4074);
        let singapore = LatLon::new(1.3521, 103.8198);

        let honest_anchors = [
            ("gcp-tokyo", LatLon::new(35.6762, 139.6503), "gcp"),
            ("aws-seoul", LatLon::new(37.5665, 126.9780), "aws"),
            ("gcp-taiwan", LatLon::new(24.0518, 120.5161), "gcp"),
            ("tencent-hk", LatLon::new(22.3193, 114.1694), "tencent"),
            ("aws-mumbai", LatLon::new(19.0760, 72.8777), "aws"),
        ];

        let mut disks: Vec<DiskConstraint> = honest_anchors
            .iter()
            .map(|(id, loc, cloud)| {
                // Realistic internet RTT to Beijing (~1.4x fiber stretch + 2 ms overhead).
                let d_km = loc.distance_km(beijing);
                let rtt_us = (((2.0 * d_km * 1.4 / 204_000.0) + 0.002) * 1e6) as u64;
                DiskConstraint::from_rtt(*id, *loc, rtt_us, BoundTier::Vacuum, *cloud)
            })
            .collect();

        // Add 1 colluding malicious Singapore anchor lying that RTT = 500 us (0.5 ms)!
        disks.push(DiskConstraint::from_rtt(
            "malicious-sg",
            singapore,
            500,
            BoundTier::Vacuum,
            "rogue",
        ));

        // With f = 1 (5-of-6 Byzantine core), the malicious anchor CANNOT pull the core to Singapore!
        let res = verify_byzantine_core(&disks, 1, singapore, 500.0, Some(beijing)).unwrap();
        assert!(
            !res.contained_within_target,
            "Spoofing Singapore MUST fail under f=1 Byzantine core!"
        );
        // Beijing MUST remain inside the feasible region, so worst-case distance from Singapore > 4000 km!
        assert!(
            res.proven_max_radius_km > 4400.0,
            "Worst-case distance from Singapore should exceed Beijing's true distance (~4480 km), got {:.1}",
            res.proven_max_radius_km
        );
    }

    #[test]
    fn test_artificial_delay_only_weakens_proof() {
        let ashburn = LatLon::new(39.0438, -77.4874);
        let d_fast = DiskConstraint::from_rtt("aws-iad", ashburn, 1_000, BoundTier::Vacuum, "aws");
        let d_delayed =
            DiskConstraint::from_rtt("aws-iad", ashburn, 10_000, BoundTier::Vacuum, "aws");
        let r_fast = verify_byzantine_core(&[d_fast], 0, ashburn, 200.0, Some(ashburn)).unwrap();
        let r_del = verify_byzantine_core(&[d_delayed], 0, ashburn, 200.0, Some(ashburn)).unwrap();
        assert!(r_fast.contained_within_target);
        assert!(!r_del.contained_within_target);
        assert!(r_del.proven_max_radius_km > r_fast.proven_max_radius_km * 9.0);
    }
}
