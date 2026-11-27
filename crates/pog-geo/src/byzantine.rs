use crate::bounds::{
    effective_radius_km, effective_radius_km_with_uncertainty, BoundTier, BoundUncertainty,
    HALF_CIRCUMFERENCE_KM,
};
use crate::sphere::{LatLon, Vec3, EARTH_RADIUS_KM};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const EARTH_SURFACE_AREA_KM2: f64 = 4.0 * std::f64::consts::PI * EARTH_RADIUS_KM * EARTH_RADIUS_KM;

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

    pub fn from_rtt_with_uncertainty(
        anchor_id: impl Into<String>,
        anchor_location: LatLon,
        rtt_min_us: u64,
        tier: BoundTier,
        uncertainty: BoundUncertainty,
        cloud_provider: impl Into<String>,
    ) -> Self {
        let radius_km = effective_radius_km_with_uncertainty(rtt_min_us, tier, uncertainty);
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
        (self.radius_km / EARTH_RADIUS_KM).clamp(0.0, std::f64::consts::PI)
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
    /// Estimated center strictly verified to lie inside the feasible (K-f)-core.
    pub witness_centroid: LatLon,
    /// Exact maximum geodesic distance (km) from `target` to ANY point in the Byzantine (K-f)-core.
    /// No artificial cap: reaches `pi * R_mean` (~20,015.1 km) when antipodal / whole-Earth feasible.
    pub proven_max_radius_km: f64,
    /// Exact worst-case boundary point on S^2 maximizing distance from `target`.
    pub worst_case_point: LatLon,
    /// True iff 100% of the Byzantine (K-f)-core lies within `required_radius_km` of `target`.
    pub contained_within_target: bool,
    /// True iff EVERY point on Earth's surface S^2 satisfies >= (K - f) constraints (unconstrained).
    #[serde(default)]
    pub whole_earth: bool,
    /// Estimated fraction of Earth's surface area in [0.0, 1.0] belonging to the feasible (K-f)-core.
    #[serde(default)]
    pub feasible_area_fraction: f64,
    /// Estimated surface area (km^2) of the feasible (K-f)-core.
    #[serde(default)]
    pub feasible_area_km2: f64,
    /// All qualifying boundary points on S^2 (useful for GeoJSON polygon export).
    pub boundary_vertices: Vec<LatLon>,
}

/// Count how many disks contain unit vector `x` (with numerical tolerance `eps`).
fn count_containing(disks: &[DiskConstraint], x: Vec3, eps: f64) -> usize {
    disks.iter().filter(|d| d.contains_vec(x, eps)).count()
}

/// Closed-form intersection of two spherical cap boundary circles on S^2:
///   u1 . x = c1,  u2 . x = c2,  ||x|| = 1
///
/// Uses `n = u1 × u2` and `n_norm_sq = ||u1 × u2||^2` directly as the denominator
/// (mathematically identical to `1 - (u1·u2)^2`, but avoids catastrophic cancellation for
/// near-co-located anchors as close as ~1 meter apart where `1 - d^2` loses 12+ digits!).
fn intersect_two_circles(u1: Vec3, c1: f64, u2: Vec3, c2: f64) -> Vec<Vec3> {
    let n = u1.cross(u2);
    let n_norm_sq = n.norm_sq();
    // 1e-24 corresponds to ~0.006 meters separation on Earth; closer than that is truly concentric.
    if n_norm_sq < 1e-24 {
        return Vec::new();
    }
    let d = u1.dot(u2);
    let a = (c1 - c2 * d) / n_norm_sq;
    let b = (c2 - c1 * d) / n_norm_sq;
    let p = u1.scale(a) + u2.scale(b);
    let p_norm_sq = p.norm_sq();
    if p_norm_sq > 1.0 + 1e-11 {
        // Circles do not intersect.
        return Vec::new();
    }
    let rem = (1.0 - p_norm_sq).max(0.0);
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

/// Candidate extrema on circle boundary `u . x = cos(theta)` that maximize geodesic distance from `target`.
/// When `u` is collinear with `target` (or `-target`), every point on the circle is equidistant from `target`,
/// so we return 4 orthogonal cardinal points on the circle so at least one hits the feasible arc even for
/// near-co-located anchors!
fn furthest_points_on_circle(u: Vec3, theta: f64, target: Vec3) -> Vec<Vec3> {
    if theta >= std::f64::consts::PI - 1e-12 {
        return vec![-target];
    }
    if theta <= 1e-12 {
        return vec![u];
    }
    let neg_t = -target;
    let proj = neg_t - u.scale(neg_t.dot(u));
    if let Some(dir) = proj.normalize() {
        let pt = (u.scale(theta.cos()) + dir.scale(theta.sin()))
            .normalize()
            .unwrap_or(u);
        vec![pt]
    } else {
        // Collinear (target == u or target == -u): sample 4 orthogonal directions on the circle boundary.
        let e1 = u.any_orthogonal_unit();
        let e2 = u.cross(e1).normalize().unwrap_or(e1);
        let dirs = [e1, -e1, e2, -e2];
        dirs.into_iter()
            .map(|d| {
                (u.scale(theta.cos()) + d.scale(theta.sin()))
                    .normalize()
                    .unwrap_or(u)
            })
            .collect()
    }
}

/// Exact check: does EVERY point on S^2 satisfy `>= req` disks (`whole_earth`)?
///
/// Dual proof: a point `x` is EXCLUDED from the `(K - f)`-core iff `x` lies in at least `f + 1`
/// open complementary caps `C_i = { x : (-u_i) · x > cos(pi - theta_i) }`.
/// Therefore the feasible core is the WHOLE EARTH iff NO point on S^2 lies in `>= f + 1` open
/// complementary caps!
fn is_whole_earth_core(
    unit_vecs: &[Vec3],
    thetas: &[f64],
    max_byzantine: usize,
) -> bool {
    let excl_req = max_byzantine + 1;
    const STRICT_EPS: f64 = 1e-11;

    // Filter only disks with theta < pi (a disk with theta >= pi has an empty complement).
    let comp: Vec<(Vec3, f64, f64)> = unit_vecs
        .iter()
        .zip(thetas.iter())
        .filter(|(_, &th)| th < std::f64::consts::PI - 1e-12)
        .map(|(&u, &th)| {
            let cu = -u;
            let cth = std::f64::consts::PI - th;
            (cu, cth, cth.cos())
        })
        .collect();

    if comp.len() < excl_req {
        return true;
    }

    let count_strict_excluded = |x: Vec3| -> usize {
        comp.iter()
            .filter(|(cu, _, cc)| cu.dot(x) > *cc + STRICT_EPS)
            .count()
    };

    // Any non-empty open intersection of >= excl_req spherical caps contains either:
    //  (a) a complementary cap center `cu_i`,
    //  (b) a slight interior perturbation of a pairwise complement boundary intersection, or
    //  (c) the midpoint between two complementary cap centers.
    for (cu, _, _) in &comp {
        if count_strict_excluded(*cu) >= excl_req {
            return false;
        }
    }
    for i in 0..comp.len() {
        for j in (i + 1)..comp.len() {
            if let Some(mid) = (comp[i].0 + comp[j].0).normalize() {
                if count_strict_excluded(mid) >= excl_req {
                    return false;
                }
            }
            for pt in intersect_two_circles(comp[i].0, comp[i].2, comp[j].0, comp[j].2) {
                // Perturb slightly inward toward both complementary cap centers.
                let inward = comp[i].0 + comp[j].0;
                if let Some(dir) = inward.normalize() {
                    if let Some(nudged) = (pt + dir.scale(1e-7)).normalize() {
                        if count_strict_excluded(nudged) >= excl_req {
                            return false;
                        }
                    }
                }
            }
        }
    }
    true
}

/// Deterministic Fibonacci-sphere area fraction estimator (2,048 points -> ~0.05% resolution, <0.1 ms).
fn estimate_feasible_area_fraction(disks: &[DiskConstraint], req: usize, eps: f64) -> f64 {
    const N: usize = 2048;
    let ga = std::f64::consts::PI * (3.0 - 5.0_f64.sqrt());
    let mut inside = 0usize;
    for i in 0..N {
        let z = 1.0 - (2.0 * (i as f64 + 0.5)) / (N as f64);
        let r = (1.0 - z * z).max(0.0).sqrt();
        let phi = ga * (i as f64);
        let p = Vec3::new(r * phi.cos(), r * phi.sin(), z);
        if count_containing(disks, p, eps) >= req {
            inside += 1;
        }
    }
    inside as f64 / N as f64
}

/// Exact O(K^3) Byzantine (K-f)-core containment verifier on the sphere S^2.
///
/// Guarantees: If at most `max_byzantine` (`f`) anchors out of `K` are malicious/colluding
/// (able to report arbitrary fake tiny RTTs), the prover's true physical location `x*` MUST lie
/// inside at least `K - f` disks (`S_{>= K-f}`).
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
    const EPS: f64 = 1e-9;

    let target_u = target.to_unit_vec();
    let unit_vecs: Vec<Vec3> = disks.iter().map(|d| d.unit_vec()).collect();
    let thetas: Vec<f64> = disks.iter().map(|d| d.angular_radius()).collect();
    let cos_thetas: Vec<f64> = thetas.iter().map(|t| t.cos()).collect();

    let whole_earth = is_whole_earth_core(&unit_vecs, &thetas, max_byzantine);

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

    // 2. Antipodal-facing extrema on each individual circle boundary ∂D_i (4 cardinal pts if collinear).
    for i in 0..k {
        for far_pt in furthest_points_on_circle(unit_vecs[i], thetas[i], target_u) {
            if count_containing(disks, far_pt, EPS) >= req {
                qualifying_points.push(far_pt);
            }
        }
    }

    // 3. Exact antipode of target (covers global-sphere / antipodal edge cases).
    let antipode = -target_u;
    if count_containing(disks, antipode, EPS) >= req {
        qualifying_points.push(antipode);
    }

    // 4. Find/verify at least one feasible witness point (handles interior/degenerate/tangent cases too).
    let mut interior_candidates: Vec<Vec3> = Vec::new();
    if let Some(w) = optional_witness {
        interior_candidates.push(w.to_unit_vec());
    }
    interior_candidates.push(target_u);
    for u in &unit_vecs {
        interior_candidates.push(*u);
    }
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
        // Only push antipode if antipode is genuinely feasible; otherwise use verified witness
        // (e.g., single-point tangent core or zero-radius exact anchor match).
        if whole_earth || count_containing(disks, antipode, EPS) >= req {
            qualifying_points.push(antipode);
        } else {
            qualifying_points.push(witness_u);
        }
    }

    // Evaluate maximum geodesic distance from target across all qualifying boundary extrema.
    let mut worst_dist_km = if whole_earth { HALF_CIRCUMFERENCE_KM } else { -1.0_f64 };
    let mut worst_pt = if whole_earth { antipode } else { witness_u };
    for pt in &qualifying_points {
        let d = target_u.geodesic_km(*pt);
        if d > worst_dist_km {
            worst_dist_km = d;
            worst_pt = *pt;
        }
    }

    // Compute a clean centroid strictly verified to lie inside the feasible (K-f)-core.
    let centroid_u = {
        let sum = qualifying_points
            .iter()
            .fold(Vec3::new(0.0, 0.0, 0.0), |acc, v| acc + *v);
        sum.normalize()
            .filter(|c| count_containing(disks, *c, EPS) >= req)
            .unwrap_or(witness_u)
    };

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

    let feasible_area_fraction = if whole_earth {
        1.0
    } else {
        estimate_feasible_area_fraction(disks, req, EPS)
    };
    let feasible_area_km2 = feasible_area_fraction * EARTH_SURFACE_AREA_KM2;

    Ok(ByzantineCoreResult {
        total_anchors: k,
        max_byzantine,
        required_disks: req,
        witness_centroid: c_ll,
        proven_max_radius_km: worst_dist_km,
        worst_case_point: worst_pt.to_lat_lon(),
        contained_within_target: worst_dist_km <= required_radius_km,
        whole_earth,
        feasible_area_fraction,
        feasible_area_km2,
        boundary_vertices,
    })
}

/// Checks whether two sets of constraints have ANY point in common on S^2.
pub fn regions_intersect(disks_a: &[DiskConstraint], disks_b: &[DiskConstraint]) -> bool {
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
    fn test_prod_v6_repro_sj_fra_nrt_150ms_is_whole_earth() {
        let sj = LatLon::new(37.4, -121.9);
        let fra = LatLon::new(50.1, 8.7);
        let nrt = LatLon::new(35.7, 139.7);
        let disks = vec![
            DiskConstraint::from_rtt("sj", sj, 150_000, BoundTier::Vacuum, "aws"),
            DiskConstraint::from_rtt("fra", fra, 150_000, BoundTier::Vacuum, "aws"),
            DiskConstraint::from_rtt("nrt", nrt, 150_000, BoundTier::Vacuum, "aws"),
        ];
        let res = verify_byzantine_core(&disks, 0, sj, 15_000.0, None).unwrap();
        assert!(res.whole_earth, "150 ms SJ/FRA/NRT must be whole Earth");
        assert!(!res.contained_within_target);
        assert!(
            (res.proven_max_radius_km - HALF_CIRCUMFERENCE_KM).abs() < 1e-3,
            "Expected ~20,015.1 km, got {:.2}",
            res.proven_max_radius_km
        );
        assert!((res.feasible_area_fraction - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_near_colocated_1m_apart_anchors_no_cancellation() {
        let a1 = LatLon::new(50.1109, 8.6821);
        let a2 = LatLon::new(50.110909, 8.6821); // ~1 meter north
        let disks = vec![
            DiskConstraint {
                anchor_id: "a1".into(),
                anchor_location: a1,
                rtt_min_us: 2_000,
                radius_km: 300.0,
                cloud_provider: "gcp".into(),
            },
            DiskConstraint {
                anchor_id: "a2".into(),
                anchor_location: a2,
                rtt_min_us: 2_000,
                radius_km: 300.0,
                cloud_provider: "aws".into(),
            },
        ];
        let res = verify_byzantine_core(&disks, 0, a1, 350.0, Some(a1)).unwrap();
        assert!(res.contained_within_target, "Expected contained, got {:.2}", res.proven_max_radius_km);
        assert!(
            (res.proven_max_radius_km - 300.0).abs() < 1.0,
            "Expected ~300 km, got {:.2}",
            res.proven_max_radius_km
        );
        assert!(!res.whole_earth);
    }

    #[test]
    fn test_poles_dateline_hemisphere_and_inconsistent() {
        // Exact hemisphere centered on North Pole -> max distance from North Pole is pi/2 * R (~10,007.56 km)
        let np = LatLon::new(90.0, 0.0);
        let d_np = DiskConstraint {
            anchor_id: "np".into(),
            anchor_location: np,
            rtt_min_us: 66_700,
            radius_km: HALF_CIRCUMFERENCE_KM / 2.0,
            cloud_provider: "test".into(),
        };
        let res_np = verify_byzantine_core(&[d_np], 0, np, 10_500.0, None).unwrap();
        assert!(!res_np.whole_earth);
        assert!((res_np.proven_max_radius_km - HALF_CIRCUMFERENCE_KM / 2.0).abs() < 1.0);

        // Dateline crossing (179E and -179W, 500 km radius each)
        let d_e = DiskConstraint {
            anchor_id: "e".into(),
            anchor_location: LatLon::new(0.0, 179.0),
            rtt_min_us: 3_300,
            radius_km: 500.0,
            cloud_provider: "aws".into(),
        };
        let d_w = DiskConstraint {
            anchor_id: "w".into(),
            anchor_location: LatLon::new(0.0, -179.0),
            rtt_min_us: 3_300,
            radius_km: 500.0,
            cloud_provider: "gcp".into(),
        };
        let res_dl = verify_byzantine_core(&[d_e, d_w], 0, LatLon::new(0.0, 180.0), 500.0, None).unwrap();
        assert!(res_dl.contained_within_target);

        // Disjoint inconsistent measurements -> EmptyFeasibleRegion
        let d_sf = DiskConstraint {
            anchor_id: "sf".into(),
            anchor_location: LatLon::new(37.77, -122.42),
            rtt_min_us: 1_000,
            radius_km: 150.0,
            cloud_provider: "aws".into(),
        };
        let d_tyo = DiskConstraint {
            anchor_id: "tyo".into(),
            anchor_location: LatLon::new(35.68, 139.65),
            rtt_min_us: 1_000,
            radius_km: 150.0,
            cloud_provider: "gcp".into(),
        };
        assert!(matches!(
            verify_byzantine_core(&[d_sf, d_tyo], 0, LatLon::new(37.77, -122.42), 500.0, None),
            Err(GeoError::EmptyFeasibleRegion)
        ));
    }

    #[test]
    fn test_disconnected_2of4_byzantine_core() {
        // Two US disks + two EU disks, each 400 km: 2-of-4 core has TWO disconnected components!
        // Max distance from NYC MUST reach the far edge of the EU component (> 6,000 km)!
        let nyc = LatLon::new(40.71, -74.00);
        let fra = LatLon::new(50.11, 8.68);
        let disks = vec![
            DiskConstraint { anchor_id: "u1".into(), anchor_location: nyc, rtt_min_us: 2000, radius_km: 400.0, cloud_provider: "aws".into() },
            DiskConstraint { anchor_id: "u2".into(), anchor_location: LatLon::new(40.8, -74.1), rtt_min_us: 2000, radius_km: 400.0, cloud_provider: "gcp".into() },
            DiskConstraint { anchor_id: "e1".into(), anchor_location: fra, rtt_min_us: 2000, radius_km: 400.0, cloud_provider: "aws".into() },
            DiskConstraint { anchor_id: "e2".into(), anchor_location: LatLon::new(50.2, 8.7), rtt_min_us: 2000, radius_km: 400.0, cloud_provider: "gcp".into() },
        ];
        let res = verify_byzantine_core(&disks, 2, nyc, 1000.0, None).unwrap();
        assert!(!res.contained_within_target);
        assert!(res.proven_max_radius_km > 6_400.0, "Got {:.1} km", res.proven_max_radius_km);
    }

    #[test]
    fn test_four_orthogonal_circles_shrink_region() {
        let center = LatLon::new(0.0, 0.0);
        let anchors = [
            ("north", LatLon::new(4.5, 0.0), "gcp"),
            ("south", LatLon::new(-4.5, 0.0), "aws"),
            ("east", LatLon::new(0.0, 4.5), "azure"),
            ("west", LatLon::new(0.0, -4.5), "ovh"),
        ];
        let disks: Vec<DiskConstraint> = anchors
            .iter()
            .map(|(id, loc, cloud)| {
                DiskConstraint::from_rtt(*id, *loc, 8_000, BoundTier::Fiber, *cloud)
            })
            .collect();

        let res = verify_byzantine_core(&disks, 0, center, 500.0, Some(center)).unwrap();
        assert!(res.contained_within_target);
        assert!(
            res.proven_max_radius_km < 470.0 && res.proven_max_radius_km > 340.0,
            "Expected ~410-445 km with conservative uncertainty, got {:.1} km",
            res.proven_max_radius_km
        );
    }

    #[test]
    fn test_byzantine_colluding_anchor_cannot_spoof_singapore() {
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
                let d_km = loc.distance_km(beijing);
                let rtt_us = (((2.0 * d_km * 1.4 / 204_000.0) + 0.002) * 1e6) as u64;
                DiskConstraint::from_rtt(*id, *loc, rtt_us, BoundTier::Vacuum, *cloud)
            })
            .collect();

        disks.push(DiskConstraint::from_rtt(
            "malicious-sg",
            singapore,
            500,
            BoundTier::Vacuum,
            "rogue",
        ));

        let res = verify_byzantine_core(&disks, 1, singapore, 500.0, Some(beijing)).unwrap();
        assert!(!res.contained_within_target);
        assert!(res.proven_max_radius_km > 4400.0);
    }

    #[test]
    fn test_artificial_delay_only_weakens_proof() {
        let ashburn = LatLon::new(39.0438, -77.4874);
        let d_fast = DiskConstraint::from_rtt("aws-iad", ashburn, 1_000, BoundTier::Vacuum, "aws");
        let d_delayed =
            DiskConstraint::from_rtt("aws-iad", ashburn, 10_000, BoundTier::Vacuum, "aws");
        let r_fast = verify_byzantine_core(&[d_fast], 0, ashburn, 250.0, Some(ashburn)).unwrap();
        let r_del = verify_byzantine_core(&[d_delayed], 0, ashburn, 250.0, Some(ashburn)).unwrap();
        assert!(r_fast.contained_within_target);
        assert!(!r_del.contained_within_target);
        assert!(r_del.proven_max_radius_km > r_fast.proven_max_radius_km * 6.0);
    }
}
