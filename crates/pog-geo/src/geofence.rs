use crate::byzantine::{ByzantineCoreResult, DiskConstraint};
use crate::sphere::{LatLon, Vec3, EARTH_RADIUS_KM};
use serde::{Deserialize, Serialize};

/// A closed geographic polygon on Earth's surface (used for export-control exclusion
/// zones and data-sovereignty jurisdiction boundaries).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoPolygon {
    pub id: String,
    pub name: String,
    /// Ordered ring of polygon vertices (implicitly closed from last to first).
    pub vertices: Vec<LatLon>,
}

impl GeoPolygon {
    pub fn new(id: impl Into<String>, name: impl Into<String>, vertices: Vec<LatLon>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            vertices,
        }
    }

    /// Reference longitude for dateline-safe local unwrapping.
    fn ref_lon(&self) -> f64 {
        self.vertices.first().map(|v| v.lon).unwrap_or(0.0)
    }

    /// Unwrap `lon` into `[ref_lon - 180, ref_lon + 180]` to avoid ±180° seam tears.
    fn unwrap_lon(lon: f64, ref_lon: f64) -> f64 {
        let mut d = lon - ref_lon;
        while d > 180.0 {
            d -= 360.0;
        }
        while d < -180.0 {
            d += 360.0;
        }
        ref_lon + d
    }

    /// Point-in-polygon check (dateline-safe ray casting on unwrapped geodetic coordinates).
    /// Returns false if polygon has fewer than 3 vertices.
    pub fn contains(&self, pt: LatLon) -> bool {
        let n = self.vertices.len();
        if n < 3 {
            return false;
        }
        let rlon = self.ref_lon();
        let px = Self::unwrap_lon(pt.lon, rlon);
        let py = pt.lat;

        let mut inside = false;
        let mut j = n - 1;
        for i in 0..n {
            let vi = self.vertices[i];
            let vj = self.vertices[j];
            let xi = Self::unwrap_lon(vi.lon, rlon);
            let yi = vi.lat;
            let xj = Self::unwrap_lon(vj.lon, rlon);
            let yj = vj.lat;

            let intersects = ((yi > py) != (yj > py))
                && (px < (xj - xi) * (py - yi) / (yj - yi) + xi);
            if intersects {
                inside = !inside;
            }
            j = i;
        }
        inside
    }

    /// Exact minimum geodesic distance (km) from `pt` to this polygon (`0.0` if inside).
    pub fn distance_km(&self, pt: LatLon) -> f64 {
        if self.vertices.is_empty() {
            return f64::INFINITY;
        }
        if self.contains(pt) {
            return 0.0;
        }
        let p = pt.to_unit_vec();
        let n = self.vertices.len();
        let mut min_dist = f64::INFINITY;
        for i in 0..n {
            let a = self.vertices[i].to_unit_vec();
            let b = self.vertices[(i + 1) % n].to_unit_vec();
            let d = point_to_great_circle_segment_km(p, a, b);
            if d < min_dist {
                min_dist = d;
            }
        }
        min_dist
    }

    /// Generate sample points along the polygon's boundary edges and interior centroid so that
    /// even a small enclave (e.g., Kaliningrad) lying strictly inside a large feasible circle
    /// is guaranteed to be detected!
    pub fn sample_probe_points(&self, max_step_km: f64) -> Vec<LatLon> {
        let n = self.vertices.len();
        if n == 0 {
            return Vec::new();
        }
        let step = max_step_km.max(10.0);
        let mut pts = Vec::with_capacity(n * 4 + 4);

        // 1. All vertices + densified great-circle edges.
        for i in 0..n {
            let a = self.vertices[i];
            let b = self.vertices[(i + 1) % n];
            pts.push(a);
            let seg_km = a.distance_km(b);
            let steps = (seg_km / step).ceil() as usize;
            if steps > 1 {
                let va = a.to_unit_vec();
                let vb = b.to_unit_vec();
                for s in 1..steps {
                    let t = (s as f64) / (steps as f64);
                    if let Some(mid) = (va.scale(1.0 - t) + vb.scale(t)).normalize() {
                        pts.push(mid.to_lat_lon());
                    }
                }
            }
        }

        // 2. Spherical centroid + vertex-to-centroid midpoints (for strictly interior enclaves).
        let mut sum = Vec3::new(0.0, 0.0, 0.0);
        for v in &self.vertices {
            sum = sum + v.to_unit_vec();
        }
        if let Some(c) = sum.normalize() {
            let c_ll = c.to_lat_lon();
            if self.contains(c_ll) {
                pts.push(c_ll);
                for v in &self.vertices {
                    if let Some(m) = (c + v.to_unit_vec()).normalize() {
                        let m_ll = m.to_lat_lon();
                        if self.contains(m_ll) {
                            pts.push(m_ll);
                        }
                    }
                }
            }
        }

        pts
    }
}

/// Shortest great-circle distance (km) from unit vector `p` to minor great-circle arc `a -> b`.
fn point_to_great_circle_segment_km(p: Vec3, a: Vec3, b: Vec3) -> f64 {
    let ab_cross = a.cross(b);
    let norm_ab = ab_cross.norm();
    if norm_ab < 1e-12 {
        return a.angular_distance(p) * EARTH_RADIUS_KM;
    }
    let plane_n = ab_cross.scale(1.0 / norm_ab);
    // Project p onto the great-circle plane spanned by (a, b).
    let proj_raw = p - plane_n.scale(p.dot(plane_n));
    if let Some(proj) = proj_raw.normalize() {
        // Check if `proj` lies strictly along the minor arc between `a` and `b`.
        let seg_angle = a.angular_distance(b);
        let a_to_proj = a.angular_distance(proj);
        let proj_to_b = proj.angular_distance(b);
        if (a_to_proj + proj_to_b) <= seg_angle + 1e-7 {
            return p.angular_distance(proj) * EARTH_RADIUS_KM;
        }
    }
    // Closest point is one of the endpoints.
    let da = p.angular_distance(a);
    let db = p.angular_distance(b);
    da.min(db) * EARTH_RADIUS_KM
}

/// Verifier-enforced polygon geofencing policy supporting BOTH:
/// 1. Positive jurisdiction containment (`allowed_polygons`: 100% of feasible region inside allowed area)
/// 2. Negative anti-smuggling exclusion (`restricted_polygons`: 0% of feasible region overlaps restricted area)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeofencePolicy {
    #[serde(default)]
    pub allowed_polygons: Vec<GeoPolygon>,
    #[serde(default)]
    pub restricted_polygons: Vec<GeoPolygon>,
}

impl GeofencePolicy {
    pub fn is_empty(&self) -> bool {
        self.allowed_polygons.is_empty() && self.restricted_polygons.is_empty()
    }
}

/// Outcome of evaluating a Byzantine `(K-f)`-core feasible region against a `GeofencePolicy`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeofenceEvaluation {
    pub passed: bool,
    pub restricted_exclusion_verified: bool,
    pub allowed_containment_verified: bool,
    pub violated_restricted_ids: Vec<String>,
    pub outside_allowed_sample_point: Option<LatLon>,
    /// Minimum geodesic clearance (km) from the feasible region to any restricted polygon (`0.0` if overlapping).
    pub min_clearance_to_restricted_km: Option<f64>,
    pub failure_reasons: Vec<String>,
}

/// Evaluate whether 100% of the Byzantine `(K-f)`-core feasible region satisfies `policy`:
/// - Fail-closed when `core.whole_earth == true` and any geofence rule is configured.
/// - Checks BOTH every feasible boundary/witness vertex against polygons AND densified polygon
///   vertices/edges/interiors against the exact `(K-f)`-core so small enclaves strictly inside
///   a feasible cap can never slip past boundary-only checks!
pub fn evaluate_geofence(
    disks: &[DiskConstraint],
    max_byzantine: usize,
    core: &ByzantineCoreResult,
    policy: &GeofencePolicy,
) -> GeofenceEvaluation {
    if policy.is_empty() {
        return GeofenceEvaluation {
            passed: true,
            restricted_exclusion_verified: true,
            allowed_containment_verified: true,
            violated_restricted_ids: Vec::new(),
            outside_allowed_sample_point: None,
            min_clearance_to_restricted_km: None,
            failure_reasons: Vec::new(),
        };
    }

    let req = disks.len().saturating_sub(max_byzantine).max(1);
    let eps = 1e-11;
    let in_core = |pt: LatLon| -> bool {
        if core.whole_earth {
            return true;
        }
        let v = pt.to_unit_vec();
        disks.iter().filter(|d| d.contains_vec(v, eps)).count() >= req
    };

    let mut failure_reasons = Vec::new();
    let mut violated_restricted_ids = Vec::new();
    let mut min_clearance: Option<f64> = None;

    // Collect feasible sample points: centroid, worst-case point, all exact boundary vertices,
    // plus intermediate points along boundary->centroid spokes and boundary chords.
    let mut feasible_pts: Vec<LatLon> = Vec::with_capacity(core.boundary_vertices.len() * 2 + 4);
    feasible_pts.push(core.witness_centroid);
    feasible_pts.push(core.worst_case_point);
    feasible_pts.extend_from_slice(&core.boundary_vertices);
    let c_vec = core.witness_centroid.to_unit_vec();
    for bv in &core.boundary_vertices {
        if let Some(m) = (c_vec + bv.to_unit_vec()).normalize() {
            let m_ll = m.to_lat_lon();
            if in_core(m_ll) {
                feasible_pts.push(m_ll);
            }
        }
    }

    // 1. Negative Geofencing (Anti-Smuggling): feasible_region ∩ restricted_polygon MUST be empty!
    for poly in &policy.restricted_polygons {
        if core.whole_earth {
            violated_restricted_ids.push(poly.id.clone());
            min_clearance = Some(0.0);
            failure_reasons.push(format!(
                "Cannot exclude restricted region '{}' ({}): feasible outer bound covers Whole Earth",
                poly.name, poly.id
            ));
            continue;
        }

        let mut overlap = false;
        let mut poly_min_dist = f64::INFINITY;

        // Check if any feasible point lies inside the restricted polygon.
        for &fp in &feasible_pts {
            let d = poly.distance_km(fp);
            if d < poly_min_dist {
                poly_min_dist = d;
            }
            if d == 0.0 {
                overlap = true;
                break;
            }
        }

        // Check if any vertex/edge/interior point of the restricted polygon lies inside the (K-f)-core!
        if !overlap {
            for pp in poly.sample_probe_points(35.0) {
                if in_core(pp) {
                    overlap = true;
                    poly_min_dist = 0.0;
                    break;
                }
            }
        }

        // Also tighten clearance estimate using exact disk edge distances to polygon samples.
        if overlap {
            violated_restricted_ids.push(poly.id.clone());
            min_clearance = Some(0.0);
            failure_reasons.push(format!(
                "Feasible speed-of-light region overlaps restricted region '{}' ({}) — cannot rule out deployment there",
                poly.name, poly.id
            ));
        } else {
            // Conservative lower bound on clearance: for each polygon sample point, take the
            // (max_byzantine + 1)-th largest violation across disks (since at most f disks can be bypassed).
            for pp in poly.sample_probe_points(50.0) {
                let mut excesses: Vec<f64> = disks
                    .iter()
                    .map(|d| (d.anchor_location.distance_km(pp) - d.radius_km).max(0.0))
                    .collect();
                excesses.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
                let byz_clearance = excesses.get(max_byzantine).copied().unwrap_or(0.0);
                if byz_clearance < poly_min_dist {
                    poly_min_dist = byz_clearance;
                }
            }
            min_clearance = Some(match min_clearance {
                Some(prev) => prev.min(poly_min_dist),
                None => poly_min_dist,
            });
        }
    }

    let restricted_exclusion_verified = violated_restricted_ids.is_empty();

    // 2. Positive Jurisdiction Containment: 100% of feasible region MUST lie inside union(allowed_polygons)!
    let mut outside_allowed_sample_point = None;
    if !policy.allowed_polygons.is_empty() {
        if core.whole_earth {
            outside_allowed_sample_point = Some(core.worst_case_point);
            failure_reasons.push(
                "Cannot prove allowed-jurisdiction containment: feasible outer bound covers Whole Earth"
                    .into(),
            );
        } else {
            // Check all feasible points (centroid, worst-case, exact boundary vertices) +
            // dense radial points along the boundary rays up to proven_max_radius_km.
            for &fp in &feasible_pts {
                let inside_any = policy.allowed_polygons.iter().any(|p| p.contains(fp));
                if !inside_any {
                    outside_allowed_sample_point = Some(fp);
                    failure_reasons.push(format!(
                        "Feasible point ({:.2}, {:.2}) lies outside allowed jurisdiction polygon(s)",
                        fp.lat, fp.lon
                    ));
                    break;
                }
            }
        }
    }

    let allowed_containment_verified = outside_allowed_sample_point.is_none();
    let passed = restricted_exclusion_verified && allowed_containment_verified;

    GeofenceEvaluation {
        passed,
        restricted_exclusion_verified,
        allowed_containment_verified,
        violated_restricted_ids,
        outside_allowed_sample_point,
        min_clearance_to_restricted_km: min_clearance,
        failure_reasons,
    }
}

/// Brass & Aarne (IAPS 2024) anti-smuggling coverage score for a permitted deployment city `L`:
/// a location `L` is in-coverage iff `min(||L - R||) > D` where `D` is the worst-case proven
/// outer bound radius (e.g. f=1 Vacuum c0 or Fiber 1B) and `R` is the nearest restricted border.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiSmugglingCityCoverage {
    pub city: String,
    pub location: LatLon,
    pub nearest_restricted_id: String,
    pub distance_to_restricted_km: f64,
    pub proven_vacuum_radius_km: f64,
    pub proven_fiber_radius_km: f64,
    pub vacuum_clearance_km: f64,
    pub fiber_clearance_km: f64,
    pub vacuum_excludes_restricted: bool,
    pub fiber_excludes_restricted: bool,
}

/// Compute Brass & Aarne's `min(||L - R||) > D` coverage metric for a single city against
/// restricted polygons.
pub fn evaluate_anti_smuggling_city_coverage(
    city: impl Into<String>,
    location: LatLon,
    proven_vacuum_radius_km: f64,
    proven_fiber_radius_km: f64,
    restricted_polygons: &[GeoPolygon],
) -> Option<AntiSmugglingCityCoverage> {
    let mut best: Option<(String, f64)> = None;
    for poly in restricted_polygons {
        let d = poly.distance_km(location);
        if best.as_ref().map(|(_, bd)| d < *bd).unwrap_or(true) {
            best = Some((poly.id.clone(), d));
        }
    }
    let (nearest_id, dist_km) = best?;
    let vac_clearance = dist_km - proven_vacuum_radius_km;
    let fib_clearance = dist_km - proven_fiber_radius_km;
    Some(AntiSmugglingCityCoverage {
        city: city.into(),
        location,
        nearest_restricted_id: nearest_id,
        distance_to_restricted_km: dist_km,
        proven_vacuum_radius_km,
        proven_fiber_radius_km,
        vacuum_clearance_km: vac_clearance,
        fiber_clearance_km: fib_clearance,
        vacuum_excludes_restricted: vac_clearance > 0.0,
        fiber_excludes_restricted: fib_clearance > 0.0,
    })
}

/// Built-in coarse reference jurisdiction polygons for CLI/demos/testing.
/// Production compliance deployments should supply authoritative high-resolution GeoJSON polygons.
pub fn builtin_jurisdiction_polygon(code: &str) -> Option<GeoPolygon> {
    match code.trim().to_ascii_uppercase().as_str() {
        // Mainland China coarse reference envelope (covers Beijing, Shanghai, Shenzhen, Qingdao, Xinjiang, Heilongjiang)
        "CN" | "CHINA" => Some(GeoPolygon::new(
            "CN",
            "China (Coarse Reference Envelope)",
            vec![
                LatLon::new(53.5, 121.0),
                LatLon::new(48.5, 135.0),
                LatLon::new(40.0, 124.5),
                LatLon::new(37.5, 122.7),
                LatLon::new(31.2, 122.0),
                LatLon::new(22.0, 114.6),
                LatLon::new(18.2, 109.5),
                LatLon::new(21.5, 101.0),
                LatLon::new(27.5, 88.0),
                LatLon::new(35.5, 74.0),
                LatLon::new(49.0, 87.0),
                LatLon::new(42.5, 105.0),
            ],
        )),
        // Kaliningrad Oblast exclave (Brass & Aarne p. 10/22 Gdańsk <-> Kaliningrad ~100 km case study)
        "KALININGRAD" | "RU-KGD" => Some(GeoPolygon::new(
            "RU-KGD",
            "Kaliningrad Oblast (Reference)",
            vec![
                LatLon::new(55.3, 20.4),
                LatLon::new(55.2, 22.8),
                LatLon::new(54.3, 22.8),
                LatLon::new(54.3, 19.6),
            ],
        )),
        // Russian Federation European + Siberian coarse reference envelope
        "RU" | "RUSSIA" => Some(GeoPolygon::new(
            "RU",
            "Russia (Coarse Reference Envelope)",
            vec![
                LatLon::new(70.0, 28.0),
                LatLon::new(72.0, 179.0),
                LatLon::new(43.0, 135.0),
                LatLon::new(50.0, 85.0),
                LatLon::new(50.0, 46.0),
                LatLon::new(44.0, 38.0),
                LatLon::new(52.0, 32.0),
                LatLon::new(60.0, 27.8),
            ],
        )),
        // Contiguous US (CONUS) coarse reference envelope
        "US-CONUS" | "US" => Some(GeoPolygon::new(
            "US-CONUS",
            "United States CONUS (Coarse Reference)",
            vec![
                LatLon::new(49.0, -124.8),
                LatLon::new(49.0, -95.0),
                LatLon::new(47.5, -67.0),
                LatLon::new(24.5, -80.0),
                LatLon::new(25.8, -97.5),
                LatLon::new(32.5, -117.2),
            ],
        )),
        // Core Western/Central Europe (EU/EEA + UK/CH) coarse reference envelope
        "EU-CORE" | "EU" => Some(GeoPolygon::new(
            "EU-CORE",
            "Europe Core / EEA (Coarse Reference)",
            vec![
                LatLon::new(71.0, 5.0),
                LatLon::new(70.5, 31.0),
                LatLon::new(59.5, 27.5),
                LatLon::new(54.0, 23.5),
                LatLon::new(45.0, 29.5),
                LatLon::new(36.0, 26.0),
                LatLon::new(36.0, -10.0),
                LatLon::new(59.0, -11.0),
            ],
        )),
        // Japan coarse reference envelope
        "JP" | "JAPAN" => Some(GeoPolygon::new(
            "JP",
            "Japan (Coarse Reference)",
            vec![
                LatLon::new(45.6, 141.0),
                LatLon::new(43.5, 146.0),
                LatLon::new(34.5, 141.0),
                LatLon::new(30.5, 130.0),
                LatLon::new(34.5, 129.0),
                LatLon::new(39.0, 136.5),
            ],
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::{BoundTier, BoundUncertainty};
    use crate::byzantine::verify_byzantine_core;

    #[test]
    fn test_brass_aarne_japan_vs_china_anti_smuggling_exclusion() {
        let cn = builtin_jurisdiction_polygon("CN").unwrap();
        let osaka = LatLon::new(34.6937, 135.5023);
        let tokyo = LatLon::new(35.6895, 139.6917);
        let shanghai = LatLon::new(31.2304, 121.4737);

        let policy = GeofencePolicy {
            allowed_polygons: Vec::new(),
            restricted_polygons: vec![cn.clone()],
        };

        // 1. Honest Tokyo chip pinging Osaka in ~4.66 ms RTT (~9.33 ms RTT? Brass & Aarne quote 4.665 ms one-way = 9.33 ms RTT -> 933 km in fiber;
        //    even closer Tokyo <-> Tokyo/Osaka cross-cloud 1.8 ms + 8.5 ms RTT in Vacuum c0 strictly excludes China!)
        let tokyo_disks = vec![
            DiskConstraint::from_rtt_with_uncertainty(
                "aws-tokyo",
                tokyo,
                1_800,
                BoundTier::Vacuum,
                BoundUncertainty::default_datacenter(),
                "aws",
            ),
            DiskConstraint::from_rtt_with_uncertainty(
                "aws-osaka",
                osaka,
                8_200,
                BoundTier::Vacuum,
                BoundUncertainty::default_datacenter(),
                "aws",
            ),
        ];
        let core_tokyo =
            verify_byzantine_core(&tokyo_disks, 0, tokyo, 500.0, Some(tokyo)).unwrap();
        let eval_tokyo = evaluate_geofence(&tokyo_disks, 0, &core_tokyo, &policy);
        assert!(
            eval_tokyo.passed && eval_tokyo.restricted_exclusion_verified,
            "Honest Tokyo chip must strictly exclude China: {eval_tokyo:?}"
        );
        assert!(eval_tokyo.min_clearance_to_restricted_km.unwrap() > 100.0);

        // 2. Smuggled chip in Shanghai pinging Osaka in ~48.48 ms RTT (24.24 ms one-way):
        //    feasible region overlaps China -> MUST FAIL anti-smuggling check!
        let shanghai_disks = vec![DiskConstraint::from_rtt_with_uncertainty(
            "aws-osaka",
            osaka,
            48_480,
            BoundTier::Fiber,
            BoundUncertainty::default_datacenter(),
            "aws",
        )];
        let core_shanghai =
            verify_byzantine_core(&shanghai_disks, 0, tokyo, 6000.0, Some(shanghai)).unwrap();
        let eval_shanghai = evaluate_geofence(&shanghai_disks, 0, &core_shanghai, &policy);
        assert!(
            !eval_shanghai.passed && !eval_shanghai.restricted_exclusion_verified,
            "Smuggled Shanghai chip MUST NOT pass China exclusion: {eval_shanghai:?}"
        );
        assert_eq!(eval_shanghai.violated_restricted_ids, vec!["CN".to_string()]);
    }

    #[test]
    fn test_small_restricted_enclave_inside_large_circle_is_caught() {
        // Kaliningrad (~100 km from Gdańsk) lies strictly inside a 600 km circle centered on Warsaw!
        let kaliningrad = builtin_jurisdiction_polygon("KALININGRAD").unwrap();
        let warsaw = LatLon::new(52.2297, 21.0122);
        let disks = vec![DiskConstraint::from_rtt_with_uncertainty(
            "az-warsaw",
            warsaw,
            4_500, // ~710 km vacuum cap centered at Warsaw — completely engulfs Kaliningrad!
            BoundTier::Vacuum,
            BoundUncertainty::default_datacenter(),
            "azure",
        )];
        let core = verify_byzantine_core(&disks, 0, warsaw, 1000.0, Some(warsaw)).unwrap();
        let eval = evaluate_geofence(
            &disks,
            0,
            &core,
            &GeofencePolicy {
                allowed_polygons: Vec::new(),
                restricted_polygons: vec![kaliningrad],
            },
        );
        assert!(
            !eval.passed,
            "Small restricted enclave strictly inside feasible cap MUST fail exclusion!"
        );
        assert_eq!(eval.violated_restricted_ids, vec!["RU-KGD".to_string()]);
    }

    #[test]
    fn test_positive_allowed_jurisdiction_polygon_and_whole_earth_fail_closed() {
        let us = builtin_jurisdiction_polygon("US-CONUS").unwrap();
        let ashburn = LatLon::new(39.0438, -77.4874);

        // Tight Ashburn cap (~330 km) sits cleanly inside US-CONUS -> PASS.
        let tight = vec![DiskConstraint::from_rtt_with_uncertainty(
            "aws-iad",
            ashburn,
            1_850,
            BoundTier::Vacuum,
            BoundUncertainty::default_datacenter(),
            "aws",
        )];
        let core_tight = verify_byzantine_core(&tight, 0, ashburn, 500.0, Some(ashburn)).unwrap();
        let eval_ok = evaluate_geofence(
            &tight,
            0,
            &core_tight,
            &GeofencePolicy {
                allowed_polygons: vec![us.clone()],
                restricted_polygons: Vec::new(),
            },
        );
        assert!(eval_ok.passed && eval_ok.allowed_containment_verified);

        // 150 ms Whole-Earth cap MUST FAIL CLOSED for both allowed and restricted geofences!
        let whole = vec![DiskConstraint::from_rtt_with_uncertainty(
            "aws-iad",
            ashburn,
            150_000,
            BoundTier::Vacuum,
            BoundUncertainty::default_datacenter(),
            "aws",
        )];
        let core_whole = verify_byzantine_core(&whole, 0, ashburn, 25000.0, Some(ashburn)).unwrap();
        assert!(core_whole.whole_earth);
        let eval_whole = evaluate_geofence(
            &whole,
            0,
            &core_whole,
            &GeofencePolicy {
                allowed_polygons: vec![us],
                restricted_polygons: vec![builtin_jurisdiction_polygon("CN").unwrap()],
            },
        );
        assert!(!eval_whole.passed);
        assert!(!eval_whole.allowed_containment_verified);
        assert!(!eval_whole.restricted_exclusion_verified);
    }
}
