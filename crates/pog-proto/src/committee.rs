use pog_geo::{CompassQuadrant, LatLon};
use pog_tee::TeeVendor;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Explicit, separate provenance basis for an Anchor's published physical coordinates.
///
/// Product Invariant:
/// **Hardware TEE identity does NOT prove physical coordinates.**
/// A hardware TEE proves *what measured binary generated the ephemeral signing key*,
/// whereas physical coordinates require a separate, independently audited basis
/// (cloud facility audit + cross-cloud anchor-to-anchor speed-of-light calibration mesh).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinateBasis {
    /// Source of published coordinates (e.g., "cloud_region_facility_audit", "operator_declared_unverified").
    pub source: String,
    /// Conservative geographic uncertainty radius (km) folded into outer physics bounds.
    pub uncertainty_km: f64,
    /// Unix timestamp of the most recent independent coordinate / mesh consistency audit (None if unaudited).
    #[serde(default)]
    pub audited_at_unix_s: Option<u64>,
    /// Explicit invariant marker — always false.
    #[serde(default)]
    pub hardware_identity_proves_coordinates: bool,
    /// Human-readable audit notes or anomalies (e.g., region-vs-city discrepancy).
    #[serde(default)]
    pub audit_note: Option<String>,
}

impl Default for CoordinateBasis {
    fn default() -> Self {
        Self {
            source: "operator_declared_region_centroid".into(),
            uncertainty_km: 35.0,
            audited_at_unix_s: None,
            hardware_identity_proves_coordinates: false,
            audit_note: Some(
                "Hardware TEE identity proves workload & key custody, NOT physical coordinates."
                    .into(),
            ),
        }
    }
}

/// Separate operational readiness dimensions (never conflated into a single count).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorEligibility {
    pub configured: bool,
    pub reachable: bool,
    pub attested_hardware_tee: bool,
    pub enrolled_key_matches_published: bool,
    pub proof_eligible: bool,
}

/// Metadata describing a registered multi-cloud Anchor TEE node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorDescriptor {
    pub anchor_id: String,
    pub cloud_provider: String,
    pub region: String,
    pub city: String,
    pub tee_vendor: TeeVendor,
    pub instance_type: String,
    pub location: LatLon,
    pub endpoint_tcp: String,
    pub endpoint_udp: String,
    /// Optional operator-hosted HTTPS base URL serving `/info`, `/attest`, and `/ping`
    /// for independent/self-hosted constellations (never routed through proofofgeography.com).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https_url: Option<String>,
    pub public_key_hex: String,
    /// Separate audited physical location provenance (never conflated with TEE attestation).
    #[serde(default)]
    pub coordinate_basis: Option<CoordinateBasis>,
}

impl AnchorDescriptor {
    /// Conservative anchor coordinate uncertainty (km) for outer-bound geometry.
    pub fn location_uncertainty_km(&self) -> f64 {
        self.coordinate_basis
            .as_ref()
            .map(|c| c.uncertainty_km.max(0.0))
            .unwrap_or(35.0)
    }

    /// True iff this descriptor declares a production hardware TEE (not `SoftwareDev`).
    pub fn is_production_hardware_tee(&self) -> bool {
        self.tee_vendor.is_production_hardware_tee()
    }
}

/// Top-level JSON Anchor registry (DNS-style public grid configuration).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorGrid {
    pub version: String,
    pub grid_name: String,
    pub description: String,
    pub anchors: Vec<AnchorDescriptor>,
}

impl AnchorGrid {
    pub fn from_json_str(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    pub fn by_id(&self, id: &str) -> Option<&AnchorDescriptor> {
        self.anchors.iter().find(|a| a.anchor_id == id)
    }

    /// Return a filtered grid containing ONLY anchors declaring production hardware TEEs
    /// (excludes all `SoftwareDev` entries). Fail-closed membership filter.
    pub fn production_hardware_only(&self) -> Self {
        Self {
            version: self.version.clone(),
            grid_name: self.grid_name.clone(),
            description: self.description.clone(),
            anchors: self
                .anchors
                .iter()
                .filter(|a| a.is_production_hardware_tee())
                .cloned()
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeConfig {
    pub committee_size: usize,
    pub min_cloud_providers: usize,
    pub max_metro_anchors: usize,
    pub metro_radius_km: f64,
    pub max_regional_km: f64,
    /// Fail-closed default: exclude `SoftwareDev` anchors from committee selection unless dev mode enabled.
    #[serde(default)]
    pub allow_software_dev_anchors: bool,
}

impl Default for CommitteeConfig {
    fn default() -> Self {
        Self {
            committee_size: 6,
            min_cloud_providers: 3,
            max_metro_anchors: 2,
            metro_radius_km: 150.0,
            max_regional_km: 5_500.0,
            allow_software_dev_anchors: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeSelection {
    pub selected: Vec<AnchorDescriptor>,
    pub distinct_clouds: usize,
    pub distinct_quadrants: usize,
    pub distinct_tee_vendors: usize,
}

/// Deterministic, anti-cherry-picking committee selection around `claimed_location`.
/// Excludes `SoftwareDev` anchors by default (`cfg.allow_software_dev_anchors == false`).
pub fn select_committee(
    grid: &AnchorGrid,
    prover_pk_hex: &str,
    epoch_challenge: &[u8],
    claimed_location: LatLon,
    cfg: &CommitteeConfig,
) -> CommitteeSelection {
    let mut picked: Vec<AnchorDescriptor> = Vec::new();
    let mut picked_ids: HashSet<String> = HashSet::new();
    let mut seen_clouds: HashSet<String> = HashSet::new();
    let mut seen_vendors: HashSet<TeeVendor> = HashSet::new();

    let det_tiebreak = |anchor_id: &str| -> u64 {
        let mut h = blake3::Hasher::new();
        h.update(b"pog-committee-v1");
        h.update(prover_pk_hex.as_bytes());
        h.update(epoch_challenge);
        h.update(anchor_id.as_bytes());
        let out = h.finalize();
        u64::from_le_bytes(out.as_bytes()[0..8].try_into().unwrap())
    };

    let mut candidates: Vec<(&AnchorDescriptor, f64, CompassQuadrant, u64)> = grid
        .anchors
        .iter()
        .filter(|a| cfg.allow_software_dev_anchors || a.is_production_hardware_tee())
        .map(|a| {
            let d = claimed_location.distance_km(a.location);
            let q = claimed_location.quadrant_of(a.location);
            let tb = det_tiebreak(&a.anchor_id);
            (a, d, q, tb)
        })
        .collect();

    let rank_key =
        |dist_km: f64, tb: u64, cloud_novel: bool, vendor_novel: bool| -> (u8, u8, u64, u64) {
            let cloud_pen = if cloud_novel { 0 } else { 1 };
            let vendor_pen = if vendor_novel { 0 } else { 1 };
            let bucket = (dist_km / 350.0) as u64;
            (cloud_pen, vendor_pen, bucket, tb)
        };

    // Step 1: Up to `max_metro_anchors` co-located metro anchors from distinct clouds.
    let mut metro: Vec<_> = candidates
        .iter()
        .filter(|(_, d, _, _)| *d <= cfg.metro_radius_km)
        .copied()
        .collect();
    metro.sort_by_key(|(_, _, _, tb)| *tb);
    let mut metro_picked = 0usize;
    let mut metro_clouds: HashSet<String> = HashSet::new();
    for (a, _, _, _) in metro {
        if metro_picked >= cfg.max_metro_anchors || picked.len() >= cfg.committee_size {
            break;
        }
        if metro_clouds.insert(a.cloud_provider.clone()) {
            picked.push(a.clone());
            picked_ids.insert(a.anchor_id.clone());
            seen_clouds.insert(a.cloud_provider.clone());
            seen_vendors.insert(a.tee_vendor);
            metro_picked += 1;
        }
    }

    // Step 2: 1 anchor per compass quadrant outside metro radius.
    let mut quad_order = CompassQuadrant::ALL;
    let rot = (det_tiebreak("quad-rot") as usize) % 4;
    quad_order.rotate_left(rot);

    for quad in quad_order {
        if picked.len() >= cfg.committee_size {
            break;
        }
        let mut q_cands: Vec<_> = candidates
            .iter()
            .filter(|(a, d, q, _)| {
                *q == quad
                    && *d > cfg.metro_radius_km
                    && *d <= cfg.max_regional_km
                    && !picked_ids.contains(&a.anchor_id)
            })
            .copied()
            .collect();
        q_cands.sort_by_key(|(a, d, _, tb)| {
            rank_key(
                *d,
                *tb,
                !seen_clouds.contains(&a.cloud_provider),
                !seen_vendors.contains(&a.tee_vendor),
            )
        });
        if let Some((a, _, _, _)) = q_cands.first() {
            picked.push((*a).clone());
            picked_ids.insert(a.anchor_id.clone());
            seen_clouds.insert(a.cloud_provider.clone());
            seen_vendors.insert(a.tee_vendor);
        }
    }

    // Step 3: Fill remaining slots up to `committee_size`.
    while picked.len() < cfg.committee_size {
        candidates.sort_by_key(|(a, d, _, tb)| {
            let need_cloud = seen_clouds.len() < cfg.min_cloud_providers
                && !seen_clouds.contains(&a.cloud_provider);
            let out_of_region: u8 = if *d <= cfg.max_regional_km { 0 } else { 1 };
            let cloud_tier: u8 = if need_cloud { 0 } else { 1 };
            let bucket = (*d / 350.0) as u64;
            let novel_tiebreak: u8 = if !seen_clouds.contains(&a.cloud_provider) {
                0
            } else {
                1
            };
            (out_of_region, cloud_tier, bucket, novel_tiebreak, *tb)
        });
        let next = candidates
            .iter()
            .find(|(a, _, _, _)| !picked_ids.contains(&a.anchor_id))
            .copied();
        match next {
            Some((a, _, _, _)) => {
                picked.push(a.clone());
                picked_ids.insert(a.anchor_id.clone());
                seen_clouds.insert(a.cloud_provider.clone());
                seen_vendors.insert(a.tee_vendor);
            }
            None => break,
        }
    }

    let mut quad_set: HashMap<CompassQuadrant, usize> = HashMap::new();
    for a in &picked {
        *quad_set
            .entry(claimed_location.quadrant_of(a.location))
            .or_insert(0) += 1;
    }

    CommitteeSelection {
        distinct_clouds: seen_clouds.len(),
        distinct_quadrants: quad_set.len(),
        distinct_tee_vendors: seen_vendors.len(),
        selected: picked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_24_grid_multi_cloud_committee_selection() {
        let json = include_str!("../../../config/global_grid_24.json");
        let grid = AnchorGrid::from_json_str(json).unwrap();
        assert_eq!(grid.anchors.len(), 24);

        let sel = select_committee(
            &grid,
            "aabbccdd",
            b"epoch-2026-11-25-hour-21",
            LatLon::new(35.68, 139.68),
            &CommitteeConfig::default(),
        );
        assert_eq!(sel.selected.len(), 6);
        assert!(sel.distinct_clouds >= 3);
        assert!(sel.distinct_quadrants >= 3);
    }

    #[test]
    fn test_committee_excludes_software_dev_by_default() {
        let grid = AnchorGrid {
            version: "1".into(),
            grid_name: "mixed".into(),
            description: "test".into(),
            anchors: vec![AnchorDescriptor {
                anchor_id: "dev-1".into(),
                cloud_provider: "aws".into(),
                region: "us-east-1".into(),
                city: "Ashburn".into(),
                tee_vendor: TeeVendor::SoftwareDev,
                instance_type: "c6a.large".into(),
                location: LatLon::new(39.0, -77.5),
                endpoint_tcp: "1.2.3.4:7443".into(),
                endpoint_udp: "1.2.3.4:7444".into(),
                https_url: None,
                public_key_hex: "aa".repeat(32),
                coordinate_basis: None,
            }],
        };
        let sel = select_committee(
            &grid,
            "pk",
            b"epoch",
            LatLon::new(39.0, -77.5),
            &CommitteeConfig::default(),
        );
        assert!(sel.selected.is_empty(), "SoftwareDev anchor MUST be excluded by default");
    }
}
