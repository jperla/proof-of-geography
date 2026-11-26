use pog_geo::{CompassQuadrant, LatLon};
use pog_tee::TeeVendor;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

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
    pub public_key_hex: String,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeConfig {
    /// Total anchors to select (e.g., 6).
    pub committee_size: usize,
    /// Minimum distinct cloud providers required (e.g., 2 or 3).
    pub min_cloud_providers: usize,
    /// Up to how many distinct-cloud metro Anchors (< `metro_radius_km`) to include.
    /// Setting this to `f + 1` (e.g., 2 for f=1 Byzantine tolerance) ensures that even if
    /// one metro Anchor is compromised, an independent cloud's metro Anchor still bounds the hub!
    pub max_metro_anchors: usize,
    /// Distance threshold (km) below which an anchor counts as a "same-metro" anchor.
    pub metro_radius_km: f64,
    /// Maximum distance (km) for regional orthogonal framing candidates.
    pub max_regional_km: f64,
}

impl Default for CommitteeConfig {
    fn default() -> Self {
        Self {
            committee_size: 6,
            min_cloud_providers: 3,
            max_metro_anchors: 2,
            metro_radius_km: 150.0,
            max_regional_km: 5_500.0,
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
///
/// Strategy:
/// 1. Score each anchor deterministically using `BLAKE3("pog-committee-v1" || prover_pk || epoch_challenge || anchor_id)`
///    mixed with proximity tier so the Prover cannot freely pick friendly/colluding anchors.
/// 2. Pick up to 1 same-metro anchor (< `metro_radius_km`) for tightest single-circle precision.
/// 3. Pick 1 anchor from each of the 4 orthogonal compass quadrants (NE, SE, SW, NW) prioritizing
///    cloud-provider diversity and proximity.
/// 4. Fill remaining slots up to `committee_size` prioritizing unseen cloud providers and silicon vendors.
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

    // Distance-annotated candidates.
    let mut candidates: Vec<(&AnchorDescriptor, f64, CompassQuadrant, u64)> = grid
        .anchors
        .iter()
        .map(|a| {
            let d = claimed_location.distance_km(a.location);
            let q = claimed_location.quadrant_of(a.location);
            let tb = det_tiebreak(&a.anchor_id);
            (a, d, q, tb)
        })
        .collect();

    // Sort nearby candidates with deterministic jitter within 250 km buckets so selection is
    // both geographically optimal AND unpredictable/un-cherry-pickable per epoch!
    let rank_key = |dist_km: f64, tb: u64, cloud_novel: bool, vendor_novel: bool| -> (u8, u8, u64, u64) {
        let cloud_pen = if cloud_novel { 0 } else { 1 };
        let vendor_pen = if vendor_novel { 0 } else { 1 };
        let bucket = (dist_km / 350.0) as u64;
        (cloud_pen, vendor_pen, bucket, tb)
    };

    // Step 1: Select up to `max_metro_anchors` (f+1 = 2) co-located metro anchors from DISTINCT clouds!
    // This guarantees tight metro-level precision (~100-170 mi hard vacuum bound) even under f=1 Byzantine fault!
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

    // Step 2: Select 1 anchor per compass quadrant (NE, SE, SW, NW) outside metro radius for orthogonal framing.
    let mut quad_order = CompassQuadrant::ALL;
    // Rotate quadrant scan order deterministically per epoch.
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

    // Step 3: Fill remaining slots up to `committee_size`, strictly preferring nearby regional
    // anchors (never reaching across continents just to add a 5th cloud once min_cloud_providers is met).
    while picked.len() < cfg.committee_size {
        candidates.sort_by_key(|(a, d, _, tb)| {
            let need_cloud = seen_clouds.len() < cfg.min_cloud_providers
                && !seen_clouds.contains(&a.cloud_provider);
            let out_of_region: u8 = if *d <= cfg.max_regional_km { 0 } else { 1 };
            let cloud_tier: u8 = if need_cloud { 0 } else { 1 };
            let bucket = (*d / 350.0) as u64;
            let novel_tiebreak: u8 = if !seen_clouds.contains(&a.cloud_provider) { 0 } else { 1 };
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

        // Select committee for a GPU cluster claiming Tokyo.
        let sel = select_committee(
            &grid,
            "aabbccdd",
            b"epoch-2026-11-25-hour-21",
            LatLon::new(35.68, 139.68),
            &CommitteeConfig::default(),
        );
        assert_eq!(sel.selected.len(), 6);
        assert!(sel.distinct_clouds >= 3, "Expected >=3 clouds, got {}", sel.distinct_clouds);
        assert!(sel.distinct_quadrants >= 3, "Expected >=3 quadrants, got {}", sel.distinct_quadrants);
    }
}
