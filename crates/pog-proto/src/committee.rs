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
    /// Optional explicit failure-domain label (e.g., "aws-us-west-2-hnl-1a/AS16509" or
    /// "vultr-hnl-drfortress/AS20473") to distinguish independent networks/facilities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_domain: Option<String>,
    /// Optional Autonomous System Number (e.g., 16509 for AWS, 20473 for Vultr).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    /// Explicit diagnostic-only marker: when true, this Anchor may join diagnostic/calibration
    /// rosters but MUST NEVER enter the production hardware proof quorum.
    #[serde(default, skip_serializing_if = "is_false")]
    pub diagnostic_only: bool,
    /// Optional ISO 3166-1 alpha-2 country code (e.g., "US", "DE", "JP", "HK", "AE") for
    /// verifier-side "striking distance" jurisdiction filtering and multi-country quorum policies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    /// Separate audited physical location provenance (never conflated with TEE attestation).
    #[serde(default)]
    pub coordinate_basis: Option<CoordinateBasis>,
}

fn is_false(v: &bool) -> bool {
    !*v
}

impl AnchorDescriptor {
    /// Conservative anchor coordinate uncertainty (km) for outer-bound geometry.
    pub fn location_uncertainty_km(&self) -> f64 {
        self.coordinate_basis
            .as_ref()
            .map(|c| c.uncertainty_km.max(0.0))
            .unwrap_or(35.0)
    }

    /// True iff this descriptor declares a production hardware TEE (not `SoftwareDev`)
    /// AND is not marked `diagnostic_only`.
    pub fn is_production_hardware_tee(&self) -> bool {
        !self.diagnostic_only && self.tee_vendor.is_production_hardware_tee()
    }

    /// Return the normalized uppercase ISO 3166-1 alpha-2 country code for this Anchor,
    /// using explicit `country_code` when set or inferring conservatively from `city` / `region`.
    pub fn effective_country_code(&self) -> Option<String> {
        if let Some(ref cc) = self.country_code {
            let norm = cc.trim().to_ascii_uppercase();
            if !norm.is_empty() {
                return Some(norm);
            }
        }
        infer_country_code_from_city_or_region(&self.city, &self.region)
    }
}

/// Conservative ISO-2 country inference for legacy grid descriptors lacking explicit `country_code`.
pub fn infer_country_code_from_city_or_region(city: &str, region: &str) -> Option<String> {
    let c = city.to_ascii_lowercase();
    let r = region.to_ascii_lowercase();
    let table: &[(&str, &str)] = &[
        ("usa", "US"),
        ("united states", "US"),
        ("canada", "CA"),
        ("mexico", "MX"),
        ("brazil", "BR"),
        ("chile", "CL"),
        ("panama", "PA"),
        ("puerto rico", "PR"),
        (", uk", "GB"),
        ("united kingdom", "GB"),
        ("ireland", "IE"),
        ("france", "FR"),
        ("germany", "DE"),
        ("netherlands", "NL"),
        ("switzerland", "CH"),
        ("spain", "ES"),
        ("portugal", "PT"),
        ("italy", "IT"),
        ("sweden", "SE"),
        ("norway", "NO"),
        ("finland", "FI"),
        ("poland", "PL"),
        ("romania", "RO"),
        ("greece", "GR"),
        ("iceland", "IS"),
        ("faroe", "FO"),
        ("turkey", "TR"),
        ("israel", "IL"),
        ("uae", "AE"),
        ("qatar", "QA"),
        ("south africa", "ZA"),
        ("morocco", "MA"),
        ("egypt", "EG"),
        ("kazakhstan", "KZ"),
        ("russia", "RU"),
        ("india", "IN"),
        ("singapore", "SG"),
        ("indonesia", "ID"),
        ("hong kong", "HK"),
        ("taiwan", "TW"),
        ("south korea", "KR"),
        ("korea", "KR"),
        ("japan", "JP"),
        ("australia", "AU"),
        ("new zealand", "NZ"),
        ("china", "CN"),
    ];
    for &(needle, code) in table {
        if c.contains(needle) {
            return Some(code.to_string());
        }
    }
    if r.starts_with("us-") || r.contains("eastus") || r.contains("westus") || r.contains("centralus") {
        return Some("US".into());
    }
    if r.starts_with("ca-") || r.contains("canada") {
        return Some("CA".into());
    }
    if r.contains("hongkong") || r == "ap-east-1" {
        return Some("HK".into());
    }
    None
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
    /// Optional ISO-2 country codes to exclude ("striking distance" defense, Brass & Aarne p. 26–27).
    #[serde(default)]
    pub excluded_anchor_countries: Vec<String>,
    /// Optional ISO-2 country allowlist (if Some and non-empty, ONLY anchors in these countries may join).
    #[serde(default)]
    pub allowed_anchor_countries: Option<Vec<String>>,
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
            excluded_anchor_countries: Vec::new(),
            allowed_anchor_countries: None,
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
        .filter(|a| {
            let cc = a.effective_country_code();
            if let Some(ref code) = cc {
                if cfg
                    .excluded_anchor_countries
                    .iter()
                    .any(|ex| ex.eq_ignore_ascii_case(code))
                {
                    return false;
                }
            }
            if let Some(ref allow) = cfg.allowed_anchor_countries {
                if !allow.is_empty() {
                    return cc
                        .as_deref()
                        .map(|code| allow.iter().any(|al| al.eq_ignore_ascii_case(code)))
                        .unwrap_or(false);
                }
            }
            true
        })
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
                failure_domain: None,
                asn: None,
                diagnostic_only: false,
                country_code: Some("US".into()),
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

    #[test]
    fn test_honolulu_two_provider_diagnostic_only_excluded_from_prod_quorum() {
        let grid = AnchorGrid {
            version: "2.0.0".into(),
            grid_name: "hnl-two-provider-diag".into(),
            description: "Honolulu AWS Local Zone + Vultr DRFortress diagnostic pair".into(),
            anchors: vec![
                AnchorDescriptor {
                    anchor_id: "aws-us-west-2-hnl-honolulu".into(),
                    cloud_provider: "aws".into(),
                    region: "us-west-2-hnl-1a".into(),
                    city: "Honolulu, HI, USA (AWS Local Zone)".into(),
                    tee_vendor: TeeVendor::SoftwareDev,
                    instance_type: "t3.medium".into(),
                    location: LatLon::new(21.3069, -157.8583),
                    endpoint_tcp: "198.51.100.11:7443".into(),
                    endpoint_udp: "198.51.100.11:7444".into(),
                    https_url: Some("https://hnl-aws.a.proofofgeography.com".into()),
                    public_key_hex: "11".repeat(32),
                    failure_domain: Some("aws-us-west-2-hnl-1a/AS16509".into()),
                    asn: Some(16509),
                    diagnostic_only: true,
                    country_code: Some("US".into()),
                    coordinate_basis: None,
                },
                AnchorDescriptor {
                    anchor_id: "vultr-hnl-honolulu".into(),
                    cloud_provider: "vultr".into(),
                    region: "hnl".into(),
                    city: "Honolulu, HI, USA (Vultr DRFortress)".into(),
                    tee_vendor: TeeVendor::SoftwareDev,
                    instance_type: "vhp-1c-2gb-intel".into(),
                    location: LatLon::new(21.3282, -157.9225),
                    endpoint_tcp: "198.51.100.22:7443".into(),
                    endpoint_udp: "198.51.100.22:7444".into(),
                    https_url: Some("https://hnl-vultr.a.proofofgeography.com".into()),
                    public_key_hex: "22".repeat(32),
                    failure_domain: Some("vultr-hnl-drfortress/AS20473".into()),
                    asn: Some(20473),
                    diagnostic_only: true,
                    country_code: Some("US".into()),
                    coordinate_basis: None,
                },
            ],
        };

        // Production default MUST exclude both diagnostic_only Honolulu anchors!
        assert!(grid.production_hardware_only().anchors.is_empty());
        let prod_sel = select_committee(
            &grid,
            "prover-pk",
            b"epoch-hnl",
            LatLon::new(21.31, -157.86),
            &CommitteeConfig::default(),
        );
        assert!(prod_sel.selected.is_empty(), "diagnostic_only Honolulu anchors MUST NOT enter production quorum");

        // Diagnostic mode explicitly selects BOTH across 2 distinct networks / failure domains!
        let diag_cfg = CommitteeConfig {
            allow_software_dev_anchors: true,
            ..Default::default()
        };
        let diag_sel = select_committee(
            &grid,
            "prover-pk",
            b"epoch-hnl",
            LatLon::new(21.31, -157.86),
            &diag_cfg,
        );
        assert_eq!(diag_sel.selected.len(), 2);
        assert_eq!(diag_sel.distinct_clouds, 2);
        assert_ne!(diag_sel.selected[0].asn, diag_sel.selected[1].asn);
        assert_ne!(diag_sel.selected[0].failure_domain, diag_sel.selected[1].failure_domain);
    }
}
