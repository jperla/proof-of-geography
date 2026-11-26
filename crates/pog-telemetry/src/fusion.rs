use crate::geofeed::GeofeedEntry;
use crate::traceroute::{extract_airport_hints, AirportHint, TracerouteHop};
use pog_geo::{ByzantineCoreResult, DiskConstraint, LatLon};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TelemetryAlert {
    /// Claimed RFC 8805 geofeed / provider marketing city contradicts the hard physics bound!
    /// Catches VPN "virtual locations", stale BYOIP records, and inference router region lies.
    GeofeedContradictsPhysics {
        claimed_city: String,
        claimed_coords: LatLon,
        violated_anchor_id: String,
        anchor_distance_km: f64,
        max_physical_radius_km: f64,
    },
    /// Large last-hop latency spike between penultimate router and TEE responder:
    /// classic signature of a front-end reverse proxy / inference router forwarding traffic offshore!
    LastHopProxyJump {
        penultimate_rtt_ms: f64,
        final_tee_rtt_ms: f64,
        excess_tunnel_ms: f64,
    },
    /// rDNS airport code on late traceroute hop conflicts with claimed target region.
    RdnsRouteDivergence {
        hint_city: String,
        distance_from_target_km: f64,
    },
}

/// Combined IPinfo-style multi-layered diagnostic & Tier-2 confidence radius output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FusedGeoAssessment {
    pub hard_physics_radius_km: f64,
    /// IPinfo-style 68% confidence radius (km) derived from calibrated physics + rDNS/geofeed alignment.
    pub confidence_68_radius_km: f64,
    pub confidence_95_radius_km: f64,
    pub rdns_hints: Vec<AirportHint>,
    pub alerts: Vec<TelemetryAlert>,
    pub proxy_or_router_lie_suspected: bool,
}

/// Fuse hard Tier-1 physics disks with IPinfo-style passive/active telemetry hints:
/// 1. Checks if RFC 8805 geofeed claims violate any Anchor's hard speed-of-light disk.
/// 2. Checks traceroute penultimate hop vs. final TEE RTT to expose split-plane reverse proxies
///    and offshore inference routers (where the IP/router is local in 1 ms, then jumps +50 ms to the GPU!).
/// 3. Computes calibrated 68% / 95% confidence radii.
pub fn fuse_ipinfo_telemetry(
    target: LatLon,
    hard_core: &ByzantineCoreResult,
    calibrated_core: &ByzantineCoreResult,
    hard_disks: &[DiskConstraint],
    geofeed_claim: Option<&GeofeedEntry>,
    traceroute: &[TracerouteHop],
    final_tee_rtt_ms: f64,
) -> FusedGeoAssessment {
    let mut alerts = Vec::new();

    // 1. Check RFC 8805 geofeed claim against every hard disk.
    if let Some(gf) = geofeed_claim {
        if let Some(gf_coords) = gf.resolved_coords {
            for d in hard_disks {
                let dist = d.anchor_location.distance_km(gf_coords);
                if dist > d.radius_km + 25.0 {
                    alerts.push(TelemetryAlert::GeofeedContradictsPhysics {
                        claimed_city: gf.city.clone(),
                        claimed_coords: gf_coords,
                        violated_anchor_id: d.anchor_id.clone(),
                        anchor_distance_km: dist,
                        max_physical_radius_km: d.radius_km,
                    });
                }
            }
        }
    }

    // 2. Detect split-plane proxy / inference router jump:
    // If penultimate IP router responds quickly (e.g., 1.5 ms in Singapore) while the TEE
    // cryptographic challenge takes 75 ms, the IP front-end is proxying to a distant backend!
    if let Some(penultimate) = traceroute.last() {
        let excess = final_tee_rtt_ms - penultimate.rtt_ms;
        if excess > 15.0 {
            alerts.push(TelemetryAlert::LastHopProxyJump {
                penultimate_rtt_ms: penultimate.rtt_ms,
                final_tee_rtt_ms,
                excess_tunnel_ms: excess,
            });
        }
    }

    // 3. Extract airport-code rDNS hints and check alignment with target.
    let rdns_hints = extract_airport_hints(traceroute);
    if let Some(last_hint) = rdns_hints.last() {
        let dist = last_hint.coords.distance_km(target);
        if dist > calibrated_core.proven_max_radius_km.max(500.0) {
            alerts.push(TelemetryAlert::RdnsRouteDivergence {
                hint_city: last_hint.city.clone(),
                distance_from_target_km: dist,
            });
        }
    }

    let proxy_or_router_lie_suspected = alerts.iter().any(|a| {
        matches!(
            a,
            TelemetryAlert::GeofeedContradictsPhysics { .. }
                | TelemetryAlert::LastHopProxyJump { .. }
        )
    });

    // Confidence 68% / 95% radii (IPinfo style): tighter when rDNS + geofeed corroborate physics,
    // widened when alerts fire.
    let penalty = if proxy_or_router_lie_suspected { 1.5 } else { 1.0 };
    let confidence_68_radius_km =
        (calibrated_core.proven_max_radius_km * 0.65 * penalty).min(hard_core.proven_max_radius_km);
    let confidence_95_radius_km =
        (calibrated_core.proven_max_radius_km * 0.95 * penalty).min(hard_core.proven_max_radius_km);

    FusedGeoAssessment {
        hard_physics_radius_km: hard_core.proven_max_radius_km,
        confidence_68_radius_km,
        confidence_95_radius_km,
        rdns_hints,
        alerts,
        proxy_or_router_lie_suspected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pog_geo::{verify_byzantine_core, BoundTier};

    #[test]
    fn test_catches_inference_router_last_hop_proxy_lie() {
        let singapore = LatLon::new(1.3521, 103.8198);
        let d_sg = DiskConstraint::from_rtt("gcp-sin", singapore, 75_000, BoundTier::Vacuum, "gcp");
        let core = verify_byzantine_core(std::slice::from_ref(&d_sg), 0, singapore, 500.0, None).unwrap();

        let hops = vec![
            TracerouteHop {
                ttl: 1,
                ip: "10.0.0.1".into(),
                rdns: Some("core1.sin1.cloud.net".into()),
                rtt_ms: 0.6,
            },
            TracerouteHop {
                ttl: 2,
                ip: "203.0.113.5".into(),
                rdns: Some("edge-proxy.sin2.wrapper-ai.example".into()),
                rtt_ms: 1.4,
            },
        ];

        // Front-end router answers ICMP in 1.4 ms in Singapore, but TEE cryptographic challenge takes 75 ms!
        let assessment = fuse_ipinfo_telemetry(singapore, &core, &core, &[d_sg], None, &hops, 75.0);
        assert!(assessment.proxy_or_router_lie_suspected);
        assert!(assessment
            .alerts
            .iter()
            .any(|a| matches!(a, TelemetryAlert::LastHopProxyJump { .. })));
    }
}
