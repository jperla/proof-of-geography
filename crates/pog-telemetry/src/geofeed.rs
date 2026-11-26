use pog_geo::LatLon;
use serde::{Deserialize, Serialize};

/// Parsed RFC 8805 self-published ISP/cloud geofeed entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeofeedEntry {
    pub cidr: String,
    pub country_code: String,
    pub region_code: String,
    pub city: String,
    pub postal_code: String,
    /// Optional resolved city center coordinates for physics cross-checking.
    pub resolved_coords: Option<LatLon>,
}

/// Parse an RFC 8805 CSV geofeed (`prefix,country,region,city,postal`).
/// Ignores blank lines and `#` comments per RFC 8805 Section 2.1.
pub fn parse_rfc8805_geofeed(csv_text: &str) -> Vec<GeofeedEntry> {
    let mut entries = Vec::new();
    for line in csv_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split(',').map(|s| s.trim()).collect();
        if parts.len() < 4 {
            continue;
        }
        entries.push(GeofeedEntry {
            cidr: parts[0].to_string(),
            country_code: parts[1].to_string(),
            region_code: parts[2].to_string(),
            city: parts[3].to_string(),
            postal_code: parts.get(4).copied().unwrap_or("").to_string(),
            resolved_coords: lookup_major_city_coords(parts[3]),
        });
    }
    entries
}

/// Lookup table of major global datacenter hub coordinates for geofeed falsification.
pub fn lookup_major_city_coords(city: &str) -> Option<LatLon> {
    match city.to_lowercase().as_str() {
        "ashburn" | "northern virginia" | "reston" => Some(LatLon::new(39.0438, -77.4874)),
        "new york" | "newark" | "secaucus" => Some(LatLon::new(40.7128, -74.0060)),
        "san jose" | "santa clara" | "san francisco" => Some(LatLon::new(37.3382, -121.8863)),
        "seattle" | "the dalles" | "boardman" => Some(LatLon::new(45.5946, -121.1787)),
        "dallas" | "san antonio" => Some(LatLon::new(32.7767, -96.7970)),
        "frankfurt" => Some(LatLon::new(50.1109, 8.6821)),
        "london" | "slough" => Some(LatLon::new(51.5074, -0.1278)),
        "amsterdam" => Some(LatLon::new(52.3676, 4.9041)),
        "paris" | "gravelines" => Some(LatLon::new(48.8566, 2.3522)),
        "warsaw" => Some(LatLon::new(52.2297, 21.0122)),
        "stockholm" => Some(LatLon::new(59.3293, 18.0686)),
        "tokyo" => Some(LatLon::new(35.6762, 139.6503)),
        "osaka" => Some(LatLon::new(34.6937, 135.5023)),
        "seoul" => Some(LatLon::new(37.5665, 126.9780)),
        "taipei" | "changhua" => Some(LatLon::new(25.0330, 121.5654)),
        "hong kong" => Some(LatLon::new(22.3193, 114.1694)),
        "singapore" | "johor" => Some(LatLon::new(1.3521, 103.8198)),
        "beijing" => Some(LatLon::new(39.9042, 116.4074)),
        "shanghai" => Some(LatLon::new(31.2304, 121.4737)),
        "mumbai" => Some(LatLon::new(19.0760, 72.8777)),
        "sydney" => Some(LatLon::new(33.8688, 151.2093)),
        "sao paulo" | "são paulo" => Some(LatLon::new(-23.5505, -46.6333)),
        _ => None,
    }
}
