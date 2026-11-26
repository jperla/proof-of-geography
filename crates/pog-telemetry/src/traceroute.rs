use pog_geo::LatLon;
use serde::{Deserialize, Serialize};

/// Single observed router hop along a traceroute from an Anchor to a Prover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteHop {
    pub ttl: u8,
    pub ip: String,
    pub rdns: Option<String>,
    pub rtt_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirportHint {
    pub hop_ttl: u8,
    pub iata_code: String,
    pub city: String,
    pub coords: LatLon,
    pub hop_rtt_ms: f64,
}

/// Extract IATA airport-code city hints embedded in reverse DNS hostnames (a classic technique
/// highlighted by IPinfo's research team — e.g., `ae-1.r20.tokyjp05.us.bb.gin.ntt.net` or `be201.fra1.core.net`).
pub fn extract_airport_hints(hops: &[TracerouteHop]) -> Vec<AirportHint> {
    const IATA_TABLE: &[(&str, &str, f64, f64)] = &[
        ("iad", "Ashburn", 39.0438, -77.4874),
        ("ewr", "Newark/NYC", 40.6895, -74.1745),
        ("sjc", "San Jose", 37.3639, -121.9289),
        ("sea", "Seattle", 47.4502, -122.3088),
        ("pdx", "Portland/Oregon", 45.5898, -122.5951),
        ("dfw", "Dallas", 32.8998, -97.0403),
        ("ord", "Chicago", 41.9742, -87.9073),
        ("yyz", "Toronto", 43.6777, -79.6248),
        ("fra", "Frankfurt", 50.0379, 8.5622),
        ("lhr", "London", 51.4700, -0.4543),
        ("ams", "Amsterdam", 52.3105, 4.7683),
        ("cdg", "Paris", 49.0097, 2.5479),
        ("waw", "Warsaw", 52.1657, 20.9671),
        ("arn", "Stockholm", 59.6519, 17.9186),
        ("nrt", "Tokyo", 35.7720, 140.3929),
        ("tyo", "Tokyo", 35.6762, 139.6503),
        ("kix", "Osaka", 34.4347, 135.2441),
        ("icn", "Seoul", 37.4602, 126.4407),
        ("tpe", "Taipei", 25.0797, 121.2342),
        ("hkg", "Hong Kong", 22.3080, 113.9185),
        ("sin", "Singapore", 1.3644, 103.9915),
        ("pek", "Beijing", 40.0799, 116.6031),
        ("pvg", "Shanghai", 31.1443, 121.8083),
        ("bom", "Mumbai", 19.0896, 72.8656),
        ("syd", "Sydney", -33.9399, 151.1753),
        ("gru", "Sao Paulo", -23.4356, -46.4731),
    ];

    let mut out = Vec::new();
    for hop in hops {
        let Some(ref rdns) = hop.rdns else {
            continue;
        };
        let lower = rdns.to_lowercase();
        let tokens: Vec<&str> = lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|t| !t.is_empty())
            .collect();

        for &(code, city, lat, lon) in IATA_TABLE {
            let matched = tokens.iter().any(|tok| {
                *tok == code
                    || (tok.starts_with(code)
                        && tok.len() <= 5
                        && tok[code.len()..].chars().all(|c| c.is_ascii_digit()))
            });
            if matched {
                out.push(AirportHint {
                    hop_ttl: hop.ttl,
                    iata_code: code.to_uppercase(),
                    city: city.to_string(),
                    coords: LatLon::new(lat, lon),
                    hop_rtt_ms: hop.rtt_ms,
                });
                break;
            }
        }
    }
    out
}
