use serde::{Deserialize, Serialize};

/// Mean Earth radius in kilometers (IUGG mean radius).
pub const EARTH_RADIUS_KM: f64 = 6371.0088;

/// Geographic coordinate in WGS84 decimal degrees.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LatLon {
    pub lat: f64,
    pub lon: f64,
}

impl LatLon {
    pub fn new(lat: f64, lon: f64) -> Self {
        Self { lat, lon }
    }

    /// Convert latitude/longitude to a 3D unit vector on the unit sphere S^2.
    pub fn to_unit_vec(self) -> Vec3 {
        let lat_rad = self.lat.to_radians();
        let lon_rad = self.lon.to_radians();
        let cos_lat = lat_rad.cos();
        Vec3 {
            x: cos_lat * lon_rad.cos(),
            y: cos_lat * lon_rad.sin(),
            z: lat_rad.sin(),
        }
    }

    /// Great-circle geodesic distance in kilometers.
    pub fn distance_km(self, other: LatLon) -> f64 {
        self.to_unit_vec().geodesic_km(other.to_unit_vec())
    }

    /// Initial compass bearing in degrees [0, 360) from `self` toward `other`.
    pub fn bearing_deg(self, other: LatLon) -> f64 {
        let lat1 = self.lat.to_radians();
        let lat2 = other.lat.to_radians();
        let dlon = (other.lon - self.lon).to_radians();
        let y = dlon.sin() * lat2.cos();
        let x = lat1.cos() * lat2.sin() - lat1.sin() * lat2.cos() * dlon.cos();
        (y.atan2(x).to_degrees() + 360.0) % 360.0
    }

    /// Compass quadrant of `other` relative to `self`.
    pub fn quadrant_of(self, other: LatLon) -> CompassQuadrant {
        let b = self.bearing_deg(other);
        if b < 90.0 {
            CompassQuadrant::NorthEast
        } else if b < 180.0 {
            CompassQuadrant::SouthEast
        } else if b < 270.0 {
            CompassQuadrant::SouthWest
        } else {
            CompassQuadrant::NorthWest
        }
    }
}

/// Cardinal compass quadrant used to enforce orthogonal anchor framing around a prover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CompassQuadrant {
    NorthEast,
    SouthEast,
    SouthWest,
    NorthWest,
}

impl CompassQuadrant {
    pub const ALL: [CompassQuadrant; 4] = [
        CompassQuadrant::NorthEast,
        CompassQuadrant::SouthEast,
        CompassQuadrant::SouthWest,
        CompassQuadrant::NorthWest,
    ];
}

/// 3D vector used for exact spherical cap half-space arithmetic on S^2.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Vec3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Vec3 {
    pub fn new(x: f64, y: f64, z: f64) -> Self {
        Self { x, y, z }
    }

    #[inline]
    pub fn dot(self, rhs: Vec3) -> f64 {
        self.x * rhs.x + self.y * rhs.y + self.z * rhs.z
    }

    #[inline]
    pub fn cross(self, rhs: Vec3) -> Vec3 {
        Vec3 {
            x: self.y * rhs.z - self.z * rhs.y,
            y: self.z * rhs.x - self.x * rhs.z,
            z: self.x * rhs.y - self.y * rhs.x,
        }
    }

    #[inline]
    pub fn norm_sq(self) -> f64 {
        self.dot(self)
    }

    #[inline]
    pub fn norm(self) -> f64 {
        self.norm_sq().sqrt()
    }

    #[inline]
    pub fn scale(self, s: f64) -> Vec3 {
        Vec3 {
            x: self.x * s,
            y: self.y * s,
            z: self.z * s,
        }
    }

    pub fn normalize(self) -> Option<Vec3> {
        let n = self.norm();
        if n < 1e-15 {
            None
        } else {
            Some(self.scale(1.0 / n))
        }
    }

    /// Exact angular distance in radians between two unit vectors on S^2.
    pub fn angular_distance(self, other: Vec3) -> f64 {
        let d = self.dot(other).clamp(-1.0, 1.0);
        d.acos()
    }

    /// Geodesic distance in km between two unit vectors on S^2.
    pub fn geodesic_km(self, other: Vec3) -> f64 {
        self.angular_distance(other) * EARTH_RADIUS_KM
    }

    /// Convert unit vector back to latitude/longitude degrees.
    pub fn to_lat_lon(self) -> LatLon {
        let u = self.normalize().unwrap_or(Vec3::new(1.0, 0.0, 0.0));
        let lat = u.z.clamp(-1.0, 1.0).asin().to_degrees();
        let lon = u.y.atan2(u.x).to_degrees();
        LatLon { lat, lon }
    }

    /// Any deterministic unit vector orthogonal to `self`.
    pub fn any_orthogonal_unit(self) -> Vec3 {
        let basis = if self.x.abs() < 0.9 {
            Vec3::new(1.0, 0.0, 0.0)
        } else {
            Vec3::new(0.0, 1.0, 0.0)
        };
        self.cross(basis)
            .normalize()
            .unwrap_or(Vec3::new(0.0, 0.0, 1.0))
    }
}

impl std::ops::Add for Vec3 {
    type Output = Vec3;
    #[inline]
    fn add(self, rhs: Vec3) -> Vec3 {
        Vec3 {
            x: self.x + rhs.x,
            y: self.y + rhs.y,
            z: self.z + rhs.z,
        }
    }
}

impl std::ops::Sub for Vec3 {
    type Output = Vec3;
    #[inline]
    fn sub(self, rhs: Vec3) -> Vec3 {
        Vec3 {
            x: self.x - rhs.x,
            y: self.y - rhs.y,
            z: self.z - rhs.z,
        }
    }
}

impl std::ops::Neg for Vec3 {
    type Output = Vec3;
    #[inline]
    fn neg(self) -> Vec3 {
        self.scale(-1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_and_distance() {
        let tokyo = LatLon::new(35.6762, 139.6503);
        let singapore = LatLon::new(1.3521, 103.8198);
        let d = tokyo.distance_km(singapore);
        assert!((d - 5312.0).abs() < 40.0, "Tokyo-Singapore distance was {d}");

        let rt = tokyo.to_unit_vec().to_lat_lon();
        assert!((rt.lat - tokyo.lat).abs() < 1e-9);
        assert!((rt.lon - tokyo.lon).abs() < 1e-9);
    }
}
