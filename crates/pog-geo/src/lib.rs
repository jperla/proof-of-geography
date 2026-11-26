pub mod bounds;
pub mod byzantine;
pub mod calibration;
pub mod sphere;

pub use bounds::{
    effective_radius_km, starlink_min_rtt_ms, BoundTier, StarlinkModel, C_FIBER_KM_PER_S,
    C_VACUUM_KM_PER_S,
};
pub use byzantine::{
    verify_byzantine_core, ByzantineCoreResult, DiskConstraint, GeoError,
};
pub use calibration::{
    AnchorPairMeasurement, CalibrationAnomaly, CalibrationMatrix, CalibrationModel,
    MovementAnomaly, MovementReport, TimedGeoSnapshot,
};
pub use sphere::{CompassQuadrant, LatLon, Vec3, EARTH_RADIUS_KM};
