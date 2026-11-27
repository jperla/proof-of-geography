pub mod bounds;
pub mod byzantine;
pub mod calibration;
pub mod sphere;

pub use bounds::{
    effective_radius_km, effective_radius_km_with_uncertainty, starlink_min_rtt_ms, BoundTier,
    BoundUncertainty, StarlinkModel, C_CALIBRATED_DEFAULT_KM_PER_S, C_FIBER_KM_PER_S,
    C_VACUUM_KM_PER_S, HALF_CIRCUMFERENCE_KM, WGS84_MIN_CURVATURE_RADIUS_KM,
};
pub use byzantine::{
    verify_byzantine_core, ByzantineCoreResult, DiskConstraint, GeoError,
};
pub use calibration::{
    compute_spatial_likelihood, estimate_probabilistic_location, route_instability_spread_ms,
    AnchorPairMeasurement, CalibrationAnomaly, CalibrationMatrix, CalibrationModel,
    LikelihoodObservation, LikelihoodPeak, MovementAnomaly, MovementReport,
    ProbabilisticGeoEstimate, SpatialLikelihoodConfig, SpatialLikelihoodSurface, TimedGeoSnapshot,
};
pub use sphere::{CompassQuadrant, LatLon, Vec3, EARTH_RADIUS_KM};
