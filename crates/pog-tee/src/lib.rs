pub mod aws_nitro;
pub mod intel_tdx;
pub mod sev_snp;
pub mod software_dev;
pub mod types;

pub use aws_nitro::AwsNitroProvider;
pub use intel_tdx::IntelTdxProvider;
pub use sev_snp::AmdSevSnpProvider;
pub use software_dev::SoftwareDevProvider;
pub use types::{
    verify_quote, AttestationPolicy, GpuAttestationBinding, TeeAttestationQuote, TeeError,
    TeeProvider, TeeVendor, VerifiedTeeIdentity, WorkloadKeypair,
};

/// Auto-detect the best available hardware TEE on the current Linux/cloud host,
/// falling back to `SoftwareDevProvider` only if `allow_dev_fallback` is true.
pub fn auto_detect_provider(
    workload_measurement_override: Option<String>,
    allow_dev_fallback: bool,
) -> Result<Box<dyn TeeProvider>, TeeError> {
    if std::path::Path::new("/dev/sev-guest").exists() {
        return Ok(Box::new(AmdSevSnpProvider::new()));
    }
    if std::path::Path::new("/dev/tdx_guest").exists()
        || std::path::Path::new("/dev/tdx-guest").exists()
    {
        return Ok(Box::new(IntelTdxProvider::new()));
    }
    if std::path::Path::new("/dev/nsm").exists() {
        return Ok(Box::new(AwsNitroProvider::new()));
    }
    if allow_dev_fallback {
        let measurement = workload_measurement_override
            .unwrap_or_else(|| hex::encode(blake3::hash(b"pog-dev-workload-v1").as_bytes()));
        return Ok(Box::new(SoftwareDevProvider::new(measurement)));
    }
    Err(TeeError::HardwareDeviceUnavailable(
        "No /dev/sev-guest, /dev/tdx_guest, or /dev/nsm device found (pass --allow-dev-tee for local simulation)".into(),
    ))
}
