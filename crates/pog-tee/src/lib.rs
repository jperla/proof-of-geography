pub mod aws_nitro;
pub mod intel_tdx;
pub mod sev_snp;
pub mod software_dev;
pub mod types;

pub use aws_nitro::{
    pinned_aws_nitro_root_der, verify_nitro_cose_with_trust_root, AwsNitroProvider,
    NitroAttestationDocument, VerifiedNitroDocument, AWS_NITRO_ROOT_G1_PEM,
    AWS_NITRO_ROOT_G1_SHA256_HEX,
};
pub use intel_tdx::{
    verify_raw_tdx_quote, verify_raw_tdx_quote_with_pinned_roots, IntelTdxProvider,
    INTEL_SGX_ROOT_CA_SHA256_HEX, PINNED_INTEL_ROOT_SHA256_HEX,
};
pub use sev_snp::{
    verify_raw_sev_snp_report, verify_raw_sev_snp_report_with_pinned_roots, AmdSevSnpProvider,
    AMD_ARK_GENOA_SHA256_HEX, AMD_ARK_MILAN_SHA256_HEX, AMD_ARK_TURIN_SHA256_HEX,
    PINNED_AMD_ARK_SHA256_HEX,
};
pub use software_dev::SoftwareDevProvider;
pub use types::{
    compute_report_data, verify_quote, AttestationPolicy, GpuAttestationBinding,
    TeeAttestationQuote, TeeError, TeeProvider, TeeVendor, VerifiedTeeIdentity, WorkloadKeypair,
};

/// Auto-detect the best available hardware TEE on the current Linux/cloud host,
/// falling back to `SoftwareDevProvider` ONLY if `allow_dev_fallback` is true.
/// Production anchors/provers MUST pass `allow_dev_fallback = false`.
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
        "No /dev/sev-guest, /dev/tdx_guest, or /dev/nsm device found (production fail-closed; --allow-dev-tee is for local dev only)".into(),
    ))
}
