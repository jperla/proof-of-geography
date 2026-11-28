pub mod aws_nitro;
pub mod azure_cvm;
pub mod gcp_confidential_space;
pub mod gpu;
pub mod intel_tdx;
pub mod sev_snp;
pub mod software_dev;
pub mod types;

pub use aws_nitro::{
    pinned_aws_nitro_root_der, verify_nitro_cose_with_trust_root, AwsNitroProvider,
    NitroAttestationDocument, VerifiedNitroDocument, AWS_NITRO_ROOT_G1_PEM,
    AWS_NITRO_ROOT_G1_SHA256_HEX,
};
pub use azure_cvm::{
    compute_azure_pcr_workload_measurement, compute_azure_vtpm_qualifying_data,
    parse_azure_hcl_report, parse_tpms_attest_quote, verify_azure_cvm_quote,
    verify_azure_cvm_quote_with_pinned_roots, AzureCvmProvider, AZURE_HCL_NV_INDEX,
    AZURE_VTPM_AK_HANDLE, HCL_REPORT_TYPE_SNP, HCL_REPORT_TYPE_TDX,
};
pub use gcp_confidential_space::{
    verify_gcp_confidential_space_jwt, verify_gcp_confidential_space_quote,
    GcpConfidentialSpaceProvider, JwkSet, RsaJwk, VerifiedGcpConfidentialSpaceToken,
    GCP_CS_DEFAULT_AUDIENCE, GCP_CS_ISSUER, GCP_CS_JWKS_URI, GCP_CS_LLM_DEMO_AUDIENCE,
    GCP_CS_TEE_SOCKET, PINNED_OFFICIAL_GCP_CS_JWKS_JSON,
};
pub use gpu::{
    compute_gpu_binding_nonce, verify_gpu_attestation_evidence, GpuAttestationEvidence,
    GpuCpuLocalityProofLevel, GpuProtectedChannelKind, SignedGpuSpdmQuotePayload,
    VerifiedGpuBinding,
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
    TeeAttestationQuote, TeeError, TeeProvider, TeeVendor, VerifiedTeeIdentity,
    WorkloadAttestation, WorkloadKeypair,
};

/// Auto-detect the best available hardware TEE on the current Linux/cloud host,
/// falling back to `SoftwareDevProvider` ONLY if `allow_dev_fallback` is true.
/// Production anchors/provers MUST pass `allow_dev_fallback = false`.
pub fn auto_detect_provider(
    workload_measurement_override: Option<String>,
    allow_dev_fallback: bool,
) -> Result<Box<dyn TeeProvider>, TeeError> {
    // Prefer GCP Confidential Space launcher socket when present so Intel TDX hardware is
    // cryptographically chained directly to the pinned zero-shell OCI image digest.
    if GcpConfidentialSpaceProvider::is_available() {
        return Ok(Box::new(GcpConfidentialSpaceProvider::new()));
    }
    // Prefer Azure CVM HCL+vTPM when /dev/tpmrm0 exposes a valid HCLA SEV-SNP/TDX report
    // (returns false on Trusted Launch VMs so Trusted Launch is NEVER accepted as a HW TEE).
    if AzureCvmProvider::is_available() {
        return Ok(Box::new(AzureCvmProvider::new()));
    }
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
        "No Confidential Space teeserver.sock, /dev/sev-guest, /dev/tdx_guest, or /dev/nsm device found (production fail-closed; --allow-dev-tee is for local dev only)".into(),
    ))
}
