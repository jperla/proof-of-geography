use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TeeError {
    #[error("hardware TEE device unavailable: {0}")]
    HardwareDeviceUnavailable(String),
    #[error("attestation generation failed: {0}")]
    GenerationFailed(String),
    #[error("attestation verification failed: {0}")]
    VerificationFailed(String),
    #[error("policy rejected TEE quote: {0}")]
    PolicyRejected(String),
}

/// Supported TEE / Confidential Computing hardware vendors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TeeVendor {
    /// AMD EPYC Milan/Genoa/Turin SEV-SNP (GCP C3D/N2D, AWS c6a/m6a, Azure DCas_v5, Tencent CVM).
    AmdSevSnp,
    /// Intel Xeon Sapphire/Emerald Rapids TDX (GCP C3, Azure DCes_v5, ByteDance/Volcengine).
    IntelTdx,
    /// AWS Nitro Enclaves (uses NSM hardware-signed COSE_Sign1 CBOR attestation chained to AWS Nitro Root-G1).
    AwsNitro,
    /// Software-only mock TEE for local development and CI tests. NEVER accepted in production policy.
    SoftwareDev,
}

impl TeeVendor {
    pub fn as_str(self) -> &'static str {
        match self {
            TeeVendor::AmdSevSnp => "amd-sev-snp",
            TeeVendor::IntelTdx => "intel-tdx",
            TeeVendor::AwsNitro => "aws-nitro",
            TeeVendor::SoftwareDev => "software-dev",
        }
    }

    /// True iff this vendor represents an actual hardware TEE (never `SoftwareDev`).
    pub fn is_production_hardware_tee(self) -> bool {
        !matches!(self, TeeVendor::SoftwareDev)
    }
}

/// Optional binding to a local Confidential GPU (e.g., NVIDIA H100/B200 CC via SPDM)
/// attached over a protected PCIe/NVLink channel to the host CPU TEE.
///
/// NOTE: For the stronger `ConfidentialGpuInferenceLocation` claim, a bare `gpu_uuid` string is
/// NEVER sufficient — `evidence`, `gpu_pubkey_hex`, `spdm_session_transcript_hash_hex`, and
/// `protected_channel_id` MUST all be populated and verified against the pinned GPU vendor root CA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuAttestationBinding {
    pub gpu_model: String,
    pub gpu_uuid: String,
    /// SHA-256 of the signed GPU SPDM/RIM attestation report bound to the CPU TEE nonce.
    pub spdm_report_hash_hex: String,
    pub driver_measurement_hex: String,
    /// SEC1 P-384 public key hex of the attested local GPU device certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_pubkey_hex: Option<String>,
    /// SHA-256 hex digest of the active SPDM 1.2 mutual handshake transcript between THIS CPU TEE and THIS GPU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spdm_session_transcript_hash_hex: Option<String>,
    /// Active protected PCIe/NVLink channel session identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected_channel_id: Option<String>,
    /// Full vendor-signed GPU attestation evidence + X.509 chain (mandatory for inference-location claims).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<crate::gpu::GpuAttestationEvidence>,
}

/// Deserializer for `BTreeMap<u32, String>` inside internally-tagged `#[serde(tag = "kind")]`
/// enums, where serde buffers JSON object keys as strings (`"0"`, `"4"`, `"7"`, ...).
fn deserialize_u32_string_map<'de, D>(
    deserializer: D,
) -> Result<std::collections::BTreeMap<u32, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw: std::collections::BTreeMap<String, String> = serde::Deserialize::deserialize(deserializer)?;
    let mut out = std::collections::BTreeMap::new();
    for (k, v) in raw {
        let idx = k.parse::<u32>().map_err(serde::de::Error::custom)?;
        out.insert(idx, v);
    }
    Ok(out)
}

/// Optional cloud-specific workload-to-silicon attestation evidence binding the exact
/// immutable zero-SSH workload image/PCRs to the vendor hardware root of trust.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum WorkloadAttestation {
    /// Google Cloud Confidential Space OIDC JWT (`teeserver.sock` `/v1/token`), binding
    /// `hwmodel == "GCP_INTEL_TDX"`, `secboot == true`, `dbgstat == "disabled-since-boot"`,
    /// pinned `submods.container.image_digest`, empty `cmd_override`, and `eat_nonce(pk, nonce)`.
    GcpConfidentialSpaceOidc {
        jwt: String,
        audience: String,
        image_digest: String,
        hwmodel: String,
        swname: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        raw_tdx_quote_b64: Option<String>,
    },
    /// Azure Confidential VM HCL Report (`0x01400001` AMD SEV-SNP/TDX) chained to vTPM `akPub`
    /// and a fresh `TPM2_Quote` (`TPMS_ATTEST`) over measured UKI/dm-verity boot PCRs.
    AzureCvmHclVtpm {
        hcl_report_b64: String,
        vtpm_quote_b64: String,
        vtpm_quote_sig_b64: String,
        #[serde(deserialize_with = "deserialize_u32_string_map")]
        pcr_values: std::collections::BTreeMap<u32, String>,
        ak_pub_jwk_json: String,
    },
}

/// Hardware-backed (or dev) TEE Remote Attestation Quote binding a non-exportable
/// workload signing key (`public_key_hex`) and exact code measurement (`workload_measurement_hex`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeAttestationQuote {
    pub vendor: TeeVendor,
    /// Hex-encoded Ed25519 public key generated inside enclave RAM (`pk_P`).
    pub public_key_hex: String,
    /// Hex-encoded TEE code measurement (SEV-SNP Launch Digest / TDX MRTD / Nitro PCR0 / CS container digest / Azure PCR SHA-384).
    pub workload_measurement_hex: String,
    /// 64-byte hardware `report_data` = SHA-512("pog-tee-bind-v1" || pk_P || nonce || optional_gpu_hash).
    pub report_data_hex: String,
    /// Challenge nonce bound into this quote (e.g., epoch challenge or client handshake nonce).
    pub nonce_hex: String,
    /// Hardware policy flags extracted from the quote:
    /// `migration_disabled` MUST be true (MIGRATE_MA=0) so an attacker cannot live-migrate the enclave!
    pub migration_disabled: bool,
    /// Debug mode MUST be false in production.
    pub debug_disabled: bool,
    /// True when AMD Secure TSC (or equivalent hardware monotonic TSC lock) is enabled.
    pub secure_tsc_enabled: bool,
    /// Optional NVIDIA H100/B200 Confidential GPU binding for GPU localization compliance.
    pub gpu_binding: Option<GpuAttestationBinding>,
    /// Raw hardware attestation bytes (base64: SEV-SNP 1184B report / TDX v4 quote / Nitro COSE_Sign1 CBOR).
    pub raw_quote_b64: String,
    /// Optional PEM-encoded vendor X.509 certificate chain (e.g., AMD VCEK -> ASK -> ARK for SEV-SNP;
    /// AWS Nitro embeds its X.509 chain directly inside the COSE_Sign1 CBOR payload).
    #[serde(default)]
    pub vendor_cert_chain_pem: Vec<String>,
    /// Optional workload-to-silicon attestation evidence (GCP Confidential Space OIDC JWT or Azure CVM HCL+vTPM).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_attestation: Option<WorkloadAttestation>,
    /// Timestamp (Unix seconds) when the quote was generated.
    pub generated_at_unix_s: u64,
}

/// Ephemeral non-exportable keypair living solely inside TEE RAM.
/// Used simultaneously to authenticate workload outputs (e.g., RA-TLS / API receipts)
/// AND the distance-bounding PoG session so an attacker cannot split ping vs. compute enclaves!
pub struct WorkloadKeypair {
    signing_key: SigningKey,
}

impl WorkloadKeypair {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    pub fn verify_with_hex(
        public_key_hex: &str,
        message: &[u8],
        sig_bytes: &[u8],
    ) -> Result<(), TeeError> {
        let pk_raw = hex::decode(public_key_hex)
            .map_err(|e| TeeError::VerificationFailed(format!("invalid pk hex: {e}")))?;
        let pk_arr: [u8; 32] = pk_raw
            .try_into()
            .map_err(|_| TeeError::VerificationFailed("pk must be 32 bytes".into()))?;
        let vk = VerifyingKey::from_bytes(&pk_arr)
            .map_err(|e| TeeError::VerificationFailed(format!("invalid ed25519 pk: {e}")))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| TeeError::VerificationFailed("sig must be 64 bytes".into()))?;
        let sig = Signature::from_bytes(&sig_arr);
        vk.verify(message, &sig)
            .map_err(|e| TeeError::VerificationFailed(format!("sig verify failed: {e}")))
    }
}

/// Compute the canonical 64-byte hardware `report_data` binding `pk_P`, `nonce`, and optional GPU SPDM hash.
pub fn compute_report_data(
    public_key: &[u8; 32],
    nonce: &[u8],
    gpu_binding: Option<&GpuAttestationBinding>,
) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(b"pog-tee-bind-v1");
    hasher.update(public_key);
    hasher.update(nonce);
    if let Some(gpu) = gpu_binding {
        hasher.update(gpu.gpu_uuid.as_bytes());
        hasher.update(gpu.spdm_report_hash_hex.as_bytes());
        if let Some(ref pk) = gpu.gpu_pubkey_hex {
            hasher.update(b"|gpk:");
            hasher.update(pk.to_ascii_lowercase().as_bytes());
        }
        if let Some(ref tr) = gpu.spdm_session_transcript_hash_hex {
            hasher.update(b"|spdm:");
            hasher.update(tr.to_ascii_lowercase().as_bytes());
        }
        if let Some(ref ch) = gpu.protected_channel_id {
            hasher.update(b"|ch:");
            hasher.update(ch.as_bytes());
        }
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

/// Policy enforced when verifying a Prover or Anchor TEE quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationPolicy {
    pub allow_software_dev: bool,
    pub require_migration_disabled: bool,
    pub require_debug_disabled: bool,
    pub require_secure_tsc: bool,
    /// Fail-closed production invariant: require full cryptographic verification of the hardware
    /// vendor signature & X.509 trust root (AWS Nitro Root-G1, AMD VCEK/ASK/ARK, Intel DCAP PCK).
    #[serde(default = "default_true")]
    pub require_cryptographic_vendor_chain: bool,
    pub max_quote_age_seconds: u64,
    /// Maximum tolerated clock skew into the future for quote timestamps (seconds).
    #[serde(default = "default_future_skew")]
    pub max_future_skew_seconds: u64,
    /// If non-empty, `workload_measurement_hex` (SEV-SNP Launch Digest / TDX MRTD / Nitro PCR0) must appear here.
    pub allowed_measurements: Vec<String>,
    /// Optional Nitro PCR1 (kernel/boot) allowlist.
    #[serde(default)]
    pub allowed_pcr1: Vec<String>,
    /// Optional Nitro PCR2 (application) allowlist.
    #[serde(default)]
    pub allowed_pcr2: Vec<String>,
    /// Optional GCP Confidential Space container `sha256:...` digest allowlist.
    #[serde(default)]
    pub allowed_container_digests: Vec<String>,
    /// Optional trusted Google Confidential Space JWKS JSON (for offline RS256 verification).
    #[serde(default)]
    pub trusted_gcp_cs_jwks_json: Option<String>,
    /// Optional expected GCP Confidential Space OIDC audience (defaults to https://proofofgeography.com).
    #[serde(default)]
    pub expected_gcp_cs_audience: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_future_skew() -> u64 {
    300
}

impl AttestationPolicy {
    /// Strict fail-closed production policy:
    /// - SoftwareDev FORBIDDEN
    /// - Cryptographic vendor trust-chain verification REQUIRED
    /// - Migration disabled & debug disabled REQUIRED
    pub fn production() -> Self {
        Self {
            allow_software_dev: false,
            require_migration_disabled: true,
            require_debug_disabled: true,
            require_secure_tsc: false,
            require_cryptographic_vendor_chain: true,
            max_quote_age_seconds: 3600,
            max_future_skew_seconds: 300,
            allowed_measurements: Vec::new(),
            allowed_pcr1: Vec::new(),
            allowed_pcr2: Vec::new(),
            allowed_container_digests: Vec::new(),
            trusted_gcp_cs_jwks_json: None,
            expected_gcp_cs_audience: None,
        }
    }

    /// Local development / CI simulation policy ONLY.
    /// MUST NEVER be enabled in production release configs or registries.
    pub fn allow_dev_software() -> Self {
        Self {
            allow_software_dev: true,
            require_migration_disabled: true,
            require_debug_disabled: true,
            require_secure_tsc: false,
            require_cryptographic_vendor_chain: false,
            max_quote_age_seconds: 86_400,
            max_future_skew_seconds: 600,
            allowed_measurements: Vec::new(),
            allowed_pcr1: Vec::new(),
            allowed_pcr2: Vec::new(),
            allowed_container_digests: Vec::new(),
            trusted_gcp_cs_jwks_json: None,
            expected_gcp_cs_audience: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedTeeIdentity {
    pub vendor: TeeVendor,
    pub public_key_hex: String,
    pub workload_measurement_hex: String,
    pub secure_tsc_enabled: bool,
    pub has_gpu_binding: bool,
    /// True iff the vendor's cryptographic signature & X.509 trust root verified end-to-end.
    #[serde(default)]
    pub vendor_chain_verified: bool,
    /// True iff `vendor.is_production_hardware_tee() && vendor_chain_verified`.
    #[serde(default)]
    pub hardware_attested: bool,
}

/// Trait implemented by each hardware TEE backend (SEV-SNP, Intel TDX, AWS Nitro, SoftwareDev).
pub trait TeeProvider: Send + Sync {
    fn vendor(&self) -> TeeVendor;

    /// Generate a hardware-attested quote binding `public_key`, `nonce`, and optional Confidential GPU.
    fn attest(
        &self,
        public_key: &[u8; 32],
        nonce: &[u8],
        gpu_binding: Option<GpuAttestationBinding>,
    ) -> Result<TeeAttestationQuote, TeeError>;
}

/// Verify a `TeeAttestationQuote` against `policy` and expected `nonce`.
pub fn verify_quote(
    quote: &TeeAttestationQuote,
    expected_nonce: &[u8],
    policy: &AttestationPolicy,
    now_unix_s: u64,
) -> Result<VerifiedTeeIdentity, TeeError> {
    if quote.vendor == TeeVendor::SoftwareDev && !policy.allow_software_dev {
        return Err(TeeError::PolicyRejected(
            "SoftwareDev TEE quotes are forbidden under production policy".into(),
        ));
    }
    if policy.require_migration_disabled && !quote.migration_disabled {
        return Err(TeeError::PolicyRejected(
            "TEE policy violation: MIGRATE_MA must be disabled to prevent live relocation".into(),
        ));
    }
    if policy.require_debug_disabled && !quote.debug_disabled {
        return Err(TeeError::PolicyRejected(
            "TEE policy violation: debug mode must be disabled".into(),
        ));
    }
    if policy.require_secure_tsc && !quote.secure_tsc_enabled {
        return Err(TeeError::PolicyRejected(
            "TEE policy violation: Secure TSC required".into(),
        ));
    }
    if now_unix_s > quote.generated_at_unix_s.saturating_add(policy.max_quote_age_seconds) {
        return Err(TeeError::PolicyRejected(format!(
            "TEE quote expired (age {}s > max {}s)",
            now_unix_s.saturating_sub(quote.generated_at_unix_s),
            policy.max_quote_age_seconds
        )));
    }
    if quote.generated_at_unix_s > now_unix_s.saturating_add(policy.max_future_skew_seconds) {
        return Err(TeeError::PolicyRejected(format!(
            "TEE quote timestamp is {}s in the future (max skew {}s)",
            quote.generated_at_unix_s - now_unix_s,
            policy.max_future_skew_seconds
        )));
    }
    if !policy.allowed_measurements.is_empty()
        && !policy
            .allowed_measurements
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&quote.workload_measurement_hex))
    {
        return Err(TeeError::PolicyRejected(format!(
            "workload measurement {} not in allowlist",
            quote.workload_measurement_hex
        )));
    }

    // Verify nonce & cryptographic report_data binding.
    let expected_nonce_hex = hex::encode(expected_nonce);
    if !quote.nonce_hex.eq_ignore_ascii_case(&expected_nonce_hex) {
        return Err(TeeError::VerificationFailed(
            "quote nonce mismatch".into(),
        ));
    }
    let pk_raw = hex::decode(&quote.public_key_hex)
        .map_err(|e| TeeError::VerificationFailed(format!("bad pk hex: {e}")))?;
    let pk_arr: [u8; 32] = pk_raw
        .try_into()
        .map_err(|_| TeeError::VerificationFailed("pk must be 32 bytes".into()))?;

    let expected_rd = compute_report_data(&pk_arr, expected_nonce, quote.gpu_binding.as_ref());
    if !quote.report_data_hex.eq_ignore_ascii_case(&hex::encode(expected_rd)) {
        return Err(TeeError::VerificationFailed(
            "hardware report_data does not match SHA-512(pk_P || nonce || gpu)".into(),
        ));
    }

    // Vendor-specific structural + cryptographic chain verification of the raw hardware quote bytes
    // (or cloud workload-to-silicon chain for GCP Confidential Space TDX & Azure CVM HCL+vTPM).
    let vendor_chain_verified = match (&quote.vendor, &quote.workload_attestation) {
        (TeeVendor::IntelTdx, Some(WorkloadAttestation::GcpConfidentialSpaceOidc { .. })) => {
            crate::gcp_confidential_space::verify_gcp_confidential_space_quote(
                quote,
                expected_nonce,
                policy,
                now_unix_s,
            )?
        }
        (
            TeeVendor::AmdSevSnp | TeeVendor::IntelTdx,
            Some(WorkloadAttestation::AzureCvmHclVtpm { .. }),
        ) => crate::azure_cvm::verify_azure_cvm_quote(quote, expected_nonce, policy, now_unix_s)?,
        (TeeVendor::AmdSevSnp, _) => {
            crate::sev_snp::verify_raw_sev_snp_report(quote, policy, now_unix_s)?
        }
        (TeeVendor::IntelTdx, _) => {
            crate::intel_tdx::verify_raw_tdx_quote(quote, policy, now_unix_s)?
        }
        (TeeVendor::AwsNitro, _) => {
            crate::aws_nitro::verify_raw_nitro_doc(quote, expected_nonce, policy, now_unix_s)?
        }
        (TeeVendor::SoftwareDev, _) => {
            crate::software_dev::verify_raw_dev_quote(quote)?;
            false
        }
    };

    if policy.require_cryptographic_vendor_chain && !vendor_chain_verified {
        return Err(TeeError::VerificationFailed(format!(
            "fail-closed policy requires cryptographic vendor chain verification for {}",
            quote.vendor.as_str()
        )));
    }

    Ok(VerifiedTeeIdentity {
        vendor: quote.vendor,
        public_key_hex: quote.public_key_hex.clone(),
        workload_measurement_hex: quote.workload_measurement_hex.clone(),
        secure_tsc_enabled: quote.secure_tsc_enabled,
        has_gpu_binding: quote.gpu_binding.is_some(),
        vendor_chain_verified,
        hardware_attested: quote.vendor.is_production_hardware_tee() && vendor_chain_verified,
    })
}
