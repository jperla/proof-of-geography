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
    /// AWS Nitro Enclaves (available in all AWS regions; uses NSM COSE_Sign1 CBOR attestation).
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
}

/// Optional binding to a local Confidential GPU (e.g., NVIDIA H100/B200 CC via SPDM)
/// attached over PCIe/NVLink to the host CPU TEE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuAttestationBinding {
    pub gpu_model: String,
    pub gpu_uuid: String,
    /// SHA-256 of the NVIDIA RIM/SPDM attestation report bound to the CPU TEE nonce.
    pub spdm_report_hash_hex: String,
    pub driver_measurement_hex: String,
}

/// Hardware-backed (or dev) TEE Remote Attestation Quote binding a non-exportable
/// workload signing key (`public_key_hex`) and exact code measurement (`workload_measurement_hex`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeAttestationQuote {
    pub vendor: TeeVendor,
    /// Hex-encoded Ed25519 public key generated inside enclave RAM (`pk_P`).
    pub public_key_hex: String,
    /// Hex-encoded TEE code measurement (SEV-SNP Launch Digest / TDX MRTD+RTMR / Nitro PCR0).
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
    /// Raw hardware attestation bytes (base64: SEV-SNP 1184B report / TDX quote / Nitro COSE_Sign1).
    pub raw_quote_b64: String,
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
    pub max_quote_age_seconds: u64,
    /// If non-empty, the quote's `workload_measurement_hex` must appear in this allowlist.
    pub allowed_measurements: Vec<String>,
}

impl AttestationPolicy {
    pub fn production() -> Self {
        Self {
            allow_software_dev: false,
            require_migration_disabled: true,
            require_debug_disabled: true,
            require_secure_tsc: false,
            max_quote_age_seconds: 3600,
            allowed_measurements: Vec::new(),
        }
    }

    pub fn allow_dev_software() -> Self {
        Self {
            allow_software_dev: true,
            require_migration_disabled: true,
            require_debug_disabled: true,
            require_secure_tsc: false,
            max_quote_age_seconds: 86_400,
            allowed_measurements: Vec::new(),
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
    if now_unix_s > quote.generated_at_unix_s + policy.max_quote_age_seconds {
        return Err(TeeError::PolicyRejected(format!(
            "TEE quote expired (age {}s > max {}s)",
            now_unix_s - quote.generated_at_unix_s,
            policy.max_quote_age_seconds
        )));
    }
    if !policy.allowed_measurements.is_empty()
        && !policy
            .allowed_measurements
            .contains(&quote.workload_measurement_hex)
    {
        return Err(TeeError::PolicyRejected(format!(
            "workload measurement {} not in allowlist",
            quote.workload_measurement_hex
        )));
    }

    // Verify nonce & cryptographic report_data binding.
    let expected_nonce_hex = hex::encode(expected_nonce);
    if quote.nonce_hex != expected_nonce_hex {
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
    if quote.report_data_hex != hex::encode(expected_rd) {
        return Err(TeeError::VerificationFailed(
            "hardware report_data does not match SHA-512(pk_P || nonce || gpu)".into(),
        ));
    }

    // Vendor-specific structural verification of the raw hardware quote bytes.
    match quote.vendor {
        TeeVendor::AmdSevSnp => crate::sev_snp::verify_raw_sev_snp_report(quote)?,
        TeeVendor::IntelTdx => crate::intel_tdx::verify_raw_tdx_quote(quote)?,
        TeeVendor::AwsNitro => crate::aws_nitro::verify_raw_nitro_doc(quote, now_unix_s)?,
        TeeVendor::SoftwareDev => crate::software_dev::verify_raw_dev_quote(quote)?,
    }

    Ok(VerifiedTeeIdentity {
        vendor: quote.vendor,
        public_key_hex: quote.public_key_hex.clone(),
        workload_measurement_hex: quote.workload_measurement_hex.clone(),
        secure_tsc_enabled: quote.secure_tsc_enabled,
        has_gpu_binding: quote.gpu_binding.is_some(),
    })
}
