use crate::types::{AttestationPolicy, GpuAttestationBinding, TeeError};
use base64::engine::general_purpose::STANDARD as B64_STD;
use base64::Engine;
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{DerSignature, VerifyingKey as P384VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// Protected interconnect channel type between CPU TEE and local Confidential GPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuProtectedChannelKind {
    /// NVIDIA H100/B200 Confidential Computing over SPDM 1.2+ encrypted PCIe/NVLink bounce buffers.
    PcieSpdmEncryptedBounceBuffer,
    /// Hardware-rooted PCIe 6.0 IDE / NVLink-C2C link encryption with platform-attested physical topology.
    PcieIdeHardwareProtected,
}

/// Honest classification of what physical CPU-to-GPU locality the available hardware evidence
/// actually proves vs. what remains an explicit platform/chassis assumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuCpuLocalityProofLevel {
    /// Hardware-attested PCIe IDE / NVLink-C2C link with platform chassis topology / link-layer distance bound.
    HardwareRootedDirectAttach,
    /// Verified SPDM 1.2+ protected channel + mutually coupled CPU/GPU quotes, WITHOUT independent
    /// verifier distance-bounding of the physical PCIe/NVLink interconnect (explicit assumption reported).
    SpdmProtectedLocalChannelAssumedColocated,
    /// Bare GPU UUID, unlinked independent quotes, or missing protected channel (always rejected!).
    UnverifiedOrSplit,
}

/// Canonical JSON payload signed directly by the Confidential GPU's device attestation key (ECDSA P-384).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedGpuSpdmQuotePayload {
    pub gpu_vendor: String,
    pub gpu_model: String,
    pub gpu_uuid: String,
    /// Cryptographic coupling nonce: MUST equal `compute_gpu_binding_nonce(prover_pk, cpu_nonce, spdm_session_transcript_hash_hex)`.
    pub gpu_nonce_hex: String,
    /// SHA-256 hex digest of the live SPDM 1.2 mutual handshake transcript between THIS CPU TEE and THIS GPU.
    pub spdm_session_transcript_hash_hex: String,
    pub protected_channel_id: String,
    pub channel_kind: GpuProtectedChannelKind,
    /// True iff GPU Confidential Compute mode (`CC=ON`) is enforced in hardware.
    pub cc_mode_enabled: bool,
    /// True iff GPU debug/unlock fuses are disabled in hardware.
    pub debug_disabled: bool,
    pub driver_measurement_hex: String,
    pub vbios_measurement_hex: String,
    pub generated_at_unix_s: u64,
}

/// Full cryptographic GPU attestation evidence required for the separate `ConfidentialGpuInferenceLocation` claim.
/// A bare `gpu_uuid` or unverified `spdm_report_hash_hex` is NEVER sufficient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuAttestationEvidence {
    pub gpu_vendor: String,
    pub gpu_model: String,
    pub gpu_uuid: String,
    /// Hex-encoded SEC1 P-384 public key of the GPU leaf device attestation certificate.
    pub gpu_pubkey_hex: String,
    /// Coupling nonce bound inside the GPU-signed SPDM quote.
    pub gpu_nonce_hex: String,
    pub cc_mode_enabled: bool,
    pub debug_disabled: bool,
    pub driver_measurement_hex: String,
    pub vbios_measurement_hex: String,
    pub channel_kind: GpuProtectedChannelKind,
    pub protected_channel_id: String,
    pub spdm_session_transcript_hash_hex: String,
    /// Base64 of canonical serialized `SignedGpuSpdmQuotePayload` (SHA-256 MUST equal `spdm_report_hash_hex`).
    pub raw_spdm_quote_b64: String,
    /// Base64 of DER-encoded ECDSA P-384 / SHA-384 signature over `raw_spdm_quote` by the GPU leaf cert.
    pub gpu_signature_b64: String,
    /// PEM X.509 certificate chain: `[GPU Device Leaf Cert, Vendor Intermediate CA, Pinned Vendor Root CA]`.
    pub vendor_cert_chain_pem: Vec<String>,
    pub generated_at_unix_s: u64,
}

/// Authoritative verification output for CPU-to-GPU confidential binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedGpuBinding {
    pub gpu_vendor: String,
    pub gpu_model: String,
    pub gpu_uuid: String,
    pub gpu_pubkey_hex: String,
    pub spdm_report_hash_hex: String,
    pub spdm_session_transcript_hash_hex: String,
    pub protected_channel_id: String,
    pub channel_kind: GpuProtectedChannelKind,
    pub root_ca_sha256_hex: String,
    pub locality_proof_level: GpuCpuLocalityProofLevel,
    /// Honestly `false` when physical PCIe/NVLink distance cannot be independently proven from
    /// available SPDM evidence alone; callers MUST inspect `locality_assumptions`.
    pub hardware_locality_established: bool,
    pub locality_assumptions: Vec<String>,
}

/// Compute the mandatory 32-byte coupling nonce that MUST appear inside the GPU's signed SPDM quote.
///
/// Defeats "two independent valid quotes": the GPU quote must commit to THIS exact Prover TEE
/// public key, THIS CPU TEE epoch/challenge nonce, AND THIS live SPDM protected-channel transcript.
pub fn compute_gpu_binding_nonce(
    prover_public_key: &[u8; 32],
    cpu_challenge_nonce: &[u8],
    spdm_session_transcript_hash_hex: &str,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"pog-gpu-bind-v1");
    h.update(prover_public_key);
    h.update(cpu_challenge_nonce);
    h.update(spdm_session_transcript_hash_hex.trim().to_ascii_lowercase().as_bytes());
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

fn verify_p384_x509_sig(child: &X509Certificate<'_>, parent: &X509Certificate<'_>) -> Result<(), TeeError> {
    let parent_vk = P384VerifyingKey::from_sec1_bytes(
        parent.public_key().subject_public_key.data.as_ref(),
    )
    .map_err(|e| TeeError::VerificationFailed(format!("invalid GPU CA P-384 key: {e}")))?;
    let der_sig = DerSignature::from_bytes(child.signature_value.data.as_ref())
        .map_err(|e| TeeError::VerificationFailed(format!("invalid GPU X.509 DER sig: {e}")))?;
    parent_vk
        .verify(child.tbs_certificate.as_ref(), &der_sig)
        .map_err(|e| TeeError::VerificationFailed(format!("GPU X.509 chain signature invalid: {e}")))
}

/// Strictly verify that a `GpuAttestationBinding` proves a real, vendor-rooted, CC-enabled,
/// non-debug Confidential GPU cryptographically coupled over a protected channel to THIS
/// specific Prover TEE key (`prover_public_key`) and challenge (`cpu_challenge_nonce`).
///
/// Fails closed on:
/// - Bare quoted GPU ID (missing `evidence`)
/// - Two independent valid quotes (missing or mismatched `gpu_nonce_hex` coupling)
/// - Missing protected channel / SPDM session transcript
/// - `cc_mode_enabled == false` or `debug_disabled == false`
/// - Unpinned / self-signed / expired GPU vendor cert chain or invalid ECDSA P-384 signature
/// - Stale or future-skewed GPU quote timestamp
pub fn verify_gpu_attestation_evidence(
    binding: &GpuAttestationBinding,
    prover_public_key: &[u8; 32],
    cpu_challenge_nonce: &[u8],
    policy: &AttestationPolicy,
    now_unix_s: u64,
    pinned_gpu_root_sha256_hex: &[&str],
) -> Result<VerifiedGpuBinding, TeeError> {
    let evidence = binding.evidence.as_ref().ok_or_else(|| {
        TeeError::VerificationFailed(
            "bare quoted GPU ID rejected: GpuAttestationBinding missing cryptographic GpuAttestationEvidence (fail-closed)"
                .into(),
        )
    })?;

    if pinned_gpu_root_sha256_hex.is_empty() && policy.require_cryptographic_vendor_chain {
        return Err(TeeError::PolicyRejected(
            "production GPU attestation requires at least one pinned GPU vendor Root CA SHA-256 (fail-closed)"
                .into(),
        ));
    }

    // 1. Require active protected channel metadata on BOTH outer binding & evidence.
    let binding_transcript = binding
        .spdm_session_transcript_hash_hex
        .as_deref()
        .unwrap_or("")
        .trim();
    let binding_channel = binding
        .protected_channel_id
        .as_deref()
        .unwrap_or("")
        .trim();
    let binding_gpu_pk = binding.gpu_pubkey_hex.as_deref().unwrap_or("").trim();

    if binding_transcript.len() != 64 || !binding_transcript.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(TeeError::VerificationFailed(
            "GPU binding missing valid 64-hex spdm_session_transcript_hash_hex".into(),
        ));
    }
    if binding_channel.is_empty() {
        return Err(TeeError::VerificationFailed(
            "GPU binding missing protected_channel_id".into(),
        ));
    }
    if binding_gpu_pk.is_empty() {
        return Err(TeeError::VerificationFailed(
            "GPU binding missing gpu_pubkey_hex".into(),
        ));
    }

    // 2. Verify raw signed SPDM quote hash matches `spdm_report_hash_hex` committed in CPU report_data!
    let raw_quote = B64_STD
        .decode(&evidence.raw_spdm_quote_b64)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid GPU raw_spdm_quote_b64: {e}")))?;
    let actual_report_hash = hex::encode(Sha256::digest(&raw_quote));
    if !actual_report_hash.eq_ignore_ascii_case(&binding.spdm_report_hash_hex) {
        return Err(TeeError::VerificationFailed(format!(
            "GPU SHA-256(raw_spdm_quote) {actual_report_hash} != binding.spdm_report_hash_hex {}",
            binding.spdm_report_hash_hex
        )));
    }

    // 3. Parse signed GPU payload and assert every security-critical claim comes from SIGNED bytes.
    let signed_payload: SignedGpuSpdmQuotePayload = serde_json::from_slice(&raw_quote)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid signed GPU SPDM quote JSON: {e}")))?;

    if !signed_payload.cc_mode_enabled {
        return Err(TeeError::PolicyRejected(
            "GPU Confidential Compute mode (cc_mode_enabled) MUST be true".into(),
        ));
    }
    if policy.require_debug_disabled && !signed_payload.debug_disabled {
        return Err(TeeError::PolicyRejected(
            "GPU debug mode MUST be disabled (debug_disabled=false rejected)".into(),
        ));
    }
    if signed_payload.gpu_uuid != binding.gpu_uuid
        || signed_payload.gpu_uuid != evidence.gpu_uuid
        || signed_payload.gpu_model != binding.gpu_model
        || signed_payload.driver_measurement_hex != binding.driver_measurement_hex
        || !signed_payload
            .spdm_session_transcript_hash_hex
            .eq_ignore_ascii_case(binding_transcript)
        || !signed_payload
            .spdm_session_transcript_hash_hex
            .eq_ignore_ascii_case(&evidence.spdm_session_transcript_hash_hex)
        || signed_payload.protected_channel_id != binding_channel
        || signed_payload.protected_channel_id != evidence.protected_channel_id
    {
        return Err(TeeError::VerificationFailed(
            "GPU signed SPDM payload fields do not match CPU-bound GpuAttestationBinding".into(),
        ));
    }

    // 4. Freshness & skew checks on signed GPU quote timestamp.
    if now_unix_s > signed_payload.generated_at_unix_s.saturating_add(policy.max_quote_age_seconds) {
        return Err(TeeError::PolicyRejected(format!(
            "GPU attestation quote expired (age {}s > max {}s)",
            now_unix_s.saturating_sub(signed_payload.generated_at_unix_s),
            policy.max_quote_age_seconds
        )));
    }
    if signed_payload.generated_at_unix_s > now_unix_s.saturating_add(policy.max_future_skew_seconds) {
        return Err(TeeError::PolicyRejected(format!(
            "GPU attestation quote timestamp {}s in future",
            signed_payload.generated_at_unix_s - now_unix_s
        )));
    }

    // 5. CRITICAL MUTUAL COUPLING CHECK: defeats "two independent valid quotes"!
    let expected_gpu_nonce_hex = hex::encode(compute_gpu_binding_nonce(
        prover_public_key,
        cpu_challenge_nonce,
        &signed_payload.spdm_session_transcript_hash_hex,
    ));
    if !signed_payload
        .gpu_nonce_hex
        .eq_ignore_ascii_case(&expected_gpu_nonce_hex)
        || !evidence
            .gpu_nonce_hex
            .eq_ignore_ascii_case(&expected_gpu_nonce_hex)
    {
        return Err(TeeError::VerificationFailed(
            "GPU attestation nonce does not cryptographically couple (prover_pk, cpu_nonce, spdm_session_transcript_hash) — two independent valid quotes rejected"
                .into(),
        ));
    }

    // 6. Cryptographic vendor X.509 chain & ECDSA P-384 GPU signature verification.
    if evidence.vendor_cert_chain_pem.len() < 3 {
        return Err(TeeError::VerificationFailed(
            "GPU vendor_cert_chain_pem must contain [GPU Leaf, Intermediate CA, Pinned Vendor Root CA]"
                .into(),
        ));
    }
    let mut der_certs = Vec::with_capacity(evidence.vendor_cert_chain_pem.len());
    for (idx, p) in evidence.vendor_cert_chain_pem.iter().enumerate() {
        let parsed = ::pem::parse(p).map_err(|e| {
            TeeError::VerificationFailed(format!("invalid GPU PEM cert[{idx}]: {e}"))
        })?;
        der_certs.push(parsed.into_contents());
    }
    let mut certs = Vec::with_capacity(der_certs.len());
    for (idx, der) in der_certs.iter().enumerate() {
        let (_, c) = X509Certificate::from_der(der).map_err(|e| {
            TeeError::VerificationFailed(format!("invalid GPU X.509[{idx}]: {e}"))
        })?;
        let nb = c.validity().not_before.timestamp();
        let na = c.validity().not_after.timestamp();
        if (now_unix_s as i64) < nb || (now_unix_s as i64) > na {
            return Err(TeeError::VerificationFailed(format!(
                "GPU cert[{idx}] expired or not yet valid at {now_unix_s}"
            )));
        }
        certs.push(c);
    }

    let root_der = der_certs.last().unwrap();
    let root_fp = hex::encode(Sha256::digest(root_der));
    if (policy.require_cryptographic_vendor_chain || !pinned_gpu_root_sha256_hex.is_empty())
        && !pinned_gpu_root_sha256_hex
            .iter()
            .any(|pin| pin.eq_ignore_ascii_case(&root_fp))
    {
        return Err(TeeError::VerificationFailed(format!(
            "GPU vendor root CA SHA-256 {root_fp} not in pinned GPU vendor trust roots"
        )));
    }
    let root_cert = certs.last().unwrap();
    if root_cert.issuer() != root_cert.subject() {
        return Err(TeeError::VerificationFailed(
            "GPU vendor root CA is not self-issued".into(),
        ));
    }
    verify_p384_x509_sig(root_cert, root_cert)?;
    for i in 0..certs.len() - 1 {
        if certs[i].issuer() != certs[i + 1].subject() {
            return Err(TeeError::VerificationFailed(format!(
                "GPU cert chain issuer mismatch at index {i}"
            )));
        }
        verify_p384_x509_sig(&certs[i], &certs[i + 1])?;
    }

    // Verify GPU leaf certificate public key matches declared `gpu_pubkey_hex` AND signed `raw_quote`.
    let leaf_spki_bytes = certs[0].public_key().subject_public_key.data.as_ref();
    let leaf_pk_hex = hex::encode(leaf_spki_bytes);
    if !leaf_pk_hex.eq_ignore_ascii_case(binding_gpu_pk)
        || !leaf_pk_hex.eq_ignore_ascii_case(&evidence.gpu_pubkey_hex)
    {
        return Err(TeeError::VerificationFailed(
            "GPU leaf certificate public key does not match bound gpu_pubkey_hex".into(),
        ));
    }
    let leaf_vk = P384VerifyingKey::from_sec1_bytes(leaf_spki_bytes)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid GPU leaf P-384 key: {e}")))?;
    let sig_bytes = B64_STD
        .decode(&evidence.gpu_signature_b64)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid gpu_signature_b64: {e}")))?;
    let sig = DerSignature::from_bytes(&sig_bytes)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid GPU ECDSA P-384 DER sig: {e}")))?;
    leaf_vk
        .verify(&raw_quote, &sig)
        .map_err(|e| TeeError::VerificationFailed(format!("GPU SPDM quote signature invalid: {e}")))?;

    // 7. Honest hardware locality classification: never overclaim physical PCIe/NVLink distance proofs!
    let (locality_proof_level, hardware_locality_established, locality_assumptions) =
        match signed_payload.channel_kind {
            GpuProtectedChannelKind::PcieIdeHardwareProtected => (
                GpuCpuLocalityProofLevel::HardwareRootedDirectAttach,
                true,
                vec![
                    "PCIe IDE / NVLink-C2C hardware-rooted channel relies on CPU & GPU silicon vendor root CAs not colluding.".into(),
                ],
            ),
            GpuProtectedChannelKind::PcieSpdmEncryptedBounceBuffer => (
                GpuCpuLocalityProofLevel::SpdmProtectedLocalChannelAssumedColocated,
                false,
                vec![
                    "LOCALITY ASSUMPTION: Available SPDM 1.2 encrypted PCIe/NVLink attestation cryptographically binds this CPU TEE session to this Confidential GPU over a protected channel, but does NOT independently distance-bound physical PCIe/NVLink interconnect length; physical CPU-GPU co-location within the same chassis/rack is assumed via the local PCIe bus and non-colluding CPU/GPU silicon vendors.".into(),
                    "EXECUTION BOUNDARY ASSUMPTION: Because standard NVIDIA CC GPUs execute CUDA kernels over encrypted bounce buffers without per-request GPU hardware output signing, binding THIS request & output to the local GPU relies on the measured local-only CPU TEE runtime digest forbidding remote upstreams and fallbacks.".into(),
                ],
            ),
        };

    Ok(VerifiedGpuBinding {
        gpu_vendor: signed_payload.gpu_vendor,
        gpu_model: signed_payload.gpu_model,
        gpu_uuid: signed_payload.gpu_uuid,
        gpu_pubkey_hex: leaf_pk_hex,
        spdm_report_hash_hex: actual_report_hash,
        spdm_session_transcript_hash_hex: signed_payload.spdm_session_transcript_hash_hex,
        protected_channel_id: signed_payload.protected_channel_id,
        channel_kind: signed_payload.channel_kind,
        root_ca_sha256_hex: root_fp,
        locality_proof_level,
        hardware_locality_established,
        locality_assumptions,
    })
}

// =============================================================================
// Physical Silicon GPU Fingerprinting / PUF Extension (Tee & Happel, arXiv:2605.01930v1)
//
// Motivation: NVIDIA Hopper/Blackwell Confidential Compute is NOT designed to resist
// invasive physical decapping (FIB / Laser Scanning Microscope) key extraction.
// A seeded physical silicon fingerprint (PUF) adds defense-in-depth against key-cloned
// software emulators — while explicitly surfacing the physics timing-headroom caveat
// (a 2.9 s PUF kernel with 1% jitter = 29 ms = ~4,347 km vacuum relay margin, so
// multi-second PUFs NEVER replace sub-ms BLAKE3-MAC speed-of-light distance bounding!).
// =============================================================================

/// Pluggable GPU physical fingerprinting / PUF algorithm families (supports multi-function
/// challenge diversity per Tee & Happel §5 so an adversary cannot pre-model one fixed kernel).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuPufAlgorithm {
    /// Parameterized cross-SM `atomicAdd` race-condition ordering fingerprint (Tee & Happel 2026 / Hohentanner 2025).
    AtomicAddSmRaceV1,
    /// Low-latency compute-API timing PUF (LockedApart / DrawnApart style, targeting < 5–20 ms runtime).
    LockedApartComputeTimingV1,
    /// Intrinsic SRAM / memory-bank contention error/timing PUF (G-PUF family).
    MemoryBankConflictV1,
    /// Custom or newly rotated challenge kernel family (prevents static modeling).
    Custom(String),
}

impl GpuPufAlgorithm {
    pub fn domain_label(&self) -> String {
        match self {
            GpuPufAlgorithm::AtomicAddSmRaceV1 => "atomic_add_sm_race_v1".into(),
            GpuPufAlgorithm::LockedApartComputeTimingV1 => "locked_apart_compute_timing_v1".into(),
            GpuPufAlgorithm::MemoryBankConflictV1 => "memory_bank_conflict_v1".into(),
            GpuPufAlgorithm::Custom(s) => format!("custom:{s}"),
        }
    }
}

/// Seeded GPU silicon fingerprint challenge response attached alongside SPDM attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuPhysicalFingerprintEvidence {
    pub algorithm: GpuPufAlgorithm,
    pub gpu_uuid: String,
    /// Deterministic unpredictable challenge seed = `compute_gpu_puf_challenge_seed(prover_pk, epoch_challenge, algorithm)`.
    pub challenge_seed_hex: String,
    /// One or more fingerprint measurement vectors collected on the live GPU (paired runs = 2 vectors
    /// per Tee & Happel §4.2, achieving 100% re-identification accuracy in H200 evaluation).
    pub run_vectors: Vec<Vec<i64>>,
    /// Wall-clock kernel execution duration (ms) for a single fingerprint run (e.g., ~2,900 ms for
    /// arXiv:2605.01930v1 vs. ~2–10 ms for low-latency compute PUFs).
    pub measured_compute_ms: f64,
    /// Conservative compute-time jitter / overclocking margin (ms) that an adversary could shave
    /// off via optimization or clock boosting to hide network transit latency.
    pub max_compute_jitter_ms: f64,
    pub generated_at_unix_s: u64,
}

/// Pre-deployment factory/registration reference set for a specific physical GPU and challenge seed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuFingerprintReference {
    pub gpu_uuid: String,
    pub algorithm: GpuPufAlgorithm,
    pub challenge_seed_hex: String,
    /// Multiple reference runs captured during trusted registration (e.g., 8 runs per Tee & Happel §4.2).
    pub registered_vectors: Vec<Vec<i64>>,
    /// Maximum acceptable L1 distance between a live verification run and the closest registered vector.
    pub max_l1_distance: f64,
}

/// Authoritative verification report for a GPU physical silicon fingerprint (PUF).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedGpuFingerprint {
    pub matched_gpu_uuid: String,
    pub algorithm: GpuPufAlgorithm,
    pub best_l1_distance: f64,
    pub paired_runs_used: usize,
    /// Vacuum light-travel radius (km) an attacker could hide inside `max_compute_jitter_ms`:
    /// `0.5 * c_0 * max_compute_jitter_ms * 1e-3`.
    pub puf_timing_relay_headroom_km: f64,
    /// True ONLY when both compute time (`<= 25 ms`) and jitter headroom (`<= 500 km`) are tight
    /// enough to physically resist remote-GPU relay; false for multi-second PUFs (e.g., 2.9 s),
    /// which still raise anti-emulation cost against key extraction when paired with sub-ms UDP PoG.
    pub bounds_physical_relay_alone: bool,
    pub security_notes: Vec<String>,
}

/// Compute the deterministic unpredictable challenge seed binding a GPU PUF challenge to
/// THIS Prover key, THIS epoch challenge, and THIS specific PUF algorithm family.
pub fn compute_gpu_puf_challenge_seed(
    prover_public_key: &[u8; 32],
    epoch_challenge: &[u8],
    algorithm: &GpuPufAlgorithm,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"pog-gpu-puf-v1");
    h.update(prover_public_key);
    h.update(epoch_challenge);
    h.update(algorithm.domain_label().as_bytes());
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

fn l1_distance(a: &[i64], b: &[i64]) -> Option<f64> {
    if a.is_empty() || a.len() != b.len() {
        return None;
    }
    let sum: f64 = a
        .iter()
        .zip(b.iter())
        .map(|(&x, &y)| ((x as i128) - (y as i128)).unsigned_abs() as f64)
        .sum();
    Some(sum)
}

/// Verify a live GPU physical silicon fingerprint against pre-deployment registration references:
/// 1. Enforces fresh unpredictable seed binding (`compute_gpu_puf_challenge_seed`) — blocks static replay!
/// 2. Evaluates L1 distance across all live runs (supports paired-run best-match per Tee & Happel §4.2)
///    against ALL candidate registered GPUs so another chip cannot impersonate `evidence.gpu_uuid`.
/// 3. Computes `puf_timing_relay_headroom_km` explicitly so verifiers never mistake a 2.9 s PUF
///    for a sub-millisecond speed-of-light distance bound!
pub fn verify_gpu_physical_fingerprint(
    evidence: &GpuPhysicalFingerprintEvidence,
    reference_set: &[GpuFingerprintReference],
    prover_public_key: &[u8; 32],
    epoch_challenge: &[u8],
) -> Result<VerifiedGpuFingerprint, TeeError> {
    if evidence.run_vectors.is_empty() {
        return Err(TeeError::VerificationFailed(
            "GPU PUF evidence contains zero run_vectors".into(),
        ));
    }
    if reference_set.is_empty() {
        return Err(TeeError::VerificationFailed(
            "GPU PUF reference_set is empty (fail-closed)".into(),
        ));
    }
    let expected_seed = hex::encode(compute_gpu_puf_challenge_seed(
        prover_public_key,
        epoch_challenge,
        &evidence.algorithm,
    ));
    if !evidence
        .challenge_seed_hex
        .eq_ignore_ascii_case(&expected_seed)
    {
        return Err(TeeError::VerificationFailed(
            "GPU PUF challenge_seed_hex does not match fresh epoch/prover binding (replay rejected)"
                .into(),
        ));
    }

    let mut best_overall: Option<(&GpuFingerprintReference, f64)> = None;
    let mut target_ref_found = false;

    for r in reference_set {
        if r.algorithm != evidence.algorithm
            || !r.challenge_seed_hex.eq_ignore_ascii_case(&expected_seed)
        {
            continue;
        }
        if r.gpu_uuid == evidence.gpu_uuid {
            target_ref_found = true;
        }
        for live_vec in &evidence.run_vectors {
            for reg_vec in &r.registered_vectors {
                if let Some(d) = l1_distance(live_vec, reg_vec) {
                    if best_overall.map(|(_, bd)| d < bd).unwrap_or(true) {
                        best_overall = Some((r, d));
                    }
                }
            }
        }
    }

    if !target_ref_found {
        return Err(TeeError::VerificationFailed(format!(
            "No registered GPU PUF reference found for gpu_uuid={} algorithm={} and fresh seed",
            evidence.gpu_uuid,
            evidence.algorithm.domain_label()
        )));
    }

    let (best_ref, best_dist) = best_overall.ok_or_else(|| {
        TeeError::VerificationFailed("GPU PUF vector dimension mismatch against references".into())
    })?;

    if best_ref.gpu_uuid != evidence.gpu_uuid {
        return Err(TeeError::VerificationFailed(format!(
            "GPU PUF re-identification mismatch: claimed {} but closest silicon match is {} (L1={:.1})",
            evidence.gpu_uuid, best_ref.gpu_uuid, best_dist
        )));
    }
    if best_dist > best_ref.max_l1_distance {
        return Err(TeeError::VerificationFailed(format!(
            "GPU PUF L1 distance {:.1} exceeds threshold {:.1} for {}",
            best_dist, best_ref.max_l1_distance, evidence.gpu_uuid
        )));
    }

    const C0_KM_PER_S: f64 = 299_792.458;
    let jitter_ms = evidence.max_compute_jitter_ms.max(0.0);
    let relay_headroom_km = 0.5 * C0_KM_PER_S * (jitter_ms * 1e-3);
    let bounds_physical_relay_alone =
        evidence.measured_compute_ms <= 25.0 && relay_headroom_km <= 500.0;

    let mut security_notes = Vec::new();
    if !bounds_physical_relay_alone {
        security_notes.push(format!(
            "PUF TIMING CAVEAT: compute={:.1} ms / jitter={:.1} ms allows up to {:.0} km vacuum relay headroom — raises anti-emulation cost against FIB/LSM key extraction, but MUST stay decoupled from sub-ms UDP BLAKE3-MAC speed-of-light distance bounding!",
            evidence.measured_compute_ms, jitter_ms, relay_headroom_km
        ));
    } else {
        security_notes.push(format!(
            "Low-latency GPU PUF ({:.2} ms compute, {:.2} ms jitter -> {:.1} km vacuum headroom) strengthens physical anti-relay resistance alongside SPDM + UDP distance bounding.",
            evidence.measured_compute_ms, jitter_ms, relay_headroom_km
        ));
    }

    Ok(VerifiedGpuFingerprint {
        matched_gpu_uuid: best_ref.gpu_uuid.clone(),
        algorithm: evidence.algorithm.clone(),
        best_l1_distance: best_dist,
        paired_runs_used: evidence.run_vectors.len(),
        puf_timing_relay_headroom_km: relay_headroom_km,
        bounds_physical_relay_alone,
        security_notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p384::ecdsa::signature::Signer as P384Signer;
    use p384::ecdsa::{DerSignature as P384DerSig, SigningKey as P384SigningKey};
    use p384::pkcs8::DecodePrivateKey;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, PKCS_ECDSA_P384_SHA384};

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn make_signed_gpu_binding(
        prover_pk: &[u8; 32],
        cpu_nonce: &[u8],
        gpu_uuid: &str,
        transcript_hex: &str,
        override_gpu_nonce_hex: Option<String>,
        cc_mode: bool,
        debug_disabled: bool,
        now: u64,
    ) -> (GpuAttestationBinding, String) {
        let mut root_p = CertificateParams::default();
        root_p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_p.distinguished_name.push(DnType::CommonName, "Test-GPU-Root-CA");
        let root_kp = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let root_c = root_p.self_signed(&root_kp).unwrap();
        let root_fp = hex::encode(Sha256::digest(root_c.der().as_ref()));

        let mut int_p = CertificateParams::default();
        int_p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        int_p.distinguished_name.push(DnType::CommonName, "Test-GPU-Device-CA");
        let int_kp = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let int_c = int_p.signed_by(&int_kp, &root_c, &root_kp).unwrap();

        let mut leaf_p = CertificateParams::default();
        leaf_p.distinguished_name.push(DnType::CommonName, gpu_uuid);
        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let leaf_c = leaf_p.signed_by(&leaf_kp, &int_c, &int_kp).unwrap();

        let (_, parsed_leaf) = X509Certificate::from_der(leaf_c.der().as_ref()).unwrap();
        let gpu_pk_hex = hex::encode(parsed_leaf.public_key().subject_public_key.data.as_ref());

        let gpu_nonce_hex = override_gpu_nonce_hex.unwrap_or_else(|| {
            hex::encode(compute_gpu_binding_nonce(prover_pk, cpu_nonce, transcript_hex))
        });
        let payload = SignedGpuSpdmQuotePayload {
            gpu_vendor: "nvidia-cc".into(),
            gpu_model: "NVIDIA H100 80GB SXM5 Confidential".into(),
            gpu_uuid: gpu_uuid.into(),
            gpu_nonce_hex: gpu_nonce_hex.clone(),
            spdm_session_transcript_hash_hex: transcript_hex.into(),
            protected_channel_id: "spdm-pcie-0000:81:00.0-sess-1".into(),
            channel_kind: GpuProtectedChannelKind::PcieSpdmEncryptedBounceBuffer,
            cc_mode_enabled: cc_mode,
            debug_disabled,
            driver_measurement_hex: "dd".repeat(32),
            vbios_measurement_hex: "ee".repeat(32),
            generated_at_unix_s: now,
        };
        let raw_bytes = serde_json::to_vec(&payload).unwrap();
        let report_hash_hex = hex::encode(Sha256::digest(&raw_bytes));

        let leaf_sk = P384SigningKey::from_pkcs8_der(leaf_kp.serialize_der().as_ref()).unwrap();
        let sig: P384DerSig = leaf_sk.sign(&raw_bytes);

        let ev = GpuAttestationEvidence {
            gpu_vendor: payload.gpu_vendor,
            gpu_model: payload.gpu_model.clone(),
            gpu_uuid: payload.gpu_uuid.clone(),
            gpu_pubkey_hex: gpu_pk_hex.clone(),
            gpu_nonce_hex,
            cc_mode_enabled: cc_mode,
            debug_disabled,
            driver_measurement_hex: payload.driver_measurement_hex.clone(),
            vbios_measurement_hex: payload.vbios_measurement_hex,
            channel_kind: payload.channel_kind,
            protected_channel_id: payload.protected_channel_id.clone(),
            spdm_session_transcript_hash_hex: transcript_hex.into(),
            raw_spdm_quote_b64: B64_STD.encode(&raw_bytes),
            gpu_signature_b64: B64_STD.encode(sig.as_bytes()),
            vendor_cert_chain_pem: vec![leaf_c.pem(), int_c.pem(), root_c.pem()],
            generated_at_unix_s: now,
        };
        let binding = GpuAttestationBinding {
            gpu_model: payload.gpu_model,
            gpu_uuid: gpu_uuid.into(),
            spdm_report_hash_hex: report_hash_hex,
            driver_measurement_hex: payload.driver_measurement_hex,
            gpu_pubkey_hex: Some(gpu_pk_hex),
            spdm_session_transcript_hash_hex: Some(transcript_hex.into()),
            protected_channel_id: Some(payload.protected_channel_id),
            evidence: Some(ev),
            physical_fingerprint: None,
        };
        (binding, root_fp)
    }

    #[test]
    fn test_gpu_binding_rejects_independent_quotes_bare_uuid_and_debug_mode() {
        let now = 1_795_760_000u64;
        let prover_pk = [0x33u8; 32];
        let cpu_nonce = [0x44u8; 32];
        let transcript = "aa".repeat(32);
        let pol = AttestationPolicy::production();

        // 1. Valid mutually coupled GPU SPDM binding PASSES and explicitly reports SPDM locality assumption!
        let (good, root_fp) = make_signed_gpu_binding(&prover_pk, &cpu_nonce, "GPU-LOCAL-01", &transcript, None, true, true, now);
        let verified = verify_gpu_attestation_evidence(&good, &prover_pk, &cpu_nonce, &pol, now + 5, &[&root_fp]).unwrap();
        assert_eq!(verified.locality_proof_level, GpuCpuLocalityProofLevel::SpdmProtectedLocalChannelAssumedColocated);
        assert!(!verified.hardware_locality_established);
        assert!(!verified.locality_assumptions.is_empty());

        // 2. Two independent valid quotes (valid GPU quote signed for a DIFFERENT nonce!) MUST FAIL!
        let (indep, indep_fp) = make_signed_gpu_binding(
            &prover_pk,
            &cpu_nonce,
            "GPU-REMOTE-99",
            &transcript,
            Some("99".repeat(32)),
            true,
            true,
            now,
        );
        let err = verify_gpu_attestation_evidence(&indep, &prover_pk, &cpu_nonce, &pol, now + 5, &[&indep_fp]).unwrap_err();
        assert!(err.to_string().contains("two independent valid quotes rejected"), "got: {err}");

        // 3. Bare quoted GPU ID (evidence = None) MUST FAIL!
        let mut bare = good.clone();
        bare.evidence = None;
        let err_bare = verify_gpu_attestation_evidence(&bare, &prover_pk, &cpu_nonce, &pol, now + 5, &[&root_fp]).unwrap_err();
        assert!(err_bare.to_string().contains("bare quoted GPU ID rejected"), "got: {err_bare}");

        // 4. Unpinned root CA MUST FAIL!
        assert!(verify_gpu_attestation_evidence(&good, &prover_pk, &cpu_nonce, &pol, now + 5, &["00".repeat(32).as_str()]).is_err());

        // 5. Non-CC mode or Debug mode MUST FAIL!
        let (no_cc, fp1) = make_signed_gpu_binding(&prover_pk, &cpu_nonce, "GPU-NOCC", &transcript, None, false, true, now);
        assert!(verify_gpu_attestation_evidence(&no_cc, &prover_pk, &cpu_nonce, &pol, now + 5, &[&fp1]).is_err());
        let (dbg_gpu, fp2) = make_signed_gpu_binding(&prover_pk, &cpu_nonce, "GPU-DBG", &transcript, None, true, false, now);
        assert!(verify_gpu_attestation_evidence(&dbg_gpu, &prover_pk, &cpu_nonce, &pol, now + 5, &[&fp2]).is_err());
    }

    #[test]
    fn test_gpu_puf_reidentification_paired_runs_and_2900ms_relay_headroom_warning() {
        let prover_pk = [0x55u8; 32];
        let epoch = b"epoch-puf-2026-11-28";
        let seed_atomic = hex::encode(compute_gpu_puf_challenge_seed(
            &prover_pk,
            epoch,
            &GpuPufAlgorithm::AtomicAddSmRaceV1,
        ));
        let seed_fast = hex::encode(compute_gpu_puf_challenge_seed(
            &prover_pk,
            epoch,
            &GpuPufAlgorithm::LockedApartComputeTimingV1,
        ));

        let refs = vec![
            GpuFingerprintReference {
                gpu_uuid: "GPU-H200-A".into(),
                algorithm: GpuPufAlgorithm::AtomicAddSmRaceV1,
                challenge_seed_hex: seed_atomic.clone(),
                registered_vectors: vec![vec![10, 42, 108, 7, 91], vec![11, 41, 109, 8, 90]],
                max_l1_distance: 25.0,
            },
            GpuFingerprintReference {
                gpu_uuid: "GPU-H200-B".into(),
                algorithm: GpuPufAlgorithm::AtomicAddSmRaceV1,
                challenge_seed_hex: seed_atomic.clone(),
                registered_vectors: vec![vec![90, 12, 30, 88, 14]],
                max_l1_distance: 25.0,
            },
            GpuFingerprintReference {
                gpu_uuid: "GPU-H200-A".into(),
                algorithm: GpuPufAlgorithm::LockedApartComputeTimingV1,
                challenge_seed_hex: seed_fast.clone(),
                registered_vectors: vec![vec![500, 512, 495, 508]],
                max_l1_distance: 20.0,
            },
        ];

        // 1. Paired verification runs (one noisy outlier + one clean match, Tee & Happel §4.2) on 2.9s PUF:
        //    PASSES re-identification AND explicitly warns about ~4,347 km relay headroom!
        let ev_2900ms = GpuPhysicalFingerprintEvidence {
            algorithm: GpuPufAlgorithm::AtomicAddSmRaceV1,
            gpu_uuid: "GPU-H200-A".into(),
            challenge_seed_hex: seed_atomic.clone(),
            run_vectors: vec![vec![50, 90, 10, 80, 10], vec![12, 43, 107, 7, 92]],
            measured_compute_ms: 2900.0,
            max_compute_jitter_ms: 29.0, // 1% timing jitter on 2.9s kernel!
            generated_at_unix_s: 1_795_800_000,
        };
        let v_slow = verify_gpu_physical_fingerprint(&ev_2900ms, &refs, &prover_pk, epoch).unwrap();
        assert_eq!(v_slow.matched_gpu_uuid, "GPU-H200-A");
        assert_eq!(v_slow.paired_runs_used, 2);
        assert!(v_slow.best_l1_distance <= 10.0);
        assert!(v_slow.puf_timing_relay_headroom_km > 4_300.0);
        assert!(!v_slow.bounds_physical_relay_alone);

        // 2. Wrong GPU (GPU-H200-B vector claiming GPU-H200-A) MUST FAIL!
        let ev_impersonator = GpuPhysicalFingerprintEvidence {
            run_vectors: vec![vec![91, 13, 29, 89, 15]],
            ..ev_2900ms.clone()
        };
        assert!(verify_gpu_physical_fingerprint(&ev_impersonator, &refs, &prover_pk, epoch).is_err());

        // 3. Stale/replayed seed MUST FAIL!
        let ev_replay = GpuPhysicalFingerprintEvidence {
            challenge_seed_hex: "00".repeat(32),
            ..ev_2900ms
        };
        assert!(verify_gpu_physical_fingerprint(&ev_replay, &refs, &prover_pk, epoch).is_err());

        // 4. Low-latency PUF (3.0 ms compute, 0.5 ms jitter -> ~75 km headroom) qualifies as relay-bounding!
        let ev_fast = GpuPhysicalFingerprintEvidence {
            algorithm: GpuPufAlgorithm::LockedApartComputeTimingV1,
            gpu_uuid: "GPU-H200-A".into(),
            challenge_seed_hex: seed_fast,
            run_vectors: vec![vec![501, 511, 496, 509]],
            measured_compute_ms: 3.0,
            max_compute_jitter_ms: 0.5,
            generated_at_unix_s: 1_795_800_000,
        };
        let v_fast = verify_gpu_physical_fingerprint(&ev_fast, &refs, &prover_pk, epoch).unwrap();
        assert!(v_fast.bounds_physical_relay_alone);
        assert!(v_fast.puf_timing_relay_headroom_km < 100.0);
    }
}
