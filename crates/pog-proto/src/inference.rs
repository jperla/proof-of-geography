//! Separate Confidential-GPU Inference-Location Claim & Fail-Closed Verifier.
//!
//! Strictly separates two claims that MUST NEVER be conflated:
//! 1. `ProverOnlyGeography` (`GeoProofBundle` / `X-PoG-Proof` / `--upstream` proxy mode):
//!    Proves where the Prover TEE/proxy sits — does NOT prove where a remote inference ran.
//!    The current `X-PoG-Proof` header alone NEVER establishes `ConfidentialGpuInferenceLocation`.
//! 2. `ConfidentialGpuInferenceLocation` (`ConfidentialInferenceReceipt` carrying the signed PoG
//!    proof bundle or its signed digest + exact verifiable bundle):
//!    Proves THIS specific calculation (`request_nonce`, `model_id`, `request_hash`, `output_hash`)
//!    executed on the EXACT SAME locally bound, attested Confidential GPU attached to the located
//!    Prover TEE over a protected channel, by a measured local-only runtime with NO remote upstream
//!    and NO fallback, bound to the EXACT end-to-end client-to-attested-runtime TLS 1.3 session
//!    (via RFC 8446 §7.5 Exported Keying Material + per-connection request sequence), with the
//!    signed receipt issued strictly AFTER execution completed.
//!
//! Note on PoG challenge transport:
//! - The distance-bounding PoG challenge itself does NOT need to travel over the client's TLS
//!   session; it continues out-of-band against the multi-cloud Anchors. The signed per-inference
//!   receipt embeds the exact `GeoProofBundle` (or signs its digest paired with the exact bundle)
//!   and cryptographically binds that verified prover identity & location evidence to this exact
//!   TLS session, bound local GPU, request, and output.
//!
//! Explicitly rejects (fail-closed):
//! - Missing or mismatched end-to-end TLS 1.3 session EKM binding (defeats reused cert & proxy TLS hop!)
//! - Replayed or swapped receipts across two requests sharing ONE keep-alive TLS 1.3 connection
//! - Missing or mismatched embedded/supplied `GeoProofBundle` vs signed `location_bundle_hash_hex`
//! - Attempting to derive the stronger inference-location claim from the legacy `X-PoG-Proof` header alone
//! - Two independent valid quotes (CPU TEE quote + uncoupled GPU quote)
//! - A bare quoted GPU ID without full vendor-verified GPU SPDM evidence
//! - A proxy signature on forwarded output (`ProxyForwarded` / `remote_upstream_disabled == false` /
//!   unmeasured runtime digest)
//! - Stale/replayed request nonces, tampered request/output bytes, pre-execution timestamps,
//!   GPU/channel swaps between location proof and execution receipt, or `SoftwareDev` fallbacks.

use crate::bundle::{
    verify_proof_bundle, GeoProofBundle, ProofVerificationReport, VerificationPolicy,
};
use crate::committee::AnchorGrid;
use crate::wire::ProtoError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use base64::Engine;
use pog_tee::{
    verify_gpu_attestation_evidence, GpuCpuLocalityProofLevel, VerifiedGpuBinding, WorkloadKeypair,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// HTTP header declaring which claim a Prover endpoint is making (never conflate proxy vs local GPU).
pub const HTTP_HEADER_POG_CLAIM_MODE: &str = "X-PoG-Claim-Mode";
/// HTTP header carrying a base64url-encoded `ConfidentialInferenceReceipt` (ONLY in measured local-GPU mode).
pub const HTTP_HEADER_POG_INFERENCE_RECEIPT: &str = "X-PoG-Inference-Receipt";
/// Claim mode header value for reverse-proxy / prover-only geography.
pub const CLAIM_MODE_PROVER_ONLY: &str = "prover-only-geography";
/// Claim mode header value for verified confidential-GPU inference location.
pub const CLAIM_MODE_CONFIDENTIAL_GPU_INFERENCE: &str = "confidential-gpu-inference-location";
/// Canonical RFC 5705 / RFC 8446 §7.5 TLS 1.3 exporter label binding the exact end-to-end client
/// <-> attested-runtime TLS session carrying an inference request.
pub const TLS_EXPORTER_LABEL: &str = "EXPORTER-pog-inference-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceClaimType {
    ProverOnlyGeography,
    ConfidentialGpuInferenceLocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceExecutionMode {
    /// Measured runtime executing strictly on its locally bound, attested Confidential GPU over a
    /// protected channel with ZERO remote upstream and ZERO fallback.
    LocalBoundConfidentialGpuOnly,
    /// Reverse proxy forwarding to an upstream server — prover-only geography, NEVER valid for
    /// `ConfidentialGpuInferenceLocation`.
    ProxyForwarded,
}

/// Cryptographic binding to the EXACT end-to-end client-to-attested-runtime TLS 1.3 session that
/// carried this inference request — NOT merely a reused server certificate or an edge proxy TLS hop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsSessionBinding {
    /// Must be `"TLSv1.3"`.
    pub tls_protocol_version: String,
    /// Must equal `TLS_EXPORTER_LABEL` (`"EXPORTER-pog-inference-v1"`).
    pub exporter_label: String,
    /// 32-byte (64 lowercase hex) RFC 8446 §7.5 Exported Keying Material derived from the live
    /// end-to-end TLS 1.3 handshake between client and measured attested runtime.
    /// - Reusing the same server certificate on a second TLS handshake produces a DIFFERENT EKM.
    /// - Terminating TLS at an intermediate proxy produces a DIFFERENT EKM on the client↔proxy hop
    ///   vs. the proxy↔runtime hop.
    pub tls_exporter_ekm_hex: String,
    /// SHA-256 hex (64 hex) of the attested runtime's leaf TLS certificate presented on this session.
    pub server_cert_sha256_hex: String,
    /// Ed25519 signature by the attested runtime's `prover_pk` over `compute_tls_cert_binding_message`
    /// proving that the leaf TLS certificate belongs to this hardware-attested Prover TEE key.
    pub cert_prover_binding_sig_hex: String,
    /// Must be `true` — rejects proxy-terminated TLS hops!
    pub terminated_in_attested_runtime: bool,
    /// Monotonic per-TLS-connection request sequence (`>= 1`), ensuring two requests carried over
    /// ONE keep-alive TLS 1.3 session have distinct per-request binding contexts.
    pub tls_connection_request_seq: u64,
}

/// Canonical message signed by the Prover TEE key to bind its RA-TLS / ephemeral TLS leaf cert.
pub fn compute_tls_cert_binding_message(server_cert_sha256_hex: &str) -> Vec<u8> {
    format!(
        "POG_RA_TLS_CERT_V1\n{}\n",
        server_cert_sha256_hex.trim().to_ascii_lowercase()
    )
    .into_bytes()
}

/// Sign a TLS leaf certificate SHA-256 fingerprint using the attested runtime's `WorkloadKeypair`.
pub fn sign_tls_cert_binding(kp: &WorkloadKeypair, server_cert_sha256_hex: &str) -> String {
    hex::encode(kp.sign(&compute_tls_cert_binding_message(server_cert_sha256_hex)))
}

/// Verify that `server_cert_sha256_hex` is cryptographically bound to `expected_prover_pk_hex`.
pub fn verify_tls_cert_binding(
    expected_prover_pk_hex: &str,
    server_cert_sha256_hex: &str,
    cert_prover_binding_sig_hex: &str,
) -> Result<(), ProtoError> {
    let sig_bytes = hex::decode(cert_prover_binding_sig_hex.trim())
        .map_err(|e| ProtoError::SignatureError(format!("bad TLS cert binding sig hex: {e}")))?;
    WorkloadKeypair::verify_with_hex(
        expected_prover_pk_hex,
        &compute_tls_cert_binding_message(server_cert_sha256_hex),
        &sig_bytes,
    )
    .map_err(|e| {
        ProtoError::SignatureError(format!(
            "TLS leaf certificate is not cryptographically bound to prover_pk: {e}"
        ))
    })
}

/// Canonical SHA-256 request commitment binding the caller's fresh nonce, model ID, and exact request bytes.
pub fn compute_inference_request_hash(
    request_nonce_hex: &str,
    model_id: &str,
    request_bytes: &[u8],
) -> String {
    let mut h = Sha256::new();
    h.update(b"pog-inf-req-v1\n");
    h.update(request_nonce_hex.trim().to_ascii_lowercase().as_bytes());
    h.update(b"\n");
    h.update(model_id.as_bytes());
    h.update(b"\n");
    h.update(request_bytes);
    hex::encode(h.finalize())
}

/// Canonical SHA-256 output commitment chained to `request_hash_hex` and exact output bytes.
pub fn compute_inference_output_hash(request_hash_hex: &str, output_bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"pog-inf-out-v1\n");
    h.update(request_hash_hex.trim().to_ascii_lowercase().as_bytes());
    h.update(b"\n");
    h.update(output_bytes);
    hex::encode(h.finalize())
}

/// Canonical SHA-256 execution transcript digest tying the active protected SPDM GPU channel,
/// GPU UUID, monotonic GPU channel sequence, end-to-end TLS 1.3 session EKM, per-connection TLS
/// request sequence, request hash, and completed output hash.
#[allow(clippy::too_many_arguments)]
pub fn compute_gpu_execution_digest(
    spdm_session_transcript_hash_hex: &str,
    gpu_uuid: &str,
    protected_channel_id: &str,
    channel_seq_no: u64,
    tls_exporter_ekm_hex: &str,
    tls_connection_request_seq: u64,
    request_hash_hex: &str,
    output_hash_hex: &str,
) -> String {
    let mut h = Sha256::new();
    h.update(b"pog-gpu-exec-v2\n");
    h.update(
        spdm_session_transcript_hash_hex
            .trim()
            .to_ascii_lowercase()
            .as_bytes(),
    );
    h.update(b"\n");
    h.update(gpu_uuid.as_bytes());
    h.update(b"\n");
    h.update(protected_channel_id.as_bytes());
    h.update(b"\n");
    h.update(channel_seq_no.to_le_bytes());
    h.update(b"\n");
    h.update(
        tls_exporter_ekm_hex
            .trim()
            .to_ascii_lowercase()
            .as_bytes(),
    );
    h.update(b"\n");
    h.update(tls_connection_request_seq.to_le_bytes());
    h.update(b"\n");
    h.update(request_hash_hex.trim().to_ascii_lowercase().as_bytes());
    h.update(b"\n");
    h.update(output_hash_hex.trim().to_ascii_lowercase().as_bytes());
    hex::encode(h.finalize())
}

/// Post-execution signed receipt tying THIS request and output to:
/// - the end-to-end client↔attested-runtime TLS 1.3 session (`tls_session_binding`),
/// - the Prover TEE's non-exportable signing key & measured local-only runtime digest,
/// - the locally bound, attested Confidential GPU & active protected SPDM channel, and
/// - the exact independently verifiable PoG `GeoProofBundle` (embedded directly in `pog_proof_bundle`
///   AND cryptographically committed via signed `location_bundle_hash_hex` + `location_epoch_challenge_hex`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialInferenceReceipt {
    pub version: u8,
    pub claim_type: InferenceClaimType,
    pub execution_mode: InferenceExecutionMode,
    /// Must be `true` — measured runtime forbids any remote HTTP/gRPC upstream for this claim.
    pub remote_upstream_disabled: bool,
    /// Must be `true` — measured runtime forbids CPU/unattested/remote fallback for this claim.
    pub fallback_disabled: bool,
    pub request_nonce_hex: String,
    pub model_id: String,
    pub request_hash_hex: String,
    pub output_hash_hex: String,
    pub prover_pk_hex: String,
    pub runtime_measurement_hex: String,
    pub gpu_uuid: String,
    pub gpu_pubkey_hex: String,
    pub spdm_report_hash_hex: String,
    pub spdm_session_transcript_hash_hex: String,
    pub protected_channel_id: String,
    pub channel_seq_no: u64,
    pub gpu_execution_digest_hex: String,
    pub execution_started_at_unix_s: u64,
    pub execution_completed_at_unix_s: u64,
    /// End-to-end TLS 1.3 session binding for the exact connection carrying THIS inference request.
    /// `Option` solely so malformed/legacy payloads missing it deserialize and fail closed cleanly.
    #[serde(default)]
    pub tls_session_binding: Option<TlsSessionBinding>,
    /// BLAKE3 hex digest (`GeoProofBundle::record_hash_hex()`) signed inside `prover_signature_hex`.
    pub location_bundle_hash_hex: String,
    /// Out-of-band PoG `epoch_challenge_hex` signed inside `prover_signature_hex`.
    pub location_epoch_challenge_hex: String,
    /// Optional embedded independently verifiable `GeoProofBundle` directly inside the receipt!
    /// Its `record_hash_hex()` MUST equal the signed `location_bundle_hash_hex`.
    /// When omitted, the caller MUST supply the exact matching `GeoProofBundle` alongside the receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pog_proof_bundle: Option<GeoProofBundle>,
    pub prover_signature_hex: String,
}

impl ConfidentialInferenceReceipt {
    pub fn signing_payload(&self) -> Vec<u8> {
        let tls_part = match &self.tls_session_binding {
            Some(t) => format!(
                "{}\n{}\n{}\n{}\n{}\n{}\n{}",
                t.tls_protocol_version,
                t.exporter_label,
                t.tls_exporter_ekm_hex.trim().to_ascii_lowercase(),
                t.server_cert_sha256_hex.trim().to_ascii_lowercase(),
                t.cert_prover_binding_sig_hex.trim().to_ascii_lowercase(),
                t.terminated_in_attested_runtime,
                t.tls_connection_request_seq,
            ),
            None => "MISSING_TLS_SESSION_BINDING".to_string(),
        };
        format!(
            "CONFIDENTIAL_INFERENCE_RECEIPT_V2\n{}\n{:?}\n{:?}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            self.version,
            self.claim_type,
            self.execution_mode,
            self.remote_upstream_disabled,
            self.fallback_disabled,
            self.request_nonce_hex.trim().to_ascii_lowercase(),
            self.model_id,
            self.request_hash_hex.trim().to_ascii_lowercase(),
            self.output_hash_hex.trim().to_ascii_lowercase(),
            self.prover_pk_hex.trim().to_ascii_lowercase(),
            self.runtime_measurement_hex.trim().to_ascii_lowercase(),
            self.gpu_uuid,
            self.gpu_pubkey_hex.trim().to_ascii_lowercase(),
            self.spdm_report_hash_hex.trim().to_ascii_lowercase(),
            self.spdm_session_transcript_hash_hex.trim().to_ascii_lowercase(),
            self.protected_channel_id,
            self.channel_seq_no,
            self.gpu_execution_digest_hex.trim().to_ascii_lowercase(),
            self.execution_started_at_unix_s,
            self.execution_completed_at_unix_s,
            tls_part,
            self.location_bundle_hash_hex.trim().to_ascii_lowercase(),
            self.location_epoch_challenge_hex.trim().to_ascii_lowercase(),
        )
        .into_bytes()
    }

    pub fn sign(&mut self, kp: &WorkloadKeypair) {
        let sig = kp.sign(&self.signing_payload());
        self.prover_signature_hex = hex::encode(sig);
    }

    pub fn verify_signature(&self, expected_prover_pk_hex: &str) -> Result<(), ProtoError> {
        let sig_bytes = hex::decode(self.prover_signature_hex.trim()).map_err(|e| {
            ProtoError::SignatureError(format!("bad inference receipt sig hex: {e}"))
        })?;
        WorkloadKeypair::verify_with_hex(expected_prover_pk_hex, &self.signing_payload(), &sig_bytes)
            .map_err(|e| {
                ProtoError::SignatureError(format!("inference receipt Ed25519 sig invalid: {e}"))
            })
    }

    pub fn to_header_value(&self) -> Result<String, ProtoError> {
        let json = serde_json::to_vec(self)
            .map_err(|e| ProtoError::SerializationError(e.to_string()))?;
        Ok(B64_URL.encode(&json))
    }

    pub fn from_header_value(val: &str) -> Result<Self, ProtoError> {
        let raw = B64_URL
            .decode(val.trim())
            .map_err(|e| ProtoError::SerializationError(e.to_string()))?;
        serde_json::from_slice(&raw).map_err(|e| ProtoError::SerializationError(e.to_string()))
    }
}

/// Client-observed context for THIS specific inference request and the exact end-to-end TLS 1.3
/// session over which the client sent the request and received the output.
#[derive(Debug, Clone)]
pub struct ExpectedInferenceRequest<'a> {
    /// Fresh per-request caller nonce (>= 16 random bytes / 32 hex chars).
    pub request_nonce_hex: &'a str,
    pub model_id: &'a str,
    pub request_bytes: &'a [u8],
    pub output_bytes: &'a [u8],
    /// 64-hex (32 bytes) RFC 8446 §7.5 EKM exported by the client directly from the exact TLS 1.3
    /// connection that carried THIS request (using `TLS_EXPORTER_LABEL`).
    pub tls_exporter_ekm_hex: &'a str,
    /// 64-hex SHA-256 of the leaf TLS certificate presented by the server on THIS TLS 1.3 connection.
    pub server_cert_sha256_hex: &'a str,
    /// Optional exact per-TLS-connection request sequence expected by the client on a keep-alive
    /// TLS 1.3 connection (e.g., `Some(1)` for the first request, `Some(2)` for the second).
    pub expected_tls_connection_request_seq: Option<u64>,
}

/// Fail-closed policy governing the stronger `ConfidentialGpuInferenceLocation` claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceVerificationPolicy {
    pub geo_policy: VerificationPolicy,
    /// Allowlist of audited, measured local-only inference runtime measurements (no remote upstream/fallback).
    #[serde(default)]
    pub allowed_inference_runtime_measurements: Vec<String>,
    /// Fail closed unless `allowed_inference_runtime_measurements` is non-empty and matches the Prover TEE.
    #[serde(default = "default_true")]
    pub require_measured_inference_runtime: bool,
    /// Pinned GPU vendor Root CA DER SHA-256 hex digests (fail closed if empty in production).
    #[serde(default)]
    pub pinned_gpu_root_sha256_hex: Vec<String>,
    /// If true, reject SPDM-assumed-colocated channels and require hardware-rooted PCIe-IDE physical attach.
    #[serde(default)]
    pub require_hardware_rooted_locality: bool,
    /// Maximum age of a fresh post-execution inference receipt in seconds.
    #[serde(default = "default_receipt_age")]
    pub max_receipt_age_seconds: u64,
}

fn default_true() -> bool {
    true
}

fn default_receipt_age() -> u64 {
    300
}

impl InferenceVerificationPolicy {
    pub fn production(
        allowed_inference_runtime_measurements: Vec<String>,
        pinned_gpu_root_sha256_hex: Vec<String>,
    ) -> Self {
        Self {
            geo_policy: VerificationPolicy::default(),
            allowed_inference_runtime_measurements,
            require_measured_inference_runtime: true,
            pinned_gpu_root_sha256_hex,
            require_hardware_rooted_locality: false,
            max_receipt_age_seconds: 300,
        }
    }
}

/// Authoritative report separating prover-only geography from the stronger confidential-GPU
/// inference-location claim, and explicitly surfacing any hardware locality assumptions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceLocationVerificationReport {
    pub claim_type: InferenceClaimType,
    /// True ONLY when ALL prover geography, embedded/paired PoG bundle binding, end-to-end TLS 1.3
    /// session EKM binding, mutually-coupled GPU SPDM attestation, measured local-only runtime,
    /// post-execution receipt, and per-request/output commitments pass fail-closed!
    pub inference_location_verified: bool,
    /// Separate status of prover-only geography (`GeoProofBundle`).
    pub prover_geography_verified: bool,
    /// True ONLY when the located Prover TEE and this calculation are cryptographically bound to
    /// the EXACT same attested local Confidential GPU & active protected channel.
    pub same_bound_gpu_verified: bool,
    /// True ONLY when the receipt is bound to the EXACT end-to-end client↔attested-runtime TLS 1.3
    /// session (EKM + prover-signed leaf cert + runtime-terminated TLS + per-request context).
    pub tls_session_verified: bool,
    /// Whether the verified `GeoProofBundle` was carried directly inside the signed receipt.
    pub pog_bundle_embedded: bool,
    pub locality_proof_level: GpuCpuLocalityProofLevel,
    /// Honestly reports whether physical CPU-GPU locality is hardware-proven vs. an explicit assumption.
    pub hardware_locality_established: bool,
    pub locality_assumptions: Vec<String>,
    pub failure_reasons: Vec<String>,
    pub geo_report: Option<ProofVerificationReport>,
    pub verified_gpu: Option<VerifiedGpuBinding>,
}

fn is_valid_64_hex(s: &str) -> bool {
    let t = s.trim();
    t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Explicit guard proving the current `X-PoG-Proof` header alone can ONLY establish
/// `ProverOnlyGeography` and NEVER satisfies `ConfidentialGpuInferenceLocation`.
pub fn verify_prover_only_header_cannot_prove_inference(
    x_pog_proof_header_value: &str,
    grid: &AnchorGrid,
    policy: &InferenceVerificationPolicy,
    now_unix_s: u64,
) -> Result<InferenceLocationVerificationReport, ProtoError> {
    let bundle = GeoProofBundle::from_header_value(x_pog_proof_header_value)?;
    let geo_report = verify_proof_bundle(&bundle, grid, &policy.geo_policy, now_unix_s).ok();
    let prover_geography_verified = geo_report.as_ref().is_some_and(|r| r.overall_valid);
    Ok(InferenceLocationVerificationReport {
        claim_type: InferenceClaimType::ProverOnlyGeography,
        inference_location_verified: false,
        prover_geography_verified,
        same_bound_gpu_verified: false,
        tls_session_verified: false,
        pog_bundle_embedded: false,
        locality_proof_level: GpuCpuLocalityProofLevel::UnverifiedOrSplit,
        hardware_locality_established: false,
        locality_assumptions: vec![
            "PROVER-ONLY HEADER: X-PoG-Proof attests only the location of the Prover TEE/proxy; it carries no per-inference receipt, no end-to-end TLS 1.3 EKM session binding, and no request/output execution commitment on a bound local Confidential GPU.".into(),
        ],
        failure_reasons: vec![
            "X-PoG-Proof header alone is prover-only geography and cannot establish ConfidentialGpuInferenceLocation (fail-closed)".into(),
        ],
        geo_report,
        verified_gpu: None,
    })
}

/// Fail-closed verifier for the separate `ConfidentialGpuInferenceLocation` claim.
///
/// The PoG `GeoProofBundle` MUST be either:
/// - embedded directly inside `receipt.pog_proof_bundle`, OR
/// - supplied via `external_location_bundle` matching the receipt's signed `location_bundle_hash_hex`,
/// - or both (in which case both MUST have identical `record_hash_hex()`).
///
/// The PoG challenge itself does NOT travel over TLS; this verifier checks that the signed
/// per-inference receipt cryptographically binds the verified out-of-band `GeoProofBundle`, the
/// exact end-to-end client↔attested-runtime TLS 1.3 session (`tls_exporter_ekm_hex`), the locally
/// bound attested GPU, and this fresh request + completed output.
pub fn verify_inference_location_claim(
    receipt: &ConfidentialInferenceReceipt,
    external_location_bundle: Option<&GeoProofBundle>,
    grid: &AnchorGrid,
    expected: &ExpectedInferenceRequest<'_>,
    policy: &InferenceVerificationPolicy,
    now_unix_s: u64,
) -> Result<InferenceLocationVerificationReport, ProtoError> {
    let mut failure_reasons = Vec::new();
    let mut locality_assumptions = Vec::new();

    // 0. Resolve the exact PoG GeoProofBundle (embedded inside receipt AND/OR externally supplied).
    let pog_bundle_embedded = receipt.pog_proof_bundle.is_some();
    let resolved_bundle: Option<&GeoProofBundle> = match (
        receipt.pog_proof_bundle.as_ref(),
        external_location_bundle,
    ) {
        (Some(embedded), Some(external)) => {
            if !embedded
                .record_hash_hex()
                .eq_ignore_ascii_case(&external.record_hash_hex())
            {
                failure_reasons.push(
                    "embedded receipt.pog_proof_bundle digest does not match supplied external GeoProofBundle (fail-closed)"
                        .into(),
                );
            }
            Some(embedded)
        }
        (Some(embedded), None) => Some(embedded),
        (None, Some(external)) => Some(external),
        (None, None) => {
            failure_reasons.push(
                "missing PoG GeoProofBundle: receipt embeds no pog_proof_bundle and no matching external bundle was supplied (fail-closed)"
                    .into(),
            );
            None
        }
    };

    // 1. Verify prover-only geography first (always separated from inference claim).
    let geo_report = match resolved_bundle {
        Some(bundle) => match verify_proof_bundle(bundle, grid, &policy.geo_policy, now_unix_s) {
            Ok(r) => Some(r),
            Err(e) => {
                failure_reasons.push(format!("Location proof bundle failed verification: {e}"));
                None
            }
        },
        None => None,
    };
    let prover_geography_verified = geo_report.as_ref().is_some_and(|r| r.overall_valid);
    if !prover_geography_verified {
        if let Some(ref gr) = geo_report {
            for reason in &gr.failure_reasons {
                failure_reasons.push(format!("prover geography: {reason}"));
            }
        }
    }
    if !policy.geo_policy.tee_policy.allow_software_dev
        && !geo_report.as_ref().is_some_and(|r| r.hardware_attested)
    {
        failure_reasons.push(
            "production inference-location claim requires hardware-attested prover TEE and hardware-attested anchors (no SoftwareDev)"
                .into(),
        );
    }

    // 2. Enforce strict claim & measured local-only runtime flags (reject proxy/forwarded/fallback!).
    if receipt.claim_type != InferenceClaimType::ConfidentialGpuInferenceLocation {
        failure_reasons.push(format!(
            "receipt claim_type {:?} is prover-only, not ConfidentialGpuInferenceLocation",
            receipt.claim_type
        ));
    }
    if receipt.execution_mode != InferenceExecutionMode::LocalBoundConfidentialGpuOnly {
        failure_reasons.push(format!(
            "proxy/forwarded execution mode {:?} cannot satisfy ConfidentialGpuInferenceLocation (fail-closed)",
            receipt.execution_mode
        ));
    }
    if !receipt.remote_upstream_disabled {
        failure_reasons.push(
            "receipt does not attest remote_upstream_disabled=true (proxy forwarding forbidden)"
                .into(),
        );
    }
    if !receipt.fallback_disabled {
        failure_reasons.push(
            "receipt does not attest fallback_disabled=true (CPU/remote fallback forbidden)".into(),
        );
    }

    // 3. Verify measured local-only runtime digest allowlist (prevents proxy binary from signing outputs!).
    if policy.require_measured_inference_runtime {
        if policy.allowed_inference_runtime_measurements.is_empty() {
            failure_reasons.push(
                "require_measured_inference_runtime=true but allowed_inference_runtime_measurements is empty (fail-closed)"
                    .into(),
            );
        } else if !policy
            .allowed_inference_runtime_measurements
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&receipt.runtime_measurement_hex))
        {
            failure_reasons.push(format!(
                "runtime measurement {} is not an approved measured local-GPU no-upstream inference runtime",
                receipt.runtime_measurement_hex
            ));
        }
    }

    // 4. Verify binding between receipt and the exact verified GeoProofBundle.
    if let Some(bundle) = resolved_bundle {
        let expected_bundle_hash = bundle.record_hash_hex();
        if !receipt
            .location_bundle_hash_hex
            .eq_ignore_ascii_case(&expected_bundle_hash)
        {
            failure_reasons.push(
                "receipt.location_bundle_hash_hex does not match verified GeoProofBundle hash (tampered or mismatched PoG proof)"
                    .into(),
            );
        }
        if !receipt
            .location_epoch_challenge_hex
            .eq_ignore_ascii_case(&bundle.epoch_challenge_hex)
        {
            failure_reasons.push(
                "receipt.location_epoch_challenge_hex does not match GeoProofBundle epoch_challenge_hex"
                    .into(),
            );
        }
    }

    // 5. Verify EXACT end-to-end client-to-attested-runtime TLS 1.3 session binding!
    // Defeats:
    // - missing TLS binding
    // - reused server certificate across different TLS connections (EKM differs!)
    // - TLS-terminating intermediate proxy hop (terminated_in_attested_runtime=false or EKM differs!)
    // - mismatched leaf cert or leaf cert not signed by the attested Prover TEE key
    // - replayed/swapped request sequence on the same keep-alive TLS connection
    let mut tls_session_verified = false;
    let mut verified_tls_ekm_norm = String::new();
    let mut verified_tls_seq = 0u64;

    if !is_valid_64_hex(expected.tls_exporter_ekm_hex) {
        failure_reasons.push(
            "expected tls_exporter_ekm_hex must be 64 hex chars (32-byte RFC 8446 §7.5 EKM)".into(),
        );
    }
    if !is_valid_64_hex(expected.server_cert_sha256_hex) {
        failure_reasons.push(
            "expected server_cert_sha256_hex must be 64 hex chars (SHA-256 leaf cert digest)".into(),
        );
    }

    match receipt.tls_session_binding.as_ref() {
        None => {
            failure_reasons.push(
                "receipt missing end-to-end tls_session_binding (fail-closed: TLS session binding required)"
                    .into(),
            );
        }
        Some(tls) => {
            let mut tls_ok = true;
            if !tls.terminated_in_attested_runtime {
                tls_ok = false;
                failure_reasons.push(
                    "TLS session was NOT terminated inside the measured attested runtime (proxy TLS hop rejected)"
                        .into(),
                );
            }
            if tls.tls_protocol_version != "TLSv1.3" {
                tls_ok = false;
                failure_reasons.push(format!(
                    "unsupported TLS protocol {:?}; end-to-end TLSv1.3 required",
                    tls.tls_protocol_version
                ));
            }
            if tls.exporter_label != TLS_EXPORTER_LABEL {
                tls_ok = false;
                failure_reasons.push(format!(
                    "unexpected TLS exporter label {:?} != {:?}",
                    tls.exporter_label, TLS_EXPORTER_LABEL
                ));
            }
            if !is_valid_64_hex(&tls.tls_exporter_ekm_hex)
                || !tls
                    .tls_exporter_ekm_hex
                    .trim()
                    .eq_ignore_ascii_case(expected.tls_exporter_ekm_hex.trim())
            {
                tls_ok = false;
                failure_reasons.push(
                    "TLS 1.3 Exported Keying Material (EKM) mismatch — reused certificate across sessions or intermediate proxy TLS hop rejected"
                        .into(),
                );
            }
            if !is_valid_64_hex(&tls.server_cert_sha256_hex)
                || !tls
                    .server_cert_sha256_hex
                    .trim()
                    .eq_ignore_ascii_case(expected.server_cert_sha256_hex.trim())
            {
                tls_ok = false;
                failure_reasons.push(
                    "TLS server leaf certificate SHA-256 does not match this client TLS session"
                        .into(),
                );
            }
            if let Err(e) = verify_tls_cert_binding(
                &receipt.prover_pk_hex,
                &tls.server_cert_sha256_hex,
                &tls.cert_prover_binding_sig_hex,
            ) {
                tls_ok = false;
                failure_reasons.push(format!("TLS certificate-to-prover key binding failed: {e}"));
            }
            if tls.tls_connection_request_seq == 0 {
                tls_ok = false;
                failure_reasons.push(
                    "tls_connection_request_seq must be >= 1 for per-request session disambiguation"
                        .into(),
                );
            }
            if let Some(exp_seq) = expected.expected_tls_connection_request_seq {
                if tls.tls_connection_request_seq != exp_seq {
                    tls_ok = false;
                    failure_reasons.push(format!(
                        "tls_connection_request_seq {} != expected {} (cross-request receipt swap on same TLS session rejected)",
                        tls.tls_connection_request_seq, exp_seq
                    ));
                }
            }
            if tls_ok {
                tls_session_verified = true;
            }
            verified_tls_ekm_norm = tls.tls_exporter_ekm_hex.trim().to_ascii_lowercase();
            verified_tls_seq = tls.tls_connection_request_seq;
        }
    }

    // 6. Verify CPU-to-GPU mutual coupling + vendor-rooted GPU SPDM attestation!
    let mut verified_gpu: Option<VerifiedGpuBinding> = None;
    let mut same_bound_gpu_verified = false;
    let mut locality_proof_level = GpuCpuLocalityProofLevel::UnverifiedOrSplit;
    let mut hardware_locality_established = false;

    if let (Some(bundle), Some(gr)) = (resolved_bundle, geo_report.as_ref()) {
        if !receipt
            .prover_pk_hex
            .eq_ignore_ascii_case(&gr.verified_tee.public_key_hex)
        {
            failure_reasons.push(
                "receipt.prover_pk_hex does not match located Prover TEE public key".into(),
            );
        }
        if !receipt
            .runtime_measurement_hex
            .eq_ignore_ascii_case(&gr.verified_tee.workload_measurement_hex)
        {
            failure_reasons.push(
                "receipt.runtime_measurement_hex does not match located Prover TEE measurement"
                    .into(),
            );
        }

        match bundle.prover_quote.gpu_binding.as_ref() {
            None => {
                failure_reasons.push(
                    "located Prover TEE quote has no bound Confidential GPU (prover-only geography cannot satisfy inference-location)"
                        .into(),
                );
            }
            Some(gpu_binding) => {
                let pk_raw = hex::decode(&gr.verified_tee.public_key_hex)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok());
                let epoch_raw = hex::decode(&bundle.epoch_challenge_hex).ok();
                if let (Some(pk_arr), Some(epoch_bytes)) = (pk_raw, epoch_raw) {
                    let pin_refs: Vec<&str> = policy
                        .pinned_gpu_root_sha256_hex
                        .iter()
                        .map(|s| s.as_str())
                        .collect();
                    match verify_gpu_attestation_evidence(
                        gpu_binding,
                        &pk_arr,
                        &epoch_bytes,
                        &policy.geo_policy.tee_policy,
                        now_unix_s,
                        &pin_refs,
                    ) {
                        Ok(vg) => {
                            locality_proof_level = vg.locality_proof_level;
                            hardware_locality_established = vg.hardware_locality_established;
                            locality_assumptions.extend(vg.locality_assumptions.clone());

                            if policy.require_hardware_rooted_locality
                                && !vg.hardware_locality_established
                            {
                                failure_reasons.push(
                                    "policy requires hardware-rooted physical CPU-GPU locality, but available SPDM evidence only establishes a protected channel with assumed chassis co-location"
                                        .into(),
                                );
                            }

                            // Assert THIS receipt executed on THAT EXACT bound GPU & active protected channel!
                            let gpu_match = receipt.gpu_uuid == vg.gpu_uuid
                                && receipt.gpu_pubkey_hex.eq_ignore_ascii_case(&vg.gpu_pubkey_hex)
                                && receipt
                                    .spdm_report_hash_hex
                                    .eq_ignore_ascii_case(&vg.spdm_report_hash_hex)
                                && receipt
                                    .spdm_session_transcript_hash_hex
                                    .eq_ignore_ascii_case(&vg.spdm_session_transcript_hash_hex)
                                && receipt.protected_channel_id == vg.protected_channel_id;
                            if !gpu_match {
                                failure_reasons.push(
                                    "inference receipt GPU UUID / pubkey / SPDM report / protected channel does not match the Confidential GPU bound to the located Prover TEE"
                                        .into(),
                                );
                            } else {
                                same_bound_gpu_verified = true;
                            }
                            verified_gpu = Some(vg);
                        }
                        Err(e) => {
                            failure_reasons.push(format!(
                                "Confidential GPU SPDM attestation/coupling failed: {e}"
                            ));
                        }
                    }
                } else {
                    failure_reasons.push("invalid prover_pk or epoch_challenge hex".into());
                }
            }
        }
    }

    // 7. Verify fresh per-request nonce, exact request/output commitments, GPU+TLS execution digest,
    //    and strict post-execution completion timestamps!
    let exp_nonce_norm = expected.request_nonce_hex.trim().to_ascii_lowercase();
    if exp_nonce_norm.len() < 32 || !exp_nonce_norm.bytes().all(|b| b.is_ascii_hexdigit()) {
        failure_reasons
            .push("expected_request_nonce_hex must be >= 32 hex chars (16 random bytes)".into());
    } else if !receipt.request_nonce_hex.eq_ignore_ascii_case(&exp_nonce_norm) {
        failure_reasons.push("stale or mismatched request_nonce_hex (replay rejected)".into());
    }
    if receipt.model_id != expected.model_id {
        failure_reasons.push(format!(
            "receipt model_id {:?} != expected {:?}",
            receipt.model_id, expected.model_id
        ));
    }
    let expected_req_hash =
        compute_inference_request_hash(&exp_nonce_norm, expected.model_id, expected.request_bytes);
    if !receipt
        .request_hash_hex
        .eq_ignore_ascii_case(&expected_req_hash)
    {
        failure_reasons.push("receipt request_hash_hex does not match this request".into());
    }
    let expected_out_hash =
        compute_inference_output_hash(&expected_req_hash, expected.output_bytes);
    if !receipt
        .output_hash_hex
        .eq_ignore_ascii_case(&expected_out_hash)
    {
        failure_reasons
            .push("receipt output_hash_hex does not match this calculation output".into());
    }

    if receipt.channel_seq_no == 0 {
        failure_reasons.push("receipt channel_seq_no must be >= 1".into());
    }
    let expected_exec_digest = compute_gpu_execution_digest(
        &receipt.spdm_session_transcript_hash_hex,
        &receipt.gpu_uuid,
        &receipt.protected_channel_id,
        receipt.channel_seq_no,
        &verified_tls_ekm_norm,
        verified_tls_seq,
        &expected_req_hash,
        &expected_out_hash,
    );
    if !receipt
        .gpu_execution_digest_hex
        .eq_ignore_ascii_case(&expected_exec_digest)
    {
        failure_reasons.push(
            "receipt gpu_execution_digest_hex does not match bound protected-channel + TLS session execution transcript"
                .into(),
        );
    }

    // Post-execution completion & freshness checks (reject pre-execution or stale receipts!).
    let max_skew = policy.geo_policy.tee_policy.max_future_skew_seconds;
    if receipt.execution_started_at_unix_s == 0
        || receipt.execution_completed_at_unix_s == 0
        || receipt.execution_completed_at_unix_s < receipt.execution_started_at_unix_s
    {
        failure_reasons.push(
            "invalid post-execution timestamps (execution_completed_at_unix_s must be >= execution_started_at_unix_s > 0)"
                .into(),
        );
    }
    if now_unix_s
        > receipt
            .execution_completed_at_unix_s
            .saturating_add(policy.max_receipt_age_seconds)
    {
        failure_reasons.push(format!(
            "inference receipt expired (age {}s > max {}s)",
            now_unix_s.saturating_sub(receipt.execution_completed_at_unix_s),
            policy.max_receipt_age_seconds
        ));
    }
    if receipt.execution_completed_at_unix_s > now_unix_s.saturating_add(max_skew) {
        failure_reasons
            .push("inference receipt execution_completed_at_unix_s is in the future".into());
    }

    // 8. Verify Ed25519 signature by the located Prover TEE's non-exportable signing key.
    if let Err(e) = receipt.verify_signature(&receipt.prover_pk_hex) {
        failure_reasons.push(format!("prover receipt signature verification failed: {e}"));
    }

    locality_assumptions.push(
        "ANCHOR COORDINATE PROVENANCE: Hardware TEE identity proves workload & key custody, not physical anchor coordinates; anchor locations rely on separate audited coordinate provenance and cross-cloud speed-of-light consistency.".into(),
    );

    let inference_location_verified = failure_reasons.is_empty()
        && prover_geography_verified
        && same_bound_gpu_verified
        && tls_session_verified;

    Ok(InferenceLocationVerificationReport {
        claim_type: InferenceClaimType::ConfidentialGpuInferenceLocation,
        inference_location_verified,
        prover_geography_verified,
        same_bound_gpu_verified,
        tls_session_verified,
        pog_bundle_embedded,
        locality_proof_level,
        hardware_locality_established,
        locality_assumptions,
        failure_reasons,
        geo_report,
        verified_gpu,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::AnchorDescriptor;
    use crate::wire::AnchorReceipt;
    use ed25519_dalek::SigningKey;
    use p384::ecdsa::signature::Signer as P384Signer;
    use p384::ecdsa::{DerSignature as P384DerSig, SigningKey as P384SigningKey};
    use p384::pkcs8::DecodePrivateKey;
    use pog_geo::LatLon;
    use pog_tee::{
        compute_gpu_binding_nonce, AttestationPolicy, GpuAttestationBinding,
        GpuAttestationEvidence, GpuProtectedChannelKind, SignedGpuSpdmQuotePayload,
        SoftwareDevProvider, TeeProvider, TeeVendor,
    };
    use rand::rngs::OsRng;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, PKCS_ECDSA_P384_SHA384};
    use x509_parser::prelude::*;

    fn build_signed_gpu(
        prover_pk: &[u8; 32],
        epoch: &[u8],
        gpu_uuid: &str,
        transcript_hex: &str,
        override_nonce: Option<String>,
        now: u64,
    ) -> (GpuAttestationBinding, String) {
        let mut root_p = CertificateParams::default();
        root_p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_p
            .distinguished_name
            .push(DnType::CommonName, "Test-NVIDIA-Root-CA");
        let root_kp = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let root_c = root_p.self_signed(&root_kp).unwrap();
        let root_fp = hex::encode(Sha256::digest(root_c.der().as_ref()));

        let mut int_p = CertificateParams::default();
        int_p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        int_p
            .distinguished_name
            .push(DnType::CommonName, "Test-NVIDIA-Device-CA");
        let int_kp = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let int_c = int_p.signed_by(&int_kp, &root_c, &root_kp).unwrap();

        let mut leaf_p = CertificateParams::default();
        leaf_p
            .distinguished_name
            .push(DnType::CommonName, gpu_uuid);
        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let leaf_c = leaf_p.signed_by(&leaf_kp, &int_c, &int_kp).unwrap();
        let (_, parsed_leaf) = X509Certificate::from_der(leaf_c.der().as_ref()).unwrap();
        let gpu_pk_hex = hex::encode(parsed_leaf.public_key().subject_public_key.data.as_ref());

        let gpu_nonce_hex = override_nonce.unwrap_or_else(|| {
            hex::encode(compute_gpu_binding_nonce(prover_pk, epoch, transcript_hex))
        });
        let payload = SignedGpuSpdmQuotePayload {
            gpu_vendor: "nvidia-cc".into(),
            gpu_model: "NVIDIA H100 80GB SXM5 Confidential".into(),
            gpu_uuid: gpu_uuid.into(),
            gpu_nonce_hex: gpu_nonce_hex.clone(),
            spdm_session_transcript_hash_hex: transcript_hex.into(),
            protected_channel_id: "spdm-pcie-0000:81:00.0-sess-7".into(),
            channel_kind: GpuProtectedChannelKind::PcieSpdmEncryptedBounceBuffer,
            cc_mode_enabled: true,
            debug_disabled: true,
            driver_measurement_hex: "dd".repeat(32),
            vbios_measurement_hex: "ee".repeat(32),
            generated_at_unix_s: now,
        };
        let raw_bytes = serde_json::to_vec(&payload).unwrap();
        let report_hash = hex::encode(Sha256::digest(&raw_bytes));
        let leaf_sk = P384SigningKey::from_pkcs8_der(leaf_kp.serialize_der().as_ref()).unwrap();
        let sig: P384DerSig = leaf_sk.sign(&raw_bytes);

        let ev = GpuAttestationEvidence {
            gpu_vendor: payload.gpu_vendor,
            gpu_model: payload.gpu_model.clone(),
            gpu_uuid: payload.gpu_uuid.clone(),
            gpu_pubkey_hex: gpu_pk_hex.clone(),
            gpu_nonce_hex,
            cc_mode_enabled: true,
            debug_disabled: true,
            driver_measurement_hex: payload.driver_measurement_hex.clone(),
            vbios_measurement_hex: payload.vbios_measurement_hex,
            channel_kind: payload.channel_kind,
            protected_channel_id: payload.protected_channel_id.clone(),
            spdm_session_transcript_hash_hex: transcript_hex.into(),
            raw_spdm_quote_b64: base64::engine::general_purpose::STANDARD.encode(&raw_bytes),
            gpu_signature_b64: base64::engine::general_purpose::STANDARD.encode(sig.as_bytes()),
            vendor_cert_chain_pem: vec![leaf_c.pem(), int_c.pem(), root_c.pem()],
            generated_at_unix_s: now,
        };
        let binding = GpuAttestationBinding {
            gpu_model: payload.gpu_model,
            gpu_uuid: gpu_uuid.into(),
            spdm_report_hash_hex: report_hash,
            driver_measurement_hex: payload.driver_measurement_hex,
            gpu_pubkey_hex: Some(gpu_pk_hex),
            spdm_session_transcript_hash_hex: Some(transcript_hex.into()),
            protected_channel_id: Some(payload.protected_channel_id),
            evidence: Some(ev),
            physical_fingerprint: None,
        };
        (binding, root_fp)
    }

    struct TestFixture {
        kp: WorkloadKeypair,
        grid: AnchorGrid,
        bundle: GeoProofBundle,
        receipt: ConfidentialInferenceReceipt,
        pol: InferenceVerificationPolicy,
        req_nonce: String,
        req_bytes: Vec<u8>,
        out_bytes: Vec<u8>,
        tls_ekm_hex: String,
        tls_cert_sha256_hex: String,
    }

    #[allow(clippy::too_many_arguments)]
    fn mint_receipt_for_request(
        kp: &WorkloadKeypair,
        bundle: &GeoProofBundle,
        runtime_meas: &str,
        req_nonce: &str,
        model_id: &str,
        req_bytes: &[u8],
        out_bytes: &[u8],
        tls_ekm_hex: &str,
        tls_cert_sha256_hex: &str,
        tls_seq: u64,
        channel_seq: u64,
        embed_bundle: bool,
        now: u64,
    ) -> ConfidentialInferenceReceipt {
        let gpu_binding = bundle.prover_quote.gpu_binding.as_ref().unwrap();
        let req_hash = compute_inference_request_hash(req_nonce, model_id, req_bytes);
        let out_hash = compute_inference_output_hash(&req_hash, out_bytes);
        let exec_digest = compute_gpu_execution_digest(
            gpu_binding
                .spdm_session_transcript_hash_hex
                .as_deref()
                .unwrap_or(""),
            &gpu_binding.gpu_uuid,
            gpu_binding.protected_channel_id.as_deref().unwrap_or(""),
            channel_seq,
            tls_ekm_hex,
            tls_seq,
            &req_hash,
            &out_hash,
        );
        let cert_sig = sign_tls_cert_binding(kp, tls_cert_sha256_hex);
        let mut receipt = ConfidentialInferenceReceipt {
            version: 2,
            claim_type: InferenceClaimType::ConfidentialGpuInferenceLocation,
            execution_mode: InferenceExecutionMode::LocalBoundConfidentialGpuOnly,
            remote_upstream_disabled: true,
            fallback_disabled: true,
            request_nonce_hex: req_nonce.into(),
            model_id: model_id.into(),
            request_hash_hex: req_hash,
            output_hash_hex: out_hash,
            prover_pk_hex: kp.public_key_hex(),
            runtime_measurement_hex: runtime_meas.into(),
            gpu_uuid: gpu_binding.gpu_uuid.clone(),
            gpu_pubkey_hex: gpu_binding.gpu_pubkey_hex.clone().unwrap_or_default(),
            spdm_report_hash_hex: gpu_binding.spdm_report_hash_hex.clone(),
            spdm_session_transcript_hash_hex: gpu_binding
                .spdm_session_transcript_hash_hex
                .clone()
                .unwrap_or_default(),
            protected_channel_id: gpu_binding.protected_channel_id.clone().unwrap_or_default(),
            channel_seq_no: channel_seq,
            gpu_execution_digest_hex: exec_digest,
            execution_started_at_unix_s: now,
            execution_completed_at_unix_s: now + 1,
            tls_session_binding: Some(TlsSessionBinding {
                tls_protocol_version: "TLSv1.3".into(),
                exporter_label: TLS_EXPORTER_LABEL.into(),
                tls_exporter_ekm_hex: tls_ekm_hex.into(),
                server_cert_sha256_hex: tls_cert_sha256_hex.into(),
                cert_prover_binding_sig_hex: cert_sig,
                terminated_in_attested_runtime: true,
                tls_connection_request_seq: tls_seq,
            }),
            location_bundle_hash_hex: bundle.record_hash_hex(),
            location_epoch_challenge_hex: bundle.epoch_challenge_hex.clone(),
            pog_proof_bundle: if embed_bundle {
                Some(bundle.clone())
            } else {
                None
            },
            prover_signature_hex: String::new(),
        };
        receipt.sign(kp);
        receipt
    }

    fn build_fixture(
        now: u64,
        gpu_override: Option<GpuAttestationBinding>,
        gpu_root_fp: Option<String>,
    ) -> TestFixture {
        let kp = WorkloadKeypair::generate();
        let epoch = [0x42u8; 32];
        let epoch_hex = hex::encode(epoch);
        let transcript = "77".repeat(32);

        let (gpu_binding, root_fp) = match (gpu_override, gpu_root_fp) {
            (Some(b), Some(fp)) => (b, fp),
            _ => build_signed_gpu(
                &kp.public_key_bytes(),
                &epoch,
                "GPU-H100-ASHBURN-01",
                &transcript,
                None,
                now,
            ),
        };

        let runtime_meas = "12".repeat(48);
        let mut prover_quote = SoftwareDevProvider::new(&runtime_meas)
            .attest(&kp.public_key_bytes(), &epoch, Some(gpu_binding))
            .unwrap();
        prover_quote.generated_at_unix_s = now;

        let sk1 = SigningKey::generate(&mut OsRng);
        let sk2 = SigningKey::generate(&mut OsRng);
        let grid = AnchorGrid {
            version: "2.0.0".into(),
            grid_name: "ashburn-test".into(),
            description: "test".into(),
            anchors: vec![
                AnchorDescriptor {
                    anchor_id: "aws-us-east-1".into(),
                    cloud_provider: "aws".into(),
                    region: "us-east-1".into(),
                    city: "Ashburn, VA".into(),
                    country_code: Some("US".into()),
                    tee_vendor: TeeVendor::AwsNitro,
                    instance_type: "c6a.xlarge".into(),
                    location: LatLon::new(39.0438, -77.4874),
                    endpoint_tcp: "1.1.1.1:7443".into(),
                    endpoint_udp: "1.1.1.1:7444".into(),
                    https_url: None,
                    public_key_hex: hex::encode(sk1.verifying_key().to_bytes()),
                    failure_domain: None,
                    asn: None,
                    diagnostic_only: false,
                    coordinate_basis: None,
                },
                AnchorDescriptor {
                    anchor_id: "gcp-us-east4".into(),
                    cloud_provider: "gcp".into(),
                    region: "us-east4".into(),
                    city: "Ashburn, VA".into(),
                    country_code: Some("US".into()),
                    tee_vendor: TeeVendor::IntelTdx,
                    instance_type: "c3-standard-4".into(),
                    location: LatLon::new(39.0438, -77.4874),
                    endpoint_tcp: "2.2.2.2:7443".into(),
                    endpoint_udp: "2.2.2.2:7444".into(),
                    https_url: None,
                    public_key_hex: hex::encode(sk2.verifying_key().to_bytes()),
                    failure_domain: None,
                    asn: None,
                    diagnostic_only: false,
                    coordinate_basis: None,
                },
            ],
        };

        let mk_r = |id: &str, cloud: &str, sk: &SigningKey| {
            let mut r = AnchorReceipt {
                anchor_id: id.into(),
                cloud_provider: cloud.into(),
                prover_pk_hex: kp.public_key_hex(),
                workload_measurement_hex: runtime_meas.clone(),
                epoch_challenge_hex: epoch_hex.clone(),
                prover_observed_ip: "198.51.100.10".into(),
                rtt_min_us: 1_500,
                rtt_p50_us: 1_600,
                rtt_samples_us: vec![1_500, 1_600],
                measured_at_unix_s: now,
                anchor_signature_hex: String::new(),
            };
            r.sign(sk);
            r
        };
        let bundle = GeoProofBundle {
            version: 1,
            epoch_challenge_hex: epoch_hex.clone(),
            client_nonce_hex: None,
            target_location: LatLon::new(39.0438, -77.4874),
            required_radius_km: 400.0,
            prover_quote,
            receipts: vec![
                mk_r("aws-us-east-1", "aws", &sk1),
                mk_r("gcp-us-east4", "gcp", &sk2),
            ],
            calibrated_velocity_km_per_s: Some(150_000.0),
            prev_chain_hash_hex: None,
            chain_seq: 1,
            created_at_unix_s: now,
        };

        let req_nonce = "ab".repeat(32);
        let req_bytes = br#"{"prompt":"prove this calculation ran on Ashburn H100"}"#.to_vec();
        let out_bytes = br#"{"completion":"verified-local-gpu-output"}"#.to_vec();
        let tls_ekm_hex = "33".repeat(32);
        let tls_cert_sha256_hex = "44".repeat(32);
        let receipt = mint_receipt_for_request(
            &kp,
            &bundle,
            &runtime_meas,
            &req_nonce,
            "llama-3.3-70b-fp8",
            &req_bytes,
            &out_bytes,
            &tls_ekm_hex,
            &tls_cert_sha256_hex,
            1,
            1,
            true, // embed PoG bundle inside the signed receipt!
            now,
        );

        let tee_pol = AttestationPolicy::allow_dev_software();
        let pol = InferenceVerificationPolicy {
            geo_policy: VerificationPolicy {
                tee_policy: tee_pol,
                min_anchors: 2,
                min_cloud_providers: 2,
                max_byzantine: 0,
                ..Default::default()
            },
            allowed_inference_runtime_measurements: vec![runtime_meas],
            require_measured_inference_runtime: true,
            pinned_gpu_root_sha256_hex: vec![root_fp],
            require_hardware_rooted_locality: false,
            max_receipt_age_seconds: 300,
        };
        TestFixture {
            kp,
            grid,
            bundle,
            receipt,
            pol,
            req_nonce,
            req_bytes,
            out_bytes,
            tls_ekm_hex,
            tls_cert_sha256_hex,
        }
    }

    #[test]
    fn test_confidential_gpu_inference_location_embedded_pog_tls_binding_and_adversarial_rejections() {
        let now = 1_795_760_000u64;
        let fx = build_fixture(now, None, None);

        let expected = ExpectedInferenceRequest {
            request_nonce_hex: &fx.req_nonce,
            model_id: "llama-3.3-70b-fp8",
            request_bytes: &fx.req_bytes,
            output_bytes: &fx.out_bytes,
            tls_exporter_ekm_hex: &fx.tls_ekm_hex,
            server_cert_sha256_hex: &fx.tls_cert_sha256_hex,
            expected_tls_connection_request_seq: Some(1),
        };

        // 1. Positive end-to-end with PoG proof EMBEDDED inside the signed receipt (no external bundle needed)!
        let ok = verify_inference_location_claim(&fx.receipt, None, &fx.grid, &expected, &fx.pol, now + 5)
            .unwrap();
        assert!(
            ok.inference_location_verified,
            "unexpected failures: {:?}",
            ok.failure_reasons
        );
        assert!(ok.prover_geography_verified);
        assert!(ok.same_bound_gpu_verified);
        assert!(ok.tls_session_verified);
        assert!(ok.pog_bundle_embedded);
        assert_eq!(
            ok.locality_proof_level,
            GpuCpuLocalityProofLevel::SpdmProtectedLocalChannelAssumedColocated
        );
        assert!(!ok.hardware_locality_established);
        assert!(ok
            .locality_assumptions
            .iter()
            .any(|s| s.contains("LOCALITY ASSUMPTION")));

        // 2. Positive end-to-end with signed digest + exact separately supplied GeoProofBundle!
        let mut detached_receipt = fx.receipt.clone();
        detached_receipt.pog_proof_bundle = None;
        let ok_detached = verify_inference_location_claim(
            &detached_receipt,
            Some(&fx.bundle),
            &fx.grid,
            &expected,
            &fx.pol,
            now + 5,
        )
        .unwrap();
        assert!(
            ok_detached.inference_location_verified,
            "unexpected failures: {:?}",
            ok_detached.failure_reasons
        );
        assert!(!ok_detached.pog_bundle_embedded);

        // 3. Missing PoG bundle (neither embedded nor supplied) OR mismatched bundle MUST FAIL CLOSED!
        let rep_missing_bundle = verify_inference_location_claim(
            &detached_receipt,
            None,
            &fx.grid,
            &expected,
            &fx.pol,
            now + 5,
        )
        .unwrap();
        assert!(!rep_missing_bundle.inference_location_verified);
        assert!(rep_missing_bundle
            .failure_reasons
            .iter()
            .any(|m| m.contains("missing PoG GeoProofBundle")));

        let mut tampered_bundle = fx.bundle.clone();
        tampered_bundle.chain_seq = 999;
        let mut tampered_embedded = fx.receipt.clone();
        tampered_embedded.pog_proof_bundle = Some(tampered_bundle.clone());
        let rep_tampered_bundle = verify_inference_location_claim(
            &tampered_embedded,
            None,
            &fx.grid,
            &expected,
            &fx.pol,
            now + 5,
        )
        .unwrap();
        assert!(!rep_tampered_bundle.inference_location_verified);
        assert!(rep_tampered_bundle
            .failure_reasons
            .iter()
            .any(|m| m.contains("location_bundle_hash_hex")));

        // 4. TWO REQUESTS ON ONE KEEP-ALIVE TLS 1.3 CONNECTION MUST NOT BE INTERCHANGEABLE!
        let req2_nonce = "ef".repeat(32);
        let req2_bytes = br#"{"prompt":"second request on SAME TLS 1.3 connection"}"#;
        let out2_bytes = br#"{"completion":"second-output-same-tls"}"#;
        let receipt2 = mint_receipt_for_request(
            &fx.kp,
            &fx.bundle,
            &fx.receipt.runtime_measurement_hex,
            &req2_nonce,
            "llama-3.3-70b-fp8",
            req2_bytes,
            out2_bytes,
            &fx.tls_ekm_hex,         // EXACT SAME TLS 1.3 session EKM!
            &fx.tls_cert_sha256_hex, // EXACT SAME leaf cert!
            2,                       // per-connection seq 2
            2,                       // GPU channel seq 2
            true,
            now,
        );
        let expected2 = ExpectedInferenceRequest {
            request_nonce_hex: &req2_nonce,
            model_id: "llama-3.3-70b-fp8",
            request_bytes: req2_bytes,
            output_bytes: out2_bytes,
            tls_exporter_ekm_hex: &fx.tls_ekm_hex,
            server_cert_sha256_hex: &fx.tls_cert_sha256_hex,
            expected_tls_connection_request_seq: Some(2),
        };
        let ok2 = verify_inference_location_claim(
            &receipt2, None, &fx.grid, &expected2, &fx.pol, now + 5,
        )
        .unwrap();
        assert!(ok2.inference_location_verified, "{:?}", ok2.failure_reasons);

        // Swapping receipt1 onto request2 (even on the SAME TLS 1.3 connection!) MUST FAIL CLOSED!
        let rep_swap_same_tls = verify_inference_location_claim(
            &fx.receipt,
            None,
            &fx.grid,
            &expected2,
            &fx.pol,
            now + 5,
        )
        .unwrap();
        assert!(!rep_swap_same_tls.inference_location_verified);
        assert!(rep_swap_same_tls
            .failure_reasons
            .iter()
            .any(|m| m.contains("tls_connection_request_seq") || m.contains("request_nonce_hex")));

        // Even if prompt/output were identical across two requests on the same TLS connection,
        // swapping receipt1 (seq=1, nonce1) onto req2 (seq=2, nonce2) MUST FAIL CLOSED!
        let expected_dup_body = ExpectedInferenceRequest {
            request_nonce_hex: &req2_nonce,
            model_id: "llama-3.3-70b-fp8",
            request_bytes: &fx.req_bytes,
            output_bytes: &fx.out_bytes,
            tls_exporter_ekm_hex: &fx.tls_ekm_hex,
            server_cert_sha256_hex: &fx.tls_cert_sha256_hex,
            expected_tls_connection_request_seq: Some(2),
        };
        let rep_dup_swap = verify_inference_location_claim(
            &fx.receipt,
            None,
            &fx.grid,
            &expected_dup_body,
            &fx.pol,
            now + 5,
        )
        .unwrap();
        assert!(!rep_dup_swap.inference_location_verified);

        // 5. REUSED CERTIFICATE ON A DIFFERENT TLS SESSION (same cert SHA-256, DIFFERENT EKM) MUST FAIL!
        let other_session_ekm = "88".repeat(32);
        let expected_reused_cert = ExpectedInferenceRequest {
            tls_exporter_ekm_hex: &other_session_ekm,
            ..expected.clone()
        };
        let rep_reused_cert = verify_inference_location_claim(
            &fx.receipt,
            None,
            &fx.grid,
            &expected_reused_cert,
            &fx.pol,
            now + 5,
        )
        .unwrap();
        assert!(!rep_reused_cert.inference_location_verified);
        assert!(!rep_reused_cert.tls_session_verified);
        assert!(rep_reused_cert
            .failure_reasons
            .iter()
            .any(|m| m.contains("Exported Keying Material (EKM) mismatch")));

        // 6. PROXY TLS HOP (terminated_in_attested_runtime=false OR missing tls_session_binding OR wrong cert signer) MUST FAIL!
        let mut proxy_tls_hop = fx.receipt.clone();
        proxy_tls_hop
            .tls_session_binding
            .as_mut()
            .unwrap()
            .terminated_in_attested_runtime = false;
        proxy_tls_hop.sign(&fx.kp);
        let rep_proxy_tls = verify_inference_location_claim(
            &proxy_tls_hop,
            None,
            &fx.grid,
            &expected,
            &fx.pol,
            now + 5,
        )
        .unwrap();
        assert!(!rep_proxy_tls.inference_location_verified);
        assert!(!rep_proxy_tls.tls_session_verified);
        assert!(rep_proxy_tls
            .failure_reasons
            .iter()
            .any(|m| m.contains("proxy TLS hop rejected")));

        let mut no_tls = fx.receipt.clone();
        no_tls.tls_session_binding = None;
        no_tls.sign(&fx.kp);
        let rep_no_tls =
            verify_inference_location_claim(&no_tls, None, &fx.grid, &expected, &fx.pol, now + 5)
                .unwrap();
        assert!(!rep_no_tls.inference_location_verified);
        assert!(!rep_no_tls.tls_session_verified);

        let wrong_cert_kp = WorkloadKeypair::generate();
        let mut bad_cert_bind = fx.receipt.clone();
        bad_cert_bind
            .tls_session_binding
            .as_mut()
            .unwrap()
            .cert_prover_binding_sig_hex =
            sign_tls_cert_binding(&wrong_cert_kp, &fx.tls_cert_sha256_hex);
        bad_cert_bind.sign(&fx.kp);
        let rep_bad_cert = verify_inference_location_claim(
            &bad_cert_bind,
            None,
            &fx.grid,
            &expected,
            &fx.pol,
            now + 5,
        )
        .unwrap();
        assert!(!rep_bad_cert.inference_location_verified);
        assert!(!rep_bad_cert.tls_session_verified);

        // 7. CURRENT X-PoG-Proof HEADER ALONE CANNOT MAKE THE STRONGER INFERENCE-LOCATION CLAIM!
        let header_val = fx.bundle.to_header_value().unwrap();
        let rep_hdr_only =
            verify_prover_only_header_cannot_prove_inference(&header_val, &fx.grid, &fx.pol, now + 5)
                .unwrap();
        assert!(rep_hdr_only.prover_geography_verified);
        assert!(!rep_hdr_only.inference_location_verified);
        assert_eq!(rep_hdr_only.claim_type, InferenceClaimType::ProverOnlyGeography);

        // 8. Strict hardware-rooted locality policy MUST fail closed when only SPDM local channel is present!
        let mut strict_loc = fx.pol.clone();
        strict_loc.require_hardware_rooted_locality = true;
        let r_strict = verify_inference_location_claim(
            &fx.receipt,
            None,
            &fx.grid,
            &expected,
            &strict_loc,
            now + 5,
        )
        .unwrap();
        assert!(!r_strict.inference_location_verified);
        assert!(r_strict.prover_geography_verified);

        // 9. TWO INDEPENDENT VALID QUOTES (valid GPU quote NOT coupled to prover_pk/epoch/transcript) MUST FAIL!
        let epoch = [0x42u8; 32];
        let (split_gpu, split_fp) = build_signed_gpu(
            &fx.kp.public_key_bytes(),
            &epoch,
            "GPU-REMOTE-SINGAPORE",
            &"77".repeat(32),
            Some("ff".repeat(32)),
            now,
        );
        let fx_split = build_fixture(now, Some(split_gpu), Some(split_fp));
        let exp_split = ExpectedInferenceRequest {
            request_nonce_hex: &fx_split.req_nonce,
            model_id: "llama-3.3-70b-fp8",
            request_bytes: &fx_split.req_bytes,
            output_bytes: &fx_split.out_bytes,
            tls_exporter_ekm_hex: &fx_split.tls_ekm_hex,
            server_cert_sha256_hex: &fx_split.tls_cert_sha256_hex,
            expected_tls_connection_request_seq: Some(1),
        };
        let rep_split = verify_inference_location_claim(
            &fx_split.receipt,
            None,
            &fx_split.grid,
            &exp_split,
            &fx_split.pol,
            now + 5,
        )
        .unwrap();
        assert!(!rep_split.inference_location_verified);
        assert!(!rep_split.same_bound_gpu_verified);
        assert!(rep_split
            .failure_reasons
            .iter()
            .any(|m| m.contains("two independent valid quotes rejected")));

        // 10. BARE QUOTED GPU ID (no verified GPU SPDM evidence) MUST FAIL!
        let mut bare_bundle = fx.bundle.clone();
        bare_bundle.prover_quote.gpu_binding.as_mut().unwrap().evidence = None;
        let mut bare_receipt = fx.receipt.clone();
        bare_receipt.location_bundle_hash_hex = bare_bundle.record_hash_hex();
        bare_receipt.pog_proof_bundle = Some(bare_bundle);
        bare_receipt.sign(&fx.kp);
        let rep_bare = verify_inference_location_claim(
            &bare_receipt,
            None,
            &fx.grid,
            &expected,
            &fx.pol,
            now + 5,
        )
        .unwrap();
        assert!(!rep_bare.inference_location_verified);
        assert!(rep_bare.prover_geography_verified);
        assert!(rep_bare
            .failure_reasons
            .iter()
            .any(|m| m.contains("bare quoted GPU ID rejected")));

        // 11. PROXY SIGNATURE ON FORWARDED OUTPUT MUST FAIL!
        let mut proxy_receipt = fx.receipt.clone();
        proxy_receipt.execution_mode = InferenceExecutionMode::ProxyForwarded;
        proxy_receipt.remote_upstream_disabled = false;
        proxy_receipt.sign(&fx.kp);
        let rep_proxy = verify_inference_location_claim(
            &proxy_receipt,
            None,
            &fx.grid,
            &expected,
            &fx.pol,
            now + 5,
        )
        .unwrap();
        assert!(!rep_proxy.inference_location_verified);
        assert!(rep_proxy.prover_geography_verified);
        assert!(rep_proxy
            .failure_reasons
            .iter()
            .any(|m| m.contains("ProxyForwarded")));

        // 12. UNMEASURED / UNAPPROVED RUNTIME DIGEST MUST FAIL!
        let mut bad_rt_pol = fx.pol.clone();
        bad_rt_pol.allowed_inference_runtime_measurements = vec!["99".repeat(48)];
        let rep_rt = verify_inference_location_claim(
            &fx.receipt,
            None,
            &fx.grid,
            &expected,
            &bad_rt_pol,
            now + 5,
        )
        .unwrap();
        assert!(!rep_rt.inference_location_verified);

        // 13. TAMPERED OUTPUT / PRE-EXECUTION TIMESTAMP / GPU SWAP / PRODUCTION SOFTWARE_DEV ALL FAIL!
        let exp_tamper = ExpectedInferenceRequest {
            output_bytes: b"tampered-output",
            ..expected.clone()
        };
        assert!(
            !verify_inference_location_claim(
                &fx.receipt,
                None,
                &fx.grid,
                &exp_tamper,
                &fx.pol,
                now + 5
            )
            .unwrap()
            .inference_location_verified
        );

        let mut pre_exec = fx.receipt.clone();
        pre_exec.execution_completed_at_unix_s = pre_exec.execution_started_at_unix_s - 1;
        pre_exec.sign(&fx.kp);
        assert!(
            !verify_inference_location_claim(
                &pre_exec,
                None,
                &fx.grid,
                &expected,
                &fx.pol,
                now + 5
            )
            .unwrap()
            .inference_location_verified
        );

        let mut swapped_gpu = fx.receipt.clone();
        swapped_gpu.gpu_uuid = "GPU-OTHER-DEVICE".into();
        swapped_gpu.sign(&fx.kp);
        let rep_swap = verify_inference_location_claim(
            &swapped_gpu,
            None,
            &fx.grid,
            &expected,
            &fx.pol,
            now + 5,
        )
        .unwrap();
        assert!(!rep_swap.inference_location_verified);
        assert!(!rep_swap.same_bound_gpu_verified);

        let prod_pol = InferenceVerificationPolicy::production(
            fx.pol.allowed_inference_runtime_measurements.clone(),
            fx.pol.pinned_gpu_root_sha256_hex.clone(),
        );
        let rep_prod = verify_inference_location_claim(
            &fx.receipt,
            None,
            &fx.grid,
            &expected,
            &prod_pol,
            now + 5,
        )
        .unwrap();
        assert!(!rep_prod.inference_location_verified);
        assert!(!rep_prod.prover_geography_verified);
    }
}
