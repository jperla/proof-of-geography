//! CPU-Only Confidential TEE Inference Receipt, Blinded Commitments & Independent Verifier.
//!
//! Designed for the public Verified LLM demo (`https://llm.proofofgeography.com`):
//! - Runs strictly on CPU inside an isolated hardware TEE (GCP Confidential Space Intel TDX),
//!   with ZERO GPU, ZERO external inference API, ZERO remote upstream, ZERO fallback,
//!   ZERO SSH/debug shell, and ZERO prompt/output logging.
//! - Uses a pinned, redistributable Apache-2.0 open-weight model (`Qwen/Qwen2.5-0.5B-Instruct-GGUF`,
//!   `qwen2.5-0.5b-instruct-q4_k_m.gguf`) baked into the measured `FROM scratch` OCI container.
//! - Privacy-preserving blinded SHA-256 commitments bind exact request bytes and exact delivered
//!   HTTP response bytes using a fresh per-request 256-bit salt (`X-PoG-Commitment-Salt`) returned
//!   ONLY to the caller over their encrypted TLS 1.3 connection (never stored in `/v1/receipts/{id}`).
//! - Strictly separates TWO independent statuses:
//!   1. `inference_tee_verified`: hardware Intel TDX OIDC chain + pinned container digest + enclave
//!      Ed25519 key + end-to-end TLS 1.3 Exported Keying Material (`EXPORTER-pog-inference-v1`) +
//!      blinded request/output commitments + pinned model/weights/license.
//!   2. `geographic_proof_verified` / `geographic_proof_status`: out-of-band PoG multi-cloud
//!      hardware TEE anchor quorum (NEVER counting the prover as its own anchor, NEVER claiming a
//!      proven location from `SoftwareDev` diagnostic anchors!).

use crate::bundle::{
    verify_proof_bundle, GeoProofBundle, ProofVerificationReport, VerificationPolicy,
};
use crate::committee::AnchorGrid;
use crate::inference::{verify_tls_cert_binding, TlsSessionBinding, TLS_EXPORTER_LABEL};
use crate::wire::ProtoError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use base64::Engine;
use pog_tee::{
    verify_gcp_confidential_space_jwt, verify_quote, AttestationPolicy, JwkSet,
    TeeAttestationQuote, TeeVendor, VerifiedGcpConfidentialSpaceToken, WorkloadAttestation,
    WorkloadKeypair,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// HTTP headers exposed by the Verified LLM demo on `POST /v1/chat/completions`.
pub const HTTP_HEADER_POG_RECEIPT_ID: &str = "X-PoG-Receipt-Id";
pub const HTTP_HEADER_POG_RECEIPT_SHA256: &str = "X-PoG-Receipt-Sha256";
pub const HTTP_HEADER_POG_COMMITMENT_SALT: &str = "X-PoG-Commitment-Salt";
pub const HTTP_HEADER_POG_CLIENT_NONCE: &str = "X-PoG-Client-Nonce";
pub const CLAIM_MODE_CONFIDENTIAL_CPU_TEE_INFERENCE: &str = "confidential-cpu-tee-inference";
pub const LLM_DEMO_DEFAULT_AUDIENCE: &str = "https://llm.proofofgeography.com";

/// Pinned redistributable open-weight model identity (`Qwen/Qwen2.5-0.5B-Instruct-GGUF`, Apache-2.0).
pub const PINNED_MODEL_ID: &str = "qwen2.5-0.5b-instruct-q4_k_m";
pub const PINNED_MODEL_REPO: &str = "Qwen/Qwen2.5-0.5B-Instruct-GGUF";
pub const PINNED_MODEL_WEIGHTS_FILE: &str = "qwen2.5-0.5b-instruct-q4_k_m.gguf";
pub const PINNED_MODEL_WEIGHTS_SHA256: &str =
    "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db";
pub const PINNED_MODEL_TOKENIZER_FILE: &str = "tokenizer.json";
pub const PINNED_MODEL_TOKENIZER_SHA256: &str =
    "c0382117ea329cdf097041132f6d735924b697924d6f6fc3945713e96ce87539";
pub const PINNED_MODEL_LICENSE: &str = "Apache-2.0";
pub const PINNED_MODEL_LICENSE_SHA256: &str =
    "832dd9e00a68dd83b3c3fb9f5588dad7dcf337a0db50f7d9483f310cd292e92e";
pub const PINNED_INFERENCE_ENGINE: &str = "candle-quantized-qwen2-cpu";

/// Privacy-preserving blinded SHA-256 request commitment.
///
/// The 256-bit `salt_hex` is returned ONLY over the caller's live TLS 1.3 connection in
/// `X-PoG-Commitment-Salt` and is NEVER stored in `/v1/receipts/{id}` or logged, preventing
/// offline dictionary attacks on short prompts even if the receipt JSON is shared publicly.
pub fn compute_blinded_request_commitment(
    salt_hex: &str,
    client_nonce_hex: &str,
    model_id: &str,
    raw_request_bytes: &[u8],
) -> String {
    let mut h = Sha256::new();
    h.update(b"pog-cpu-inf-req-v1\n");
    h.update(salt_hex.trim().to_ascii_lowercase().as_bytes());
    h.update(b"\n");
    h.update(client_nonce_hex.trim().to_ascii_lowercase().as_bytes());
    h.update(b"\n");
    h.update(model_id.as_bytes());
    h.update(b"\n");
    h.update(raw_request_bytes);
    hex::encode(h.finalize())
}

/// Privacy-preserving blinded SHA-256 output commitment chained to `request_commitment_hex` and
/// the EXACT delivered HTTP response bytes (including JSON OpenAI choices/model/usage).
pub fn compute_blinded_output_commitment(
    salt_hex: &str,
    request_commitment_hex: &str,
    raw_response_bytes: &[u8],
) -> String {
    let mut h = Sha256::new();
    h.update(b"pog-cpu-inf-out-v1\n");
    h.update(salt_hex.trim().to_ascii_lowercase().as_bytes());
    h.update(b"\n");
    h.update(request_commitment_hex.trim().to_ascii_lowercase().as_bytes());
    h.update(b"\n");
    h.update(raw_response_bytes);
    hex::encode(h.finalize())
}

/// Compute canonical SHA-256 digest of a serialized `TeeAttestationQuote`.
pub fn compute_hardware_quote_digest(quote: &TeeAttestationQuote) -> String {
    let bytes = serde_json::to_vec(quote).unwrap_or_default();
    hex::encode(Sha256::digest(&bytes))
}

/// Pinned model weights, license, and CPU-only runtime identity attested inside the receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRuntimeIdentity {
    pub model_id: String,
    pub model_repo: String,
    pub weights_filename: String,
    pub weights_sha256_hex: String,
    pub tokenizer_sha256_hex: String,
    pub license: String,
    pub license_sha256_hex: String,
    pub inference_engine: String,
    pub runtime_version: String,
    pub git_revision: String,
    pub cpu_only: bool,
    pub remote_upstream_disabled: bool,
    pub fallback_disabled: bool,
    pub prompt_output_logging_disabled: bool,
}

impl ModelRuntimeIdentity {
    pub fn pinned_qwen25_05b(git_revision: impl Into<String>) -> Self {
        Self {
            model_id: PINNED_MODEL_ID.into(),
            model_repo: PINNED_MODEL_REPO.into(),
            weights_filename: PINNED_MODEL_WEIGHTS_FILE.into(),
            weights_sha256_hex: PINNED_MODEL_WEIGHTS_SHA256.into(),
            tokenizer_sha256_hex: PINNED_MODEL_TOKENIZER_SHA256.into(),
            license: PINNED_MODEL_LICENSE.into(),
            license_sha256_hex: PINNED_MODEL_LICENSE_SHA256.into(),
            inference_engine: PINNED_INFERENCE_ENGINE.into(),
            runtime_version: env!("CARGO_PKG_VERSION").into(),
            git_revision: git_revision.into(),
            cpu_only: true,
            remote_upstream_disabled: true,
            fallback_disabled: true,
            prompt_output_logging_disabled: true,
        }
    }
}

/// Strictly separated geographic proof status (NEVER conflated with inference TEE attestation!).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeographicProofStatus {
    /// Verified by >= `min_anchors` hardware-attested anchors across >= `min_cloud_providers`
    /// independent clouds, excluding the prover itself, under conservative Vacuum `c₀`.
    VerifiedProductionHardwareQuorum,
    /// Production multi-cloud hardware TEE anchor quorum is not yet available (e.g., published
    /// anchors are still `SoftwareDev` diagnostic nodes); location is UNPROVEN.
    InsufficientProductionHardwareAnchors,
    /// Out-of-band PoG evidence bundle is absent or failed integrity/binding checks.
    UnverifiedOrMissingEvidence,
}

/// Transparent diagnostic observation from the existing non-production diagnostic fleet.
/// Explicitly marked `diagnostic_only = true` and NEVER counted toward geographic proof!
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticAnchorObservation {
    pub anchor_id: String,
    pub cloud_provider: String,
    pub region: String,
    pub city: String,
    pub rtt_min_ms: f64,
    pub diagnostic_only: bool,
    pub measured_at_unix_s: u64,
}

/// Post-execution signed receipt issued strictly AFTER the measured CPU TEE completes generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialCpuInferenceReceipt {
    pub version: u8,
    pub receipt_id: String,
    pub claim_type: String,
    pub client_nonce_hex: String,
    pub client_nonce_supplied_by_caller: bool,
    pub request_commitment_hex: String,
    pub output_commitment_hex: String,
    pub response_http_status: u16,
    pub model_runtime: ModelRuntimeIdentity,
    pub prover_pk_hex: String,
    pub workload_measurement_hex: String,
    pub tls_session_binding: Option<TlsSessionBinding>,
    pub hardware_attestation_digest_hex: String,
    pub pog_bundle_hash_hex: Option<String>,
    pub pog_epoch_challenge_hex: Option<String>,
    pub execution_started_at_unix_s: u64,
    pub execution_completed_at_unix_s: u64,
    pub prover_signature_hex: String,
}

impl ConfidentialCpuInferenceReceipt {
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
            None => "MISSING_TLS_SESSION_BINDING".into(),
        };
        let m = &self.model_runtime;
        format!(
            "CONFIDENTIAL_CPU_INFERENCE_RECEIPT_V1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            self.version,
            self.receipt_id,
            self.claim_type,
            self.client_nonce_hex.trim().to_ascii_lowercase(),
            self.client_nonce_supplied_by_caller,
            self.request_commitment_hex.trim().to_ascii_lowercase(),
            self.output_commitment_hex.trim().to_ascii_lowercase(),
            self.response_http_status,
            m.model_id,
            m.model_repo,
            m.weights_filename,
            m.weights_sha256_hex.trim().to_ascii_lowercase(),
            m.tokenizer_sha256_hex.trim().to_ascii_lowercase(),
            m.license,
            m.license_sha256_hex.trim().to_ascii_lowercase(),
            m.inference_engine,
            m.git_revision,
            m.cpu_only,
            m.remote_upstream_disabled,
            m.fallback_disabled,
            m.prompt_output_logging_disabled,
            self.prover_pk_hex.trim().to_ascii_lowercase(),
            self.workload_measurement_hex.trim().to_ascii_lowercase(),
            tls_part,
            self.hardware_attestation_digest_hex.trim().to_ascii_lowercase(),
            self.pog_bundle_hash_hex
                .as_deref()
                .unwrap_or("NONE")
                .trim()
                .to_ascii_lowercase(),
            self.pog_epoch_challenge_hex
                .as_deref()
                .unwrap_or("NONE")
                .trim()
                .to_ascii_lowercase(),
            self.execution_started_at_unix_s,
            self.execution_completed_at_unix_s,
        )
        .into_bytes()
    }

    pub fn sign(&mut self, kp: &WorkloadKeypair) {
        self.prover_signature_hex = hex::encode(kp.sign(&self.signing_payload()));
    }

    pub fn verify_signature(&self, expected_prover_pk_hex: &str) -> Result<(), ProtoError> {
        let sig_bytes = hex::decode(self.prover_signature_hex.trim()).map_err(|e| {
            ProtoError::SignatureError(format!("bad CPU inference receipt sig hex: {e}"))
        })?;
        WorkloadKeypair::verify_with_hex(expected_prover_pk_hex, &self.signing_payload(), &sig_bytes)
            .map_err(|e| {
                ProtoError::SignatureError(format!("CPU inference receipt Ed25519 sig invalid: {e}"))
            })
    }

    pub fn sha256_hex(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        hex::encode(Sha256::digest(&bytes))
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

/// Client-side observed transcript saved ONLY locally by an independent verifying client (NEVER
/// stored on the server!). Enables 100% offline reproducible verification & tamper tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientObservedEvidence {
    pub endpoint_url: String,
    pub client_nonce_hex: String,
    pub commitment_salt_hex: String,
    pub tls_exporter_ekm_hex: String,
    pub server_cert_sha256_hex: String,
    pub expected_tls_connection_request_seq: Option<u64>,
    pub raw_request_body: String,
    pub raw_response_body: String,
    pub observed_at_unix_s: u64,
}

/// Full downloadable evidence bundle returned by `GET /v1/receipts/{receipt_id}` (with zero prompt
/// or output plaintext!) and optionally enriched locally by an independent client with
/// `client_observed_evidence` and `google_jwks_snapshot` for offline verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialCpuEvidenceBundle {
    pub version: u8,
    pub receipt: ConfidentialCpuInferenceReceipt,
    pub hardware_quote: TeeAttestationQuote,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pog_proof_bundle: Option<GeoProofBundle>,
    #[serde(default)]
    pub diagnostic_anchor_rtts: Vec<DiagnosticAnchorObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub google_jwks_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_observed: Option<ClientObservedEvidence>,
}

/// Fail-closed policy for verifying the CPU-only Confidential TEE Inference Demo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInferenceVerificationPolicy {
    pub geo_policy: VerificationPolicy,
    /// Expected pinned container digest(s) (`sha256:...`). Non-empty in production!
    #[serde(default)]
    pub allowed_container_digests: Vec<String>,
    /// Expected GCP Confidential Space OIDC audience (defaults to `https://llm.proofofgeography.com`).
    pub expected_oidc_audience: String,
    /// Expected pinned model ID (defaults to `qwen2.5-0.5b-instruct-q4_k_m`).
    pub expected_model_id: String,
    /// Expected pinned model weights SHA-256 hex.
    pub expected_weights_sha256_hex: String,
    /// Expected pinned tokenizer SHA-256 hex.
    pub expected_tokenizer_sha256_hex: String,
    /// Expected pinned license identifier & SHA-256.
    pub expected_license: String,
    pub expected_license_sha256_hex: String,
    /// Require fresh caller-supplied client nonce (true for independent clients; false only when
    /// inspecting a stock-SDK response that omitted `X-PoG-Client-Nonce`).
    pub require_caller_supplied_nonce: bool,
    pub max_receipt_age_seconds: u64,
}

impl CpuInferenceVerificationPolicy {
    pub fn production(allowed_container_digests: Vec<String>, google_jwks_json: String) -> Self {
        let mut tee_policy = AttestationPolicy::production();
        tee_policy.allowed_container_digests = allowed_container_digests.clone();
        tee_policy.expected_gcp_cs_audience = Some(LLM_DEMO_DEFAULT_AUDIENCE.into());
        tee_policy.trusted_gcp_cs_jwks_json = Some(google_jwks_json);
        Self {
            geo_policy: VerificationPolicy {
                tee_policy,
                ..Default::default()
            },
            allowed_container_digests,
            expected_oidc_audience: LLM_DEMO_DEFAULT_AUDIENCE.into(),
            expected_model_id: PINNED_MODEL_ID.into(),
            expected_weights_sha256_hex: PINNED_MODEL_WEIGHTS_SHA256.into(),
            expected_tokenizer_sha256_hex: PINNED_MODEL_TOKENIZER_SHA256.into(),
            expected_license: PINNED_MODEL_LICENSE.into(),
            expected_license_sha256_hex: PINNED_MODEL_LICENSE_SHA256.into(),
            require_caller_supplied_nonce: true,
            max_receipt_age_seconds: 600,
        }
    }
}

/// Authoritative report strictly separating:
/// 1. `inference_tee_verified` (hardware TEE + container digest + TLS 1.3 EKM + model + commitments)
/// 2. `geographic_proof_verified` / `geographic_proof_status` (multi-cloud hardware PoG quorum)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInferenceVerificationReport {
    /// True ONLY when hardware TEE chain, measured workload, enclave keys, end-to-end TLS 1.3 EKM,
    /// fresh nonce, blinded request/output commitments, pinned model/weights/license, and
    /// post-execution timing ALL pass fail-closed!
    pub inference_tee_verified: bool,
    /// True ONLY when a production multi-cloud hardware TEE anchor quorum verifies server geography
    /// (excluding the prover itself and excluding `SoftwareDev` diagnostic nodes).
    pub geographic_proof_verified: bool,
    pub geographic_proof_status: GeographicProofStatus,
    pub hardware_tee_verified: bool,
    pub tls_channel_binding_verified: bool,
    pub request_output_commitments_verified: bool,
    pub model_runtime_pinned_verified: bool,
    pub prover_pk_hex: String,
    pub verified_container_digest: Option<String>,
    /// GCP cloud-attested VM zone from `submods.gce.zone` (cloud metadata ONLY — NOT speed-of-light geographic proof!).
    pub gcp_cloud_metadata_zone: Option<String>,
    pub proven_vacuum_max_radius_km: Option<f64>,
    pub inference_failure_reasons: Vec<String>,
    pub geographic_failure_reasons: Vec<String>,
    pub geo_report: Option<ProofVerificationReport>,
    pub diagnostic_anchor_count: usize,
    pub verification_notes: Vec<String>,
}

fn is_hex_len(s: &str, len: usize) -> bool {
    let t = s.trim();
    t.len() == len && t.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Independently verify a `ConfidentialCpuEvidenceBundle` fail-closed.
///
/// Never trusts the demo website: validates hardware attestation against Google Confidential Space
/// JWKS, validates enclave Ed25519 signature + TLS 1.3 EKM channel binding + blinded commitments
/// against client-observed bytes, and evaluates production PoG geography separately.
pub fn verify_cpu_inference_evidence(
    evidence: &ConfidentialCpuEvidenceBundle,
    client_observed: &ClientObservedEvidence,
    grid: &AnchorGrid,
    policy: &CpuInferenceVerificationPolicy,
    now_unix_s: u64,
) -> Result<CpuInferenceVerificationReport, ProtoError> {
    let receipt = &evidence.receipt;
    let mut inf_failures = Vec::new();
    let mut geo_failures = Vec::new();
    let mut notes = Vec::new();

    // 1. Validate receipt structural & CPU-only no-upstream invariants.
    if receipt.claim_type != CLAIM_MODE_CONFIDENTIAL_CPU_TEE_INFERENCE {
        inf_failures.push(format!(
            "unexpected claim_type {:?} (expected {:?})",
            receipt.claim_type, CLAIM_MODE_CONFIDENTIAL_CPU_TEE_INFERENCE
        ));
    }
    let m = &receipt.model_runtime;
    let mut model_ok = true;
    if !m.cpu_only || !m.remote_upstream_disabled || !m.fallback_disabled || !m.prompt_output_logging_disabled {
        model_ok = false;
        inf_failures.push(
            "runtime must attest cpu_only=true, remote_upstream_disabled=true, fallback_disabled=true, prompt_output_logging_disabled=true"
                .into(),
        );
    }
    if m.model_id != policy.expected_model_id {
        model_ok = false;
        inf_failures.push(format!(
            "model_id {:?} != expected {:?}",
            m.model_id, policy.expected_model_id
        ));
    }
    if !m
        .weights_sha256_hex
        .eq_ignore_ascii_case(&policy.expected_weights_sha256_hex)
    {
        model_ok = false;
        inf_failures.push(format!(
            "model weights SHA-256 {} != pinned {}",
            m.weights_sha256_hex, policy.expected_weights_sha256_hex
        ));
    }
    if !m
        .tokenizer_sha256_hex
        .eq_ignore_ascii_case(&policy.expected_tokenizer_sha256_hex)
    {
        model_ok = false;
        inf_failures.push(format!(
            "tokenizer SHA-256 {} != pinned {}",
            m.tokenizer_sha256_hex, policy.expected_tokenizer_sha256_hex
        ));
    }
    if m.license != policy.expected_license
        || !m
            .license_sha256_hex
            .eq_ignore_ascii_case(&policy.expected_license_sha256_hex)
    {
        model_ok = false;
        inf_failures.push("model license or LICENSE SHA-256 does not match pinned Apache-2.0".into());
    }

    // 2. Verify hardware TEE quote binding (GCP Confidential Space Intel TDX RS256 OIDC JWT or
    //    other hardware TEE, strictly rejecting SoftwareDev in production!).
    let actual_quote_digest = compute_hardware_quote_digest(&evidence.hardware_quote);
    if !receipt
        .hardware_attestation_digest_hex
        .eq_ignore_ascii_case(&actual_quote_digest)
    {
        inf_failures.push(
            "receipt.hardware_attestation_digest_hex does not match attached hardware_quote (mixed receipt/quote rejected)"
                .into(),
        );
    }
    if !evidence
        .hardware_quote
        .public_key_hex
        .eq_ignore_ascii_case(&receipt.prover_pk_hex)
    {
        inf_failures.push(
            "hardware_quote.public_key_hex != receipt.prover_pk_hex (mixed prover/receipt rejected)"
                .into(),
        );
    }
    if !evidence
        .hardware_quote
        .workload_measurement_hex
        .eq_ignore_ascii_case(&receipt.workload_measurement_hex)
    {
        inf_failures.push(
            "hardware_quote.workload_measurement_hex != receipt.workload_measurement_hex".into(),
        );
    }

    let mut hardware_tee_verified = false;
    let mut verified_container_digest: Option<String> = None;
    let mut gcp_cloud_metadata_zone: Option<String> = None;

    if !policy.geo_policy.tee_policy.allow_software_dev
        && evidence.hardware_quote.vendor == TeeVendor::SoftwareDev
    {
        inf_failures.push("SoftwareDev quote forbidden in production (fail-closed)".into());
    } else if let Some(WorkloadAttestation::GcpConfidentialSpaceOidc {
        jwt,
        audience,
        image_digest,
        ..
    }) = evidence.hardware_quote.workload_attestation.as_ref()
    {
        let jwks_str = policy
            .geo_policy
            .tee_policy
            .trusted_gcp_cs_jwks_json
            .as_deref()
            .or(evidence.google_jwks_json.as_deref());
        match jwks_str {
            None => {
                inf_failures.push(
                    "missing trusted Google Confidential Space JWKS (cannot verify RS256 OIDC hardware chain)"
                        .into(),
                );
            }
            Some(js) => match serde_json::from_str::<JwkSet>(js) {
                Err(e) => inf_failures.push(format!("invalid Google JWKS JSON: {e}")),
                Ok(jwk_set) => {
                    if audience != &policy.expected_oidc_audience {
                        inf_failures.push(format!(
                            "OIDC audience {:?} != expected {:?}",
                            audience, policy.expected_oidc_audience
                        ));
                    }
                    // The quote's `nonce_hex` must be bound into `eat_nonce` along with `prover_pk_hex`!
                    let mut tee_pol = policy.geo_policy.tee_policy.clone();
                    if !policy.allowed_container_digests.is_empty() {
                        tee_pol.allowed_container_digests = policy.allowed_container_digests.clone();
                    }
                    match verify_gcp_confidential_space_jwt(
                        jwt,
                        &jwk_set.keys,
                        &policy.expected_oidc_audience,
                        &receipt.prover_pk_hex,
                        &evidence.hardware_quote.nonce_hex,
                        &tee_pol,
                        now_unix_s,
                    ) {
                        Ok(VerifiedGcpConfidentialSpaceToken {
                            image_digest: ver_digest,
                            image_digest_hex: ver_hex,
                            gce_zone,
                            ..
                        }) => {
                            if !ver_digest.eq_ignore_ascii_case(image_digest)
                                || !ver_hex.eq_ignore_ascii_case(&receipt.workload_measurement_hex)
                            {
                                inf_failures.push(
                                    "verified Confidential Space container image_digest mismatches receipt.workload_measurement_hex"
                                        .into(),
                                );
                            } else {
                                hardware_tee_verified = true;
                                verified_container_digest = Some(ver_digest);
                                gcp_cloud_metadata_zone = gce_zone;
                            }
                        }
                        Err(e) => {
                            inf_failures.push(format!(
                                "GCP Confidential Space Intel TDX OIDC verification failed: {e}"
                            ));
                        }
                    }
                }
            },
        }
    } else {
        // Fallback to general hardware TEE quote verifier (AWS Nitro / SEV-SNP / TDX DCAP / Azure CVM).
        let nonce_bytes = hex::decode(&evidence.hardware_quote.nonce_hex).unwrap_or_default();
        match verify_quote(
            &evidence.hardware_quote,
            &nonce_bytes,
            &policy.geo_policy.tee_policy,
            now_unix_s,
        ) {
            Ok(id) => {
                if id.vendor == TeeVendor::SoftwareDev
                    && !policy.geo_policy.tee_policy.allow_software_dev
                {
                    inf_failures.push("SoftwareDev quote rejected".into());
                } else {
                    hardware_tee_verified = true;
                    verified_container_digest = Some(id.workload_measurement_hex);
                }
            }
            Err(e) => inf_failures.push(format!("hardware TEE quote verification failed: {e}")),
        }
    }

    // 3. Verify end-to-end TLS 1.3 session binding against client's OWN observed TLS 1.3 EKM!
    let mut tls_ok = false;
    if !is_hex_len(&client_observed.tls_exporter_ekm_hex, 64) {
        inf_failures.push("client_observed.tls_exporter_ekm_hex must be 64 hex chars".into());
    }
    if !is_hex_len(&client_observed.server_cert_sha256_hex, 64) {
        inf_failures.push("client_observed.server_cert_sha256_hex must be 64 hex chars".into());
    }
    match receipt.tls_session_binding.as_ref() {
        None => inf_failures.push("receipt missing tls_session_binding (fail-closed)".into()),
        Some(tls) => {
            let mut ok = true;
            if !tls.terminated_in_attested_runtime {
                ok = false;
                inf_failures.push("TLS terminated outside attested runtime (proxy TLS hop rejected)".into());
            }
            if tls.tls_protocol_version != "TLSv1.3" {
                ok = false;
                inf_failures.push(format!("TLS protocol must be TLSv1.3, got {:?}", tls.tls_protocol_version));
            }
            if tls.exporter_label != TLS_EXPORTER_LABEL {
                ok = false;
                inf_failures.push(format!("TLS exporter label {:?} != {:?}", tls.exporter_label, TLS_EXPORTER_LABEL));
            }
            if !is_hex_len(&tls.tls_exporter_ekm_hex, 64)
                || !tls
                    .tls_exporter_ekm_hex
                    .trim()
                    .eq_ignore_ascii_case(client_observed.tls_exporter_ekm_hex.trim())
            {
                ok = false;
                inf_failures.push(
                    "TLS 1.3 Exported Keying Material mismatch (mixed TLS session, reused cert, or MITM proxy rejected)"
                        .into(),
                );
            }
            if !is_hex_len(&tls.server_cert_sha256_hex, 64)
                || !tls
                    .server_cert_sha256_hex
                    .trim()
                    .eq_ignore_ascii_case(client_observed.server_cert_sha256_hex.trim())
            {
                ok = false;
                inf_failures.push("TLS leaf certificate SHA-256 mismatch".into());
            }
            if let Err(e) = verify_tls_cert_binding(
                &receipt.prover_pk_hex,
                &tls.server_cert_sha256_hex,
                &tls.cert_prover_binding_sig_hex,
            ) {
                ok = false;
                inf_failures.push(format!("TLS leaf cert binding to enclave key failed: {e}"));
            }
            if tls.tls_connection_request_seq == 0 {
                ok = false;
                inf_failures.push("tls_connection_request_seq must be >= 1".into());
            }
            if let Some(exp_seq) = client_observed.expected_tls_connection_request_seq {
                if tls.tls_connection_request_seq != exp_seq {
                    ok = false;
                    inf_failures.push(format!(
                        "tls_connection_request_seq {} != expected {} (cross-request swap rejected)",
                        tls.tls_connection_request_seq, exp_seq
                    ));
                }
            }
            tls_ok = ok;
        }
    }

    // 4. Verify fresh client nonce & blinded privacy-preserving request/output commitments!
    let mut commitments_ok = true;
    let exp_nonce = client_observed.client_nonce_hex.trim().to_ascii_lowercase();
    if exp_nonce.len() < 32 || !exp_nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
        commitments_ok = false;
        inf_failures.push("client_nonce_hex must be >= 32 hex chars (16 random bytes)".into());
    } else if !receipt.client_nonce_hex.eq_ignore_ascii_case(&exp_nonce) {
        commitments_ok = false;
        inf_failures.push("stale or mismatched client_nonce_hex (replay rejected)".into());
    }
    if policy.require_caller_supplied_nonce && !receipt.client_nonce_supplied_by_caller {
        commitments_ok = false;
        inf_failures.push(
            "receipt indicates client_nonce was not supplied by caller (stock client without X-PoG-Client-Nonce)".into(),
        );
    }
    if !is_hex_len(&client_observed.commitment_salt_hex, 64) {
        commitments_ok = false;
        inf_failures.push("commitment_salt_hex must be 64 hex chars (32 random bytes)".into());
    } else {
        let exp_req_c = compute_blinded_request_commitment(
            &client_observed.commitment_salt_hex,
            &exp_nonce,
            &receipt.model_runtime.model_id,
            client_observed.raw_request_body.as_bytes(),
        );
        if !receipt
            .request_commitment_hex
            .eq_ignore_ascii_case(&exp_req_c)
        {
            commitments_ok = false;
            inf_failures.push(
                "request_commitment_hex mismatch (request modified or wrong salt/nonce)".into(),
            );
        }
        let exp_out_c = compute_blinded_output_commitment(
            &client_observed.commitment_salt_hex,
            &exp_req_c,
            client_observed.raw_response_body.as_bytes(),
        );
        if !receipt
            .output_commitment_hex
            .eq_ignore_ascii_case(&exp_out_c)
        {
            commitments_ok = false;
            inf_failures.push(
                "output_commitment_hex mismatch (delivered output modified or swapped receipt)"
                    .into(),
            );
        }
    }

    // 5. Post-execution timing & freshness checks.
    let max_skew = policy.geo_policy.tee_policy.max_future_skew_seconds;
    if receipt.execution_started_at_unix_s == 0
        || receipt.execution_completed_at_unix_s == 0
        || receipt.execution_completed_at_unix_s < receipt.execution_started_at_unix_s
    {
        inf_failures.push("invalid post-execution timestamps".into());
    }
    if now_unix_s
        > receipt
            .execution_completed_at_unix_s
            .saturating_add(policy.max_receipt_age_seconds)
    {
        inf_failures.push(format!(
            "inference receipt expired (age {}s > max {}s)",
            now_unix_s.saturating_sub(receipt.execution_completed_at_unix_s),
            policy.max_receipt_age_seconds
        ));
    }
    if receipt.execution_completed_at_unix_s > now_unix_s.saturating_add(max_skew) {
        inf_failures.push("inference receipt completed_at timestamp is in the future".into());
    }

    // 6. Enclave nonexportable Ed25519 signature over receipt.
    if let Err(e) = receipt.verify_signature(&receipt.prover_pk_hex) {
        inf_failures.push(format!("enclave Ed25519 receipt signature invalid: {e}"));
    }

    // 7. SEPARATE Geographic Proof verification (never conflated with inference TEE attestation;
    //    never counts the prover as its own anchor; never claims a location from SoftwareDev nodes!).
    let mut geographic_proof_verified = false;
    let mut geographic_proof_status = GeographicProofStatus::UnverifiedOrMissingEvidence;
    let mut geo_report: Option<ProofVerificationReport> = None;
    let mut proven_vacuum_max_radius_km: Option<f64> = None;

    match (receipt.pog_bundle_hash_hex.as_deref(), evidence.pog_proof_bundle.as_ref()) {
        (Some(signed_hash), Some(bundle)) => {
            let actual_hash = bundle.record_hash_hex();
            if !signed_hash.eq_ignore_ascii_case(&actual_hash) {
                geo_failures.push(
                    "receipt.pog_bundle_hash_hex does not match attached pog_proof_bundle (mismatched PoG evidence)"
                        .into(),
                );
            } else if !bundle
                .prover_quote
                .public_key_hex
                .eq_ignore_ascii_case(&receipt.prover_pk_hex)
            {
                geo_failures.push(
                    "pog_proof_bundle prover public key does not match inference receipt prover_pk_hex (mixed prover rejected)"
                        .into(),
                );
            } else {
                // Hard anti-self-anchoring invariant: reject if prover tries to count itself as an anchor!
                let self_anchored = bundle.receipts.iter().any(|r| {
                    grid.by_id(&r.anchor_id)
                        .map(|a| a.public_key_hex.eq_ignore_ascii_case(&receipt.prover_pk_hex))
                        .unwrap_or(false)
                });
                if self_anchored {
                    geo_failures.push(
                        "prover cannot count itself as its own geographic anchor (self-anchor rejected)"
                            .into(),
                    );
                } else {
                    match verify_proof_bundle(bundle, grid, &policy.geo_policy, now_unix_s) {
                        Ok(rep) => {
                            if rep.overall_valid && rep.hardware_attested {
                                geographic_proof_verified = true;
                                geographic_proof_status =
                                    GeographicProofStatus::VerifiedProductionHardwareQuorum;
                                proven_vacuum_max_radius_km =
                                    rep.tier1a_vacuum.as_ref().map(|c| c.proven_max_radius_km);
                            } else {
                                geographic_proof_status =
                                    GeographicProofStatus::InsufficientProductionHardwareAnchors;
                                if !rep.hardware_attested {
                                    geo_failures.push(
                                        "no production multi-cloud hardware TEE anchor quorum yet (SoftwareDev diagnostic nodes excluded from geographic proof)"
                                            .into(),
                                    );
                                }
                                for r in &rep.failure_reasons {
                                    geo_failures.push(r.clone());
                                }
                            }
                            geo_report = Some(rep);
                        }
                        Err(e) => {
                            geographic_proof_status =
                                GeographicProofStatus::InsufficientProductionHardwareAnchors;
                            geo_failures.push(format!("PoG bundle verification failed: {e}"));
                        }
                    }
                }
            }
        }
        (None, None) => {
            geographic_proof_status = GeographicProofStatus::InsufficientProductionHardwareAnchors;
            geo_failures.push(
                "no production multi-cloud hardware TEE anchor quorum bundle attached yet; server geographic location remains UNPROVEN (separate from verified inference TEE)"
                    .into(),
            );
        }
        _ => {
            geo_failures.push(
                "mismatch between receipt.pog_bundle_hash_hex and presence of pog_proof_bundle"
                    .into(),
            );
        }
    }

    if let Some(ref z) = gcp_cloud_metadata_zone {
        notes.push(format!(
            "GCP CLOUD METADATA (NOT SPEED-OF-LIGHT PROOF): Confidential Space OIDC JWT reports submods.gce.zone={z:?}; independent physical geography requires verified multi-cloud hardware TEE anchors."
        ));
    }
    if !evidence.diagnostic_anchor_rtts.is_empty() {
        notes.push(format!(
            "DIAGNOSTIC OBSERVATIONS ONLY: {} non-production SoftwareDev anchor RTT(s) recorded for transparency and strictly excluded from geographic_proof_verified.",
            evidence.diagnostic_anchor_rtts.len()
        ));
    }

    let inference_tee_verified =
        inf_failures.is_empty() && hardware_tee_verified && tls_ok && commitments_ok && model_ok;

    Ok(CpuInferenceVerificationReport {
        inference_tee_verified,
        geographic_proof_verified,
        geographic_proof_status,
        hardware_tee_verified,
        tls_channel_binding_verified: tls_ok,
        request_output_commitments_verified: commitments_ok,
        model_runtime_pinned_verified: model_ok,
        prover_pk_hex: receipt.prover_pk_hex.clone(),
        verified_container_digest,
        gcp_cloud_metadata_zone,
        proven_vacuum_max_radius_km,
        inference_failure_reasons: inf_failures,
        geographic_failure_reasons: geo_failures,
        geo_report,
        diagnostic_anchor_count: evidence.diagnostic_anchor_rtts.len(),
        verification_notes: notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::AnchorDescriptor;
    use crate::inference::sign_tls_cert_binding;
    use crate::wire::AnchorReceipt;
    use base64::engine::general_purpose::STANDARD as B64_STD;
    use ed25519_dalek::SigningKey;
    use pog_geo::LatLon;
    use pog_tee::{GCP_CS_ISSUER, RsaJwk};
    use rand::rngs::OsRng;
    use ring::rand::SystemRandom;
    use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};

    fn parse_pkcs1_rsa_pub_ne(der: &[u8]) -> (&[u8], &[u8]) {
        fn read_tlv(b: &[u8]) -> (u8, &[u8], &[u8]) {
            let tag = b[0];
            let (len, off) = if b[1] & 0x80 == 0 {
                (b[1] as usize, 2)
            } else {
                let n = (b[1] & 0x7f) as usize;
                let mut v = 0usize;
                for &x in &b[2..2 + n] {
                    v = (v << 8) | (x as usize);
                }
                (v, 2 + n)
            };
            (tag, &b[off..off + len], &b[off + len..])
        }
        let (_, seq, _) = read_tlv(der);
        let (_, n_raw, rest) = read_tlv(seq);
        let (_, e_raw, _) = read_tlv(rest);
        (
            n_raw.strip_prefix(&[0]).unwrap_or(n_raw),
            e_raw.strip_prefix(&[0]).unwrap_or(e_raw),
        )
    }

    fn make_test_google_jwks_and_jwt(
        pk_hex: &str,
        quote_nonce_hex: &str,
        image_digest: &str,
        now: u64,
    ) -> (String, String) {
        let child = std::process::Command::new("openssl")
            .args(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pem_out = child.wait_with_output().unwrap();
        let mut pk8 = std::process::Command::new("openssl")
            .args(["pkcs8", "-topk8", "-nocrypt", "-outform", "DER"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        {
            use std::io::Write;
            pk8.stdin.as_mut().unwrap().write_all(&pem_out.stdout).unwrap();
        }
        let der_out = pk8.wait_with_output().unwrap();
        let kp = RsaKeyPair::from_pkcs8(&der_out.stdout)
            .or_else(|_| RsaKeyPair::from_der(&der_out.stdout))
            .unwrap();
        let (n, e) = parse_pkcs1_rsa_pub_ne(kp.public().as_ref());
        let jwk = RsaJwk {
            kty: "RSA".into(),
            kid: Some("cs-demo-kid-1".into()),
            alg: Some("RS256".into()),
            n: B64_URL.encode(n),
            e: B64_URL.encode(e),
        };
        let jwks_json = serde_json::to_string(&JwkSet { keys: vec![jwk] }).unwrap();

        let claims = serde_json::json!({
            "iss": GCP_CS_ISSUER,
            "aud": LLM_DEMO_DEFAULT_AUDIENCE,
            "iat": now - 5,
            "nbf": now - 5,
            "exp": now + 3600,
            "hwmodel": "GCP_INTEL_TDX",
            "swname": "CONFIDENTIAL_SPACE",
            "secboot": true,
            "dbgstat": "disabled-since-boot",
            "eat_nonce": [pk_hex, quote_nonce_hex],
            "submods": {
                "confidential_space": { "support_attributes": ["LATEST", "STABLE", "USABLE"] },
                "gce": { "zone": "europe-west9-b", "project_id": "pog-pilot-20261125", "instance_name": "gcp-europe-west9-paris" },
                "container": { "image_digest": image_digest, "cmd_override": [], "env_override": {} }
            }
        });
        let hdr = B64_URL.encode(
            serde_json::json!({"alg":"RS256","typ":"JWT","kid":"cs-demo-kid-1"})
                .to_string()
                .as_bytes(),
        );
        let pay = B64_URL.encode(claims.to_string().as_bytes());
        let input = format!("{hdr}.{pay}");
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; kp.public().modulus_len()];
        kp.sign(&RSA_PKCS1_SHA256, &rng, input.as_bytes(), &mut sig).unwrap();
        let jwt = format!("{input}.{}", B64_URL.encode(&sig));
        (jwks_json, jwt)
    }

    #[test]
    fn test_cpu_tee_inference_positive_and_all_offline_adversarial_rejections() {
        let now = 1_795_770_000u64;
        let kp = WorkloadKeypair::generate();
        let digest_hex = "aa".repeat(32);
        let image_digest = format!("sha256:{digest_hex}");
        let client_nonce = "11".repeat(32);
        let salt = "22".repeat(32);
        let tls_ekm = "33".repeat(32);
        let tls_cert = "44".repeat(32);
        let cert_sig = sign_tls_cert_binding(&kp, &tls_cert);

        let (jwks_json, jwt) =
            make_test_google_jwks_and_jwt(&kp.public_key_hex(), &client_nonce, &image_digest, now);

        let hw_quote = TeeAttestationQuote {
            vendor: TeeVendor::IntelTdx,
            public_key_hex: kp.public_key_hex(),
            workload_measurement_hex: digest_hex.clone(),
            report_data_hex: "00".repeat(64),
            nonce_hex: client_nonce.clone(),
            migration_disabled: true,
            debug_disabled: true,
            secure_tsc_enabled: true,
            gpu_binding: None,
            raw_quote_b64: B64_STD.encode(jwt.as_bytes()),
            vendor_cert_chain_pem: Vec::new(),
            workload_attestation: Some(WorkloadAttestation::GcpConfidentialSpaceOidc {
                jwt,
                audience: LLM_DEMO_DEFAULT_AUDIENCE.into(),
                image_digest: image_digest.clone(),
                hwmodel: "GCP_INTEL_TDX".into(),
                swname: "CONFIDENTIAL_SPACE".into(),
                raw_tdx_quote_b64: None,
            }),
            generated_at_unix_s: now,
        };

        let raw_req = r#"{"model":"qwen2.5-0.5b-instruct-q4_k_m","messages":[{"role":"user","content":"Hello from Paris?"}]}"#;
        let raw_resp = r#"{"id":"chatcmpl-1","object":"chat.completion","created":1795770001,"model":"qwen2.5-0.5b-instruct-q4_k_m","choices":[{"index":0,"message":{"role":"assistant","content":"Hello!"},"finish_reason":"stop"}]}"#;
        let req_c = compute_blinded_request_commitment(&salt, &client_nonce, PINNED_MODEL_ID, raw_req.as_bytes());
        let out_c = compute_blinded_output_commitment(&salt, &req_c, raw_resp.as_bytes());

        let mut receipt = ConfidentialCpuInferenceReceipt {
            version: 1,
            receipt_id: "rcpt-01".into(),
            claim_type: CLAIM_MODE_CONFIDENTIAL_CPU_TEE_INFERENCE.into(),
            client_nonce_hex: client_nonce.clone(),
            client_nonce_supplied_by_caller: true,
            request_commitment_hex: req_c,
            output_commitment_hex: out_c,
            response_http_status: 200,
            model_runtime: ModelRuntimeIdentity::pinned_qwen25_05b("test-rev"),
            prover_pk_hex: kp.public_key_hex(),
            workload_measurement_hex: digest_hex.clone(),
            tls_session_binding: Some(TlsSessionBinding {
                tls_protocol_version: "TLSv1.3".into(),
                exporter_label: TLS_EXPORTER_LABEL.into(),
                tls_exporter_ekm_hex: tls_ekm.clone(),
                server_cert_sha256_hex: tls_cert.clone(),
                cert_prover_binding_sig_hex: cert_sig,
                terminated_in_attested_runtime: true,
                tls_connection_request_seq: 1,
            }),
            hardware_attestation_digest_hex: compute_hardware_quote_digest(&hw_quote),
            pog_bundle_hash_hex: None,
            pog_epoch_challenge_hex: None,
            execution_started_at_unix_s: now,
            execution_completed_at_unix_s: now + 1,
            prover_signature_hex: String::new(),
        };
        receipt.sign(&kp);

        let evidence = ConfidentialCpuEvidenceBundle {
            version: 1,
            receipt: receipt.clone(),
            hardware_quote: hw_quote.clone(),
            pog_proof_bundle: None,
            diagnostic_anchor_rtts: vec![DiagnosticAnchorObservation {
                anchor_id: "fra-gcp".into(),
                cloud_provider: "gcp".into(),
                region: "europe-west3".into(),
                city: "Frankfurt".into(),
                rtt_min_ms: 9.2,
                diagnostic_only: true,
                measured_at_unix_s: now,
            }],
            google_jwks_json: Some(jwks_json.clone()),
            client_observed: None,
        };
        let observed = ClientObservedEvidence {
            endpoint_url: "https://llm.proofofgeography.com/v1/chat/completions".into(),
            client_nonce_hex: client_nonce.clone(),
            commitment_salt_hex: salt,
            tls_exporter_ekm_hex: tls_ekm,
            server_cert_sha256_hex: tls_cert,
            expected_tls_connection_request_seq: Some(1),
            raw_request_body: raw_req.into(),
            raw_response_body: raw_resp.into(),
            observed_at_unix_s: now + 2,
        };
        let grid = AnchorGrid {
            version: "2.0.0".into(),
            grid_name: "empty-prod".into(),
            description: "no prod hw anchors yet".into(),
            anchors: Vec::new(),
        };
        let pol = CpuInferenceVerificationPolicy::production(vec![image_digest.clone()], jwks_json);

        // 1. Legitimate run: inference_tee_verified = TRUE, geographic_proof_verified = FALSE (separate!)
        let rep = verify_cpu_inference_evidence(&evidence, &observed, &grid, &pol, now + 5).unwrap();
        assert!(rep.inference_tee_verified, "unexpected failures: {:?}", rep.inference_failure_reasons);
        assert!(rep.hardware_tee_verified);
        assert!(rep.tls_channel_binding_verified);
        assert!(rep.request_output_commitments_verified);
        assert!(rep.model_runtime_pinned_verified);
        assert_eq!(rep.gcp_cloud_metadata_zone.as_deref(), Some("europe-west9-b"));
        assert!(!rep.geographic_proof_verified);
        assert_eq!(rep.geographic_proof_status, GeographicProofStatus::InsufficientProductionHardwareAnchors);

        // 2. Modified output MUST FAIL CLOSED!
        let mut mod_out = observed.clone();
        mod_out.raw_response_body = mod_out.raw_response_body.replace("Hello!", "Tampered!");
        let r_out = verify_cpu_inference_evidence(&evidence, &mod_out, &grid, &pol, now + 5).unwrap();
        assert!(!r_out.inference_tee_verified);
        assert!(!r_out.request_output_commitments_verified);

        // 3. Stale / mismatched client nonce MUST FAIL CLOSED!
        let mut stale_nonce = observed.clone();
        stale_nonce.client_nonce_hex = "99".repeat(32);
        let r_nonce = verify_cpu_inference_evidence(&evidence, &stale_nonce, &grid, &pol, now + 5).unwrap();
        assert!(!r_nonce.inference_tee_verified);

        // 4. Mixed TLS session (different EKM) MUST FAIL CLOSED!
        let mut mixed_tls = observed.clone();
        mixed_tls.tls_exporter_ekm_hex = "77".repeat(32);
        let r_tls = verify_cpu_inference_evidence(&evidence, &mixed_tls, &grid, &pol, now + 5).unwrap();
        assert!(!r_tls.inference_tee_verified);
        assert!(!r_tls.tls_channel_binding_verified);

        // 5. Wrong container image digest MUST FAIL CLOSED!
        let mut wrong_img_pol = pol.clone();
        wrong_img_pol.allowed_container_digests = vec![format!("sha256:{}", "bb".repeat(32))];
        let r_img = verify_cpu_inference_evidence(&evidence, &observed, &grid, &wrong_img_pol, now + 5).unwrap();
        assert!(!r_img.inference_tee_verified);
        assert!(!r_img.hardware_tee_verified);

        // 6. Wrong model weights SHA-256 MUST FAIL CLOSED!
        let mut wrong_model_pol = pol.clone();
        wrong_model_pol.expected_weights_sha256_hex = "cc".repeat(32);
        let r_mod = verify_cpu_inference_evidence(&evidence, &observed, &grid, &wrong_model_pol, now + 5).unwrap();
        assert!(!r_mod.inference_tee_verified);
        assert!(!r_mod.model_runtime_pinned_verified);

        // 7. Mixed prover/receipt (quote signed for another keypair) MUST FAIL CLOSED!
        let other_kp = WorkloadKeypair::generate();
        let mut mixed_ev = evidence.clone();
        mixed_ev.hardware_quote.public_key_hex = other_kp.public_key_hex();
        let r_mix = verify_cpu_inference_evidence(&mixed_ev, &observed, &grid, &pol, now + 5).unwrap();
        assert!(!r_mix.inference_tee_verified);

        // 8. Prover attempting to count ITSELF as an anchor in pog_proof_bundle MUST FAIL geographic proof!
        let self_grid = AnchorGrid {
            version: "2.0.0".into(),
            grid_name: "self-anchor-attempt".into(),
            description: "test".into(),
            anchors: vec![AnchorDescriptor {
                anchor_id: "self-anchor".into(),
                cloud_provider: "gcp".into(),
                region: "europe-west9".into(),
                city: "Paris".into(),
                country_code: Some("FR".into()),
                tee_vendor: TeeVendor::IntelTdx,
                instance_type: "c3-standard-4".into(),
                location: LatLon::new(48.8566, 2.3522),
                endpoint_tcp: "34.1.13.45:7443".into(),
                endpoint_udp: "34.1.13.45:7444".into(),
                https_url: None,
                public_key_hex: kp.public_key_hex(), // SAME KEY AS PROVER!
                failure_domain: None,
                asn: None,
                diagnostic_only: false,
                coordinate_basis: None,
            }],
        };
        let sk_dummy = SigningKey::generate(&mut OsRng);
        let mut self_r = AnchorReceipt {
            anchor_id: "self-anchor".into(),
            cloud_provider: "gcp".into(),
            prover_pk_hex: kp.public_key_hex(),
            workload_measurement_hex: digest_hex,
            epoch_challenge_hex: client_nonce.clone(),
            prover_observed_ip: "34.1.13.45".into(),
            rtt_min_us: 100,
            rtt_p50_us: 120,
            rtt_samples_us: vec![100, 120],
            measured_at_unix_s: now,
            anchor_signature_hex: String::new(),
        };
        self_r.sign(&sk_dummy);
        let self_bundle = GeoProofBundle {
            version: 1,
            epoch_challenge_hex: client_nonce,
            client_nonce_hex: None,
            target_location: LatLon::new(48.8566, 2.3522),
            required_radius_km: 50.0,
            prover_quote: hw_quote,
            receipts: vec![self_r],
            calibrated_velocity_km_per_s: None,
            prev_chain_hash_hex: None,
            chain_seq: 1,
            created_at_unix_s: now,
        };
        let mut self_ev = evidence;
        self_ev.receipt.pog_bundle_hash_hex = Some(self_bundle.record_hash_hex());
        self_ev.receipt.pog_epoch_challenge_hex = Some(self_bundle.epoch_challenge_hex.clone());
        self_ev.receipt.sign(&kp);
        self_ev.pog_proof_bundle = Some(self_bundle);
        let r_self = verify_cpu_inference_evidence(&self_ev, &observed, &self_grid, &pol, now + 5).unwrap();
        assert!(!r_self.geographic_proof_verified);
        assert!(r_self
            .geographic_failure_reasons
            .iter()
            .any(|s| s.contains("prover cannot count itself")));
    }
}
