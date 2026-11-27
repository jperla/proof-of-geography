mod acme;
mod model;
mod pog;
mod tls;
mod web_ui;

use crate::acme::{
    generate_self_signed_tls, obtain_acme_tls_alpn01_cert, LETS_ENCRYPT_PROD_DIRECTORY,
    LETS_ENCRYPT_STAGING_DIRECTORY,
};
use crate::model::{
    CandleQwen2Engine, ChatMessage, LocalCpuModelEngine, DEFAULT_COMPLETION_TOKENS,
    MAX_COMPLETION_TOKENS,
};
use crate::pog::run_out_of_band_pog_refresh;
use crate::tls::{serve_enclave_tls, ActiveTlsSession, EnclaveCertResolver};
use anyhow::{bail, Result};
use axum::{
    body::{to_bytes, Body},
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use chrono::Utc;
use clap::{Parser, ValueEnum};
use pog_geo::LatLon;
use pog_proto::{
    compute_blinded_output_commitment, compute_blinded_request_commitment,
    compute_hardware_quote_digest, AnchorGrid, ConfidentialCpuEvidenceBundle,
    ConfidentialCpuInferenceReceipt, DiagnosticAnchorObservation, GeoProofBundle,
    ModelRuntimeIdentity, CLAIM_MODE_CONFIDENTIAL_CPU_TEE_INFERENCE, HTTP_HEADER_POG_CLAIM_MODE,
    HTTP_HEADER_POG_CLIENT_NONCE, HTTP_HEADER_POG_COMMITMENT_SALT,
    HTTP_HEADER_POG_INFERENCE_RECEIPT, HTTP_HEADER_POG_RECEIPT_ID, HTTP_HEADER_POG_RECEIPT_SHA256,
    LLM_DEMO_DEFAULT_AUDIENCE, PINNED_MODEL_ID,
};
use pog_tee::{
    GcpConfidentialSpaceProvider, SoftwareDevProvider, TeeAttestationQuote, TeeProvider, TeeVendor,
    WorkloadAttestation, WorkloadKeypair,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{info, warn};

const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024;
const MAX_CONCURRENT_GENERATIONS: usize = 2;
const MAX_STORED_RECEIPTS: usize = 256;
const RATE_LIMIT_WINDOW_SECS: u64 = 60;
const RATE_LIMIT_MAX_PER_IP: usize = 12;

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum TlsMode {
    AcmeProd,
    AcmeStaging,
    SelfSigned,
}

#[derive(Parser, Debug)]
#[command(
    name = "pog-llm-demo",
    about = "Measured CPU-Only Intel TDX Confidential Space Verified LLM Demo (No GPU, No External API, No SSH)"
)]
struct Args {
    #[arg(long, default_value = "llm.proofofgeography.com")]
    domain: String,
    #[arg(long, default_value = "0.0.0.0:443")]
    https_listen: SocketAddr,
    #[arg(long, value_enum, default_value_t = TlsMode::AcmeProd)]
    tls_mode: TlsMode,
    #[arg(long, default_value = "ops@proofofgeography.com")]
    acme_email: String,
    #[arg(long, default_value = "/opt/pog/model")]
    model_dir: PathBuf,
    #[arg(long, default_value = "/etc/pog/public_anchors.json")]
    grid_path: PathBuf,
    #[arg(long, default_value = LLM_DEMO_DEFAULT_AUDIENCE)]
    oidc_audience: String,
    #[arg(long, default_value_t = 48.8566)]
    claimed_lat: f64,
    #[arg(long, default_value_t = 2.3522)]
    claimed_lon: f64,
    /// Explicitly allow non-Confidential-Space local testing ONLY (FORBIDDEN in production Dockerfile).
    #[arg(long, default_value_t = false)]
    local_test_no_teeserver: bool,
}

/// Bounded in-memory privacy-preserving receipt ring buffer.
/// Stores ONLY signed receipts + commitments + hardware quote + PoG evidence (NEVER raw prompts,
/// NEVER raw completions, NEVER commitment salts!).
struct ReceiptStore {
    order: VecDeque<String>,
    by_id: HashMap<String, ConfidentialCpuEvidenceBundle>,
}

impl ReceiptStore {
    fn new() -> Self {
        Self {
            order: VecDeque::with_capacity(MAX_STORED_RECEIPTS + 1),
            by_id: HashMap::with_capacity(MAX_STORED_RECEIPTS + 1),
        }
    }

    fn insert(&mut self, id: String, bundle: ConfidentialCpuEvidenceBundle) {
        if self.by_id.len() >= MAX_STORED_RECEIPTS {
            if let Some(old) = self.order.pop_front() {
                self.by_id.remove(&old);
            }
        }
        self.order.push_back(id.clone());
        self.by_id.insert(id, bundle);
    }

    fn get(&self, id: &str) -> Option<ConfidentialCpuEvidenceBundle> {
        self.by_id.get(id).cloned()
    }
}

struct IpRateLimiter {
    hits: HashMap<IpAddr, VecDeque<Instant>>,
}

impl IpRateLimiter {
    fn new() -> Self {
        Self {
            hits: HashMap::new(),
        }
    }

    fn allow(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(RATE_LIMIT_WINDOW_SECS);
        if self.hits.len() > 2048 {
            self.hits.retain(|_, q| {
                while let Some(&front) = q.front() {
                    if now.duration_since(front) > window {
                        q.pop_front();
                    } else {
                        break;
                    }
                }
                !q.is_empty()
            });
        }
        let q = self.hits.entry(ip).or_default();
        while let Some(&front) = q.front() {
            if now.duration_since(front) > window {
                q.pop_front();
            } else {
                break;
            }
        }
        if q.len() >= RATE_LIMIT_MAX_PER_IP {
            return false;
        }
        q.push_back(now);
        true
    }
}

struct DemoState {
    domain: String,
    keypair: WorkloadKeypair,
    tee_provider: Arc<dyn TeeProvider>,
    hardware_tee_active: bool,
    model_engine: Arc<dyn LocalCpuModelEngine>,
    model_runtime: ModelRuntimeIdentity,
    cert_resolver: Arc<EnclaveCertResolver>,
    gen_semaphore: Arc<Semaphore>,
    rate_limiter: Mutex<IpRateLimiter>,
    receipts: RwLock<ReceiptStore>,
    latest_hw_quote: RwLock<TeeAttestationQuote>,
    latest_pog_bundle: RwLock<Option<GeoProofBundle>>,
    diagnostic_rtts: RwLock<Vec<DiagnosticAnchorObservation>>,
    acme_last_status: RwLock<String>,
}

#[derive(Deserialize)]
struct ChatCompletionRequest {
    model: Option<String>,
    messages: Vec<ChatMessage>,
    max_tokens: Option<usize>,
    temperature: Option<f64>,
    stream: Option<bool>,
}

#[derive(Serialize)]
struct ChatCompletionResponse {
    id: String,
    object: &'static str,
    created: u64,
    model: String,
    choices: Vec<ChatCompletionChoice>,
    usage: ChatCompletionUsage,
}

#[derive(Serialize)]
struct ChatCompletionChoice {
    index: usize,
    message: ChatMessage,
    finish_reason: String,
}

#[derive(Serialize)]
struct ChatCompletionUsage {
    prompt_tokens: usize,
    completion_tokens: usize,
    total_tokens: usize,
}

#[derive(Deserialize)]
struct AttestQuery {
    nonce: String,
}

fn random_hex(n_bytes: usize) -> String {
    let mut b = vec![0u8; n_bytes];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

fn extract_gce_zone_from_quote(quote: &TeeAttestationQuote) -> Option<String> {
    let WorkloadAttestation::GcpConfidentialSpaceOidc { jwt, .. } =
        quote.workload_attestation.as_ref()?
    else {
        return None;
    };
    let payload_b64 = jwt.split('.').nth(1)?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    v.pointer("/submods/gce/zone")
        .and_then(|z| z.as_str())
        .map(|s| s.to_string())
}

fn extract_container_digest_from_quote(quote: &TeeAttestationQuote) -> Option<String> {
    match quote.workload_attestation.as_ref() {
        Some(WorkloadAttestation::GcpConfidentialSpaceOidc { image_digest, .. }) => {
            Some(image_digest.clone())
        }
        _ => None,
    }
}

fn build_router(state: Arc<DemoState>) -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/health", get(health_handler))
        .route("/v1/info", get(info_handler))
        .route("/v1/models", get(models_handler))
        .route("/v1/attest", get(attest_handler))
        .route("/v1/receipts/:receipt_id", get(get_receipt_handler))
        .route("/v1/chat/completions", post(chat_completions_handler))
        .with_state(state)
}

async fn index_handler() -> impl IntoResponse {
    (
        [
            ("content-type", "text/html; charset=utf-8"),
            ("cache-control", "no-store"),
            ("x-pog-claim-mode", CLAIM_MODE_CONFIDENTIAL_CPU_TEE_INFERENCE),
        ],
        Html(web_ui::INDEX_HTML),
    )
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "cpu_only": true }))
}

async fn models_handler(State(state): State<Arc<DemoState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "object": "list",
        "data": [{
            "id": state.model_runtime.model_id,
            "object": "model",
            "created": 1731369600,
            "owned_by": state.model_runtime.model_repo,
            "license": state.model_runtime.license,
            "weights_sha256_hex": state.model_runtime.weights_sha256_hex,
            "tokenizer_sha256_hex": state.model_runtime.tokenizer_sha256_hex,
            "cpu_only": true
        }]
    }))
}

async fn info_handler(State(state): State<Arc<DemoState>>) -> Json<serde_json::Value> {
    let hw_quote = state.latest_hw_quote.read().unwrap().clone();
    let live_tls = state.cert_resolver.current_identity();
    let prod_pog = state.latest_pog_bundle.read().unwrap().is_some();
    let diag_rtts = state.diagnostic_rtts.read().unwrap().clone();
    Json(serde_json::json!({
        "domain": state.domain,
        "claim_mode": CLAIM_MODE_CONFIDENTIAL_CPU_TEE_INFERENCE,
        "hardware_tee_active": state.hardware_tee_active,
        "tee_vendor": hw_quote.vendor.as_str(),
        "prover_pk_hex": state.keypair.public_key_hex(),
        "container_image_digest": extract_container_digest_from_quote(&hw_quote),
        "gcp_cloud_metadata_zone": extract_gce_zone_from_quote(&hw_quote),
        "tls_leaf_cert_sha256_hex": live_tls.as_ref().map(|t| t.leaf_cert_sha256_hex.clone()),
        "tls_cert_prover_binding_sig_hex": live_tls.as_ref().map(|t| t.cert_prover_binding_sig_hex.clone()),
        "tls_issuer": live_tls.as_ref().map(|t| t.issuer_note.clone()).unwrap_or_else(|| "initializing".into()),
        "acme_status": state.acme_last_status.read().unwrap().clone(),
        "model_runtime": state.model_runtime,
        "production_geo_quorum_available": prod_pog,
        "geographic_proof_note": "Inference TEE attestation and production multi-cloud geographic proof are strictly separated; SoftwareDev diagnostic nodes and the prover itself are NEVER counted toward geographic proof.",
        "diagnostic_anchor_rtts": diag_rtts,
        "limits": {
            "max_request_bytes": MAX_REQUEST_BODY_BYTES,
            "max_prompt_chars": model::MAX_PROMPT_CHARS,
            "max_completion_tokens": MAX_COMPLETION_TOKENS,
            "max_concurrent_generations": MAX_CONCURRENT_GENERATIONS,
            "rate_limit_per_ip_per_min": RATE_LIMIT_MAX_PER_IP,
            "prompt_output_logging": false
        }
    }))
}

async fn attest_handler(
    State(state): State<Arc<DemoState>>,
    Query(q): Query<AttestQuery>,
) -> Response {
    let nonce_norm = q.nonce.trim().to_ascii_lowercase();
    if nonce_norm.len() < 32
        || nonce_norm.len() > 88
        || !nonce_norm.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "nonce must be 32..=88 hex chars" })),
        )
            .into_response();
    }
    let Ok(nonce_bytes) = hex::decode(&nonce_norm) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid hex nonce" })),
        )
            .into_response();
    };
    let provider = Arc::clone(&state.tee_provider);
    let pk_bytes = state.keypair.public_key_bytes();
    let quote_res =
        tokio::task::spawn_blocking(move || provider.attest(&pk_bytes, &nonce_bytes, None)).await;
    match quote_res {
        Ok(Ok(quote)) => {
            let pop_msg = format!("POG_LLM_ATTEST_POP_V1\n{}\n{}\n", state.keypair.public_key_hex(), nonce_norm);
            let pop_sig = hex::encode(state.keypair.sign(pop_msg.as_bytes()));
            Json(serde_json::json!({
                "prover_pk_hex": state.keypair.public_key_hex(),
                "nonce_hex": nonce_norm,
                "pop_signature_hex": pop_sig,
                "quote": quote,
                "model_runtime": state.model_runtime,
            }))
            .into_response()
        }
        Ok(Err(e)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": format!("hardware attestation unavailable: {e}") })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("attest task failed: {e}") })),
        )
            .into_response(),
    }
}

async fn get_receipt_handler(
    State(state): State<Arc<DemoState>>,
    Path(receipt_id): Path<String>,
) -> Response {
    let guard = state.receipts.read().unwrap();
    match guard.get(&receipt_id) {
        Some(ev) => (
            [("cache-control", "no-store")],
            Json(ev),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "receipt_id not found or evicted from bounded RAM ring buffer" })),
        )
            .into_response(),
    }
}

async fn chat_completions_handler(
    State(state): State<Arc<DemoState>>,
    Extension(tls_session): Extension<Arc<ActiveTlsSession>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    // 1. Per-IP rate limiting (resource-bounded public demo).
    {
        let mut rl = state.rate_limiter.lock().unwrap();
        if !rl.allow(tls_session.peer_ip) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": { "message": "rate limit exceeded (max 12 requests/min per IP)", "type": "rate_limit_error" }
                })),
            )
                .into_response();
        }
    }

    // 2. Read exact raw HTTP request bytes (bounded at 16 KiB) — NEVER logged!
    let raw_req_bytes = match to_bytes(body, MAX_REQUEST_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({
                    "error": { "message": "request exceeds 16 KiB public demo cap", "type": "invalid_request_error" }
                })),
            )
                .into_response();
        }
    };
    let req: ChatCompletionRequest = match serde_json::from_slice(&raw_req_bytes) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": { "message": format!("invalid OpenAI chat completion JSON: {e}"), "type": "invalid_request_error" }
                })),
            )
                .into_response();
        }
    };
    if req.stream == Some(true) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": { "message": "set stream=false so the enclave can sign an atomic post-execution commitment over the complete response body in HTTP headers", "type": "invalid_request_error" }
            })),
        )
            .into_response();
    }
    if let Some(ref requested_model) = req.model {
        if requested_model != PINNED_MODEL_ID {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": {
                        "message": format!("only pinned local CPU model '{PINNED_MODEL_ID}' is served by this measured enclave (no external routing)"),
                        "type": "invalid_request_error"
                    }
                })),
            )
                .into_response();
        }
    }

    // 3. Extract optional caller freshness nonce (`X-PoG-Client-Nonce`); stock OpenAI SDK clients
    //    may omit it, in which case the receipt honestly records `client_nonce_supplied_by_caller=false`.
    let (client_nonce_hex, caller_supplied) = match headers
        .get(HTTP_HEADER_POG_CLIENT_NONCE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_ascii_lowercase())
    {
        Some(n) if n.len() >= 32 && n.len() <= 88 && n.bytes().all(|b| b.is_ascii_hexdigit()) => {
            (n, true)
        }
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": { "message": "X-PoG-Client-Nonce must be 32..=88 hex characters", "type": "invalid_request_error" }
                })),
            )
                .into_response();
        }
        None => (random_hex(32), false),
    };

    // 4. Acquire bounded CPU generation semaphore (timeout 30s so public queue never hangs).
    let permit = match tokio::time::timeout(
        Duration::from_secs(30),
        Arc::clone(&state.gen_semaphore).acquire_owned(),
    )
    .await
    {
        Ok(Ok(p)) => p,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": { "message": "enclave CPU inference queue busy; retry shortly", "type": "server_busy" }
                })),
            )
                .into_response();
        }
    };

    // 5. Generate completion STRICTLY locally on enclave CPU (no external API, no fallback, no logs).
    let started_at = Utc::now().timestamp().max(0) as u64;
    let max_tokens = req
        .max_tokens
        .unwrap_or(DEFAULT_COMPLETION_TOKENS)
        .clamp(1, MAX_COMPLETION_TOKENS);
    let temperature = req.temperature.unwrap_or(0.2);
    let seed = rand::rngs::OsRng.next_u64();
    let messages = req.messages;
    let engine = Arc::clone(&state.model_engine);
    let gen_res = tokio::task::spawn_blocking(move || {
        let _p = permit;
        engine.generate(&messages, max_tokens, temperature, seed)
    })
    .await;

    let gen_out = match gen_res {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": { "message": e.to_string(), "type": "invalid_request_error" }
                })),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": { "message": "local CPU generation task interrupted", "type": "internal_error" }
                })),
            )
                .into_response();
        }
    };

    // 6. Strictly POST-EXECUTION: serialize exact delivered OpenAI JSON response body, mint/bind
    //    fresh hardware TDX quote over `client_nonce_hex`, compute blinded SHA-256 commitments,
    //    and sign receipt with the enclave-held nonexportable Ed25519 key!
    let completed_at = (Utc::now().timestamp().max(0) as u64).max(started_at);
    let receipt_id = format!("pog-{}", random_hex(16));
    let response_payload = ChatCompletionResponse {
        id: format!("chatcmpl-{}", &receipt_id[4..]),
        object: "chat.completion",
        created: completed_at,
        model: state.model_runtime.model_id.clone(),
        choices: vec![ChatCompletionChoice {
            index: 0,
            message: ChatMessage {
                role: "assistant".into(),
                content: gen_out.text,
            },
            finish_reason: gen_out.finish_reason,
        }],
        usage: ChatCompletionUsage {
            prompt_tokens: gen_out.prompt_tokens,
            completion_tokens: gen_out.completion_tokens,
            total_tokens: gen_out.prompt_tokens + gen_out.completion_tokens,
        },
    };
    let raw_resp_bytes = match serde_json::to_vec(&response_payload) {
        Ok(b) => b,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    // Mint a fresh per-request hardware TDX OIDC quote binding `[prover_pk_hex, client_nonce_hex]`
    // when possible; if the Confidential Space socket briefly throttles, fall back ONLY to the
    // recent hardware TDX quote already bound to `prover_pk_hex` (NEVER software/dev fallback!).
    let hw_quote = {
        let provider = Arc::clone(&state.tee_provider);
        let pk_bytes = state.keypair.public_key_bytes();
        let nonce_bytes = hex::decode(&client_nonce_hex).unwrap_or_default();
        match tokio::time::timeout(
            Duration::from_secs(4),
            tokio::task::spawn_blocking(move || provider.attest(&pk_bytes, &nonce_bytes, None)),
        )
        .await
        {
            Ok(Ok(Ok(q))) => {
                *state.latest_hw_quote.write().unwrap() = q.clone();
                q
            }
            _ => state.latest_hw_quote.read().unwrap().clone(),
        }
    };
    if state.hardware_tee_active && hw_quote.vendor == TeeVendor::SoftwareDev {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    // Fresh 256-bit salt returned ONLY in this encrypted TLS 1.3 response header (never stored!).
    let commitment_salt_hex = random_hex(32);
    let request_commitment_hex = compute_blinded_request_commitment(
        &commitment_salt_hex,
        &client_nonce_hex,
        &state.model_runtime.model_id,
        &raw_req_bytes,
    );
    let output_commitment_hex = compute_blinded_output_commitment(
        &commitment_salt_hex,
        &request_commitment_hex,
        &raw_resp_bytes,
    );

    let pog_bundle = state.latest_pog_bundle.read().unwrap().clone();
    let diag_rtts = state.diagnostic_rtts.read().unwrap().clone();
    let tls_binding = tls_session.next_binding();

    let mut receipt = ConfidentialCpuInferenceReceipt {
        version: 1,
        receipt_id: receipt_id.clone(),
        claim_type: CLAIM_MODE_CONFIDENTIAL_CPU_TEE_INFERENCE.into(),
        client_nonce_hex: client_nonce_hex.clone(),
        client_nonce_supplied_by_caller: caller_supplied,
        request_commitment_hex,
        output_commitment_hex,
        response_http_status: 200,
        model_runtime: state.model_runtime.clone(),
        prover_pk_hex: state.keypair.public_key_hex(),
        workload_measurement_hex: hw_quote.workload_measurement_hex.clone(),
        tls_session_binding: Some(tls_binding),
        hardware_attestation_digest_hex: compute_hardware_quote_digest(&hw_quote),
        pog_bundle_hash_hex: pog_bundle.as_ref().map(|b| b.record_hash_hex()),
        pog_epoch_challenge_hex: pog_bundle.as_ref().map(|b| b.epoch_challenge_hex.clone()),
        execution_started_at_unix_s: started_at,
        execution_completed_at_unix_s: completed_at,
        prover_signature_hex: String::new(),
    };
    receipt.sign(&state.keypair);
    let receipt_sha256 = receipt.sha256_hex();
    let receipt_hdr = receipt.to_header_value().unwrap_or_default();

    // Store ONLY privacy-preserving signed receipt + hardware quote + PoG evidence (ZERO plaintext, ZERO salt!).
    let evidence = ConfidentialCpuEvidenceBundle {
        version: 1,
        receipt,
        hardware_quote: hw_quote,
        pog_proof_bundle: pog_bundle,
        diagnostic_anchor_rtts: diag_rtts,
        google_jwks_json: None,
        client_observed: None,
    };
    state
        .receipts
        .write()
        .unwrap()
        .insert(receipt_id.clone(), evidence);

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header(
            HTTP_HEADER_POG_CLAIM_MODE,
            CLAIM_MODE_CONFIDENTIAL_CPU_TEE_INFERENCE,
        )
        .header(HTTP_HEADER_POG_RECEIPT_ID, &receipt_id)
        .header(HTTP_HEADER_POG_RECEIPT_SHA256, &receipt_sha256)
        .header(HTTP_HEADER_POG_COMMITMENT_SALT, &commitment_salt_hex)
        .header(HTTP_HEADER_POG_CLIENT_NONCE, &client_nonce_hex)
        .header(
            "access-control-expose-headers",
            format!(
                "{HTTP_HEADER_POG_CLAIM_MODE}, {HTTP_HEADER_POG_RECEIPT_ID}, {HTTP_HEADER_POG_RECEIPT_SHA256}, {HTTP_HEADER_POG_COMMITMENT_SALT}, {HTTP_HEADER_POG_CLIENT_NONCE}, {HTTP_HEADER_POG_INFERENCE_RECEIPT}"
            ),
        );
    if let (Ok(hn), Ok(hv)) = (
        HeaderName::from_bytes(HTTP_HEADER_POG_INFERENCE_RECEIPT.as_bytes()),
        HeaderValue::from_str(&receipt_hdr),
    ) {
        builder = builder.header(hn, hv);
    }
    builder.body(Body::from(raw_resp_bytes)).unwrap()
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls ring CryptoProvider once at process startup.
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let git_rev = option_env!("POG_GIT_REV").unwrap_or("unknown").to_string();

    // 1. Fail-closed hardware TEE initialization (NEVER silently falls back to SoftwareDev!).
    let (tee_provider, hardware_tee_active): (Arc<dyn TeeProvider>, bool) =
        if GcpConfidentialSpaceProvider::is_available() {
            info!(
                audience = %args.oidc_audience,
                "Detected GCP Confidential Space teeserver.sock — hardware Intel TDX attestation ACTIVE"
            );
            (
                Arc::new(GcpConfidentialSpaceProvider::with_audience(
                    args.oidc_audience.clone(),
                )),
                true,
            )
        } else if args.local_test_no_teeserver {
            warn!("--local-test-no-teeserver set: running local non-hardware test mode ONLY");
            (
                Arc::new(SoftwareDevProvider::new("00".repeat(32))),
                false,
            )
        } else {
            bail!(
                "FAIL-CLOSED: /run/container_launcher/teeserver.sock not present and --local-test-no-teeserver not set. Refusing to serve software/dev proofs."
            );
        };

    // 2. Generate nonexportable enclave Ed25519 keypair strictly in RAM & obtain initial hardware quote!
    let keypair = WorkloadKeypair::generate();
    let boot_nonce_hex = random_hex(32);
    let boot_nonce_bytes = hex::decode(&boot_nonce_hex)?;
    let initial_quote = tee_provider.attest(&keypair.public_key_bytes(), &boot_nonce_bytes, None)?;
    info!(
        prover_pk = %keypair.public_key_hex(),
        tee = initial_quote.vendor.as_str(),
        container_digest = ?extract_container_digest_from_quote(&initial_quote),
        gce_zone = ?extract_gce_zone_from_quote(&initial_quote),
        "Enclave identity attested"
    );

    // 3. Load and SHA-256-verify pinned Qwen2.5-0.5B-Instruct CPU weights, tokenizer, and Apache-2.0 LICENSE!
    info!(model_dir = ?args.model_dir, "Verifying SHA-256 and loading pinned Qwen2.5-0.5B-Instruct Q4_K_M on CPU");
    let model_dir_clone = args.model_dir.clone();
    let model_engine: Arc<dyn LocalCpuModelEngine> = Arc::new(
        tokio::task::spawn_blocking(move || CandleQwen2Engine::load_pinned(&model_dir_clone))
            .await??,
    );
    info!("Pinned CPU LLM loaded and SHA-256 verified");

    // 4. Load anchor grid for out-of-band PoG probing & diagnostic RTT observations.
    let grid = match std::fs::read_to_string(&args.grid_path) {
        Ok(s) => AnchorGrid::from_json_str(&s)?,
        Err(e) => {
            warn!(path = ?args.grid_path, err = %e, "Anchor grid unavailable; running with empty grid");
            AnchorGrid {
                version: "2.0.0".into(),
                grid_name: "empty".into(),
                description: "empty".into(),
                anchors: Vec::new(),
            }
        }
    };

    let cert_resolver = Arc::new(EnclaveCertResolver::new());
    // Install immediate temporary in-RAM cert so TLS listener binds right away; ACME replaces it in ~5s!
    let bootstrap_cert = generate_self_signed_tls(&args.domain)?;
    cert_resolver.install_live(bootstrap_cert, &keypair);

    let state = Arc::new(DemoState {
        domain: args.domain.clone(),
        keypair,
        tee_provider,
        hardware_tee_active,
        model_engine,
        model_runtime: ModelRuntimeIdentity::pinned_qwen25_05b(git_rev),
        cert_resolver: Arc::clone(&cert_resolver),
        gen_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_GENERATIONS)),
        rate_limiter: Mutex::new(IpRateLimiter::new()),
        receipts: RwLock::new(ReceiptStore::new()),
        latest_hw_quote: RwLock::new(initial_quote),
        latest_pog_bundle: RwLock::new(None),
        diagnostic_rtts: RwLock::new(Vec::new()),
        acme_last_status: RwLock::new("initializing".into()),
    });

    // 5. Background out-of-band PoG refresh loop (uses SAME enclave Ed25519 key; separates prod vs diagnostic).
    let pog_state = Arc::clone(&state);
    let claimed_target = LatLon::new(args.claimed_lat, args.claimed_lon);
    tokio::spawn(async move {
        loop {
            let res = run_out_of_band_pog_refresh(
                &grid,
                &pog_state.keypair,
                pog_state.tee_provider.as_ref(),
                claimed_target,
            )
            .await;
            *pog_state.latest_pog_bundle.write().unwrap() = res.production_bundle;
            *pog_state.diagnostic_rtts.write().unwrap() = res.diagnostic_observations;
            tokio::time::sleep(Duration::from_secs(600)).await;
        }
    });

    // 6. Background Let's Encrypt ACME TLS-ALPN-01 issuance & auto-renewal directly inside enclave RAM!
    if args.tls_mode != TlsMode::SelfSigned {
        let dir_url = match args.tls_mode {
            TlsMode::AcmeProd => LETS_ENCRYPT_PROD_DIRECTORY.to_string(),
            TlsMode::AcmeStaging => LETS_ENCRYPT_STAGING_DIRECTORY.to_string(),
            TlsMode::SelfSigned => unreachable!(),
        };
        let acme_state = Arc::clone(&state);
        let acme_domain = args.domain.clone();
        let acme_email = args.acme_email.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            loop {
                info!(domain = %acme_domain, directory = %dir_url, "Requesting Let's Encrypt TLS-ALPN-01 cert directly into enclave RAM");
                let res_for_cb = Arc::clone(&acme_state.cert_resolver);
                match obtain_acme_tls_alpn01_cert(&dir_url, &acme_domain, &acme_email, move |ch| {
                    res_for_cb.set_acme_challenge(ch);
                })
                .await
                {
                    Ok(mat) => {
                        info!(
                            leaf_sha256 = %mat.leaf_cert_sha256_hex,
                            issuer = %mat.issuer_note,
                            "Installed browser-trusted Let's Encrypt TLS 1.3 cert inside enclave RAM"
                        );
                        *acme_state.acme_last_status.write().unwrap() =
                            format!("ok: {}", mat.issuer_note);
                        acme_state
                            .cert_resolver
                            .install_live(mat, &acme_state.keypair);
                        // Renew every 45 days.
                        tokio::time::sleep(Duration::from_secs(45 * 86400)).await;
                    }
                    Err(e) => {
                        warn!(err = %e, "ACME TLS-ALPN-01 attempt failed; retrying in 60s");
                        *acme_state.acme_last_status.write().unwrap() = format!("error: {e}");
                        tokio::time::sleep(Duration::from_secs(60)).await;
                    }
                }
            }
        });
    }

    let router = build_router(Arc::clone(&state));
    serve_enclave_tls(args.https_listen, cert_resolver, router).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::GenerationOutput;
    use pog_proto::{
        sign_tls_cert_binding, verify_cpu_inference_evidence, ClientObservedEvidence,
        CpuInferenceVerificationPolicy, GeographicProofStatus,
    };
    use std::sync::atomic::AtomicU64;

    struct DeterministicTestCpuEngine;

    impl LocalCpuModelEngine for DeterministicTestCpuEngine {
        fn generate(
            &self,
            messages: &[ChatMessage],
            _max_tokens: usize,
            _temperature: f64,
            _seed: u64,
        ) -> Result<GenerationOutput> {
            let prompt = model::format_chatml_prompt(messages)?;
            Ok(GenerationOutput {
                text: format!("Enclave CPU reply (prompt_chars={})", prompt.len()),
                prompt_tokens: 12,
                completion_tokens: 7,
                finish_reason: "stop".into(),
            })
        }
    }

    #[tokio::test]
    async fn test_openai_endpoint_end_to_end_tls_binding_and_no_prompt_storage() {
        let kp = WorkloadKeypair::generate();
        let tee: Arc<dyn TeeProvider> = Arc::new(SoftwareDevProvider::new("aa".repeat(32)));
        let init_q = tee
            .attest(&kp.public_key_bytes(), &[0x11u8; 32], None)
            .unwrap();
        let resolver = Arc::new(EnclaveCertResolver::new());
        let mat = generate_self_signed_tls("llm.proofofgeography.com").unwrap();
        let leaf_sha = mat.leaf_cert_sha256_hex.clone();
        resolver.install_live(mat, &kp);
        let cert_sig = sign_tls_cert_binding(&kp, &leaf_sha);

        let state = Arc::new(DemoState {
            domain: "llm.proofofgeography.com".into(),
            keypair: kp,
            tee_provider: tee,
            hardware_tee_active: false,
            model_engine: Arc::new(DeterministicTestCpuEngine),
            model_runtime: ModelRuntimeIdentity::pinned_qwen25_05b("test-sha"),
            cert_resolver: resolver,
            gen_semaphore: Arc::new(Semaphore::new(2)),
            rate_limiter: Mutex::new(IpRateLimiter::new()),
            receipts: RwLock::new(ReceiptStore::new()),
            latest_hw_quote: RwLock::new(init_q),
            latest_pog_bundle: RwLock::new(None),
            diagnostic_rtts: RwLock::new(Vec::new()),
            acme_last_status: RwLock::new("test".into()),
        });

        let tls_ekm = "55".repeat(32);
        let sess = Arc::new(ActiveTlsSession {
            peer_ip: "203.0.113.10".parse().unwrap(),
            tls_protocol_version: "TLSv1.3".into(),
            tls_exporter_ekm_hex: tls_ekm.clone(),
            server_cert_sha256_hex: leaf_sha.clone(),
            cert_prover_binding_sig_hex: cert_sig,
            request_seq: AtomicU64::new(0),
        });

        let secret_prompt = "TOP_SECRET_UNPREDICTABLE_PROMPT_987654321";
        let req_json = serde_json::json!({
            "model": PINNED_MODEL_ID,
            "messages": [{"role": "user", "content": secret_prompt}],
            "max_tokens": 32
        })
        .to_string();
        let nonce = "ab".repeat(32);
        let mut hdrs = HeaderMap::new();
        hdrs.insert(
            HeaderName::from_bytes(HTTP_HEADER_POG_CLIENT_NONCE.as_bytes()).unwrap(),
            HeaderValue::from_str(&nonce).unwrap(),
        );

        let resp = chat_completions_handler(
            State(Arc::clone(&state)),
            Extension(Arc::clone(&sess)),
            hdrs,
            Body::from(req_json.clone()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let receipt_id = resp
            .headers()
            .get(HTTP_HEADER_POG_RECEIPT_ID)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let salt = resp
            .headers()
            .get(HTTP_HEADER_POG_COMMITMENT_SALT)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let raw_resp_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let raw_resp_str = String::from_utf8(raw_resp_bytes.to_vec()).unwrap();
        assert!(raw_resp_str.contains("Enclave CPU reply"));

        // Verify stored `/v1/receipts/{id}` contains ZERO prompt text, ZERO completion text, and ZERO salt!
        let stored = state.receipts.read().unwrap().get(&receipt_id).unwrap();
        let stored_json = serde_json::to_string(&stored).unwrap();
        assert!(!stored_json.contains(secret_prompt));
        assert!(!stored_json.contains("Enclave CPU reply"));
        assert!(!stored_json.contains(&salt));

        // Verify full blinded commitment + TLS 1.3 EKM binding (with dev-TEE flag in unit test).
        let obs = ClientObservedEvidence {
            endpoint_url: "https://llm.proofofgeography.com/v1/chat/completions".into(),
            client_nonce_hex: nonce,
            commitment_salt_hex: salt,
            tls_exporter_ekm_hex: tls_ekm,
            server_cert_sha256_hex: leaf_sha,
            expected_tls_connection_request_seq: Some(1),
            raw_request_body: req_json,
            raw_response_body: raw_resp_str,
            observed_at_unix_s: Utc::now().timestamp() as u64,
        };
        let mut pol = CpuInferenceVerificationPolicy::production(vec![], "{}".into());
        pol.geo_policy.tee_policy = pog_tee::AttestationPolicy::allow_dev_software();
        let grid = AnchorGrid {
            version: "2.0.0".into(),
            grid_name: "empty".into(),
            description: "empty".into(),
            anchors: Vec::new(),
        };
        let rep = verify_cpu_inference_evidence(
            &stored,
            &obs,
            &grid,
            &pol,
            Utc::now().timestamp() as u64 + 1,
        )
        .unwrap();
        assert!(
            rep.inference_tee_verified,
            "failures: {:?}",
            rep.inference_failure_reasons
        );
        assert!(rep.tls_channel_binding_verified);
        assert!(rep.request_output_commitments_verified);
        assert!(!rep.geographic_proof_verified);
        assert_eq!(
            rep.geographic_proof_status,
            GeographicProofStatus::InsufficientProductionHardwareAnchors
        );
    }
}
