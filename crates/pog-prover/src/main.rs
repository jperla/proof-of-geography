use anyhow::Result;
use axum::{
    body::{to_bytes, Body},
    extract::{Query, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use clap::Parser;
use pog_geo::LatLon;
use pog_proto::{
    bind_low_latency_udp, compute_gpu_execution_digest, compute_inference_output_hash,
    compute_inference_request_hash, derive_session_key, encode_udp_punch, respond_once_udp,
    select_committee, verify_tls_cert_binding, AnchorDescriptor, AnchorGrid, AnchorReceipt,
    CommitteeConfig, ConfidentialInferenceReceipt, GeoProofBundle, InferenceClaimType,
    InferenceExecutionMode, Phase1InitRequest, Phase1InitResponse, TlsSessionBinding,
    CLAIM_MODE_PROVER_ONLY, HTTP_HEADER_POG_CLAIM_MODE, HTTP_HEADER_POG_PROOF, TLS_EXPORTER_LABEL,
};
use pog_tee::{auto_detect_provider, GpuAttestationBinding, TeeProvider, WorkloadKeypair};
use rand::rngs::OsRng;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{info, warn};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

const MAX_PROXY_BODY_BYTES: usize = 8 * 1024 * 1024; // 8 MiB max proxied HTTP payload

#[derive(Parser, Debug)]
#[command(
    name = "pog-prover",
    about = "Proof of Geography Prover TEE Sidecar (Prover-Only Proxy + Separate Measured Local-GPU Inference Runtime)"
)]
struct Args {
    #[arg(long)]
    grid_path: PathBuf,
    #[arg(long)]
    claimed_lat: f64,
    #[arg(long)]
    claimed_lon: f64,
    #[arg(long, default_value_t = 350.0)]
    required_radius_km: f64,
    #[arg(long, default_value_t = 8)]
    rounds: u16,
    /// Continuous hourly refresh interval in seconds (default 3600s).
    #[arg(long, default_value_t = 3600)]
    interval_secs: u64,
    #[arg(long, default_value = "127.0.0.1:8080")]
    http_listen: SocketAddr,
    /// Optional transparency log endpoint (e.g. http://127.0.0.1:8090) to auto-publish each hourly chain link.
    #[arg(long)]
    log_url: Option<String>,
    /// Optional upstream workload (prover-only geography reverse proxy — NEVER valid for
    /// `ConfidentialGpuInferenceLocation` claims; mutually exclusive with `--local-gpu-runtime`).
    #[arg(long)]
    upstream: Option<String>,
    /// Run in measured local-only Confidential GPU inference mode (forbids `--upstream` and any
    /// remote/CPU fallback; issues signed post-execution receipts bound to end-to-end TLS 1.3 EKM).
    #[arg(long, default_value_t = false)]
    local_gpu_runtime: bool,
    #[arg(long, default_value_t = false)]
    allow_dev_tee: bool,
}

/// Strictly validates execution mode so a measured local-GPU runtime can NEVER be combined with
/// `--upstream` proxy forwarding (fail-closed at startup).
fn validate_runtime_mode(
    local_gpu_runtime: bool,
    upstream: Option<&str>,
) -> Result<InferenceExecutionMode> {
    if local_gpu_runtime {
        if upstream.is_some() {
            anyhow::bail!(
                "--local-gpu-runtime cannot be combined with --upstream: ConfidentialGpuInferenceLocation forbids any remote upstream or proxy fallback (fail-closed)"
            );
        }
        Ok(InferenceExecutionMode::LocalBoundConfidentialGpuOnly)
    } else {
        Ok(InferenceExecutionMode::ProxyForwarded)
    }
}

/// Trait implemented by a locally attached Confidential GPU executor reachable solely over the
/// measured runtime's active SPDM-protected local channel (zero remote HTTP/gRPC upstream).
trait LocalBoundGpuExecutor: Send + Sync {
    fn gpu_binding(&self) -> &GpuAttestationBinding;
    fn execute_on_bound_gpu(
        &self,
        model_id: &str,
        request_bytes: &[u8],
        channel_seq_no: u64,
    ) -> Result<Vec<u8>>;
}

/// End-to-end TLS 1.3 session terminated directly inside the measured attested inference runtime.
///
/// Each distinct TLS 1.3 handshake yields a unique `tls_exporter_ekm_hex` (RFC 8446 §7.5);
/// multiple requests multiplexed on the same keep-alive TLS 1.3 session receive strictly monotonic
/// `request_seq` values so receipts are never interchangeable across requests.
struct ActiveTlsSession {
    tls_protocol_version: String,
    exporter_label: String,
    tls_exporter_ekm_hex: String,
    server_cert_sha256_hex: String,
    cert_prover_binding_sig_hex: String,
    terminated_in_attested_runtime: bool,
    request_seq: AtomicU64,
}

impl ActiveTlsSession {
    fn next_request_seq(&self) -> u64 {
        self.request_seq.fetch_add(1, Ordering::SeqCst) + 1
    }
}

/// Measured local-only Confidential GPU inference runtime that:
/// 1. Forbids any remote upstream or fallback (`execution_mode == LocalBoundConfidentialGpuOnly`).
/// 2. Requires a live end-to-end TLS 1.3 session terminated inside the attested runtime.
/// 3. Executes inference strictly on the locally bound attested GPU matching the latest PoG bundle.
/// 4. Issues a signed `ConfidentialInferenceReceipt` (embedding the exact `GeoProofBundle` and
///    binding the live TLS 1.3 EKM + per-request nonce/sequence + request/output hashes) strictly
///    AFTER local GPU execution completes — emitting NO receipt if execution fails!
#[allow(dead_code)]
struct LocalConfidentialGpuRuntime {
    execution_mode: InferenceExecutionMode,
    upstream: Option<String>,
    keypair: WorkloadKeypair,
    runtime_measurement_hex: String,
    executor: Box<dyn LocalBoundGpuExecutor>,
    channel_seq: AtomicU64,
}

#[allow(dead_code)]
impl LocalConfidentialGpuRuntime {
    fn new(
        keypair: WorkloadKeypair,
        runtime_measurement_hex: String,
        executor: Box<dyn LocalBoundGpuExecutor>,
    ) -> Self {
        Self {
            execution_mode: InferenceExecutionMode::LocalBoundConfidentialGpuOnly,
            upstream: None,
            keypair,
            runtime_measurement_hex,
            executor,
            channel_seq: AtomicU64::new(0),
        }
    }

    fn execute_and_sign_receipt(
        &self,
        latest_bundle: &GeoProofBundle,
        tls_session: &ActiveTlsSession,
        request_nonce_hex: &str,
        model_id: &str,
        request_bytes: &[u8],
        now_unix_s: u64,
    ) -> Result<(Vec<u8>, ConfidentialInferenceReceipt)> {
        // 1. Hard invariant: zero remote upstream & local-only mode.
        if self.execution_mode != InferenceExecutionMode::LocalBoundConfidentialGpuOnly
            || self.upstream.is_some()
        {
            anyhow::bail!("runtime is not in LocalBoundConfidentialGpuOnly no-upstream mode");
        }

        // 2. Hard invariant: end-to-end TLS 1.3 terminated inside this attested runtime (no proxy TLS hop!).
        if !tls_session.terminated_in_attested_runtime {
            anyhow::bail!(
                "refusing to issue inference receipt: TLS session was not terminated inside the attested runtime (proxy TLS hop rejected)"
            );
        }
        if tls_session.tls_protocol_version != "TLSv1.3" {
            anyhow::bail!(
                "refusing to issue inference receipt: TLSv1.3 required, got {}",
                tls_session.tls_protocol_version
            );
        }
        if tls_session.exporter_label != TLS_EXPORTER_LABEL {
            anyhow::bail!("unexpected TLS exporter label {}", tls_session.exporter_label);
        }
        if tls_session.tls_exporter_ekm_hex.len() != 64
            || !tls_session
                .tls_exporter_ekm_hex
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            anyhow::bail!("invalid 64-hex TLS 1.3 Exported Keying Material");
        }
        verify_tls_cert_binding(
            &self.keypair.public_key_hex(),
            &tls_session.server_cert_sha256_hex,
            &tls_session.cert_prover_binding_sig_hex,
        )?;

        // 3. Require fresh caller request nonce (>= 16 random bytes / 32 hex).
        let nonce_norm = request_nonce_hex.trim().to_ascii_lowercase();
        if nonce_norm.len() < 32 || !nonce_norm.bytes().all(|b| b.is_ascii_hexdigit()) {
            anyhow::bail!("request_nonce_hex must be >= 32 hex chars (16 random bytes)");
        }

        // 4. Verify the latest out-of-band PoG GeoProofBundle is bound to THIS prover key,
        //    THIS measured runtime, and THIS EXACT locally bound Confidential GPU!
        let local_gpu = self.executor.gpu_binding();
        if !latest_bundle
            .prover_quote
            .public_key_hex
            .eq_ignore_ascii_case(&self.keypair.public_key_hex())
        {
            anyhow::bail!("GeoProofBundle prover_pk does not match local runtime keypair");
        }
        if !latest_bundle
            .prover_quote
            .workload_measurement_hex
            .eq_ignore_ascii_case(&self.runtime_measurement_hex)
        {
            anyhow::bail!("GeoProofBundle workload measurement does not match local runtime");
        }
        let bundle_gpu = latest_bundle.prover_quote.gpu_binding.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "GeoProofBundle lacks bound Confidential GPU (prover-only bundle cannot back inference receipt)"
            )
        })?;
        let gpu_pk = local_gpu
            .gpu_pubkey_hex
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("local GPU binding missing gpu_pubkey_hex"))?;
        let spdm_transcript = local_gpu
            .spdm_session_transcript_hash_hex
            .as_deref()
            .filter(|s| s.len() == 64)
            .ok_or_else(|| anyhow::anyhow!("local GPU binding missing 64-hex SPDM transcript"))?;
        let channel_id = local_gpu
            .protected_channel_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("local GPU binding missing protected_channel_id"))?;
        if bundle_gpu.gpu_uuid != local_gpu.gpu_uuid
            || !bundle_gpu
                .spdm_report_hash_hex
                .eq_ignore_ascii_case(&local_gpu.spdm_report_hash_hex)
            || bundle_gpu.gpu_pubkey_hex.as_deref() != Some(gpu_pk)
            || bundle_gpu.spdm_session_transcript_hash_hex.as_deref() != Some(spdm_transcript)
            || bundle_gpu.protected_channel_id.as_deref() != Some(channel_id)
        {
            anyhow::bail!(
                "GeoProofBundle GPU binding does not match active locally bound Confidential GPU"
            );
        }

        // 5. Execute strictly on the locally bound Confidential GPU FIRST!
        //    If execution fails, return Err immediately — NO receipt is ever signed or emitted.
        let channel_seq_no = self.channel_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let tls_connection_request_seq = tls_session.next_request_seq();
        let started_at = now_unix_s;
        let output_bytes = self
            .executor
            .execute_on_bound_gpu(model_id, request_bytes, channel_seq_no)?;
        let completed_at = Utc::now().timestamp().max(0) as u64;
        let completed_at = completed_at.max(started_at);

        // 6. Strictly POST-EXECUTION: bind request, output, GPU channel, end-to-end TLS 1.3 EKM,
        //    and embed the exact independently verifiable PoG GeoProofBundle inside the receipt!
        let request_hash_hex =
            compute_inference_request_hash(&nonce_norm, model_id, request_bytes);
        let output_hash_hex = compute_inference_output_hash(&request_hash_hex, &output_bytes);
        let gpu_execution_digest_hex = compute_gpu_execution_digest(
            spdm_transcript,
            &local_gpu.gpu_uuid,
            channel_id,
            channel_seq_no,
            &tls_session.tls_exporter_ekm_hex,
            tls_connection_request_seq,
            &request_hash_hex,
            &output_hash_hex,
        );

        let mut receipt = ConfidentialInferenceReceipt {
            version: 2,
            claim_type: InferenceClaimType::ConfidentialGpuInferenceLocation,
            execution_mode: InferenceExecutionMode::LocalBoundConfidentialGpuOnly,
            remote_upstream_disabled: true,
            fallback_disabled: true,
            request_nonce_hex: nonce_norm,
            model_id: model_id.to_string(),
            request_hash_hex,
            output_hash_hex,
            prover_pk_hex: self.keypair.public_key_hex(),
            runtime_measurement_hex: self.runtime_measurement_hex.clone(),
            gpu_uuid: local_gpu.gpu_uuid.clone(),
            gpu_pubkey_hex: gpu_pk.to_string(),
            spdm_report_hash_hex: local_gpu.spdm_report_hash_hex.clone(),
            spdm_session_transcript_hash_hex: spdm_transcript.to_string(),
            protected_channel_id: channel_id.to_string(),
            channel_seq_no,
            gpu_execution_digest_hex,
            execution_started_at_unix_s: started_at,
            execution_completed_at_unix_s: completed_at,
            tls_session_binding: Some(TlsSessionBinding {
                tls_protocol_version: tls_session.tls_protocol_version.clone(),
                exporter_label: tls_session.exporter_label.clone(),
                tls_exporter_ekm_hex: tls_session.tls_exporter_ekm_hex.clone(),
                server_cert_sha256_hex: tls_session.server_cert_sha256_hex.clone(),
                cert_prover_binding_sig_hex: tls_session.cert_prover_binding_sig_hex.clone(),
                terminated_in_attested_runtime: true,
                tls_connection_request_seq,
            }),
            location_bundle_hash_hex: latest_bundle.record_hash_hex(),
            location_epoch_challenge_hex: latest_bundle.epoch_challenge_hex.clone(),
            pog_proof_bundle: Some(latest_bundle.clone()),
            prover_signature_hex: String::new(),
        };
        receipt.sign(&self.keypair);
        Ok((output_bytes, receipt))
    }
}

struct ProverState {
    grid: AnchorGrid,
    target: LatLon,
    required_radius_km: f64,
    rounds: u16,
    log_url: Option<String>,
    upstream: Option<String>,
    execution_mode: InferenceExecutionMode,
    keypair: WorkloadKeypair,
    tee_provider: Box<dyn TeeProvider>,
    latest_bundle: RwLock<Option<GeoProofBundle>>,
    chain_seq: RwLock<u64>,
    last_hash: RwLock<Option<String>>,
}

#[derive(Deserialize)]
struct HandshakeQuery {
    client_nonce: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let execution_mode = validate_runtime_mode(args.local_gpu_runtime, args.upstream.as_deref())?;
    let grid_json = std::fs::read_to_string(&args.grid_path)?;
    let grid = AnchorGrid::from_json_str(&grid_json)?;
    let tee_provider = auto_detect_provider(None, args.allow_dev_tee)?;
    let keypair = WorkloadKeypair::generate();

    info!(
        prover_pk = %keypair.public_key_hex(),
        tee = tee_provider.vendor().as_str(),
        execution_mode = ?execution_mode,
        lat = args.claimed_lat,
        lon = args.claimed_lon,
        log_url = ?args.log_url,
        upstream = ?args.upstream,
        "Starting PoG Prover TEE Sidecar"
    );

    let state = Arc::new(ProverState {
        grid,
        target: LatLon::new(args.claimed_lat, args.claimed_lon),
        required_radius_km: args.required_radius_km,
        rounds: args.rounds,
        log_url: args.log_url,
        upstream: args.upstream,
        execution_mode,
        keypair,
        tee_provider,
        latest_bundle: RwLock::new(None),
        chain_seq: RwLock::new(0),
        last_hash: RwLock::new(None),
    });

    // Background task: Continuous hourly hash-chained PoG loop + optional push to pog-log!
    // Out-of-band UDP/TCP PoG proofs establish prover identity & geography independently of client TLS.
    let bg_state = Arc::clone(&state);
    let interval = Duration::from_secs(args.interval_secs.max(10));
    tokio::spawn(async move {
        loop {
            match run_pog_round(&bg_state, None, true).await {
                Ok(bundle) => {
                    info!(
                        seq = bundle.chain_seq,
                        receipts = bundle.receipts.len(),
                        record_hash = %bundle.record_hash_hex(),
                        "Completed continuous hourly PoG chain link"
                    );
                    if let Some(ref log_url) = bg_state.log_url {
                        match publish_to_log(log_url, &bundle).await {
                            Ok(status) => info!(%log_url, status, "Published hourly PoG link to transparency log"),
                            Err(e) => warn!(%log_url, err = %e, "Failed to publish PoG link to transparency log"),
                        }
                    }
                }
                Err(e) => {
                    warn!(err = %e, "Hourly PoG round did not reach quorum (will retry)");
                }
            }
            tokio::time::sleep(interval).await;
        }
    });

    let app = build_prover_router(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind(args.http_listen).await?;
    info!(listen = %args.http_listen, "Prover HTTP handshake sidecar ready");
    axum::serve(listener, app).await?;
    Ok(())
}

fn build_prover_router(state: Arc<ProverState>) -> Router {
    let mut app = Router::new()
        .route("/health", get(|| async { Json(serde_json::json!({ "status": "ok" })) }))
        .route("/v1/handshake-proof", get(handshake_proof_handler))
        .route("/v1/latest-proof", get(latest_proof_handler))
        .route("/v1/infer", post(infer_endpoint_handler));

    if state.upstream.is_some() && state.execution_mode == InferenceExecutionMode::ProxyForwarded {
        app = app.fallback(reverse_proxy_handler);
    }
    app.with_state(state)
}

/// Fail-closed `/v1/infer` endpoint:
/// - In proxy mode (`--upstream` / `ProverOnlyGeography`): ALWAYS rejects with `403 Forbidden`
///   and `X-PoG-Claim-Mode: prover-only-geography` — proxy mode can NEVER issue a
///   `ConfidentialGpuInferenceLocation` receipt.
/// - In `--local-gpu-runtime` mode over plaintext HTTP (no runtime-terminated TLS 1.3 EKM):
///   fails closed with `426 Upgrade Required` until served over an end-to-end RA-TLS 1.3 listener
///   with a bound hardware Confidential GPU executor attached.
async fn infer_endpoint_handler(State(state): State<Arc<ProverState>>) -> Response {
    if state.execution_mode != InferenceExecutionMode::LocalBoundConfidentialGpuOnly
        || state.upstream.is_some()
    {
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(HTTP_HEADER_POG_CLAIM_MODE, CLAIM_MODE_PROVER_ONLY)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "error": "prover-only proxy mode cannot issue ConfidentialGpuInferenceLocation receipts; X-PoG-Proof attests only prover location",
                    "claim_mode": CLAIM_MODE_PROVER_ONLY
                })
                .to_string(),
            ))
            .unwrap();
    }

    Response::builder()
        .status(StatusCode::UPGRADE_REQUIRED)
        .header(HTTP_HEADER_POG_CLAIM_MODE, CLAIM_MODE_PROVER_ONLY)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "error": "ConfidentialGpuInferenceLocation requires an end-to-end TLS 1.3 session terminated inside the measured runtime (RFC 8446 EKM) and an attached locally bound SPDM-attested Confidential GPU executor (fail-closed on plaintext HTTP)",
                "claim_mode": CLAIM_MODE_PROVER_ONLY
            })
            .to_string(),
        ))
        .unwrap()
}

async fn handshake_proof_handler(
    State(state): State<Arc<ProverState>>,
    Query(q): Query<HandshakeQuery>,
) -> (HeaderMap, Json<serde_json::Value>) {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("x-pog-claim-mode"),
        HeaderValue::from_static(CLAIM_MODE_PROVER_ONLY),
    );
    match run_pog_round(&state, q.client_nonce, false).await {
        Ok(bundle) => {
            if let Ok(hdr) = bundle.to_header_value() {
                if let Ok(val) = HeaderValue::from_str(&hdr) {
                    headers.insert(HTTP_HEADER_POG_PROOF, val);
                }
            }
            (headers, Json(serde_json::to_value(bundle).unwrap_or_default()))
        }
        Err(e) => (
            headers,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}

async fn latest_proof_handler(
    State(state): State<Arc<ProverState>>,
) -> (HeaderMap, Json<serde_json::Value>) {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("x-pog-claim-mode"),
        HeaderValue::from_static(CLAIM_MODE_PROVER_ONLY),
    );
    let guard = state.latest_bundle.read().unwrap();
    if let Some(ref b) = *guard {
        if let Ok(hdr) = b.to_header_value() {
            if let Ok(val) = HeaderValue::from_str(&hdr) {
                headers.insert(HTTP_HEADER_POG_PROOF, val);
            }
        }
        (headers, Json(serde_json::to_value(b).unwrap_or_default()))
    } else {
        (
            headers,
            Json(serde_json::json!({ "status": "pending_first_round" })),
        )
    }
}

async fn run_pog_round(
    state: &ProverState,
    client_nonce: Option<String>,
    advance_chain: bool,
) -> Result<GeoProofBundle> {
    let now = Utc::now().timestamp().max(0) as u64;
    let hour_bucket = now / 3600;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pog-epoch-v1");
    hasher.update(&hour_bucket.to_le_bytes());
    if let Some(ref cn) = client_nonce {
        hasher.update(cn.as_bytes());
    }
    let epoch_challenge = *hasher.finalize().as_bytes();
    let epoch_hex = hex::encode(epoch_challenge);

    let pk_bytes = state.keypair.public_key_bytes();
    let pk_hex = state.keypair.public_key_hex();
    let prover_quote = state.tee_provider.attest(&pk_bytes, &epoch_challenge, None)?;

    let committee = select_committee(
        &state.grid,
        &pk_hex,
        &epoch_challenge,
        state.target,
        &CommitteeConfig::default(),
    );

    let mut tasks = Vec::new();
    for anchor in committee.selected {
        let quote_clone = prover_quote.clone();
        let epoch_hex_clone = epoch_hex.clone();
        let epoch_bytes = epoch_challenge;
        let pk_hex_clone = pk_hex.clone();
        let rounds = state.rounds;
        tasks.push(tokio::spawn(async move {
            probe_single_anchor(
                &anchor,
                quote_clone,
                &epoch_hex_clone,
                &epoch_bytes,
                &pk_hex_clone,
                rounds,
            )
            .await
        }));
    }

    let mut receipts = Vec::new();
    for t in tasks {
        if let Ok(Ok(r)) = t.await {
            receipts.push(r);
        }
    }
    if receipts.is_empty() {
        anyhow::bail!("No reachable anchors completed Phase 2 UDP burst");
    }

    let (seq, prev_hash) = if advance_chain {
        let s = *state.chain_seq.read().unwrap();
        let p = state.last_hash.read().unwrap().clone();
        (s, p)
    } else {
        (0, None)
    };

    let bundle = GeoProofBundle {
        version: 1,
        epoch_challenge_hex: epoch_hex,
        client_nonce_hex: client_nonce,
        target_location: state.target,
        required_radius_km: state.required_radius_km,
        prover_quote,
        receipts,
        calibrated_velocity_km_per_s: Some(145_000.0),
        prev_chain_hash_hex: prev_hash,
        chain_seq: seq,
        created_at_unix_s: now,
    };

    if advance_chain {
        let h = bundle.record_hash_hex();
        *state.chain_seq.write().unwrap() = seq + 1;
        *state.last_hash.write().unwrap() = Some(h);
        *state.latest_bundle.write().unwrap() = Some(bundle.clone());
    }

    Ok(bundle)
}

async fn probe_single_anchor(
    anchor: &AnchorDescriptor,
    prover_quote: pog_tee::TeeAttestationQuote,
    epoch_hex: &str,
    epoch_bytes: &[u8; 32],
    prover_pk_hex: &str,
    rounds: u16,
) -> Result<AnchorReceipt> {
    let stream = TcpStream::connect(&anchor.endpoint_tcp).await?;
    let stream_peer_ip = stream.peer_addr()?.ip();
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);

    let udp_sock = bind_low_latency_udp("0.0.0.0:0".parse()?, Duration::from_secs(2))?;
    let local_udp_port = udp_sock.local_addr()?.port();

    let eph_sk = EphemeralSecret::random_from_rng(OsRng);
    let eph_pk = X25519PublicKey::from(&eph_sk);

    let init_req = Phase1InitRequest {
        prover_quote,
        epoch_challenge_hex: epoch_hex.to_string(),
        prover_ephemeral_x25519_hex: hex::encode(eph_pk.as_bytes()),
        prover_udp_port: local_udp_port,
        rounds,
    };
    let mut req_line = serde_json::to_string(&init_req)?;
    req_line.push('\n');
    writer.write_all(req_line.as_bytes()).await?;
    writer.flush().await?;

    let mut resp_line = String::new();
    buf_reader.read_line(&mut resp_line).await?;
    let init_resp: Phase1InitResponse = serde_json::from_str(resp_line.trim())?;

    let anchor_eph_raw = hex::decode(&init_resp.anchor_ephemeral_x25519_hex)?;
    let anchor_eph_arr: [u8; 32] = anchor_eph_raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad anchor x25519"))?;
    let shared = eph_sk.diffie_hellman(&X25519PublicKey::from(anchor_eph_arr));
    let session_key = derive_session_key(
        shared.as_bytes(),
        init_resp.session_id,
        epoch_bytes,
        prover_pk_hex,
        &anchor.anchor_id,
    );

    let session_id = init_resp.session_id;
    let anchor_ip = stream_peer_ip;
    let anchor_udp_addr = SocketAddr::new(anchor_ip, init_resp.anchor_udp_port);
    let cookie_raw = hex::decode(&init_resp.return_cookie_hex)?;
    let cookie_arr: [u8; 8] = cookie_raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad return cookie"))?;
    let punch = encode_udp_punch(session_id, cookie_arr);
    let epoch_copy = *epoch_bytes;

    writer.write_all(b"READY\n").await?;
    writer.flush().await?;

    let udp_handle = tokio::task::spawn_blocking(move || -> Result<()> {
        // Punch NAT pinhole & prove UDP return-routability to Anchor's bound UDP port.
        udp_sock.send_to(&punch, anchor_udp_addr)?;
        for _ in 0..rounds {
            respond_once_udp(&udp_sock, session_id, &session_key, &epoch_copy)?;
        }
        Ok(())
    });

    udp_handle.await??;

    resp_line.clear();
    buf_reader.read_line(&mut resp_line).await?;
    let receipt: AnchorReceipt = serde_json::from_str(resp_line.trim())?;
    Ok(receipt)
}

fn parse_http_host_port(url_or_addr: &str) -> Result<(String, String)> {
    let stripped = url_or_addr
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let authority = stripped.split('/').next().unwrap_or(stripped);
    if authority.is_empty() {
        anyhow::bail!("empty endpoint: {url_or_addr}");
    }
    let addr = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    Ok((addr, authority.to_string()))
}

/// Zero-dependency HTTP/1.1 POST of a newly minted hourly `GeoProofBundle` to `pog-log`.
async fn publish_to_log(log_url: &str, bundle: &GeoProofBundle) -> Result<u16> {
    let (addr, host_hdr) = parse_http_host_port(log_url)?;
    let body = serde_json::to_vec(bundle)?;
    let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow::anyhow!("log connect timeout"))??;
    let req = format!(
        "POST /v1/attestations HTTP/1.1\r\nHost: {host_hdr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(req.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;

    let mut resp_buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut resp_buf))
        .await
        .map_err(|_| anyhow::anyhow!("log response timeout"))??;
    let status_line = String::from_utf8_lossy(&resp_buf)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&code) {
        anyhow::bail!("log returned HTTP {code} ({status_line})");
    }
    Ok(code)
}

/// Drop-in reverse proxy forwarding requests to `--upstream` (prover-only geography!).
/// Injects `X-PoG-Claim-Mode: prover-only-geography`, `X-PoG-Proof`, `X-PoG-Prover-Key`, and
/// `X-PoG-Chain-Seq` — NEVER emits `X-PoG-Inference-Receipt` or claims inference-GPU location!
async fn reverse_proxy_handler(
    State(state): State<Arc<ProverState>>,
    req: Request,
) -> Response {
    let Some(ref upstream) = state.upstream else {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("upstream not configured"))
            .unwrap();
    };
    let Ok((addr, host_hdr)) = parse_http_host_port(upstream) else {
        return Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::from("invalid upstream address"))
            .unwrap();
    };

    let (parts, body) = req.into_parts();
    let req_bytes = match to_bytes(body, MAX_PROXY_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(Body::from("request body exceeds 8 MiB sidecar cap"))
                .unwrap();
        }
    };

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let mut raw_req = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        parts.method, path_and_query, host_hdr
    );
    for (k, v) in &parts.headers {
        let name = k.as_str();
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        if let Ok(vs) = v.to_str() {
            raw_req.push_str(&format!("{name}: {vs}\r\n"));
        }
    }
    if !req_bytes.is_empty() {
        raw_req.push_str(&format!("Content-Length: {}\r\n", req_bytes.len()));
    }
    raw_req.push_str("\r\n");

    let mut stream =
        match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => {
                return Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from("upstream unreachable"))
                    .unwrap();
            }
        };
    if stream.write_all(raw_req.as_bytes()).await.is_err()
        || (!req_bytes.is_empty() && stream.write_all(&req_bytes).await.is_err())
        || stream.flush().await.is_err()
    {
        return Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::from("upstream write failed"))
            .unwrap();
    }

    let mut resp_bytes = Vec::new();
    if tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut resp_bytes))
        .await
        .is_err()
    {
        return Response::builder()
            .status(StatusCode::GATEWAY_TIMEOUT)
            .body(Body::from("upstream timeout"))
            .unwrap();
    }

    let split_idx = resp_bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(resp_bytes.len());
    let head_str = String::from_utf8_lossy(&resp_bytes[..split_idx]);
    let resp_body = if split_idx + 4 <= resp_bytes.len() {
        resp_bytes[split_idx + 4..].to_vec()
    } else {
        Vec::new()
    };

    let mut lines = head_str.lines();
    let status_code = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .and_then(|c| StatusCode::from_u16(c).ok())
        .unwrap_or(StatusCode::OK);

    let mut builder = Response::builder().status(status_code);
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let kn = k.trim();
            // Strip any spoofed upstream inference-receipt or claim-mode headers!
            if kn.eq_ignore_ascii_case("transfer-encoding")
                || kn.eq_ignore_ascii_case("connection")
                || kn.eq_ignore_ascii_case(HTTP_HEADER_POG_CLAIM_MODE)
                || kn.eq_ignore_ascii_case("x-pog-inference-receipt")
            {
                continue;
            }
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(kn.as_bytes()),
                HeaderValue::from_str(v.trim()),
            ) {
                builder = builder.header(hn, hv);
            }
        }
    }

    // Explicitly label proxied responses as prover-only geography!
    builder = builder.header(HTTP_HEADER_POG_CLAIM_MODE, CLAIM_MODE_PROVER_ONLY);

    let cached = state.latest_bundle.read().unwrap().clone();
    if let Some(bundle) = cached {
        if let Ok(hdr) = bundle.to_header_value() {
            if let Ok(hv) = HeaderValue::from_str(&hdr) {
                builder = builder.header(HTTP_HEADER_POG_PROOF, hv);
            }
        }
        if let Ok(hv) = HeaderValue::from_str(&bundle.chain_seq.to_string()) {
            builder = builder.header("x-pog-chain-seq", hv);
        }
    }
    if let Ok(hv) = HeaderValue::from_str(&state.keypair.public_key_hex()) {
        builder = builder.header("x-pog-prover-key", hv);
    }

    builder.body(Body::from(resp_body)).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::SigningKey;
    use p384::ecdsa::signature::Signer as P384Signer;
    use p384::ecdsa::{DerSignature as P384DerSig, SigningKey as P384SigningKey};
    use p384::pkcs8::DecodePrivateKey;
    use pog_proto::{
        sign_tls_cert_binding, verify_inference_location_claim, ExpectedInferenceRequest,
        InferenceVerificationPolicy, VerificationPolicy,
    };
    use pog_tee::{
        compute_gpu_binding_nonce, AttestationPolicy, GpuAttestationEvidence,
        GpuProtectedChannelKind, SignedGpuSpdmQuotePayload, SoftwareDevProvider, TeeVendor,
    };
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, PKCS_ECDSA_P384_SHA384};
    use sha2::{Digest, Sha256};
    use x509_parser::prelude::*;

    struct TestLocalGpuExecutor {
        binding: GpuAttestationBinding,
        fail_execution: bool,
    }

    impl LocalBoundGpuExecutor for TestLocalGpuExecutor {
        fn gpu_binding(&self) -> &GpuAttestationBinding {
            &self.binding
        }

        fn execute_on_bound_gpu(
            &self,
            model_id: &str,
            request_bytes: &[u8],
            channel_seq_no: u64,
        ) -> Result<Vec<u8>> {
            if self.fail_execution {
                anyhow::bail!("simulated local Confidential GPU execution failure");
            }
            Ok(format!(
                "{{\"model\":\"{model_id}\",\"seq\":{channel_seq_no},\"echo_len\":{}}}",
                request_bytes.len()
            )
            .into_bytes())
        }
    }

    fn build_signed_test_gpu(
        prover_pk: &[u8; 32],
        epoch: &[u8],
        gpu_uuid: &str,
        now: u64,
    ) -> (GpuAttestationBinding, String) {
        let transcript = "77".repeat(32);
        let mut root_p = CertificateParams::default();
        root_p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_p
            .distinguished_name
            .push(DnType::CommonName, "Test-NVIDIA-Root");
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

        let gpu_nonce_hex = hex::encode(compute_gpu_binding_nonce(prover_pk, epoch, &transcript));
        let payload = SignedGpuSpdmQuotePayload {
            gpu_vendor: "nvidia-cc".into(),
            gpu_model: "NVIDIA H100 80GB SXM5 Confidential".into(),
            gpu_uuid: gpu_uuid.into(),
            gpu_nonce_hex: gpu_nonce_hex.clone(),
            spdm_session_transcript_hash_hex: transcript.clone(),
            protected_channel_id: "spdm-pcie-0000:81:00.0-sess-9".into(),
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
            spdm_session_transcript_hash_hex: transcript.clone(),
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
            spdm_session_transcript_hash_hex: Some(transcript),
            protected_channel_id: Some(payload.protected_channel_id),
            evidence: Some(ev),
            physical_fingerprint: None,
        };
        (binding, root_fp)
    }

    #[test]
    fn test_parse_http_host_port() {
        let (addr, host) = parse_http_host_port("http://127.0.0.1:8090/v1").unwrap();
        assert_eq!(addr, "127.0.0.1:8090");
        assert_eq!(host, "127.0.0.1:8090");

        let (addr2, host2) = parse_http_host_port("127.0.0.1:8000").unwrap();
        assert_eq!(addr2, "127.0.0.1:8000");
        assert_eq!(host2, "127.0.0.1:8000");
    }

    #[test]
    fn test_runtime_mode_forbids_combining_local_gpu_and_upstream() {
        assert_eq!(
            validate_runtime_mode(true, None).unwrap(),
            InferenceExecutionMode::LocalBoundConfidentialGpuOnly
        );
        assert_eq!(
            validate_runtime_mode(false, Some("http://127.0.0.1:8000")).unwrap(),
            InferenceExecutionMode::ProxyForwarded
        );
        let err = validate_runtime_mode(true, Some("http://127.0.0.1:8000")).unwrap_err();
        assert!(err.to_string().contains("forbids any remote upstream"));
    }

    #[tokio::test]
    async fn test_proxy_mode_rejects_infer_endpoint_with_403_prover_only() {
        let state = Arc::new(ProverState {
            grid: AnchorGrid {
                version: "2.0.0".into(),
                grid_name: "test".into(),
                description: "test".into(),
                anchors: Vec::new(),
            },
            target: LatLon::new(39.0438, -77.4874),
            required_radius_km: 350.0,
            rounds: 4,
            log_url: None,
            upstream: Some("http://127.0.0.1:8000".into()),
            execution_mode: InferenceExecutionMode::ProxyForwarded,
            keypair: WorkloadKeypair::generate(),
            tee_provider: Box::new(SoftwareDevProvider::new("11".repeat(48))),
            latest_bundle: RwLock::new(None),
            chain_seq: RwLock::new(0),
            last_hash: RwLock::new(None),
        });
        let resp = infer_endpoint_handler(State(state)).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers()
                .get(HTTP_HEADER_POG_CLAIM_MODE)
                .and_then(|v| v.to_str().ok()),
            Some(CLAIM_MODE_PROVER_ONLY)
        );
    }

    #[test]
    fn test_local_gpu_runtime_post_exec_receipt_same_tls_non_interchangeable_and_fail_closed() {
        let now = Utc::now().timestamp().max(0) as u64;
        let kp = WorkloadKeypair::generate();
        let runtime_meas = "24".repeat(48);
        let epoch = [0x55u8; 32];
        let epoch_hex = hex::encode(epoch);

        let (gpu_binding, root_fp) =
            build_signed_test_gpu(&kp.public_key_bytes(), &epoch, "GPU-LOCAL-H100-01", now);
        let mut prover_quote = SoftwareDevProvider::new(&runtime_meas)
            .attest(&kp.public_key_bytes(), &epoch, Some(gpu_binding.clone()))
            .unwrap();
        prover_quote.generated_at_unix_s = now;

        let sk1 = SigningKey::generate(&mut OsRng);
        let sk2 = SigningKey::generate(&mut OsRng);
        let grid = AnchorGrid {
            version: "2.0.0".into(),
            grid_name: "ashburn".into(),
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
                rtt_min_us: 1_400,
                rtt_p50_us: 1_500,
                rtt_samples_us: vec![1_400, 1_500],
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

        let tls_ekm = "66".repeat(32);
        let tls_cert = "77".repeat(32);
        let cert_sig = sign_tls_cert_binding(&kp, &tls_cert);
        let tls_sess = ActiveTlsSession {
            tls_protocol_version: "TLSv1.3".into(),
            exporter_label: TLS_EXPORTER_LABEL.into(),
            tls_exporter_ekm_hex: tls_ekm.clone(),
            server_cert_sha256_hex: tls_cert.clone(),
            cert_prover_binding_sig_hex: cert_sig.clone(),
            terminated_in_attested_runtime: true,
            request_seq: AtomicU64::new(0),
        };

        let runtime = LocalConfidentialGpuRuntime::new(
            kp,
            runtime_meas.clone(),
            Box::new(TestLocalGpuExecutor {
                binding: gpu_binding.clone(),
                fail_execution: false,
            }),
        );

        // Execute TWO requests on the EXACT SAME end-to-end keep-alive TLS 1.3 connection!
        let nonce1 = "a1".repeat(32);
        let req1 = br#"{"prompt":"first local H100 inference"}"#;
        let (out1, receipt1) = runtime
            .execute_and_sign_receipt(&bundle, &tls_sess, &nonce1, "llama-3.3-70b", req1, now)
            .unwrap();

        let nonce2 = "b2".repeat(32);
        let req2 = br#"{"prompt":"second local H100 inference on same TLS conn"}"#;
        let (out2, receipt2) = runtime
            .execute_and_sign_receipt(&bundle, &tls_sess, &nonce2, "llama-3.3-70b", req2, now)
            .unwrap();

        assert_eq!(receipt1.channel_seq_no, 1);
        assert_eq!(receipt2.channel_seq_no, 2);
        assert_eq!(
            receipt1.tls_session_binding.as_ref().unwrap().tls_connection_request_seq,
            1
        );
        assert_eq!(
            receipt2.tls_session_binding.as_ref().unwrap().tls_connection_request_seq,
            2
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
            allowed_inference_runtime_measurements: vec![runtime_meas.clone()],
            require_measured_inference_runtime: true,
            pinned_gpu_root_sha256_hex: vec![root_fp],
            require_hardware_rooted_locality: false,
            max_receipt_age_seconds: 300,
        };

        // Both receipts verify independently with their embedded PoG proof bundle!
        let exp1 = ExpectedInferenceRequest {
            request_nonce_hex: &nonce1,
            model_id: "llama-3.3-70b",
            request_bytes: req1,
            output_bytes: &out1,
            tls_exporter_ekm_hex: &tls_ekm,
            server_cert_sha256_hex: &tls_cert,
            expected_tls_connection_request_seq: Some(1),
        };
        let exp2 = ExpectedInferenceRequest {
            request_nonce_hex: &nonce2,
            model_id: "llama-3.3-70b",
            request_bytes: req2,
            output_bytes: &out2,
            tls_exporter_ekm_hex: &tls_ekm,
            server_cert_sha256_hex: &tls_cert,
            expected_tls_connection_request_seq: Some(2),
        };
        let rep1 = verify_inference_location_claim(&receipt1, None, &grid, &exp1, &pol, now + 5)
            .unwrap();
        assert!(rep1.inference_location_verified, "{:?}", rep1.failure_reasons);
        let rep2 = verify_inference_location_claim(&receipt2, None, &grid, &exp2, &pol, now + 5)
            .unwrap();
        assert!(rep2.inference_location_verified, "{:?}", rep2.failure_reasons);

        // Swapping receipt1 onto request2 on the SAME TLS connection MUST FAIL CLOSED!
        let rep_swap = verify_inference_location_claim(&receipt1, None, &grid, &exp2, &pol, now + 5)
            .unwrap();
        assert!(!rep_swap.inference_location_verified);

        // Proxy-terminated TLS hop MUST be refused BEFORE execution!
        let proxy_tls = ActiveTlsSession {
            tls_protocol_version: "TLSv1.3".into(),
            exporter_label: TLS_EXPORTER_LABEL.into(),
            tls_exporter_ekm_hex: tls_ekm,
            server_cert_sha256_hex: tls_cert,
            cert_prover_binding_sig_hex: cert_sig,
            terminated_in_attested_runtime: false,
            request_seq: AtomicU64::new(0),
        };
        assert!(runtime
            .execute_and_sign_receipt(&bundle, &proxy_tls, &nonce1, "llama-3.3-70b", req1, now)
            .is_err());

        // Failed local GPU execution MUST return Err and emit NO receipt!
        let failing_kp = WorkloadKeypair::generate();
        let failing_cert_sig = sign_tls_cert_binding(&failing_kp, &"77".repeat(32));
        let (f_gpu, _) = build_signed_test_gpu(
            &failing_kp.public_key_bytes(),
            &epoch,
            "GPU-LOCAL-H100-FAIL",
            now,
        );
        let mut f_bundle = bundle;
        f_bundle.prover_quote.public_key_hex = failing_kp.public_key_hex();
        f_bundle.prover_quote.gpu_binding = Some(f_gpu.clone());
        let failing_rt = LocalConfidentialGpuRuntime::new(
            failing_kp,
            runtime_meas,
            Box::new(TestLocalGpuExecutor {
                binding: f_gpu,
                fail_execution: true,
            }),
        );
        let failing_tls = ActiveTlsSession {
            tls_protocol_version: "TLSv1.3".into(),
            exporter_label: TLS_EXPORTER_LABEL.into(),
            tls_exporter_ekm_hex: "66".repeat(32),
            server_cert_sha256_hex: "77".repeat(32),
            cert_prover_binding_sig_hex: failing_cert_sig,
            terminated_in_attested_runtime: true,
            request_seq: AtomicU64::new(0),
        };
        assert!(failing_rt
            .execute_and_sign_receipt(&f_bundle, &failing_tls, &nonce1, "llama-3.3-70b", req1, now)
            .is_err());
    }
}
