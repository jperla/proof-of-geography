use anyhow::Result;
use axum::{
    body::Bytes,
    extract::{Query, State as AxumState},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use pog_proto::{
    accept_phase1_anchor, bind_low_latency_udp, decode_udp_punch, enclave_measure_vsock_round,
    measure_udp_round, read_vsock_frame, verify_phase1_confirm, write_vsock_frame,
    AnchorEndorsement, AnchorReceipt, EnclaveToHostMsg, HostToEnclaveMsg, Phase1Confirm,
    Phase1InitRequest, DEFAULT_NITRO_VSOCK_PORT, PHASE1_PROTOCOL_VERSION, PUNCH_PACKET_SIZE,
};
#[cfg(target_os = "linux")]
use pog_proto::PACKET_SIZE;
use pog_tee::{auto_detect_provider, AttestationPolicy, TeeProvider};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{info, warn};

/// Hard security caps to protect public Anchor nodes from memory exhaustion, Slowloris, and bandwidth abuse.
const MAX_LINE_BYTES: u64 = 32 * 1024;
const MAX_CONFIRM_LINE_BYTES: u64 = 512;
const MAX_ROUNDS: u16 = 16;
const PHASE1_READ_TIMEOUT: Duration = Duration::from_secs(4);
const SESSION_TOTAL_TIMEOUT: Duration = Duration::from_secs(12);
const INFO_CACHE_TTL: Duration = Duration::from_secs(60);
const MAX_TRACKED_IPS: usize = 32_768;

#[derive(Parser, Debug)]
#[command(
    name = "pog-anchor",
    about = "Proof of Geography Multi-Cloud Anchor TEE Daemon (Hardened Production + AWS Nitro Vsock Mode)"
)]
struct Args {
    #[arg(long, default_value = "local-anchor-01")]
    anchor_id: String,
    #[arg(long, default_value = "gcp")]
    cloud_provider: String,
    #[arg(long, default_value = "0.0.0.0:7443")]
    tcp_listen: SocketAddr,
    #[arg(long, default_value = "0.0.0.0:7444")]
    udp_bind: SocketAddr,
    /// Narrow UDP port range for Phase 2 ephemeral sockets.
    #[arg(long, default_value_t = 40000)]
    udp_port_min: u16,
    #[arg(long, default_value_t = 40999)]
    udp_port_max: u16,
    /// Public HTTP metadata endpoint (/info, /health) serving cached hardware-attested Anchor metadata.
    #[arg(long, default_value = "0.0.0.0:7445")]
    http_info_listen: SocketAddr,
    /// Maximum simultaneous in-flight prover sessions.
    #[arg(long, default_value_t = 64)]
    max_concurrent: usize,
    /// Per-IP probe rate limit per 60-second window.
    #[arg(long, default_value_t = 12)]
    max_per_ip_per_min: u32,
    /// Global probe rate limit per 60-second window.
    #[arg(long, default_value_t = 600)]
    max_global_per_min: u32,
    /// Allow software-dev TEE fallback for THIS Anchor (LOCAL DEV ONLY; NEVER in production!).
    #[arg(long, default_value_t = false)]
    allow_dev_tee: bool,
    /// Allow incoming Provers using software-dev TEE quotes (e.g., public laptop demos; NOT production proofs).
    #[arg(long, default_value_t = false)]
    allow_dev_prover: bool,
    /// Optional hex seed (32 bytes) for deterministic local unit tests ONLY.
    /// FORBIDDEN when running on any hardware TEE (enclave keys must be ephemeral & non-exportable!).
    #[arg(long)]
    seed_hex: Option<String>,
    /// Optional path to a signed operator AnchorEndorsement certificate (also checks POG_ENDORSEMENT_PATH).
    #[arg(long)]
    endorsement_path: Option<std::path::PathBuf>,
    /// Optional pinned operator Ed25519 root public key hex (also checks POG_ROOT_PUBLIC_KEY_HEX)
    /// to verify endorsement signatures locally before serving them on `/info`.
    #[arg(long)]
    operator_root_pk_hex: Option<String>,
    /// Run inside an AWS Nitro Enclave listening on `AF_VSOCK` port (e.g., 7443) with zero network interfaces.
    /// All NSM attestation, X25519 key agreement, Phase 2 BLAKE3-MAC timing, and Ed25519 receipt signing
    /// happen strictly inside enclave RAM.
    #[arg(long)]
    vsock_port: Option<u32>,
    /// Run on the UNTRUSTED parent EC2 host as a stateless TCP/UDP-to-vsock relay forwarding traffic to
    /// the Nitro Enclave CID (holds NO private signing keys and NO session secrets!).
    #[arg(long, default_value_t = false)]
    nitro_host_relay: bool,
    /// Nitro Enclave CID to connect to when `--nitro-host-relay` is enabled (from `nitro-cli describe-enclaves`).
    #[arg(long)]
    enclave_cid: Option<u32>,
    /// Nitro Enclave vsock port to connect to when `--nitro-host-relay` is enabled.
    #[arg(long, default_value_t = DEFAULT_NITRO_VSOCK_PORT)]
    enclave_vsock_port: u32,
}

struct RateLimiter {
    per_ip_limit: u32,
    global_limit: u32,
    window_start: Instant,
    global_count: u32,
    ip_counts: HashMap<IpAddr, u32>,
}

impl RateLimiter {
    fn new(per_ip_limit: u32, global_limit: u32) -> Self {
        Self {
            per_ip_limit,
            global_limit,
            window_start: Instant::now(),
            global_count: 0,
            ip_counts: HashMap::new(),
        }
    }

    fn check_and_record(&mut self, ip: IpAddr) -> bool {
        if self.window_start.elapsed() >= Duration::from_secs(60) {
            self.window_start = Instant::now();
            self.global_count = 0;
            self.ip_counts.clear();
        }
        if self.global_count >= self.global_limit {
            return false;
        }
        if self.ip_counts.len() >= MAX_TRACKED_IPS && !self.ip_counts.contains_key(&ip) {
            return false;
        }
        let entry = self.ip_counts.entry(ip).or_insert(0);
        if *entry >= self.per_ip_limit {
            return false;
        }
        *entry += 1;
        self.global_count += 1;
        true
    }
}

struct CachedInfo {
    generated_at: Instant,
    payload: serde_json::Value,
}

struct AnchorState {
    anchor_id: String,
    cloud_provider: String,
    signing_key: SigningKey,
    cookie_secret: [u8; 32],
    tee_provider: Box<dyn TeeProvider>,
    tee_policy: AttestationPolicy,
    udp_bind_ip: IpAddr,
    udp_port_min: u16,
    udp_port_max: u16,
    concurrency_sem: Arc<Semaphore>,
    rate_limiter: Mutex<RateLimiter>,
    info_cache: RwLock<Option<CachedInfo>>,
    in_memory_endorsement: RwLock<Option<AnchorEndorsement>>,
    endorsement_path: PathBuf,
    operator_root_pk_hex: Option<String>,
}

/// Strictly validate an `AnchorEndorsement` struct against live anchor identity, RAM key, time,
/// and optional pinned operator root public key.
fn validate_endorsement_cert(
    cert: AnchorEndorsement,
    expected_anchor_id: &str,
    live_pk_hex: &str,
    pinned_root_pk_hex: Option<&str>,
    now_unix_s: u64,
) -> (Option<AnchorEndorsement>, &'static str) {
    if cert.anchor_id != expected_anchor_id {
        return (None, "anchor_id_mismatch");
    }
    if !cert.anchor_public_key_hex.eq_ignore_ascii_case(live_pk_hex) {
        return (None, "key_mismatch");
    }
    if now_unix_s > cert.expires_at_unix_s {
        return (None, "expired");
    }
    if let Some(root_pk) = pinned_root_pk_hex {
        if cert.verify(root_pk, now_unix_s).is_err() {
            return (None, "invalid_signature");
        }
    }
    (Some(cert), "matched")
}

/// Strictly load and validate an operator `AnchorEndorsement` against this Anchor's live ephemeral
/// in-RAM public key, `anchor_id`, current time, and optional pinned operator root public key.
///
/// Always rejects old/stale endorsements after a restart or key rotation!
fn load_verified_endorsement(
    path: &std::path::Path,
    expected_anchor_id: &str,
    live_pk_hex: &str,
    pinned_root_pk_hex: Option<&str>,
    now_unix_s: u64,
) -> (Option<AnchorEndorsement>, &'static str) {
    let raw = match std::fs::read_to_string(path) {
        Ok(r) => r,
        Err(_) => return (None, "missing"),
    };
    let cert: AnchorEndorsement = match serde_json::from_str(&raw) {
        Ok(c) => c,
        Err(_) => return (None, "parse_error"),
    };
    validate_endorsement_cert(
        cert,
        expected_anchor_id,
        live_pk_hex,
        pinned_root_pk_hex,
        now_unix_s,
    )
}

fn resolve_verified_endorsement(
    state: &AnchorState,
    effective_anchor_id: &str,
    live_pk_hex: &str,
    now_unix_s: u64,
) -> (Option<AnchorEndorsement>, &'static str) {
    if let Some(ref mem_cert) = *state.in_memory_endorsement.read().unwrap() {
        let (ok_cert, status) = validate_endorsement_cert(
            mem_cert.clone(),
            effective_anchor_id,
            live_pk_hex,
            state.operator_root_pk_hex.as_deref(),
            now_unix_s,
        );
        if ok_cert.is_some() {
            return (ok_cert, status);
        }
    }
    load_verified_endorsement(
        &state.endorsement_path,
        effective_anchor_id,
        live_pk_hex,
        state.operator_root_pk_hex.as_deref(),
        now_unix_s,
    )
}

#[derive(serde::Deserialize)]
struct AttestQuery {
    nonce: String,
}

/// Validate a caller-supplied hex freshness nonce (16..=64 bytes, i.e. 32..=128 hex chars).
fn parse_caller_nonce_hex(nonce_hex: &str) -> Result<Vec<u8>, String> {
    let trimmed = nonce_hex.trim();
    if trimmed.len() < 32 || trimmed.len() > 128 || !trimmed.len().is_multiple_of(2) {
        return Err("nonce must be 32..=128 even hex characters (16..=64 random bytes)".into());
    }
    hex::decode(trimmed).map_err(|e| format!("invalid hex nonce: {e}"))
}

/// Canonical Proof-of-Possession signing payload binding the live probe Ed25519 key to the
/// caller's fresh nonce and the hardware-attested workload measurement.
fn attest_pop_message(anchor_id: &str, caller_nonce_hex: &str, measurement_hex: &str) -> Vec<u8> {
    format!("POG-ATTEST-POP-V1\n{anchor_id}\n{caller_nonce_hex}\n{measurement_hex}\n").into_bytes()
}

/// Generate a FRESH, uncached hardware attestation bound to a public verifier's random nonce
/// plus an Ed25519 Proof-of-Possession signature by this Anchor's live ephemeral probe key.
/// Requires ZERO cloud credentials and ZERO SSH!
fn build_fresh_attest_payload(
    state: &AnchorState,
    caller_nonce_hex: &str,
) -> Result<serde_json::Value, String> {
    build_fresh_attest_payload_with_id(state, caller_nonce_hex, &state.anchor_id)
}

fn build_fresh_attest_payload_with_id(
    state: &AnchorState,
    caller_nonce_hex: &str,
    effective_anchor_id: &str,
) -> Result<serde_json::Value, String> {
    let nonce_bytes = parse_caller_nonce_hex(caller_nonce_hex)?;
    let norm_nonce_hex = hex::encode(&nonce_bytes);
    let pk_bytes = state.signing_key.verifying_key().to_bytes();
    let pk_hex = hex::encode(pk_bytes);
    let now = Utc::now().timestamp().max(0) as u64;
    let quote = state
        .tee_provider
        .attest(&pk_bytes, &nonce_bytes, None)
        .map_err(|e| format!("hardware attestation failed: {e}"))?;
    let pop_msg = attest_pop_message(
        effective_anchor_id,
        &norm_nonce_hex,
        &quote.workload_measurement_hex,
    );
    let pop_sig_hex = hex::encode(state.signing_key.sign(&pop_msg).to_bytes());
    let (operator_endorsement, endorsement_status) =
        resolve_verified_endorsement(state, effective_anchor_id, &pk_hex, now);
    let vendor = state.tee_provider.vendor();
    Ok(serde_json::json!({
        "anchor_id": effective_anchor_id,
        "cloud_provider": state.cloud_provider,
        "tee_vendor": vendor,
        "hardware_tee_device": vendor.is_production_hardware_tee(),
        "ephemeral_key_in_ram": true,
        "fresh_caller_nonce": true,
        "caller_nonce_hex": norm_nonce_hex,
        "public_key_hex": pk_hex,
        "proof_of_possession_sig_hex": pop_sig_hex,
        "tee_quote": quote,
        "operator_endorsement": operator_endorsement,
        "endorsement_status": endorsement_status,
        "timing_boundary_assumptions": {
            "key_generation": "inside_tee_ram_ephemeral",
            "challenge_mac_and_rtt_stopwatch": "inside_tee_monotonic_instant",
            "wall_clock_timestamps": "host_or_ntp_untrusted_for_freshness_rely_on_caller_nonce",
            "network_or_vsock_relay": "untrusted_relay_can_only_delay_widening_outer_bound_fail_safe"
        },
        "hardened": true,
    }))
}

fn build_info_payload(state: &AnchorState, bootstrap_nonce: String) -> serde_json::Value {
    build_info_payload_with_id(state, bootstrap_nonce, &state.anchor_id)
}

fn build_info_payload_with_id(
    state: &AnchorState,
    bootstrap_nonce: String,
    effective_anchor_id: &str,
) -> serde_json::Value {
    let pk_bytes = state.signing_key.verifying_key().to_bytes();
    let pk_hex = hex::encode(pk_bytes);
    let now = Utc::now().timestamp().max(0) as u64;
    let quote = state
        .tee_provider
        .attest(&pk_bytes, bootstrap_nonce.as_bytes(), None)
        .ok();
    let (operator_endorsement, endorsement_status) =
        resolve_verified_endorsement(state, effective_anchor_id, &pk_hex, now);
    let vendor = state.tee_provider.vendor();
    serde_json::json!({
        "anchor_id": effective_anchor_id,
        "cloud_provider": state.cloud_provider,
        "tee_vendor": vendor,
        "hardware_tee_device": vendor.is_production_hardware_tee(),
        "ephemeral_key_in_ram": true,
        "public_key_hex": pk_hex,
        "bootstrap_nonce": bootstrap_nonce,
        "tee_quote": quote,
        "operator_endorsement": operator_endorsement,
        "endorsement_status": endorsement_status,
        "udp_port_range": [state.udp_port_min, state.udp_port_max],
        "hardened": true,
    })
}

fn bind_scoped_udp(ip: IpAddr, port_min: u16, port_max: u16) -> std::io::Result<UdpSocket> {
    let span = (port_max.saturating_sub(port_min) as u32) + 1;
    let start_offset = OsRng.next_u32() % span;
    for attempt in 0..span.min(64) {
        let port = port_min + ((start_offset + attempt) % span) as u16;
        if let Ok(sock) =
            bind_low_latency_udp(SocketAddr::new(ip, port), Duration::from_millis(1500))
        {
            return Ok(sock);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrInUse,
        "no free UDP port in scoped range",
    ))
}

async fn read_bounded_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    max_bytes: u64,
) -> Result<String> {
    let mut limited = reader.take(max_bytes);
    let mut buf = String::new();
    let n = tokio::time::timeout(PHASE1_READ_TIMEOUT, limited.read_line(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("read timeout"))??;
    if n == 0 {
        anyhow::bail!("unexpected EOF");
    }
    if n as u64 >= max_bytes && !buf.ends_with('\n') {
        anyhow::bail!("line exceeded {max_bytes} byte security limit");
    }
    Ok(buf)
}

fn fetch_azure_imds_vm_name() -> Option<String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let addr: SocketAddr = "169.254.169.254:80".parse().ok()?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
    s.write_all(
        b"GET /metadata/instance/compute/name?api-version=2021-02-01&format=text HTTP/1.1\r\nHost: 169.254.169.254\r\nMetadata: true\r\nConnection: close\r\n\r\n",
    )
    .ok()?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).ok()?;
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..sep]).ok()?;
    if !head.lines().next()?.contains(" 200 ") {
        return None;
    }
    let body = std::str::from_utf8(&raw[sep + 4..]).ok()?.trim();
    if !body.is_empty() && body.len() <= 128 && body.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') {
        Some(body.to_string())
    } else {
        None
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut args = Args::parse();
    // Allow GCP Confidential Space / immutable zero-SSH CVM images to resolve `anchor_id` via
    // `POG_ANCHOR_ID` env var or `--anchor-id auto` (Azure IMDS compute/name, else `/etc/hostname`).
    if args.anchor_id == "local-anchor-01" || args.anchor_id == "auto" {
        if let Ok(env_id) = std::env::var("POG_ANCHOR_ID") {
            let trimmed = env_id.trim();
            if !trimmed.is_empty() {
                args.anchor_id = trimmed.to_string();
            }
        }
    }
    if args.anchor_id == "auto" {
        if let Some(imds_name) = fetch_azure_imds_vm_name() {
            args.anchor_id = imds_name;
        } else if let Ok(hn) = std::fs::read_to_string("/etc/hostname") {
            let trimmed = hn.trim();
            if !trimmed.is_empty() && trimmed != "localhost" {
                args.anchor_id = trimmed.to_string();
            }
        }
    }

    // Mode A: Untrusted Parent EC2 Host Relay -> forwards TCP/UDP/HTTP to Nitro Enclave over AF_VSOCK.
    if args.nitro_host_relay {
        let cid = args.enclave_cid.ok_or_else(|| {
            anyhow::anyhow!("--nitro-host-relay requires --enclave-cid <CID> from nitro-cli")
        })?;
        return run_nitro_host_relay(args, cid).await;
    }

    let tee_provider = auto_detect_provider(None, args.allow_dev_tee)?;

    // Security Invariant: Hardware TEEs MUST ALWAYS generate a fresh ephemeral non-exportable
    // signing key strictly inside enclave RAM (NEVER accept external deterministic --seed-hex!).
    if args.seed_hex.is_some() && tee_provider.vendor().is_production_hardware_tee() {
        anyhow::bail!(
            "SECURITY VIOLATION: --seed-hex is FORBIDDEN on hardware TEE ({}); enclave signing keys must be generated ephemerally inside TEE RAM",
            tee_provider.vendor().as_str()
        );
    }

    let signing_key = if let Some(ref seed) = args.seed_hex {
        let bytes = hex::decode(seed)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("seed_hex must be 32 bytes"))?;
        SigningKey::from_bytes(&arr)
    } else {
        SigningKey::generate(&mut OsRng)
    };

    let mut cookie_secret = [0u8; 32];
    OsRng.fill_bytes(&mut cookie_secret);

    let pk_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let mut tee_policy = if args.allow_dev_tee || args.allow_dev_prover {
        warn!("NON-PRODUCTION DEV TEE POLICY ENABLED — DO NOT USE FOR PRODUCTION PROOFS");
        AttestationPolicy::allow_dev_software()
    } else {
        AttestationPolicy::production()
    };
    // Enable offline verification of GCP Confidential Space Intel TDX provers (e.g. llm.proofofgeography.com)
    // using either an operator-provided JWKS file or the pinned official Google Confidential Space JWKS.
    let gcp_cs_jwks = std::env::var("POG_GCP_CS_JWKS_PATH")
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_else(|| pog_tee::PINNED_OFFICIAL_GCP_CS_JWKS_JSON.to_string());
    tee_policy.trusted_gcp_cs_jwks_json = Some(gcp_cs_jwks);

    let endorsement_path = args
        .endorsement_path
        .or_else(|| std::env::var("POG_ENDORSEMENT_PATH").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/etc/pog/endorsement.json"));
    let operator_root_pk_hex = args
        .operator_root_pk_hex
        .or_else(|| std::env::var("POG_ROOT_PUBLIC_KEY_HEX").ok());

    let state = Arc::new(AnchorState {
        anchor_id: args.anchor_id.clone(),
        cloud_provider: args.cloud_provider.clone(),
        signing_key,
        cookie_secret,
        tee_provider,
        tee_policy,
        udp_bind_ip: args.udp_bind.ip(),
        udp_port_min: args.udp_port_min,
        udp_port_max: args.udp_port_max,
        concurrency_sem: Arc::new(Semaphore::new(args.max_concurrent)),
        rate_limiter: Mutex::new(RateLimiter::new(
            args.max_per_ip_per_min,
            args.max_global_per_min,
        )),
        info_cache: RwLock::new(None),
        in_memory_endorsement: RwLock::new(None),
        endorsement_path,
        operator_root_pk_hex,
    });

    // Mode B: Running INSIDE an AWS Nitro Enclave on AF_VSOCK (zero network interfaces!).
    if let Some(vport) = args.vsock_port {
        info!(
            anchor_id = %state.anchor_id,
            tee = state.tee_provider.vendor().as_str(),
            pubkey = %pk_hex,
            vsock_port = vport,
            "Starting AWS Nitro Enclave Anchor inside isolated AF_VSOCK boundary"
        );
        return run_nitro_enclave_vsock_server(state, vport);
    }

    // Mode C: Standard Confidential VM (GCP/Azure AMD SEV-SNP or Intel TDX) with direct TCP/UDP/HTTP.
    info!(
        anchor_id = %state.anchor_id,
        cloud = %state.cloud_provider,
        tee = state.tee_provider.vendor().as_str(),
        pubkey = %pk_hex,
        tcp = %args.tcp_listen,
        udp_range = format!("{}-{}", args.udp_port_min, args.udp_port_max),
        max_concurrent = args.max_concurrent,
        "Starting HARDENED PoG Anchor TEE daemon"
    );

    let info_state = Arc::clone(&state);
    let info_listen = args.http_info_listen;
    tokio::spawn(async move {
        let app = Router::new()
            .route(
                "/health",
                get(|| async { Json(serde_json::json!({ "status": "ok" })) }),
            )
            .route("/info", get(anchor_info_handler))
            .route("/attest", get(anchor_attest_handler))
            .route("/endorsement", post(anchor_post_endorsement_handler))
            .with_state(info_state);
        if let Ok(listener) = TcpListener::bind(info_listen).await {
            info!(http_info = %info_listen, "Anchor cached HTTP /info endpoint ready");
            let _ = axum::serve(listener, app).await;
        }
    });

    let listener = TcpListener::bind(args.tcp_listen).await?;
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let allowed = {
            let mut rl = state.rate_limiter.lock().unwrap();
            rl.check_and_record(peer_addr.ip())
        };
        if !allowed {
            warn!(peer = %peer_addr.ip(), "Rate limit exceeded; dropping connection");
            drop(stream);
            continue;
        }

        let permit = match Arc::clone(&state.concurrency_sem).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!(peer = %peer_addr.ip(), "Max concurrency reached; shedding load");
                drop(stream);
                continue;
            }
        };

        let st = Arc::clone(&state);
        tokio::spawn(async move {
            let _permit = permit;
            let res = tokio::time::timeout(
                SESSION_TOTAL_TIMEOUT,
                handle_prover_session(stream, peer_addr, st),
            )
            .await;
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!(peer = %peer_addr.ip(), err = %e, "Prover session rejected"),
                Err(_) => warn!(peer = %peer_addr.ip(), "Prover session hard timeout"),
            }
        });
    }
}

/// Handle a single host-to-enclave vsock stream INSIDE the AWS Nitro Enclave.
/// Generic over `Read + Write` so both Linux `vsock::VsockStream` and cross-platform loopback tests
/// execute the exact same enclave-side attestation, X25519 key agreement, Phase 2 BLAKE3-MAC timing,
/// and Ed25519 receipt signing logic!
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn handle_enclave_session_stream<S: Read + Write>(
    stream: &mut S,
    state: &AnchorState,
) -> Result<()> {
    let first: HostToEnclaveMsg = read_vsock_frame(stream)?;
    match first {
        HostToEnclaveMsg::GetInfo {
            bootstrap_nonce,
            anchor_id,
        } => {
            let effective_id = anchor_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(&state.anchor_id);
            let payload = build_info_payload_with_id(state, bootstrap_nonce, effective_id);
            write_vsock_frame(stream, &EnclaveToHostMsg::InfoResponse { payload })?;
            Ok(())
        }
        HostToEnclaveMsg::AttestFresh {
            caller_nonce_hex,
            anchor_id,
        } => {
            let effective_id = anchor_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(&state.anchor_id);
            match build_fresh_attest_payload_with_id(state, &caller_nonce_hex, effective_id) {
                Ok(payload) => {
                    write_vsock_frame(stream, &EnclaveToHostMsg::AttestResponse { payload })?;
                    Ok(())
                }
                Err(message) => {
                    let _ = write_vsock_frame(stream, &EnclaveToHostMsg::Error { message: message.clone() });
                    anyhow::bail!(message);
                }
            }
        }
        HostToEnclaveMsg::Phase1Start {
            peer_ip,
            host_udp_port,
            init_req,
            anchor_id,
        } => {
            let effective_id = anchor_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(&state.anchor_id)
                .to_string();
            let now = Utc::now().timestamp().max(0) as u64;
            let anchor_hs = match accept_phase1_anchor(
                &init_req,
                &effective_id,
                &state.signing_key,
                state.tee_provider.as_ref(),
                &state.tee_policy,
                &state.cookie_secret,
                &peer_ip,
                host_udp_port,
                MAX_ROUNDS,
                now,
            ) {
                Ok(hs) => hs,
                Err(e) => {
                    let message = format!("Phase 1 v2 authentication rejected: {e}");
                    let _ = write_vsock_frame(
                        stream,
                        &EnclaveToHostMsg::Error {
                            message: message.clone(),
                        },
                    );
                    anyhow::bail!(message);
                }
            };

            write_vsock_frame(
                stream,
                &EnclaveToHostMsg::Phase1Ready {
                    init_resp: anchor_hs.init_resp.clone(),
                    return_cookie_hex: hex::encode(anchor_hs.cookie),
                },
            )?;

            // Wait for parent relay to forward Prover's explicit Phase1Confirm + UDP PUNCH signal.
            // Verify Prover key confirmation INSIDE enclave RAM BEFORE starting timed Phase 2 rounds!
            let start_msg: HostToEnclaveMsg = read_vsock_frame(stream)?;
            let (rounds, prover_confirm) = match start_msg {
                HostToEnclaveMsg::Phase2Start {
                    rounds,
                    prover_confirm,
                } => (rounds, prover_confirm),
                _ => {
                    let msg = "expected Phase2Start with Phase1Confirm from host relay".to_string();
                    let _ = write_vsock_frame(stream, &EnclaveToHostMsg::Error { message: msg.clone() });
                    anyhow::bail!(msg);
                }
            };
            if rounds != anchor_hs.negotiated_rounds {
                let msg = format!(
                    "Phase2Start rounds {rounds} != negotiated rounds {}",
                    anchor_hs.negotiated_rounds
                );
                let _ = write_vsock_frame(stream, &EnclaveToHostMsg::Error { message: msg.clone() });
                anyhow::bail!(msg);
            }
            if let Err(e) = verify_phase1_confirm(&anchor_hs, &prover_confirm) {
                let msg = format!("Phase 1 v2 prover key confirmation failed: {e}");
                let _ = write_vsock_frame(stream, &EnclaveToHostMsg::Error { message: msg.clone() });
                anyhow::bail!(msg);
            }

            let mut samples = Vec::with_capacity(rounds as usize);
            for round in 0..rounds {
                let rtt_us = enclave_measure_vsock_round(
                    stream,
                    anchor_hs.session_id,
                    round,
                    &anchor_hs.keys.phase2_mac_key,
                    &anchor_hs.epoch_bytes,
                    anchor_hs.cookie,
                )?;
                samples.push(rtt_us);
            }

            let mut sorted = samples.clone();
            sorted.sort_unstable();
            let rtt_min_us = sorted[0];
            let rtt_p50_us = sorted[sorted.len() / 2];

            let mut receipt = AnchorReceipt {
                anchor_id: effective_id,
                cloud_provider: state.cloud_provider.clone(),
                prover_pk_hex: anchor_hs.verified_prover.public_key_hex,
                workload_measurement_hex: anchor_hs.verified_prover.workload_measurement_hex,
                epoch_challenge_hex: anchor_hs.epoch_challenge_hex,
                prover_observed_ip: peer_ip,
                rtt_min_us,
                rtt_p50_us,
                rtt_samples_us: samples,
                measured_at_unix_s: Utc::now().timestamp().max(0) as u64,
                anchor_signature_hex: String::new(),
            };
            receipt.sign(&state.signing_key);

            write_vsock_frame(stream, &EnclaveToHostMsg::Phase2Receipt { receipt })?;
            Ok(())
        }
        _ => {
            let _ = write_vsock_frame(
                stream,
                &EnclaveToHostMsg::Error {
                    message: "unexpected initial host-to-enclave frame".into(),
                },
            );
            anyhow::bail!("unexpected initial host-to-enclave frame")
        }
    }
}

#[cfg(target_os = "linux")]
fn run_nitro_enclave_vsock_server(state: Arc<AnchorState>, port: u32) -> Result<()> {
    let listener = pog_proto::vsock::bind_nitro_vsock_listener(port)?;
    for conn in listener.incoming() {
        let Ok(mut stream) = conn else {
            continue;
        };
        let _ = stream.set_read_timeout(Some(SESSION_TOTAL_TIMEOUT));
        let _ = stream.set_write_timeout(Some(SESSION_TOTAL_TIMEOUT));
        let st = Arc::clone(&state);
        std::thread::spawn(move || {
            if let Err(e) = handle_enclave_session_stream(&mut stream, &st) {
                warn!(err = %e, "Nitro enclave vsock session rejected");
            }
        });
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run_nitro_enclave_vsock_server(_state: Arc<AnchorState>, _port: u32) -> Result<()> {
    anyhow::bail!("AF_VSOCK Nitro Enclave server requires Linux running inside an AWS Nitro Enclave")
}

/// Untrusted parent EC2 host relay: exposes external HTTP `/info`, TCP `:7443`, and scoped UDP
/// `40000-40999` while forwarding all attestation, challenge, and signing RPCs over `AF_VSOCK`
/// to the isolated Nitro Enclave (the parent host holds ZERO signing or session keys!).
#[cfg(target_os = "linux")]
async fn run_nitro_host_relay(args: Args, enclave_cid: u32) -> Result<()> {
    let enclave_port = args.enclave_vsock_port;
    let endorsement_path = args
        .endorsement_path
        .or_else(|| std::env::var("POG_ENDORSEMENT_PATH").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/etc/pog/endorsement.json"));
    let operator_root_pk_hex = args
        .operator_root_pk_hex
        .or_else(|| std::env::var("POG_ROOT_PUBLIC_KEY_HEX").ok());
    let anchor_id = args.anchor_id.clone();

    info!(
        anchor_id = %anchor_id,
        enclave_cid,
        enclave_port,
        tcp = %args.tcp_listen,
        http = %args.http_info_listen,
        "Starting UNTRUSTED parent EC2 host vsock relay for AWS Nitro Enclave"
    );

    // Spawn HTTP /info proxy forwarding to enclave over vsock and attaching verified host-side endorsement
    // ONLY if endorsement strictly matches the enclave's live public_key_hex!
    let info_listen = args.http_info_listen;
    let info_cache: Arc<RwLock<Option<CachedInfo>>> = Arc::new(RwLock::new(None));
    let info_cache_c = Arc::clone(&info_cache);
    let ep_c = endorsement_path.clone();
    let root_c = operator_root_pk_hex.clone();
    let aid_c = anchor_id.clone();
    let aid_att = anchor_id.clone();
    tokio::spawn(async move {
        let app = Router::new()
            .route(
                "/health",
                get(|| async { Json(serde_json::json!({ "status": "ok", "mode": "nitro_host_relay" })) }),
            )
            .route(
                "/info",
                get(move || {
                    let cache = Arc::clone(&info_cache_c);
                    let ep = ep_c.clone();
                    let root = root_c.clone();
                    let aid = aid_c.clone();
                    async move {
                        {
                            let guard = cache.read().unwrap();
                            if let Some(ref c) = *guard {
                                if c.generated_at.elapsed() < INFO_CACHE_TTL {
                                    return Ok::<_, StatusCode>(Json(c.payload.clone()));
                                }
                            }
                        }
                        let nonce = format!("anchor-bootstrap-{}", Utc::now().timestamp() / 60);
                        let res = tokio::task::spawn_blocking(move || -> Result<serde_json::Value> {
                            let mut vs = pog_proto::vsock::connect_nitro_vsock(enclave_cid, enclave_port)?;
                            vs.set_read_timeout(Some(Duration::from_secs(5)))?;
                            vs.set_write_timeout(Some(Duration::from_secs(5)))?;
                            write_vsock_frame(&mut vs, &HostToEnclaveMsg::GetInfo {
                                bootstrap_nonce: nonce,
                                anchor_id: Some(aid.clone()),
                            })?;
                            match read_vsock_frame::<_, EnclaveToHostMsg>(&mut vs)? {
                                EnclaveToHostMsg::InfoResponse { mut payload } => {
                                    // Attach parent-host `/etc/pog/endorsement.json` ONLY if it strictly matches
                                    // the enclave's attested live `public_key_hex` (rejects stale certs on restart!).
                                    if let Some(pk) = payload.get("public_key_hex").and_then(|v| v.as_str()).map(|s| s.to_string()) {
                                        let now = Utc::now().timestamp().max(0) as u64;
                                        let (cert, status) = load_verified_endorsement(&ep, &aid, &pk, root.as_deref(), now);
                                        payload["operator_endorsement"] = serde_json::to_value(cert).unwrap_or(serde_json::Value::Null);
                                        payload["endorsement_status"] = serde_json::json!(status);
                                    }
                                    Ok(payload)
                                }
                                EnclaveToHostMsg::Error { message } => anyhow::bail!(message),
                                _ => anyhow::bail!("unexpected enclave response"),
                            }
                        })
                        .await
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                        .map_err(|_| StatusCode::BAD_GATEWAY)?;
                        *cache.write().unwrap() = Some(CachedInfo {
                            generated_at: Instant::now(),
                            payload: res.clone(),
                        });
                        Ok(Json(res))
                    }
                }),
            )
            .route(
                "/attest",
                get({
                    let ep = endorsement_path.clone();
                    let root = operator_root_pk_hex.clone();
                    let aid = aid_att.clone();
                    move |Query(q): Query<AttestQuery>| {
                        let ep = ep.clone();
                        let root = root.clone();
                        let aid = aid.clone();
                        async move {
                            if parse_caller_nonce_hex(&q.nonce).is_err() {
                                return Err(StatusCode::BAD_REQUEST);
                            }
                            let nonce_hex = q.nonce.trim().to_string();
                            let res = tokio::task::spawn_blocking(move || -> Result<serde_json::Value> {
                                let mut vs = pog_proto::vsock::connect_nitro_vsock(enclave_cid, enclave_port)?;
                                vs.set_read_timeout(Some(Duration::from_secs(5)))?;
                                vs.set_write_timeout(Some(Duration::from_secs(5)))?;
                                write_vsock_frame(&mut vs, &HostToEnclaveMsg::AttestFresh {
                                    caller_nonce_hex: nonce_hex,
                                    anchor_id: Some(aid.clone()),
                                })?;
                                match read_vsock_frame::<_, EnclaveToHostMsg>(&mut vs)? {
                                    EnclaveToHostMsg::AttestResponse { mut payload } => {
                                        if let Some(pk) = payload.get("public_key_hex").and_then(|v| v.as_str()).map(|s| s.to_string()) {
                                            let now = Utc::now().timestamp().max(0) as u64;
                                            let (cert, status) = load_verified_endorsement(&ep, &aid, &pk, root.as_deref(), now);
                                            payload["operator_endorsement"] = serde_json::to_value(cert).unwrap_or(serde_json::Value::Null);
                                            payload["endorsement_status"] = serde_json::json!(status);
                                        }
                                        Ok(payload)
                                    }
                                    EnclaveToHostMsg::Error { message } => anyhow::bail!(message),
                                    _ => anyhow::bail!("unexpected enclave attest response"),
                                }
                            })
                            .await
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                            .map_err(|_| StatusCode::BAD_GATEWAY)?;
                            Ok::<_, StatusCode>(Json(res))
                        }
                    }
                }),
            );
        if let Ok(listener) = TcpListener::bind(info_listen).await {
            let _ = axum::serve(listener, app).await;
        }
    });

    let sem = Arc::new(Semaphore::new(args.max_concurrent));
    let rl = Arc::new(Mutex::new(RateLimiter::new(
        args.max_per_ip_per_min,
        args.max_global_per_min,
    )));
    let listener = TcpListener::bind(args.tcp_listen).await?;
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        if !rl.lock().unwrap().check_and_record(peer_addr.ip()) {
            drop(stream);
            continue;
        }
        let Ok(permit) = Arc::clone(&sem).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let udp_ip = args.udp_bind.ip();
        let pmin = args.udp_port_min;
        let pmax = args.udp_port_max;
        let aid_tcp = anchor_id.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tokio::time::timeout(SESSION_TOTAL_TIMEOUT, async move {
                let _ = stream.set_nodelay(true);
                let (reader, mut writer) = stream.into_split();
                let mut buf_reader = BufReader::new(reader);
                let line = read_bounded_line(&mut buf_reader, MAX_LINE_BYTES).await?;
                let init_req: Phase1InitRequest = serde_json::from_str(line.trim())?;
                if init_req.protocol_version != PHASE1_PROTOCOL_VERSION {
                    anyhow::bail!("unsupported Phase 1 protocol_version {}", init_req.protocol_version);
                }
                if init_req.rounds == 0 || init_req.rounds > MAX_ROUNDS {
                    anyhow::bail!("invalid requested rounds {}", init_req.rounds);
                }
                let udp_sock = bind_scoped_udp(udp_ip, pmin, pmax)?;
                let host_udp_port = udp_sock.local_addr()?.port();
                let peer_ip_str = peer_addr.ip().to_string();

                let (mut vs, init_resp, cookie_arr) = tokio::task::spawn_blocking(move || -> Result<_> {
                    let mut vs = pog_proto::vsock::connect_nitro_vsock(enclave_cid, enclave_port)?;
                    vs.set_read_timeout(Some(SESSION_TOTAL_TIMEOUT))?;
                    vs.set_write_timeout(Some(SESSION_TOTAL_TIMEOUT))?;
                    write_vsock_frame(&mut vs, &HostToEnclaveMsg::Phase1Start {
                        peer_ip: peer_ip_str,
                        host_udp_port,
                        init_req,
                        anchor_id: Some(aid_tcp),
                    })?;
                    match read_vsock_frame::<_, EnclaveToHostMsg>(&mut vs)? {
                        EnclaveToHostMsg::Phase1Ready { init_resp, return_cookie_hex } => {
                            let c: [u8; 8] = hex::decode(&return_cookie_hex)?
                                .try_into()
                                .map_err(|_| anyhow::anyhow!("bad cookie"))?;
                            Ok((vs, init_resp, c))
                        }
                        EnclaveToHostMsg::Error { message } => anyhow::bail!(message),
                        _ => anyhow::bail!("unexpected enclave Phase1 reply"),
                    }
                }).await??;

                let session_id = init_resp.session_id;
                let rounds = init_resp.negotiated_rounds;
                let mut resp_json = serde_json::to_string(&init_resp)?;
                resp_json.push('\n');
                writer.write_all(resp_json.as_bytes()).await?;
                writer.flush().await?;

                // Phase 1 v2 requires authenticated JSON Phase1Confirm (rejects legacy plaintext READY!).
                let confirm_line = read_bounded_line(&mut buf_reader, MAX_CONFIRM_LINE_BYTES).await?;
                let prover_confirm: Phase1Confirm = serde_json::from_str(confirm_line.trim())
                    .map_err(|e| anyhow::anyhow!("Expected v2 Phase1Confirm JSON (legacy READY rejected): {e}"))?;
                if prover_confirm.protocol_version != PHASE1_PROTOCOL_VERSION
                    || prover_confirm.session_id != session_id
                {
                    anyhow::bail!("Phase1Confirm version or session_id mismatch");
                }

                let tcp_peer_ip = peer_addr.ip();
                let receipt = tokio::task::spawn_blocking(move || -> Result<AnchorReceipt> {
                    let mut punch_buf = [0u8; PUNCH_PACKET_SIZE];
                    let (n, src) = udp_sock.recv_from(&mut punch_buf)?;
                    if n != PUNCH_PACKET_SIZE {
                        anyhow::bail!("Invalid UDP punch size");
                    }
                    let (p_sid, p_cookie) = decode_udp_punch(&punch_buf)?;
                    if p_sid != session_id || p_cookie != cookie_arr || src.ip() != tcp_peer_ip {
                        anyhow::bail!("Invalid UDP punch cookie/source IP");
                    }
                    write_vsock_frame(&mut vs, &HostToEnclaveMsg::Phase2Start {
                        rounds,
                        prover_confirm,
                    })?;
                    let mut udp_buf = [0u8; PACKET_SIZE];
                    for round in 0..rounds {
                        match read_vsock_frame::<_, EnclaveToHostMsg>(&mut vs)? {
                            EnclaveToHostMsg::Phase2ChallengeDatagram { round: r, packet_hex } if r == round => {
                                let ch_bytes = hex::decode(&packet_hex)?;
                                udp_sock.send_to(&ch_bytes, src)?;
                                let (rn, rsrc) = udp_sock.recv_from(&mut udp_buf)?;
                                if rn != PACKET_SIZE || rsrc != src {
                                    anyhow::bail!("Invalid UDP response datagram");
                                }
                                write_vsock_frame(&mut vs, &HostToEnclaveMsg::Phase2ResponseDatagram {
                                    round,
                                    packet_hex: hex::encode(udp_buf),
                                })?;
                            }
                            EnclaveToHostMsg::Error { message } => anyhow::bail!(message),
                            _ => anyhow::bail!("unexpected enclave Phase2 message"),
                        }
                    }
                    match read_vsock_frame::<_, EnclaveToHostMsg>(&mut vs)? {
                        EnclaveToHostMsg::Phase2Receipt { receipt } => Ok(receipt),
                        EnclaveToHostMsg::Error { message } => anyhow::bail!(message),
                        _ => anyhow::bail!("expected enclave Phase2Receipt"),
                    }
                }).await??;

                let mut receipt_json = serde_json::to_string(&receipt)?;
                receipt_json.push('\n');
                writer.write_all(receipt_json.as_bytes()).await?;
                writer.flush().await?;
                Ok::<(), anyhow::Error>(())
            })
            .await;
        });
    }
}

#[cfg(not(target_os = "linux"))]
async fn run_nitro_host_relay(_args: Args, _enclave_cid: u32) -> Result<()> {
    anyhow::bail!("--nitro-host-relay requires Linux EC2 parent instance with AF_VSOCK")
}

/// Direct TCP Anchor session entrypoint: executes Phase 1 v2 authenticated handshake + key
/// confirmation over `stream` and timed Phase 2 UDP challenges over a newly bound scoped UDP socket.
async fn handle_prover_session(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    state: Arc<AnchorState>,
) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let (reader, writer) = stream.into_split();
    let bind_ip = state.udp_bind_ip;
    let pmin = state.udp_port_min;
    let pmax = state.udp_port_max;
    handle_prover_session_with_io(
        reader,
        writer,
        peer_addr,
        state,
        move || {
            let sock = bind_scoped_udp(bind_ip, pmin, pmax)?;
            let port = sock.local_addr()?.port();
            Ok((sock, port))
        },
        |udp_sock, tcp_peer_ip, session_id, cookie, session_key, epoch_bytes, rounds| async move {
            tokio::task::spawn_blocking(move || -> Result<Vec<u64>> {
                let mut punch_buf = [0u8; PUNCH_PACKET_SIZE];
                let (n, src) = udp_sock
                    .recv_from(&mut punch_buf)
                    .map_err(|e| anyhow::anyhow!("UDP punch required (anti-reflection): {e}"))?;
                if n != PUNCH_PACKET_SIZE {
                    anyhow::bail!("Invalid UDP punch size {n}");
                }
                let (p_sid, p_cookie) = decode_udp_punch(&punch_buf)?;
                if p_sid != session_id || p_cookie != cookie {
                    anyhow::bail!("Invalid UDP punch session_id or return cookie");
                }
                if src.ip() != tcp_peer_ip {
                    anyhow::bail!(
                        "UDP punch source IP {} != TCP peer IP {}",
                        src.ip(),
                        tcp_peer_ip
                    );
                }

                let mut out = Vec::with_capacity(rounds as usize);
                for round in 0..rounds {
                    let rtt_us = measure_udp_round(
                        &udp_sock,
                        src,
                        session_id,
                        round,
                        &session_key,
                        &epoch_bytes,
                        cookie,
                    )?;
                    out.push(rtt_us);
                }
                Ok(out)
            })
            .await?
        },
    )
    .await
}

/// Core direct-Anchor session state machine parameterized over stream + Phase 2 runner so BOTH
/// production TCP/UDP and in-memory adversarial regression tests execute the exact same
/// Phase 1 v2 authentication, DH validation, key-confirmation, and receipt-signing code path!
async fn handle_prover_session_with_io<R, W, U, B, F, Fut>(
    reader: R,
    mut writer: W,
    peer_addr: SocketAddr,
    state: Arc<AnchorState>,
    bind_udp: B,
    run_phase2: F,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    B: FnOnce() -> std::io::Result<(U, u16)>,
    F: FnOnce(U, IpAddr, u64, [u8; 8], [u8; 32], Vec<u8>, u16) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u64>>>,
{
    let mut buf_reader = BufReader::new(reader);

    let line = read_bounded_line(&mut buf_reader, MAX_LINE_BYTES).await?;
    let init_req: Phase1InitRequest = serde_json::from_str(line.trim())
        .map_err(|e| anyhow::anyhow!("Invalid or legacy unsigned Phase1InitRequest rejected: {e}"))?;

    // Fast fail-closed validation BEFORE binding an OS UDP socket (prevents unauthenticated port DoS!).
    if init_req.protocol_version != PHASE1_PROTOCOL_VERSION {
        anyhow::bail!(
            "Unsupported Phase 1 protocol_version {} (expected {})",
            init_req.protocol_version,
            PHASE1_PROTOCOL_VERSION
        );
    }
    let _ = init_req.prover_init_transcript_hash()?;

    let (udp_handle, bound_udp_port) = bind_udp()?;
    let now = Utc::now().timestamp().max(0) as u64;
    let peer_ip_str = peer_addr.ip().to_string();

    let anchor_hs = accept_phase1_anchor(
        &init_req,
        &state.anchor_id,
        &state.signing_key,
        state.tee_provider.as_ref(),
        &state.tee_policy,
        &state.cookie_secret,
        &peer_ip_str,
        bound_udp_port,
        MAX_ROUNDS,
        now,
    )?;

    let mut resp_json = serde_json::to_string(&anchor_hs.init_resp)?;
    resp_json.push('\n');
    writer.write_all(resp_json.as_bytes()).await?;
    writer.flush().await?;

    // Phase 1 v2 Message 3: require explicit authenticated Phase1Confirm JSON (rejects legacy READY!).
    let confirm_line = read_bounded_line(&mut buf_reader, MAX_CONFIRM_LINE_BYTES).await?;
    let prover_confirm: Phase1Confirm = serde_json::from_str(confirm_line.trim()).map_err(|e| {
        anyhow::anyhow!("Expected v2 Phase1Confirm JSON before Phase 2 (legacy READY rejected): {e}")
    })?;
    verify_phase1_confirm(&anchor_hs, &prover_confirm)?;

    let samples = run_phase2(
        udp_handle,
        peer_addr.ip(),
        anchor_hs.session_id,
        anchor_hs.cookie,
        anchor_hs.keys.phase2_mac_key,
        anchor_hs.epoch_bytes.clone(),
        anchor_hs.negotiated_rounds,
    )
    .await?;

    if samples.is_empty() {
        anyhow::bail!("Phase 2 produced zero RTT samples");
    }

    let mut sorted = samples.clone();
    sorted.sort_unstable();
    let rtt_min_us = sorted[0];
    let rtt_p50_us = sorted[sorted.len() / 2];

    let mut receipt = AnchorReceipt {
        anchor_id: state.anchor_id.clone(),
        cloud_provider: state.cloud_provider.clone(),
        prover_pk_hex: anchor_hs.verified_prover.public_key_hex,
        workload_measurement_hex: anchor_hs.verified_prover.workload_measurement_hex,
        epoch_challenge_hex: anchor_hs.epoch_challenge_hex,
        prover_observed_ip: peer_ip_str,
        rtt_min_us,
        rtt_p50_us,
        rtt_samples_us: samples,
        measured_at_unix_s: Utc::now().timestamp().max(0) as u64,
        anchor_signature_hex: String::new(),
    };
    receipt.sign(&state.signing_key);

    let mut receipt_json = serde_json::to_string(&receipt)?;
    receipt_json.push('\n');
    writer.write_all(receipt_json.as_bytes()).await?;
    writer.flush().await?;

    info!(
        anchor = %state.anchor_id,
        peer = %peer_addr.ip(),
        rtt_min_us,
        rtt_p50_us,
        "Issued signed AnchorReceipt (Phase 1 v2 authenticated)"
    );
    Ok(())
}

async fn anchor_attest_handler(
    AxumState(state): AxumState<Arc<AnchorState>>,
    Query(q): Query<AttestQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Err(msg) = parse_caller_nonce_hex(&q.nonce) {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": msg }))));
    }
    match build_fresh_attest_payload(&state, &q.nonce) {
        Ok(payload) => Ok(Json(payload)),
        Err(msg) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": msg })),
        )),
    }
}

/// Zero-SSH authenticated endorsement delivery endpoint (`POST /endorsement`).
///
/// Strictly requires a pinned `POG_ROOT_PUBLIC_KEY_HEX`, bounded payload (<= 8 KiB), exact match
/// against this Anchor's live `anchor_id` and ephemeral in-RAM Ed25519 public key, unexpired TTL,
/// and a valid Ed25519 signature under the pinned operator root key. Stores the verified
/// endorsement in RAM only (zero disk writes, zero SSH, zero outbound TCP; automatically cleared
/// on restart when a new ephemeral key is generated).
async fn anchor_post_endorsement_handler(
    AxumState(state): AxumState<Arc<AnchorState>>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if body.len() > 8192 {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({ "error": "endorsement payload exceeds 8192 bytes" })),
        ));
    }
    let Some(root_pk) = state.operator_root_pk_hex.as_deref() else {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "operator_root_pk_hex not pinned on anchor (fail-closed)" })),
        ));
    };
    let cert: AnchorEndorsement = serde_json::from_slice(&body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("invalid AnchorEndorsement JSON: {e}") })),
        )
    })?;
    let live_pk_hex = hex::encode(state.signing_key.verifying_key().to_bytes());
    let now = Utc::now().timestamp().max(0) as u64;
    let (verified_opt, status) = validate_endorsement_cert(
        cert,
        &state.anchor_id,
        &live_pk_hex,
        Some(root_pk),
        now,
    );
    let Some(verified_cert) = verified_opt else {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": format!("endorsement rejected: {status}") })),
        ));
    };
    *state.in_memory_endorsement.write().unwrap() = Some(verified_cert);
    *state.info_cache.write().unwrap() = None;
    info!(anchor = %state.anchor_id, "Accepted root-signed zero-SSH in-RAM AnchorEndorsement");
    Ok(Json(serde_json::json!({
        "status": "endorsed",
        "anchor_id": state.anchor_id,
        "public_key_hex": live_pk_hex,
    })))
}

async fn anchor_info_handler(
    AxumState(state): AxumState<Arc<AnchorState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    {
        let guard = state.info_cache.read().unwrap();
        if let Some(ref cached) = *guard {
            if cached.generated_at.elapsed() < INFO_CACHE_TTL {
                return Ok(Json(cached.payload.clone()));
            }
        }
    }

    let nonce = format!("anchor-bootstrap-{}", Utc::now().timestamp() / 60);
    let payload = build_info_payload(&state, nonce);
    let mut guard = state.info_cache.write().unwrap();
    *guard = Some(CachedInfo {
        generated_at: Instant::now(),
        payload: payload.clone(),
    });
    Ok(Json(payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pog_proto::{compute_challenge_mac, ChallengePacket, ResponsePacket};
    use pog_tee::{SoftwareDevProvider, WorkloadKeypair};
    #[cfg(unix)]
    use std::os::unix::net::UnixStream;
    use std::thread;

    #[test]
    fn test_rejects_old_endorsement_on_restart_and_accepts_matching_root_signed() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_pk_hex = hex::encode(root_sk.verifying_key().to_bytes());
        let old_sk = SigningKey::generate(&mut OsRng);
        let new_sk = SigningKey::generate(&mut OsRng);
        let old_pk = hex::encode(old_sk.verifying_key().to_bytes());
        let new_pk = hex::encode(new_sk.verifying_key().to_bytes());
        let now = Utc::now().timestamp().max(0) as u64;

        let tmp = std::env::temp_dir().join(format!("pog_test_endorse_{now}.json"));
        let old_cert = AnchorEndorsement::sign_new(
            "proofofgeography.com",
            "aws-fra",
            &old_pk,
            50.11,
            8.68,
            now - 10,
            3600,
            &root_sk,
        );
        std::fs::write(&tmp, serde_json::to_string(&old_cert).unwrap()).unwrap();

        // After restart with new_pk, old endorsement MUST be rejected with key_mismatch!
        let (cert_after_restart, status_restart) =
            load_verified_endorsement(&tmp, "aws-fra", &new_pk, Some(&root_pk_hex), now);
        assert!(cert_after_restart.is_none());
        assert_eq!(status_restart, "key_mismatch");

        // Matching live key + valid root signature MUST pass!
        let (cert_ok, status_ok) =
            load_verified_endorsement(&tmp, "aws-fra", &old_pk, Some(&root_pk_hex), now);
        assert!(cert_ok.is_some());
        assert_eq!(status_ok, "matched");

        // Wrong pinned root key MUST reject with invalid_signature!
        let other_root = SigningKey::generate(&mut OsRng);
        let other_root_pk = hex::encode(other_root.verifying_key().to_bytes());
        let (cert_bad_root, status_bad_root) =
            load_verified_endorsement(&tmp, "aws-fra", &old_pk, Some(&other_root_pk), now);
        assert!(cert_bad_root.is_none());
        assert_eq!(status_bad_root, "invalid_signature");

        // Expired endorsement MUST reject with expired!
        let (cert_exp, status_exp) =
            load_verified_endorsement(&tmp, "aws-fra", &old_pk, Some(&root_pk_hex), now + 7200);
        assert!(cert_exp.is_none());
        assert_eq!(status_exp, "expired");

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_enclave_vsock_end_to_end_challenge_and_signed_receipt() {
        let anchor_sk = SigningKey::generate(&mut OsRng);
        let anchor_pk_hex = hex::encode(anchor_sk.verifying_key().to_bytes());
        let state = Arc::new(AnchorState {
            anchor_id: "local-anchor-01".into(),
            cloud_provider: "aws".into(),
            signing_key: anchor_sk,
            cookie_secret: [0x33u8; 32],
            tee_provider: Box::new(SoftwareDevProvider::new("ee".repeat(32))),
            tee_policy: AttestationPolicy::allow_dev_software(),
            udp_bind_ip: "127.0.0.1".parse().unwrap(),
            udp_port_min: 40000,
            udp_port_max: 40999,
            concurrency_sem: Arc::new(Semaphore::new(4)),
            rate_limiter: Mutex::new(RateLimiter::new(100, 100)),
            info_cache: RwLock::new(None),
            in_memory_endorsement: RwLock::new(None),
            endorsement_path: PathBuf::from("/nonexistent/endorsement.json"),
            operator_root_pk_hex: None,
        });

        // 1. Verify AttestFresh binds the per-region anchor_id supplied by the host relay (shared EIF!)
        {
            let (mut enc_s, mut host_s) = UnixStream::pair().unwrap();
            let st_c = Arc::clone(&state);
            let t = thread::spawn(move || {
                handle_enclave_session_stream(&mut enc_s, &st_c).unwrap();
            });
            let nonce = "55".repeat(32);
            write_vsock_frame(
                &mut host_s,
                &HostToEnclaveMsg::AttestFresh {
                    caller_nonce_hex: nonce.clone(),
                    anchor_id: Some("aws-us-east-1-nvirginia".into()),
                },
            )
            .unwrap();
            let EnclaveToHostMsg::AttestResponse { payload } =
                read_vsock_frame(&mut host_s).unwrap()
            else {
                panic!("expected AttestResponse");
            };
            assert_eq!(payload["anchor_id"], "aws-us-east-1-nvirginia");
            let q_meas = payload["tee_quote"]["workload_measurement_hex"]
                .as_str()
                .unwrap();
            let pop_sig =
                hex::decode(payload["proof_of_possession_sig_hex"].as_str().unwrap()).unwrap();
            let pop_msg = attest_pop_message("aws-us-east-1-nvirginia", &nonce, q_meas);
            assert!(WorkloadKeypair::verify_with_hex(&anchor_pk_hex, &pop_msg, &pop_sig).is_ok());
            t.join().unwrap();
        }

        let (mut enclave_stream, mut host_stream) = UnixStream::pair().unwrap();
        let st_clone = Arc::clone(&state);
        let enclave_thread = thread::spawn(move || {
            handle_enclave_session_stream(&mut enclave_stream, &st_clone).unwrap();
        });

        // Simulate untrusted host relay + authenticated Phase 1 v2 Prover!
        let prover_kp = WorkloadKeypair::generate();
        let epoch = [0x99u8; 32];
        let now = Utc::now().timestamp().max(0) as u64;
        let prover_quote = SoftwareDevProvider::new("dd".repeat(32))
            .attest(&prover_kp.public_key_bytes(), &epoch, None)
            .unwrap();
        let client_hs = pog_proto::start_phase1_client(
            &prover_kp,
            prover_quote,
            &epoch,
            "aws-nitro-canary",
            &anchor_pk_hex,
            pog_tee::TeeVendor::SoftwareDev,
            55000,
            3,
        )
        .unwrap();

        write_vsock_frame(
            &mut host_stream,
            &HostToEnclaveMsg::Phase1Start {
                peer_ip: "198.51.100.77".into(),
                host_udp_port: 40123,
                anchor_id: Some("aws-nitro-canary".into()),
                init_req: client_hs.init_req.clone(),
            },
        )
        .unwrap();

        let EnclaveToHostMsg::Phase1Ready { init_resp, .. } =
            read_vsock_frame(&mut host_stream).unwrap()
        else {
            panic!("expected Phase1Ready");
        };
        assert_eq!(init_resp.anchor_id, "aws-nitro-canary");
        assert_eq!(init_resp.anchor_quote.public_key_hex, anchor_pk_hex);

        let completed = pog_proto::finish_phase1_client(
            client_hs,
            &init_resp,
            &AttestationPolicy::allow_dev_software(),
            now,
        )
        .unwrap();
        let session_key = completed.keys.phase2_mac_key;

        write_vsock_frame(
            &mut host_stream,
            &HostToEnclaveMsg::Phase2Start {
                rounds: 3,
                prover_confirm: completed.confirm,
            },
        )
        .unwrap();
        for r in 0..3u16 {
            let EnclaveToHostMsg::Phase2ChallengeDatagram { round, packet_hex } =
                read_vsock_frame(&mut host_stream).unwrap()
            else {
                panic!("expected challenge");
            };
            assert_eq!(round, r);
            let ch = ChallengePacket::decode(&hex::decode(packet_hex).unwrap()).unwrap();
            let mac = compute_challenge_mac(&session_key, ch.session_id, ch.round, &ch.nonce, &epoch);
            let resp = ResponsePacket {
                round: ch.round,
                session_id: ch.session_id,
                prover_proc_ns: 100,
                mac,
                nonce_echo: ch.nonce[0..8].try_into().unwrap(),
            };
            write_vsock_frame(
                &mut host_stream,
                &HostToEnclaveMsg::Phase2ResponseDatagram {
                    round,
                    packet_hex: hex::encode(resp.encode()),
                },
            )
            .unwrap();
        }

        let EnclaveToHostMsg::Phase2Receipt { receipt } =
            read_vsock_frame(&mut host_stream).unwrap()
        else {
            panic!("expected receipt");
        };
        assert_eq!(receipt.rtt_samples_us.len(), 3);
        assert!(receipt.verify(&anchor_pk_hex).is_ok());
        enclave_thread.join().unwrap();
    }

    fn make_test_anchor_state(anchor_id: &str) -> (Arc<AnchorState>, String) {
        let anchor_sk = SigningKey::generate(&mut OsRng);
        let anchor_pk_hex = hex::encode(anchor_sk.verifying_key().to_bytes());
        let state = Arc::new(AnchorState {
            anchor_id: anchor_id.into(),
            cloud_provider: "aws".into(),
            signing_key: anchor_sk,
            cookie_secret: [0x55u8; 32],
            tee_provider: Box::new(SoftwareDevProvider::new("ee".repeat(32))),
            tee_policy: AttestationPolicy::allow_dev_software(),
            udp_bind_ip: "127.0.0.1".parse().unwrap(),
            udp_port_min: 40000,
            udp_port_max: 40999,
            concurrency_sem: Arc::new(Semaphore::new(8)),
            rate_limiter: Mutex::new(RateLimiter::new(100, 100)),
            info_cache: RwLock::new(None),
            in_memory_endorsement: RwLock::new(None),
            endorsement_path: PathBuf::from("/nonexistent/endorsement.json"),
            operator_root_pk_hex: None,
        });
        (state, anchor_pk_hex)
    }

    #[test]
    fn test_nitro_enclave_vsock_adversarial_phase1_rejections() {
        let (state, anchor_pk_hex) = make_test_anchor_state("aws-nitro-enclave-01");
        let victim_kp = WorkloadKeypair::generate();
        let attacker_kp = WorkloadKeypair::generate();
        let epoch = [0xAAu8; 32];
        let now = Utc::now().timestamp().max(0) as u64;
        let victim_quote = SoftwareDevProvider::new("dd".repeat(32))
            .attest(&victim_kp.public_key_bytes(), &epoch, None)
            .unwrap();
        let valid_client = pog_proto::start_phase1_client(
            &victim_kp,
            victim_quote.clone(),
            &epoch,
            "aws-nitro-enclave-01",
            &anchor_pk_hex,
            pog_tee::TeeVendor::SoftwareDev,
            55001,
            3,
        )
        .unwrap();

        let expect_enclave_reject = |req: Phase1InitRequest, host_anchor_id: &str, label: &str| {
            let (mut enc_s, mut host_s) = UnixStream::pair().unwrap();
            let st_c = Arc::clone(&state);
            let t = thread::spawn(move || handle_enclave_session_stream(&mut enc_s, &st_c));
            write_vsock_frame(
                &mut host_s,
                &HostToEnclaveMsg::Phase1Start {
                    peer_ip: "198.51.100.88".into(),
                    host_udp_port: 40124,
                    anchor_id: Some(host_anchor_id.into()),
                    init_req: req,
                },
            )
            .unwrap();
            let reply: EnclaveToHostMsg = read_vsock_frame(&mut host_s).unwrap();
            assert!(
                matches!(reply, EnclaveToHostMsg::Error { .. }),
                "{label}: expected EnclaveToHostMsg::Error, got {reply:?}"
            );
            assert!(t.join().unwrap().is_err(), "{label}: enclave handler must return Err");
        };

        // 1. Stolen valid victim quote + attacker DH key + attacker sig -> REJECTED inside Nitro Enclave!
        let mut stolen = valid_client.init_req.clone();
        stolen.prover_ephemeral_x25519_hex = "42".repeat(32);
        let sh = stolen.prover_init_transcript_hash().unwrap();
        stolen.prover_init_sig_hex = hex::encode(attacker_kp.sign(&sh));
        expect_enclave_reject(stolen, "aws-nitro-enclave-01", "stolen quote + attacker DH");

        // 2. Altered prover DH key with victim's original signature -> REJECTED!
        let mut altered_dh = valid_client.init_req.clone();
        altered_dh.prover_ephemeral_x25519_hex = "42".repeat(32);
        expect_enclave_reject(altered_dh, "aws-nitro-enclave-01", "altered prover DH");

        // 3. Untrusted Nitro parent host spoofing a mismatched anchor_id -> REJECTED!
        expect_enclave_reject(
            valid_client.init_req.clone(),
            "spoofed-host-anchor-id",
            "host relay spoofed anchor_id",
        );

        // 4. Wrong target_anchor_pk_hex -> REJECTED!
        let mut wrong_pk = valid_client.init_req.clone();
        wrong_pk.target_anchor_pk_hex = "11".repeat(32);
        let wph = wrong_pk.prover_init_transcript_hash().unwrap();
        wrong_pk.prover_init_sig_hex = hex::encode(victim_kp.sign(&wph));
        expect_enclave_reject(wrong_pk, "aws-nitro-enclave-01", "wrong target_anchor_pk");

        // 5. All-zero / low-order DH public key even legitimately signed by victim -> REJECTED!
        let mut zero_dh = valid_client.init_req.clone();
        zero_dh.prover_ephemeral_x25519_hex = "00".repeat(32);
        let zh = zero_dh.prover_init_transcript_hash().unwrap();
        zero_dh.prover_init_sig_hex = hex::encode(victim_kp.sign(&zh));
        expect_enclave_reject(zero_dh, "aws-nitro-enclave-01", "all-zero prover DH");

        // 6. Legacy protocol_version=1 downgrade -> REJECTED!
        let mut v1_req = valid_client.init_req.clone();
        v1_req.protocol_version = 1;
        expect_enclave_reject(v1_req, "aws-nitro-enclave-01", "legacy protocol_version=1");

        // 7. Bad Phase1Confirm MAC sent in Phase2Start -> enclave REJECTS BEFORE any Phase 2 challenge!
        let (mut enc_s, mut host_s) = UnixStream::pair().unwrap();
        let st_c = Arc::clone(&state);
        let t = thread::spawn(move || handle_enclave_session_stream(&mut enc_s, &st_c));
        let fresh_client = pog_proto::start_phase1_client(
            &victim_kp,
            victim_quote,
            &epoch,
            "aws-nitro-enclave-01",
            &anchor_pk_hex,
            pog_tee::TeeVendor::SoftwareDev,
            55002,
            3,
        )
        .unwrap();
        write_vsock_frame(
            &mut host_s,
            &HostToEnclaveMsg::Phase1Start {
                peer_ip: "198.51.100.88".into(),
                host_udp_port: 40125,
                anchor_id: Some("aws-nitro-enclave-01".into()),
                init_req: fresh_client.init_req.clone(),
            },
        )
        .unwrap();
        let EnclaveToHostMsg::Phase1Ready { init_resp, .. } =
            read_vsock_frame(&mut host_s).unwrap()
        else {
            panic!("expected Phase1Ready");
        };
        let completed = pog_proto::finish_phase1_client(
            fresh_client,
            &init_resp,
            &AttestationPolicy::allow_dev_software(),
            now,
        )
        .unwrap();
        let mut forged_confirm = completed.confirm;
        forged_confirm.prover_confirm_mac_hex = "ff".repeat(32);
        write_vsock_frame(
            &mut host_s,
            &HostToEnclaveMsg::Phase2Start {
                rounds: 3,
                prover_confirm: forged_confirm,
            },
        )
        .unwrap();
        let err_reply: EnclaveToHostMsg = read_vsock_frame(&mut host_s).unwrap();
        assert!(
            matches!(err_reply, EnclaveToHostMsg::Error { .. }),
            "forged Phase1Confirm MUST be rejected before Phase 2 challenges, got {err_reply:?}"
        );
        assert!(t.join().unwrap().is_err());
    }

    #[tokio::test]
    async fn test_direct_anchor_entrypoint_valid_and_all_adversarial_rejections() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let (state, anchor_pk_hex) = make_test_anchor_state("gcp-direct-anchor-01");
        let victim_kp = WorkloadKeypair::generate();
        let attacker_kp = WorkloadKeypair::generate();
        let epoch = [0xBBu8; 32];
        let now = Utc::now().timestamp().max(0) as u64;
        let victim_quote = SoftwareDevProvider::new("cc".repeat(32))
            .attest(&victim_kp.public_key_bytes(), &epoch, None)
            .unwrap();
        let peer_addr: SocketAddr = "198.51.100.55:44321".parse().unwrap();

        // 1. Valid direct-anchor v2 handshake + Phase1Confirm -> executes Phase 2 & issues signed receipt!
        {
            let (server_io, client_io) = tokio::io::duplex(64 * 1024);
            let (sr, sw) = tokio::io::split(server_io);
            let (cr, mut cw) = tokio::io::split(client_io);
            let mut c_reader = BufReader::new(cr);
            let phase2_ran = Arc::new(AtomicBool::new(false));
            let phase2_ran_c = Arc::clone(&phase2_ran);
            let st_c = Arc::clone(&state);

            let srv = tokio::spawn(async move {
                handle_prover_session_with_io(
                    sr,
                    sw,
                    peer_addr,
                    st_c,
                    || Ok(((), 40500)),
                    |_, _, _, _, _, _, rounds| async move {
                        phase2_ran_c.store(true, Ordering::SeqCst);
                        Ok(vec![1_250; rounds as usize])
                    },
                )
                .await
            });

            let client_hs = pog_proto::start_phase1_client(
                &victim_kp,
                victim_quote.clone(),
                &epoch,
                "gcp-direct-anchor-01",
                &anchor_pk_hex,
                pog_tee::TeeVendor::SoftwareDev,
                55100,
                4,
            )
            .unwrap();
            let mut req_line = serde_json::to_string(&client_hs.init_req).unwrap();
            req_line.push('\n');
            cw.write_all(req_line.as_bytes()).await.unwrap();
            cw.flush().await.unwrap();

            let mut resp_line = String::new();
            c_reader.read_line(&mut resp_line).await.unwrap();
            let init_resp: pog_proto::Phase1InitResponse =
                serde_json::from_str(resp_line.trim()).unwrap();
            let completed = pog_proto::finish_phase1_client(
                client_hs,
                &init_resp,
                &AttestationPolicy::allow_dev_software(),
                now,
            )
            .unwrap();
            let mut conf_line = serde_json::to_string(&completed.confirm).unwrap();
            conf_line.push('\n');
            cw.write_all(conf_line.as_bytes()).await.unwrap();
            cw.flush().await.unwrap();

            resp_line.clear();
            c_reader.read_line(&mut resp_line).await.unwrap();
            let receipt: AnchorReceipt = serde_json::from_str(resp_line.trim()).unwrap();
            assert!(receipt.verify(&anchor_pk_hex).is_ok());
            assert_eq!(receipt.prover_pk_hex, victim_kp.public_key_hex());
            assert_eq!(receipt.rtt_samples_us, vec![1_250; 4]);
            srv.await.unwrap().unwrap();
            assert!(phase2_ran.load(Ordering::SeqCst));
        }

        // Helper for adversarial Phase 1 init payloads against the real direct-anchor entrypoint:
        let run_bad_init = |raw_line: String| {
            let st_c = Arc::clone(&state);
            async move {
                let (server_io, mut client_io) = tokio::io::duplex(64 * 1024);
                let (sr, sw) = tokio::io::split(server_io);
                let phase2_ran = Arc::new(AtomicBool::new(false));
                let phase2_ran_c = Arc::clone(&phase2_ran);
                let srv = tokio::spawn(async move {
                    handle_prover_session_with_io(
                        sr,
                        sw,
                        peer_addr,
                        st_c,
                        || Ok(((), 40501)),
                        |_, _, _, _, _, _, _| async move {
                            phase2_ran_c.store(true, Ordering::SeqCst);
                            Ok(vec![500])
                        },
                    )
                    .await
                });
                client_io.write_all(raw_line.as_bytes()).await.unwrap();
                client_io.flush().await.unwrap();
                drop(client_io);
                let res = srv.await.unwrap();
                assert!(!phase2_ran.load(Ordering::SeqCst), "Phase 2 must NEVER run on rejected init!");
                assert!(res.is_err());
            }
        };

        // 2. Legacy unsigned v1 JSON -> REJECTED!
        let legacy_v1 = format!(
            "{}\n",
            serde_json::json!({
                "prover_quote": victim_quote,
                "epoch_challenge_hex": hex::encode(epoch),
                "prover_ephemeral_x25519_hex": "22".repeat(32),
                "prover_udp_port": 55100,
                "rounds": 4
            })
        );
        run_bad_init(legacy_v1).await;

        let base_c = pog_proto::start_phase1_client(
            &victim_kp,
            victim_quote.clone(),
            &epoch,
            "gcp-direct-anchor-01",
            &anchor_pk_hex,
            pog_tee::TeeVendor::SoftwareDev,
            55100,
            4,
        )
        .unwrap();

        // 3. Stolen fresh quote + attacker local DH key + attacker signature -> REJECTED!
        let mut stolen = base_c.init_req.clone();
        stolen.prover_ephemeral_x25519_hex = "77".repeat(32);
        let sh = stolen.prover_init_transcript_hash().unwrap();
        stolen.prover_init_sig_hex = hex::encode(attacker_kp.sign(&sh));
        run_bad_init(format!("{}\n", serde_json::to_string(&stolen).unwrap())).await;

        // 4. Altered prover DH key -> REJECTED!
        let mut alt_dh = base_c.init_req.clone();
        alt_dh.prover_ephemeral_x25519_hex = "77".repeat(32);
        run_bad_init(format!("{}\n", serde_json::to_string(&alt_dh).unwrap())).await;

        // 5. Wrong anchor_id -> REJECTED!
        let mut wrong_aid = base_c.init_req.clone();
        wrong_aid.target_anchor_id = "other-anchor".into();
        let wah = wrong_aid.prover_init_transcript_hash().unwrap();
        wrong_aid.prover_init_sig_hex = hex::encode(victim_kp.sign(&wah));
        run_bad_init(format!("{}\n", serde_json::to_string(&wrong_aid).unwrap())).await;

        // 6. All-zero X25519 DH key (even signed by valid sk_P!) -> REJECTED!
        let mut zero_dh = base_c.init_req.clone();
        zero_dh.prover_ephemeral_x25519_hex = "00".repeat(32);
        let zdh = zero_dh.prover_init_transcript_hash().unwrap();
        zero_dh.prover_init_sig_hex = hex::encode(victim_kp.sign(&zdh));
        run_bad_init(format!("{}\n", serde_json::to_string(&zero_dh).unwrap())).await;

        // 7. Legacy plaintext "READY\n" instead of Phase1Confirm JSON -> REJECTED BEFORE Phase 2!
        {
            let (server_io, client_io) = tokio::io::duplex(64 * 1024);
            let (sr, sw) = tokio::io::split(server_io);
            let (cr, mut cw) = tokio::io::split(client_io);
            let mut c_reader = BufReader::new(cr);
            let phase2_ran = Arc::new(AtomicBool::new(false));
            let phase2_ran_c = Arc::clone(&phase2_ran);
            let st_c = Arc::clone(&state);

            let srv = tokio::spawn(async move {
                handle_prover_session_with_io(
                    sr,
                    sw,
                    peer_addr,
                    st_c,
                    || Ok(((), 40502)),
                    |_, _, _, _, _, _, _| async move {
                        phase2_ran_c.store(true, Ordering::SeqCst);
                        Ok(vec![500])
                    },
                )
                .await
            });
            let mut req_line = serde_json::to_string(&base_c.init_req).unwrap();
            req_line.push('\n');
            cw.write_all(req_line.as_bytes()).await.unwrap();
            cw.flush().await.unwrap();
            let mut resp_line = String::new();
            c_reader.read_line(&mut resp_line).await.unwrap();
            cw.write_all(b"READY\n").await.unwrap();
            cw.flush().await.unwrap();
            assert!(srv.await.unwrap().is_err());
            assert!(!phase2_ran.load(Ordering::SeqCst), "legacy READY MUST NOT start Phase 2!");
        }
    }

    #[tokio::test]
    async fn test_direct_anchor_live_tcp_udp_handle_prover_session_end_to_end() {
        let (state, anchor_pk_hex) = make_test_anchor_state("gcp-live-loopback-01");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = listener.local_addr().unwrap();

        let st_c = Arc::clone(&state);
        let srv = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            handle_prover_session(stream, peer, st_c).await
        });

        let prover_kp = WorkloadKeypair::generate();
        let epoch = [0xCCu8; 32];
        let now = Utc::now().timestamp().max(0) as u64;
        let prover_quote = SoftwareDevProvider::new("dd".repeat(32))
            .attest(&prover_kp.public_key_bytes(), &epoch, None)
            .unwrap();
        let udp_sock = bind_low_latency_udp("127.0.0.1:0".parse().unwrap(), Duration::from_secs(2)).unwrap();
        let local_udp_port = udp_sock.local_addr().unwrap().port();

        let client_hs = pog_proto::start_phase1_client(
            &prover_kp,
            prover_quote,
            &epoch,
            "gcp-live-loopback-01",
            &anchor_pk_hex,
            pog_tee::TeeVendor::SoftwareDev,
            local_udp_port,
            3,
        )
        .unwrap();

        let stream = tokio::net::TcpStream::connect(tcp_addr).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut br = BufReader::new(r);
        let mut req_line = serde_json::to_string(&client_hs.init_req).unwrap();
        req_line.push('\n');
        w.write_all(req_line.as_bytes()).await.unwrap();
        w.flush().await.unwrap();

        let mut resp_line = String::new();
        br.read_line(&mut resp_line).await.unwrap();
        let init_resp: pog_proto::Phase1InitResponse =
            serde_json::from_str(resp_line.trim()).unwrap();
        let completed = pog_proto::finish_phase1_client(
            client_hs,
            &init_resp,
            &AttestationPolicy::allow_dev_software(),
            now,
        )
        .unwrap();

        let mut conf_line = serde_json::to_string(&completed.confirm).unwrap();
        conf_line.push('\n');
        w.write_all(conf_line.as_bytes()).await.unwrap();
        w.flush().await.unwrap();

        let punch = pog_proto::encode_udp_punch(completed.session_id, completed.cookie);
        let anchor_udp_addr = SocketAddr::new("127.0.0.1".parse().unwrap(), completed.anchor_udp_port);
        let sid = completed.session_id;
        let sk = completed.keys.phase2_mac_key;
        let udp_task = tokio::task::spawn_blocking(move || {
            udp_sock.send_to(&punch, anchor_udp_addr).unwrap();
            for _ in 0..3 {
                pog_proto::respond_once_udp(&udp_sock, sid, &sk, &epoch).unwrap();
            }
        });
        udp_task.await.unwrap();

        resp_line.clear();
        br.read_line(&mut resp_line).await.unwrap();
        let receipt: AnchorReceipt = serde_json::from_str(resp_line.trim()).unwrap();
        assert!(receipt.verify(&anchor_pk_hex).is_ok());
        assert_eq!(receipt.rtt_samples_us.len(), 3);
        srv.await.unwrap().unwrap();
    }

    #[test]
    fn test_fresh_attest_binds_caller_nonce_and_verifies_ed25519_pop() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let state = AnchorState {
            anchor_id: "gcp-europe-west3-frankfurt".into(),
            cloud_provider: "gcp".into(),
            signing_key: sk,
            cookie_secret: [9u8; 32],
            tee_provider: Box::new(SoftwareDevProvider::new("ab".repeat(48))),
            tee_policy: AttestationPolicy::allow_dev_software(),
            udp_bind_ip: "127.0.0.1".parse().unwrap(),
            udp_port_min: 40000,
            udp_port_max: 40999,
            concurrency_sem: Arc::new(Semaphore::new(4)),
            rate_limiter: Mutex::new(RateLimiter::new(10, 100)),
            info_cache: RwLock::new(None),
            in_memory_endorsement: RwLock::new(None),
            endorsement_path: PathBuf::from("/nonexistent/endorsement.json"),
            operator_root_pk_hex: None,
        };

        // Reject short / invalid caller nonces
        assert!(build_fresh_attest_payload(&state, "deadbeef").is_err());
        assert!(build_fresh_attest_payload(&state, "zz".repeat(32).as_str()).is_err());

        // Valid 32-byte random caller nonce -> fresh quote + valid Ed25519 PoP signature!
        let caller_nonce_hex = "42".repeat(32);
        let payload = build_fresh_attest_payload(&state, &caller_nonce_hex).unwrap();
        assert_eq!(payload["fresh_caller_nonce"], true);
        assert_eq!(payload["caller_nonce_hex"], caller_nonce_hex);
        assert_eq!(payload["public_key_hex"], pk_hex);

        let quote: pog_tee::TeeAttestationQuote =
            serde_json::from_value(payload["tee_quote"].clone()).unwrap();
        assert_eq!(quote.nonce_hex, caller_nonce_hex);
        assert_eq!(quote.public_key_hex, pk_hex);

        let pop_sig = hex::decode(payload["proof_of_possession_sig_hex"].as_str().unwrap()).unwrap();
        let pop_msg = attest_pop_message(
            "gcp-europe-west3-frankfurt",
            &caller_nonce_hex,
            &quote.workload_measurement_hex,
        );
        assert!(WorkloadKeypair::verify_with_hex(&pk_hex, &pop_msg, &pop_sig).is_ok());
        // Tampering with nonce MUST break PoP verification
        let wrong_msg = attest_pop_message(
            "gcp-europe-west3-frankfurt",
            &"99".repeat(32),
            &quote.workload_measurement_hex,
        );
        assert!(WorkloadKeypair::verify_with_hex(&pk_hex, &wrong_msg, &pop_sig).is_err());
    }

    #[tokio::test]
    async fn test_zero_ssh_post_endorsement_accepts_valid_and_rejects_forged() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_pk_hex = hex::encode(root_sk.verifying_key().to_bytes());
        let other_root_sk = SigningKey::generate(&mut OsRng);
        let anchor_sk = SigningKey::generate(&mut OsRng);
        let anchor_pk_hex = hex::encode(anchor_sk.verifying_key().to_bytes());
        let now = Utc::now().timestamp().max(0) as u64;

        let make_state = |pinned_root: Option<String>| {
            Arc::new(AnchorState {
                anchor_id: "azure-uksouth-london-cvm".into(),
                cloud_provider: "azure".into(),
                signing_key: SigningKey::from_bytes(&anchor_sk.to_bytes()),
                cookie_secret: [7u8; 32],
                tee_provider: Box::new(SoftwareDevProvider::new("cd".repeat(48))),
                tee_policy: AttestationPolicy::allow_dev_software(),
                udp_bind_ip: "127.0.0.1".parse().unwrap(),
                udp_port_min: 40000,
                udp_port_max: 40999,
                concurrency_sem: Arc::new(Semaphore::new(4)),
                rate_limiter: Mutex::new(RateLimiter::new(10, 100)),
                info_cache: RwLock::new(None),
                in_memory_endorsement: RwLock::new(None),
                endorsement_path: PathBuf::from("/nonexistent/endorsement.json"),
                operator_root_pk_hex: pinned_root,
            })
        };

        let valid_cert = AnchorEndorsement::sign_new(
            "proofofgeography.com",
            "azure-uksouth-london-cvm",
            &anchor_pk_hex,
            51.5074,
            -0.1278,
            now.saturating_sub(10),
            86_400,
            &root_sk,
        );
        let valid_bytes = Bytes::from(serde_json::to_vec(&valid_cert).unwrap());

        // 1. Fail-closed when operator_root_pk_hex is NOT pinned
        let no_root_state = make_state(None);
        let err = anchor_post_endorsement_handler(AxumState(no_root_state), valid_bytes.clone())
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);

        let state = make_state(Some(root_pk_hex.clone()));

        // 2. Oversized body (> 8192 bytes) MUST be rejected with 413
        let err_big = anchor_post_endorsement_handler(
            AxumState(Arc::clone(&state)),
            Bytes::from(vec![b' '; 8193]),
        )
        .await
        .unwrap_err();
        assert_eq!(err_big.0, StatusCode::PAYLOAD_TOO_LARGE);

        // 3. Forged signature under a different root key MUST be rejected with 403
        let forged_cert = AnchorEndorsement::sign_new(
            "proofofgeography.com",
            "azure-uksouth-london-cvm",
            &anchor_pk_hex,
            51.5074,
            -0.1278,
            now.saturating_sub(10),
            86_400,
            &other_root_sk,
        );
        let err_forged = anchor_post_endorsement_handler(
            AxumState(Arc::clone(&state)),
            Bytes::from(serde_json::to_vec(&forged_cert).unwrap()),
        )
        .await
        .unwrap_err();
        assert_eq!(err_forged.0, StatusCode::FORBIDDEN);

        // 4. Wrong live anchor public key MUST be rejected with 403
        let wrong_key_cert = AnchorEndorsement::sign_new(
            "proofofgeography.com",
            "azure-uksouth-london-cvm",
            "00".repeat(32),
            51.5074,
            -0.1278,
            now.saturating_sub(10),
            86_400,
            &root_sk,
        );
        let err_key = anchor_post_endorsement_handler(
            AxumState(Arc::clone(&state)),
            Bytes::from(serde_json::to_vec(&wrong_key_cert).unwrap()),
        )
        .await
        .unwrap_err();
        assert_eq!(err_key.0, StatusCode::FORBIDDEN);

        // 5. Valid root-signed endorsement MUST be accepted, stored in RAM, and exposed in /info & /attest
        let ok = anchor_post_endorsement_handler(AxumState(Arc::clone(&state)), valid_bytes)
            .await
            .unwrap();
        assert_eq!(ok.0["status"], "endorsed");
        assert_eq!(ok.0["anchor_id"], "azure-uksouth-london-cvm");

        let info = build_info_payload(&state, "bootstrap-test".into());
        assert_eq!(info["endorsement_status"], "matched");
        assert_eq!(
            info["operator_endorsement"]["anchor_public_key_hex"],
            anchor_pk_hex
        );

        let attest = build_fresh_attest_payload(&state, &"11".repeat(32)).unwrap();
        assert_eq!(attest["endorsement_status"], "matched");
        assert_eq!(
            attest["operator_endorsement"]["anchor_id"],
            "azure-uksouth-london-cvm"
        );
    }
}
