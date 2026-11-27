use anyhow::Result;
use axum::{
    extract::{Query, State as AxumState},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use chrono::Utc;
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use pog_proto::{
    bind_low_latency_udp, compute_return_cookie, decode_udp_punch, derive_session_key,
    enclave_measure_vsock_round, measure_udp_round, read_vsock_frame, write_vsock_frame,
    AnchorEndorsement, AnchorReceipt, EnclaveToHostMsg, HostToEnclaveMsg, Phase1InitRequest,
    Phase1InitResponse, DEFAULT_NITRO_VSOCK_PORT, PUNCH_PACKET_SIZE,
};
#[cfg(target_os = "linux")]
use pog_proto::PACKET_SIZE;
use pog_tee::{auto_detect_provider, verify_quote, AttestationPolicy, TeeProvider};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{info, warn};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

/// Hard security caps to protect public Anchor nodes from memory exhaustion, Slowloris, and bandwidth abuse.
const MAX_LINE_BYTES: u64 = 32 * 1024;
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
    endorsement_path: PathBuf,
    operator_root_pk_hex: Option<String>,
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
    let nonce_bytes = parse_caller_nonce_hex(caller_nonce_hex)?;
    let norm_nonce_hex = hex::encode(&nonce_bytes);
    let pk_bytes = state.signing_key.verifying_key().to_bytes();
    let pk_hex = hex::encode(pk_bytes);
    let now = Utc::now().timestamp().max(0) as u64;
    let quote = state
        .tee_provider
        .attest(&pk_bytes, &nonce_bytes, None)
        .map_err(|e| format!("hardware attestation failed: {e}"))?;
    let pop_msg = attest_pop_message(&state.anchor_id, &norm_nonce_hex, &quote.workload_measurement_hex);
    let pop_sig_hex = hex::encode(state.signing_key.sign(&pop_msg).to_bytes());
    let (operator_endorsement, endorsement_status) = load_verified_endorsement(
        &state.endorsement_path,
        &state.anchor_id,
        &pk_hex,
        state.operator_root_pk_hex.as_deref(),
        now,
    );
    let vendor = state.tee_provider.vendor();
    Ok(serde_json::json!({
        "anchor_id": state.anchor_id,
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
    let pk_bytes = state.signing_key.verifying_key().to_bytes();
    let pk_hex = hex::encode(pk_bytes);
    let now = Utc::now().timestamp().max(0) as u64;
    let quote = state
        .tee_provider
        .attest(&pk_bytes, bootstrap_nonce.as_bytes(), None)
        .ok();
    let (operator_endorsement, endorsement_status) = load_verified_endorsement(
        &state.endorsement_path,
        &state.anchor_id,
        &pk_hex,
        state.operator_root_pk_hex.as_deref(),
        now,
    );
    let vendor = state.tee_provider.vendor();
    serde_json::json!({
        "anchor_id": state.anchor_id,
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut args = Args::parse();
    // Allow GCP Confidential Space / immutable container images to pass `POG_ANCHOR_ID` via
    // narrow allowlisted env_override while keeping `cmd_override` strictly empty `[]`.
    if args.anchor_id == "local-anchor-01" {
        if let Ok(env_id) = std::env::var("POG_ANCHOR_ID") {
            let trimmed = env_id.trim();
            if !trimmed.is_empty() {
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
    let tee_policy = if args.allow_dev_tee || args.allow_dev_prover {
        warn!("NON-PRODUCTION DEV TEE POLICY ENABLED — DO NOT USE FOR PRODUCTION PROOFS");
        AttestationPolicy::allow_dev_software()
    } else {
        AttestationPolicy::production()
    };

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
        HostToEnclaveMsg::GetInfo { bootstrap_nonce } => {
            let payload = build_info_payload(state, bootstrap_nonce);
            write_vsock_frame(stream, &EnclaveToHostMsg::InfoResponse { payload })?;
            Ok(())
        }
        HostToEnclaveMsg::AttestFresh { caller_nonce_hex } => {
            match build_fresh_attest_payload(state, &caller_nonce_hex) {
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
        } => {
            if init_req.epoch_challenge_hex.len() > 128
                || init_req.prover_quote.raw_quote_b64.len() > 24_000
            {
                let _ = write_vsock_frame(
                    stream,
                    &EnclaveToHostMsg::Error {
                        message: "request fields exceed maximum allowed size".into(),
                    },
                );
                anyhow::bail!("request fields exceed maximum allowed size");
            }
            let now = Utc::now().timestamp().max(0) as u64;
            let epoch_bytes = hex::decode(&init_req.epoch_challenge_hex)?;
            let verified_prover =
                verify_quote(&init_req.prover_quote, &epoch_bytes, &state.tee_policy, now)?;

            let prover_eph_arr: [u8; 32] = hex::decode(&init_req.prover_ephemeral_x25519_hex)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("prover ephemeral x25519 must be 32 bytes"))?;
            let anchor_eph_sk = EphemeralSecret::random_from_rng(OsRng);
            let anchor_eph_pk = X25519PublicKey::from(&anchor_eph_sk);
            let shared = anchor_eph_sk.diffie_hellman(&X25519PublicKey::from(prover_eph_arr));

            let session_id = OsRng.next_u64();
            let session_key = derive_session_key(
                shared.as_bytes(),
                session_id,
                &epoch_bytes,
                &verified_prover.public_key_hex,
                &state.anchor_id,
            );
            let cookie = compute_return_cookie(&state.cookie_secret, session_id, &peer_ip);
            let anchor_pk_bytes = state.signing_key.verifying_key().to_bytes();
            let anchor_quote = state
                .tee_provider
                .attest(&anchor_pk_bytes, &epoch_bytes, None)?;

            let init_resp = Phase1InitResponse {
                session_id,
                anchor_id: state.anchor_id.clone(),
                anchor_quote,
                anchor_ephemeral_x25519_hex: hex::encode(anchor_eph_pk.as_bytes()),
                return_cookie_hex: hex::encode(cookie),
                anchor_udp_port: host_udp_port,
            };
            write_vsock_frame(
                stream,
                &EnclaveToHostMsg::Phase1Ready {
                    init_resp,
                    return_cookie_hex: hex::encode(cookie),
                },
            )?;

            // Wait for parent relay to confirm TCP READY + UDP PUNCH, then run timed rounds INSIDE enclave!
            let start_msg: HostToEnclaveMsg = read_vsock_frame(stream)?;
            let rounds = match start_msg {
                HostToEnclaveMsg::Phase2Start { rounds } => rounds.clamp(1, MAX_ROUNDS),
                _ => anyhow::bail!("expected Phase2Start from host relay"),
            };

            let mut samples = Vec::with_capacity(rounds as usize);
            for round in 0..rounds {
                let rtt_us = enclave_measure_vsock_round(
                    stream,
                    session_id,
                    round,
                    &session_key,
                    &epoch_bytes,
                    cookie,
                )?;
                samples.push(rtt_us);
            }

            let mut sorted = samples.clone();
            sorted.sort_unstable();
            let rtt_min_us = sorted[0];
            let rtt_p50_us = sorted[sorted.len() / 2];

            let mut receipt = AnchorReceipt {
                anchor_id: state.anchor_id.clone(),
                cloud_provider: state.cloud_provider.clone(),
                prover_pk_hex: verified_prover.public_key_hex,
                workload_measurement_hex: verified_prover.workload_measurement_hex,
                epoch_challenge_hex: init_req.epoch_challenge_hex,
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
                            write_vsock_frame(&mut vs, &HostToEnclaveMsg::GetInfo { bootstrap_nonce: nonce })?;
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
                    let aid = anchor_id.clone();
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
                                write_vsock_frame(&mut vs, &HostToEnclaveMsg::AttestFresh { caller_nonce_hex: nonce_hex })?;
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
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tokio::time::timeout(SESSION_TOTAL_TIMEOUT, async move {
                let _ = stream.set_nodelay(true);
                let (reader, mut writer) = stream.into_split();
                let mut buf_reader = BufReader::new(reader);
                let line = read_bounded_line(&mut buf_reader, MAX_LINE_BYTES).await?;
                let init_req: Phase1InitRequest = serde_json::from_str(line.trim())?;
                let rounds = init_req.rounds.clamp(1, MAX_ROUNDS);
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
                let mut resp_json = serde_json::to_string(&init_resp)?;
                resp_json.push('\n');
                writer.write_all(resp_json.as_bytes()).await?;
                writer.flush().await?;

                let ready = read_bounded_line(&mut buf_reader, 64).await?;
                if ready.trim() != "READY" {
                    anyhow::bail!("Expected READY signal");
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
                    write_vsock_frame(&mut vs, &HostToEnclaveMsg::Phase2Start { rounds })?;
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

async fn handle_prover_session(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    state: Arc<AnchorState>,
) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);

    let line = read_bounded_line(&mut buf_reader, MAX_LINE_BYTES).await?;
    let init_req: Phase1InitRequest = serde_json::from_str(line.trim())?;

    if init_req.epoch_challenge_hex.len() > 128
        || init_req.prover_quote.raw_quote_b64.len() > 24_000
    {
        anyhow::bail!("request fields exceed maximum allowed size");
    }

    let now = Utc::now().timestamp().max(0) as u64;
    let epoch_bytes = hex::decode(&init_req.epoch_challenge_hex)?;
    let verified_prover =
        verify_quote(&init_req.prover_quote, &epoch_bytes, &state.tee_policy, now)?;

    let prover_eph_raw = hex::decode(&init_req.prover_ephemeral_x25519_hex)?;
    let prover_eph_arr: [u8; 32] = prover_eph_raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("prover ephemeral x25519 must be 32 bytes"))?;
    let prover_eph_pk = X25519PublicKey::from(prover_eph_arr);

    let anchor_eph_sk = EphemeralSecret::random_from_rng(OsRng);
    let anchor_eph_pk = X25519PublicKey::from(&anchor_eph_sk);
    let shared = anchor_eph_sk.diffie_hellman(&prover_eph_pk);

    let session_id = OsRng.next_u64();
    let session_key = derive_session_key(
        shared.as_bytes(),
        session_id,
        &epoch_bytes,
        &verified_prover.public_key_hex,
        &state.anchor_id,
    );

    let peer_ip_str = peer_addr.ip().to_string();
    let cookie = compute_return_cookie(&state.cookie_secret, session_id, &peer_ip_str);

    let anchor_pk_bytes = state.signing_key.verifying_key().to_bytes();
    let anchor_quote = state
        .tee_provider
        .attest(&anchor_pk_bytes, &epoch_bytes, None)?;

    let udp_sock = bind_scoped_udp(state.udp_bind_ip, state.udp_port_min, state.udp_port_max)?;
    let bound_udp_port = udp_sock.local_addr()?.port();

    let resp = Phase1InitResponse {
        session_id,
        anchor_id: state.anchor_id.clone(),
        anchor_quote,
        anchor_ephemeral_x25519_hex: hex::encode(anchor_eph_pk.as_bytes()),
        return_cookie_hex: hex::encode(cookie),
        anchor_udp_port: bound_udp_port,
    };
    let mut resp_json = serde_json::to_string(&resp)?;
    resp_json.push('\n');
    writer.write_all(resp_json.as_bytes()).await?;
    writer.flush().await?;

    let ready = read_bounded_line(&mut buf_reader, 64).await?;
    if ready.trim() != "READY" {
        anyhow::bail!("Expected READY signal before Phase 2 UDP burst");
    }

    let tcp_peer_ip = peer_addr.ip();
    let rounds = init_req.rounds.clamp(1, MAX_ROUNDS);
    let epoch_clone = epoch_bytes.clone();

    let samples: Vec<u64> = tokio::task::spawn_blocking(move || -> Result<Vec<u64>> {
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
            anyhow::bail!("UDP punch source IP {} != TCP peer IP {}", src.ip(), tcp_peer_ip);
        }

        let mut out = Vec::with_capacity(rounds as usize);
        for round in 0..rounds {
            let rtt_us = measure_udp_round(
                &udp_sock,
                src,
                session_id,
                round,
                &session_key,
                &epoch_clone,
                cookie,
            )?;
            out.push(rtt_us);
        }
        Ok(out)
    })
    .await??;

    let mut sorted = samples.clone();
    sorted.sort_unstable();
    let rtt_min_us = sorted[0];
    let rtt_p50_us = sorted[sorted.len() / 2];

    let mut receipt = AnchorReceipt {
        anchor_id: state.anchor_id.clone(),
        cloud_provider: state.cloud_provider.clone(),
        prover_pk_hex: verified_prover.public_key_hex,
        workload_measurement_hex: verified_prover.workload_measurement_hex,
        epoch_challenge_hex: init_req.epoch_challenge_hex,
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
        "Issued signed AnchorReceipt"
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
            anchor_id: "aws-nitro-canary".into(),
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
            endorsement_path: PathBuf::from("/nonexistent/endorsement.json"),
            operator_root_pk_hex: None,
        });

        let (mut enclave_stream, mut host_stream) = UnixStream::pair().unwrap();
        let st_clone = Arc::clone(&state);
        let enclave_thread = thread::spawn(move || {
            handle_enclave_session_stream(&mut enclave_stream, &st_clone).unwrap();
        });

        // Simulate untrusted host relay + Prover
        let prover_kp = WorkloadKeypair::generate();
        let epoch = [0x99u8; 32];
        let prover_quote = SoftwareDevProvider::new("dd".repeat(32))
            .attest(&prover_kp.public_key_bytes(), &epoch, None)
            .unwrap();
        let prover_eph_sk = EphemeralSecret::random_from_rng(OsRng);
        let prover_eph_pk = X25519PublicKey::from(&prover_eph_sk);

        write_vsock_frame(
            &mut host_stream,
            &HostToEnclaveMsg::Phase1Start {
                peer_ip: "198.51.100.77".into(),
                host_udp_port: 40123,
                init_req: Phase1InitRequest {
                    prover_quote,
                    epoch_challenge_hex: hex::encode(epoch),
                    prover_ephemeral_x25519_hex: hex::encode(prover_eph_pk.as_bytes()),
                    prover_udp_port: 55000,
                    rounds: 3,
                },
            },
        )
        .unwrap();

        let EnclaveToHostMsg::Phase1Ready { init_resp, .. } =
            read_vsock_frame(&mut host_stream).unwrap()
        else {
            panic!("expected Phase1Ready");
        };
        assert_eq!(init_resp.anchor_quote.public_key_hex, anchor_pk_hex);

        let anchor_eph_arr: [u8; 32] = hex::decode(&init_resp.anchor_ephemeral_x25519_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let shared = prover_eph_sk.diffie_hellman(&X25519PublicKey::from(anchor_eph_arr));
        let session_key = derive_session_key(
            shared.as_bytes(),
            init_resp.session_id,
            &epoch,
            &prover_kp.public_key_hex(),
            "aws-nitro-canary",
        );

        write_vsock_frame(&mut host_stream, &HostToEnclaveMsg::Phase2Start { rounds: 3 }).unwrap();
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
}
