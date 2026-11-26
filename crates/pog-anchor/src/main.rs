use anyhow::Result;
use axum::{extract::State as AxumState, http::StatusCode, routing::get, Json, Router};
use chrono::Utc;
use clap::Parser;
use ed25519_dalek::SigningKey;
use pog_proto::{
    bind_low_latency_udp, compute_return_cookie, decode_udp_punch, derive_session_key,
    measure_udp_round, AnchorEndorsement, AnchorReceipt, Phase1InitRequest, Phase1InitResponse,
    PUNCH_PACKET_SIZE,
};
use pog_tee::{auto_detect_provider, verify_quote, AttestationPolicy, TeeProvider};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{info, warn};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

/// Hard security caps to protect public Anchor nodes from memory exhaustion, Slowloris, and bandwidth abuse.
const MAX_LINE_BYTES: u64 = 32 * 1024; // 32 KiB max Phase 1 JSON line
const MAX_ROUNDS: u16 = 16;
const PHASE1_READ_TIMEOUT: Duration = Duration::from_secs(4);
const SESSION_TOTAL_TIMEOUT: Duration = Duration::from_secs(12);
const INFO_CACHE_TTL: Duration = Duration::from_secs(60);
const MAX_TRACKED_IPS: usize = 32_768;

#[derive(Parser, Debug)]
#[command(
    name = "pog-anchor",
    about = "Proof of Geography Multi-Cloud Anchor TEE Daemon (Hardened Public Mode)"
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
    /// Narrow UDP port range for Phase 2 ephemeral sockets (lets cloud firewalls stay tightly scoped).
    #[arg(long, default_value_t = 40000)]
    udp_port_min: u16,
    #[arg(long, default_value_t = 40999)]
    udp_port_max: u16,
    /// Public HTTP metadata endpoint (/info, /health) serving cached hardware-attested Anchor metadata.
    #[arg(long, default_value = "0.0.0.0:7445")]
    http_info_listen: SocketAddr,
    /// Maximum simultaneous in-flight prover sessions (prevents FD/CPU exhaustion).
    #[arg(long, default_value_t = 64)]
    max_concurrent: usize,
    /// Per-IP probe rate limit per 60-second window (prevents per-client DoS).
    #[arg(long, default_value_t = 12)]
    max_per_ip_per_min: u32,
    /// Global probe rate limit per 60-second window (caps worst-case cloud egress cost under DDoS).
    #[arg(long, default_value_t = 600)]
    max_global_per_min: u32,
    /// Allow software-dev TEE fallback for THIS Anchor (only for local laptop testing; NEVER on cloud TEEs).
    #[arg(long, default_value_t = false)]
    allow_dev_tee: bool,
    /// Allow incoming Provers using software-dev TEE quotes (enables public laptop testing against real TEE Anchors).
    #[arg(long, default_value_t = false)]
    allow_dev_prover: bool,
    /// Optional hex seed (32 bytes) for deterministic test keypairs; random OS entropy in production.
    #[arg(long)]
    seed_hex: Option<String>,
    /// Optional path to a signed operator AnchorEndorsement certificate (secretly provisioned per node;
    /// also checks POG_ENDORSEMENT_PATH env var; the operator's root private key NEVER leaves the local machine).
    #[arg(long)]
    endorsement_path: Option<std::path::PathBuf>,
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
    operator_endorsement: Option<AnchorEndorsement>,
}

/// Bind a low-latency UDP socket strictly inside `[port_min, port_max]` so cloud firewalls
/// only need a narrow UDP port range open (e.g., 40000-40999/udp instead of all 65k ports).
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

/// Read a single `\n`-terminated line with strict byte limit (blocks OOM / Slowloris).
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

    let args = Args::parse();
    let tee_provider = auto_detect_provider(None, args.allow_dev_tee)?;

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
    info!(
        anchor_id = %args.anchor_id,
        cloud = %args.cloud_provider,
        tee = tee_provider.vendor().as_str(),
        pubkey = %pk_hex,
        tcp = %args.tcp_listen,
        udp_range = format!("{}-{}", args.udp_port_min, args.udp_port_max),
        max_concurrent = args.max_concurrent,
        per_ip_rpm = args.max_per_ip_per_min,
        global_rpm = args.max_global_per_min,
        "Starting HARDENED PoG Anchor TEE daemon"
    );

    let tee_policy = if args.allow_dev_tee || args.allow_dev_prover {
        AttestationPolicy::allow_dev_software()
    } else {
        AttestationPolicy::production()
    };

    let endorsement_path = args
        .endorsement_path
        .or_else(|| std::env::var("POG_ENDORSEMENT_PATH").ok().map(std::path::PathBuf::from));
    let operator_endorsement: Option<AnchorEndorsement> = match endorsement_path {
        Some(ref path) => {
            let raw = std::fs::read_to_string(path)?;
            let cert: AnchorEndorsement = serde_json::from_str(&raw)?;
            info!(
                network_id = %cert.network_id,
                root_pk = %&cert.root_public_key_hex[..cert.root_public_key_hex.len().min(16)],
                "Loaded operator AnchorEndorsement certificate"
            );
            Some(cert)
        }
        None => None,
    };

    let state = Arc::new(AnchorState {
        anchor_id: args.anchor_id,
        cloud_provider: args.cloud_provider,
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
        operator_endorsement,
    });

    // Spawn lightweight cached HTTP /info & /health endpoint (never hammers /dev/sev-guest!).
    let info_state = Arc::clone(&state);
    let info_listen = args.http_info_listen;
    tokio::spawn(async move {
        let app = Router::new()
            .route(
                "/health",
                get(|| async { Json(serde_json::json!({ "status": "ok" })) }),
            )
            .route("/info", get(anchor_info_handler))
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

    if init_req.epoch_challenge_hex.len() > 128 || init_req.prover_quote.raw_quote_b64.len() > 24_000
    {
        anyhow::bail!("request fields exceed maximum allowed size");
    }

    // 1. Verify Prover's TEE Remote Attestation Quote before allocating UDP resources.
    let now = Utc::now().timestamp().max(0) as u64;
    let epoch_bytes = hex::decode(&init_req.epoch_challenge_hex)?;
    let verified_prover =
        verify_quote(&init_req.prover_quote, &epoch_bytes, &state.tee_policy, now)?;

    // 2. Compute ephemeral X25519 shared secret -> session key `K_PA` inside Anchor TEE RAM.
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

    // 3. Generate Anchor's TEE attestation quote bound to this epoch challenge.
    let anchor_pk_bytes = state.signing_key.verifying_key().to_bytes();
    let anchor_quote = state
        .tee_provider
        .attest(&anchor_pk_bytes, &epoch_bytes, None)?;

    // Allocate a low-latency UDP socket strictly inside [udp_port_min, udp_port_max].
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

    // Wait for Prover "READY\n" acknowledgement (max 64 bytes, 4s timeout).
    let ready = read_bounded_line(&mut buf_reader, 64).await?;
    if ready.trim() != "READY" {
        anyhow::bail!("Expected READY signal before Phase 2 UDP burst");
    }

    // 4. Phase 2: STRICT authenticated UDP PUNCH required (blocks 100% of UDP reflection DDoS!).
    // Anchor NEVER sends a single UDP packet until the exact TCP peer IP sends a valid 20-byte
    // PUNCH packet bearing `session_id` + `return_cookie`!
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

/// Cached `/info` handler (refreshes hardware TEE quote at most once per 60 seconds so public
/// HTTP floods can NEVER hammer `/dev/sev-guest` or Intel TDX ConfigFS TSM!).
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

    let pk_bytes = state.signing_key.verifying_key().to_bytes();
    let nonce = format!("anchor-bootstrap-{}", Utc::now().timestamp() / 60);
    let quote = state
        .tee_provider
        .attest(&pk_bytes, nonce.as_bytes(), None)
        .ok();
    let payload = serde_json::json!({
        "anchor_id": state.anchor_id,
        "cloud_provider": state.cloud_provider,
        "tee_vendor": state.tee_provider.vendor(),
        "public_key_hex": hex::encode(pk_bytes),
        "bootstrap_nonce": nonce,
        "tee_quote": quote,
        "operator_endorsement": state.operator_endorsement,
        "udp_port_range": [state.udp_port_min, state.udp_port_max],
        "hardened": true,
    });
    let mut guard = state.info_cache.write().unwrap();
    *guard = Some(CachedInfo {
        generated_at: Instant::now(),
        payload: payload.clone(),
    });
    Ok(Json(payload))
}
