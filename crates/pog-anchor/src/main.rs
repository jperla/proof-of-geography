use anyhow::Result;
use axum::{extract::State as AxumState, routing::get, Json, Router};
use chrono::Utc;
use clap::Parser;
use ed25519_dalek::SigningKey;
use pog_proto::{
    bind_low_latency_udp, compute_return_cookie, decode_udp_punch, derive_session_key,
    measure_udp_round, AnchorReceipt, Phase1InitRequest, Phase1InitResponse, PUNCH_PACKET_SIZE,
};
use pog_tee::{auto_detect_provider, verify_quote, AttestationPolicy, TeeProvider};
use rand::rngs::OsRng;
use rand::RngCore;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::{info, warn};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

#[derive(Parser, Debug)]
#[command(
    name = "pog-anchor",
    about = "Proof of Geography Multi-Cloud Anchor TEE Daemon"
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
    /// Public HTTP metadata endpoint (/info, /health) used to collect hardware-attested Anchor keys at deploy time.
    #[arg(long, default_value = "0.0.0.0:7445")]
    http_info_listen: SocketAddr,
    /// Allow software-dev TEE fallback for THIS Anchor (only for local laptop testing; NEVER on cloud TEEs).
    #[arg(long, default_value_t = false)]
    allow_dev_tee: bool,
    /// Allow incoming Provers using software-dev TEE quotes (enables public laptop testing against real SEV-SNP Anchors).
    #[arg(long, default_value_t = false)]
    allow_dev_prover: bool,
    /// Optional hex seed (32 bytes) for deterministic test keypairs; random OS entropy in production.
    #[arg(long)]
    seed_hex: Option<String>,
}

struct AnchorState {
    anchor_id: String,
    cloud_provider: String,
    signing_key: SigningKey,
    cookie_secret: [u8; 32],
    tee_provider: Box<dyn TeeProvider>,
    tee_policy: AttestationPolicy,
    udp_bind: SocketAddr,
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
        udp = %args.udp_bind,
        "Starting PoG Anchor TEE daemon"
    );

    let tee_policy = if args.allow_dev_tee || args.allow_dev_prover {
        AttestationPolicy::allow_dev_software()
    } else {
        AttestationPolicy::production()
    };

    let state = Arc::new(AnchorState {
        anchor_id: args.anchor_id,
        cloud_provider: args.cloud_provider,
        signing_key,
        cookie_secret,
        tee_provider,
        tee_policy,
        udp_bind: args.udp_bind,
    });

    // Spawn lightweight HTTP /info & /health endpoint for automated 24-node registry bootstrapping.
    let info_state = Arc::clone(&state);
    let info_listen = args.http_info_listen;
    tokio::spawn(async move {
        let app = Router::new()
            .route("/health", get(|| async { Json(serde_json::json!({ "status": "ok" })) }))
            .route("/info", get(anchor_info_handler))
            .with_state(info_state);
        if let Ok(listener) = TcpListener::bind(info_listen).await {
            info!(http_info = %info_listen, "Anchor HTTP /info endpoint ready");
            let _ = axum::serve(listener, app).await;
        }
    });

    let listener = TcpListener::bind(args.tcp_listen).await?;
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_prover_session(stream, peer_addr, st).await {
                warn!(peer = %peer_addr, err = %e, "Prover session failed");
            }
        });
    }
}

async fn handle_prover_session(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    state: Arc<AnchorState>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    buf_reader.read_line(&mut line).await?;
    let init_req: Phase1InitRequest = serde_json::from_str(line.trim())?;

    // 1. Verify Prover's TEE Remote Attestation Quote before doing any UDP probing.
    let now = Utc::now().timestamp().max(0) as u64;
    let epoch_bytes = hex::decode(&init_req.epoch_challenge_hex)?;
    let verified_prover = verify_quote(&init_req.prover_quote, &epoch_bytes, &state.tee_policy, now)?;

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

    // 3. Generate Anchor's own TEE attestation quote bound to this epoch challenge.
    let anchor_pk_bytes = state.signing_key.verifying_key().to_bytes();
    let anchor_quote = state.tee_provider.attest(&anchor_pk_bytes, &epoch_bytes, None)?;

    // Allocate an ephemeral low-latency UDP socket on the configured bind IP for this burst.
    let udp_sock_addr = SocketAddr::new(state.udp_bind.ip(), 0);
    let udp_sock = bind_low_latency_udp(udp_sock_addr, Duration::from_millis(1500))?;
    let bound_udp_port = udp_sock.local_addr()?.port();

    // Send Phase 1 InitResponse so Prover prepares its UDP fast-path socket.
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

    // Wait for Prover "READY\n" acknowledgement, then receive Prover's 20-byte UDP NAT-punch
    // packet so Phase 2 works identically behind home/corporate NAT and on public cloud IPs!
    line.clear();
    buf_reader.read_line(&mut line).await?;
    if line.trim() != "READY" {
        anyhow::bail!("Expected READY signal before Phase 2 UDP burst");
    }

    // 4. Phase 2: Wait for authenticated UDP PUNCH, then execute M sequential timed UDP rounds!
    let tcp_peer_ip = peer_addr.ip();
    let fallback_udp_addr = SocketAddr::new(tcp_peer_ip, init_req.prover_udp_port);
    let rounds = init_req.rounds.clamp(1, 32);
    let epoch_clone = epoch_bytes.clone();

    let samples: Vec<u64> = tokio::task::spawn_blocking(move || -> Result<Vec<u64>> {
        let mut punch_buf = [0u8; PUNCH_PACKET_SIZE];
        let prover_udp_addr = match udp_sock.recv_from(&mut punch_buf) {
            Ok((n, src)) if n == PUNCH_PACKET_SIZE => {
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
                src
            }
            _ => fallback_udp_addr,
        };

        let mut out = Vec::with_capacity(rounds as usize);
        for round in 0..rounds {
            let rtt_us = measure_udp_round(
                &udp_sock,
                prover_udp_addr,
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

async fn anchor_info_handler(
    AxumState(state): AxumState<Arc<AnchorState>>,
) -> Json<serde_json::Value> {
    let pk_bytes = state.signing_key.verifying_key().to_bytes();
    let nonce = format!("anchor-bootstrap-{}", Utc::now().timestamp() / 60);
    let quote = state
        .tee_provider
        .attest(&pk_bytes, nonce.as_bytes(), None)
        .ok();
    Json(serde_json::json!({
        "anchor_id": state.anchor_id,
        "cloud_provider": state.cloud_provider,
        "tee_vendor": state.tee_provider.vendor(),
        "public_key_hex": hex::encode(pk_bytes),
        "bootstrap_nonce": nonce,
        "tee_quote": quote,
    }))
}
