use anyhow::Result;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, HeaderValue},
    routing::get,
    Json, Router,
};
use chrono::Utc;
use clap::Parser;
use pog_geo::LatLon;
use pog_proto::{
    bind_low_latency_udp, derive_session_key, encode_udp_punch, respond_once_udp, select_committee,
    AnchorDescriptor, AnchorGrid, AnchorReceipt, CommitteeConfig, GeoProofBundle,
    Phase1InitRequest, Phase1InitResponse, HTTP_HEADER_POG_PROOF,
};
use pog_tee::{auto_detect_provider, TeeProvider, WorkloadKeypair};
use rand::rngs::OsRng;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{info, warn};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

#[derive(Parser, Debug)]
#[command(
    name = "pog-prover",
    about = "Proof of Geography Prover TEE Sidecar (Hourly Chain + Handshake Header Mode)"
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
    #[arg(long, default_value_t = false)]
    allow_dev_tee: bool,
}

struct ProverState {
    grid: AnchorGrid,
    target: LatLon,
    required_radius_km: f64,
    rounds: u16,
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
    let grid_json = std::fs::read_to_string(&args.grid_path)?;
    let grid = AnchorGrid::from_json_str(&grid_json)?;
    let tee_provider = auto_detect_provider(None, args.allow_dev_tee)?;
    let keypair = WorkloadKeypair::generate();

    info!(
        prover_pk = %keypair.public_key_hex(),
        tee = tee_provider.vendor().as_str(),
        lat = args.claimed_lat,
        lon = args.claimed_lon,
        "Starting PoG Prover TEE Sidecar"
    );

    let state = Arc::new(ProverState {
        grid,
        target: LatLon::new(args.claimed_lat, args.claimed_lon),
        required_radius_km: args.required_radius_km,
        rounds: args.rounds,
        keypair,
        tee_provider,
        latest_bundle: RwLock::new(None),
        chain_seq: RwLock::new(0),
        last_hash: RwLock::new(None),
    });

    // Background task: Continuous hourly hash-chained PoG loop (defends against mobile DCs / relocation).
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
                }
                Err(e) => {
                    warn!(err = %e, "Hourly PoG round did not reach quorum (will retry)");
                }
            }
            tokio::time::sleep(interval).await;
        }
    });

    // HTTP sidecar endpoint: attaches live or cached `X-PoG-Proof` header to workload connections!
    let app = Router::new()
        .route("/v1/handshake-proof", get(handshake_proof_handler))
        .route("/v1/latest-proof", get(latest_proof_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(args.http_listen).await?;
    info!(listen = %args.http_listen, "Prover HTTP handshake sidecar ready");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handshake_proof_handler(
    State(state): State<Arc<ProverState>>,
    Query(q): Query<HandshakeQuery>,
) -> (HeaderMap, Json<serde_json::Value>) {
    let mut headers = HeaderMap::new();
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
