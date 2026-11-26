use anyhow::Result;
use axum::{
    body::{to_bytes, Body},
    extract::{Query, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::Response,
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
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{info, warn};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

const MAX_PROXY_BODY_BYTES: usize = 8 * 1024 * 1024; // 8 MiB max proxied HTTP payload

#[derive(Parser, Debug)]
#[command(
    name = "pog-prover",
    about = "Proof of Geography Prover TEE Sidecar (Hourly Chain + Log Push + Drop-In Reverse Proxy)"
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
    /// Optional local upstream workload (e.g. http://127.0.0.1:8000 for vLLM/SGLang/API):
    /// proxies all non-/v1/* requests and automatically injects `X-PoG-Proof` on every HTTP response!
    #[arg(long)]
    upstream: Option<String>,
    #[arg(long, default_value_t = false)]
    allow_dev_tee: bool,
}

struct ProverState {
    grid: AnchorGrid,
    target: LatLon,
    required_radius_km: f64,
    rounds: u16,
    log_url: Option<String>,
    upstream: Option<String>,
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
        keypair,
        tee_provider,
        latest_bundle: RwLock::new(None),
        chain_seq: RwLock::new(0),
        last_hash: RwLock::new(None),
    });

    // Background task: Continuous hourly hash-chained PoG loop + optional push to pog-log!
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

    // HTTP sidecar endpoint + optional drop-in reverse proxy injecting `X-PoG-Proof` on every response!
    let mut app = Router::new()
        .route("/health", get(|| async { Json(serde_json::json!({ "status": "ok" })) }))
        .route("/v1/handshake-proof", get(handshake_proof_handler))
        .route("/v1/latest-proof", get(latest_proof_handler));

    if state.upstream.is_some() {
        app = app.fallback(reverse_proxy_handler);
    }

    let listener = tokio::net::TcpListener::bind(args.http_listen).await?;
    info!(listen = %args.http_listen, "Prover HTTP handshake sidecar ready");
    axum::serve(listener, app.with_state(state)).await?;
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

/// Drop-in reverse proxy forwarding requests to `--upstream` (e.g., vLLM / SGLang / API)
/// and injecting `X-PoG-Proof`, `X-PoG-Prover-Key`, and `X-PoG-Chain-Seq` on every response!
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

    let mut stream = match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
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
            if kn.eq_ignore_ascii_case("transfer-encoding") || kn.eq_ignore_ascii_case("connection") {
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

    // Automatically inject cached continuous-chain X-PoG-Proof header on every response!
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

    #[test]
    fn test_parse_http_host_port() {
        let (addr, host) = parse_http_host_port("http://127.0.0.1:8090/v1").unwrap();
        assert_eq!(addr, "127.0.0.1:8090");
        assert_eq!(host, "127.0.0.1:8090");

        let (addr2, host2) = parse_http_host_port("127.0.0.1:8000").unwrap();
        assert_eq!(addr2, "127.0.0.1:8000");
        assert_eq!(host2, "127.0.0.1:8000");
    }
}
