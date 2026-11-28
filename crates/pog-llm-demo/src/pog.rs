//! Out-of-band Proof of Geography prover running inside the SAME measured workload using the
//! EXACT SAME enclave-held nonexportable Ed25519 key (`prover_kp`).
//!
//! Strictly separates:
//! 1. Production hardware TEE anchor probing (`GeoProofBundle`, excluding `SoftwareDev` AND
//!    excluding any anchor sharing `prover_pk_hex` so the prover NEVER counts as its own anchor).
//! 2. Transparent diagnostic-only RTT observations against the live non-production fleet
//!    (`diagnostic_only: true`, NEVER counted toward `geographic_proof_verified`).

use anyhow::Result;
use chrono::Utc;
use pog_geo::LatLon;
use pog_proto::{
    anchor_handshake_attestation_policy, bind_low_latency_udp, encode_udp_punch,
    finish_phase1_client, respond_once_udp, select_committee, start_phase1_client,
    AnchorDescriptor, AnchorGrid, AnchorReceipt, CommitteeConfig, DiagnosticAnchorObservation,
    GeoProofBundle, Phase1ClientState, Phase1InitResponse,
};
use pog_tee::{TeeProvider, TeeVendor, WorkloadKeypair};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

pub struct OutOfBandPogResult {
    /// Present ONLY when >= 1 real non-SoftwareDev hardware TEE anchor completed Phase 2 UDP!
    pub production_bundle: Option<GeoProofBundle>,
    /// Transparent diagnostic observations (NEVER used as geographic proof).
    pub diagnostic_observations: Vec<DiagnosticAnchorObservation>,
}

/// Run one out-of-band PoG refresh round from inside the enclave.
pub async fn run_out_of_band_pog_refresh(
    grid: &AnchorGrid,
    keypair: &WorkloadKeypair,
    tee_provider: &dyn TeeProvider,
    claimed_target: LatLon,
) -> OutOfBandPogResult {
    let now = Utc::now().timestamp().max(0) as u64;
    let pk_hex = keypair.public_key_hex();

    // 1. Attempt production hardware-only PoG UDP distance-bounding against eligible non-SoftwareDev
    //    anchors (NEVER counting self!).
    let hw_anchors: Vec<AnchorDescriptor> = grid
        .anchors
        .iter()
        .filter(|a| {
            a.tee_vendor != TeeVendor::SoftwareDev
                && !a.diagnostic_only
                && !a.public_key_hex.eq_ignore_ascii_case(&pk_hex)
        })
        .cloned()
        .collect();

    let production_bundle = if !hw_anchors.is_empty() {
        let hw_grid = AnchorGrid {
            version: grid.version.clone(),
            grid_name: grid.grid_name.clone(),
            description: grid.description.clone(),
            anchors: hw_anchors,
        };
        try_probe_hardware_committee(&hw_grid, keypair, tee_provider, claimed_target, now)
            .await
            .ok()
    } else {
        None
    };

    // 2. Separately measure diagnostic-only TCP/RTT observations to up to 10 closest diagnostic
    //    anchors across distinct clouds so visitors can inspect transparent network latency
    //    WITHOUT ever claiming hardware-proven geography!
    let mut candidates: Vec<&AnchorDescriptor> = grid
        .anchors
        .iter()
        .filter(|a| !a.public_key_hex.eq_ignore_ascii_case(&pk_hex))
        .collect();
    candidates.sort_by(|a, b| {
        a.location
            .distance_km(claimed_target)
            .partial_cmp(&b.location.distance_km(claimed_target))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    candidates.truncate(10);

    let mut tasks = Vec::new();
    for a in candidates {
        let a_clone = a.clone();
        tasks.push(tokio::spawn(async move {
            measure_diagnostic_tcp_rtt(&a_clone, now).await
        }));
    }
    let mut diagnostic_observations = Vec::new();
    for t in tasks {
        if let Ok(Some(obs)) = t.await {
            diagnostic_observations.push(obs);
        }
    }
    diagnostic_observations.sort_by(|a, b| {
        a.rtt_min_ms
            .partial_cmp(&b.rtt_min_ms)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    OutOfBandPogResult {
        production_bundle,
        diagnostic_observations,
    }
}

async fn measure_diagnostic_tcp_rtt(
    anchor: &AnchorDescriptor,
    now: u64,
) -> Option<DiagnosticAnchorObservation> {
    let mut best_ms = f64::INFINITY;
    for _ in 0..3 {
        let t0 = Instant::now();
        if let Ok(Ok(stream)) =
            tokio::time::timeout(Duration::from_millis(1200), TcpStream::connect(&anchor.endpoint_tcp))
                .await
        {
            let ms = t0.elapsed().as_secs_f64() * 1000.0;
            drop(stream);
            if ms < best_ms {
                best_ms = ms;
            }
        }
    }
    if best_ms.is_finite() {
        Some(DiagnosticAnchorObservation {
            anchor_id: anchor.anchor_id.clone(),
            cloud_provider: anchor.cloud_provider.clone(),
            region: anchor.region.clone(),
            city: anchor.city.clone(),
            rtt_min_ms: (best_ms * 100.0).round() / 100.0,
            diagnostic_only: true,
            measured_at_unix_s: now,
        })
    } else {
        None
    }
}

async fn try_probe_hardware_committee(
    hw_grid: &AnchorGrid,
    keypair: &WorkloadKeypair,
    tee_provider: &dyn TeeProvider,
    target: LatLon,
    now: u64,
) -> Result<GeoProofBundle> {
    let hour_bucket = now / 3600;
    let mut h = blake3::Hasher::new();
    h.update(b"pog-llm-demo-epoch-v1");
    h.update(&hour_bucket.to_le_bytes());
    let epoch = *h.finalize().as_bytes();
    let epoch_hex = hex::encode(epoch);

    let pk_bytes = keypair.public_key_bytes();
    let pk_hex = keypair.public_key_hex();
    let prover_quote = tee_provider.attest(&pk_bytes, &epoch, None)?;

    let sel = select_committee(
        hw_grid,
        &pk_hex,
        &epoch,
        target,
        &CommitteeConfig {
            committee_size: 16,
            max_regional_km: 7_500.0,
            ..CommitteeConfig::default()
        },
    );
    let mut tasks = Vec::new();
    for anchor in sel.selected {
        let Ok(udp_sock) = bind_low_latency_udp("0.0.0.0:0".parse()?, Duration::from_secs(2)) else {
            continue;
        };
        let Ok(local_udp_port) = udp_sock.local_addr().map(|a| a.port()) else {
            continue;
        };
        let Ok(client_state) = start_phase1_client(
            keypair,
            prover_quote.clone(),
            &epoch,
            &anchor.anchor_id,
            &anchor.public_key_hex,
            anchor.tee_vendor,
            local_udp_port,
            6,
        ) else {
            continue;
        };
        let aid = anchor.anchor_id.clone();
        tasks.push(tokio::spawn(async move {
            (aid, probe_single_anchor(&anchor, udp_sock, client_state).await)
        }));
    }
    let mut receipts = Vec::new();
    for t in tasks {
        if let Ok((aid, res)) = t.await {
            match res {
                Ok(r) => {
                    tracing::info!(
                        anchor_id = %aid,
                        rtt_min_us = r.rtt_min_us,
                        "Hardware TEE anchor issued signed PoG UDP receipt"
                    );
                    receipts.push(r);
                }
                Err(e) => {
                    tracing::warn!(anchor_id = %aid, error = %e, "Hardware TEE anchor probe did not complete");
                }
            }
        }
    }
    if receipts.is_empty() {
        anyhow::bail!("no hardware TEE anchors completed Phase 2 UDP burst");
    }

    Ok(GeoProofBundle {
        version: 1,
        epoch_challenge_hex: epoch_hex,
        client_nonce_hex: None,
        target_location: target,
        required_radius_km: 2_500.0,
        prover_quote,
        receipts,
        calibrated_velocity_km_per_s: Some(145_000.0),
        prev_chain_hash_hex: None,
        chain_seq: 1,
        created_at_unix_s: now,
    })
}

async fn probe_single_anchor(
    anchor: &AnchorDescriptor,
    udp_sock: UdpSocket,
    client_state: Phase1ClientState,
) -> Result<AnchorReceipt> {
    let stream = tokio::time::timeout(Duration::from_secs(4), TcpStream::connect(&anchor.endpoint_tcp))
        .await??;
    let peer_ip = stream.peer_addr()?.ip();
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);

    let mut req_line = serde_json::to_string(&client_state.init_req)?;
    req_line.push('\n');
    writer.write_all(req_line.as_bytes()).await?;
    writer.flush().await?;

    let mut resp_line = String::new();
    buf_reader.read_line(&mut resp_line).await?;
    let init_resp: Phase1InitResponse = serde_json::from_str(resp_line.trim())?;

    // Production hardware TEE Anchors strictly enforce AttestationPolicy::production()!
    let anchor_tee_policy = anchor_handshake_attestation_policy(anchor.tee_vendor, false);
    let now = Utc::now().timestamp().max(0) as u64;
    let epoch_copy = client_state.epoch_bytes.clone();
    let completed = finish_phase1_client(client_state, &init_resp, &anchor_tee_policy, now)?;

    let session_id = completed.session_id;
    let rounds = completed.negotiated_rounds;
    let session_key = completed.keys.phase2_mac_key;
    let anchor_udp_addr = SocketAddr::new(peer_ip, completed.anchor_udp_port);
    let punch = encode_udp_punch(session_id, completed.cookie);

    let mut confirm_line = serde_json::to_string(&completed.confirm)?;
    confirm_line.push('\n');
    writer.write_all(confirm_line.as_bytes()).await?;
    writer.flush().await?;

    let udp_handle = tokio::task::spawn_blocking(move || -> Result<()> {
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
    receipt.verify(&anchor.public_key_hex)?;
    Ok(receipt)
}
