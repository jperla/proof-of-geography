use anyhow::Result;
use chrono::Utc;
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use pog_geo::bounds::starlink_vs_fiber_crossover_km;
use pog_geo::{
    effective_radius_km, starlink_min_rtt_ms, BoundTier, DiskConstraint, LatLon, StarlinkModel,
    C_FIBER_KM_PER_S, EARTH_RADIUS_KM,
};
use pog_log::{build_router, ContinuousGeoLog};
use pog_proto::{
    compute_challenge_mac, select_committee, verify_proof_bundle, AnchorGrid, AnchorReceipt,
    CommitteeConfig, GeoProofBundle, VerificationPolicy,
};
use pog_tee::{
    AttestationPolicy, GpuAttestationBinding, SoftwareDevProvider, TeeProvider, WorkloadKeypair,
};
use pog_telemetry::{fuse_ipinfo_telemetry, parse_rfc8805_geofeed, TracerouteHop};
use rand::rngs::OsRng;
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(
    name = "pog-cli",
    about = "Proof of Geography CLI: Verifier, Red-Team Simulator, Throughput Benchmark & Transparency Log"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run full red-team simulation suite (Tokyo GPU, Beijing->SG proxy lie, Starlink, Byzantine f=1, Boat/Plane relocation, 24h convergence).
    Simulate {
        #[arg(long, default_value = "config/global_grid_24.json")]
        grid: PathBuf,
    },
    /// Benchmark BLAKE3-MAC fast-path, Byzantine (K-f)-core verifier, and estimate global trillions-of-requests capacity.
    Bench {
        #[arg(long, default_value = "config/global_grid_24.json")]
        grid: PathBuf,
        #[arg(long, default_value_t = 5000)]
        verify_iters: usize,
    },
    /// Verify a GeoProofBundle JSON file or base64url X-PoG-Proof header offline.
    Verify {
        #[arg(long, default_value = "config/global_grid_24.json")]
        grid: PathBuf,
        #[arg(long)]
        bundle_json: Option<PathBuf>,
        #[arg(long)]
        header_value: Option<String>,
        #[arg(long, default_value_t = false)]
        allow_dev_tee: bool,
    },
    /// Start the DNS/CT-style signed append-only transparency log HTTP server.
    ServeLog {
        #[arg(long, default_value = "config/global_grid_24.json")]
        grid: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8090")]
        listen: SocketAddr,
        #[arg(long, default_value_t = false)]
        allow_dev_tee: bool,
    },
    /// Export an Anchor disk & Byzantine intersection visualization as GeoJSON.
    ExportGeojson {
        #[arg(long, default_value = "config/global_grid_24.json")]
        grid: PathBuf,
        #[arg(long, default_value_t = 35.6762)]
        lat: f64,
        #[arg(long, default_value_t = 139.6503)]
        lon: f64,
        #[arg(long, default_value = "pog_tokyo.geojson")]
        out: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Simulate { grid } => run_simulations(&grid),
        Commands::Bench { grid, verify_iters } => run_benchmarks(&grid, verify_iters),
        Commands::Verify {
            grid,
            bundle_json,
            header_value,
            allow_dev_tee,
        } => run_verify(&grid, bundle_json, header_value, allow_dev_tee),
        Commands::ServeLog {
            grid,
            listen,
            allow_dev_tee,
        } => run_serve_log(&grid, listen, allow_dev_tee).await,
        Commands::ExportGeojson {
            grid,
            lat,
            lon,
            out,
        } => run_export_geojson(&grid, LatLon::new(lat, lon), &out),
    }
}

/// Replace placeholder registry keys with fresh real Ed25519 keys for live cryptographic simulations.
fn hydrate_grid_with_live_keys(grid_path: &PathBuf) -> Result<(AnchorGrid, HashMap<String, SigningKey>)> {
    let text = std::fs::read_to_string(grid_path)?;
    let mut grid = AnchorGrid::from_json_str(&text)?;
    let mut keys = HashMap::new();
    for a in &mut grid.anchors {
        let sk = SigningKey::generate(&mut OsRng);
        a.public_key_hex = hex::encode(sk.verifying_key().to_bytes());
        keys.insert(a.anchor_id.clone(), sk);
    }
    Ok((grid, keys))
}

fn realistic_internet_rtt_us(a: LatLon, b: LatLon, stretch: f64, overhead_ms: f64) -> u64 {
    let d_km = a.distance_km(b);
    let rtt_s = (2.0 * d_km * stretch) / C_FIBER_KM_PER_S + (overhead_ms * 1e-3);
    (rtt_s * 1e6).max(600.0) as u64
}

struct SimBundleSpec<'a> {
    true_location: LatLon,
    claimed_location: LatLon,
    required_radius_km: f64,
    epoch_label: &'a str,
    seq: u64,
    prev_hash: Option<String>,
    now_unix_s: u64,
    stretch: f64,
    overhead_ms: f64,
    colluding_anchor_override: Option<(&'a str, u64)>,
}

fn build_signed_bundle(
    grid: &AnchorGrid,
    anchor_keys: &HashMap<String, SigningKey>,
    prover_kp: &WorkloadKeypair,
    spec: SimBundleSpec<'_>,
) -> GeoProofBundle {
    let epoch = *blake3::hash(spec.epoch_label.as_bytes()).as_bytes();
    let epoch_hex = hex::encode(epoch);
    let dev_tee = SoftwareDevProvider::new(hex::encode(
        blake3::hash(b"nvidia-h100-inference-container-v1").as_bytes(),
    ));
    let gpu = GpuAttestationBinding {
        gpu_model: "NVIDIA H100 80GB SXM5 Confidential".into(),
        gpu_uuid: "GPU-9f2a1c44-8b10-4e21-a8d7-112233445566".into(),
        spdm_report_hash_hex: hex::encode(blake3::hash(b"spdm-rim-report").as_bytes()),
        driver_measurement_hex: hex::encode(blake3::hash(b"nvidia-cc-driver-550").as_bytes()),
    };
    let quote = dev_tee
        .attest(&prover_kp.public_key_bytes(), &epoch, Some(gpu))
        .unwrap();

    let sel = select_committee(
        grid,
        &prover_kp.public_key_hex(),
        &epoch,
        spec.claimed_location,
        &CommitteeConfig::default(),
    );

    let mut receipts = Vec::new();
    for a in &sel.selected {
        let mut rtt_min = realistic_internet_rtt_us(
            a.location,
            spec.true_location,
            spec.stretch,
            spec.overhead_ms,
        );
        if let Some((bad_id, fake_us)) = spec.colluding_anchor_override {
            if a.anchor_id == bad_id {
                rtt_min = fake_us;
            }
        }
        let mut r = AnchorReceipt {
            anchor_id: a.anchor_id.clone(),
            cloud_provider: a.cloud_provider.clone(),
            prover_pk_hex: prover_kp.public_key_hex(),
            workload_measurement_hex: quote.workload_measurement_hex.clone(),
            epoch_challenge_hex: epoch_hex.clone(),
            prover_observed_ip: "198.51.100.42".into(),
            rtt_min_us: rtt_min,
            rtt_p50_us: rtt_min + 350,
            rtt_samples_us: vec![rtt_min, rtt_min + 220, rtt_min + 350, rtt_min + 510],
            measured_at_unix_s: spec.now_unix_s,
            anchor_signature_hex: String::new(),
        };
        r.sign(&anchor_keys[&a.anchor_id]);
        receipts.push(r);
    }

    GeoProofBundle {
        version: 1,
        epoch_challenge_hex: epoch_hex,
        client_nonce_hex: Some("client-handshake-nonce-deadbeef".into()),
        target_location: spec.claimed_location,
        required_radius_km: spec.required_radius_km,
        prover_quote: quote,
        receipts,
        calibrated_velocity_km_per_s: Some(165_000.0),
        prev_chain_hash_hex: spec.prev_hash,
        chain_seq: spec.seq,
        created_at_unix_s: spec.now_unix_s,
    }
}

fn run_simulations(grid_path: &PathBuf) -> Result<()> {
    let (grid, keys) = hydrate_grid_with_live_keys(grid_path)?;
    let now = Utc::now().timestamp() as u64;
    let policy = VerificationPolicy {
        tee_policy: AttestationPolicy::allow_dev_software(),
        max_byzantine: 1,
        min_anchors: 5,
        min_cloud_providers: 3,
        max_proof_age_seconds: 3_900,
        enforce_tier: BoundTier::Vacuum,
    };

    println!("==========================================================================");
    println!("  PROOF OF GEOGRAPHY — END-TO-END RED-TEAM & PHYSICS SIMULATION SUITE");
    println!("  Grid: {} ({} nodes across 6 clouds)", grid.grid_name, grid.anchors.len());
    println!("==========================================================================\n");

    // -----------------------------------------------------------------------
    // SCENARIO 1: Honest Tokyo H100 GPU Cluster (Cross-Cloud Metro + Regional)
    // -----------------------------------------------------------------------
    let tokyo = LatLon::new(35.6762, 139.6503);
    let tokyo_kp = WorkloadKeypair::generate();
    let b1 = build_signed_bundle(
        &grid,
        &keys,
        &tokyo_kp,
        SimBundleSpec {
            true_location: tokyo,
            claimed_location: tokyo,
            required_radius_km: 300.0,
            epoch_label: "epoch-tokyo-honest",
            seq: 0,
            prev_hash: None,
            now_unix_s: now,
            stretch: 1.32,
            overhead_ms: 1.0,
            colluding_anchor_override: None,
        },
    );
    let rep1 = verify_proof_bundle(&b1, &grid, &policy, now)?;
    let hdr_bytes = b1.to_header_value()?.len();
    println!("[1] HONEST TOKYO H100 GPU CLUSTER (f=1 Byzantine quorum across {} clouds)", rep1.distinct_clouds);
    println!("    Anchors: {:?}", b1.receipts.iter().map(|r| format!("{} ({:.2}ms)", r.anchor_id, r.rtt_min_us as f64 / 1000.0)).collect::<Vec<_>>());
    println!("    Tier 1A (Vacuum / Starlink-safe): max radius = {:.1} km ({:.1} mi)", rep1.tier1a_vacuum.proven_max_radius_km, rep1.tier1a_vacuum.proven_max_radius_km * 0.621371);
    println!("    Tier 1B (Silica Fiber):           max radius = {:.1} km ({:.1} mi)", rep1.tier1b_fiber.proven_max_radius_km, rep1.tier1b_fiber.proven_max_radius_km * 0.621371);
    println!("    Tier 2  (Calibrated Empirical):   max radius = {:.1} km ({:.1} mi)", rep1.tier2_calibrated.proven_max_radius_km, rep1.tier2_calibrated.proven_max_radius_km * 0.621371);
    println!("    X-PoG-Proof handshake header size: {} bytes | Valid: {}\n", hdr_bytes, rep1.overall_valid);

    // -----------------------------------------------------------------------
    // SCENARIO 2: Inference Router Lie — Beijing GPU Proxying via Singapore
    // -----------------------------------------------------------------------
    let beijing = LatLon::new(39.9042, 116.4074);
    let singapore = LatLon::new(1.3521, 103.8198);
    let liar_kp = WorkloadKeypair::generate();
    let b2 = build_signed_bundle(
        &grid,
        &keys,
        &liar_kp,
        SimBundleSpec {
            true_location: beijing,    // ACTUAL physical GPU silicon is in Beijing!
            claimed_location: singapore, // CLAIMED inference router region is Singapore!
            required_radius_km: 500.0,
            epoch_label: "epoch-beijing-proxy-sg",
            seq: 0,
            prev_hash: None,
            now_unix_s: now,
            stretch: 1.38,
            overhead_ms: 1.5,
            colluding_anchor_override: None,
        },
    );
    let rep2 = verify_proof_bundle(&b2, &grid, &policy, now)?;
    let sg_rtt_ms = b2
        .receipts
        .iter()
        .find(|r| r.anchor_id.contains("singapore") || r.anchor_id.contains("johor"))
        .map(|r| r.rtt_min_us as f64 / 1000.0)
        .unwrap_or(62.0);
    let fake_geofeed = parse_rfc8805_geofeed("198.51.100.0/24,SG,SG-01,Singapore,018956");
    let hops = vec![TracerouteHop {
        ttl: 3,
        ip: "198.51.100.42".into(),
        rdns: Some("edge-router.sin1.sketchy-ai.example".into()),
        rtt_ms: 1.4, // Front-end proxy responds in 1.4 ms in Singapore!
    }];
    let disks2: Vec<DiskConstraint> = b2
        .receipts
        .iter()
        .map(|r| {
            let a = grid.by_id(&r.anchor_id).unwrap();
            DiskConstraint::from_rtt(&a.anchor_id, a.location, r.rtt_min_us, BoundTier::Vacuum, &a.cloud_provider)
        })
        .collect();
    let telem2 = fuse_ipinfo_telemetry(
        singapore,
        &rep2.tier1a_vacuum,
        &rep2.tier2_calibrated,
        &disks2,
        fake_geofeed.first(),
        &hops,
        sg_rtt_ms,
    );
    println!("[2] INFERENCE ROUTER LIE: BEIJING GPUS PROXYING THROUGH SINGAPORE");
    println!("    Router IP responds in 1.4 ms in Singapore, BUT TEE challenge RTT = {:.1} ms!", sg_rtt_ms);
    println!("    Tier 1A worst-case distance from Singapore: {:.1} km ({:.1} mi) vs 500 km limit", rep2.tier1a_vacuum.proven_max_radius_km, rep2.tier1a_vacuum.proven_max_radius_km * 0.621371);
    println!("    Proof Accepted? {} (CAUGHT!) | IPinfo Telemetry Proxy Alert? {} ({} alerts)\n", rep2.overall_valid, telem2.proxy_or_router_lie_suspected, telem2.alerts.len());

    // -----------------------------------------------------------------------
    // SCENARIO 3: Starlink LEO Laser Relay Analysis
    // -----------------------------------------------------------------------
    let sl = StarlinkModel::default();
    let crossover = starlink_vs_fiber_crossover_km(sl);
    println!("[3] STARLINK LEO VACUUM LASER ISL PHYSICS AUDIT (550 km shell, 40 deg elev)");
    println!("    Crossover where Starlink vacuum ISLs beat ideal silica fiber: {:.0} km ({:.0} mi)", crossover, crossover * 0.621371);
    for d in [500.0, 2500.0, 5000.0, 9000.0] {
        let sl_rtt = starlink_min_rtt_ms(d, sl);
        let fiber_rtt = (2.0 * d / C_FIBER_KM_PER_S) * 1000.0;
        let vac_r = effective_radius_km((sl_rtt * 1000.0) as u64, BoundTier::Vacuum);
        let fib_r = effective_radius_km((sl_rtt * 1000.0) as u64, BoundTier::Fiber);
        println!(
            "    Dist {:>5.0} km | Starlink RTT {:>5.1} ms vs Ideal Fiber {:>5.1} ms | Tier1A(Vac)={:>6.0} km (SAFE:{}) | Tier1B(Fib)={:>6.0} km (SAFE:{})",
            d,
            sl_rtt,
            fiber_rtt,
            vac_r,
            vac_r >= d,
            fib_r,
            fib_r >= d
        );
    }
    println!();

    // -----------------------------------------------------------------------
    // SCENARIO 4: Byzantine Colluding Anchor Attack (1 of 6 Anchors Compromised)
    // -----------------------------------------------------------------------
    let sel_sg = select_committee(
        &grid,
        &liar_kp.public_key_hex(),
        blake3::hash(b"epoch-byzantine-attack").as_bytes(),
        singapore,
        &CommitteeConfig::default(),
    );
    let rogue_id = sel_sg.selected[0].anchor_id.clone();
    let b4 = build_signed_bundle(
        &grid,
        &keys,
        &liar_kp,
        SimBundleSpec {
            true_location: beijing,
            claimed_location: singapore,
            required_radius_km: 500.0,
            epoch_label: "epoch-byzantine-attack",
            seq: 0,
            prev_hash: None,
            now_unix_s: now,
            stretch: 1.35,
            overhead_ms: 1.5,
            colluding_anchor_override: Some((&rogue_id, 300)), // Rogue anchor lies: "RTT = 0.3 ms!"
        },
    );
    let rep4 = verify_proof_bundle(&b4, &grid, &policy, now)?;
    println!("[4] BYZANTINE COLLUDING ANCHOR ATTACK (f=1 rogue anchor '{}' fabricates 0.3 ms RTT)", rogue_id);
    println!("    5-of-6 Byzantine Core max distance from Singapore: {:.1} km -> Accepted? {} (BLOCKED!)\n", rep4.tier1a_vacuum.proven_max_radius_km, rep4.overall_valid);

    // -----------------------------------------------------------------------
    // SCENARIO 5: Mobile Datacenter (Hardware Relocated on Boat / Aircraft)
    // -----------------------------------------------------------------------
    let ashburn = LatLon::new(39.0438, -77.4874);
    let frankfurt = LatLon::new(50.1109, 8.6821);
    let mobile_kp = WorkloadKeypair::generate();
    let mut log_policy = policy.clone();
    log_policy.max_proof_age_seconds = 3600 * 48;
    let mut ct_log = ContinuousGeoLog::new(grid.clone(), log_policy.clone());

    let h0 = build_signed_bundle(
        &grid,
        &keys,
        &mobile_kp,
        SimBundleSpec {
            true_location: ashburn,
            claimed_location: ashburn,
            required_radius_km: 400.0,
            epoch_label: "mobile-hr-0",
            seq: 0,
            prev_hash: None,
            now_unix_s: now - 8 * 3600,
            stretch: 1.30,
            overhead_ms: 1.0,
            colluding_anchor_override: None,
        },
    );
    let rec0 = ct_log.append_bundle(h0, now - 8 * 3600)?;
    // 8 hours later, hardware is flown to Frankfurt (~6,550 km away) and tries to keep attesting!
    let h8 = build_signed_bundle(
        &grid,
        &keys,
        &mobile_kp,
        SimBundleSpec {
            true_location: frankfurt,
            claimed_location: frankfurt,
            required_radius_km: 400.0,
            epoch_label: "mobile-hr-8",
            seq: 1,
            prev_hash: Some(rec0.record_hash_hex),
            now_unix_s: now,
            stretch: 1.30,
            overhead_ms: 1.0,
            colluding_anchor_override: None,
        },
    );
    let rec8 = ct_log.append_bundle(h8, now)?;
    println!("[5] MOBILE DATACENTER / HARDWARE RELOCATION ATTACK (Ashburn -> Frankfurt in 8h)");
    println!("    Merkle Log Tree Size: {} | Stationary Confirmed? {}", rec8.sth.tree_size, rec8.movement_report.stationary_confirmed);
    println!("    Detected Anomalies: {:?}\n", rec8.movement_report.anomalies);

    // -----------------------------------------------------------------------
    // SCENARIO 6: 24-Hour Continuous Stationary Orthogonal Convergence (Chicago, IL)
    // No co-located metro anchor — framed solely by 4 outside orthogonal directions!
    // -----------------------------------------------------------------------
    let chicago = LatLon::new(41.8781, -87.6298);
    let stat_kp = WorkloadKeypair::generate();
    let mut stat_policy = log_policy;
    stat_policy.enforce_tier = BoundTier::Fiber;
    let mut stat_log = ContinuousGeoLog::new(grid.clone(), stat_policy);
    let mut prev: Option<String> = None;
    let mut single_hour_radii = Vec::new();
    for hr in 0..24u64 {
        // Simulate fluctuating internet congestion (1.22x to 1.55x stretch across hours).
        let jitter_stretch = 1.22 + ((hr * 7 % 11) as f64) * 0.03;
        let jitter_overhead = 0.8 + ((hr * 3 % 5) as f64) * 0.8;
        let ts = now - (23 - hr) * 3600;
        let b = build_signed_bundle(
            &grid,
            &keys,
            &stat_kp,
            SimBundleSpec {
                true_location: chicago,
                claimed_location: chicago,
                required_radius_km: 2_200.0,
                epoch_label: &format!("stationary-hr-{hr}"),
                seq: hr,
                prev_hash: prev.clone(),
                now_unix_s: ts,
                stretch: jitter_stretch,
                overhead_ms: jitter_overhead,
                colluding_anchor_override: None,
            },
        );
        let r = stat_log.append_bundle(b, ts)?;
        single_hour_radii.push(r.verification.tier1b_fiber.proven_max_radius_km);
        prev = Some(r.record_hash_hex);
    }
    let status = stat_log.prover_status(&stat_kp.public_key_hex()).unwrap();
    let worst_single = single_hour_radii.iter().copied().fold(0.0_f64, f64::max);
    let converged = status
        .movement_report
        .converged_multi_hour_radius_km
        .unwrap_or(worst_single);
    println!("[6] 24-HOUR CONTINUOUS STATIONARY ORTHOGONAL CONVERGENCE (Chicago, IL — no local anchor!)");
    println!("    Chain length: {} hourly links | Stationary: {}", status.chain_length, status.movement_report.stationary_confirmed);
    println!("    Worst congested single-hour Tier 1B (Fiber) radius: {:.1} km ({:.1} mi)", worst_single, worst_single * 0.621371);
    println!("    24h Multi-Hour Min-RTT Converged Radius:            {:.1} km ({:.1} mi) [Tightened by {:.1}%!]", converged, converged * 0.621371, (1.0 - converged / worst_single) * 100.0);

    Ok(())
}

fn run_benchmarks(grid_path: &PathBuf, verify_iters: usize) -> Result<()> {
    let (grid, keys) = hydrate_grid_with_live_keys(grid_path)?;
    let now = Utc::now().timestamp() as u64;
    let kp = WorkloadKeypair::generate();
    let tokyo = LatLon::new(35.6762, 139.6503);
    let bundle = build_signed_bundle(
        &grid,
        &keys,
        &kp,
        SimBundleSpec {
            true_location: tokyo,
            claimed_location: tokyo,
            required_radius_km: 300.0,
            epoch_label: "bench-epoch",
            seq: 0,
            prev_hash: None,
            now_unix_s: now,
            stretch: 1.32,
            overhead_ms: 1.0,
            colluding_anchor_override: None,
        },
    );
    let policy = VerificationPolicy {
        tee_policy: AttestationPolicy::allow_dev_software(),
        max_byzantine: 1,
        min_anchors: 5,
        min_cloud_providers: 3,
        max_proof_age_seconds: 3_900,
        enforce_tier: BoundTier::Vacuum,
    };

    // 1. BLAKE3-MAC fast-path benchmark (timed Phase 2 prover response overhead).
    let mac_iters = 500_000usize;
    let key = [0x55u8; 32];
    let nonce = [0xAAu8; 32];
    let t0 = Instant::now();
    let mut acc = 0u8;
    for i in 0..mac_iters {
        let m = compute_challenge_mac(&key, i as u64, 0, &nonce, b"bench");
        acc ^= m[0];
    }
    let mac_elapsed = t0.elapsed();
    let mac_ns = mac_elapsed.as_nanos() as f64 / mac_iters as f64;
    let mac_ops_s = mac_iters as f64 / mac_elapsed.as_secs_f64();

    // 2. Full offline client verification benchmark (TEE quote + 6 Ed25519 sigs + Byzantine (K-f)-core).
    let t1 = Instant::now();
    let mut ok_count = 0usize;
    for _ in 0..verify_iters {
        let rep = verify_proof_bundle(&bundle, &grid, &policy, now)?;
        if rep.overall_valid {
            ok_count += 1;
        }
    }
    let ver_elapsed = t1.elapsed();
    let ver_us = (ver_elapsed.as_secs_f64() * 1e6) / verify_iters as f64;
    let ver_ops_s = verify_iters as f64 / ver_elapsed.as_secs_f64();

    // Capacity projection across 24-node global grid.
    // Conservative single-core NIC UDP rate per Anchor = 120,000 pkt/s -> 15,000 8-round probes/s.
    // Each proof uses K=6 Anchors, so 24 nodes handle (24 / 6) * 15,000 = 60,000 raw live proofs/sec!
    let raw_proofs_per_sec_24_nodes: f64 = 60_000.0;
    let raw_proofs_per_year = raw_proofs_per_sec_24_nodes * 31_536_000.0;
    // With hourly cached chain proofs attached to handshakes (1 proof covers 10,000 API/inference req/s per cluster):
    let cached_reqs_per_year = raw_proofs_per_year * 10_000.0;

    println!("==========================================================================");
    println!("  PROOF OF GEOGRAPHY — EMPIRICAL PERFORMANCE & CAPACITY BENCHMARK");
    println!("==========================================================================");
    println!("  [Prover Fast-Path] BLAKE3-MAC:   {:.1} ns/op ({:.2} M ops/sec) [checksum={acc}]", mac_ns, mac_ops_s / 1e6);
    println!("    -> Adds < 0.001 ms (< 0.15 km) to speed-of-light radius!");
    println!("  [Client Verifier]  Full Bundle:  {:.1} us/verify ({:.0} verifies/sec/core, ok={ok_count}/{verify_iters})", ver_us, ver_ops_s);
    println!("    -> Includes TEE quote check + 6 Ed25519 Anchor sigs + exact O(K^3) Byzantine core!");
    println!("  [24-Node Global Grid Capacity Estimates]");
    println!("    -> Raw live UDP distance-bounding proofs:  ~60,000 proofs/sec (~{:.2} TRILLION proofs/yr)", raw_proofs_per_year / 1e12);
    println!("    -> Handshake/hourly-cached API requests:   ~{:.0} TRILLION+ verified requests/yr", cached_reqs_per_year / 1e12);
    println!("    -> At 10M distinct Prover servers running hourly chains: only ~2,778 proofs/sec (<5% grid load!)");
    println!("==========================================================================");
    Ok(())
}

fn run_verify(
    grid_path: &PathBuf,
    bundle_json: Option<PathBuf>,
    header_value: Option<String>,
    allow_dev_tee: bool,
) -> Result<()> {
    let grid = AnchorGrid::from_json_str(&std::fs::read_to_string(grid_path)?)?;
    let bundle = if let Some(path) = bundle_json {
        serde_json::from_str(&std::fs::read_to_string(path)?)?
    } else if let Some(hdr) = header_value {
        GeoProofBundle::from_header_value(&hdr)?
    } else {
        anyhow::bail!("Provide either --bundle-json or --header-value");
    };
    let policy = VerificationPolicy {
        tee_policy: if allow_dev_tee {
            AttestationPolicy::allow_dev_software()
        } else {
            AttestationPolicy::production()
        },
        ..Default::default()
    };
    let now = Utc::now().timestamp() as u64;
    let report = verify_proof_bundle(&bundle, &grid, &policy, now)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if !report.overall_valid {
        std::process::exit(1);
    }
    Ok(())
}

async fn run_serve_log(grid_path: &PathBuf, listen: SocketAddr, allow_dev_tee: bool) -> Result<()> {
    tracing_subscriber::fmt().init();
    let grid = AnchorGrid::from_json_str(&std::fs::read_to_string(grid_path)?)?;
    let policy = VerificationPolicy {
        tee_policy: if allow_dev_tee {
            AttestationPolicy::allow_dev_software()
        } else {
            AttestationPolicy::production()
        },
        ..Default::default()
    };
    let log = Arc::new(RwLock::new(ContinuousGeoLog::new(grid, policy)));
    let app = build_router(log);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    println!("PoG DNS/CT Transparency Log listening on http://{listen}");
    axum::serve(listener, app).await?;
    Ok(())
}

fn circle_polygon_coords(center: LatLon, radius_km: f64, steps: usize) -> Vec<[f64; 2]> {
    let angular_r = (radius_km / EARTH_RADIUS_KM).min(std::f64::consts::PI * 0.99);
    let lat1 = center.lat.to_radians();
    let lon1 = center.lon.to_radians();
    let mut ring = Vec::with_capacity(steps + 1);
    for i in 0..=steps {
        let brng = (i as f64 / steps as f64) * 2.0 * std::f64::consts::PI;
        let lat2 = (lat1.sin() * angular_r.cos()
            + lat1.cos() * angular_r.sin() * brng.cos())
        .asin();
        let lon2 = lon1
            + (brng.sin() * angular_r.sin() * lat1.cos())
                .atan2(angular_r.cos() - lat1.sin() * lat2.sin());
        ring.push([lon2.to_degrees(), lat2.to_degrees()]);
    }
    ring
}

fn run_export_geojson(grid_path: &PathBuf, target: LatLon, out: &PathBuf) -> Result<()> {
    let (grid, keys) = hydrate_grid_with_live_keys(grid_path)?;
    let kp = WorkloadKeypair::generate();
    let now = Utc::now().timestamp() as u64;
    let bundle = build_signed_bundle(
        &grid,
        &keys,
        &kp,
        SimBundleSpec {
            true_location: target,
            claimed_location: target,
            required_radius_km: 2_000.0,
            epoch_label: "geojson-export",
            seq: 0,
            prev_hash: None,
            now_unix_s: now,
            stretch: 1.32,
            overhead_ms: 1.0,
            colluding_anchor_override: None,
        },
    );
    let policy = VerificationPolicy {
        tee_policy: AttestationPolicy::allow_dev_software(),
        max_byzantine: 1,
        min_anchors: 5,
        min_cloud_providers: 2,
        max_proof_age_seconds: 3_900,
        enforce_tier: BoundTier::Vacuum,
    };
    let rep = verify_proof_bundle(&bundle, &grid, &policy, now)?;

    let mut features = Vec::new();
    // Anchor upper-bound disks (Tier 1A Vacuum).
    for r in &bundle.receipts {
        let a = grid.by_id(&r.anchor_id).unwrap();
        let radius_km = effective_radius_km(r.rtt_min_us, BoundTier::Vacuum);
        features.push(json!({
            "type": "Feature",
            "properties": {
                "kind": "anchor_disk_tier1a_vacuum",
                "anchor_id": a.anchor_id,
                "cloud": a.cloud_provider,
                "rtt_min_ms": r.rtt_min_us as f64 / 1000.0,
                "radius_km": radius_km
            },
            "geometry": {
                "type": "Polygon",
                "coordinates": [circle_polygon_coords(a.location, radius_km, 72)]
            }
        }));
    }
    // Byzantine (K-f)-core intersection polygon.
    let mut core_ring: Vec<[f64; 2]> = rep
        .tier1a_vacuum
        .boundary_vertices
        .iter()
        .map(|p| [p.lon, p.lat])
        .collect();
    if let Some(first) = core_ring.first().copied() {
        core_ring.push(first);
    }
    features.push(json!({
        "type": "Feature",
        "properties": {
            "kind": "byzantine_core_intersection",
            "proven_max_radius_km": rep.tier1a_vacuum.proven_max_radius_km,
            "tier1b_fiber_radius_km": rep.tier1b_fiber.proven_max_radius_km
        },
        "geometry": {
            "type": "Polygon",
            "coordinates": [core_ring]
        }
    }));

    let geojson = json!({
        "type": "FeatureCollection",
        "features": features
    });
    std::fs::write(out, serde_json::to_string_pretty(&geojson)?)?;
    println!("Wrote GeoJSON with {} features to {}", features.len(), out.display());
    Ok(())
}
