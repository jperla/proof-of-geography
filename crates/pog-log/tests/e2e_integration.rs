use chrono::Utc;
use ed25519_dalek::SigningKey;
use pog_geo::{BoundTier, LatLon};
use pog_log::merkle::{verify_inclusion_proof, verify_signed_tree_head};
use pog_log::ContinuousGeoLog;
use pog_proto::{
    accept_phase1_anchor, bind_low_latency_udp, finish_phase1_client, measure_udp_round,
    respond_once_udp, select_committee, start_phase1_client, verify_phase1_confirm,
    verify_proof_bundle, AnchorGrid, AnchorReceipt, CommitteeConfig, GeoProofBundle,
    VerificationPolicy,
};
use pog_tee::{AttestationPolicy, SoftwareDevProvider, TeeProvider, TeeVendor, WorkloadKeypair};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::thread;
use std::time::Duration;

#[test]
fn test_full_e2e_live_udp_header_and_transparency_log() {
    let json = include_str!("../../../config/global_grid_24.json");
    let mut grid = AnchorGrid::from_json_str(json).unwrap();
    let mut keys = HashMap::new();
    for a in &mut grid.anchors {
        let sk = SigningKey::generate(&mut OsRng);
        a.public_key_hex = hex::encode(sk.verifying_key().to_bytes());
        keys.insert(a.anchor_id.clone(), sk);
    }

    let ashburn = LatLon::new(39.0438, -77.4874);
    let prover_kp = WorkloadKeypair::generate();
    let dev_tee = SoftwareDevProvider::new("11223344".repeat(8));
    let epoch = *blake3::hash(b"e2e-integration-epoch").as_bytes();
    let epoch_hex = hex::encode(epoch);
    let now = Utc::now().timestamp() as u64;

    let quote = dev_tee
        .attest(&prover_kp.public_key_bytes(), &epoch, None)
        .unwrap();
    let committee = select_committee(
        &grid,
        &prover_kp.public_key_hex(),
        &epoch,
        ashburn,
        &CommitteeConfig::default(),
    );

    // Run real local authenticated Phase 1 v2 + Phase 2 UDP distance-bounding exchanges for all K=6 committee anchors!
    let mut receipts = Vec::new();
    let dev_policy = AttestationPolicy::allow_dev_software();
    let anchor_tee_dev = SoftwareDevProvider::new("99887766".repeat(8));
    for anchor in &committee.selected {
        let anchor_sock =
            bind_low_latency_udp("127.0.0.1:0".parse().unwrap(), Duration::from_secs(2)).unwrap();
        let prover_sock =
            bind_low_latency_udp("127.0.0.1:0".parse().unwrap(), Duration::from_secs(2)).unwrap();
        let anchor_udp_port = anchor_sock.local_addr().unwrap().port();
        let prover_addr = prover_sock.local_addr().unwrap();

        // Full authenticated Phase 1 v2 handshake (Prover -> Anchor -> Prover -> Anchor confirm)!
        let client_hs = start_phase1_client(
            &prover_kp,
            quote.clone(),
            &epoch,
            &anchor.anchor_id,
            &anchor.public_key_hex,
            TeeVendor::SoftwareDev,
            prover_addr.port(),
            4,
        )
        .unwrap();
        let anchor_hs = accept_phase1_anchor(
            &client_hs.init_req,
            &anchor.anchor_id,
            &keys[&anchor.anchor_id],
            &anchor_tee_dev,
            &dev_policy,
            &[0x42u8; 32],
            "127.0.0.1",
            anchor_udp_port,
            16,
            now,
        )
        .unwrap();
        let completed = finish_phase1_client(client_hs, &anchor_hs.init_resp, &dev_policy, now).unwrap();
        verify_phase1_confirm(&anchor_hs, &completed.confirm).unwrap();

        assert_eq!(completed.keys.phase2_mac_key, anchor_hs.keys.phase2_mac_key);
        let sid = anchor_hs.session_id;
        let session_key = anchor_hs.keys.phase2_mac_key;
        let cookie = anchor_hs.cookie;

        let epoch_copy = epoch;
        let t = thread::spawn(move || {
            for _ in 0..4 {
                respond_once_udp(&prover_sock, sid, &session_key, &epoch_copy).unwrap();
            }
        });

        let mut samples = Vec::new();
        for round in 0..4u16 {
            let live_rtt_us = measure_udp_round(
                &anchor_sock,
                prover_addr,
                sid,
                round,
                &session_key,
                &epoch,
                cookie,
            )
            .unwrap();
            // Add realistic physical geodesic propagation time to the measured live loopback RTT.
            let dist_km = anchor.location.distance_km(ashburn);
            let phys_us = ((2.0 * dist_km * 1.32 / 204_000.0) * 1e6) as u64;
            samples.push(live_rtt_us + phys_us);
        }
        t.join().unwrap();

        samples.sort_unstable();
        let mut receipt = AnchorReceipt {
            anchor_id: anchor.anchor_id.clone(),
            cloud_provider: anchor.cloud_provider.clone(),
            prover_pk_hex: prover_kp.public_key_hex(),
            workload_measurement_hex: quote.workload_measurement_hex.clone(),
            epoch_challenge_hex: epoch_hex.clone(),
            prover_observed_ip: "127.0.0.1".into(),
            rtt_min_us: samples[0],
            rtt_p50_us: samples[samples.len() / 2],
            rtt_samples_us: samples,
            measured_at_unix_s: now,
            anchor_signature_hex: String::new(),
        };
        receipt.sign(&keys[&anchor.anchor_id]);
        receipts.push(receipt);
    }

    let bundle = GeoProofBundle {
        version: 1,
        epoch_challenge_hex: epoch_hex,
        client_nonce_hex: Some("tls-exporter-secret-01".into()),
        target_location: ashburn,
        required_radius_km: 1_500.0,
        prover_quote: quote,
        receipts,
        calibrated_velocity_km_per_s: Some(145_000.0),
        prev_chain_hash_hex: None,
        chain_seq: 0,
        created_at_unix_s: now,
    };

    // Verify compact HTTP / RA-TLS handshake header roundtrip!
    let hdr = bundle.to_header_value().unwrap();
    let decoded = GeoProofBundle::from_header_value(&hdr).unwrap();

    let policy = VerificationPolicy {
        tee_policy: AttestationPolicy::allow_dev_software(),
        max_byzantine: 1,
        min_anchors: 5,
        min_cloud_providers: 2,
        max_proof_age_seconds: 3_600,
        enforce_tier: BoundTier::Vacuum,
        ..Default::default()
    };

    let rep = verify_proof_bundle(&decoded, &grid, &policy, now).unwrap();
    assert!(rep.overall_valid, "Failures: {:?}", rep.failure_reasons);

    // Append to DNS/CT-style transparency log and verify Merkle inclusion + STH!
    let mut log = ContinuousGeoLog::new(grid, policy);
    let append_receipt = log.append_bundle(decoded, now).unwrap();
    assert!(verify_inclusion_proof(&append_receipt.inclusion_proof));
    assert!(verify_signed_tree_head(&append_receipt.sth));
    assert!(append_receipt.movement_report.stationary_confirmed);
}
