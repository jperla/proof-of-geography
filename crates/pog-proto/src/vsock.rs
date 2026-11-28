//! Host-to-Enclave AF_VSOCK transport framing for AWS Nitro Enclaves.
//!
//! Architecture & Security Invariant:
//! AWS Nitro Enclaves have ZERO network interfaces (no eth0, no TCP/UDP stack) and communicate
//! with the untrusted parent EC2 host solely over virtio `AF_VSOCK`.
//!
//! To ensure the **measured distance-bounding challenge and Ed25519 `AnchorReceipt` signing
//! occur strictly INSIDE the Nitro Enclave**:
//! 1. The enclave-resident ephemeral Ed25519 signing key (`sk_A`) and X25519 session secret
//!    NEVER leave enclave RAM.
//! 2. The enclave owns the monotonic RTT stopwatch (`Instant::now()`), generates the unpredictable
//!    256-bit Phase 2 challenge nonces inside enclave RAM, emits 64-byte `ChallengePacket`s over
//!    vsock, verifies the Prover's `BLAKE3-MAC` `ResponsePacket`s inside enclave RAM, and signs
//!    the final `AnchorReceipt` inside enclave RAM.
//! 3. The untrusted parent EC2 host runs ONLY a stateless TCP/UDP-to-vsock relay. Because the
//!    parent does NOT know the X25519 session key or the enclave's Ed25519 signing key, it
//!    cannot forge a `ResponsePacket` or shorten a round-trip time — any host delay strictly
//!    increases measured RTT, which ONLY widens the speed-of-light outer bound (fail-safe!).

use crate::wire::{
    compute_challenge_mac, ct_eq_32, ChallengePacket, Phase1Confirm, Phase1InitRequest,
    Phase1InitResponse, ProtoError, ResponsePacket, PACKET_SIZE,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::time::Instant;

/// Maximum framed vsock RPC message size (64 KiB — blocks host-side OOM attempts).
pub const MAX_VSOCK_FRAME_BYTES: usize = 64 * 1024;

/// Default AWS Nitro Enclave parent CID (always 3 on AWS Nitro).
pub const NITRO_PARENT_CID: u32 = 3;
/// Default vsock port on which `pog-anchor --vsock-port` listens inside the Nitro Enclave.
pub const DEFAULT_NITRO_VSOCK_PORT: u32 = 7443;

/// Messages sent from the untrusted parent EC2 relay into the Nitro Enclave over `AF_VSOCK`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[allow(clippy::large_enum_variant)]
pub enum HostToEnclaveMsg {
    /// Request the enclave's cached/fresh NSM-attested `/info` metadata payload.
    GetInfo {
        bootstrap_nonce: String,
        #[serde(default)]
        anchor_id: Option<String>,
    },
    /// Request a fresh uncached hardware attestation bound to a public verifier's random hex nonce,
    /// paired with an Ed25519 proof-of-possession signature by the enclave's live probe key.
    AttestFresh {
        caller_nonce_hex: String,
        #[serde(default)]
        anchor_id: Option<String>,
    },
    /// Forward a Prover's Phase 1 initialization request (observed peer IP recorded by relay).
    Phase1Start {
        peer_ip: String,
        host_udp_port: u16,
        init_req: Phase1InitRequest,
        #[serde(default)]
        anchor_id: Option<String>,
    },
    /// Deliver the Prover's Phase 1 v2 key-confirmation message (`Phase1Confirm`) and requested
    /// round count into the Nitro Enclave after verifying UDP `PUNCH` on the host relay.
    /// The enclave verifies `prover_confirm_mac_hex` inside enclave RAM BEFORE starting Phase 2!
    Phase2Start {
        rounds: u16,
        prover_confirm: Phase1Confirm,
    },
    /// Deliver raw 64-byte UDP `ResponsePacket` received from the Prover back into the enclave.
    Phase2ResponseDatagram {
        round: u16,
        packet_hex: String,
    },
}

/// Messages sent from the Nitro Enclave back to the untrusted parent EC2 relay over `AF_VSOCK`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[allow(clippy::large_enum_variant)]
pub enum EnclaveToHostMsg {
    /// Enclave `/info` payload containing NSM hardware COSE_Sign1 quote and enclave-resident public key.
    InfoResponse {
        payload: serde_json::Value,
    },
    /// Fresh `/attest?nonce=` response containing NSM quote bound to caller nonce + Ed25519 PoP sig.
    AttestResponse {
        payload: serde_json::Value,
    },
    /// Phase 1 response carrying the enclave's NSM quote, X25519 pubkey, and return cookie.
    Phase1Ready {
        init_resp: Phase1InitResponse,
        return_cookie_hex: String,
    },
    /// Enclave-generated 64-byte `ChallengePacket` for the parent relay to transmit immediately over UDP.
    Phase2ChallengeDatagram {
        round: u16,
        packet_hex: String,
    },
    /// Final Ed25519-signed `AnchorReceipt` signed strictly inside the Nitro Enclave.
    Phase2Receipt {
        receipt: crate::wire::AnchorReceipt,
    },
    /// Explicit error response (fail-closed).
    Error {
        message: String,
    },
}

/// Write a 4-byte big-endian length-prefixed JSON frame over any blocking stream (AF_VSOCK or TCP).
pub fn write_vsock_frame<W: Write, T: Serialize>(w: &mut W, msg: &T) -> Result<(), ProtoError> {
    let bytes =
        serde_json::to_vec(msg).map_err(|e| ProtoError::SerializationError(e.to_string()))?;
    if bytes.len() > MAX_VSOCK_FRAME_BYTES {
        return Err(ProtoError::SerializationError(format!(
            "vsock frame too large: {} > {}",
            bytes.len(),
            MAX_VSOCK_FRAME_BYTES
        )));
    }
    let len = (bytes.len() as u32).to_be_bytes();
    w.write_all(&len)?;
    w.write_all(&bytes)?;
    w.flush()?;
    Ok(())
}

/// Read a 4-byte big-endian length-prefixed JSON frame with hard size cap.
pub fn read_vsock_frame<R: Read, T: for<'de> Deserialize<'de>>(r: &mut R) -> Result<T, ProtoError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_VSOCK_FRAME_BYTES {
        return Err(ProtoError::SerializationError(format!(
            "invalid vsock frame length {len}"
        )));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    serde_json::from_slice(&buf).map_err(|e| ProtoError::SerializationError(e.to_string()))
}

/// Execute ONE enclave-measured distance-bounding round over a host-to-enclave vsock stream:
/// 1. Inside the enclave: generate unpredictable 256-bit nonce + encode 64-byte `ChallengePacket`.
/// 2. Start enclave monotonic timer `t0 = Instant::now()`.
/// 3. Send `Phase2ChallengeDatagram` over vsock to parent relay -> relay sends UDP to Prover ->
///    Prover computes `BLAKE3-MAC` and replies -> relay forwards `Phase2ResponseDatagram` over vsock.
/// 4. Capture `t1 = Instant::now()` BEFORE MAC check inside the enclave.
/// 5. Verify `session_id`, `round`, `nonce_echo`, and `BLAKE3-MAC` strictly inside enclave RAM.
/// 6. Return measured RTT rounded UP to whole microseconds (`div_ceil(1_000)`).
pub fn enclave_measure_vsock_round<S: Read + Write>(
    stream: &mut S,
    session_id: u64,
    round: u16,
    session_key: &[u8; 32],
    epoch_challenge: &[u8],
    cookie_prefix: [u8; 8],
) -> Result<u64, ProtoError> {
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let challenge = ChallengePacket {
        round,
        session_id,
        anchor_tx_ns: 0,
        nonce,
        cookie_prefix,
    };
    let wire_bytes = challenge.encode();

    let t0 = Instant::now();
    write_vsock_frame(
        stream,
        &EnclaveToHostMsg::Phase2ChallengeDatagram {
            round,
            packet_hex: hex::encode(wire_bytes),
        },
    )?;

    let incoming: HostToEnclaveMsg = read_vsock_frame(stream)?;
    let rtt_ns = t0.elapsed().as_nanos() as u64;

    let packet_hex = match incoming {
        HostToEnclaveMsg::Phase2ResponseDatagram {
            round: r,
            packet_hex,
        } if r == round => packet_hex,
        _ => return Err(ProtoError::InvalidPacketHeader),
    };
    let raw = hex::decode(&packet_hex).map_err(|_| ProtoError::InvalidPacketHeader)?;
    if raw.len() != PACKET_SIZE {
        return Err(ProtoError::InvalidPacketLength {
            expected: PACKET_SIZE,
            got: raw.len(),
        });
    }
    let resp = ResponsePacket::decode(&raw)?;
    if resp.session_id != session_id || resp.round != round || resp.nonce_echo != nonce[0..8] {
        return Err(ProtoError::InvalidPacketHeader);
    }

    let expected_mac =
        compute_challenge_mac(session_key, session_id, round, &nonce, epoch_challenge);
    if !ct_eq_32(&resp.mac, &expected_mac) {
        return Err(ProtoError::InvalidMac);
    }

    Ok(rtt_ns.div_ceil(1_000).max(1))
}

/// Linux-only AF_VSOCK listener binding `VMADDR_CID_ANY` inside an AWS Nitro Enclave.
#[cfg(target_os = "linux")]
pub fn bind_nitro_vsock_listener(port: u32) -> std::io::Result<vsock::VsockListener> {
    vsock::VsockListener::bind_with_cid_port(vsock::VMADDR_CID_ANY, port)
}

/// Linux-only AF_VSOCK client connecting from the untrusted parent EC2 host to an Enclave CID.
#[cfg(target_os = "linux")]
pub fn connect_nitro_vsock(enclave_cid: u32, port: u32) -> std::io::Result<vsock::VsockStream> {
    vsock::VsockStream::connect_with_cid_port(enclave_cid, port)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::wire::{ChallengePacket, ResponsePacket};
    use std::os::unix::net::UnixStream;
    use std::thread;

    #[test]
    fn test_enclave_vsock_measured_challenge_roundtrip_and_tamper_rejection() {
        let (mut enclave_stream, mut host_stream) = UnixStream::pair().unwrap();
        let session_key = [0x42u8; 32];
        let epoch = b"nitro-vsock-epoch-test";
        let session_id = 999u64;
        let cookie = [0x11u8; 8];

        // Simulated untrusted parent relay forwarding blindly between vsock and prover
        let relay_handle = thread::spawn(move || {
            // Round 0: valid Prover response
            let msg: EnclaveToHostMsg = read_vsock_frame(&mut host_stream).unwrap();
            let EnclaveToHostMsg::Phase2ChallengeDatagram { round, packet_hex } = msg else {
                panic!("expected challenge");
            };
            let ch = ChallengePacket::decode(&hex::decode(packet_hex).unwrap()).unwrap();
            let mac = compute_challenge_mac(&session_key, ch.session_id, ch.round, &ch.nonce, epoch);
            let resp = ResponsePacket {
                round: ch.round,
                session_id: ch.session_id,
                prover_proc_ns: 500,
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

            // Round 1: untrusted parent tries to forge MAC without session_key -> MUST fail!
            let msg2: EnclaveToHostMsg = read_vsock_frame(&mut host_stream).unwrap();
            let EnclaveToHostMsg::Phase2ChallengeDatagram { round: r2, packet_hex: ph2 } = msg2 else {
                panic!("expected challenge 2");
            };
            let ch2 = ChallengePacket::decode(&hex::decode(ph2).unwrap()).unwrap();
            let bad_resp = ResponsePacket {
                round: ch2.round,
                session_id: ch2.session_id,
                prover_proc_ns: 1,
                mac: [0xFFu8; 32],
                nonce_echo: ch2.nonce[0..8].try_into().unwrap(),
            };
            write_vsock_frame(
                &mut host_stream,
                &HostToEnclaveMsg::Phase2ResponseDatagram {
                    round: r2,
                    packet_hex: hex::encode(bad_resp.encode()),
                },
            )
            .unwrap();
        });

        let rtt_us =
            enclave_measure_vsock_round(&mut enclave_stream, session_id, 0, &session_key, epoch, cookie)
                .unwrap();
        assert!((1..100_000).contains(&rtt_us), "unexpected rtt {rtt_us}");

        let forged =
            enclave_measure_vsock_round(&mut enclave_stream, session_id, 1, &session_key, epoch, cookie);
        assert!(
            matches!(forged, Err(ProtoError::InvalidMac)),
            "untrusted parent host forging MAC MUST fail inside enclave: {forged:?}"
        );
        relay_handle.join().unwrap();
    }
}
