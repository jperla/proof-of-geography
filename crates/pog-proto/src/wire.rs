use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pog_tee::TeeAttestationQuote;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_MAGIC: [u8; 4] = *b"POG1";
pub const PROTOCOL_VERSION: u8 = 1;
/// Exact symmetric 64-byte UDP packet size for both Challenge and Response (amplification factor = 1.0).
pub const PACKET_SIZE: usize = 64;

pub const MSG_TYPE_CHALLENGE: u8 = 0x01;
pub const MSG_TYPE_RESPONSE: u8 = 0x02;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("invalid packet magic or version")]
    InvalidPacketHeader,
    #[error("packet length mismatch: expected {expected}, got {got}")]
    InvalidPacketLength { expected: usize, got: usize },
    #[error("MAC authentication failed")]
    InvalidMac,
    #[error("signature verification failed: {0}")]
    SignatureError(String),
    #[error("serialization error: {0}")]
    SerializationError(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Phase 1 (Untimed TCP/TLS): Prover introduces its TEE Quote and ephemeral X25519 public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Phase1InitRequest {
    pub prover_quote: TeeAttestationQuote,
    pub epoch_challenge_hex: String,
    pub prover_ephemeral_x25519_hex: String,
    /// Optional public UDP address (ip:port) where Prover will answer Phase 2 UDP challenges.
    pub prover_udp_port: u16,
    pub rounds: u16,
}

/// Phase 1 (Untimed TCP/TLS): Anchor replies with its TEE Quote, ephemeral X25519 key, session ID, and return cookie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Phase1InitResponse {
    pub session_id: u64,
    pub anchor_id: String,
    pub anchor_quote: TeeAttestationQuote,
    pub anchor_ephemeral_x25519_hex: String,
    pub return_cookie_hex: String,
    pub anchor_udp_port: u16,
}

/// Derive a 32-byte symmetric session key `K_PA` inside enclave RAM from X25519 ECDH shared secret.
pub fn derive_session_key(
    shared_secret: &[u8; 32],
    session_id: u64,
    epoch_challenge: &[u8],
    prover_pk_hex: &str,
    anchor_id: &str,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(shared_secret);
    h.update(b"pog-session-key-v1");
    h.update(&session_id.to_le_bytes());
    h.update(epoch_challenge);
    h.update(prover_pk_hex.as_bytes());
    h.update(anchor_id.as_bytes());
    *h.finalize().as_bytes()
}

/// Stateless 8-byte return-routability cookie prefix to block UDP reflection / spoofing.
pub fn compute_return_cookie(anchor_secret: &[u8; 32], session_id: u64, peer_ip: &str) -> [u8; 8] {
    let mut h = blake3::Hasher::new_keyed(anchor_secret);
    h.update(b"pog-cookie-v1");
    h.update(&session_id.to_le_bytes());
    h.update(peer_ip.as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&h.finalize().as_bytes()[0..8]);
    out
}

/// Ultra-fast keyed BLAKE3 MAC (< 1 microsecond on x86_64/arm64) computed inside the Prover TEE
/// during the timed Phase 2 UDP burst.
#[inline]
pub fn compute_challenge_mac(
    session_key: &[u8; 32],
    session_id: u64,
    round: u16,
    nonce: &[u8; 32],
    epoch_challenge: &[u8],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(session_key);
    h.update(&session_id.to_le_bytes());
    h.update(&round.to_le_bytes());
    h.update(nonce);
    h.update(epoch_challenge);
    *h.finalize().as_bytes()
}

/// Fixed 64-byte Phase 2 UDP Challenge sent by Anchor -> Prover public IP.
/// Layout:
///   [0..4]   magic ("POG1")
///   [4]      version (1)
///   [5]      msg_type (0x01)
///   [6..8]   round (u16 LE)
///   [8..16]  session_id (u64 LE)
///   [16..24] anchor_tx_ns (u64 LE, monotonic reference)
///   [24..56] nonce (32 random bytes, freshly generated right before send)
///   [56..64] cookie_prefix (8 bytes)
#[derive(Debug, Clone, Copy)]
pub struct ChallengePacket {
    pub round: u16,
    pub session_id: u64,
    pub anchor_tx_ns: u64,
    pub nonce: [u8; 32],
    pub cookie_prefix: [u8; 8],
}

impl ChallengePacket {
    pub fn encode(&self) -> [u8; PACKET_SIZE] {
        let mut buf = [0u8; PACKET_SIZE];
        buf[0..4].copy_from_slice(&PROTOCOL_MAGIC);
        buf[4] = PROTOCOL_VERSION;
        buf[5] = MSG_TYPE_CHALLENGE;
        buf[6..8].copy_from_slice(&self.round.to_le_bytes());
        buf[8..16].copy_from_slice(&self.session_id.to_le_bytes());
        buf[16..24].copy_from_slice(&self.anchor_tx_ns.to_le_bytes());
        buf[24..56].copy_from_slice(&self.nonce);
        buf[56..64].copy_from_slice(&self.cookie_prefix);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() != PACKET_SIZE {
            return Err(ProtoError::InvalidPacketLength {
                expected: PACKET_SIZE,
                got: buf.len(),
            });
        }
        if buf[0..4] != PROTOCOL_MAGIC || buf[4] != PROTOCOL_VERSION || buf[5] != MSG_TYPE_CHALLENGE
        {
            return Err(ProtoError::InvalidPacketHeader);
        }
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&buf[24..56]);
        let mut cookie_prefix = [0u8; 8];
        cookie_prefix.copy_from_slice(&buf[56..64]);
        Ok(Self {
            round: u16::from_le_bytes(buf[6..8].try_into().unwrap()),
            session_id: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            anchor_tx_ns: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
            nonce,
            cookie_prefix,
        })
    }
}

/// Fixed 64-byte Phase 2 UDP Response sent by Prover TEE -> Anchor.
/// Layout:
///   [0..4]   magic ("POG1")
///   [4]      version (1)
///   [5]      msg_type (0x02)
///   [6..8]   round (u16 LE)
///   [8..16]  session_id (u64 LE)
///   [16..24] prover_proc_ns (u64 LE, informational diagnostic ONLY - never trusted for bounds!)
///   [24..56] mac (32 bytes BLAKE3 keyed MAC)
///   [56..64] nonce_echo (first 8 bytes of challenge nonce)
#[derive(Debug, Clone, Copy)]
pub struct ResponsePacket {
    pub round: u16,
    pub session_id: u64,
    pub prover_proc_ns: u64,
    pub mac: [u8; 32],
    pub nonce_echo: [u8; 8],
}

impl ResponsePacket {
    pub fn encode(&self) -> [u8; PACKET_SIZE] {
        let mut buf = [0u8; PACKET_SIZE];
        buf[0..4].copy_from_slice(&PROTOCOL_MAGIC);
        buf[4] = PROTOCOL_VERSION;
        buf[5] = MSG_TYPE_RESPONSE;
        buf[6..8].copy_from_slice(&self.round.to_le_bytes());
        buf[8..16].copy_from_slice(&self.session_id.to_le_bytes());
        buf[16..24].copy_from_slice(&self.prover_proc_ns.to_le_bytes());
        buf[24..56].copy_from_slice(&self.mac);
        buf[56..64].copy_from_slice(&self.nonce_echo);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() != PACKET_SIZE {
            return Err(ProtoError::InvalidPacketLength {
                expected: PACKET_SIZE,
                got: buf.len(),
            });
        }
        if buf[0..4] != PROTOCOL_MAGIC || buf[4] != PROTOCOL_VERSION || buf[5] != MSG_TYPE_RESPONSE
        {
            return Err(ProtoError::InvalidPacketHeader);
        }
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&buf[24..56]);
        let mut nonce_echo = [0u8; 8];
        nonce_echo.copy_from_slice(&buf[56..64]);
        Ok(Self {
            round: u16::from_le_bytes(buf[6..8].try_into().unwrap()),
            session_id: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            prover_proc_ns: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
            mac,
            nonce_echo,
        })
    }
}

/// Signed RTT measurement receipt issued by an Anchor TEE after verifying all M UDP rounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorReceipt {
    pub anchor_id: String,
    pub cloud_provider: String,
    pub prover_pk_hex: String,
    pub workload_measurement_hex: String,
    pub epoch_challenge_hex: String,
    pub prover_observed_ip: String,
    pub rtt_min_us: u64,
    pub rtt_p50_us: u64,
    pub rtt_samples_us: Vec<u64>,
    pub measured_at_unix_s: u64,
    /// Hex-encoded Ed25519 signature by the Anchor TEE's attested signing key.
    pub anchor_signature_hex: String,
}

impl AnchorReceipt {
    /// Deterministic canonical signing digest of all receipt fields (excluding `anchor_signature_hex`).
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"pog-anchor-receipt-v1");
        h.update(self.anchor_id.as_bytes());
        h.update(b"|");
        h.update(self.cloud_provider.as_bytes());
        h.update(b"|");
        h.update(self.prover_pk_hex.as_bytes());
        h.update(b"|");
        h.update(self.workload_measurement_hex.as_bytes());
        h.update(b"|");
        h.update(self.epoch_challenge_hex.as_bytes());
        h.update(b"|");
        h.update(self.prover_observed_ip.as_bytes());
        h.update(b"|");
        h.update(&self.rtt_min_us.to_le_bytes());
        h.update(&self.rtt_p50_us.to_le_bytes());
        h.update(&(self.rtt_samples_us.len() as u32).to_le_bytes());
        for s in &self.rtt_samples_us {
            h.update(&s.to_le_bytes());
        }
        h.update(&self.measured_at_unix_s.to_le_bytes());
        *h.finalize().as_bytes()
    }

    pub fn sign(&mut self, anchor_key: &SigningKey) {
        let digest = self.signing_digest();
        let sig = anchor_key.sign(&digest);
        self.anchor_signature_hex = hex::encode(sig.to_bytes());
    }

    pub fn verify(&self, anchor_pubkey_hex: &str) -> Result<(), ProtoError> {
        let pk_raw = hex::decode(anchor_pubkey_hex)
            .map_err(|e| ProtoError::SignatureError(format!("bad anchor pk hex: {e}")))?;
        let pk_arr: [u8; 32] = pk_raw
            .try_into()
            .map_err(|_| ProtoError::SignatureError("anchor pk must be 32 bytes".into()))?;
        let vk = VerifyingKey::from_bytes(&pk_arr)
            .map_err(|e| ProtoError::SignatureError(format!("invalid ed25519 pk: {e}")))?;
        let sig_raw = hex::decode(&self.anchor_signature_hex)
            .map_err(|e| ProtoError::SignatureError(format!("bad sig hex: {e}")))?;
        let sig_arr: [u8; 64] = sig_raw
            .try_into()
            .map_err(|_| ProtoError::SignatureError("sig must be 64 bytes".into()))?;
        let sig = Signature::from_bytes(&sig_arr);
        let digest = self.signing_digest();
        vk.verify(&digest, &sig)
            .map_err(|e| ProtoError::SignatureError(format!("anchor receipt sig invalid: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_roundtrip_and_mac() {
        let key = [0x42u8; 32];
        let nonce = [0xABu8; 32];
        let pkt = ChallengePacket {
            round: 3,
            session_id: 999_123,
            anchor_tx_ns: 123_456_789,
            nonce,
            cookie_prefix: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let bytes = pkt.encode();
        assert_eq!(bytes.len(), 64);
        let decoded = ChallengePacket::decode(&bytes).unwrap();
        assert_eq!(decoded.session_id, pkt.session_id);
        assert_eq!(decoded.nonce, pkt.nonce);

        let mac = compute_challenge_mac(&key, pkt.session_id, pkt.round, &pkt.nonce, b"epoch");
        let resp = ResponsePacket {
            round: pkt.round,
            session_id: pkt.session_id,
            prover_proc_ns: 950,
            mac,
            nonce_echo: pkt.nonce[0..8].try_into().unwrap(),
        };
        let rbytes = resp.encode();
        assert_eq!(rbytes.len(), 64);
        let rdec = ResponsePacket::decode(&rbytes).unwrap();
        assert_eq!(rdec.mac, mac);
    }
}
