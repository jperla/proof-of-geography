use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pog_tee::{
    verify_quote, AttestationPolicy, TeeAttestationQuote, TeeProvider, TeeVendor,
    VerifiedTeeIdentity, WorkloadKeypair,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

pub const PROTOCOL_MAGIC: [u8; 4] = *b"POG1";
pub const PUNCH_MAGIC: [u8; 4] = *b"POGP";
pub const PROTOCOL_VERSION: u8 = 1;
/// Authenticated Phase 1 handshake protocol version (rejects legacy unsigned v1 handshakes).
pub const PHASE1_PROTOCOL_VERSION: u8 = 2;
pub const PHASE1_MIN_ROUNDS: u16 = 1;
pub const PHASE1_MAX_ROUNDS: u16 = 16;
pub const ROLE_PROVER: &str = "prover";
pub const ROLE_ANCHOR: &str = "anchor";

const DOMAIN_PROVER_INIT_V2: &[u8] = b"POG-PHASE1-PROVER-INIT-V2";
const DOMAIN_ANCHOR_QUOTE_NONCE_V2: &[u8] = b"POG-PHASE1-ANCHOR-QUOTE-NONCE-V2";
const DOMAIN_ANCHOR_RESP_V2: &[u8] = b"POG-PHASE1-ANCHOR-RESP-V2";
const DOMAIN_SESSION_KEYS_V2: &[u8] = b"POG-PHASE1-SESSION-KEYS-V2";
const DOMAIN_KEY_PHASE2_MAC_V2: &[u8] = b"POG-KEY-PHASE2-MAC-V2";
const DOMAIN_ANCHOR_CONFIRM_V2: &[u8] = b"POG-PHASE1-ANCHOR-CONFIRM-V2";
const DOMAIN_PROVER_CONFIRM_V2: &[u8] = b"POG-PHASE1-PROVER-CONFIRM-V2";

/// Known small-order Curve25519 u-coordinates (with bit 255 cleared) that produce an all-zero
/// X25519 shared secret regardless of private scalar (RFC 7748 §6.1).
const LOW_ORDER_X25519_POINTS: [[u8; 32]; 7] = [
    [0x00; 32],
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];
/// Exact symmetric 64-byte UDP packet size for both Challenge and Response (amplification factor = 1.0).
pub const PACKET_SIZE: usize = 64;
/// Compact 20-byte UDP NAT-traversal / return-routability punch packet (`POGP` + session_id + 8B cookie).
pub const PUNCH_PACKET_SIZE: usize = 20;

/// Encode a 20-byte UDP NAT-traversal punch packet sent Prover -> Anchor right before Phase 2.
pub fn encode_udp_punch(session_id: u64, cookie: [u8; 8]) -> [u8; PUNCH_PACKET_SIZE] {
    let mut buf = [0u8; PUNCH_PACKET_SIZE];
    buf[0..4].copy_from_slice(&PUNCH_MAGIC);
    buf[4..12].copy_from_slice(&session_id.to_le_bytes());
    buf[12..20].copy_from_slice(&cookie);
    buf
}

/// Decode and validate a 20-byte UDP NAT-traversal punch packet.
pub fn decode_udp_punch(buf: &[u8]) -> Result<(u64, [u8; 8]), ProtoError> {
    if buf.len() != PUNCH_PACKET_SIZE || buf[0..4] != PUNCH_MAGIC {
        return Err(ProtoError::InvalidPacketHeader);
    }
    let sid = u64::from_le_bytes(buf[4..12].try_into().unwrap());
    let mut cookie = [0u8; 8];
    cookie.copy_from_slice(&buf[12..20]);
    Ok((sid, cookie))
}

pub const MSG_TYPE_CHALLENGE: u8 = 0x01;
pub const MSG_TYPE_RESPONSE: u8 = 0x02;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("invalid packet magic or version")]
    InvalidPacketHeader,
    #[error("unsupported Phase 1 handshake protocol version: expected {expected}, got {got} (legacy unsigned v1 handshakes are rejected)")]
    UnsupportedProtocolVersion { expected: u8, got: u8 },
    #[error("Phase 1 handshake authentication failed: {0}")]
    HandshakeAuthFailed(String),
    #[error("rejected low-order or all-zero X25519 Diffie-Hellman key/shared secret")]
    WeakDhSharedSecret,
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

/// Constant-time equality for 32-byte MAC/digest tags (delegates to `blake3::Hash::eq`).
#[inline]
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    blake3::Hash::from(*a) == blake3::Hash::from(*b)
}

/// Canonical fixed-width + u32-LE length-prefixed SHA-256 transcript builder.
/// Eliminates all delimiter/boundary ambiguity across variable-length fields.
struct TranscriptHasher {
    h: Sha256,
}

impl TranscriptHasher {
    fn new(domain: &[u8]) -> Self {
        let mut s = Self { h: Sha256::new() };
        s.write_lp(domain);
        s
    }

    fn write_u8(&mut self, v: u8) {
        self.h.update([v]);
    }

    fn write_u16(&mut self, v: u16) {
        self.h.update(v.to_le_bytes());
    }

    fn write_u64(&mut self, v: u64) {
        self.h.update(v.to_le_bytes());
    }

    fn write_fixed(&mut self, bytes: &[u8]) {
        self.h.update(bytes);
    }

    fn write_lp(&mut self, bytes: &[u8]) {
        self.h.update((bytes.len() as u32).to_le_bytes());
        self.h.update(bytes);
    }

    fn finalize(self) -> [u8; 32] {
        self.h.finalize().into()
    }
}

fn decode_hex_fixed<const N: usize>(field: &str, hex_str: &str) -> Result<[u8; N], ProtoError> {
    let trimmed = hex_str.trim();
    if trimmed.len() != N * 2 {
        return Err(ProtoError::HandshakeAuthFailed(format!(
            "{field} must be exactly {} hex chars ({N} bytes), got {}",
            N * 2,
            trimmed.len()
        )));
    }
    let raw = hex::decode(trimmed)
        .map_err(|e| ProtoError::HandshakeAuthFailed(format!("invalid hex in {field}: {e}")))?;
    raw.try_into()
        .map_err(|_| ProtoError::HandshakeAuthFailed(format!("{field} must be {N} bytes")))
}

fn decode_hex_bounded(
    field: &str,
    hex_str: &str,
    min_bytes: usize,
    max_bytes: usize,
) -> Result<Vec<u8>, ProtoError> {
    let trimmed = hex_str.trim();
    let raw = hex::decode(trimmed)
        .map_err(|e| ProtoError::HandshakeAuthFailed(format!("invalid hex in {field}: {e}")))?;
    if raw.len() < min_bytes || raw.len() > max_bytes {
        return Err(ProtoError::HandshakeAuthFailed(format!(
            "{field} length {} outside [{min_bytes}, {max_bytes}] bytes",
            raw.len()
        )));
    }
    Ok(raw)
}

fn verify_ed25519_sig(
    pubkey_bytes: &[u8; 32],
    message: &[u8],
    sig_hex: &str,
    context: &str,
) -> Result<(), ProtoError> {
    let vk = VerifyingKey::from_bytes(pubkey_bytes)
        .map_err(|e| ProtoError::SignatureError(format!("{context}: invalid Ed25519 pubkey: {e}")))?;
    let sig_arr = decode_hex_fixed::<64>(context, sig_hex)?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(message, &sig)
        .map_err(|e| ProtoError::SignatureError(format!("{context}: Ed25519 signature invalid: {e}")))
}

/// Reject all known low-order / all-zero Curve25519 public keys upfront (RFC 7748 §6.1).
pub fn validate_x25519_public_key_bytes(pk: &[u8; 32]) -> Result<X25519PublicKey, ProtoError> {
    let mut masked = *pk;
    masked[31] &= 0x7f;
    if LOW_ORDER_X25519_POINTS.iter().any(|bad| ct_eq_32(&masked, bad)) {
        return Err(ProtoError::WeakDhSharedSecret);
    }
    Ok(X25519PublicKey::from(*pk))
}

/// Perform X25519 Diffie-Hellman and strictly reject low-order inputs or non-contributory
/// (all-zero) shared secrets per RFC 7748 §6.1.
pub fn compute_checked_x25519_shared_secret(
    local_eph_sk: EphemeralSecret,
    peer_eph_pk_bytes: &[u8; 32],
) -> Result<[u8; 32], ProtoError> {
    let peer_pk = validate_x25519_public_key_bytes(peer_eph_pk_bytes)?;
    let shared = local_eph_sk.diffie_hellman(&peer_pk);
    if !shared.was_contributory() || ct_eq_32(shared.as_bytes(), &[0u8; 32]) {
        return Err(ProtoError::WeakDhSharedSecret);
    }
    Ok(*shared.as_bytes())
}

/// Compute the per-session fresh nonce bound into the Anchor's TEE quote during Phase 1 v2:
/// `SHA-256(lp("POG-PHASE1-ANCHOR-QUOTE-NONCE-V2") || lp(epoch_challenge) || prover_nonce_32)`.
/// Guarantees the Anchor cannot replay an old cached quote across sessions.
pub fn compute_anchor_quote_nonce(epoch_challenge: &[u8], prover_nonce: &[u8; 32]) -> [u8; 32] {
    let mut t = TranscriptHasher::new(DOMAIN_ANCHOR_QUOTE_NONCE_V2);
    t.write_lp(epoch_challenge);
    t.write_fixed(prover_nonce);
    t.finalize()
}

/// Phase 1 v2 (Untimed TCP / Nitro Vsock): Prover introduces its TEE Quote, intended Anchor
/// identity, fresh per-session nonce, ephemeral X25519 public key, and an explicit Ed25519
/// signature by the attested Prover key (`sk_P`) over the canonical init transcript.
///
/// NOTE: All v2 authentication fields are REQUIRED (no `#[serde(default)]`), so legacy unsigned
/// v1 requests fail closed immediately without silent downgrade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Phase1InitRequest {
    pub protocol_version: u8,
    /// Intended Anchor identifier from the Prover's trusted Constellation registry.
    pub target_anchor_id: String,
    /// Intended Anchor's pinned 32-byte Ed25519 public key hex from the Constellation registry.
    pub target_anchor_pk_hex: String,
    /// Fresh 32-byte CSPRNG per-session nonce generated by the Prover.
    pub prover_nonce_hex: String,
    pub prover_quote: TeeAttestationQuote,
    pub epoch_challenge_hex: String,
    pub prover_ephemeral_x25519_hex: String,
    /// Local UDP port where Prover will answer Phase 2 UDP challenges.
    pub prover_udp_port: u16,
    pub rounds: u16,
    /// Ed25519 signature by `prover_quote.public_key_hex` over `prover_init_transcript_hash()`.
    pub prover_init_sig_hex: String,
}

impl Phase1InitRequest {
    /// Canonical fixed-width / length-prefixed SHA-256 transcript digest signed by the Prover's
    /// attested Ed25519 key (`sk_P`).
    pub fn prover_init_transcript_hash(&self) -> Result<[u8; 32], ProtoError> {
        if self.protocol_version != PHASE1_PROTOCOL_VERSION {
            return Err(ProtoError::UnsupportedProtocolVersion {
                expected: PHASE1_PROTOCOL_VERSION,
                got: self.protocol_version,
            });
        }
        if self.target_anchor_id.trim().is_empty() || self.target_anchor_id.len() > 128 {
            return Err(ProtoError::HandshakeAuthFailed(
                "target_anchor_id must be 1..=128 bytes".into(),
            ));
        }
        if self.rounds < PHASE1_MIN_ROUNDS || self.rounds > PHASE1_MAX_ROUNDS {
            return Err(ProtoError::HandshakeAuthFailed(format!(
                "rounds {} outside allowed range {}..={}",
                self.rounds, PHASE1_MIN_ROUNDS, PHASE1_MAX_ROUNDS
            )));
        }

        let prover_pk = decode_hex_fixed::<32>("prover_quote.public_key_hex", &self.prover_quote.public_key_hex)?;
        let prover_meas = decode_hex_bounded("prover_quote.workload_measurement_hex", &self.prover_quote.workload_measurement_hex, 16, 128)?;
        let prover_rd = decode_hex_fixed::<64>("prover_quote.report_data_hex", &self.prover_quote.report_data_hex)?;
        let target_anchor_pk = decode_hex_fixed::<32>("target_anchor_pk_hex", &self.target_anchor_pk_hex)?;
        let epoch_bytes = decode_hex_bounded("epoch_challenge_hex", &self.epoch_challenge_hex, 16, 64)?;
        let prover_nonce = decode_hex_fixed::<32>("prover_nonce_hex", &self.prover_nonce_hex)?;
        let prover_eph = decode_hex_fixed::<32>("prover_ephemeral_x25519_hex", &self.prover_ephemeral_x25519_hex)?;

        let mut t = TranscriptHasher::new(DOMAIN_PROVER_INIT_V2);
        t.write_u8(self.protocol_version);
        t.write_lp(ROLE_PROVER.as_bytes());
        t.write_lp(ROLE_ANCHOR.as_bytes());
        t.write_fixed(&prover_pk);
        t.write_lp(&prover_meas);
        t.write_fixed(&prover_rd);
        t.write_lp(self.target_anchor_id.as_bytes());
        t.write_fixed(&target_anchor_pk);
        t.write_lp(&epoch_bytes);
        t.write_fixed(&prover_nonce);
        t.write_fixed(&prover_eph);
        t.write_u16(self.prover_udp_port);
        t.write_u16(self.rounds);
        Ok(t.finalize())
    }
}

/// Phase 1 v2 (Untimed TCP / Nitro Vsock): Anchor replies with its fresh TEE Quote, fresh
/// per-session nonce, ephemeral X25519 key, session ID, return cookie, UDP port, negotiated
/// rounds, an Ed25519 signature by `sk_A` over the full handshake transcript, and an explicit
/// key-confirmation MAC proving derivation of the shared X25519 session secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Phase1InitResponse {
    pub protocol_version: u8,
    pub session_id: u64,
    pub anchor_id: String,
    pub anchor_nonce_hex: String,
    pub anchor_quote: TeeAttestationQuote,
    pub anchor_ephemeral_x25519_hex: String,
    pub return_cookie_hex: String,
    pub anchor_udp_port: u16,
    pub negotiated_rounds: u16,
    /// Ed25519 signature by Anchor's attested `sk_A` over `anchor_resp_transcript_hash()`.
    pub anchor_resp_sig_hex: String,
    /// Key-confirmation MAC (`anchor_confirm_mac`) bound to the shared secret & full transcript.
    pub anchor_confirm_mac_hex: String,
}

impl Phase1InitResponse {
    /// Canonical fixed-width / length-prefixed SHA-256 transcript digest binding the entire
    /// `Phase1InitRequest` (`prover_init_hash`) together with all Anchor response parameters,
    /// identities, roles, nonces, ephemeral DH keys, session ID, cookie, UDP port, and rounds.
    pub fn anchor_resp_transcript_hash(
        &self,
        prover_init_hash: &[u8; 32],
    ) -> Result<[u8; 32], ProtoError> {
        if self.protocol_version != PHASE1_PROTOCOL_VERSION {
            return Err(ProtoError::UnsupportedProtocolVersion {
                expected: PHASE1_PROTOCOL_VERSION,
                got: self.protocol_version,
            });
        }
        if self.anchor_id.trim().is_empty() || self.anchor_id.len() > 128 {
            return Err(ProtoError::HandshakeAuthFailed(
                "anchor_id must be 1..=128 bytes".into(),
            ));
        }
        if self.negotiated_rounds < PHASE1_MIN_ROUNDS || self.negotiated_rounds > PHASE1_MAX_ROUNDS
        {
            return Err(ProtoError::HandshakeAuthFailed(format!(
                "negotiated_rounds {} outside allowed range {}..={}",
                self.negotiated_rounds, PHASE1_MIN_ROUNDS, PHASE1_MAX_ROUNDS
            )));
        }

        let anchor_pk = decode_hex_fixed::<32>("anchor_quote.public_key_hex", &self.anchor_quote.public_key_hex)?;
        let anchor_meas = decode_hex_bounded("anchor_quote.workload_measurement_hex", &self.anchor_quote.workload_measurement_hex, 16, 128)?;
        let anchor_rd = decode_hex_fixed::<64>("anchor_quote.report_data_hex", &self.anchor_quote.report_data_hex)?;
        let anchor_nonce = decode_hex_fixed::<32>("anchor_nonce_hex", &self.anchor_nonce_hex)?;
        let anchor_eph = decode_hex_fixed::<32>("anchor_ephemeral_x25519_hex", &self.anchor_ephemeral_x25519_hex)?;
        let cookie = decode_hex_fixed::<8>("return_cookie_hex", &self.return_cookie_hex)?;

        let mut t = TranscriptHasher::new(DOMAIN_ANCHOR_RESP_V2);
        t.write_u8(self.protocol_version);
        t.write_lp(ROLE_ANCHOR.as_bytes());
        t.write_lp(ROLE_PROVER.as_bytes());
        t.write_fixed(prover_init_hash);
        t.write_u64(self.session_id);
        t.write_lp(self.anchor_id.as_bytes());
        t.write_fixed(&anchor_pk);
        t.write_lp(&anchor_meas);
        t.write_fixed(&anchor_rd);
        t.write_fixed(&anchor_nonce);
        t.write_fixed(&anchor_eph);
        t.write_fixed(&cookie);
        t.write_u16(self.anchor_udp_port);
        t.write_u16(self.negotiated_rounds);
        Ok(t.finalize())
    }
}

/// Phase 1 v2 Message 3 (Prover -> Anchor, replaces legacy unsigned `"READY\n"`):
/// Explicit key-confirmation message proving the Prover derived the exact same X25519 shared
/// secret and authenticated v2 handshake transcript BEFORE Phase 2 UDP timing starts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Phase1Confirm {
    pub protocol_version: u8,
    pub session_id: u64,
    pub prover_confirm_mac_hex: String,
}

/// Domain-separated symmetric keys derived from the authenticated Phase 1 v2 handshake.
#[derive(Debug, Clone)]
pub struct HandshakeSessionKeys {
    pub handshake_transcript_hash: [u8; 32],
    pub phase2_mac_key: [u8; 32],
    pub anchor_confirm_mac: [u8; 32],
    pub prover_confirm_mac: [u8; 32],
}

/// Derive domain-separated Phase 2 MAC key and mutual Phase 1 key-confirmation MACs from a
/// non-zero X25519 shared secret and the canonical v2 handshake transcript hash (`H_hs`).
pub fn derive_handshake_keys_v2(
    shared_secret: &[u8; 32],
    handshake_transcript_hash: &[u8; 32],
) -> Result<HandshakeSessionKeys, ProtoError> {
    if ct_eq_32(shared_secret, &[0u8; 32]) {
        return Err(ProtoError::WeakDhSharedSecret);
    }
    let mut mk_h = blake3::Hasher::new_keyed(shared_secret);
    mk_h.update(DOMAIN_SESSION_KEYS_V2);
    mk_h.update(handshake_transcript_hash);
    let master_key: [u8; 32] = *mk_h.finalize().as_bytes();

    let mut p2_h = blake3::Hasher::new_keyed(&master_key);
    p2_h.update(DOMAIN_KEY_PHASE2_MAC_V2);
    p2_h.update(handshake_transcript_hash);
    let phase2_mac_key = *p2_h.finalize().as_bytes();

    let mut ac_h = blake3::Hasher::new_keyed(&master_key);
    ac_h.update(DOMAIN_ANCHOR_CONFIRM_V2);
    ac_h.update(handshake_transcript_hash);
    let anchor_confirm_mac = *ac_h.finalize().as_bytes();

    let mut pc_h = blake3::Hasher::new_keyed(&master_key);
    pc_h.update(DOMAIN_PROVER_CONFIRM_V2);
    pc_h.update(handshake_transcript_hash);
    let prover_confirm_mac = *pc_h.finalize().as_bytes();

    Ok(HandshakeSessionKeys {
        handshake_transcript_hash: *handshake_transcript_hash,
        phase2_mac_key,
        anchor_confirm_mac,
        prover_confirm_mac,
    })
}

/// In-RAM Prover handshake state created by [`start_phase1_client`] and consumed by
/// [`finish_phase1_client`] once the Anchor responds.
pub struct Phase1ClientState {
    pub init_req: Phase1InitRequest,
    pub init_transcript_hash: [u8; 32],
    pub prover_nonce: [u8; 32],
    pub epoch_bytes: Vec<u8>,
    pub target_anchor_id: String,
    pub target_anchor_pk_hex: String,
    pub expected_anchor_vendor: TeeVendor,
    prover_eph_sk: EphemeralSecret,
}

/// Verified Prover handshake output ready to send `confirm` and execute Phase 2 UDP rounds.
pub struct Phase1ClientCompleted {
    pub confirm: Phase1Confirm,
    pub session_id: u64,
    pub negotiated_rounds: u16,
    pub cookie: [u8; 8],
    pub anchor_udp_port: u16,
    pub verified_anchor: VerifiedTeeIdentity,
    pub keys: HandshakeSessionKeys,
}

/// Start an authenticated Phase 1 v2 handshake on the Prover side:
/// generates a fresh per-session nonce and ephemeral X25519 keypair, constructs the canonical
/// v2 init transcript, and signs it with the Prover's attested Ed25519 key (`sk_P`).
#[allow(clippy::too_many_arguments)]
pub fn start_phase1_client(
    prover_keypair: &WorkloadKeypair,
    prover_quote: TeeAttestationQuote,
    epoch_bytes: &[u8],
    target_anchor_id: &str,
    target_anchor_pk_hex: &str,
    expected_anchor_vendor: TeeVendor,
    prover_udp_port: u16,
    rounds: u16,
) -> Result<Phase1ClientState, ProtoError> {
    if epoch_bytes.len() < 16 || epoch_bytes.len() > 64 {
        return Err(ProtoError::HandshakeAuthFailed(format!(
            "epoch_bytes length {} outside [16, 64]",
            epoch_bytes.len()
        )));
    }
    let own_pk_hex = prover_keypair.public_key_hex();
    if !prover_quote.public_key_hex.eq_ignore_ascii_case(&own_pk_hex) {
        return Err(ProtoError::HandshakeAuthFailed(
            "prover_quote.public_key_hex does not match prover_keypair".into(),
        ));
    }
    let _ = decode_hex_fixed::<32>("target_anchor_pk_hex", target_anchor_pk_hex)?;

    let mut prover_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut prover_nonce);
    let prover_eph_sk = EphemeralSecret::random_from_rng(OsRng);
    let prover_eph_pk = X25519PublicKey::from(&prover_eph_sk);

    let mut init_req = Phase1InitRequest {
        protocol_version: PHASE1_PROTOCOL_VERSION,
        target_anchor_id: target_anchor_id.to_string(),
        target_anchor_pk_hex: target_anchor_pk_hex.to_ascii_lowercase(),
        prover_nonce_hex: hex::encode(prover_nonce),
        prover_quote,
        epoch_challenge_hex: hex::encode(epoch_bytes),
        prover_ephemeral_x25519_hex: hex::encode(prover_eph_pk.as_bytes()),
        prover_udp_port,
        rounds,
        prover_init_sig_hex: String::new(),
    };
    let init_hash = init_req.prover_init_transcript_hash()?;
    init_req.prover_init_sig_hex = hex::encode(prover_keypair.sign(&init_hash));

    Ok(Phase1ClientState {
        init_req,
        init_transcript_hash: init_hash,
        prover_nonce,
        epoch_bytes: epoch_bytes.to_vec(),
        target_anchor_id: target_anchor_id.to_string(),
        target_anchor_pk_hex: target_anchor_pk_hex.to_ascii_lowercase(),
        expected_anchor_vendor,
        prover_eph_sk,
    })
}

/// Complete Phase 1 v2 authentication on the Prover side after receiving `Phase1InitResponse`:
/// 1. Enforces `protocol_version == 2`, exact `anchor_id`, and valid `negotiated_rounds`.
/// 2. Verifies Anchor's fresh TEE quote against `compute_anchor_quote_nonce(epoch, prover_nonce)`
///    and pins `anchor_quote.vendor` + `anchor_quote.public_key_hex` to the expected registry entry.
/// 3. Verifies Anchor's Ed25519 transcript signature over `anchor_resp_transcript_hash`.
/// 4. Computes checked X25519 ECDH (rejecting low-order / all-zero shared secrets).
/// 5. Verifies `anchor_confirm_mac` in constant time and produces `Phase1Confirm`.
pub fn finish_phase1_client(
    state: Phase1ClientState,
    init_resp: &Phase1InitResponse,
    anchor_tee_policy: &AttestationPolicy,
    now_unix_s: u64,
) -> Result<Phase1ClientCompleted, ProtoError> {
    if init_resp.protocol_version != PHASE1_PROTOCOL_VERSION {
        return Err(ProtoError::UnsupportedProtocolVersion {
            expected: PHASE1_PROTOCOL_VERSION,
            got: init_resp.protocol_version,
        });
    }
    if init_resp.anchor_id != state.target_anchor_id {
        return Err(ProtoError::HandshakeAuthFailed(format!(
            "anchor_id mismatch: expected '{}', got '{}'",
            state.target_anchor_id, init_resp.anchor_id
        )));
    }
    if init_resp.negotiated_rounds < PHASE1_MIN_ROUNDS
        || init_resp.negotiated_rounds > state.init_req.rounds
    {
        return Err(ProtoError::HandshakeAuthFailed(format!(
            "invalid negotiated_rounds {} (requested {})",
            init_resp.negotiated_rounds, state.init_req.rounds
        )));
    }

    let expected_quote_nonce =
        compute_anchor_quote_nonce(&state.epoch_bytes, &state.prover_nonce);
    let verified_anchor = verify_quote(
        &init_resp.anchor_quote,
        &expected_quote_nonce,
        anchor_tee_policy,
        now_unix_s,
    )
    .map_err(|e| ProtoError::HandshakeAuthFailed(format!("anchor TEE quote invalid: {e}")))?;

    if verified_anchor.vendor != state.expected_anchor_vendor {
        return Err(ProtoError::HandshakeAuthFailed(format!(
            "anchor TEE vendor mismatch: expected {}, got {}",
            state.expected_anchor_vendor.as_str(),
            verified_anchor.vendor.as_str()
        )));
    }
    if !verified_anchor
        .public_key_hex
        .eq_ignore_ascii_case(&state.target_anchor_pk_hex)
    {
        return Err(ProtoError::HandshakeAuthFailed(format!(
            "anchor attested public key {} does not match pinned registry key {}",
            verified_anchor.public_key_hex, state.target_anchor_pk_hex
        )));
    }

    let hs_hash = init_resp.anchor_resp_transcript_hash(&state.init_transcript_hash)?;
    let anchor_pk_arr = decode_hex_fixed::<32>("target_anchor_pk_hex", &state.target_anchor_pk_hex)?;
    verify_ed25519_sig(
        &anchor_pk_arr,
        &hs_hash,
        &init_resp.anchor_resp_sig_hex,
        "anchor_resp_sig_hex",
    )?;

    let anchor_eph_arr =
        decode_hex_fixed::<32>("anchor_ephemeral_x25519_hex", &init_resp.anchor_ephemeral_x25519_hex)?;
    let shared = compute_checked_x25519_shared_secret(state.prover_eph_sk, &anchor_eph_arr)?;
    let keys = derive_handshake_keys_v2(&shared, &hs_hash)?;

    let resp_confirm_arr =
        decode_hex_fixed::<32>("anchor_confirm_mac_hex", &init_resp.anchor_confirm_mac_hex)?;
    if !ct_eq_32(&resp_confirm_arr, &keys.anchor_confirm_mac) {
        return Err(ProtoError::InvalidMac);
    }

    let cookie = decode_hex_fixed::<8>("return_cookie_hex", &init_resp.return_cookie_hex)?;
    let confirm = Phase1Confirm {
        protocol_version: PHASE1_PROTOCOL_VERSION,
        session_id: init_resp.session_id,
        prover_confirm_mac_hex: hex::encode(keys.prover_confirm_mac),
    };

    Ok(Phase1ClientCompleted {
        confirm,
        session_id: init_resp.session_id,
        negotiated_rounds: init_resp.negotiated_rounds,
        cookie,
        anchor_udp_port: init_resp.anchor_udp_port,
        verified_anchor,
        keys,
    })
}

/// In-RAM Anchor handshake state created by [`accept_phase1_anchor`] and verified against the
/// Prover's [`Phase1Confirm`] via [`verify_phase1_confirm`] before Phase 2 UDP timing starts.
pub struct Phase1AnchorState {
    pub init_resp: Phase1InitResponse,
    pub session_id: u64,
    pub negotiated_rounds: u16,
    pub cookie: [u8; 8],
    pub epoch_bytes: Vec<u8>,
    pub epoch_challenge_hex: String,
    pub verified_prover: VerifiedTeeIdentity,
    pub keys: HandshakeSessionKeys,
}

/// Validate an incoming `Phase1InitRequest` on the Anchor side (shared by direct TCP and AWS
/// Nitro Enclave vsock handlers!):
/// 1. Enforces `protocol_version == 2` and bounded sizes/rounds (rejects legacy v1!).
/// 2. Enforces `target_anchor_id == own_anchor_id` and `target_anchor_pk == own_anchor_pk`.
/// 3. Verifies `prover_quote` under `prover_tee_policy` and `epoch_challenge`.
/// 4. Verifies explicit Ed25519 PoP signature `prover_init_sig_hex` over `prover_init_transcript_hash`
///    under `verified_prover.public_key_hex` (prevents pairing a stolen quote with attacker DH!).
/// 5. Computes checked X25519 ECDH (rejecting low-order / all-zero shared secrets).
/// 6. Attests fresh `anchor_quote` over `compute_anchor_quote_nonce(epoch, prover_nonce)`, signs
///    the full v2 response transcript with `anchor_signing_key`, and emits `anchor_confirm_mac`.
#[allow(clippy::too_many_arguments)]
pub fn accept_phase1_anchor(
    init_req: &Phase1InitRequest,
    own_anchor_id: &str,
    anchor_signing_key: &SigningKey,
    anchor_tee_provider: &dyn TeeProvider,
    prover_tee_policy: &AttestationPolicy,
    cookie_secret: &[u8; 32],
    peer_ip: &str,
    anchor_udp_port: u16,
    max_rounds: u16,
    now_unix_s: u64,
) -> Result<Phase1AnchorState, ProtoError> {
    if init_req.protocol_version != PHASE1_PROTOCOL_VERSION {
        return Err(ProtoError::UnsupportedProtocolVersion {
            expected: PHASE1_PROTOCOL_VERSION,
            got: init_req.protocol_version,
        });
    }
    if init_req.epoch_challenge_hex.len() > 128
        || init_req.prover_quote.raw_quote_b64.len() > 24_000
    {
        return Err(ProtoError::HandshakeAuthFailed(
            "request fields exceed maximum allowed size".into(),
        ));
    }
    let effective_max_rounds = max_rounds.clamp(PHASE1_MIN_ROUNDS, PHASE1_MAX_ROUNDS);
    if init_req.rounds < PHASE1_MIN_ROUNDS || init_req.rounds > effective_max_rounds {
        return Err(ProtoError::HandshakeAuthFailed(format!(
            "requested rounds {} outside allowed 1..={effective_max_rounds}",
            init_req.rounds
        )));
    }

    let own_pk_bytes = anchor_signing_key.verifying_key().to_bytes();
    let own_pk_hex = hex::encode(own_pk_bytes);
    if init_req.target_anchor_id != own_anchor_id {
        return Err(ProtoError::HandshakeAuthFailed(format!(
            "target_anchor_id '{}' does not match this anchor '{}'",
            init_req.target_anchor_id, own_anchor_id
        )));
    }
    let target_pk_arr = decode_hex_fixed::<32>("target_anchor_pk_hex", &init_req.target_anchor_pk_hex)?;
    if !ct_eq_32(&target_pk_arr, &own_pk_bytes) {
        return Err(ProtoError::HandshakeAuthFailed(format!(
            "target_anchor_pk_hex does not match this anchor's attested key ({own_pk_hex})"
        )));
    }

    let epoch_bytes = decode_hex_bounded("epoch_challenge_hex", &init_req.epoch_challenge_hex, 16, 64)?;
    let prover_nonce = decode_hex_fixed::<32>("prover_nonce_hex", &init_req.prover_nonce_hex)?;
    let verified_prover =
        verify_quote(&init_req.prover_quote, &epoch_bytes, prover_tee_policy, now_unix_s).map_err(
            |e| ProtoError::HandshakeAuthFailed(format!("prover TEE quote invalid: {e}")),
        )?;

    // Explicit Proof-of-Possession & DH binding: verify sk_P signature over canonical init transcript!
    let prover_init_hash = init_req.prover_init_transcript_hash()?;
    let prover_pk_arr =
        decode_hex_fixed::<32>("verified_prover.public_key_hex", &verified_prover.public_key_hex)?;
    verify_ed25519_sig(
        &prover_pk_arr,
        &prover_init_hash,
        &init_req.prover_init_sig_hex,
        "prover_init_sig_hex",
    )?;

    // Checked X25519 ECDH (rejects all low-order / all-zero public keys and shared secrets).
    let prover_eph_arr = decode_hex_fixed::<32>(
        "prover_ephemeral_x25519_hex",
        &init_req.prover_ephemeral_x25519_hex,
    )?;
    let anchor_eph_sk = EphemeralSecret::random_from_rng(OsRng);
    let anchor_eph_pk = X25519PublicKey::from(&anchor_eph_sk);
    let shared = compute_checked_x25519_shared_secret(anchor_eph_sk, &prover_eph_arr)?;

    let session_id = OsRng.next_u64();
    let mut anchor_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut anchor_nonce);
    let cookie = compute_return_cookie(cookie_secret, session_id, peer_ip);
    let negotiated_rounds = init_req.rounds;

    let anchor_quote_nonce = compute_anchor_quote_nonce(&epoch_bytes, &prover_nonce);
    let anchor_quote = anchor_tee_provider
        .attest(&own_pk_bytes, &anchor_quote_nonce, None)
        .map_err(|e| ProtoError::HandshakeAuthFailed(format!("anchor TEE attest failed: {e}")))?;

    let mut init_resp = Phase1InitResponse {
        protocol_version: PHASE1_PROTOCOL_VERSION,
        session_id,
        anchor_id: own_anchor_id.to_string(),
        anchor_nonce_hex: hex::encode(anchor_nonce),
        anchor_quote,
        anchor_ephemeral_x25519_hex: hex::encode(anchor_eph_pk.as_bytes()),
        return_cookie_hex: hex::encode(cookie),
        anchor_udp_port,
        negotiated_rounds,
        anchor_resp_sig_hex: String::new(),
        anchor_confirm_mac_hex: String::new(),
    };

    let hs_hash = init_resp.anchor_resp_transcript_hash(&prover_init_hash)?;
    let keys = derive_handshake_keys_v2(&shared, &hs_hash)?;
    init_resp.anchor_resp_sig_hex = hex::encode(anchor_signing_key.sign(&hs_hash).to_bytes());
    init_resp.anchor_confirm_mac_hex = hex::encode(keys.anchor_confirm_mac);

    Ok(Phase1AnchorState {
        init_resp,
        session_id,
        negotiated_rounds,
        cookie,
        epoch_bytes,
        epoch_challenge_hex: hex::encode(&decode_hex_bounded(
            "epoch_challenge_hex",
            &init_req.epoch_challenge_hex,
            16,
            64,
        )?),
        verified_prover,
        keys,
    })
}

/// Build the fail-closed `AttestationPolicy` a Prover client uses to verify an Anchor's fresh
/// Phase 1 v2 `anchor_quote`:
/// - Hardware TEE Anchors (`AwsNitro`, `AmdSevSnp`, `IntelTdx`) ALWAYS enforce
///   `AttestationPolicy::production()` (full vendor trust root + pinned GCP CS JWKS), even when
///   a local developer Prover passed `--allow-dev-tee`!
/// - Only `TeeVendor::SoftwareDev` Anchors with `allow_dev_anchors == true` allow software dev quotes.
pub fn anchor_handshake_attestation_policy(
    expected_anchor_vendor: TeeVendor,
    allow_dev_anchors: bool,
) -> AttestationPolicy {
    let mut pol = if expected_anchor_vendor == TeeVendor::SoftwareDev && allow_dev_anchors {
        AttestationPolicy::allow_dev_software()
    } else {
        AttestationPolicy::production()
    };
    pol.trusted_gcp_cs_jwks_json = Some(pog_tee::PINNED_OFFICIAL_GCP_CS_JWKS_JSON.to_string());
    pol
}

/// Verify the Prover's explicit key-confirmation message (`Phase1Confirm`) strictly BEFORE
/// starting Phase 2 timed UDP challenges.
pub fn verify_phase1_confirm(
    state: &Phase1AnchorState,
    confirm: &Phase1Confirm,
) -> Result<(), ProtoError> {
    if confirm.protocol_version != PHASE1_PROTOCOL_VERSION {
        return Err(ProtoError::UnsupportedProtocolVersion {
            expected: PHASE1_PROTOCOL_VERSION,
            got: confirm.protocol_version,
        });
    }
    if confirm.session_id != state.session_id {
        return Err(ProtoError::HandshakeAuthFailed(format!(
            "confirm session_id mismatch: expected {}, got {}",
            state.session_id, confirm.session_id
        )));
    }
    let got_mac = decode_hex_fixed::<32>("prover_confirm_mac_hex", &confirm.prover_confirm_mac_hex)?;
    if !ct_eq_32(&got_mac, &state.keys.prover_confirm_mac) {
        return Err(ProtoError::InvalidMac);
    }
    Ok(())
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
    /// Deterministic canonical SHA-256 signing digest of all receipt fields (excluding `anchor_signature_hex`).
    /// Uses SHA-256 so every client SDK (TypeScript/Browser, Python, Go, Rust) verifies receipts
    /// using standard built-in cryptography with zero third-party hash dependencies!
    pub fn signing_digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
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
        h.update(self.rtt_min_us.to_le_bytes());
        h.update(self.rtt_p50_us.to_le_bytes());
        h.update((self.rtt_samples_us.len() as u32).to_le_bytes());
        for s in &self.rtt_samples_us {
            h.update(s.to_le_bytes());
        }
        h.update(self.measured_at_unix_s.to_le_bytes());
        h.finalize().into()
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

    #[test]
    fn test_phase1_v2_valid_mutual_auth_and_key_confirmation() {
        use pog_tee::SoftwareDevProvider;
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let prover_kp = WorkloadKeypair::generate();
        let anchor_sk = SigningKey::generate(&mut OsRng);
        let anchor_pk_hex = hex::encode(anchor_sk.verifying_key().to_bytes());
        let epoch = [0x44u8; 32];
        let prover_tee = SoftwareDevProvider::new("aa".repeat(32));
        let anchor_tee = SoftwareDevProvider::new("bb".repeat(32));
        let dev_pol = AttestationPolicy::allow_dev_software();

        let prover_quote = prover_tee
            .attest(&prover_kp.public_key_bytes(), &epoch, None)
            .unwrap();

        let client_hs = start_phase1_client(
            &prover_kp,
            prover_quote,
            &epoch,
            "aws-eu-central-1-frankfurt",
            &anchor_pk_hex,
            TeeVendor::SoftwareDev,
            55123,
            8,
        )
        .unwrap();

        let anchor_hs = accept_phase1_anchor(
            &client_hs.init_req,
            "aws-eu-central-1-frankfurt",
            &anchor_sk,
            &anchor_tee,
            &dev_pol,
            &[0x77u8; 32],
            "198.51.100.10",
            40100,
            16,
            now,
        )
        .unwrap();

        let completed =
            finish_phase1_client(client_hs, &anchor_hs.init_resp, &dev_pol, now).unwrap();
        assert_eq!(completed.session_id, anchor_hs.session_id);
        assert_eq!(completed.negotiated_rounds, 8);
        assert_eq!(completed.keys.phase2_mac_key, anchor_hs.keys.phase2_mac_key);
        assert_eq!(
            completed.keys.handshake_transcript_hash,
            anchor_hs.keys.handshake_transcript_hash
        );
        verify_phase1_confirm(&anchor_hs, &completed.confirm).unwrap();

        // Hardware TEE anchors ALWAYS require production AttestationPolicy even if allow_dev_anchors=true!
        let hw_pol = anchor_handshake_attestation_policy(TeeVendor::AwsNitro, true);
        assert!(!hw_pol.allow_software_dev);
        assert!(hw_pol.require_cryptographic_vendor_chain);
    }

    #[test]
    fn test_phase1_v2_adversarial_key_substitution_stolen_quote_and_tampering() {
        use pog_tee::SoftwareDevProvider;
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let victim_kp = WorkloadKeypair::generate();
        let attacker_kp = WorkloadKeypair::generate();
        let anchor_sk = SigningKey::generate(&mut OsRng);
        let anchor_pk_hex = hex::encode(anchor_sk.verifying_key().to_bytes());
        let epoch = [0x55u8; 32];
        let prover_tee = SoftwareDevProvider::new("aa".repeat(32));
        let anchor_tee = SoftwareDevProvider::new("bb".repeat(32));
        let dev_pol = AttestationPolicy::allow_dev_software();

        let victim_quote = prover_tee
            .attest(&victim_kp.public_key_bytes(), &epoch, None)
            .unwrap();

        let valid_client = start_phase1_client(
            &victim_kp,
            victim_quote.clone(),
            &epoch,
            "gcp-us-east4-ashburn",
            &anchor_pk_hex,
            TeeVendor::SoftwareDev,
            51000,
            6,
        )
        .unwrap();

        // 1. CORE CODEX ATTACK: Fresh valid remote victim quote paired with attacker's local X25519 key
        //    and signed by attacker's Ed25519 key (attacker lacks victim sk_P!) -> MUST REJECT!
        let attacker_eph_sk = EphemeralSecret::random_from_rng(OsRng);
        let attacker_eph_pk = X25519PublicKey::from(&attacker_eph_sk);
        let mut stolen_req = valid_client.init_req.clone();
        stolen_req.prover_ephemeral_x25519_hex = hex::encode(attacker_eph_pk.as_bytes());
        let stolen_hash = stolen_req.prover_init_transcript_hash().unwrap();
        stolen_req.prover_init_sig_hex = hex::encode(attacker_kp.sign(&stolen_hash));
        assert!(matches!(
            accept_phase1_anchor(
                &stolen_req,
                "gcp-us-east4-ashburn",
                &anchor_sk,
                &anchor_tee,
                &dev_pol,
                &[0x11u8; 32],
                "198.51.100.20",
                40101,
                16,
                now,
            ),
            Err(ProtoError::SignatureError(_))
        ));

        // 2. Altered prover DH key while keeping victim's original signature -> MUST REJECT!
        let mut altered_prover_dh = valid_client.init_req.clone();
        altered_prover_dh.prover_ephemeral_x25519_hex = hex::encode(attacker_eph_pk.as_bytes());
        assert!(matches!(
            accept_phase1_anchor(
                &altered_prover_dh,
                "gcp-us-east4-ashburn",
                &anchor_sk,
                &anchor_tee,
                &dev_pol,
                &[0x11u8; 32],
                "198.51.100.20",
                40101,
                16,
                now,
            ),
            Err(ProtoError::SignatureError(_))
        ));

        // 3. Altered rounds / udp_port / prover_nonce -> MUST REJECT!
        for mutate in [
            |r: &mut Phase1InitRequest| r.rounds = 12,
            |r: &mut Phase1InitRequest| r.prover_udp_port = 60000,
            |r: &mut Phase1InitRequest| r.prover_nonce_hex = "cc".repeat(32),
        ] {
            let mut m = valid_client.init_req.clone();
            mutate(&mut m);
            assert!(accept_phase1_anchor(
                &m,
                "gcp-us-east4-ashburn",
                &anchor_sk,
                &anchor_tee,
                &dev_pol,
                &[0x11u8; 32],
                "198.51.100.20",
                40101,
                16,
                now,
            )
            .is_err());
        }

        // Now establish a valid Anchor response and tamper with Anchor-side fields!
        let anchor_hs = accept_phase1_anchor(
            &valid_client.init_req,
            "gcp-us-east4-ashburn",
            &anchor_sk,
            &anchor_tee,
            &dev_pol,
            &[0x11u8; 32],
            "198.51.100.20",
            40101,
            16,
            now,
        )
        .unwrap();

        // 4. Altered anchor DH key (MITM swapping anchor_ephemeral_x25519_hex) -> MUST REJECT!
        let mitm_client = start_phase1_client(
            &victim_kp,
            victim_quote.clone(),
            &epoch,
            "gcp-us-east4-ashburn",
            &anchor_pk_hex,
            TeeVendor::SoftwareDev,
            51000,
            6,
        )
        .unwrap();
        let mitm_anchor_hs = accept_phase1_anchor(
            &mitm_client.init_req,
            "gcp-us-east4-ashburn",
            &anchor_sk,
            &anchor_tee,
            &dev_pol,
            &[0x11u8; 32],
            "198.51.100.20",
            40101,
            16,
            now,
        )
        .unwrap();
        let mut tampered_resp = mitm_anchor_hs.init_resp.clone();
        tampered_resp.anchor_ephemeral_x25519_hex = hex::encode(attacker_eph_pk.as_bytes());
        assert!(matches!(
            finish_phase1_client(mitm_client, &tampered_resp, &dev_pol, now),
            Err(ProtoError::SignatureError(_))
        ));

        // 5. Altered anchor_confirm_mac_hex (even with valid Ed25519 sig!) -> MUST REJECT (InvalidMac)!
        let mut bad_mac_resp = anchor_hs.init_resp.clone();
        bad_mac_resp.anchor_confirm_mac_hex = "ff".repeat(32);
        assert!(matches!(
            finish_phase1_client(valid_client, &bad_mac_resp, &dev_pol, now),
            Err(ProtoError::InvalidMac)
        ));

        // 6. Wrong session_id or forged prover_confirm_mac_hex in Phase1Confirm -> MUST REJECT!
        let bad_confirm_sid = Phase1Confirm {
            protocol_version: PHASE1_PROTOCOL_VERSION,
            session_id: anchor_hs.session_id.wrapping_add(1),
            prover_confirm_mac_hex: hex::encode(anchor_hs.keys.prover_confirm_mac),
        };
        assert!(verify_phase1_confirm(&anchor_hs, &bad_confirm_sid).is_err());

        let bad_confirm_mac = Phase1Confirm {
            protocol_version: PHASE1_PROTOCOL_VERSION,
            session_id: anchor_hs.session_id,
            prover_confirm_mac_hex: "00".repeat(32),
        };
        assert!(matches!(
            verify_phase1_confirm(&anchor_hs, &bad_confirm_mac),
            Err(ProtoError::InvalidMac)
        ));
    }

    #[test]
    fn test_phase1_v2_wrong_anchor_epoch_session_role_and_vendor_downgrade() {
        use pog_tee::SoftwareDevProvider;
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let prover_kp = WorkloadKeypair::generate();
        let anchor_a_sk = SigningKey::generate(&mut OsRng);
        let anchor_b_sk = SigningKey::generate(&mut OsRng);
        let anchor_a_pk = hex::encode(anchor_a_sk.verifying_key().to_bytes());
        let epoch = [0x66u8; 32];
        let prover_tee = SoftwareDevProvider::new("aa".repeat(32));
        let anchor_tee = SoftwareDevProvider::new("bb".repeat(32));
        let dev_pol = AttestationPolicy::allow_dev_software();

        let prover_quote = prover_tee
            .attest(&prover_kp.public_key_bytes(), &epoch, None)
            .unwrap();

        let c1 = start_phase1_client(
            &prover_kp,
            prover_quote.clone(),
            &epoch,
            "anchor-a",
            &anchor_a_pk,
            TeeVendor::SoftwareDev,
            52000,
            4,
        )
        .unwrap();

        // 1. Cross-anchor relay: valid request for anchor-a replayed to anchor-b (wrong anchor_id) -> REJECT!
        assert!(accept_phase1_anchor(
            &c1.init_req,
            "anchor-b",
            &anchor_a_sk,
            &anchor_tee,
            &dev_pol,
            &[0x22u8; 32],
            "198.51.100.30",
            40102,
            16,
            now,
        )
        .is_err());

        // 2. Wrong anchor key (same anchor_id, different anchor_sk) -> REJECT!
        assert!(accept_phase1_anchor(
            &c1.init_req,
            "anchor-a",
            &anchor_b_sk,
            &anchor_tee,
            &dev_pol,
            &[0x22u8; 32],
            "198.51.100.30",
            40102,
            16,
            now,
        )
        .is_err());

        // 3. Mismatched epoch_challenge_hex (even re-signed by prover_kp, fails quote nonce binding!) -> REJECT!
        let mut wrong_epoch = c1.init_req.clone();
        wrong_epoch.epoch_challenge_hex = hex::encode([0x77u8; 32]);
        let h_we = wrong_epoch.prover_init_transcript_hash().unwrap();
        wrong_epoch.prover_init_sig_hex = hex::encode(prover_kp.sign(&h_we));
        assert!(accept_phase1_anchor(
            &wrong_epoch,
            "anchor-a",
            &anchor_a_sk,
            &anchor_tee,
            &dev_pol,
            &[0x22u8; 32],
            "198.51.100.30",
            40102,
            16,
            now,
        )
        .is_err());

        // 4. Cross-session replay: Anchor response from session 1 fed to session 2 client -> REJECT!
        let a_hs1 = accept_phase1_anchor(
            &c1.init_req,
            "anchor-a",
            &anchor_a_sk,
            &anchor_tee,
            &dev_pol,
            &[0x22u8; 32],
            "198.51.100.30",
            40102,
            16,
            now,
        )
        .unwrap();
        let c2 = start_phase1_client(
            &prover_kp,
            prover_quote.clone(),
            &epoch,
            "anchor-a",
            &anchor_a_pk,
            TeeVendor::SoftwareDev,
            52000,
            4,
        )
        .unwrap();
        assert!(
            finish_phase1_client(c2, &a_hs1.init_resp, &dev_pol, now).is_err(),
            "cross-session Anchor response replay MUST fail quote nonce & transcript binding"
        );

        // 5. Cross-role / reflection attack: signing transcript with swapped roles ("anchor","prover") -> REJECT!
        let mut swapped_role_req = c1.init_req.clone();
        let mut t = TranscriptHasher::new(DOMAIN_PROVER_INIT_V2);
        t.write_u8(PHASE1_PROTOCOL_VERSION);
        t.write_lp(ROLE_ANCHOR.as_bytes()); // SWAPPED ROLE!
        t.write_lp(ROLE_PROVER.as_bytes());
        t.write_fixed(&prover_kp.public_key_bytes());
        let bad_role_hash = t.finalize();
        swapped_role_req.prover_init_sig_hex = hex::encode(prover_kp.sign(&bad_role_hash));
        assert!(matches!(
            accept_phase1_anchor(
                &swapped_role_req,
                "anchor-a",
                &anchor_a_sk,
                &anchor_tee,
                &dev_pol,
                &[0x22u8; 32],
                "198.51.100.30",
                40102,
                16,
                now,
            ),
            Err(ProtoError::SignatureError(_))
        ));

        // 6. Vendor downgrade: client expects AwsNitro anchor, gets SoftwareDev anchor -> REJECT!
        let c_hw = start_phase1_client(
            &prover_kp,
            prover_quote,
            &epoch,
            "anchor-a",
            &anchor_a_pk,
            TeeVendor::AwsNitro,
            52000,
            4,
        )
        .unwrap();
        let a_hs_hw = accept_phase1_anchor(
            &c_hw.init_req,
            "anchor-a",
            &anchor_a_sk,
            &anchor_tee,
            &dev_pol,
            &[0x22u8; 32],
            "198.51.100.30",
            40102,
            16,
            now,
        )
        .unwrap();
        assert!(
            finish_phase1_client(c_hw, &a_hs_hw.init_resp, &dev_pol, now).is_err(),
            "SoftwareDev quote MUST fail when registry expects AwsNitro"
        );
    }

    #[test]
    fn test_phase1_v2_rejects_legacy_unsigned_v1_and_low_order_all_zero_dh() {
        use pog_tee::SoftwareDevProvider;
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let prover_kp = WorkloadKeypair::generate();
        let anchor_sk = SigningKey::generate(&mut OsRng);
        let anchor_pk_hex = hex::encode(anchor_sk.verifying_key().to_bytes());
        let epoch = [0x88u8; 32];
        let prover_tee = SoftwareDevProvider::new("aa".repeat(32));
        let anchor_tee = SoftwareDevProvider::new("bb".repeat(32));
        let dev_pol = AttestationPolicy::allow_dev_software();

        let prover_quote = prover_tee
            .attest(&prover_kp.public_key_bytes(), &epoch, None)
            .unwrap();

        // 1. Legacy unsigned v1 JSON (missing protocol_version, nonces, target_anchor, signature) MUST fail decode!
        let legacy_v1_json = serde_json::json!({
            "prover_quote": prover_quote,
            "epoch_challenge_hex": hex::encode(epoch),
            "prover_ephemeral_x25519_hex": "11".repeat(32),
            "prover_udp_port": 55000,
            "rounds": 4
        })
        .to_string();
        assert!(
            serde_json::from_str::<Phase1InitRequest>(&legacy_v1_json).is_err(),
            "legacy unsigned v1 Phase1InitRequest MUST fail deserialization"
        );

        // 2. Explicit protocol_version=1 MUST fail closed with UnsupportedProtocolVersion!
        let c_base = start_phase1_client(
            &prover_kp,
            prover_quote.clone(),
            &epoch,
            "anchor-v2",
            &anchor_pk_hex,
            TeeVendor::SoftwareDev,
            55000,
            4,
        )
        .unwrap();
        let mut downgrade_req = c_base.init_req.clone();
        downgrade_req.protocol_version = 1;
        assert!(matches!(
            accept_phase1_anchor(
                &downgrade_req,
                "anchor-v2",
                &anchor_sk,
                &anchor_tee,
                &dev_pol,
                &[0x33u8; 32],
                "198.51.100.40",
                40103,
                16,
                now,
            ),
            Err(ProtoError::UnsupportedProtocolVersion { expected: 2, got: 1 })
        ));

        // 3. Direct KDF rejects all-zero shared secret!
        assert!(matches!(
            derive_handshake_keys_v2(&[0u8; 32], &[0xABu8; 32]),
            Err(ProtoError::WeakDhSharedSecret)
        ));

        // 4. All 7 small-order Curve25519 points + bit-255-set variant MUST be rejected even when
        //    legitimately signed by the Prover's attested Ed25519 key!
        let mut bad_points: Vec<[u8; 32]> = LOW_ORDER_X25519_POINTS.to_vec();
        let mut zero_hi_bit = [0u8; 32];
        zero_hi_bit[31] = 0x80;
        bad_points.push(zero_hi_bit);

        for bad_pt in bad_points {
            assert!(matches!(
                validate_x25519_public_key_bytes(&bad_pt),
                Err(ProtoError::WeakDhSharedSecret)
            ));
            let sk = EphemeralSecret::random_from_rng(OsRng);
            assert!(matches!(
                compute_checked_x25519_shared_secret(sk, &bad_pt),
                Err(ProtoError::WeakDhSharedSecret)
            ));

            let mut low_order_req = c_base.init_req.clone();
            low_order_req.prover_ephemeral_x25519_hex = hex::encode(bad_pt);
            let h = low_order_req.prover_init_transcript_hash().unwrap();
            low_order_req.prover_init_sig_hex = hex::encode(prover_kp.sign(&h));
            assert!(
                matches!(
                    accept_phase1_anchor(
                        &low_order_req,
                        "anchor-v2",
                        &anchor_sk,
                        &anchor_tee,
                        &dev_pol,
                        &[0x33u8; 32],
                        "198.51.100.40",
                        40103,
                        16,
                        now,
                    ),
                    Err(ProtoError::WeakDhSharedSecret)
                ),
                "low-order prover DH point {} MUST be rejected",
                hex::encode(bad_pt)
            );
        }

        // 5. Low-order Anchor DH key (even legitimately signed by anchor_sk!) MUST be rejected by client!
        let c_low_a = start_phase1_client(
            &prover_kp,
            prover_quote,
            &epoch,
            "anchor-v2",
            &anchor_pk_hex,
            TeeVendor::SoftwareDev,
            55000,
            4,
        )
        .unwrap();
        let a_hs = accept_phase1_anchor(
            &c_low_a.init_req,
            "anchor-v2",
            &anchor_sk,
            &anchor_tee,
            &dev_pol,
            &[0x33u8; 32],
            "198.51.100.40",
            40103,
            16,
            now,
        )
        .unwrap();
        let mut low_a_resp = a_hs.init_resp.clone();
        low_a_resp.anchor_ephemeral_x25519_hex = "00".repeat(32);
        let hs_hash = low_a_resp
            .anchor_resp_transcript_hash(&c_low_a.init_transcript_hash)
            .unwrap();
        low_a_resp.anchor_resp_sig_hex = hex::encode(anchor_sk.sign(&hs_hash).to_bytes());
        assert!(matches!(
            finish_phase1_client(c_low_a, &low_a_resp, &dev_pol, now),
            Err(ProtoError::WeakDhSharedSecret)
        ));
    }
}
