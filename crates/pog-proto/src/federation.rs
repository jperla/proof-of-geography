use crate::bundle::{
    verify_proof_bundle, GeoProofBundle, ProofVerificationReport, VerificationPolicy,
};
use crate::committee::{AnchorDescriptor, AnchorGrid};
use crate::wire::ProtoError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pog_tee::{verify_quote, AttestationPolicy, TeeAttestationQuote, TeeVendor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};

/// Cryptographically signed Anchor network registry published by an independent operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedNetworkRegistry {
    pub version: u8,
    pub network_id: String,
    pub operator_name: String,
    pub root_public_key_hex: String,
    pub issued_at_unix_s: u64,
    pub expires_at_unix_s: u64,
    pub grid: AnchorGrid,
    pub operator_signature_hex: String,
}

impl SignedNetworkRegistry {
    /// Deterministic, cross-language canonical SHA-256 signing digest.
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"POG-NETWORK-REGISTRY-V1\n");
        h.update(self.network_id.as_bytes());
        h.update(b"\n");
        h.update(self.operator_name.as_bytes());
        h.update(b"\n");
        h.update(self.root_public_key_hex.as_bytes());
        h.update(b"\n");
        h.update(self.issued_at_unix_s.to_string().as_bytes());
        h.update(b"\n");
        h.update(self.expires_at_unix_s.to_string().as_bytes());
        h.update(b"\n");
        h.update(self.grid.grid_name.as_bytes());
        h.update(b"\n");

        let mut anchors = self.grid.anchors.clone();
        anchors.sort_by(|a, b| a.anchor_id.cmp(&b.anchor_id));
        for a in &anchors {
            let line = format!(
                "{}|{}|{}|{:.6}|{:.6}|{}|{}\n",
                a.anchor_id,
                a.cloud_provider,
                a.region,
                a.location.lat,
                a.location.lon,
                a.endpoint_tcp,
                a.public_key_hex
            );
            h.update(line.as_bytes());
        }
        h.finalize().into()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_new(
        network_id: impl Into<String>,
        operator_name: impl Into<String>,
        grid: AnchorGrid,
        issued_at_unix_s: u64,
        ttl_seconds: u64,
        root_key: &SigningKey,
    ) -> Self {
        let root_public_key_hex = hex::encode(root_key.verifying_key().to_bytes());
        let mut reg = Self {
            version: 1,
            network_id: network_id.into(),
            operator_name: operator_name.into(),
            root_public_key_hex,
            issued_at_unix_s,
            expires_at_unix_s: issued_at_unix_s.saturating_add(ttl_seconds),
            grid,
            operator_signature_hex: String::new(),
        };
        let digest = reg.signing_digest();
        let sig = root_key.sign(&digest);
        reg.operator_signature_hex = hex::encode(sig.to_bytes());
        reg
    }

    /// Fail-closed check: reject any production registry containing `SoftwareDev` anchors.
    pub fn validate_production_membership(&self) -> Result<(), ProtoError> {
        let dev_anchors: Vec<&str> = self
            .grid
            .anchors
            .iter()
            .filter(|a| !a.is_production_hardware_tee())
            .map(|a| a.anchor_id.as_str())
            .collect();
        if !dev_anchors.is_empty() {
            return Err(ProtoError::SignatureError(format!(
                "Production registry `{}` contains {} SoftwareDev anchors (forbidden): {}",
                self.network_id,
                dev_anchors.len(),
                dev_anchors.join(", ")
            )));
        }
        Ok(())
    }

    /// Fail-closed production registry hygiene: rejects empty grids, `SoftwareDev` members,
    /// duplicate IDs or keys, placeholder repeated-byte keys (e.g. `0101...`), and
    /// simulated/example/loopback endpoints (e.g. `*.pog.example`, `localhost`, `127.0.0.1`).
    pub fn validate_production_hygiene(&self) -> Result<(), ProtoError> {
        if self.grid.anchors.is_empty() {
            return Err(ProtoError::SignatureError(format!(
                "Production registry `{}` contains 0 anchors",
                self.network_id
            )));
        }
        self.validate_production_membership()?;

        let mut seen_ids = HashSet::new();
        let mut seen_pks = HashSet::new();
        for a in &self.grid.anchors {
            if !seen_ids.insert(a.anchor_id.clone()) {
                return Err(ProtoError::SignatureError(format!(
                    "Duplicate anchor_id `{}` in registry `{}`",
                    a.anchor_id, self.network_id
                )));
            }
            let pk_bytes = hex::decode(&a.public_key_hex).map_err(|e| {
                ProtoError::SignatureError(format!(
                    "Anchor `{}` has invalid public_key_hex: {e}",
                    a.anchor_id
                ))
            })?;
            if pk_bytes.len() != 32 {
                return Err(ProtoError::SignatureError(format!(
                    "Anchor `{}` public_key_hex must be 32 bytes (got {})",
                    a.anchor_id,
                    pk_bytes.len()
                )));
            }
            if pk_bytes.iter().all(|&b| b == pk_bytes[0]) {
                return Err(ProtoError::SignatureError(format!(
                    "Anchor `{}` uses a placeholder repeated-byte public_key_hex (`{:02x}`×32)",
                    a.anchor_id, pk_bytes[0]
                )));
            }
            if !seen_pks.insert(a.public_key_hex.to_ascii_lowercase()) {
                return Err(ProtoError::SignatureError(format!(
                    "Duplicate public_key_hex shared across multiple anchors (including `{}`)",
                    a.anchor_id
                )));
            }
            let is_placeholder_host = |ep: &str| -> bool {
                let lower = ep.trim().to_ascii_lowercase();
                let host = lower
                    .strip_prefix("https://")
                    .or_else(|| lower.strip_prefix("http://"))
                    .unwrap_or(&lower)
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .split(':')
                    .next()
                    .unwrap_or("");
                host.is_empty()
                    || host.ends_with(".example")
                    || host.ends_with(".example.com")
                    || host.ends_with(".example.org")
                    || host == "example.com"
                    || host == "example.org"
                    || host == "localhost"
                    || host == "127.0.0.1"
                    || host == "0.0.0.0"
            };
            if is_placeholder_host(&a.endpoint_tcp) || is_placeholder_host(&a.endpoint_udp) {
                return Err(ProtoError::SignatureError(format!(
                    "Anchor `{}` has placeholder/non-production endpoint `{}` / `{}`",
                    a.anchor_id, a.endpoint_tcp, a.endpoint_udp
                )));
            }
            if let Some(ref url) = a.https_url {
                if !url.starts_with("https://") || is_placeholder_host(url) {
                    return Err(ProtoError::SignatureError(format!(
                        "Anchor `{}` has invalid or placeholder https_url `{}`",
                        a.anchor_id, url
                    )));
                }
            }
        }
        Ok(())
    }

    /// Verify the operator's Ed25519 root signature and optional pinned root public key & expiry.
    pub fn verify(
        &self,
        expected_root_pk_hex: Option<&str>,
        now_unix_s: u64,
    ) -> Result<(), ProtoError> {
        if let Some(expected) = expected_root_pk_hex {
            if !self.root_public_key_hex.eq_ignore_ascii_case(expected) {
                return Err(ProtoError::SignatureError(format!(
                    "Network {} root_public_key_hex does not match pinned operator key",
                    self.network_id
                )));
            }
        }
        if now_unix_s > self.expires_at_unix_s {
            return Err(ProtoError::SignatureError(format!(
                "Network {} signed registry expired at {}",
                self.network_id, self.expires_at_unix_s
            )));
        }
        let pk_raw = hex::decode(&self.root_public_key_hex)
            .map_err(|e| ProtoError::SignatureError(format!("bad root pk hex: {e}")))?;
        let pk_arr: [u8; 32] = pk_raw
            .try_into()
            .map_err(|_| ProtoError::SignatureError("root pk must be 32 bytes".into()))?;
        let vk = VerifyingKey::from_bytes(&pk_arr)
            .map_err(|e| ProtoError::SignatureError(e.to_string()))?;

        let sig_raw = hex::decode(&self.operator_signature_hex)
            .map_err(|e| ProtoError::SignatureError(format!("bad sig hex: {e}")))?;
        let sig_arr: [u8; 64] = sig_raw
            .try_into()
            .map_err(|_| ProtoError::SignatureError("sig must be 64 bytes".into()))?;
        let sig = Signature::from_bytes(&sig_arr);
        let digest = self.signing_digest();
        vk.verify(&digest, &sig)
            .map_err(|e| ProtoError::SignatureError(format!("operator signature invalid: {e}")))
    }
}

/// Per-Anchor cryptographic endorsement certificate signed by the network operator's local root key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorEndorsement {
    pub network_id: String,
    pub anchor_id: String,
    pub anchor_public_key_hex: String,
    pub lat: f64,
    pub lon: f64,
    pub issued_at_unix_s: u64,
    pub expires_at_unix_s: u64,
    pub root_public_key_hex: String,
    pub root_signature_hex: String,
}

impl AnchorEndorsement {
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        let msg = format!(
            "POG-ANCHOR-ENDORSEMENT-V1\n{}\n{}\n{}\n{:.6}\n{:.6}\n{}\n{}\n",
            self.network_id,
            self.anchor_id,
            self.anchor_public_key_hex,
            self.lat,
            self.lon,
            self.issued_at_unix_s,
            self.expires_at_unix_s
        );
        h.update(msg.as_bytes());
        h.finalize().into()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_new(
        network_id: impl Into<String>,
        anchor_id: impl Into<String>,
        anchor_public_key_hex: impl Into<String>,
        lat: f64,
        lon: f64,
        issued_at_unix_s: u64,
        ttl_seconds: u64,
        root_key: &SigningKey,
    ) -> Self {
        let mut cert = Self {
            network_id: network_id.into(),
            anchor_id: anchor_id.into(),
            anchor_public_key_hex: anchor_public_key_hex.into(),
            lat,
            lon,
            issued_at_unix_s,
            expires_at_unix_s: issued_at_unix_s.saturating_add(ttl_seconds),
            root_public_key_hex: hex::encode(root_key.verifying_key().to_bytes()),
            root_signature_hex: String::new(),
        };
        let sig = root_key.sign(&cert.signing_digest());
        cert.root_signature_hex = hex::encode(sig.to_bytes());
        cert
    }

    pub fn verify(&self, expected_root_pk_hex: &str, now_unix_s: u64) -> Result<(), ProtoError> {
        if !self.root_public_key_hex.eq_ignore_ascii_case(expected_root_pk_hex) {
            return Err(ProtoError::SignatureError("endorsement root pk mismatch".into()));
        }
        if now_unix_s > self.expires_at_unix_s {
            return Err(ProtoError::SignatureError("anchor endorsement expired".into()));
        }
        let pk_arr: [u8; 32] = hex::decode(&self.root_public_key_hex)
            .map_err(|e| ProtoError::SignatureError(e.to_string()))?
            .try_into()
            .map_err(|_| ProtoError::SignatureError("bad root pk length".into()))?;
        let sig_arr: [u8; 64] = hex::decode(&self.root_signature_hex)
            .map_err(|e| ProtoError::SignatureError(e.to_string()))?
            .try_into()
            .map_err(|_| ProtoError::SignatureError("bad sig length".into()))?;
        let vk = VerifyingKey::from_bytes(&pk_arr)
            .map_err(|e| ProtoError::SignatureError(e.to_string()))?;
        vk.verify(&self.signing_digest(), &Signature::from_bytes(&sig_arr))
            .map_err(|e| ProtoError::SignatureError(format!("endorsement sig invalid: {e}")))
    }
}

/// Live `/info` JSON payload returned by an Anchor node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorLiveInfo {
    pub anchor_id: String,
    pub cloud_provider: String,
    pub tee_vendor: TeeVendor,
    pub public_key_hex: String,
    pub bootstrap_nonce: String,
    pub tee_quote: Option<TeeAttestationQuote>,
    pub operator_endorsement: Option<AnchorEndorsement>,
    #[serde(default)]
    pub endorsement_status: Option<String>,
    #[serde(default)]
    pub hardened: bool,
}

/// Strict live-anchor identity & hardware-TEE audit result (reports every dimension separately).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorIdentityAuditResult {
    pub anchor_id: String,
    pub configured: bool,
    pub reachable: bool,
    pub hardware_tee_attested: bool,
    pub key_matches_published_registry: bool,
    pub endorsement_matches_live_key: bool,
    pub endorsement_signature_valid: bool,
    pub proof_eligible: bool,
    pub failure_reasons: Vec<String>,
}

/// Strictly verify a live Anchor's `/info` response against its published registry entry,
/// pinned operator root key, and `AttestationPolicy`.
///
/// Rejects:
/// - `anchor_id` mismatch
/// - live `public_key_hex` != published registry `public_key_hex`
/// - stale/old endorsement from a previous boot (`endorsement.anchor_public_key_hex != info.public_key_hex`)
/// - expired or invalidly signed endorsement
/// - `SoftwareDev` or unverified TEE quote under production policy
/// - `tee_quote.public_key_hex != info.public_key_hex` (enclave key custody mismatch!)
pub fn verify_anchor_info_identity(
    info: &AnchorLiveInfo,
    published: &AnchorDescriptor,
    pinned_root_pk_hex: &str,
    tee_policy: &AttestationPolicy,
    now_unix_s: u64,
) -> AnchorIdentityAuditResult {
    let mut failures = Vec::new();

    if info.anchor_id != published.anchor_id {
        failures.push(format!(
            "anchor_id mismatch: live={} != published={}",
            info.anchor_id, published.anchor_id
        ));
    }

    let key_matches_published = info
        .public_key_hex
        .eq_ignore_ascii_case(&published.public_key_hex);
    if !key_matches_published {
        failures.push(format!(
            "live signing key {} does not match published registry key {} (node restarted without re-enrollment or key tampered)",
            &info.public_key_hex[..info.public_key_hex.len().min(16)],
            &published.public_key_hex[..published.public_key_hex.len().min(16)]
        ));
    }

    let mut endorsement_matches_live = false;
    let mut endorsement_sig_valid = false;
    match &info.operator_endorsement {
        None => {
            failures.push("missing operator_endorsement on live /info".into());
        }
        Some(cert) => {
            if cert.anchor_id != published.anchor_id {
                failures.push(format!(
                    "endorsement anchor_id {} != {}",
                    cert.anchor_id, published.anchor_id
                ));
            }
            endorsement_matches_live = cert
                .anchor_public_key_hex
                .eq_ignore_ascii_case(&info.public_key_hex);
            if !endorsement_matches_live {
                failures.push(
                    "stale/mismatched endorsement: endorsement.anchor_public_key_hex != live public_key_hex (old endorsement rejected on restart/rotation)"
                        .into(),
                );
            }
            match cert.verify(pinned_root_pk_hex, now_unix_s) {
                Ok(()) => endorsement_sig_valid = true,
                Err(e) => failures.push(format!("endorsement verification failed: {e}")),
            }
        }
    }

    let mut hardware_tee_attested = false;
    if !info.tee_vendor.is_production_hardware_tee() && !tee_policy.allow_software_dev {
        failures.push(format!(
            "live anchor reports {} (hardware TEE required in production)",
            info.tee_vendor.as_str()
        ));
    }
    match &info.tee_quote {
        None => {
            failures.push("live /info missing tee_quote".into());
        }
        Some(quote) => {
            if quote.vendor != info.tee_vendor {
                failures.push("tee_quote.vendor != info.tee_vendor".into());
            }
            if !quote.public_key_hex.eq_ignore_ascii_case(&info.public_key_hex) {
                failures.push(
                    "enclave-generated tee_quote.public_key_hex != live signing public_key_hex"
                        .into(),
                );
            }
            match verify_quote(quote, info.bootstrap_nonce.as_bytes(), tee_policy, now_unix_s) {
                Ok(verified) => {
                    hardware_tee_attested = verified.hardware_attested;
                    if !verified.hardware_attested && !tee_policy.allow_software_dev {
                        failures.push("TEE quote did not pass hardware vendor-chain attestation".into());
                    }
                }
                Err(e) => {
                    failures.push(format!("live TEE quote verification failed: {e}"));
                }
            }
        }
    }

    let proof_eligible = failures.is_empty()
        && key_matches_published
        && endorsement_matches_live
        && endorsement_sig_valid
        && (hardware_tee_attested || tee_policy.allow_software_dev);

    AnchorIdentityAuditResult {
        anchor_id: published.anchor_id.clone(),
        configured: true,
        reachable: true,
        hardware_tee_attested,
        key_matches_published_registry: key_matches_published,
        endorsement_matches_live_key: endorsement_matches_live,
        endorsement_signature_valid: endorsement_sig_valid,
        proof_eligible,
        failure_reasons: failures,
    }
}

/// Live `/attest?nonce=<64-hex>` response returned by an Anchor node proving fresh caller-nonce
/// hardware attestation + Ed25519 Proof-of-Possession + live-key-bound operator endorsement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorFreshAttestResponse {
    pub anchor_id: String,
    pub cloud_provider: String,
    pub tee_vendor: TeeVendor,
    #[serde(default)]
    pub fresh_caller_nonce: bool,
    pub caller_nonce_hex: String,
    pub public_key_hex: String,
    pub proof_of_possession_sig_hex: String,
    pub tee_quote: Option<TeeAttestationQuote>,
    pub operator_endorsement: Option<AnchorEndorsement>,
    #[serde(default)]
    pub endorsement_status: Option<String>,
    #[serde(default)]
    pub hardened: bool,
}

/// Authoritative fail-closed verification result for a fresh `/attest?nonce=...` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorFreshAttestAuditResult {
    pub anchor_id: String,
    pub tee_vendor: TeeVendor,
    pub public_key_hex: String,
    pub workload_measurement_hex: Option<String>,
    pub fresh_caller_nonce_verified: bool,
    pub proof_of_possession_verified: bool,
    pub hardware_tee_attested: bool,
    pub key_matches_published_registry: bool,
    pub endorsement_matches_live_key: bool,
    pub endorsement_signature_valid: bool,
    pub endorsement_coords_match_registry: bool,
    pub proof_eligible: bool,
    pub failure_reasons: Vec<String>,
}

/// Canonical Ed25519 Proof-of-Possession signing payload matching `pog-anchor` `/attest?nonce=`.
pub fn attest_pop_signing_message(
    anchor_id: &str,
    caller_nonce_hex: &str,
    workload_measurement_hex: &str,
) -> Vec<u8> {
    format!(
        "POG-ATTEST-POP-V1\n{}\n{}\n{}\n",
        anchor_id,
        caller_nonce_hex.to_ascii_lowercase(),
        workload_measurement_hex
    )
    .into_bytes()
}

/// Strictly verify a live Anchor's fresh `/attest?nonce=<64-hex>` response against:
/// 1. The published `AnchorDescriptor` in the operator-signed registry,
/// 2. The pinned operator root Ed25519 public key (`pinned_root_pk_hex`),
/// 3. The caller's fresh random 32-byte nonce (`expected_caller_nonce_hex`),
/// 4. The Ed25519 Proof-of-Possession signature binding the ephemeral enclave key to the nonce & measurement,
/// 5. Full hardware TEE vendor verification (`pog_tee::verify_quote` with pinned AWS/AMD/Intel Root CAs & measurement allowlist).
pub fn verify_anchor_fresh_attestation(
    resp: &AnchorFreshAttestResponse,
    published: &AnchorDescriptor,
    pinned_root_pk_hex: &str,
    expected_caller_nonce_hex: &str,
    tee_policy: &AttestationPolicy,
    now_unix_s: u64,
) -> AnchorFreshAttestAuditResult {
    let mut failures = Vec::new();
    let expected_nonce_norm = expected_caller_nonce_hex.trim().to_ascii_lowercase();
    let expected_nonce_bytes = match hex::decode(&expected_nonce_norm) {
        Ok(b) if b.len() >= 16 => b,
        _ => {
            failures.push("expected_caller_nonce_hex must be valid hex of at least 16 bytes".into());
            Vec::new()
        }
    };

    if resp.anchor_id != published.anchor_id {
        failures.push(format!(
            "anchor_id mismatch: live={} != published={}",
            resp.anchor_id, published.anchor_id
        ));
    }

    let fresh_nonce_matched = resp.fresh_caller_nonce
        && !expected_nonce_bytes.is_empty()
        && resp.caller_nonce_hex.eq_ignore_ascii_case(&expected_nonce_norm);
    if !fresh_nonce_matched {
        failures.push(format!(
            "fresh caller nonce mismatch (fresh_caller_nonce={}, live={}, expected={})",
            resp.fresh_caller_nonce, resp.caller_nonce_hex, expected_nonce_norm
        ));
    }

    let key_matches_published = resp
        .public_key_hex
        .eq_ignore_ascii_case(&published.public_key_hex);
    if !key_matches_published {
        failures.push(format!(
            "live signing key {} does not match signed registry key {}",
            &resp.public_key_hex[..resp.public_key_hex.len().min(16)],
            &published.public_key_hex[..published.public_key_hex.len().min(16)]
        ));
    }

    if resp.tee_vendor != published.tee_vendor {
        failures.push(format!(
            "live tee_vendor {:?} does not match signed registry tee_vendor {:?}",
            resp.tee_vendor, published.tee_vendor
        ));
    }

    let mut endorsement_matches_live = false;
    let mut endorsement_sig_valid = false;
    let mut endorsement_coords_match = false;
    match &resp.operator_endorsement {
        None => failures.push("missing operator_endorsement on /attest response".into()),
        Some(cert) => {
            if cert.anchor_id != published.anchor_id {
                failures.push(format!(
                    "endorsement anchor_id {} != {}",
                    cert.anchor_id, published.anchor_id
                ));
            }
            endorsement_matches_live = cert
                .anchor_public_key_hex
                .eq_ignore_ascii_case(&resp.public_key_hex);
            if !endorsement_matches_live {
                failures.push(
                    "stale/mismatched endorsement: endorsement.anchor_public_key_hex != live public_key_hex"
                        .into(),
                );
            }
            endorsement_coords_match = (cert.lat - published.location.lat).abs() <= 0.001
                && (cert.lon - published.location.lon).abs() <= 0.001;
            if !endorsement_coords_match {
                failures.push(format!(
                    "endorsement coordinates ({:.5},{:.5}) drift from registry ({:.5},{:.5})",
                    cert.lat, cert.lon, published.location.lat, published.location.lon
                ));
            }
            match cert.verify(pinned_root_pk_hex, now_unix_s) {
                Ok(()) => endorsement_sig_valid = true,
                Err(e) => failures.push(format!("endorsement signature verification failed: {e}")),
            }
        }
    }

    let mut hardware_tee_attested = false;
    let mut pop_verified = false;
    let mut workload_measurement_hex = None;

    if !resp.tee_vendor.is_production_hardware_tee() && !tee_policy.allow_software_dev {
        failures.push(format!(
            "live anchor reports {} (hardware TEE required in production)",
            resp.tee_vendor.as_str()
        ));
    }

    match &resp.tee_quote {
        None => failures.push("missing tee_quote on /attest response".into()),
        Some(quote) => {
            workload_measurement_hex = Some(quote.workload_measurement_hex.clone());
            if quote.vendor != resp.tee_vendor {
                failures.push("tee_quote.vendor != resp.tee_vendor".into());
            }
            if !quote.public_key_hex.eq_ignore_ascii_case(&resp.public_key_hex) {
                failures.push("enclave-generated tee_quote.public_key_hex != live public_key_hex".into());
            }

            // Verify Ed25519 Proof-of-Possession binding live key -> (anchor_id, caller_nonce, measurement)
            let pop_msg = attest_pop_signing_message(
                &resp.anchor_id,
                &expected_nonce_norm,
                &quote.workload_measurement_hex,
            );
            let pk_res = hex::decode(&resp.public_key_hex)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .and_then(|arr| VerifyingKey::from_bytes(&arr).ok());
            let sig_res = hex::decode(&resp.proof_of_possession_sig_hex)
                .ok()
                .and_then(|b| <[u8; 64]>::try_from(b).ok())
                .map(|arr| Signature::from_bytes(&arr));
            match (pk_res, sig_res) {
                (Some(vk), Some(sig)) if vk.verify(&pop_msg, &sig).is_ok() => {
                    pop_verified = true;
                }
                _ => failures.push("Ed25519 Proof-of-Possession signature verification failed".into()),
            }

            if !expected_nonce_bytes.is_empty() {
                match verify_quote(quote, &expected_nonce_bytes, tee_policy, now_unix_s) {
                    Ok(verified) => {
                        hardware_tee_attested = verified.hardware_attested;
                        if !verified.hardware_attested && !tee_policy.allow_software_dev {
                            failures.push("TEE quote did not pass hardware vendor-chain attestation".into());
                        }
                    }
                    Err(e) => failures.push(format!("fresh TEE quote verification failed: {e}")),
                }
            }
        }
    }

    let proof_eligible = failures.is_empty()
        && fresh_nonce_matched
        && pop_verified
        && key_matches_published
        && endorsement_matches_live
        && endorsement_sig_valid
        && endorsement_coords_match
        && (hardware_tee_attested || tee_policy.allow_software_dev);

    AnchorFreshAttestAuditResult {
        anchor_id: published.anchor_id.clone(),
        tee_vendor: resp.tee_vendor,
        public_key_hex: resp.public_key_hex.clone(),
        workload_measurement_hex,
        fresh_caller_nonce_verified: fresh_nonce_matched && pop_verified && (hardware_tee_attested || tee_policy.allow_software_dev),
        proof_of_possession_verified: pop_verified,
        hardware_tee_attested,
        key_matches_published_registry: key_matches_published,
        endorsement_matches_live_key: endorsement_matches_live,
        endorsement_signature_valid: endorsement_sig_valid,
        endorsement_coords_match_registry: endorsement_coords_match,
        proof_eligible,
        failure_reasons: failures,
    }
}

/// An independent operator network trusted by a relying-party client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedNetwork {
    pub network_id: String,
    pub pinned_root_public_key_hex: String,
    pub signed_registry: SignedNetworkRegistry,
}

/// Proof submission from one independent Proof of Geography network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkProofSubmission {
    pub network_id: String,
    pub bundle: GeoProofBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerNetworkVerification {
    pub network_id: String,
    pub operator_name: String,
    pub registry_signature_valid: bool,
    pub proof_valid: bool,
    pub report: Option<ProofVerificationReport>,
    pub error: Option<String>,
}

/// Multi-network federated verification report across `X` independent operator networks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedVerificationReport {
    pub overall_valid: bool,
    pub required_independent_networks: usize,
    pub valid_independent_networks: usize,
    pub distinct_operators_verified: Vec<String>,
    pub prover_pk_consistent_across_networks: bool,
    pub observed_prover_ips_across_networks: Vec<String>,
    pub ip_consistent_across_networks: bool,
    pub consensus_tier1a_vacuum_km: Option<f64>,
    pub consensus_tier1b_fiber_km: Option<f64>,
    pub consensus_tier2_calibrated_km: Option<f64>,
    pub failure_reasons: Vec<String>,
    pub per_network: Vec<PerNetworkVerification>,
}

/// Verify proofs obtained from multiple INDEPENDENT Proof of Geography networks.
pub fn verify_federated_proof(
    submissions: &[NetworkProofSubmission],
    trusted_networks: &[TrustedNetwork],
    policy: &VerificationPolicy,
    min_independent_networks: usize,
    now_unix_s: u64,
) -> FederatedVerificationReport {
    let mut per_network = Vec::new();
    let mut failure_reasons = Vec::new();
    let mut seen_networks = HashSet::new();
    let mut seen_root_keys = HashSet::new();
    let mut distinct_operators = Vec::new();
    let mut prover_pks = HashSet::new();
    let mut all_ips = BTreeSet::new();

    let mut min_vac: Option<f64> = None;
    let mut min_fib: Option<f64> = None;
    let mut min_cal: Option<f64> = None;

    for sub in submissions {
        if !seen_networks.insert(sub.network_id.clone()) {
            failure_reasons.push(format!("Duplicate network submission: {}", sub.network_id));
            continue;
        }
        let Some(net) = trusted_networks.iter().find(|n| n.network_id == sub.network_id) else {
            per_network.push(PerNetworkVerification {
                network_id: sub.network_id.clone(),
                operator_name: "unknown".into(),
                registry_signature_valid: false,
                proof_valid: false,
                report: None,
                error: Some("Untrusted network_id".into()),
            });
            continue;
        };

        let root_key_norm = net.pinned_root_public_key_hex.to_lowercase();
        if !seen_root_keys.insert(root_key_norm) {
            failure_reasons.push(format!(
                "Network {} shares root key with another submitted network (not independent)",
                sub.network_id
            ));
            continue;
        }

        if let Err(e) = net
            .signed_registry
            .verify(Some(&net.pinned_root_public_key_hex), now_unix_s)
        {
            per_network.push(PerNetworkVerification {
                network_id: sub.network_id.clone(),
                operator_name: net.signed_registry.operator_name.clone(),
                registry_signature_valid: false,
                proof_valid: false,
                report: None,
                error: Some(e.to_string()),
            });
            continue;
        }

        match verify_proof_bundle(&sub.bundle, &net.signed_registry.grid, policy, now_unix_s) {
            Ok(report) => {
                let valid = report.overall_valid;
                if valid {
                    distinct_operators.push(net.signed_registry.operator_name.clone());
                    prover_pks.insert(report.verified_tee.public_key_hex.clone());
                    for ip in &report.distinct_observed_ips {
                        all_ips.insert(ip.clone());
                    }
                    if let Some(ref c) = report.tier1a_vacuum {
                        min_vac = Some(min_vac.map_or(c.proven_max_radius_km, |v| {
                            v.min(c.proven_max_radius_km)
                        }));
                    }
                    if let Some(ref c) = report.tier1b_fiber {
                        min_fib = Some(min_fib.map_or(c.proven_max_radius_km, |v| {
                            v.min(c.proven_max_radius_km)
                        }));
                    }
                    if let Some(ref c) = report.tier2_calibrated {
                        min_cal = Some(min_cal.map_or(c.proven_max_radius_km, |v| {
                            v.min(c.proven_max_radius_km)
                        }));
                    }
                }
                per_network.push(PerNetworkVerification {
                    network_id: sub.network_id.clone(),
                    operator_name: net.signed_registry.operator_name.clone(),
                    registry_signature_valid: true,
                    proof_valid: valid,
                    report: Some(report),
                    error: None,
                });
            }
            Err(e) => {
                per_network.push(PerNetworkVerification {
                    network_id: sub.network_id.clone(),
                    operator_name: net.signed_registry.operator_name.clone(),
                    registry_signature_valid: true,
                    proof_valid: false,
                    report: None,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    let valid_count = distinct_operators.len();
    let prover_pk_consistent = prover_pks.len() <= 1;
    let ip_consistent = all_ips.len() <= 1;

    if valid_count < min_independent_networks {
        failure_reasons.push(format!(
            "Insufficient independent networks verified: {valid_count} < {min_independent_networks}"
        ));
    }
    if !prover_pk_consistent {
        failure_reasons.push(
            "Prover TEE public key mismatch across independent networks (possible split-TEE attack)".into(),
        );
    }

    FederatedVerificationReport {
        overall_valid: failure_reasons.is_empty() && valid_count >= min_independent_networks,
        required_independent_networks: min_independent_networks,
        valid_independent_networks: valid_count,
        distinct_operators_verified: distinct_operators,
        prover_pk_consistent_across_networks: prover_pk_consistent,
        observed_prover_ips_across_networks: all_ips.into_iter().collect(),
        ip_consistent_across_networks: ip_consistent,
        consensus_tier1a_vacuum_km: min_vac,
        consensus_tier1b_fiber_km: min_fib,
        consensus_tier2_calibrated_km: min_cal,
        failure_reasons,
        per_network,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::AnchorDescriptor;
    use pog_geo::LatLon;
    use pog_tee::{SoftwareDevProvider, TeeProvider, TeeVendor};
    use rand::rngs::OsRng;

    #[test]
    fn test_signed_registry_and_anchor_endorsement() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_pk_hex = hex::encode(root_sk.verifying_key().to_bytes());
        let grid = AnchorGrid {
            version: "2.0.0".into(),
            grid_name: "jperla-72".into(),
            description: "test".into(),
            anchors: vec![AnchorDescriptor {
                anchor_id: "gcp-fra".into(),
                cloud_provider: "gcp".into(),
                region: "europe-west3".into(),
                city: "Frankfurt".into(),
                tee_vendor: TeeVendor::AmdSevSnp,
                instance_type: "n2d-standard-2".into(),
                location: LatLon::new(50.1109, 8.6821),
                endpoint_tcp: "35.207.136.128:7443".into(),
                endpoint_udp: "35.207.136.128:7444".into(),
                https_url: None,
                public_key_hex: "aa".repeat(32),
                coordinate_basis: None,
            }],
        };

        let mut signed = SignedNetworkRegistry::sign_new(
            "proofofgeography.com",
            "jperla",
            grid,
            1_700_000_000,
            86_400 * 30,
            &root_sk,
        );
        assert!(signed.verify(Some(&root_pk_hex), 1_700_001_000).is_ok());
        assert!(signed.validate_production_membership().is_ok());

        signed.grid.anchors[0].location.lat += 1.0;
        assert!(signed.verify(Some(&root_pk_hex), 1_700_001_000).is_err());

        let cert = AnchorEndorsement::sign_new(
            "proofofgeography.com",
            "gcp-fra",
            "aa".repeat(32),
            50.1109,
            8.6821,
            1_700_000_000,
            86_400 * 30,
            &root_sk,
        );
        assert!(cert.verify(&root_pk_hex, 1_700_001_000).is_ok());
    }

    #[test]
    fn test_rejects_stale_endorsement_after_restart_and_software_dev_in_prod() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_pk_hex = hex::encode(root_sk.verifying_key().to_bytes());
        let old_sk = SigningKey::generate(&mut OsRng);
        let new_sk = SigningKey::generate(&mut OsRng);
        let old_pk = hex::encode(old_sk.verifying_key().to_bytes());
        let new_pk = hex::encode(new_sk.verifying_key().to_bytes());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let published = AnchorDescriptor {
            anchor_id: "aws-fra".into(),
            cloud_provider: "aws".into(),
            region: "eu-central-1".into(),
            city: "Frankfurt".into(),
            tee_vendor: TeeVendor::AwsNitro,
            instance_type: "c6i.xlarge".into(),
            location: LatLon::new(50.11, 8.68),
            endpoint_tcp: "1.2.3.4:7443".into(),
            endpoint_udp: "1.2.3.4:7444".into(),
            https_url: None,
            public_key_hex: old_pk.clone(),
            coordinate_basis: None,
        };
        let old_cert = AnchorEndorsement::sign_new(
            "proofofgeography.com",
            "aws-fra",
            &old_pk,
            50.11,
            8.68,
            now - 100,
            86_400,
            &root_sk,
        );
        let dev_quote = SoftwareDevProvider::new("cc".repeat(32))
            .attest(&new_sk.verifying_key().to_bytes(), b"boot-nonce", None)
            .unwrap();

        let live_info = AnchorLiveInfo {
            anchor_id: "aws-fra".into(),
            cloud_provider: "aws".into(),
            tee_vendor: TeeVendor::SoftwareDev,
            public_key_hex: new_pk,
            bootstrap_nonce: "boot-nonce".into(),
            tee_quote: Some(dev_quote),
            operator_endorsement: Some(old_cert),
            endorsement_status: None,
            hardened: true,
        };

        let audit = verify_anchor_info_identity(
            &live_info,
            &published,
            &root_pk_hex,
            &AttestationPolicy::production(),
            now,
        );
        assert!(!audit.proof_eligible);
        assert!(!audit.key_matches_published_registry);
        assert!(!audit.endorsement_matches_live_key);
        assert!(!audit.hardware_tee_attested);
    }

    #[test]
    fn test_fresh_attestation_verification_and_production_hygiene() {
        let root_sk = SigningKey::generate(&mut OsRng);
        let root_pk_hex = hex::encode(root_sk.verifying_key().to_bytes());
        let node_sk = SigningKey::generate(&mut OsRng);
        let node_pk_bytes = node_sk.verifying_key().to_bytes();
        let node_pk_hex = hex::encode(node_pk_bytes);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let nonce_bytes = [0x42u8; 32];
        let nonce_hex = hex::encode(nonce_bytes);
        let meas_hex = "ab".repeat(48);

        // Placeholder simulated grid MUST fail validate_production_hygiene()!
        let sim_grid = AnchorGrid {
            version: "2.0.0".into(),
            grid_name: "sim-grid".into(),
            description: "simulated".into(),
            anchors: vec![AnchorDescriptor {
                anchor_id: "edge-us-hnl".into(),
                cloud_provider: "edge".into(),
                region: "us-hi".into(),
                city: "Honolulu".into(),
                tee_vendor: TeeVendor::AmdSevSnp,
                instance_type: "baremetal".into(),
                location: LatLon::new(21.3, -157.8),
                endpoint_tcp: "edge-us-hnl.pog.example:7443".into(),
                endpoint_udp: "edge-us-hnl.pog.example:7444".into(),
                https_url: None,
                public_key_hex: "01".repeat(32),
                coordinate_basis: None,
            }],
        };
        let sim_signed = SignedNetworkRegistry::sign_new("proofofgeography.com", "jperla", sim_grid, now, 86_400, &root_sk);
        assert!(sim_signed.validate_production_hygiene().is_err());

        // Real-key / real-IP descriptor + fresh /attest response
        let published = AnchorDescriptor {
            anchor_id: "gcp-europe-west3-frankfurt".into(),
            cloud_provider: "gcp".into(),
            region: "europe-west3".into(),
            city: "Frankfurt".into(),
            tee_vendor: TeeVendor::SoftwareDev,
            instance_type: "n2d-standard-2".into(),
            location: LatLon::new(50.1109, 8.6821),
            endpoint_tcp: "35.207.136.128:7443".into(),
            endpoint_udp: "35.207.136.128:7444".into(),
            https_url: Some("https://fra-gcp.a.proofofgeography.com".into()),
            public_key_hex: node_pk_hex.clone(),
            coordinate_basis: None,
        };
        let cert = AnchorEndorsement::sign_new(
            "proofofgeography.com",
            &published.anchor_id,
            &node_pk_hex,
            published.location.lat,
            published.location.lon,
            now - 10,
            86_400,
            &root_sk,
        );
        let quote = SoftwareDevProvider::new(meas_hex.clone())
            .attest(&node_pk_bytes, &nonce_bytes, None)
            .unwrap();
        let pop_msg = attest_pop_signing_message(&published.anchor_id, &nonce_hex, &meas_hex);
        let pop_sig = hex::encode(node_sk.sign(&pop_msg).to_bytes());
        let resp = AnchorFreshAttestResponse {
            anchor_id: published.anchor_id.clone(),
            cloud_provider: "gcp".into(),
            tee_vendor: TeeVendor::SoftwareDev,
            fresh_caller_nonce: true,
            caller_nonce_hex: nonce_hex.clone(),
            public_key_hex: node_pk_hex,
            proof_of_possession_sig_hex: pop_sig,
            tee_quote: Some(quote),
            operator_endorsement: Some(cert),
            endorsement_status: Some("verified".into()),
            hardened: true,
        };

        // 1. Production policy MUST reject SoftwareDev fail-closed!
        let prod_res = verify_anchor_fresh_attestation(&resp, &published, &root_pk_hex, &nonce_hex, &AttestationPolicy::production(), now);
        assert!(!prod_res.proof_eligible);
        assert!(!prod_res.hardware_tee_attested);

        // 2. Under dev policy with matching measurement allowlist -> passes; wrong measurement or wrong nonce -> fails!
        let mut dev_pol = AttestationPolicy::allow_dev_software();
        dev_pol.allowed_measurements = vec![meas_hex.clone()];
        let ok_res = verify_anchor_fresh_attestation(&resp, &published, &root_pk_hex, &nonce_hex, &dev_pol, now);
        assert!(ok_res.proof_eligible, "failures: {:?}", ok_res.failure_reasons);
        assert!(ok_res.proof_of_possession_verified);
        assert!(ok_res.endorsement_coords_match_registry);

        let wrong_nonce = "99".repeat(32);
        let bad_nonce_res = verify_anchor_fresh_attestation(&resp, &published, &root_pk_hex, &wrong_nonce, &dev_pol, now);
        assert!(!bad_nonce_res.proof_eligible);

        dev_pol.allowed_measurements = vec!["ff".repeat(48)];
        let bad_meas_res = verify_anchor_fresh_attestation(&resp, &published, &root_pk_hex, &nonce_hex, &dev_pol, now);
        assert!(!bad_meas_res.proof_eligible);
    }
}
