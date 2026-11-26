use crate::bundle::{
    verify_proof_bundle, GeoProofBundle, ProofVerificationReport, VerificationPolicy,
};
use crate::committee::AnchorGrid;
use crate::wire::ProtoError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};

/// Cryptographically signed Anchor network registry published by an independent operator
/// (e.g., `proofofgeography.com`, Cloudflare, OVH, EFF, or an enterprise consortium).
///
/// The operator's master Ed25519 root private key stays strictly offline / on the operator's
/// admin workstation (or HSM) and signs:
///   1. This `SignedNetworkRegistry` (authorizing the operator's Anchor list & TEE public keys).
///   2. Optional per-Anchor `AnchorEndorsement` certs delivered securely to each Anchor node.
///
/// Clients pin ONLY each trusted operator's `root_public_key_hex` and can require quorum across
/// `X` independent networks in `verify_federated_proof(...)`!
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
    /// Identical across Rust, TypeScript, Python, and Go without JSON key-ordering ambiguity.
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

    /// Sign a network registry using the operator's local root Ed25519 signing key.
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

/// Per-Anchor cryptographic endorsement certificate signed by the network operator's local root key
/// and delivered securely to an Anchor node (so the root key itself NEVER leaves the operator's machine!).
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

/// An independent operator network trusted by a relying-party client (e.g. jperla + Cloudflare + OVH).
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

/// Verify proofs obtained from multiple INDEPENDENT Proof of Geography networks
/// (e.g. `proofofgeography.com` + `cloudflare-pog` + `ovh-pog`), requiring at least
/// `min_independent_networks` distinct root-key-signed networks to agree on the Prover's
/// hardware identity and physical location!
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

        // Prevent counting two aliases backed by the same operator root key as independent networks!
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
                    min_vac = Some(min_vac.map_or(report.tier1a_vacuum.proven_max_radius_km, |v| {
                        v.min(report.tier1a_vacuum.proven_max_radius_km)
                    }));
                    min_fib = Some(min_fib.map_or(report.tier1b_fiber.proven_max_radius_km, |v| {
                        v.min(report.tier1b_fiber.proven_max_radius_km)
                    }));
                    min_cal = Some(min_cal.map_or(report.tier2_calibrated.proven_max_radius_km, |v| {
                        v.min(report.tier2_calibrated.proven_max_radius_km)
                    }));
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
    use pog_tee::TeeVendor;
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
                public_key_hex: "aa".repeat(32),
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

        // Tampering with an anchor coordinate MUST fail operator signature verification!
        signed.grid.anchors[0].location.lat += 1.0;
        assert!(signed.verify(Some(&root_pk_hex), 1_700_001_000).is_err());

        // Endorsement cert roundtrip
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
}
