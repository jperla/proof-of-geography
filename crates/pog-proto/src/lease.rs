use crate::bundle::{GeoProofBundle, ProofVerificationReport};
use crate::wire::ProtoError;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Standard HTTP header name for presenting a privacy-preserving Coarse Jurisdiction Lease.
pub const HTTP_HEADER_POG_LEASE: &str = "X-PoG-Lease";

/// Privacy-preserving Coarse Jurisdiction Lease / On-Chip Operating License (Brass & Aarne pp. 9–10, 35).
///
/// Issued by a trusted operator/auditor after verifying a full `GeoProofBundle` against hardware TEE
/// Anchors and `GeofencePolicy`. Relying parties and on-chip monotonic-timer "region locking" modules
/// verify the lease offline WITHOUT learning the Prover's exact city coordinates, raw RTT vector,
/// or public IP address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoarseJurisdictionLease {
    pub version: u8,
    pub lease_id: String,
    pub issuer_network_id: String,
    pub issuer_public_key_hex: String,
    pub prover_pk_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_uuid: Option<String>,
    pub workload_measurement_hex: String,
    /// Positive allowed jurisdictions proven to contain 100% of the feasible region (e.g., `["EU-CORE"]`).
    pub allowed_jurisdictions: Vec<String>,
    /// Restricted regions proven strictly disjoint from the feasible region (e.g., `["CN", "RU-KGD"]`).
    pub excluded_restricted_regions: Vec<String>,
    /// Hard physics tier enforced when issuing this lease (e.g., `"tier1a_vacuum"`).
    pub bound_tier: String,
    pub hardware_attested: bool,
    pub distinct_clouds: usize,
    pub distinct_countries: usize,
    pub verified_anchor_count: usize,
    /// SHA-256/BLAKE3 commitment to the full private `GeoProofBundle` archived by the auditor/issuer.
    pub proof_bundle_hash_hex: String,
    pub issued_at_unix_s: u64,
    pub expires_at_unix_s: u64,
    /// Maximum on-chip monotonic elapsed seconds before local hardware throttles/locks if unrenewed
    /// (avoids trusting host wall-clock / NTP for region-locking enforcement).
    pub max_monotonic_lease_seconds: u64,
    /// Ed25519 signature by `issuer_public_key_hex` over `signing_digest()`.
    pub issuer_signature_hex: String,
}

impl CoarseJurisdictionLease {
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"pog-coarse-jurisdiction-lease-v1");
        h.update([self.version]);
        h.update(self.lease_id.as_bytes());
        h.update(b"|");
        h.update(self.issuer_network_id.as_bytes());
        h.update(b"|");
        h.update(self.issuer_public_key_hex.to_ascii_lowercase().as_bytes());
        h.update(b"|");
        h.update(self.prover_pk_hex.to_ascii_lowercase().as_bytes());
        h.update(b"|");
        if let Some(ref gid) = self.gpu_uuid {
            h.update(gid.as_bytes());
        }
        h.update(b"|");
        h.update(self.workload_measurement_hex.to_ascii_lowercase().as_bytes());
        h.update(b"|");
        h.update((self.allowed_jurisdictions.len() as u32).to_le_bytes());
        for j in &self.allowed_jurisdictions {
            h.update(j.as_bytes());
            h.update(b",");
        }
        h.update((self.excluded_restricted_regions.len() as u32).to_le_bytes());
        for r in &self.excluded_restricted_regions {
            h.update(r.as_bytes());
            h.update(b",");
        }
        h.update(self.bound_tier.as_bytes());
        h.update([if self.hardware_attested { 1 } else { 0 }]);
        h.update((self.distinct_clouds as u64).to_le_bytes());
        h.update((self.distinct_countries as u64).to_le_bytes());
        h.update((self.verified_anchor_count as u64).to_le_bytes());
        h.update(self.proof_bundle_hash_hex.to_ascii_lowercase().as_bytes());
        h.update(self.issued_at_unix_s.to_le_bytes());
        h.update(self.expires_at_unix_s.to_le_bytes());
        h.update(self.max_monotonic_lease_seconds.to_le_bytes());
        h.finalize().into()
    }

    pub fn to_header_value(&self) -> Result<String, ProtoError> {
        let json = serde_json::to_vec(self)
            .map_err(|e| ProtoError::SerializationError(e.to_string()))?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&json))
    }

    pub fn from_header_value(val: &str) -> Result<Self, ProtoError> {
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(val.trim())
            .map_err(|e| ProtoError::SerializationError(e.to_string()))?;
        serde_json::from_slice(&raw).map_err(|e| ProtoError::SerializationError(e.to_string()))
    }

    /// Verify a `CoarseJurisdictionLease` offline against a pinned issuer Ed25519 public key,
    /// optional prover key, required allowed/excluded jurisdictions, wall clock, and optional
    /// on-chip monotonic counter elapsed time (`elapsed_monotonic_s`).
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        pinned_issuer_pk_hex: &str,
        expected_prover_pk_hex: Option<&str>,
        required_allowed_jurisdiction: Option<&str>,
        required_excluded_region: Option<&str>,
        require_hardware_attested: bool,
        now_unix_s: u64,
        elapsed_monotonic_s: Option<u64>,
    ) -> Result<(), ProtoError> {
        if !self
            .issuer_public_key_hex
            .eq_ignore_ascii_case(pinned_issuer_pk_hex)
        {
            return Err(ProtoError::SignatureError(
                "lease issuer_public_key_hex does not match pinned issuer key".into(),
            ));
        }
        let pk_raw = hex::decode(pinned_issuer_pk_hex)
            .map_err(|e| ProtoError::SignatureError(format!("bad issuer pk hex: {e}")))?;
        let pk_arr: [u8; 32] = pk_raw
            .try_into()
            .map_err(|_| ProtoError::SignatureError("issuer pk must be 32 bytes".into()))?;
        let vk = VerifyingKey::from_bytes(&pk_arr)
            .map_err(|e| ProtoError::SignatureError(format!("invalid ed25519 pk: {e}")))?;
        let sig_raw = hex::decode(&self.issuer_signature_hex)
            .map_err(|e| ProtoError::SignatureError(format!("bad lease sig hex: {e}")))?;
        let sig_arr: [u8; 64] = sig_raw
            .try_into()
            .map_err(|_| ProtoError::SignatureError("lease sig must be 64 bytes".into()))?;
        let sig = Signature::from_bytes(&sig_arr);
        let digest = self.signing_digest();
        vk.verify(&digest, &sig)
            .map_err(|e| ProtoError::SignatureError(format!("lease signature invalid: {e}")))?;

        if require_hardware_attested && !self.hardware_attested {
            return Err(ProtoError::SignatureError(
                "lease is not backed by hardware-attested TEE proof".into(),
            ));
        }
        if let Some(exp_pk) = expected_prover_pk_hex {
            if !self.prover_pk_hex.eq_ignore_ascii_case(exp_pk) {
                return Err(ProtoError::SignatureError(
                    "lease prover_pk_hex mismatch".into(),
                ));
            }
        }
        if now_unix_s > self.expires_at_unix_s {
            return Err(ProtoError::SignatureError(format!(
                "lease expired ({now_unix_s} > {})",
                self.expires_at_unix_s
            )));
        }
        if self.issued_at_unix_s > now_unix_s.saturating_add(300) {
            return Err(ProtoError::SignatureError(
                "lease issued_at_unix_s is too far in the future".into(),
            ));
        }
        if let Some(mono_s) = elapsed_monotonic_s {
            if mono_s > self.max_monotonic_lease_seconds {
                return Err(ProtoError::SignatureError(format!(
                    "on-chip monotonic lease expired ({mono_s}s > max {}s): region lock triggered",
                    self.max_monotonic_lease_seconds
                )));
            }
        }
        if let Some(req_allow) = required_allowed_jurisdiction {
            if !self
                .allowed_jurisdictions
                .iter()
                .any(|j| j.eq_ignore_ascii_case(req_allow))
            {
                return Err(ProtoError::SignatureError(format!(
                    "lease does not attest allowed jurisdiction '{req_allow}'"
                )));
            }
        }
        if let Some(req_excl) = required_excluded_region {
            if !self
                .excluded_restricted_regions
                .iter()
                .any(|r| r.eq_ignore_ascii_case(req_excl))
            {
                return Err(ProtoError::SignatureError(format!(
                    "lease does not attest exclusion from restricted region '{req_excl}'"
                )));
            }
        }
        Ok(())
    }
}

/// Issue a signed privacy-preserving `CoarseJurisdictionLease` strictly from a verified
/// `ProofVerificationReport`. Fails closed if `report.overall_valid == false` or if
/// `require_hardware_attested && !report.hardware_attested` or if geofence verification failed.
#[allow(clippy::too_many_arguments)]
pub fn issue_coarse_jurisdiction_lease(
    bundle: &GeoProofBundle,
    report: &ProofVerificationReport,
    issuer_key: &SigningKey,
    issuer_network_id: impl Into<String>,
    allowed_jurisdictions: Vec<String>,
    excluded_restricted_regions: Vec<String>,
    bound_tier: impl Into<String>,
    ttl_seconds: u64,
    require_hardware_attested: bool,
    now_unix_s: u64,
) -> Result<CoarseJurisdictionLease, ProtoError> {
    if !report.overall_valid {
        return Err(ProtoError::SignatureError(format!(
            "cannot issue jurisdiction lease for invalid proof: {}",
            report.failure_reasons.join("; ")
        )));
    }
    if require_hardware_attested && !report.hardware_attested {
        return Err(ProtoError::SignatureError(
            "cannot issue production jurisdiction lease without hardware TEE attestation".into(),
        ));
    }
    if let Some(ref gf) = report.geofence_evaluation {
        if !gf.passed {
            return Err(ProtoError::SignatureError(format!(
                "cannot issue jurisdiction lease: geofence failed ({})",
                gf.failure_reasons.join("; ")
            )));
        }
    }

    let bundle_hash = bundle.record_hash_hex();
    let lease_id = format!("lease-{}-{}", &bundle_hash[..16], now_unix_s);
    let issuer_pk_hex = hex::encode(issuer_key.verifying_key().to_bytes());
    let gpu_uuid = bundle
        .prover_quote
        .gpu_binding
        .as_ref()
        .map(|g| g.gpu_uuid.clone());

    let mut lease = CoarseJurisdictionLease {
        version: 1,
        lease_id,
        issuer_network_id: issuer_network_id.into(),
        issuer_public_key_hex: issuer_pk_hex,
        prover_pk_hex: report.verified_tee.public_key_hex.clone(),
        gpu_uuid,
        workload_measurement_hex: report.verified_tee.workload_measurement_hex.clone(),
        allowed_jurisdictions,
        excluded_restricted_regions,
        bound_tier: bound_tier.into(),
        hardware_attested: report.hardware_attested,
        distinct_clouds: report.distinct_clouds,
        distinct_countries: report.distinct_countries,
        verified_anchor_count: report.verified_receipt_count,
        proof_bundle_hash_hex: bundle_hash,
        issued_at_unix_s: now_unix_s,
        expires_at_unix_s: now_unix_s.saturating_add(ttl_seconds),
        max_monotonic_lease_seconds: ttl_seconds,
        issuer_signature_hex: String::new(),
    };
    let digest = lease.signing_digest();
    lease.issuer_signature_hex = hex::encode(issuer_key.sign(&digest).to_bytes());
    Ok(lease)
}
