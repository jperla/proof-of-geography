use crate::types::{
    compute_report_data, AttestationPolicy, GpuAttestationBinding, TeeAttestationQuote, TeeError,
    TeeProvider, TeeVendor,
};
use base64::Engine;
use coset::{iana, CborSerializable, CoseSign1, TaggedCborSerializable};
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{DerSignature, Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use x509_parser::prelude::*;

/// Official AWS Nitro Enclaves Root-G1 X.509 PEM certificate (downloaded from
/// https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip).
pub const AWS_NITRO_ROOT_G1_PEM: &str =
    include_str!("../certs/aws_nitro_enclaves_root_g1.pem");

/// Pinned SHA-256 fingerprint of the official AWS Nitro Enclaves Root-G1 DER certificate.
pub const AWS_NITRO_ROOT_G1_SHA256_HEX: &str =
    "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b";

/// Decoded CBOR payload inside an AWS Nitro Enclave NSM COSE_Sign1 attestation document.
/// Matches the official AWS Nitro Security Module specification.
#[derive(Debug, Clone, Deserialize)]
pub struct NitroAttestationDocument {
    pub module_id: String,
    pub digest: String,
    /// Milliseconds since Unix epoch (signed by Nitro hypervisor / NSM).
    pub timestamp: u64,
    /// PCR index -> raw digest bytes (48 bytes for SHA384).
    /// PCR0 = EIF image, PCR1 = Linux kernel & boot, PCR2 = Application.
    pub pcrs: BTreeMap<u32, serde_bytes_vec::ByteVec>,
    /// DER-encoded leaf X.509 certificate for the NSM signing key.
    pub certificate: serde_bytes_vec::ByteVec,
    /// DER-encoded X.509 CA chain from root to issuing intermediate (AWS order: [root, int1, ...]).
    pub cabundle: Vec<serde_bytes_vec::ByteVec>,
    /// Optional enclave-generated ephemeral public key bound into the document.
    #[serde(default)]
    pub public_key: Option<serde_bytes_vec::ByteVec>,
    /// Optional application-defined user data (PoG `report_data` = SHA-512 binding).
    #[serde(default)]
    pub user_data: Option<serde_bytes_vec::ByteVec>,
    /// Optional verifier freshness nonce.
    #[serde(default)]
    pub nonce: Option<serde_bytes_vec::ByteVec>,
}

/// Helper serde wrapper so CBOR byte strings (`bstr`) deserialize cleanly into `Vec<u8>`.
mod serde_bytes_vec {
    use serde::{Deserialize, Deserializer};

    #[derive(Debug, Clone)]
    pub struct ByteVec(pub Vec<u8>);

    impl std::ops::Deref for ByteVec {
        type Target = [u8];
        fn deref(&self) -> &[u8] {
            &self.0
        }
    }

    impl<'de> Deserialize<'de> for ByteVec {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = ByteVec;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("a CBOR byte string")
                }
                fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                    Ok(ByteVec(v.to_vec()))
                }
                fn visit_byte_buf<E: serde::de::Error>(
                    self,
                    v: Vec<u8>,
                ) -> Result<Self::Value, E> {
                    Ok(ByteVec(v))
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> Result<Self::Value, A::Error> {
                    let mut out = Vec::new();
                    while let Some(b) = seq.next_element::<u8>()? {
                        out.push(b);
                    }
                    Ok(ByteVec(out))
                }
            }
            deserializer.deserialize_bytes(Visitor)
        }
    }
}

/// Verified metadata extracted from a cryptographically verified AWS Nitro NSM document.
#[derive(Debug, Clone)]
pub struct VerifiedNitroDocument {
    pub module_id: String,
    pub timestamp_ms: u64,
    pub pcr0_hex: String,
    pub pcr1_hex: Option<String>,
    pub pcr2_hex: Option<String>,
    pub root_sha256_hex: String,
}

/// Decode the pinned official AWS Nitro Enclaves Root-G1 DER bytes and assert its SHA-256 fingerprint.
pub fn pinned_aws_nitro_root_der() -> Result<Vec<u8>, TeeError> {
    let parsed = ::pem::parse(AWS_NITRO_ROOT_G1_PEM)
        .map_err(|e| TeeError::VerificationFailed(format!("pinned Nitro Root PEM invalid: {e}")))?;
    let der = parsed.into_contents();
    let fp = hex::encode(Sha256::digest(&der));
    if fp != AWS_NITRO_ROOT_G1_SHA256_HEX {
        return Err(TeeError::VerificationFailed(format!(
            "pinned AWS Nitro Root-G1 SHA-256 mismatch: got {fp}, expected {AWS_NITRO_ROOT_G1_SHA256_HEX}"
        )));
    }
    Ok(der)
}

/// AWS Nitro Enclaves hardware TEE provider.
///
/// Requires running INSIDE an actual AWS Nitro Enclave with `/dev/nsm` attached by the Nitro
/// hypervisor. Calls the official `aws-nitro-enclaves-nsm-api` driver (`Request::Attestation`)
/// to obtain a hardware-signed COSE_Sign1 CBOR attestation document binding the enclave-resident
/// ephemeral Ed25519 signing key, PoG `report_data`, and challenge `nonce`.
///
/// NEVER synthesizes local JSON or falls back to simulated attestation!
pub struct AwsNitroProvider {
    pub nsm_device: String,
}

impl Default for AwsNitroProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AwsNitroProvider {
    pub fn new() -> Self {
        Self {
            nsm_device: "/dev/nsm".to_string(),
        }
    }

    #[cfg(target_os = "linux")]
    fn fetch_nsm_cose_document(
        &self,
        public_key: &[u8; 32],
        report_data: &[u8; 64],
        nonce: &[u8],
    ) -> Result<Vec<u8>, TeeError> {
        use aws_nitro_enclaves_nsm_api::api::{Request, Response};
        use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

        if !std::path::Path::new(&self.nsm_device).exists() {
            return Err(TeeError::HardwareDeviceUnavailable(format!(
                "AWS Nitro Security Module {} not found (must run inside an active AWS Nitro Enclave EIF)",
                self.nsm_device
            )));
        }

        let fd = nsm_init();
        if fd < 0 {
            return Err(TeeError::HardwareDeviceUnavailable(
                "nsm_init() failed opening /dev/nsm (not running inside a Nitro Enclave)".into(),
            ));
        }

        let req = Request::Attestation {
            user_data: Some(report_data.to_vec().into()),
            nonce: Some(nonce.to_vec().into()),
            public_key: Some(public_key.to_vec().into()),
        };
        let resp = nsm_process_request(fd, req);
        nsm_exit(fd);

        match resp {
            Response::Attestation { document } => Ok(document),
            Response::Error(err) => Err(TeeError::GenerationFailed(format!(
                "NSM Request::Attestation returned error: {err:?}"
            ))),
            other => Err(TeeError::GenerationFailed(format!(
                "Unexpected NSM response variant: {other:?}"
            ))),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn fetch_nsm_cose_document(
        &self,
        _public_key: &[u8; 32],
        _report_data: &[u8; 64],
        _nonce: &[u8],
    ) -> Result<Vec<u8>, TeeError> {
        Err(TeeError::HardwareDeviceUnavailable(
            "AWS Nitro Enclaves /dev/nsm requires Linux running inside an active Nitro Enclave EIF"
                .into(),
        ))
    }
}

impl TeeProvider for AwsNitroProvider {
    fn vendor(&self) -> TeeVendor {
        TeeVendor::AwsNitro
    }

    fn attest(
        &self,
        public_key: &[u8; 32],
        nonce: &[u8],
        gpu_binding: Option<GpuAttestationBinding>,
    ) -> Result<TeeAttestationQuote, TeeError> {
        let report_data = compute_report_data(public_key, nonce, gpu_binding.as_ref());
        let raw_cose = self.fetch_nsm_cose_document(public_key, &report_data, nonce)?;

        // Parse the NSM-signed COSE_Sign1 document directly to extract hardware-signed PCR0 & timestamp
        // (never invent PCRs or module IDs locally!).
        let (_cose, doc) = decode_nitro_cose(&raw_cose)?;
        let pcr0 = doc.pcrs.get(&0).ok_or_else(|| {
            TeeError::GenerationFailed("NSM attestation document missing PCR0".into())
        })?;
        if pcr0.len() != 48 {
            return Err(TeeError::GenerationFailed(format!(
                "NSM PCR0 length {} != 48 bytes (SHA-384)",
                pcr0.len()
            )));
        }
        // AWS Nitro Enclaves sets PCR0 to all zeros when launched with `--debug-mode`.
        let debug_disabled = !pcr0.iter().all(|&b| b == 0);
        let generated_at_unix_s = doc.timestamp / 1000;

        Ok(TeeAttestationQuote {
            vendor: TeeVendor::AwsNitro,
            public_key_hex: hex::encode(public_key),
            workload_measurement_hex: hex::encode(&pcr0.0),
            report_data_hex: hex::encode(report_data),
            nonce_hex: hex::encode(nonce),
            // Nitro Enclaves do not support live VM migration by hardware architecture.
            migration_disabled: true,
            debug_disabled,
            secure_tsc_enabled: false,
            gpu_binding,
            raw_quote_b64: base64::engine::general_purpose::STANDARD.encode(&raw_cose),
            vendor_cert_chain_pem: Vec::new(),
            generated_at_unix_s,
        })
    }
}

fn decode_nitro_cose(raw_cose: &[u8]) -> Result<(CoseSign1, NitroAttestationDocument), TeeError> {
    let cose = CoseSign1::from_tagged_slice(raw_cose)
        .or_else(|_| CoseSign1::from_slice(raw_cose))
        .map_err(|e| {
            TeeError::VerificationFailed(format!(
                "invalid AWS Nitro COSE_Sign1 CBOR document (legacy fake JSON rejected): {e}"
            ))
        })?;
    let payload_bytes = cose.payload.as_deref().ok_or_else(|| {
        TeeError::VerificationFailed("AWS Nitro COSE_Sign1 missing payload".into())
    })?;
    let doc: NitroAttestationDocument = ciborium::from_reader(payload_bytes).map_err(|e| {
        TeeError::VerificationFailed(format!("invalid AWS Nitro CBOR payload: {e}"))
    })?;
    Ok((cose, doc))
}

/// Extract an ECDSA P-384 verifying key from an X.509 certificate's SubjectPublicKeyInfo.
fn extract_p384_verifying_key(cert: &X509Certificate<'_>) -> Result<P384VerifyingKey, TeeError> {
    let pubkey_bytes = cert.public_key().subject_public_key.data.as_ref();
    P384VerifyingKey::from_sec1_bytes(pubkey_bytes).map_err(|e| {
        TeeError::VerificationFailed(format!("X.509 cert SPKI is not a valid P-384 key: {e}"))
    })
}

/// Verify X.509 certificate `child` was signed by `issuer` using ECDSA P-384 / SHA-384
/// (the algorithm used throughout the AWS Nitro Enclaves Root-G1 CA hierarchy).
fn verify_x509_sig_p384(
    child: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> Result<(), TeeError> {
    let vk = extract_p384_verifying_key(issuer)?;
    let sig_der = child.signature_value.data.as_ref();
    let sig = DerSignature::from_bytes(sig_der).map_err(|e| {
        TeeError::VerificationFailed(format!("invalid DER ECDSA signature in X.509 cert: {e}"))
    })?;
    let tbs = child.tbs_certificate.as_ref();
    vk.verify(tbs, &sig).map_err(|e| {
        TeeError::VerificationFailed(format!(
            "X.509 certificate signature verification failed (subject={} issuer={}): {e}",
            child.subject(),
            issuer.subject()
        ))
    })
}

/// Check X.509 certificate validity window against `at_unix_s`.
fn check_cert_validity(cert: &X509Certificate<'_>, at_unix_s: u64, label: &str) -> Result<(), TeeError> {
    let nb = cert.validity().not_before.timestamp();
    let na = cert.validity().not_after.timestamp();
    let ts = at_unix_s as i64;
    if ts < nb || ts > na {
        return Err(TeeError::VerificationFailed(format!(
            "Nitro {label} certificate not valid at {at_unix_s} (valid [{nb}, {na}])"
        )));
    }
    Ok(())
}

/// Verify an AWS Nitro Enclave COSE_Sign1 CBOR attestation document against an explicit pinned
/// root CA DER certificate (`expected_root_der`), enforcing:
/// 1. Valid COSE_Sign1 protected algorithm `ES384`
/// 2. Valid X.509 certificate chain (`leaf <- intermediate(s) <- pinned root`), CA basic constraints,
///    and validity windows at the document's timestamp
/// 3. Valid ECDSA P-384 COSE_Sign1 signature over `Sig_structure` by the verified leaf certificate
/// 4. Freshness against `now_unix_s`, `max_quote_age_seconds`, and `max_future_skew_seconds`
/// 5. Exact binding of `public_key`, `user_data` (`report_data`), `nonce`, `PCR0` (+ optional PCR1/PCR2),
///    and rejection of all-zero `--debug-mode` PCR0!
pub fn verify_nitro_cose_with_trust_root(
    raw_cose: &[u8],
    expected_root_der: &[u8],
    quote: &TeeAttestationQuote,
    expected_nonce: &[u8],
    policy: &AttestationPolicy,
    now_unix_s: u64,
) -> Result<VerifiedNitroDocument, TeeError> {
    let (cose, doc) = decode_nitro_cose(raw_cose)?;

    // 1. Verify protected header algorithm is ES384 (-35).
    match cose.protected.header.alg {
        Some(coset::Algorithm::Assigned(iana::Algorithm::ES384)) => {}
        other => {
            return Err(TeeError::VerificationFailed(format!(
                "AWS Nitro COSE_Sign1 algorithm must be ES384, got {other:?}"
            )));
        }
    }

    // 2. Verify digest algorithm and freshness of NSM-signed timestamp.
    if doc.digest != "SHA384" {
        return Err(TeeError::VerificationFailed(format!(
            "AWS Nitro digest must be SHA384, got {}",
            doc.digest
        )));
    }
    let doc_ts_s = doc.timestamp / 1000;
    if now_unix_s > doc_ts_s.saturating_add(policy.max_quote_age_seconds) {
        return Err(TeeError::PolicyRejected(format!(
            "AWS Nitro attestation document expired (age {}s > max {}s)",
            now_unix_s.saturating_sub(doc_ts_s),
            policy.max_quote_age_seconds
        )));
    }
    if doc_ts_s > now_unix_s.saturating_add(policy.max_future_skew_seconds) {
        return Err(TeeError::PolicyRejected(format!(
            "AWS Nitro attestation document timestamp {}s in future (max skew {}s)",
            doc_ts_s - now_unix_s,
            policy.max_future_skew_seconds
        )));
    }

    // 3. Parse and verify X.509 chain from leaf -> cabundle -> pinned root CA.
    if doc.cabundle.is_empty() {
        return Err(TeeError::VerificationFailed(
            "AWS Nitro attestation document missing cabundle".into(),
        ));
    }
    let (_, leaf_cert) = X509Certificate::from_der(&doc.certificate).map_err(|e| {
        TeeError::VerificationFailed(format!("invalid Nitro leaf X.509 DER: {e}"))
    })?;
    check_cert_validity(&leaf_cert, doc_ts_s, "leaf")?;

    let mut ca_certs: Vec<X509Certificate<'_>> = Vec::with_capacity(doc.cabundle.len());
    for (idx, ca_der) in doc.cabundle.iter().enumerate() {
        let (_, cert) = X509Certificate::from_der(ca_der).map_err(|e| {
            TeeError::VerificationFailed(format!("invalid Nitro cabundle[{idx}] X.509 DER: {e}"))
        })?;
        check_cert_validity(&cert, doc_ts_s, &format!("cabundle[{idx}]"))?;
        let is_ca = cert
            .basic_constraints()
            .ok()
            .flatten()
            .map(|ext| ext.value.ca)
            .unwrap_or(false);
        if !is_ca {
            return Err(TeeError::VerificationFailed(format!(
                "Nitro cabundle[{idx}] does not have BasicConstraints CA=true"
            )));
        }
        ca_certs.push(cert);
    }

    // AWS Nitro puts Root-G1 at `cabundle[0]` and intermediates in order [root, int1, ..., issuing_ca].
    // Verify pinned root matches `cabundle[0]` exactly (DER bytes + SHA-256) and is self-signed.
    if doc.cabundle[0].0.as_slice() != expected_root_der {
        return Err(TeeError::VerificationFailed(format!(
            "AWS Nitro root certificate does not match pinned trust root (got sha256={})",
            hex::encode(Sha256::digest(&doc.cabundle[0].0))
        )));
    }
    let root_sha256_hex = hex::encode(Sha256::digest(expected_root_der));
    verify_x509_sig_p384(&ca_certs[0], &ca_certs[0])?;

    // Verify each intermediate is signed by its predecessor in cabundle, and leaf is signed by the last CA.
    for i in 1..ca_certs.len() {
        if ca_certs[i].issuer() != ca_certs[i - 1].subject() {
            return Err(TeeError::VerificationFailed(format!(
                "Nitro cabundle[{i}] issuer DN mismatch"
            )));
        }
        verify_x509_sig_p384(&ca_certs[i], &ca_certs[i - 1])?;
    }
    let issuing_ca = ca_certs.last().unwrap();
    if leaf_cert.issuer() != issuing_ca.subject() {
        return Err(TeeError::VerificationFailed(
            "Nitro leaf certificate issuer DN does not match issuing CA".into(),
        ));
    }
    verify_x509_sig_p384(&leaf_cert, issuing_ca)?;

    // 4. Verify COSE_Sign1 ECDSA P-384 / SHA-384 signature using the verified leaf certificate key.
    let leaf_vk = extract_p384_verifying_key(&leaf_cert)?;
    let sig_bytes = &cose.signature;
    // RFC 9052 §8.1 / AWS Nitro NSM encodes ES384 signatures as 96-byte fixed-width (r || s).
    let cose_sig = P384Signature::from_slice(sig_bytes).map_err(|e| {
        TeeError::VerificationFailed(format!(
            "invalid COSE_Sign1 ES384 signature length/encoding (len={}): {e}",
            sig_bytes.len()
        ))
    })?;
    let tbs = cose.tbs_data(&[]);
    leaf_vk.verify(&tbs, &cose_sig).map_err(|e| {
        TeeError::VerificationFailed(format!(
            "AWS Nitro COSE_Sign1 ES384 signature verification failed: {e}"
        ))
    })?;

    // 5. Verify PCR0 (and optional PCR1 / PCR2) & reject all-zero `--debug-mode` enclaves.
    let pcr0 = doc.pcrs.get(&0).ok_or_else(|| {
        TeeError::VerificationFailed("AWS Nitro document missing PCR0".into())
    })?;
    if pcr0.len() != 48 {
        return Err(TeeError::VerificationFailed(format!(
            "AWS Nitro PCR0 must be 48 bytes (SHA-384), got {}",
            pcr0.len()
        )));
    }
    let pcr0_is_all_zero = pcr0.iter().all(|&b| b == 0);
    if policy.require_debug_disabled && pcr0_is_all_zero {
        return Err(TeeError::PolicyRejected(
            "AWS Nitro Enclave PCR0 is all zeros (--debug-mode enclave forbidden in production)"
                .into(),
        ));
    }
    let pcr0_hex = hex::encode(&pcr0.0);
    if !pcr0_hex.eq_ignore_ascii_case(&quote.workload_measurement_hex) {
        return Err(TeeError::VerificationFailed(
            "AWS Nitro PCR0 does not match quote.workload_measurement_hex".into(),
        ));
    }
    if !policy.allowed_measurements.is_empty()
        && !policy
            .allowed_measurements
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&pcr0_hex))
    {
        return Err(TeeError::PolicyRejected(format!(
            "AWS Nitro PCR0 {pcr0_hex} not in expected image measurement allowlist"
        )));
    }

    let pcr1_hex = doc.pcrs.get(&1).map(|v| hex::encode(&v.0));
    if !policy.allowed_pcr1.is_empty() {
        match pcr1_hex.as_deref() {
            Some(h) if policy.allowed_pcr1.iter().any(|m| m.eq_ignore_ascii_case(h)) => {}
            other => {
                return Err(TeeError::PolicyRejected(format!(
                    "AWS Nitro PCR1 {other:?} not in allowed_pcr1"
                )));
            }
        }
    }

    let pcr2_hex = doc.pcrs.get(&2).map(|v| hex::encode(&v.0));
    if !policy.allowed_pcr2.is_empty() {
        match pcr2_hex.as_deref() {
            Some(h) if policy.allowed_pcr2.iter().any(|m| m.eq_ignore_ascii_case(h)) => {}
            other => {
                return Err(TeeError::PolicyRejected(format!(
                    "AWS Nitro PCR2 {other:?} not in allowed_pcr2"
                )));
            }
        }
    }

    // 6. Verify enclave-resident ephemeral signing key, user_data (report_data), and freshness nonce.
    let doc_pk = doc.public_key.as_deref().ok_or_else(|| {
        TeeError::VerificationFailed(
            "AWS Nitro document missing bound enclave public_key".into(),
        )
    })?;
    if !hex::encode(doc_pk).eq_ignore_ascii_case(&quote.public_key_hex) {
        return Err(TeeError::VerificationFailed(
            "AWS Nitro public_key does not match quote.public_key_hex".into(),
        ));
    }

    let doc_ud = doc.user_data.as_deref().ok_or_else(|| {
        TeeError::VerificationFailed("AWS Nitro document missing user_data (report_data)".into())
    })?;
    if !hex::encode(doc_ud).eq_ignore_ascii_case(&quote.report_data_hex) {
        return Err(TeeError::VerificationFailed(
            "AWS Nitro user_data does not match quote.report_data_hex".into(),
        ));
    }

    let doc_nonce = doc.nonce.as_deref().ok_or_else(|| {
        TeeError::VerificationFailed("AWS Nitro document missing freshness nonce".into())
    })?;
    if doc_nonce != expected_nonce {
        return Err(TeeError::VerificationFailed(
            "AWS Nitro document nonce does not match expected challenge nonce".into(),
        ));
    }

    Ok(VerifiedNitroDocument {
        module_id: doc.module_id,
        timestamp_ms: doc.timestamp,
        pcr0_hex,
        pcr1_hex,
        pcr2_hex,
        root_sha256_hex,
    })
}

/// Verify an AWS Nitro Enclave attestation quote against the pinned official AWS Nitro Root-G1 CA.
/// Returns `Ok(true)` iff the full COSE_Sign1 + X.509 chain up to AWS Nitro Root-G1 verified.
pub fn verify_raw_nitro_doc(
    quote: &TeeAttestationQuote,
    expected_nonce: &[u8],
    policy: &AttestationPolicy,
    now_unix_s: u64,
) -> Result<bool, TeeError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&quote.raw_quote_b64)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid base64 Nitro doc: {e}")))?;
    let root_der = pinned_aws_nitro_root_der()?;
    let _verified = verify_nitro_cose_with_trust_root(
        &raw,
        &root_der,
        quote,
        expected_nonce,
        policy,
        now_unix_s,
    )?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{verify_quote, WorkloadKeypair};
    use coset::CoseSign1Builder;
    use p384::ecdsa::signature::Signer;
    use p384::ecdsa::SigningKey as P384SigningKey;
    use p384::pkcs8::DecodePrivateKey;
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, PKCS_ECDSA_P384_SHA384};

    struct SyntheticNitroChain {
        root_der: Vec<u8>,
        int_der: Vec<u8>,
        leaf_der: Vec<u8>,
        leaf_sk: P384SigningKey,
    }

    fn build_synthetic_p384_chain() -> SyntheticNitroChain {
        let root_kp = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut rdn = DistinguishedName::new();
        rdn.push(DnType::CommonName, "test.nitro-root");
        root_params.distinguished_name = rdn;
        let root_cert = root_params.self_signed(&root_kp).unwrap();

        let int_kp = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let mut int_params = CertificateParams::default();
        int_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut idn = DistinguishedName::new();
        idn.push(DnType::CommonName, "test.nitro-intermediate");
        int_params.distinguished_name = idn;
        let int_cert = int_params.signed_by(&int_kp, &root_cert, &root_kp).unwrap();

        let leaf_kp = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let mut leaf_params = CertificateParams::default();
        leaf_params.is_ca = IsCa::NoCa;
        let mut ldn = DistinguishedName::new();
        ldn.push(DnType::CommonName, "i-0123456789abcdef0-enc0123");
        leaf_params.distinguished_name = ldn;
        let leaf_cert = leaf_params.signed_by(&leaf_kp, &int_cert, &int_kp).unwrap();

        let leaf_sk = P384SigningKey::from_pkcs8_der(leaf_kp.serialize_der().as_slice()).unwrap();

        SyntheticNitroChain {
            root_der: root_cert.der().to_vec(),
            int_der: int_cert.der().to_vec(),
            leaf_der: leaf_cert.der().to_vec(),
            leaf_sk,
        }
    }

    fn sign_synthetic_nitro_quote(
        chain: &SyntheticNitroChain,
        kp: &WorkloadKeypair,
        nonce: &[u8],
        pcr0: [u8; 48],
        pcr1: [u8; 48],
        pcr2: [u8; 48],
        ts_unix_s: u64,
    ) -> (Vec<u8>, TeeAttestationQuote) {
        let pk_bytes = kp.public_key_bytes();
        let report_data = compute_report_data(&pk_bytes, nonce, None);

        let payload_val = ciborium::Value::Map(vec![
            (ciborium::Value::Text("module_id".into()), ciborium::Value::Text("i-canary-enc1".into())),
            (ciborium::Value::Text("digest".into()), ciborium::Value::Text("SHA384".into())),
            (ciborium::Value::Text("timestamp".into()), ciborium::Value::Integer((ts_unix_s * 1000).into())),
            (
                ciborium::Value::Text("pcrs".into()),
                ciborium::Value::Map(vec![
                    (ciborium::Value::Integer(0.into()), ciborium::Value::Bytes(pcr0.to_vec())),
                    (ciborium::Value::Integer(1.into()), ciborium::Value::Bytes(pcr1.to_vec())),
                    (ciborium::Value::Integer(2.into()), ciborium::Value::Bytes(pcr2.to_vec())),
                ]),
            ),
            (ciborium::Value::Text("certificate".into()), ciborium::Value::Bytes(chain.leaf_der.clone())),
            (
                ciborium::Value::Text("cabundle".into()),
                ciborium::Value::Array(vec![
                    ciborium::Value::Bytes(chain.root_der.clone()),
                    ciborium::Value::Bytes(chain.int_der.clone()),
                ]),
            ),
            (ciborium::Value::Text("public_key".into()), ciborium::Value::Bytes(pk_bytes.to_vec())),
            (ciborium::Value::Text("user_data".into()), ciborium::Value::Bytes(report_data.to_vec())),
            (ciborium::Value::Text("nonce".into()), ciborium::Value::Bytes(nonce.to_vec())),
        ]);
        let mut payload_bytes = Vec::new();
        ciborium::into_writer(&payload_val, &mut payload_bytes).unwrap();

        let protected = coset::HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES384)
            .build();
        let cose = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload_bytes)
            .create_signature(&[], |tbs| {
                let sig: P384Signature = chain.leaf_sk.sign(tbs);
                sig.to_bytes().to_vec()
            })
            .build();
        let raw_cose = cose.to_tagged_vec().unwrap();

        let quote = TeeAttestationQuote {
            vendor: TeeVendor::AwsNitro,
            public_key_hex: hex::encode(pk_bytes),
            workload_measurement_hex: hex::encode(pcr0),
            report_data_hex: hex::encode(report_data),
            nonce_hex: hex::encode(nonce),
            migration_disabled: true,
            debug_disabled: !pcr0.iter().all(|&b| b == 0),
            secure_tsc_enabled: false,
            gpu_binding: None,
            raw_quote_b64: base64::engine::general_purpose::STANDARD.encode(&raw_cose),
            vendor_cert_chain_pem: Vec::new(),
            generated_at_unix_s: ts_unix_s,
        };
        (raw_cose, quote)
    }

    #[test]
    fn test_pinned_aws_nitro_root_g1_cert_parses_and_self_verifies() {
        let der = pinned_aws_nitro_root_der().unwrap();
        let (_, root) = X509Certificate::from_der(&der).unwrap();
        assert!(root.subject().to_string().contains("aws.nitro-enclaves"));
        verify_x509_sig_p384(&root, &root).unwrap();
    }

    #[test]
    fn test_nitro_cose_valid_chain_and_negative_security_cases() {
        let chain = build_synthetic_p384_chain();
        let kp = WorkloadKeypair::generate();
        let nonce = b"pog-nitro-fresh-nonce-2026";
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let pcr0 = [0xA1u8; 48];
        let pcr1 = [0xB2u8; 48];
        let pcr2 = [0xC3u8; 48];

        let (raw_cose, quote) = sign_synthetic_nitro_quote(&chain, &kp, nonce, pcr0, pcr1, pcr2, now);
        let mut pol = AttestationPolicy::production();
        pol.allowed_measurements = vec![hex::encode(pcr0)];
        pol.allowed_pcr1 = vec![hex::encode(pcr1)];
        pol.allowed_pcr2 = vec![hex::encode(pcr2)];

        // 1. Valid synthetic chain passes against its own test root.
        let verified = verify_nitro_cose_with_trust_root(
            &raw_cose,
            &chain.root_der,
            &quote,
            nonce,
            &pol,
            now + 5,
        )
        .unwrap();
        assert_eq!(verified.pcr0_hex, hex::encode(pcr0));

        // 2. Same synthetic chain MUST FAIL against the real pinned AWS Nitro Root-G1 CA!
        assert!(
            verify_quote(&quote, nonce, &pol, now + 5).is_err(),
            "Self-signed / unpinned Nitro CA chain MUST be rejected by pinned AWS Nitro Root-G1!"
        );

        // 3. Tampered COSE signature MUST fail.
        let mut bad_cose = raw_cose.clone();
        let last = bad_cose.len() - 1;
        bad_cose[last] ^= 0xFF;
        assert!(verify_nitro_cose_with_trust_root(&bad_cose, &chain.root_der, &quote, nonce, &pol, now + 5).is_err());

        // 4. Nonce mismatch MUST fail.
        assert!(verify_nitro_cose_with_trust_root(&raw_cose, &chain.root_der, &quote, b"wrong-nonce", &pol, now + 5).is_err());

        // 5. Expired timestamp MUST fail.
        assert!(verify_nitro_cose_with_trust_root(&raw_cose, &chain.root_der, &quote, nonce, &pol, now + 7200).is_err());

        // 6. Future timestamp beyond skew MUST fail.
        assert!(verify_nitro_cose_with_trust_root(&raw_cose, &chain.root_der, &quote, nonce, &pol, now.saturating_sub(1000)).is_err());

        // 7. Wrong PCR0 allowlist MUST fail.
        let mut bad_pcr_pol = pol.clone();
        bad_pcr_pol.allowed_measurements = vec![hex::encode([0x99u8; 48])];
        assert!(verify_nitro_cose_with_trust_root(&raw_cose, &chain.root_der, &quote, nonce, &bad_pcr_pol, now + 5).is_err());

        // 8. Debug-mode all-zero PCR0 MUST fail under production policy.
        let (dbg_cose, dbg_quote) = sign_synthetic_nitro_quote(&chain, &kp, nonce, [0u8; 48], pcr1, pcr2, now);
        assert!(verify_nitro_cose_with_trust_root(&dbg_cose, &chain.root_der, &dbg_quote, nonce, &AttestationPolicy::production(), now + 5).is_err());

        // 9. Legacy fake JSON payload MUST be rejected immediately!
        let fake_json = serde_json::json!({
            "module_id": "i-fake",
            "digest": "SHA384",
            "timestamp_ms": now * 1000,
            "pcr0_hex": hex::encode(pcr0),
            "public_key_hex": kp.public_key_hex(),
            "user_data_hex": quote.report_data_hex,
            "nonce_hex": hex::encode(nonce),
        });
        let mut fake_quote = quote.clone();
        fake_quote.raw_quote_b64 = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&fake_json).unwrap());
        assert!(verify_raw_nitro_doc(&fake_quote, nonce, &AttestationPolicy::production(), now + 5).is_err());
    }
}
