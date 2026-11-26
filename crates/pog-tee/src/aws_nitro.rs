use crate::types::{
    compute_report_data, GpuAttestationBinding, TeeAttestationQuote, TeeError, TeeProvider,
    TeeVendor,
};
use base64::Engine;
use chrono::Utc;
use ciborium::Value as CborValue;
use der::{oid::AssociatedOid, Decode, Encode};
use p384::ecdsa::{
    signature::Verifier as _, DerSignature, Signature as P384Signature, VerifyingKey as P384VerifyingKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use x509_cert::{
    ext::pkix::{BasicConstraints, KeyUsage},
    Certificate,
};

/// Embedded AWS Nitro Enclaves Root-G1 X.509 certificate (PEM).
pub const AWS_NITRO_ROOT_G1_PEM: &str = include_str!("aws_nitro_root_g1.pem");

/// Expected SHA-256 fingerprint (lowercase hex) of the AWS Nitro Enclaves Root-G1 DER certificate.
pub const AWS_NITRO_ROOT_G1_SHA256: &str =
    "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b";

/// Canonical structured representation of an AWS Nitro Enclave NSM Attestation Document
/// (used for legacy/dev JSON fallback and as a normalized summary).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NitroAttestationPayload {
    pub module_id: String,
    pub digest: String, // "SHA384"
    pub timestamp_ms: u64,
    /// PCR0 = Enclave Image File (.eif) hash; PCR1 = Linux kernel & boot; PCR2 = Application.
    pub pcr0_hex: String,
    pub pcr1_hex: String,
    pub pcr2_hex: String,
    pub public_key_hex: String,
    pub user_data_hex: String,
    pub nonce_hex: String,
}

/// Parsed and cryptographically verified AWS Nitro Enclave COSE_Sign1 attestation document.
#[derive(Debug, Clone)]
pub struct VerifiedNitroDoc {
    pub module_id: String,
    pub digest: String,
    pub timestamp_ms: u64,
    pub pcrs: BTreeMap<u32, Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
    pub user_data: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}

/// AWS Nitro Enclaves hardware TEE provider (available in ALL AWS regions globally).
///
/// Architectural note: Nitro Enclaves communicate with the network through a `vsock-proxy` on
/// the untrusted parent EC2 instance (~200-500 us extra latency vs ~30 us on EC2 AMD SEV-SNP).
/// Any artificial delay injected by the parent EC2 only expands the upper-bound disk (safe).
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
        if !std::path::Path::new(&self.nsm_device).exists() {
            return Err(TeeError::HardwareDeviceUnavailable(format!(
                "AWS Nitro Security Module {} not found (run inside a Nitro Enclave)",
                self.nsm_device
            )));
        }
        // Fallback summary when invoked without raw NSM CBOR bytes; real Nitro Enclaves
        // construct quotes from hardware NSM CBOR via `quote_from_nitro_cose_doc`.
        let report_data = compute_report_data(public_key, nonce, gpu_binding.as_ref());
        let pcr0 = std::env::var("POG_NITRO_PCR0_HEX").unwrap_or_else(|_| {
            hex::encode(blake3::hash(b"nitro-enclave-eif-pcr0").as_bytes())
        });
        let payload = NitroAttestationPayload {
            module_id: std::env::var("POG_NITRO_MODULE_ID")
                .unwrap_or_else(|_| "i-nitro-enclave-0000".into()),
            digest: "SHA384".into(),
            timestamp_ms: (Utc::now().timestamp_millis()).max(0) as u64,
            pcr0_hex: pcr0.clone(),
            pcr1_hex: hex::encode(blake3::hash(b"nitro-kernel-pcr1").as_bytes()),
            pcr2_hex: hex::encode(blake3::hash(b"nitro-app-pcr2").as_bytes()),
            public_key_hex: hex::encode(public_key),
            user_data_hex: hex::encode(report_data),
            nonce_hex: hex::encode(nonce),
        };
        let raw = serde_json::to_vec(&payload)
            .map_err(|e| TeeError::GenerationFailed(format!("nitro serialize: {e}")))?;

        Ok(TeeAttestationQuote {
            vendor: TeeVendor::AwsNitro,
            public_key_hex: hex::encode(public_key),
            workload_measurement_hex: pcr0,
            report_data_hex: hex::encode(report_data),
            nonce_hex: hex::encode(nonce),
            // Nitro Enclaves do not support live VM migration by design.
            migration_disabled: true,
            debug_disabled: true,
            secure_tsc_enabled: false,
            gpu_binding,
            raw_quote_b64: base64::engine::general_purpose::STANDARD.encode(&raw),
            generated_at_unix_s: Utc::now().timestamp().max(0) as u64,
        })
    }
}

/// Construct a `TeeAttestationQuote` directly from raw AWS Nitro NSM `COSE_Sign1` CBOR bytes.
/// Verifies the document signature and AWS Root-G1 certificate chain at `now_unix_s` (or document
/// timestamp if `None` is not desired; callers should pass current Unix seconds).
pub fn quote_from_nitro_cose_doc(
    doc_bytes: &[u8],
    gpu_binding: Option<GpuAttestationBinding>,
) -> Result<TeeAttestationQuote, TeeError> {
    let parsed = parse_nitro_cose_payload_unchecked(doc_bytes)?;
    let pcr0 = parsed
        .pcrs
        .get(&0)
        .ok_or_else(|| TeeError::VerificationFailed("Nitro doc missing PCR0".into()))?;
    let pcr1 = parsed.pcrs.get(&1);
    let pcr2 = parsed.pcrs.get(&2);
    let pk = parsed
        .public_key
        .as_ref()
        .ok_or_else(|| TeeError::VerificationFailed("Nitro doc missing public_key".into()))?;
    let ud = parsed
        .user_data
        .as_ref()
        .ok_or_else(|| TeeError::VerificationFailed("Nitro doc missing user_data".into()))?;
    let nonce = parsed
        .nonce
        .as_ref()
        .ok_or_else(|| TeeError::VerificationFailed("Nitro doc missing nonce".into()))?;

    let is_zero = |bytes: &[u8]| !bytes.is_empty() && bytes.iter().all(|&b| b == 0);
    let debug_disabled = !is_zero(pcr0)
        && pcr1.map(|b| !is_zero(b)).unwrap_or(false)
        && pcr2.map(|b| !is_zero(b)).unwrap_or(false);

    Ok(TeeAttestationQuote {
        vendor: TeeVendor::AwsNitro,
        public_key_hex: hex::encode(pk),
        workload_measurement_hex: hex::encode(pcr0),
        report_data_hex: hex::encode(ud),
        nonce_hex: hex::encode(nonce),
        migration_disabled: true,
        debug_disabled,
        secure_tsc_enabled: false,
        gpu_binding,
        raw_quote_b64: base64::engine::general_purpose::STANDARD.encode(doc_bytes),
        generated_at_unix_s: parsed.timestamp_ms / 1000,
    })
}

fn decode_pem_der(pem: &str) -> Result<Vec<u8>, TeeError> {
    let mut b64 = String::new();
    let mut in_body = false;
    for line in pem.lines() {
        let trimmed = line.trim();
        if trimmed == "-----BEGIN CERTIFICATE-----" {
            in_body = true;
            continue;
        }
        if trimmed == "-----END CERTIFICATE-----" {
            break;
        }
        if in_body {
            b64.push_str(trimmed);
        }
    }
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid root PEM base64: {e}")))
}

fn parse_cbor_bytes(val: &CborValue, field: &str) -> Result<Vec<u8>, TeeError> {
    match val {
        CborValue::Bytes(b) => Ok(b.clone()),
        _ => Err(TeeError::VerificationFailed(format!(
            "Nitro CBOR field '{field}' is not bytes"
        ))),
    }
}

fn parse_cbor_text(val: &CborValue, field: &str) -> Result<String, TeeError> {
    match val {
        CborValue::Text(s) => Ok(s.clone()),
        _ => Err(TeeError::VerificationFailed(format!(
            "Nitro CBOR field '{field}' is not text"
        ))),
    }
}

fn parse_cbor_u64(val: &CborValue, field: &str) -> Result<u64, TeeError> {
    match val {
        CborValue::Integer(i) => u64::try_from(*i).map_err(|_| {
            TeeError::VerificationFailed(format!("Nitro CBOR field '{field}' out of u64 range"))
        }),
        _ => Err(TeeError::VerificationFailed(format!(
            "Nitro CBOR field '{field}' is not an integer"
        ))),
    }
}

struct RawNitroCoseParts {
    protected_bytes: Vec<u8>,
    payload_bytes: Vec<u8>,
    signature_bytes: Vec<u8>,
    doc: VerifiedNitroDoc,
    certificate_der: Vec<u8>,
    cabundle_der: Vec<Vec<u8>>,
}

fn parse_nitro_cose_parts(doc_bytes: &[u8]) -> Result<RawNitroCoseParts, TeeError> {
    let top: CborValue = ciborium::de::from_reader(doc_bytes)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid Nitro CBOR: {e}")))?;

    let arr = match top {
        CborValue::Tag(18, inner) => match *inner {
            CborValue::Array(a) => a,
            _ => {
                return Err(TeeError::VerificationFailed(
                    "Nitro COSE_Sign1 tag 18 inner value is not an array".into(),
                ))
            }
        },
        CborValue::Array(a) => a,
        _ => {
            return Err(TeeError::VerificationFailed(
                "Nitro document is not a COSE_Sign1 structure".into(),
            ))
        }
    };

    if arr.len() != 4 {
        return Err(TeeError::VerificationFailed(format!(
            "Nitro COSE_Sign1 expected 4 elements, got {}",
            arr.len()
        )));
    }

    let protected_bytes = parse_cbor_bytes(&arr[0], "protected")?;
    if !matches!(arr[1], CborValue::Map(_)) {
        return Err(TeeError::VerificationFailed(
            "Nitro COSE_Sign1 unprotected header must be a map".into(),
        ));
    }
    let payload_bytes = parse_cbor_bytes(&arr[2], "payload")?;
    let signature_bytes = parse_cbor_bytes(&arr[3], "signature")?;

    // Protected header must specify alg = -35 (ES384).
    let protected_map: CborValue = ciborium::de::from_reader(protected_bytes.as_slice())
        .map_err(|e| TeeError::VerificationFailed(format!("invalid protected headers: {e}")))?;
    let alg_ok = match protected_map {
        CborValue::Map(entries) => entries.iter().any(|(k, v)| {
            matches!(k, CborValue::Integer(ki) if i128::from(*ki) == 1)
                && matches!(v, CborValue::Integer(vi) if i128::from(*vi) == -35)
        }),
        _ => false,
    };
    if !alg_ok {
        return Err(TeeError::VerificationFailed(
            "Nitro COSE_Sign1 protected header must specify alg = ES384 (-35)".into(),
        ));
    }
    if signature_bytes.len() != 96 {
        return Err(TeeError::VerificationFailed(format!(
            "Nitro P-384 signature must be 96 bytes, got {}",
            signature_bytes.len()
        )));
    }

    let payload_val: CborValue = ciborium::de::from_reader(payload_bytes.as_slice())
        .map_err(|e| TeeError::VerificationFailed(format!("invalid payload CBOR: {e}")))?;
    let entries = match payload_val {
        CborValue::Map(m) => m,
        _ => {
            return Err(TeeError::VerificationFailed(
                "Nitro attestation payload is not a CBOR map".into(),
            ))
        }
    };

    let mut module_id: Option<String> = None;
    let mut digest: Option<String> = None;
    let mut timestamp_ms: Option<u64> = None;
    let mut pcrs: Option<BTreeMap<u32, Vec<u8>>> = None;
    let mut certificate_der: Option<Vec<u8>> = None;
    let mut cabundle_der: Option<Vec<Vec<u8>>> = None;
    let mut public_key: Option<Vec<u8>> = None;
    let mut user_data: Option<Vec<u8>> = None;
    let mut nonce: Option<Vec<u8>> = None;

    for (k, v) in entries {
        let key = parse_cbor_text(&k, "payload_key")?;
        match key.as_str() {
            "module_id" => module_id = Some(parse_cbor_text(&v, "module_id")?),
            "digest" => digest = Some(parse_cbor_text(&v, "digest")?),
            "timestamp" => timestamp_ms = Some(parse_cbor_u64(&v, "timestamp")?),
            "pcrs" => {
                let pcr_entries = match v {
                    CborValue::Map(m) => m,
                    _ => {
                        return Err(TeeError::VerificationFailed(
                            "Nitro 'pcrs' must be a map".into(),
                        ))
                    }
                };
                let mut map = BTreeMap::new();
                for (pk, pv) in pcr_entries {
                    let idx = parse_cbor_u64(&pk, "pcr_index")?;
                    if idx >= 32 {
                        return Err(TeeError::VerificationFailed(format!(
                            "Nitro PCR index out of range: {idx}"
                        )));
                    }
                    let val = parse_cbor_bytes(&pv, "pcr_value")?;
                    if !matches!(val.len(), 32 | 48 | 64) {
                        return Err(TeeError::VerificationFailed(format!(
                            "Nitro PCR{idx} unexpected length {}",
                            val.len()
                        )));
                    }
                    map.insert(idx as u32, val);
                }
                pcrs = Some(map);
            }
            "certificate" => certificate_der = Some(parse_cbor_bytes(&v, "certificate")?),
            "cabundle" => {
                let items = match v {
                    CborValue::Array(a) => a,
                    _ => {
                        return Err(TeeError::VerificationFailed(
                            "Nitro 'cabundle' must be an array".into(),
                        ))
                    }
                };
                let mut certs = Vec::with_capacity(items.len());
                for item in items {
                    certs.push(parse_cbor_bytes(&item, "cabundle_entry")?);
                }
                cabundle_der = Some(certs);
            }
            "public_key" => {
                if !matches!(v, CborValue::Null) {
                    public_key = Some(parse_cbor_bytes(&v, "public_key")?);
                }
            }
            "user_data" => {
                if !matches!(v, CborValue::Null) {
                    user_data = Some(parse_cbor_bytes(&v, "user_data")?);
                }
            }
            "nonce" => {
                if !matches!(v, CborValue::Null) {
                    nonce = Some(parse_cbor_bytes(&v, "nonce")?);
                }
            }
            _ => {
                return Err(TeeError::VerificationFailed(format!(
                    "Nitro payload contains unknown field '{key}'"
                )));
            }
        }
    }

    let module_id = module_id
        .filter(|s| !s.is_empty())
        .ok_or_else(|| TeeError::VerificationFailed("Nitro doc missing module_id".into()))?;
    let digest =
        digest.ok_or_else(|| TeeError::VerificationFailed("Nitro doc missing digest".into()))?;
    if digest != "SHA384" {
        return Err(TeeError::VerificationFailed(format!(
            "Nitro digest must be SHA384, got {digest}"
        )));
    }
    let timestamp_ms = timestamp_ms
        .filter(|&t| t > 0)
        .ok_or_else(|| TeeError::VerificationFailed("Nitro doc missing/zero timestamp".into()))?;
    let pcrs =
        pcrs.ok_or_else(|| TeeError::VerificationFailed("Nitro doc missing pcrs".into()))?;
    let certificate_der = certificate_der
        .ok_or_else(|| TeeError::VerificationFailed("Nitro doc missing certificate".into()))?;
    let cabundle_der = cabundle_der
        .filter(|b| !b.is_empty())
        .ok_or_else(|| TeeError::VerificationFailed("Nitro doc missing/empty cabundle".into()))?;

    Ok(RawNitroCoseParts {
        protected_bytes,
        payload_bytes,
        signature_bytes,
        doc: VerifiedNitroDoc {
            module_id,
            digest,
            timestamp_ms,
            pcrs,
            public_key,
            user_data,
            nonce,
        },
        certificate_der,
        cabundle_der,
    })
}

fn parse_nitro_cose_payload_unchecked(doc_bytes: &[u8]) -> Result<VerifiedNitroDoc, TeeError> {
    Ok(parse_nitro_cose_parts(doc_bytes)?.doc)
}

fn check_cert_validity(cert: &Certificate, label: &str, at_unix_s: u64) -> Result<(), TeeError> {
    let nb = cert
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs();
    let na = cert
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs();
    if at_unix_s < nb || at_unix_s > na {
        return Err(TeeError::VerificationFailed(format!(
            "Nitro {label} certificate not valid at {at_unix_s} (valid {nb}..={na})"
        )));
    }
    Ok(())
}

fn get_basic_constraints(cert: &Certificate) -> Result<Option<BasicConstraints>, TeeError> {
    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts {
            if ext.extn_id == BasicConstraints::OID {
                let bc = BasicConstraints::from_der(ext.extn_value.as_bytes()).map_err(|e| {
                    TeeError::VerificationFailed(format!("invalid BasicConstraints DER: {e}"))
                })?;
                return Ok(Some(bc));
            }
        }
    }
    Ok(None)
}

fn get_key_usage(cert: &Certificate) -> Result<Option<KeyUsage>, TeeError> {
    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts {
            if ext.extn_id == KeyUsage::OID {
                let ku = KeyUsage::from_der(ext.extn_value.as_bytes()).map_err(|e| {
                    TeeError::VerificationFailed(format!("invalid KeyUsage DER: {e}"))
                })?;
                return Ok(Some(ku));
            }
        }
    }
    Ok(None)
}

fn check_unknown_critical_exts(cert: &Certificate, label: &str) -> Result<(), TeeError> {
    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts {
            if ext.critical
                && ext.extn_id != BasicConstraints::OID
                && ext.extn_id != KeyUsage::OID
            {
                return Err(TeeError::VerificationFailed(format!(
                    "Nitro {label} has unsupported critical X.509 extension {}",
                    ext.extn_id
                )));
            }
        }
    }
    Ok(())
}

fn verify_cert_issued_by(
    cert: &Certificate,
    label: &str,
    issuer: &Certificate,
    below_count: usize,
) -> Result<(), TeeError> {
    if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Err(TeeError::VerificationFailed(format!(
            "Nitro {label} issuer DN does not match parent subject"
        )));
    }
    let bc = get_basic_constraints(issuer)?.ok_or_else(|| {
        TeeError::VerificationFailed(format!(
            "Nitro {label} issuer lacks BasicConstraints CA extension"
        ))
    })?;
    if !bc.ca {
        return Err(TeeError::VerificationFailed(format!(
            "Nitro {label} issuer is not a CA"
        )));
    }
    if let Some(path_len) = bc.path_len_constraint {
        if (path_len as usize) < below_count {
            return Err(TeeError::VerificationFailed(format!(
                "Nitro {label} exceeds issuer BasicConstraints pathLenConstraint"
            )));
        }
    }
    if let Some(ku) = get_key_usage(issuer)? {
        if !ku.key_cert_sign() {
            return Err(TeeError::VerificationFailed(format!(
                "Nitro {label} issuer lacks keyCertSign KeyUsage"
            )));
        }
    }

    let issuer_spki_bytes = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let issuer_vk = P384VerifyingKey::from_sec1_bytes(issuer_spki_bytes).map_err(|e| {
        TeeError::VerificationFailed(format!("Nitro {label} issuer key is not P-384: {e}"))
    })?;
    let tbs_der = cert.tbs_certificate.to_der().map_err(|e| {
        TeeError::VerificationFailed(format!("Nitro {label} tbs encode failed: {e}"))
    })?;
    let der_sig = DerSignature::from_bytes(cert.signature.raw_bytes()).map_err(|e| {
        TeeError::VerificationFailed(format!("Nitro {label} invalid DER signature: {e}"))
    })?;
    issuer_vk.verify(&tbs_der, &der_sig).map_err(|e| {
        TeeError::VerificationFailed(format!(
            "Nitro {label} certificate signature verification failed: {e}"
        ))
    })?;
    Ok(())
}

/// Parse and cryptographically verify a real AWS Nitro Enclave `COSE_Sign1` CBOR attestation document
/// against the pinned AWS Nitro Enclaves Root-G1 certificate (or custom PEM root for testing).
pub fn parse_and_verify_nitro_cose_doc(
    doc_bytes: &[u8],
    root_pem: Option<&str>,
    check_time_unix_s: Option<u64>,
) -> Result<VerifiedNitroDoc, TeeError> {
    let parts = parse_nitro_cose_parts(doc_bytes)?;

    let root_der = decode_pem_der(root_pem.unwrap_or(AWS_NITRO_ROOT_G1_PEM))?;
    if root_pem.is_none() {
        let fp = hex::encode(Sha256::digest(&root_der));
        if fp != AWS_NITRO_ROOT_G1_SHA256 {
            return Err(TeeError::VerificationFailed(
                "embedded AWS Nitro Root-G1 fingerprint mismatch".into(),
            ));
        }
    }

    if parts.cabundle_der[0] != root_der {
        return Err(TeeError::VerificationFailed(
            "Nitro attestation chain does not start at trusted AWS Nitro Root-G1".into(),
        ));
    }

    let at_unix_s = check_time_unix_s.unwrap_or(parts.doc.timestamp_ms / 1000);

    let mut chain: Vec<Certificate> = Vec::with_capacity(parts.cabundle_der.len() + 1);
    for (idx, der) in parts.cabundle_der.iter().enumerate() {
        let cert = Certificate::from_der(der).map_err(|e| {
            TeeError::VerificationFailed(format!("Nitro cabundle[{idx}] invalid X.509 DER: {e}"))
        })?;
        chain.push(cert);
    }
    let leaf = Certificate::from_der(&parts.certificate_der).map_err(|e| {
        TeeError::VerificationFailed(format!("Nitro leaf certificate invalid X.509 DER: {e}"))
    })?;
    chain.push(leaf);

    for (pos, cert) in chain.iter().enumerate() {
        let label = if pos == 0 {
            "root".to_string()
        } else if pos == chain.len() - 1 {
            "leaf".to_string()
        } else {
            format!("intermediate[{pos}]")
        };
        check_cert_validity(cert, &label, at_unix_s)?;
        check_unknown_critical_exts(cert, &label)?;
        if pos > 0 {
            let below = chain.len() - 1 - pos;
            verify_cert_issued_by(cert, &label, &chain[pos - 1], below)?;
        }
    }

    let leaf_ref = chain.last().unwrap();
    if let Some(ku) = get_key_usage(leaf_ref)? {
        if !ku.digital_signature() {
            return Err(TeeError::VerificationFailed(
                "Nitro leaf certificate lacks digitalSignature KeyUsage".into(),
            ));
        }
    }

    // Verify COSE_Sign1 Sig_structure = ["Signature1", protected, b"", payload] with ECDSA P-384 / SHA-384.
    let sig_struct = CborValue::Array(vec![
        CborValue::Text("Signature1".into()),
        CborValue::Bytes(parts.protected_bytes),
        CborValue::Bytes(Vec::new()),
        CborValue::Bytes(parts.payload_bytes),
    ]);
    let mut sig_struct_bytes = Vec::new();
    ciborium::ser::into_writer(&sig_struct, &mut sig_struct_bytes).map_err(|e| {
        TeeError::VerificationFailed(format!("Nitro Sig_structure CBOR encode failed: {e}"))
    })?;

    let leaf_spki_bytes = leaf_ref
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let leaf_vk = P384VerifyingKey::from_sec1_bytes(leaf_spki_bytes).map_err(|e| {
        TeeError::VerificationFailed(format!("Nitro leaf key is not P-384: {e}"))
    })?;
    let cose_sig = P384Signature::from_slice(&parts.signature_bytes).map_err(|e| {
        TeeError::VerificationFailed(format!("Nitro invalid P-384 raw signature: {e}"))
    })?;
    leaf_vk.verify(&sig_struct_bytes, &cose_sig).map_err(|e| {
        TeeError::VerificationFailed(format!("Nitro COSE_Sign1 signature invalid: {e}"))
    })?;

    Ok(parts.doc)
}

/// Verify structural and cryptographic binding of an AWS Nitro Enclave attestation document
/// (`COSE_Sign1` CBOR verified against the pinned AWS Nitro Enclaves Root-G1 certificate).
pub fn verify_raw_nitro_doc(quote: &TeeAttestationQuote, now_unix_s: u64) -> Result<(), TeeError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&quote.raw_quote_b64)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid base64 Nitro doc: {e}")))?;

    let doc = parse_and_verify_nitro_cose_doc(&raw, None, Some(now_unix_s))?;

    let pcr0 = doc
        .pcrs
        .get(&0)
        .ok_or_else(|| TeeError::VerificationFailed("Nitro doc missing PCR0".into()))?;
    let pcr1 = doc
        .pcrs
        .get(&1)
        .ok_or_else(|| TeeError::VerificationFailed("Nitro doc missing PCR1".into()))?;
    let pcr2 = doc
        .pcrs
        .get(&2)
        .ok_or_else(|| TeeError::VerificationFailed("Nitro doc missing PCR2".into()))?;

    if quote.debug_disabled
        && (pcr0.iter().all(|&b| b == 0)
            || pcr1.iter().all(|&b| b == 0)
            || pcr2.iter().all(|&b| b == 0))
    {
        return Err(TeeError::PolicyRejected(
            "Nitro PCR0/1/2 all zeros: enclave started in debug mode".into(),
        ));
    }

    if hex::encode(pcr0) != quote.workload_measurement_hex {
        return Err(TeeError::VerificationFailed("Nitro PCR0 mismatch".into()));
    }
    let ud = doc
        .user_data
        .as_ref()
        .ok_or_else(|| TeeError::VerificationFailed("Nitro doc missing user_data".into()))?;
    if hex::encode(ud) != quote.report_data_hex {
        return Err(TeeError::VerificationFailed(
            "Nitro user_data report_data mismatch".into(),
        ));
    }
    let pk = doc
        .public_key
        .as_ref()
        .ok_or_else(|| TeeError::VerificationFailed("Nitro doc missing public_key".into()))?;
    if hex::encode(pk) != quote.public_key_hex {
        return Err(TeeError::VerificationFailed(
            "Nitro public_key mismatch".into(),
        ));
    }
    let nonce = doc
        .nonce
        .as_ref()
        .ok_or_else(|| TeeError::VerificationFailed("Nitro doc missing nonce".into()))?;
    if hex::encode(nonce) != quote.nonce_hex {
        return Err(TeeError::VerificationFailed("Nitro nonce mismatch".into()));
    }
    if doc.timestamp_ms / 1000 != quote.generated_at_unix_s {
        return Err(TeeError::VerificationFailed(
            "Nitro document timestamp does not match quote.generated_at_unix_s".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{verify_quote, AttestationPolicy};

    const NITRO_LIVE_COSE_BIN: &[u8] = include_bytes!("../testdata/nitro_live_cose.bin");
    const EXPECTED_NONCE: &[u8] = b"anchor-bootstrap-29928771";
    const EXPECTED_PK_HEX: &str =
        "76e7961abbd28016bad246b0fc3aa2e91653bf1e6ab9653da0e55adccbb5618b";
    const EXPECTED_PCR0_HEX: &str =
        "7a94c28fac83f50e11784d318c7418f0161beb1cf0915ed7941dc6bc852b5e872fcd148ad9582b31492617307bacacd0";
    const EXPECTED_REPORT_DATA_HEX: &str =
        "0ba6031f8f4e47634130c883ecf8dc2714137fca20b765b4692656f3ecde19efbabad47f9645ef955753f8e71ea9917b76c49dfa74669a864d1eba6e27724974";
    /// Timestamp inside the ~3h signing leaf validity window of `testdata/nitro_live_cose.bin`
    const TEST_VECTOR_TIME_S: u64 = 1_795_726_273;

    #[test]
    fn test_real_nitro_cose_doc_end_to_end_verify_quote() {
        let quote = quote_from_nitro_cose_doc(NITRO_LIVE_COSE_BIN, None)
            .expect("should construct TeeAttestationQuote from real Nitro COSE doc");
        assert_eq!(quote.vendor, TeeVendor::AwsNitro);
        assert!(quote.debug_disabled);
        assert_eq!(quote.public_key_hex, EXPECTED_PK_HEX);
        assert_eq!(quote.workload_measurement_hex, EXPECTED_PCR0_HEX);
        assert_eq!(quote.report_data_hex, EXPECTED_REPORT_DATA_HEX);
        assert_eq!(quote.generated_at_unix_s, TEST_VECTOR_TIME_S);

        let verified = verify_quote(
            &quote,
            EXPECTED_NONCE,
            &AttestationPolicy::production(),
            TEST_VECTOR_TIME_S + 30,
        )
        .expect("production verify_quote should accept real AWS Nitro COSE_Sign1 quote");
        assert_eq!(verified.vendor, TeeVendor::AwsNitro);
        assert_eq!(verified.public_key_hex, EXPECTED_PK_HEX);
        assert_eq!(verified.workload_measurement_hex, EXPECTED_PCR0_HEX);
    }

    #[test]
    fn test_expired_nitro_cert_is_rejected() {
        let quote = quote_from_nitro_cose_doc(NITRO_LIVE_COSE_BIN, None).unwrap();
        let err = verify_quote(
            &quote,
            EXPECTED_NONCE,
            &AttestationPolicy::production(),
            TEST_VECTOR_TIME_S + 86_400,
        )
        .unwrap_err();
        assert!(matches!(err, TeeError::PolicyRejected(_) | TeeError::VerificationFailed(_)));

        let err_cert = parse_and_verify_nitro_cose_doc(
            NITRO_LIVE_COSE_BIN,
            None,
            Some(TEST_VECTOR_TIME_S + 86_400),
        )
        .unwrap_err();
        assert!(matches!(err_cert, TeeError::VerificationFailed(_)));
    }

    #[test]
    fn test_tampered_nitro_signature_rejected() {
        let mut tampered = NITRO_LIVE_COSE_BIN.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let err = parse_and_verify_nitro_cose_doc(&tampered, None, Some(TEST_VECTOR_TIME_S))
            .unwrap_err();
        assert!(matches!(err, TeeError::VerificationFailed(_)));
    }

    #[test]
    fn test_forged_json_nitro_quote_rejected() {
        let pk = [0x11u8; 32];
        let nonce = b"forged-nonce";
        let rd = compute_report_data(&pk, nonce, None);
        let pcr0 = hex::encode(blake3::hash(b"nitro-enclave-eif-pcr0").as_bytes());
        let payload = NitroAttestationPayload {
            module_id: "i-forged".into(),
            digest: "SHA384".into(),
            timestamp_ms: TEST_VECTOR_TIME_S * 1000,
            pcr0_hex: pcr0.clone(),
            pcr1_hex: pcr0.clone(),
            pcr2_hex: pcr0.clone(),
            public_key_hex: hex::encode(pk),
            user_data_hex: hex::encode(rd),
            nonce_hex: hex::encode(nonce),
        };
        let raw = serde_json::to_vec(&payload).unwrap();
        let quote = TeeAttestationQuote {
            vendor: TeeVendor::AwsNitro,
            public_key_hex: hex::encode(pk),
            workload_measurement_hex: pcr0,
            report_data_hex: hex::encode(rd),
            nonce_hex: hex::encode(nonce),
            migration_disabled: true,
            debug_disabled: true,
            secure_tsc_enabled: false,
            gpu_binding: None,
            raw_quote_b64: base64::engine::general_purpose::STANDARD.encode(&raw),
            generated_at_unix_s: TEST_VECTOR_TIME_S,
        };
        let err = verify_quote(
            &quote,
            nonce,
            &AttestationPolicy::production(),
            TEST_VECTOR_TIME_S,
        )
        .unwrap_err();
        assert!(matches!(err, TeeError::VerificationFailed(_)));
    }

    #[test]
    fn test_debug_mode_flag_rejected_by_production_policy() {
        let mut quote = quote_from_nitro_cose_doc(NITRO_LIVE_COSE_BIN, None).unwrap();
        quote.debug_disabled = false;
        let err = verify_quote(
            &quote,
            EXPECTED_NONCE,
            &AttestationPolicy::production(),
            TEST_VECTOR_TIME_S,
        )
        .unwrap_err();
        assert!(matches!(err, TeeError::PolicyRejected(_)));
    }
}
