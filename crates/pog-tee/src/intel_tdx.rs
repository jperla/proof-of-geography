use crate::types::{
    compute_report_data, AttestationPolicy, GpuAttestationBinding, TeeAttestationQuote, TeeError,
    TeeProvider, TeeVendor,
};
use base64::Engine;
use chrono::Utc;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

/// Official Intel SGX / TDX Provisioning Certification Root CA DER SHA-256 fingerprint
/// (from https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem).
pub const INTEL_SGX_ROOT_CA_SHA256_HEX: &str =
    "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3";
/// Default production allowlist of pinned official Intel SGX/TDX Root CA DER SHA-256 digests.
pub const PINNED_INTEL_ROOT_SHA256_HEX: &[&str] = &[INTEL_SGX_ROOT_CA_SHA256_HEX];

/// Minimum Intel TDX Quote v4 header + TD Report Body length (48B header + 584B TD Report = 632B).
pub const TDX_QUOTE_MIN_LEN: usize = 48 + 584;
/// Offset of MRTD (48 bytes) inside the TD Report body (offset 136 from TD report body start -> 184 in quote).
pub const TDX_QUOTE_MRTD_OFFSET: usize = 48 + 136;
/// Offset of 64-byte `REPORTDATA` inside the TD Report body (offset 520 from body start -> 568 in quote).
pub const TDX_QUOTE_REPORTDATA_OFFSET: usize = 48 + 520;
/// Offset of 8-byte `TDATTRIBUTES` inside the TD Report body (offset 120 from body start -> 168 in quote).
pub const TDX_QUOTE_TDATTRIBUTES_OFFSET: usize = 48 + 120;
/// Bit 0 of `TDATTRIBUTES`: DEBUG (must be 0).
pub const TDX_ATTR_DEBUG_BIT: u64 = 1 << 0;
/// Bit 29 of `TDATTRIBUTES`: MIGRATABLE (must be 0).
pub const TDX_ATTR_MIGRATABLE_BIT: u64 = 1 << 29;

/// Intel TDX hardware TEE provider (GCP C3 Sapphire Rapids, Azure DCes_v5, ByteDance/Volcengine).
pub struct IntelTdxProvider {
    pub configfs_tsm_path: String,
}

impl Default for IntelTdxProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl IntelTdxProvider {
    pub fn new() -> Self {
        Self {
            configfs_tsm_path: "/sys/kernel/config/tsm/report".to_string(),
        }
    }

    #[cfg(target_os = "linux")]
    fn fetch_tdx_quote(&self, report_data: [u8; 64]) -> Result<Vec<u8>, TeeError> {
        use std::fs;
        use std::path::PathBuf;

        let report_dir = PathBuf::from(&self.configfs_tsm_path)
            .join(format!("pog_{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        fs::create_dir_all(&report_dir).map_err(|e| {
            TeeError::HardwareDeviceUnavailable(format!(
                "Cannot create ConfigFS TSM report dir {}: {e}",
                report_dir.display()
            ))
        })?;
        fs::write(report_dir.join("inblob"), report_data)
            .map_err(|e| TeeError::GenerationFailed(format!("TSM inblob write failed: {e}")))?;
        let out = fs::read(report_dir.join("outblob"))
            .map_err(|e| TeeError::GenerationFailed(format!("TSM outblob read failed: {e}")))?;
        let _ = fs::remove_dir(&report_dir);
        Ok(out)
    }

    #[cfg(not(target_os = "linux"))]
    fn fetch_tdx_quote(&self, _report_data: [u8; 64]) -> Result<Vec<u8>, TeeError> {
        Err(TeeError::HardwareDeviceUnavailable(
            "Intel TDX ConfigFS TSM requires Linux TDX Confidential VM".into(),
        ))
    }
}

impl TeeProvider for IntelTdxProvider {
    fn vendor(&self) -> TeeVendor {
        TeeVendor::IntelTdx
    }

    fn attest(
        &self,
        public_key: &[u8; 32],
        nonce: &[u8],
        gpu_binding: Option<GpuAttestationBinding>,
    ) -> Result<TeeAttestationQuote, TeeError> {
        let report_data = compute_report_data(public_key, nonce, gpu_binding.as_ref());
        let raw = self.fetch_tdx_quote(report_data)?;
        if raw.len() < TDX_QUOTE_MIN_LEN {
            return Err(TeeError::GenerationFailed(
                "TDX quote shorter than minimum v4 length".into(),
            ));
        }

        let attrs = u64::from_le_bytes(
            raw[TDX_QUOTE_TDATTRIBUTES_OFFSET..TDX_QUOTE_TDATTRIBUTES_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        let mrtd = &raw[TDX_QUOTE_MRTD_OFFSET..TDX_QUOTE_MRTD_OFFSET + 48];

        Ok(TeeAttestationQuote {
            vendor: TeeVendor::IntelTdx,
            public_key_hex: hex::encode(public_key),
            workload_measurement_hex: hex::encode(mrtd),
            report_data_hex: hex::encode(report_data),
            nonce_hex: hex::encode(nonce),
            migration_disabled: (attrs & TDX_ATTR_MIGRATABLE_BIT) == 0,
            debug_disabled: (attrs & TDX_ATTR_DEBUG_BIT) == 0,
            secure_tsc_enabled: true,
            gpu_binding,
            raw_quote_b64: base64::engine::general_purpose::STANDARD.encode(&raw),
            vendor_cert_chain_pem: Vec::new(),
            generated_at_unix_s: Utc::now().timestamp().max(0) as u64,
        })
    }
}

/// Structural + cryptographic verification of an Intel TDX v4 DCAP Quote against the pinned
/// official Intel SGX / TDX Provisioning Certification Root CA SHA-256 fingerprint.
///
/// Validates:
/// - Quote v4 header (`version == 4`, `att_key_type == 2` ECDSA-P256, `tee_type == 0x81` TDX)
/// - `REPORTDATA`, `MRTD`, `DEBUG == 0`, `MIGRATABLE == 0`
/// - Embedded DCAP ECDSA-P256 signature over `raw[0..632]` using the quote's attestation key,
///   QE Report binding (`SHA-256(att_pub_key || qe_auth_data) == qe_report.report_data[0..32]`),
///   PCK -> Intel Platform/Processor CA -> pinned Intel SGX Root CA X.509 P-256 chain!
///
/// Fails closed under `AttestationPolicy::production()` if signature data or pinned PCK chain fails.
pub fn verify_raw_tdx_quote(
    quote: &TeeAttestationQuote,
    policy: &AttestationPolicy,
    now_unix_s: u64,
) -> Result<bool, TeeError> {
    verify_raw_tdx_quote_with_pinned_roots(quote, policy, now_unix_s, PINNED_INTEL_ROOT_SHA256_HEX)
}

/// Same as `verify_raw_tdx_quote`, accepting explicit pinned Intel Root CA DER SHA-256 hex digests.
pub fn verify_raw_tdx_quote_with_pinned_roots(
    quote: &TeeAttestationQuote,
    policy: &AttestationPolicy,
    now_unix_s: u64,
    pinned_root_sha256_hex: &[&str],
) -> Result<bool, TeeError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&quote.raw_quote_b64)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid base64 TDX quote: {e}")))?;
    if raw.len() < TDX_QUOTE_MIN_LEN {
        return Err(TeeError::VerificationFailed(format!(
            "TDX quote too short: {} < {}",
            raw.len(),
            TDX_QUOTE_MIN_LEN
        )));
    }
    let embedded_rd = &raw[TDX_QUOTE_REPORTDATA_OFFSET..TDX_QUOTE_REPORTDATA_OFFSET + 64];
    if !hex::encode(embedded_rd).eq_ignore_ascii_case(&quote.report_data_hex) {
        return Err(TeeError::VerificationFailed(
            "TDX REPORTDATA bytes mismatch".into(),
        ));
    }
    let embedded_mrtd = &raw[TDX_QUOTE_MRTD_OFFSET..TDX_QUOTE_MRTD_OFFSET + 48];
    if !hex::encode(embedded_mrtd).eq_ignore_ascii_case(&quote.workload_measurement_hex) {
        return Err(TeeError::VerificationFailed(
            "TDX MRTD measurement mismatch".into(),
        ));
    }
    let attrs = u64::from_le_bytes(
        raw[TDX_QUOTE_TDATTRIBUTES_OFFSET..TDX_QUOTE_TDATTRIBUTES_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    if (attrs & TDX_ATTR_DEBUG_BIT) != 0 {
        return Err(TeeError::PolicyRejected("TDX DEBUG bit set".into()));
    }
    if (attrs & TDX_ATTR_MIGRATABLE_BIT) != 0 {
        return Err(TeeError::PolicyRejected("TDX MIGRATABLE bit set".into()));
    }

    // Parse TDX Quote v4 header & DCAP ECDSA-P256 signature data (starts at offset 632).
    let version = u16::from_le_bytes(raw[0..2].try_into().unwrap());
    let att_key_type = u16::from_le_bytes(raw[2..4].try_into().unwrap());
    let tee_type = u32::from_le_bytes(raw[4..8].try_into().unwrap());
    if version != 4 || att_key_type != 2 || tee_type != 0x0000_0081 {
        if policy.require_cryptographic_vendor_chain {
            return Err(TeeError::VerificationFailed(format!(
                "TDX v4 DCAP header invalid (version={version}, att_key_type={att_key_type}, tee_type={tee_type:#x})"
            )));
        }
        return Ok(false);
    }

    // Offset 632: 4-byte signature_data_len followed by 64B ECDSA sig + 64B ECDSA att_pub_key + cert_data.
    if raw.len() < TDX_QUOTE_MIN_LEN + 4 + 64 + 64 + 6 {
        if policy.require_cryptographic_vendor_chain {
            return Err(TeeError::VerificationFailed(
                "TDX v4 quote missing DCAP ECDSA-P256 signature & PCK cert data (fail-closed)"
                    .into(),
            ));
        }
        return Ok(false);
    }

    let sig_data_len =
        u32::from_le_bytes(raw[TDX_QUOTE_MIN_LEN..TDX_QUOTE_MIN_LEN + 4].try_into().unwrap())
            as usize;
    let sig_start = TDX_QUOTE_MIN_LEN + 4;
    if sig_start + sig_data_len > raw.len() || sig_data_len < 134 {
        return Err(TeeError::VerificationFailed(
            "TDX v4 signature_data_len truncated or out of bounds".into(),
        ));
    }
    let sig_bytes = &raw[sig_start..sig_start + 64];
    let att_pub_xy = &raw[sig_start + 64..sig_start + 128];

    // Verify ECDSA-P256 signature over header + TD report body (raw[0..632]).
    let mut sec1_pub = [0u8; 65];
    sec1_pub[0] = 0x04;
    sec1_pub[1..].copy_from_slice(att_pub_xy);
    let att_vk = P256VerifyingKey::from_sec1_bytes(&sec1_pub).map_err(|e| {
        TeeError::VerificationFailed(format!("invalid TDX attestation P-256 key: {e}"))
    })?;
    let sig = P256Signature::from_slice(sig_bytes).map_err(|e| {
        TeeError::VerificationFailed(format!("invalid TDX ECDSA P-256 signature: {e}"))
    })?;
    att_vk.verify(&raw[..TDX_QUOTE_MIN_LEN], &sig).map_err(|e| {
        TeeError::VerificationFailed(format!("TDX quote ECDSA-P256 signature invalid: {e}"))
    })?;

    // Parse QE Certification Data (type 6 = QE Report Certification Data in TDX v4).
    let cert_hdr_off = sig_start + 128;
    let cert_type = u16::from_le_bytes(raw[cert_hdr_off..cert_hdr_off + 2].try_into().unwrap());
    let cert_len =
        u32::from_le_bytes(raw[cert_hdr_off + 2..cert_hdr_off + 6].try_into().unwrap()) as usize;
    let cert_body_start = cert_hdr_off + 6;
    if cert_type != 6 || cert_body_start + cert_len > raw.len() || cert_len < 384 + 64 + 2 {
        return Err(TeeError::VerificationFailed(format!(
            "TDX v4 quote missing QE Report Certification Data (cert_type={cert_type})"
        )));
    }
    let qe_report = &raw[cert_body_start..cert_body_start + 384];
    let qe_report_sig = &raw[cert_body_start + 384..cert_body_start + 448];
    let qe_auth_len =
        u16::from_le_bytes(raw[cert_body_start + 448..cert_body_start + 450].try_into().unwrap())
            as usize;
    let qe_auth_start = cert_body_start + 450;
    if qe_auth_start + qe_auth_len + 6 > cert_body_start + cert_len {
        return Err(TeeError::VerificationFailed(
            "TDX v4 QE auth data truncated".into(),
        ));
    }
    let qe_auth_data = &raw[qe_auth_start..qe_auth_start + qe_auth_len];

    // Check QE Report REPORTDATA[0..32] == SHA-256(att_pub_xy || qe_auth_data).
    let mut h = Sha256::new();
    h.update(att_pub_xy);
    h.update(qe_auth_data);
    let expected_qe_rd = h.finalize();
    // REPORTDATA inside 384-byte SGX/TDX QE Report body sits at offset 320..384.
    if qe_report[320..352] != expected_qe_rd[..] {
        return Err(TeeError::VerificationFailed(
            "TDX QE Report REPORTDATA binding mismatch".into(),
        ));
    }

    // Parse inner PCK Cert Chain (cert_type == 5 = PEM-encoded PCK -> Intermediate -> Intel SGX Root CA).
    let inner_hdr = qe_auth_start + qe_auth_len;
    let inner_type = u16::from_le_bytes(raw[inner_hdr..inner_hdr + 2].try_into().unwrap());
    let inner_len =
        u32::from_le_bytes(raw[inner_hdr + 2..inner_hdr + 6].try_into().unwrap()) as usize;
    let pck_start = inner_hdr + 6;
    if inner_type != 5 || pck_start + inner_len > cert_body_start + cert_len {
        return Err(TeeError::VerificationFailed(format!(
            "TDX v4 quote missing PEM PCK cert chain (inner_type={inner_type})"
        )));
    }
    let pck_pem_str = std::str::from_utf8(&raw[pck_start..pck_start + inner_len])
        .map_err(|_| TeeError::VerificationFailed("TDX PCK chain not UTF-8 PEM".into()))?;
    let pems = pem::parse_many(pck_pem_str)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid TDX PCK PEM chain: {e}")))?;
    if pems.len() < 3 {
        return Err(TeeError::VerificationFailed(
            "TDX PCK PEM chain must contain [PCK, Platform/Processor CA, Intel SGX Root CA]"
                .into(),
        ));
    }

    let mut certs = Vec::with_capacity(pems.len());
    for (idx, p) in pems.iter().enumerate() {
        let (_, c) = X509Certificate::from_der(p.contents()).map_err(|e| {
            TeeError::VerificationFailed(format!("invalid TDX PCK X.509[{idx}]: {e}"))
        })?;
        let nb = c.validity().not_before.timestamp();
        let na = c.validity().not_after.timestamp();
        if (now_unix_s as i64) < nb || (now_unix_s as i64) > na {
            return Err(TeeError::VerificationFailed(format!(
                "TDX PCK cert[{idx}] expired/not-yet-valid at {now_unix_s}"
            )));
        }
        certs.push(c);
    }

    // Verify QE report signature using PCK leaf certificate P-256 key.
    let pck_vk = P256VerifyingKey::from_sec1_bytes(
        certs[0].public_key().subject_public_key.data.as_ref(),
    )
    .map_err(|e| TeeError::VerificationFailed(format!("invalid TDX PCK P-256 key: {e}")))?;
    let qe_sig = P256Signature::from_slice(qe_report_sig)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid TDX QE report sig: {e}")))?;
    pck_vk.verify(qe_report, &qe_sig).map_err(|e| {
        TeeError::VerificationFailed(format!("TDX QE report PCK signature invalid: {e}"))
    })?;

    // Verify PCK -> Intermediate -> Intel SGX Root CA P-256 X.509 chain.
    for i in 0..certs.len() - 1 {
        if certs[i].issuer() != certs[i + 1].subject() {
            return Err(TeeError::VerificationFailed(format!(
                "TDX PCK chain issuer mismatch at index {i}"
            )));
        }
        let parent_vk = P256VerifyingKey::from_sec1_bytes(
            certs[i + 1].public_key().subject_public_key.data.as_ref(),
        )
        .map_err(|e| TeeError::VerificationFailed(format!("invalid TDX CA P-256 key: {e}")))?;
        let der_sig = p256::ecdsa::DerSignature::from_bytes(certs[i].signature_value.data.as_ref())
            .map_err(|e| TeeError::VerificationFailed(format!("invalid TDX CA DER sig: {e}")))?;
        parent_vk
            .verify(certs[i].tbs_certificate.as_ref(), &der_sig)
            .map_err(|e| {
                TeeError::VerificationFailed(format!("TDX PCK X.509 signature invalid at {i}: {e}"))
            })?;
    }
    // Pin exact SHA-256 DER fingerprint of the Intel SGX Root CA (never trust subject string alone!).
    let root_der = pems.last().unwrap().contents();
    let root_fp = hex::encode(Sha256::digest(root_der));
    if !pinned_root_sha256_hex
        .iter()
        .any(|pin| pin.eq_ignore_ascii_case(&root_fp))
    {
        return Err(TeeError::VerificationFailed(format!(
            "TDX root CA SHA-256 {root_fp} does not match pinned Intel SGX Root CA"
        )));
    }
    let root_cert = certs.last().unwrap();
    if root_cert.issuer() != root_cert.subject() {
        return Err(TeeError::VerificationFailed(
            "TDX root CA certificate is not self-issued".into(),
        ));
    }
    let root_vk = P256VerifyingKey::from_sec1_bytes(
        root_cert.public_key().subject_public_key.data.as_ref(),
    )
    .map_err(|e| TeeError::VerificationFailed(format!("invalid TDX Root P-256 key: {e}")))?;
    let root_sig = p256::ecdsa::DerSignature::from_bytes(root_cert.signature_value.data.as_ref())
        .map_err(|e| TeeError::VerificationFailed(format!("invalid TDX Root DER sig: {e}")))?;
    root_vk
        .verify(root_cert.tbs_certificate.as_ref(), &root_sig)
        .map_err(|e| {
            TeeError::VerificationFailed(format!("TDX Root CA self-signature invalid: {e}"))
        })?;

    Ok(true)
}
