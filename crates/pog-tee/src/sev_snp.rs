use crate::types::{
    compute_report_data, AttestationPolicy, GpuAttestationBinding, TeeAttestationQuote, TeeError,
    TeeProvider, TeeVendor,
};
use base64::Engine;
use chrono::Utc;
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{DerSignature, Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// Official AMD SEV-SNP ARK-Milan DER SHA-256 fingerprint (from https://kdsintf.amd.com/vcek/v1/Milan/cert_chain).
pub const AMD_ARK_MILAN_SHA256_HEX: &str =
    "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd";
/// Official AMD SEV-SNP ARK-Genoa DER SHA-256 fingerprint (from https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain).
pub const AMD_ARK_GENOA_SHA256_HEX: &str =
    "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1";
/// Official AMD SEV-SNP ARK-Turin DER SHA-256 fingerprint (from https://kdsintf.amd.com/vcek/v1/Turin/cert_chain).
pub const AMD_ARK_TURIN_SHA256_HEX: &str =
    "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a";
/// Default production allowlist of pinned official AMD SEV-SNP Root Key (ARK) DER SHA-256 digests.
pub const PINNED_AMD_ARK_SHA256_HEX: &[&str] = &[
    AMD_ARK_MILAN_SHA256_HEX,
    AMD_ARK_GENOA_SHA256_HEX,
    AMD_ARK_TURIN_SHA256_HEX,
];

/// Standard AMD SEV-SNP Attestation Report size (1184 bytes per AMD ABI Spec Table 22).
pub const SEV_SNP_REPORT_LEN: usize = 1184;
/// Offset of 64-byte `REPORT_DATA` field in SEV-SNP attestation report.
pub const SEV_SNP_REPORT_DATA_OFFSET: usize = 0x50;
/// Offset of 48-byte `MEASUREMENT` (Launch Digest) field in SEV-SNP attestation report.
pub const SEV_SNP_MEASUREMENT_OFFSET: usize = 0x90;
/// Offset of 8-byte `POLICY` field in SEV-SNP attestation report.
pub const SEV_SNP_POLICY_OFFSET: usize = 0x08;
/// End of signed portion of the SEV-SNP attestation report (`0x000..0x2A0` = 672 bytes).
pub const SEV_SNP_SIGNED_BODY_LEN: usize = 0x2A0;
/// Offset of ECDSA P-384 signature inside the 1184-byte report: `r` (72B LE) at 0x2A0, `s` (72B LE) at 0x2E8.
pub const SEV_SNP_SIG_R_OFFSET: usize = 0x2A0;
pub const SEV_SNP_SIG_S_OFFSET: usize = 0x2E8;
/// Policy bit 18: `MIGRATE_MA` (must be 0 to forbid live migration).
pub const SEV_SNP_POLICY_MIGRATE_MA_BIT: u64 = 1 << 18;
/// Policy bit 19: `DEBUG` (must be 0 in production).
pub const SEV_SNP_POLICY_DEBUG_BIT: u64 = 1 << 19;

/// AMD SEV-SNP hardware TEE provider (GCP C3D/N2D, AWS EC2 c6a/m6a, Azure DCas_v5, Tencent CVM).
pub struct AmdSevSnpProvider {
    pub device_path: String,
}

impl Default for AmdSevSnpProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AmdSevSnpProvider {
    pub fn new() -> Self {
        Self {
            device_path: "/dev/sev-guest".to_string(),
        }
    }

    /// Reads a real hardware SEV-SNP attestation report from `/dev/sev-guest` on Linux >= 6.2.
    #[cfg(target_os = "linux")]
    fn fetch_hardware_report(&self, report_data: [u8; 64]) -> Result<Vec<u8>, TeeError> {
        use std::fs::OpenOptions;
        use std::os::unix::io::AsRawFd;

        #[repr(C)]
        struct SnpReportReq {
            user_data: [u8; 64],
            vmpl: u32,
            rsvd: [u8; 28],
        }

        #[repr(C)]
        struct SnpReportResp {
            data: [u8; 4000],
        }

        #[repr(C)]
        struct SnpGuestRequestIoctl {
            msg_version: u8,
            _pad: [u8; 7],
            req_data: u64,
            resp_data: u64,
            exitinfo2: u64,
        }

        const SNP_GET_REPORT: libc::c_ulong = 0xC020_5300;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.device_path)
            .map_err(|e| TeeError::HardwareDeviceUnavailable(format!("{}: {e}", self.device_path)))?;

        let req = SnpReportReq {
            user_data: report_data,
            vmpl: 0,
            rsvd: [0u8; 28],
        };
        let mut resp = SnpReportResp { data: [0u8; 4000] };
        let mut ioctl_arg = SnpGuestRequestIoctl {
            msg_version: 1,
            _pad: [0u8; 7],
            req_data: &req as *const _ as u64,
            resp_data: &mut resp as *mut _ as u64,
            exitinfo2: 0,
        };

        let rc = unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                SNP_GET_REPORT as libc::Ioctl,
                &mut ioctl_arg,
            )
        };
        let status = u32::from_le_bytes(resp.data[0..4].try_into().unwrap());
        let report_size = u32::from_le_bytes(resp.data[4..8].try_into().unwrap()) as usize;
        if rc != 0 || status != 0 || report_size < SEV_SNP_REPORT_LEN {
            let tsm_root = std::path::Path::new("/sys/kernel/config/tsm/report");
            if tsm_root.exists() {
                let rdir = tsm_root.join(format!("pog_snp_{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)));
                if std::fs::create_dir_all(&rdir).is_ok()
                    && std::fs::write(rdir.join("inblob"), report_data).is_ok()
                {
                    if let Ok(out) = std::fs::read(rdir.join("outblob")) {
                        let _ = std::fs::remove_dir(&rdir);
                        if out.len() >= SEV_SNP_REPORT_LEN {
                            return Ok(out[..SEV_SNP_REPORT_LEN].to_vec());
                        }
                    }
                    let _ = std::fs::remove_dir(&rdir);
                }
            }
            return Err(TeeError::GenerationFailed(format!(
                "SNP_GET_REPORT failed (rc={rc}, errno={:?}, status={status}, size={report_size}, exitinfo2={:#x})",
                std::io::Error::last_os_error(),
                ioctl_arg.exitinfo2
            )));
        }
        Ok(resp.data[32..32 + SEV_SNP_REPORT_LEN].to_vec())
    }

    #[cfg(not(target_os = "linux"))]
    fn fetch_hardware_report(&self, _report_data: [u8; 64]) -> Result<Vec<u8>, TeeError> {
        Err(TeeError::HardwareDeviceUnavailable(
            "AMD SEV-SNP /dev/sev-guest requires Linux Confidential VM".into(),
        ))
    }

    /// Load locally provisioned AMD VCEK -> ASK -> ARK PEM chain if available on the host
    /// (e.g., `/etc/pog/amd_vcek_chain.pem` fetched from AMD KDS or cloud IMDS during boot).
    fn load_optional_vendor_chain() -> Vec<String> {
        let path = std::env::var("POG_AMD_CERT_CHAIN_PATH")
            .unwrap_or_else(|_| "/etc/pog/amd_vcek_chain.pem".to_string());
        let Ok(raw) = std::fs::read_to_string(path) else {
            return Vec::new();
        };
        ::pem::parse_many(raw)
            .unwrap_or_default()
            .into_iter()
            .map(|p| ::pem::encode(&p))
            .collect()
    }
}

impl TeeProvider for AmdSevSnpProvider {
    fn vendor(&self) -> TeeVendor {
        TeeVendor::AmdSevSnp
    }

    fn attest(
        &self,
        public_key: &[u8; 32],
        nonce: &[u8],
        gpu_binding: Option<GpuAttestationBinding>,
    ) -> Result<TeeAttestationQuote, TeeError> {
        let report_data = compute_report_data(public_key, nonce, gpu_binding.as_ref());
        let raw = self.fetch_hardware_report(report_data)?;
        if raw.len() < SEV_SNP_REPORT_LEN {
            return Err(TeeError::GenerationFailed(
                "SEV-SNP report shorter than 1184 bytes".into(),
            ));
        }

        let policy = u64::from_le_bytes(
            raw[SEV_SNP_POLICY_OFFSET..SEV_SNP_POLICY_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        let measurement = &raw[SEV_SNP_MEASUREMENT_OFFSET..SEV_SNP_MEASUREMENT_OFFSET + 48];
        let version = u32::from_le_bytes(raw[0..4].try_into().unwrap());
        let secure_tsc = version >= 2;

        Ok(TeeAttestationQuote {
            vendor: TeeVendor::AmdSevSnp,
            public_key_hex: hex::encode(public_key),
            workload_measurement_hex: hex::encode(measurement),
            report_data_hex: hex::encode(report_data),
            nonce_hex: hex::encode(nonce),
            migration_disabled: (policy & SEV_SNP_POLICY_MIGRATE_MA_BIT) == 0,
            debug_disabled: (policy & SEV_SNP_POLICY_DEBUG_BIT) == 0,
            secure_tsc_enabled: secure_tsc,
            gpu_binding,
            raw_quote_b64: base64::engine::general_purpose::STANDARD.encode(&raw),
            vendor_cert_chain_pem: Self::load_optional_vendor_chain(),
            workload_attestation: None,
            generated_at_unix_s: Utc::now().timestamp().max(0) as u64,
        })
    }
}

/// Convert AMD SEV-SNP 72-byte little-endian P-384 scalar (`r` or `s`) to 48-byte big-endian.
fn snp_le72_to_be48(le72: &[u8]) -> Result<[u8; 48], TeeError> {
    if le72.len() != 72 {
        return Err(TeeError::VerificationFailed("bad SEV-SNP scalar len".into()));
    }
    if le72[48..].iter().any(|&b| b != 0) {
        return Err(TeeError::VerificationFailed(
            "non-zero upper padding in SEV-SNP P-384 signature scalar".into(),
        ));
    }
    let mut be = [0u8; 48];
    for i in 0..48 {
        be[i] = le72[47 - i];
    }
    Ok(be)
}

/// Structural + cryptographic verification of an AMD SEV-SNP raw 1184-byte hardware report
/// against the pinned official AMD ARK (Milan / Genoa / Turin) root certificate fingerprints.
///
/// Returns `Ok(true)` ONLY when the VCEK ECDSA P-384 signature over `raw[0..0x2A0]` AND the
/// VCEK -> ASK -> ARK X.509 RSA-PSS-4096 (or P-384) signature chain verify up to a pinned ARK root.
/// Under `AttestationPolicy::production()`, missing or unverified vendor chains FAIL CLOSED!
pub fn verify_raw_sev_snp_report(
    quote: &TeeAttestationQuote,
    policy: &AttestationPolicy,
    now_unix_s: u64,
) -> Result<bool, TeeError> {
    verify_raw_sev_snp_report_with_pinned_roots(quote, policy, now_unix_s, PINNED_AMD_ARK_SHA256_HEX)
}

/// Verify an X.509 certificate's TBS bytes against its issuer's public key using either
/// AMD's RSA-PSS-4096-SHA384 (`ring`) or ECDSA P-384. Fails closed on unsupported algorithms!
fn verify_x509_cert_sig(child: &X509Certificate<'_>, parent: &X509Certificate<'_>) -> Result<(), TeeError> {
    let tbs = child.tbs_certificate.as_ref();
    let sig_bytes = child.signature_value.data.as_ref();
    let pub_key_bytes = parent.public_key().subject_public_key.data.as_ref();
    let alg_oid = parent.public_key().algorithm.algorithm.to_id_string();

    // RSA (1.2.840.113549.1.1.1 = rsaEncryption or 1.2.840.113549.1.1.10 = id-RSASSA-PSS)
    if alg_oid == "1.2.840.113549.1.1.1" || alg_oid == "1.2.840.113549.1.1.10" {
        let pss_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PSS_2048_8192_SHA384,
            pub_key_bytes,
        );
        return pss_key.verify(tbs, sig_bytes).map_err(|_| {
            TeeError::VerificationFailed("AMD SEV-SNP RSA-PSS-SHA384 X.509 signature invalid".into())
        });
    }

    // ECDSA P-384 (1.2.840.10045.2.1 = id-ecPublicKey)
    if alg_oid == "1.2.840.10045.2.1" {
        let parent_vk = P384VerifyingKey::from_sec1_bytes(pub_key_bytes).map_err(|e| {
            TeeError::VerificationFailed(format!("invalid AMD SEV-SNP P-384 CA key: {e}"))
        })?;
        let der_sig = DerSignature::from_bytes(sig_bytes).map_err(|e| {
            TeeError::VerificationFailed(format!("invalid AMD SEV-SNP P-384 DER sig: {e}"))
        })?;
        return parent_vk.verify(tbs, &der_sig).map_err(|e| {
            TeeError::VerificationFailed(format!("AMD SEV-SNP P-384 X.509 signature invalid: {e}"))
        });
    }

    Err(TeeError::VerificationFailed(format!(
        "unsupported AMD SEV-SNP CA public key algorithm OID {alg_oid} (fail-closed)"
    )))
}

/// Same as `verify_raw_sev_snp_report`, accepting an explicit slice of pinned ARK DER SHA-256 hex digests
/// (for unit tests with synthetic CAs or custom root rotation policies).
pub fn verify_raw_sev_snp_report_with_pinned_roots(
    quote: &TeeAttestationQuote,
    policy: &AttestationPolicy,
    now_unix_s: u64,
    pinned_ark_sha256_hex: &[&str],
) -> Result<bool, TeeError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&quote.raw_quote_b64)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid base64 SEV-SNP report: {e}")))?;
    if raw.len() < SEV_SNP_REPORT_LEN {
        return Err(TeeError::VerificationFailed(format!(
            "SEV-SNP report too short: {} < {}",
            raw.len(),
            SEV_SNP_REPORT_LEN
        )));
    }
    let embedded_rd = &raw[SEV_SNP_REPORT_DATA_OFFSET..SEV_SNP_REPORT_DATA_OFFSET + 64];
    if !hex::encode(embedded_rd).eq_ignore_ascii_case(&quote.report_data_hex) {
        return Err(TeeError::VerificationFailed(
            "SEV-SNP report_data bytes mismatch".into(),
        ));
    }
    let embedded_meas = &raw[SEV_SNP_MEASUREMENT_OFFSET..SEV_SNP_MEASUREMENT_OFFSET + 48];
    if !hex::encode(embedded_meas).eq_ignore_ascii_case(&quote.workload_measurement_hex) {
        return Err(TeeError::VerificationFailed(
            "SEV-SNP launch measurement mismatch".into(),
        ));
    }
    let snp_policy = u64::from_le_bytes(
        raw[SEV_SNP_POLICY_OFFSET..SEV_SNP_POLICY_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    if (snp_policy & SEV_SNP_POLICY_MIGRATE_MA_BIT) != 0 {
        return Err(TeeError::PolicyRejected(
            "SEV-SNP MIGRATE_MA bit set (live migration enabled)".into(),
        ));
    }
    if (snp_policy & SEV_SNP_POLICY_DEBUG_BIT) != 0 {
        return Err(TeeError::PolicyRejected("SEV-SNP DEBUG bit set".into()));
    }

    // Cryptographic VCEK -> ASK -> ARK verification (required in fail-closed production policy).
    if quote.vendor_cert_chain_pem.is_empty() {
        if policy.require_cryptographic_vendor_chain {
            return Err(TeeError::VerificationFailed(
                "AMD SEV-SNP quote missing VCEK/ASK/ARK vendor certificate chain (fail-closed)"
                    .into(),
            ));
        }
        return Ok(false);
    }

    let mut der_certs = Vec::with_capacity(quote.vendor_cert_chain_pem.len());
    for p in &quote.vendor_cert_chain_pem {
        let parsed = ::pem::parse(p).map_err(|e| {
            TeeError::VerificationFailed(format!("invalid AMD SEV-SNP PEM cert: {e}"))
        })?;
        der_certs.push(parsed.into_contents());
    }
    let mut certs = Vec::with_capacity(der_certs.len());
    for (idx, der) in der_certs.iter().enumerate() {
        let (_, c) = X509Certificate::from_der(der).map_err(|e| {
            TeeError::VerificationFailed(format!("invalid AMD SEV-SNP X.509[{idx}]: {e}"))
        })?;
        let nb = c.validity().not_before.timestamp();
        let na = c.validity().not_after.timestamp();
        if (now_unix_s as i64) < nb || (now_unix_s as i64) > na {
            return Err(TeeError::VerificationFailed(format!(
                "AMD SEV-SNP cert[{idx}] expired/not-yet-valid at {now_unix_s}"
            )));
        }
        certs.push(c);
    }
    if certs.len() < 3 {
        return Err(TeeError::VerificationFailed(
            "AMD SEV-SNP vendor_cert_chain_pem must contain [VCEK, ASK, ARK]".into(),
        ));
    }

    // Pin the exact SHA-256 DER fingerprint of the root ARK certificate (never trust subject string alone!).
    let ark_der = der_certs.last().unwrap();
    let ark_fp = hex::encode(Sha256::digest(ark_der));
    if !pinned_ark_sha256_hex
        .iter()
        .any(|pin| pin.eq_ignore_ascii_case(&ark_fp))
    {
        return Err(TeeError::VerificationFailed(format!(
            "AMD SEV-SNP root certificate SHA-256 {ark_fp} does not match any pinned AMD ARK root"
        )));
    }
    let ark = certs.last().unwrap();
    if ark.issuer() != ark.subject() {
        return Err(TeeError::VerificationFailed(
            "AMD SEV-SNP ARK root certificate is not self-issued".into(),
        ));
    }
    verify_x509_cert_sig(ark, ark)?;

    // Verify signature on report[0..0x2A0] with VCEK P-384 public key.
    let vcek = &certs[0];
    let vcek_vk =
        P384VerifyingKey::from_sec1_bytes(vcek.public_key().subject_public_key.data.as_ref())
            .map_err(|e| TeeError::VerificationFailed(format!("invalid VCEK P-384 key: {e}")))?;
    let r_be = snp_le72_to_be48(&raw[SEV_SNP_SIG_R_OFFSET..SEV_SNP_SIG_R_OFFSET + 72])?;
    let s_be = snp_le72_to_be48(&raw[SEV_SNP_SIG_S_OFFSET..SEV_SNP_SIG_S_OFFSET + 72])?;
    let mut rs = [0u8; 96];
    rs[..48].copy_from_slice(&r_be);
    rs[48..].copy_from_slice(&s_be);
    let sig = P384Signature::from_slice(&rs)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid SEV-SNP P-384 sig: {e}")))?;
    vcek_vk
        .verify(&raw[..SEV_SNP_SIGNED_BODY_LEN], &sig)
        .map_err(|e| {
            TeeError::VerificationFailed(format!("AMD SEV-SNP report VCEK signature invalid: {e}"))
        })?;

    // Cryptographically verify every link in VCEK -> ASK -> ARK (fail-closed RSA-PSS-4096 or P-384).
    for i in 0..certs.len() - 1 {
        if certs[i].issuer() != certs[i + 1].subject() {
            return Err(TeeError::VerificationFailed(format!(
                "AMD SEV-SNP cert chain issuer mismatch at index {i}"
            )));
        }
        verify_x509_cert_sig(&certs[i], &certs[i + 1])?;
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p384::ecdsa::signature::Signer as P384Signer;
    use p384::ecdsa::SigningKey as P384SigningKey;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, PKCS_ECDSA_P384_SHA384};

    fn make_synthetic_snp_quote(now: u64) -> (TeeAttestationQuote, String) {
        let mut ark_params = CertificateParams::default();
        ark_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ark_params.distinguished_name.push(DnType::CommonName, "ARK-Milan");
        ark_params.distinguished_name.push(DnType::OrganizationName, "Advanced Micro Devices");
        let ark_kp = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let ark_cert = ark_params.self_signed(&ark_kp).unwrap();
        let ark_fp = hex::encode(Sha256::digest(ark_cert.der().as_ref()));

        let mut ask_params = CertificateParams::default();
        ask_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ask_params.distinguished_name.push(DnType::CommonName, "SEV-Milan");
        let ask_kp = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let ask_cert = ask_params.signed_by(&ask_kp, &ark_cert, &ark_kp).unwrap();

        let mut vcek_params = CertificateParams::default();
        vcek_params.distinguished_name.push(DnType::CommonName, "SEV-VCEK");
        let vcek_kp = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let vcek_cert = vcek_params.signed_by(&vcek_kp, &ask_cert, &ask_kp).unwrap();

        let pk = [0x11u8; 32];
        let nonce = b"fresh-snp-nonce";
        let rd = compute_report_data(&pk, nonce, None);
        let meas = [0xABu8; 48];

        let mut raw = vec![0u8; SEV_SNP_REPORT_LEN];
        raw[0..4].copy_from_slice(&2u32.to_le_bytes());
        raw[SEV_SNP_POLICY_OFFSET..SEV_SNP_POLICY_OFFSET + 8].copy_from_slice(&0x0003_0000u64.to_le_bytes());
        raw[SEV_SNP_REPORT_DATA_OFFSET..SEV_SNP_REPORT_DATA_OFFSET + 64].copy_from_slice(&rd);
        raw[SEV_SNP_MEASUREMENT_OFFSET..SEV_SNP_MEASUREMENT_OFFSET + 48].copy_from_slice(&meas);

        // Sign raw[0..0x2A0] with VCEK P-384 key (PKCS#8 DER from rcgen)
        use p384::pkcs8::DecodePrivateKey;
        let vcek_sk = P384SigningKey::from_pkcs8_der(vcek_kp.serialize_der().as_ref()).unwrap();
        let sig: P384Signature = vcek_sk.sign(&raw[..SEV_SNP_SIGNED_BODY_LEN]);
        let sig_bytes = sig.to_bytes();
        let mut r_le = [0u8; 72];
        let mut s_le = [0u8; 72];
        for i in 0..48 {
            r_le[i] = sig_bytes[47 - i];
            s_le[i] = sig_bytes[95 - i];
        }
        raw[SEV_SNP_SIG_R_OFFSET..SEV_SNP_SIG_R_OFFSET + 72].copy_from_slice(&r_le);
        raw[SEV_SNP_SIG_S_OFFSET..SEV_SNP_SIG_S_OFFSET + 72].copy_from_slice(&s_le);

        let quote = TeeAttestationQuote {
            vendor: TeeVendor::AmdSevSnp,
            public_key_hex: hex::encode(pk),
            workload_measurement_hex: hex::encode(meas),
            report_data_hex: hex::encode(rd),
            nonce_hex: hex::encode(nonce),
            migration_disabled: true,
            debug_disabled: true,
            secure_tsc_enabled: true,
            gpu_binding: None,
            raw_quote_b64: base64::engine::general_purpose::STANDARD.encode(&raw),
            vendor_cert_chain_pem: vec![vcek_cert.pem(), ask_cert.pem(), ark_cert.pem()],
            workload_attestation: None,
            generated_at_unix_s: now,
        };
        (quote, ark_fp)
    }

    #[test]
    fn test_sev_snp_rejects_unpinned_self_signed_ark_and_accepts_pinned_chain() {
        let now = Utc::now().timestamp() as u64;
        let (quote, test_ark_fp) = make_synthetic_snp_quote(now);
        let policy = AttestationPolicy::production();

        // Default production verifier MUST REJECT even though subject says "ARK-Milan" (root SHA-256 pin!)
        let err = verify_raw_sev_snp_report(&quote, &policy, now).unwrap_err();
        assert!(err.to_string().contains("does not match any pinned AMD ARK root"), "got: {err}");

        // With the test ARK explicitly pinned, full cryptographic chain & report sig MUST pass!
        let ok = verify_raw_sev_snp_report_with_pinned_roots(&quote, &policy, now, &[&test_ark_fp]).unwrap();
        assert!(ok);
    }
}
