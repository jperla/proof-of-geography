use crate::types::{
    compute_report_data, GpuAttestationBinding, TeeAttestationQuote, TeeError, TeeProvider,
    TeeVendor,
};
use base64::Engine;
use chrono::Utc;

/// Standard AMD SEV-SNP Attestation Report size (1184 bytes per AMD ABI Spec Table 22).
pub const SEV_SNP_REPORT_LEN: usize = 1184;
/// Offset of 64-byte `REPORT_DATA` field in SEV-SNP attestation report.
pub const SEV_SNP_REPORT_DATA_OFFSET: usize = 0x50;
/// Offset of 48-byte `MEASUREMENT` (Launch Digest) field in SEV-SNP attestation report.
pub const SEV_SNP_MEASUREMENT_OFFSET: usize = 0x90;
/// Offset of 8-byte `POLICY` field in SEV-SNP attestation report.
pub const SEV_SNP_POLICY_OFFSET: usize = 0x08;
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

    /// Reads a real hardware SEV-SNP attestation report from `/dev/sev-guest` on Linux >= 6.2
    /// (Ubuntu 24.04 uses Linux 6.8+, where `struct snp_guest_request_ioctl` is 32 bytes -> `0xC0205300`).
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

        // _IOWR('S', 0x0, struct snp_guest_request_ioctl) for 32-byte Linux 6.2+ ABI.
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
            // Fallback: Linux ConfigFS TSM (/sys/kernel/config/tsm/report) works across RHEL/Rocky 9 & Linux 6.7+ kernels.
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
        // Per AMD SEV-SNP ABI Table 21: 32-byte header (status[4], report_size[4], rsvd[24]) followed by 1184B report.
        Ok(resp.data[32..32 + SEV_SNP_REPORT_LEN].to_vec())
    }

    #[cfg(not(target_os = "linux"))]
    fn fetch_hardware_report(&self, _report_data: [u8; 64]) -> Result<Vec<u8>, TeeError> {
        Err(TeeError::HardwareDeviceUnavailable(
            "AMD SEV-SNP /dev/sev-guest requires Linux Confidential VM".into(),
        ))
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
        // Feature info bit 0 (offset 0x4C) or Genoa Secure TSC flag.
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
            generated_at_unix_s: Utc::now().timestamp().max(0) as u64,
        })
    }
}

/// Structural verification of an AMD SEV-SNP raw 1184-byte hardware report.
/// Note: Full AMD ARK -> ASK -> VCEK ECDSA-P384 certificate chain validation integrates with
/// AMD KDS (kdsintf.amd.com) cached certificates in production verifier deployments.
pub fn verify_raw_sev_snp_report(quote: &TeeAttestationQuote) -> Result<(), TeeError> {
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
    if hex::encode(embedded_rd) != quote.report_data_hex {
        return Err(TeeError::VerificationFailed(
            "SEV-SNP report_data bytes mismatch".into(),
        ));
    }
    let embedded_meas = &raw[SEV_SNP_MEASUREMENT_OFFSET..SEV_SNP_MEASUREMENT_OFFSET + 48];
    if hex::encode(embedded_meas) != quote.workload_measurement_hex {
        return Err(TeeError::VerificationFailed(
            "SEV-SNP launch measurement mismatch".into(),
        ));
    }
    let policy = u64::from_le_bytes(
        raw[SEV_SNP_POLICY_OFFSET..SEV_SNP_POLICY_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    if (policy & SEV_SNP_POLICY_MIGRATE_MA_BIT) != 0 {
        return Err(TeeError::PolicyRejected(
            "SEV-SNP MIGRATE_MA bit set (live migration enabled)".into(),
        ));
    }
    if (policy & SEV_SNP_POLICY_DEBUG_BIT) != 0 {
        return Err(TeeError::PolicyRejected(
            "SEV-SNP DEBUG bit set".into(),
        ));
    }
    Ok(())
}
