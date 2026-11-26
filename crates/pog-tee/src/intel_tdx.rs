use crate::types::{
    compute_report_data, GpuAttestationBinding, TeeAttestationQuote, TeeError, TeeProvider,
    TeeVendor,
};
use base64::Engine;
use chrono::Utc;

/// Minimum Intel TDX Quote v4 header + TD Report Body length (48B header + 584B TD Report).
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

    /// Reads a real Intel TDX DCAP Quote via Linux kernel ConfigFS TSM (`/sys/kernel/config/tsm/report`),
    /// which works uniformly on GCP C3 and Azure TDX Confidential VMs (Linux >= 6.7).
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
            secure_tsc_enabled: true, // TDX enforces architectural virtualized TSC consistency
            gpu_binding,
            raw_quote_b64: base64::engine::general_purpose::STANDARD.encode(&raw),
            generated_at_unix_s: Utc::now().timestamp().max(0) as u64,
        })
    }
}

/// Structural verification of an Intel TDX v4 DCAP Quote.
/// Production deployments chain this with Intel PCS / DCAP QVL PCK certificate verification.
pub fn verify_raw_tdx_quote(quote: &TeeAttestationQuote) -> Result<(), TeeError> {
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
    if hex::encode(embedded_rd) != quote.report_data_hex {
        return Err(TeeError::VerificationFailed(
            "TDX REPORTDATA bytes mismatch".into(),
        ));
    }
    let embedded_mrtd = &raw[TDX_QUOTE_MRTD_OFFSET..TDX_QUOTE_MRTD_OFFSET + 48];
    if hex::encode(embedded_mrtd) != quote.workload_measurement_hex {
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
    Ok(())
}
