use crate::types::{
    compute_report_data, GpuAttestationBinding, TeeAttestationQuote, TeeError, TeeProvider,
    TeeVendor,
};
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct DevQuoteBody {
    tag: String,
    measurement_hex: String,
    report_data_hex: String,
    digest_hex: String,
}

/// Deterministic software-only mock TEE provider for local testing, laptops, and CI.
/// Always tagged `TeeVendor::SoftwareDev` and unconditionally rejected by `AttestationPolicy::production()`.
pub struct SoftwareDevProvider {
    pub measurement_hex: String,
}

impl SoftwareDevProvider {
    pub fn new(measurement_hex: impl Into<String>) -> Self {
        Self {
            measurement_hex: measurement_hex.into(),
        }
    }
}

impl TeeProvider for SoftwareDevProvider {
    fn vendor(&self) -> TeeVendor {
        TeeVendor::SoftwareDev
    }

    fn attest(
        &self,
        public_key: &[u8; 32],
        nonce: &[u8],
        gpu_binding: Option<GpuAttestationBinding>,
    ) -> Result<TeeAttestationQuote, TeeError> {
        let report_data = compute_report_data(public_key, nonce, gpu_binding.as_ref());
        let report_data_hex = hex::encode(report_data);
        let mut h = blake3::Hasher::new();
        h.update(b"pog-software-dev-quote-v1");
        h.update(self.measurement_hex.as_bytes());
        h.update(report_data_hex.as_bytes());
        let digest_hex = hex::encode(h.finalize().as_bytes());

        let body = DevQuoteBody {
            tag: "SOFTWARE_DEV_NON_PRODUCTION".into(),
            measurement_hex: self.measurement_hex.clone(),
            report_data_hex: report_data_hex.clone(),
            digest_hex,
        };
        let raw = serde_json::to_vec(&body)
            .map_err(|e| TeeError::GenerationFailed(e.to_string()))?;

        Ok(TeeAttestationQuote {
            vendor: TeeVendor::SoftwareDev,
            public_key_hex: hex::encode(public_key),
            workload_measurement_hex: self.measurement_hex.clone(),
            report_data_hex,
            nonce_hex: hex::encode(nonce),
            migration_disabled: true,
            debug_disabled: true,
            secure_tsc_enabled: false,
            gpu_binding,
            raw_quote_b64: base64::engine::general_purpose::STANDARD.encode(&raw),
            generated_at_unix_s: Utc::now().timestamp().max(0) as u64,
        })
    }
}

pub fn verify_raw_dev_quote(quote: &TeeAttestationQuote) -> Result<(), TeeError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&quote.raw_quote_b64)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid dev quote b64: {e}")))?;
    let body: DevQuoteBody = serde_json::from_slice(&raw)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid dev quote json: {e}")))?;
    let mut h = blake3::Hasher::new();
    h.update(b"pog-software-dev-quote-v1");
    h.update(body.measurement_hex.as_bytes());
    h.update(body.report_data_hex.as_bytes());
    if hex::encode(h.finalize().as_bytes()) != body.digest_hex {
        return Err(TeeError::VerificationFailed("dev quote digest mismatch".into()));
    }
    if body.report_data_hex != quote.report_data_hex
        || body.measurement_hex != quote.workload_measurement_hex
    {
        return Err(TeeError::VerificationFailed("dev quote fields mismatch".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{verify_quote, AttestationPolicy, WorkloadKeypair};

    #[test]
    fn test_production_policy_rejects_dev_tee() {
        let kp = WorkloadKeypair::generate();
        let dev = SoftwareDevProvider::new("deadbeef".repeat(8));
        let nonce = b"epoch-nonce-1234";
        let quote = dev.attest(&kp.public_key_bytes(), nonce, None).unwrap();

        let now = Utc::now().timestamp() as u64;
        assert!(verify_quote(&quote, nonce, &AttestationPolicy::production(), now).is_err());
        let verified =
            verify_quote(&quote, nonce, &AttestationPolicy::allow_dev_software(), now).unwrap();
        assert_eq!(verified.public_key_hex, kp.public_key_hex());
    }
}
