use crate::gcp_confidential_space::RsaJwk;
use crate::intel_tdx::{
    verify_raw_tdx_quote_with_pinned_roots, PINNED_INTEL_ROOT_SHA256_HEX, TDX_ATTR_DEBUG_BIT,
    TDX_ATTR_MIGRATABLE_BIT, TDX_QUOTE_MIN_LEN, TDX_QUOTE_MRTD_OFFSET,
    TDX_QUOTE_REPORTDATA_OFFSET, TDX_QUOTE_TDATTRIBUTES_OFFSET,
};
use crate::sev_snp::{
    verify_raw_sev_snp_report_with_pinned_roots, PINNED_AMD_ARK_SHA256_HEX,
    SEV_SNP_MEASUREMENT_OFFSET, SEV_SNP_POLICY_DEBUG_BIT, SEV_SNP_POLICY_MIGRATE_MA_BIT,
    SEV_SNP_POLICY_OFFSET, SEV_SNP_REPORT_DATA_OFFSET, SEV_SNP_REPORT_LEN,
};
use crate::types::{
    AttestationPolicy, TeeAttestationQuote, TeeError, TeeVendor, WorkloadAttestation,
};
#[cfg(target_os = "linux")]
use base64::engine::general_purpose::URL_SAFE as B64_URL_PAD;
use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD as B64_URL};
use base64::Engine;
use ring::signature::{RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA256};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384};
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::sync::OnceLock;

/// Azure Confidential VM vTPM NV Index containing the HCL Report (embedded AMD SEV-SNP / TDX
/// hardware report + runtime claims JSON binding the vTPM Attestation Key `akPub`).
pub const AZURE_HCL_NV_INDEX: u32 = 0x0140_0001;
/// Azure Confidential VM persistent vTPM Attestation Key (AK) handle.
pub const AZURE_VTPM_AK_HANDLE: u32 = 0x8100_0003;
/// Little-endian HCL report header signature (`"HCLA"`).
pub const HCL_HEADER_SIGNATURE: u32 = 0x414C_4348;
/// HCL `report_type` value for AMD SEV-SNP Confidential VM.
pub const HCL_REPORT_TYPE_SNP: u32 = 2;
/// HCL `report_type` value for Intel TDX Confidential VM.
pub const HCL_REPORT_TYPE_TDX: u32 = 4;
/// Offset of embedded hardware attestation report inside the Azure HCL blob.
pub const HCL_HW_REPORT_OFFSET: usize = 32;
/// Offset of `HCL_RUNTIME_DATA_HEADER` (`"RDAT"`) right after the 1184-byte SEV-SNP report.
pub const HCL_RUNTIME_DATA_OFFSET: usize = HCL_HW_REPORT_OFFSET + SEV_SNP_REPORT_LEN;
/// TPM 2.0 `TPM_GENERATED_VALUE` magic (big-endian `0xFF544347`).
pub const TPM2_GENERATED_VALUE: u32 = 0xFF54_4347;
/// TPM 2.0 `TPM_ST_ATTEST_QUOTE` tag (big-endian `0x8018`).
pub const TPM2_ST_ATTEST_QUOTE: u16 = 0x8018;

/// Compute canonical 32-byte `extraData` (`qualifyingData`) passed to Azure vTPM `TPM2_Quote`,
/// binding the enclave/CVM-generated Ed25519 signing key and fresh verifier challenge nonce.
pub fn compute_azure_vtpm_qualifying_data(public_key: &[u8; 32], nonce: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"pog-azure-vtpm-v1");
    h.update(public_key);
    h.update(nonce);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Compute the deterministic 96-hex SHA-384 measured-guest workload digest over the sorted
/// vTPM PCR register map (e.g., PCR 4 UKI bootloader, PCR 7 Secure Boot, PCR 9/11 immutable rootfs).
pub fn compute_azure_pcr_workload_measurement(pcr_values: &BTreeMap<u32, String>) -> Result<String, TeeError> {
    if pcr_values.is_empty() {
        return Err(TeeError::VerificationFailed(
            "Azure CVM vTPM quote missing measured PCR values".into(),
        ));
    }
    let mut h = Sha384::new();
    h.update(b"pog-azure-cvm-pcrs-v1\n");
    for (idx, val) in pcr_values {
        let norm = val.trim().to_ascii_lowercase();
        let bytes = hex::decode(&norm).map_err(|e| {
            TeeError::VerificationFailed(format!("invalid hex for Azure PCR{idx}: {e}"))
        })?;
        if bytes.len() != 32 {
            return Err(TeeError::VerificationFailed(format!(
                "Azure SHA-256 PCR{idx} must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        h.update(format!("pcr{idx}:{norm}\n").as_bytes());
    }
    Ok(hex::encode(h.finalize()))
}

/// Parsed fields from an Azure CVM HCL Report (`0x01400001`).
#[derive(Debug, Clone)]
pub struct ParsedAzureHclReport {
    pub report_type: u32,
    pub hw_report: Vec<u8>,
    pub runtime_data_json_bytes: Vec<u8>,
    pub ak_pub: RsaJwk,
}

/// Parse an Azure CVM HCL binary blob (rejecting `TrustedLaunch` or malformed blobs fail-closed).
pub fn parse_azure_hcl_report(hcl: &[u8]) -> Result<ParsedAzureHclReport, TeeError> {
    if hcl.len() < HCL_RUNTIME_DATA_OFFSET + 20 {
        return Err(TeeError::VerificationFailed(format!(
            "Azure HCL report too short ({} bytes) — Trusted Launch VMs lack hardware HCL reports (fail-closed)",
            hcl.len()
        )));
    }
    let sig = u32::from_le_bytes(hcl[0..4].try_into().unwrap());
    if sig != HCL_HEADER_SIGNATURE {
        return Err(TeeError::VerificationFailed(format!(
            "Azure HCL header magic mismatch: got {sig:#x}, expected {HCL_HEADER_SIGNATURE:#x}"
        )));
    }
    let header_req_type = u32::from_le_bytes(hcl[12..16].try_into().unwrap());
    if header_req_type == 0 {
        return Err(TeeError::PolicyRejected(
            "Azure HCL header request_type=0 is NOT a Confidential VM report — Trusted Launch rejected".into(),
        ));
    }

    // Parse HCL_RUNTIME_DATA_HEADER at offset 1216:
    //   0..4:   size (u32 LE)
    //   4..8:   version (u32 LE)
    //   8..12:  report_type (u32 LE: 2 = AMD SEV-SNP, 4 = Intel TDX)
    //   12..16: hash_type (u32 LE: 1 = SHA-256)
    //   16..20: claim_size (u32 LE)
    //   20..20+claim_size: UTF-8 JSON runtime claims (hashed by HCL into hw_report.report_data[0..32])
    let rdat = &hcl[HCL_RUNTIME_DATA_OFFSET..];
    let report_type = u32::from_le_bytes(rdat[8..12].try_into().unwrap());
    if report_type != HCL_REPORT_TYPE_SNP && report_type != HCL_REPORT_TYPE_TDX {
        return Err(TeeError::PolicyRejected(format!(
            "Azure HCL runtime_data report_type={report_type} is NOT Confidential VM SEV-SNP (2) or TDX (4) — Trusted Launch rejected"
        )));
    }

    let hw_len = if report_type == HCL_REPORT_TYPE_TDX {
        1024
    } else {
        SEV_SNP_REPORT_LEN
    };
    let hw_report = hcl[HCL_HW_REPORT_OFFSET..HCL_HW_REPORT_OFFSET + hw_len].to_vec();

    let claim_size = u32::from_le_bytes(rdat[16..20].try_into().unwrap()) as usize;
    if claim_size == 0 || 20 + claim_size > rdat.len() {
        return Err(TeeError::VerificationFailed(format!(
            "Azure HCL runtime_data claim_size {claim_size} out of bounds"
        )));
    }
    let runtime_data_json_bytes = rdat[20..20 + claim_size].to_vec();
    let json_slice = match runtime_data_json_bytes.iter().position(|&b| b == 0) {
        Some(pos) => &runtime_data_json_bytes[..pos],
        None => &runtime_data_json_bytes[..],
    };
    let claims: Value = serde_json::from_slice(json_slice).map_err(|e| {
        TeeError::VerificationFailed(format!("invalid Azure HCL runtime_data JSON: {e}"))
    })?;

    let keys = claims
        .get("keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| TeeError::VerificationFailed("Azure HCL runtime_data missing keys[]".into()))?;
    let ak_val = keys
        .iter()
        .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some("HCLAkPub"))
        .or_else(|| keys.first())
        .ok_or_else(|| TeeError::VerificationFailed("Azure HCL runtime_data has empty keys[]".into()))?;
    let ak_pub: RsaJwk = serde_json::from_value(ak_val.clone()).map_err(|e| {
        TeeError::VerificationFailed(format!("invalid Azure HCL akPub JWK: {e}"))
    })?;
    if ak_pub.kty != "RSA" {
        return Err(TeeError::VerificationFailed(format!(
            "Azure HCL akPub kty must be RSA, got {:?}",
            ak_pub.kty
        )));
    }

    Ok(ParsedAzureHclReport {
        report_type,
        hw_report,
        runtime_data_json_bytes,
        ak_pub,
    })
}

/// Parsed fields from a TPM 2.0 `TPMS_ATTEST` Quote structure.
#[derive(Debug, Clone)]
pub struct ParsedTpmsAttestQuote {
    pub extra_data: Vec<u8>,
    pub pcr_digest: Vec<u8>,
}

/// Parse a binary TPM 2.0 `TPMS_ATTEST` blob (`TPM_ST_ATTEST_QUOTE`).
pub fn parse_tpms_attest_quote(attest: &[u8]) -> Result<ParsedTpmsAttestQuote, TeeError> {
    let mut off = 0usize;
    let read_u16 = |buf: &[u8], o: &mut usize| -> Result<u16, TeeError> {
        if *o + 2 > buf.len() {
            return Err(TeeError::VerificationFailed("TPMS_ATTEST truncated (u16)".into()));
        }
        let v = u16::from_be_bytes(buf[*o..*o + 2].try_into().unwrap());
        *o += 2;
        Ok(v)
    };
    let read_u32 = |buf: &[u8], o: &mut usize| -> Result<u32, TeeError> {
        if *o + 4 > buf.len() {
            return Err(TeeError::VerificationFailed("TPMS_ATTEST truncated (u32)".into()));
        }
        let v = u32::from_be_bytes(buf[*o..*o + 4].try_into().unwrap());
        *o += 4;
        Ok(v)
    };

    let magic = read_u32(attest, &mut off)?;
    if magic != TPM2_GENERATED_VALUE {
        return Err(TeeError::VerificationFailed(format!(
            "TPMS_ATTEST magic {magic:#x} != TPM_GENERATED_VALUE"
        )));
    }
    let st_type = read_u16(attest, &mut off)?;
    if st_type != TPM2_ST_ATTEST_QUOTE {
        return Err(TeeError::VerificationFailed(format!(
            "TPMS_ATTEST type {st_type:#x} != TPM_ST_ATTEST_QUOTE (0x8018)"
        )));
    }
    let qsigner_len = read_u16(attest, &mut off)? as usize;
    if off + qsigner_len > attest.len() {
        return Err(TeeError::VerificationFailed("TPMS_ATTEST qualifiedSigner truncated".into()));
    }
    off += qsigner_len;

    let extra_len = read_u16(attest, &mut off)? as usize;
    if off + extra_len > attest.len() {
        return Err(TeeError::VerificationFailed("TPMS_ATTEST extraData truncated".into()));
    }
    let extra_data = attest[off..off + extra_len].to_vec();
    off += extra_len;

    // TPMS_CLOCK_INFO (17 bytes) + firmwareVersion (8 bytes) = 25 bytes
    if off + 25 > attest.len() {
        return Err(TeeError::VerificationFailed("TPMS_ATTEST clockInfo/fwVersion truncated".into()));
    }
    off += 25;

    // TPMS_QUOTE_INFO: TPML_PCR_SELECTION (count: u32 + entries of [hash: u16, sizeofSelect: u8, selectBytes]) + pcrDigest (u16 len + bytes)
    let pcr_sel_count = read_u32(attest, &mut off)? as usize;
    for _ in 0..pcr_sel_count {
        let _hash_alg = read_u16(attest, &mut off)?;
        if off + 1 > attest.len() {
            return Err(TeeError::VerificationFailed("TPMS_QUOTE_INFO pcrSelect truncated".into()));
        }
        let sz = attest[off] as usize;
        off += 1;
        if off + sz > attest.len() {
            return Err(TeeError::VerificationFailed("TPMS_QUOTE_INFO bitmap truncated".into()));
        }
        off += sz;
    }
    let digest_len = read_u16(attest, &mut off)? as usize;
    if off + digest_len > attest.len() {
        return Err(TeeError::VerificationFailed("TPMS_QUOTE_INFO pcrDigest truncated".into()));
    }
    let pcr_digest = attest[off..off + digest_len].to_vec();

    Ok(ParsedTpmsAttestQuote {
        extra_data,
        pcr_digest,
    })
}

/// Cryptographically verify an Azure Confidential VM measured-guest attestation end-to-end:
/// 1. Rejects Trusted Launch / non-CVM immediately (requires HCL AMD SEV-SNP hardware report).
/// 2. Verifies the embedded AMD SEV-SNP 1184-byte report against VCEK -> ASK -> pinned AMD ARK
///    (Milan / Genoa / Turin), enforcing `DEBUG=0` and `MIGRATE_MA=0`.
/// 3. Verifies hardware-to-vTPM binding: `SHA-256(hcl_runtime_data_json) == sev_snp.report_data[0..32]`.
/// 4. Verifies `TPM2_Quote` (`TPMS_ATTEST`) RSA-2048 SHA-256 signature under hardware-bound `akPub`.
/// 5. Verifies `extraData == SHA-256("pog-azure-vtpm-v1" || pk || expected_nonce)`.
/// 6. Verifies `pcrDigest == SHA-256(concat(sorted PCR SHA-256 values))`, requires non-zero measured
///    boot PCRs (PCR4 bootloader/UKI + PCR7 Secure Boot + PCR11/PCR9 immutable OS/rootfs), and
///    checks `workload_measurement_hex` against `policy.allowed_measurements`.
pub fn verify_azure_cvm_quote_with_pinned_roots(
    quote: &TeeAttestationQuote,
    expected_nonce: &[u8],
    policy: &AttestationPolicy,
    now_unix_s: u64,
    pinned_ark_sha256_hex: &[&str],
) -> Result<bool, TeeError> {
    let Some(WorkloadAttestation::AzureCvmHclVtpm {
        hcl_report_b64,
        vtpm_quote_b64,
        vtpm_quote_sig_b64,
        pcr_values,
        ..
    }) = quote.workload_attestation.as_ref()
    else {
        return Err(TeeError::VerificationFailed(
            "Missing AzureCvmHclVtpm workload_attestation payload (Trusted Launch rejected)".into(),
        ));
    };

    let hcl_bytes = B64_STD
        .decode(hcl_report_b64)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid Azure HCL base64: {e}")))?;
    let parsed_hcl = parse_azure_hcl_report(&hcl_bytes)?;

    let expected_rdat_hash = Sha256::digest(&parsed_hcl.runtime_data_json_bytes);
    if parsed_hcl.report_type == HCL_REPORT_TYPE_SNP {
        // Link 1 (AMD SEV-SNP): Verify embedded 1184B report against pinned AMD ARK roots!
        let snp = &parsed_hcl.hw_report;
        let snp_policy = u64::from_le_bytes(snp[SEV_SNP_POLICY_OFFSET..SEV_SNP_POLICY_OFFSET + 8].try_into().unwrap());
        let snp_rd = &snp[SEV_SNP_REPORT_DATA_OFFSET..SEV_SNP_REPORT_DATA_OFFSET + 64];
        let snp_meas = &snp[SEV_SNP_MEASUREMENT_OFFSET..SEV_SNP_MEASUREMENT_OFFSET + 48];
        let hw_quote_view = TeeAttestationQuote {
            vendor: TeeVendor::AmdSevSnp,
            public_key_hex: quote.public_key_hex.clone(),
            workload_measurement_hex: hex::encode(snp_meas),
            report_data_hex: hex::encode(snp_rd),
            nonce_hex: quote.nonce_hex.clone(),
            migration_disabled: (snp_policy & SEV_SNP_POLICY_MIGRATE_MA_BIT) == 0,
            debug_disabled: (snp_policy & SEV_SNP_POLICY_DEBUG_BIT) == 0,
            secure_tsc_enabled: quote.secure_tsc_enabled,
            gpu_binding: None,
            raw_quote_b64: B64_STD.encode(snp),
            vendor_cert_chain_pem: quote.vendor_cert_chain_pem.clone(),
            workload_attestation: None,
            generated_at_unix_s: quote.generated_at_unix_s,
        };
        let snp_ok = verify_raw_sev_snp_report_with_pinned_roots(
            &hw_quote_view,
            policy,
            now_unix_s,
            pinned_ark_sha256_hex,
        )?;
        if !snp_ok {
            return Err(TeeError::VerificationFailed(
                "Azure CVM embedded AMD SEV-SNP report did not pass vendor chain verification".into(),
            ));
        }
        // Link 2: Hardware SEV-SNP REPORT_DATA[0..32] MUST equal SHA-256(hcl_runtime_data_json_bytes).
        if snp_rd[0..32] != expected_rdat_hash[..] {
            return Err(TeeError::VerificationFailed(
                "Azure CVM SEV-SNP REPORT_DATA[0..32] does not match SHA-256(HCL runtime_data)".into(),
            ));
        }
    } else if parsed_hcl.report_type == HCL_REPORT_TYPE_TDX {
        // Link 1 (Intel TDX): Verify Intel DCAP v4 Quote in `quote.raw_quote_b64` against pinned Intel SGX Root CA!
        let tdx_raw = B64_STD
            .decode(&quote.raw_quote_b64)
            .map_err(|e| TeeError::VerificationFailed(format!("invalid Azure TDX DCAP quote base64: {e}")))?;
        if tdx_raw.len() < TDX_QUOTE_MIN_LEN {
            return Err(TeeError::VerificationFailed(format!(
                "Azure CVM TDX DCAP quote too short: {} < {}",
                tdx_raw.len(),
                TDX_QUOTE_MIN_LEN
            )));
        }
        let tdx_attrs = u64::from_le_bytes(
            tdx_raw[TDX_QUOTE_TDATTRIBUTES_OFFSET..TDX_QUOTE_TDATTRIBUTES_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        let tdx_mrtd = &tdx_raw[TDX_QUOTE_MRTD_OFFSET..TDX_QUOTE_MRTD_OFFSET + 48];
        let tdx_rd = &tdx_raw[TDX_QUOTE_REPORTDATA_OFFSET..TDX_QUOTE_REPORTDATA_OFFSET + 64];
        let hw_quote_view = TeeAttestationQuote {
            vendor: TeeVendor::IntelTdx,
            public_key_hex: quote.public_key_hex.clone(),
            workload_measurement_hex: hex::encode(tdx_mrtd),
            report_data_hex: hex::encode(tdx_rd),
            nonce_hex: quote.nonce_hex.clone(),
            migration_disabled: (tdx_attrs & TDX_ATTR_MIGRATABLE_BIT) == 0,
            debug_disabled: (tdx_attrs & TDX_ATTR_DEBUG_BIT) == 0,
            secure_tsc_enabled: true,
            gpu_binding: None,
            raw_quote_b64: quote.raw_quote_b64.clone(),
            vendor_cert_chain_pem: Vec::new(),
            workload_attestation: None,
            generated_at_unix_s: quote.generated_at_unix_s,
        };
        let tdx_ok = verify_raw_tdx_quote_with_pinned_roots(
            &hw_quote_view,
            policy,
            now_unix_s,
            PINNED_INTEL_ROOT_SHA256_HEX,
        )?;
        if !tdx_ok {
            return Err(TeeError::VerificationFailed(
                "Azure CVM Intel TDX DCAP v4 quote did not pass Intel Root CA verification".into(),
            ));
        }
        // Link 2: Hardware TDX REPORTDATA[0..32] MUST equal SHA-256(hcl_runtime_data_json_bytes)
        // AND match the HCL embedded TD_REPORT MRTD (offset 528..576 inside 1024B TD_REPORT).
        if tdx_rd[0..32] != expected_rdat_hash[..] {
            return Err(TeeError::VerificationFailed(
                "Azure CVM Intel TDX REPORTDATA[0..32] does not match SHA-256(HCL runtime_data)".into(),
            ));
        }
        if parsed_hcl.hw_report.len() >= 576 && &parsed_hcl.hw_report[528..576] != tdx_mrtd {
            return Err(TeeError::VerificationFailed(
                "Azure CVM Intel TDX DCAP quote MRTD does not match HCL TD_REPORT MRTD".into(),
            ));
        }
    } else {
        return Err(TeeError::VerificationFailed(format!(
            "Unsupported Azure CVM HCL report_type {}",
            parsed_hcl.report_type
        )));
    }

    // Link 3: Verify vTPM TPMS_ATTEST Quote RSA-2048 SHA-256 signature under hardware-bound akPub!
    let attest_bytes = B64_STD
        .decode(vtpm_quote_b64)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid Azure vTPM quote base64: {e}")))?;
    let sig_bytes = B64_STD
        .decode(vtpm_quote_sig_b64)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid Azure vTPM sig base64: {e}")))?;

    let n_bytes = B64_URL
        .decode(&parsed_hcl.ak_pub.n)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid Azure akPub modulus n: {e}")))?;
    let e_bytes = B64_URL
        .decode(&parsed_hcl.ak_pub.e)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid Azure akPub exponent e: {e}")))?;
    let rsa_pub = RsaPublicKeyComponents {
        n: &n_bytes,
        e: &e_bytes,
    };
    rsa_pub
        .verify(&RSA_PKCS1_2048_8192_SHA256, &attest_bytes, &sig_bytes)
        .map_err(|_| {
            TeeError::VerificationFailed(
                "Azure CVM vTPM TPMS_ATTEST RSA-2048 signature verification failed".into(),
            )
        })?;

    let parsed_attest = parse_tpms_attest_quote(&attest_bytes)?;

    // Verify extraData binds ephemeral enclave/CVM Ed25519 key + fresh verifier nonce!
    let pk_arr: [u8; 32] = hex::decode(&quote.public_key_hex)
        .map_err(|e| TeeError::VerificationFailed(format!("bad pk hex: {e}")))?
        .try_into()
        .map_err(|_| TeeError::VerificationFailed("pk must be 32 bytes".into()))?;
    let expected_extra = compute_azure_vtpm_qualifying_data(&pk_arr, expected_nonce);
    if parsed_attest.extra_data.as_slice() != expected_extra.as_slice() {
        return Err(TeeError::VerificationFailed(
            "Azure CVM vTPM extraData does not bind ephemeral public_key + expected fresh nonce".into(),
        ));
    }

    // Verify required measured-boot PCRs exist and are non-zero (PCR4 bootloader/UKI, PCR7 Secure Boot,
    // and PCR9 or PCR11 immutable UKI/dm-verity rootfs measurement).
    for req_pcr in [4u32, 7u32] {
        let val = pcr_values.get(&req_pcr).ok_or_else(|| {
            TeeError::PolicyRejected(format!(
                "Azure CVM measured guest missing mandatory PCR{req_pcr}"
            ))
        })?;
        if val.bytes().all(|b| b == b'0') {
            return Err(TeeError::PolicyRejected(format!(
                "Azure CVM mandatory PCR{req_pcr} is all-zero (unmeasured boot rejected)"
            )));
        }
    }
    let has_rootfs_pcr = [9u32, 11u32]
        .iter()
        .any(|p| pcr_values.get(p).map(|v| !v.bytes().all(|b| b == b'0')).unwrap_or(false));
    if !has_rootfs_pcr {
        return Err(TeeError::PolicyRejected(
            "Azure CVM measured guest missing non-zero PCR9/PCR11 (immutable kernel/initrd/dm-verity)".into(),
        ));
    }

    // Verify pcrDigest == SHA-256(concat(sorted PCR raw 32-byte values)).
    let mut pcr_concat = Sha256::new();
    for (idx, val) in pcr_values {
        let raw_pcr = hex::decode(val.trim()).map_err(|e| {
            TeeError::VerificationFailed(format!("invalid PCR{idx} hex: {e}"))
        })?;
        if raw_pcr.len() != 32 {
            return Err(TeeError::VerificationFailed(format!(
                "PCR{idx} must be 32 bytes"
            )));
        }
        pcr_concat.update(&raw_pcr);
    }
    let computed_pcr_digest = pcr_concat.finalize();
    if parsed_attest.pcr_digest.as_slice() != computed_pcr_digest.as_slice() {
        return Err(TeeError::VerificationFailed(
            "Azure CVM vTPM pcrDigest does not match SHA-256 of reported PCR values".into(),
        ));
    }

    let computed_workload_meas = compute_azure_pcr_workload_measurement(pcr_values)?;
    if !computed_workload_meas.eq_ignore_ascii_case(&quote.workload_measurement_hex) {
        return Err(TeeError::VerificationFailed(
            "Azure CVM computed PCR workload measurement does not match quote.workload_measurement_hex".into(),
        ));
    }

    Ok(true)
}

pub fn verify_azure_cvm_quote(
    quote: &TeeAttestationQuote,
    expected_nonce: &[u8],
    policy: &AttestationPolicy,
    now_unix_s: u64,
) -> Result<bool, TeeError> {
    verify_azure_cvm_quote_with_pinned_roots(
        quote,
        expected_nonce,
        policy,
        now_unix_s,
        PINNED_AMD_ARK_SHA256_HEX,
    )
}

/// Native Linux `/dev/tpmrm0` provider for Azure Confidential VMs (AMD SEV-SNP / Intel TDX).
/// Reads the HCL hardware report at NV index `0x01400001`, obtains a fresh `TPM2_Quote`
/// under persistent AK `0x81000003` over measured boot PCRs `[0, 1, 2, 4, 7, 9, 11, 14]`
/// with `qualifyingData = SHA-256("pog-azure-vtpm-v1" || pk || nonce)`, and FAILS CLOSED
/// on `TrustedLaunch` VMs (which have no `"HCLA"` SEV-SNP/TDX hardware report at `0x01400001`).
pub struct AzureCvmProvider {
    pub tpm_device: String,
    detected_vendor: TeeVendor,
    #[cfg(target_os = "linux")]
    cached_vendor_chain: OnceLock<Vec<String>>,
    #[cfg(target_os = "linux")]
    cached_tdx_quote: OnceLock<Vec<u8>>,
}

impl Default for AzureCvmProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
fn http_imds_request(method: &str, path: &str, body: Option<&[u8]>) -> Result<Vec<u8>, TeeError> {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    let addr: SocketAddr = "169.254.169.254:80".parse().unwrap();
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(4))
        .map_err(|e| TeeError::GenerationFailed(format!("Azure IMDS connect failed ({path}): {e}")))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(6)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(4)));

    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 169.254.169.254\r\nMetadata: true\r\nConnection: close\r\n"
    );
    if let Some(b) = body {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| TeeError::GenerationFailed(format!("Azure IMDS write failed: {e}")))?;
    if let Some(b) = body {
        stream
            .write_all(b)
            .map_err(|e| TeeError::GenerationFailed(format!("Azure IMDS body write failed: {e}")))?;
    }
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| TeeError::GenerationFailed(format!("Azure IMDS read failed: {e}")))?;
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| TeeError::GenerationFailed("Malformed Azure IMDS HTTP response".into()))?;
    let header_str = std::str::from_utf8(&raw[..sep]).unwrap_or("");
    let status_ok = header_str
        .lines()
        .next()
        .map(|l| l.contains(" 200 "))
        .unwrap_or(false);
    if !status_ok {
        return Err(TeeError::GenerationFailed(format!(
            "Azure IMDS {path} non-200 response: {}",
            header_str.lines().next().unwrap_or("unknown")
        )));
    }
    let body_raw = &raw[sep + 4..];
    if header_str.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        let mut out = Vec::new();
        let mut slice = body_raw;
        while let Some(pos) = slice.windows(2).position(|w| w == b"\r\n") {
            let sz_str = std::str::from_utf8(&slice[..pos]).unwrap_or("").trim();
            let sz = usize::from_str_radix(sz_str.split(';').next().unwrap_or(""), 16).unwrap_or(0);
            slice = &slice[pos + 2..];
            if sz == 0 || sz > slice.len() {
                break;
            }
            out.extend_from_slice(&slice[..sz]);
            slice = if slice.len() >= sz + 2 { &slice[sz + 2..] } else { &[] };
        }
        Ok(out)
    } else {
        Ok(body_raw.to_vec())
    }
}

impl AzureCvmProvider {
    pub fn new() -> Self {
        #[allow(unused_mut)]
        let mut prov = Self {
            tpm_device: "/dev/tpmrm0".to_string(),
            detected_vendor: TeeVendor::AmdSevSnp,
            #[cfg(target_os = "linux")]
            cached_vendor_chain: OnceLock::new(),
            #[cfg(target_os = "linux")]
            cached_tdx_quote: OnceLock::new(),
        };
        #[cfg(target_os = "linux")]
        {
            if let Ok(hcl) = prov.read_hcl_report() {
                if let Ok(parsed) = parse_azure_hcl_report(&hcl) {
                    if parsed.report_type == HCL_REPORT_TYPE_TDX {
                        prov.detected_vendor = TeeVendor::IntelTdx;
                    }
                }
            }
        }
        prov
    }

    #[cfg(target_os = "linux")]
    fn load_or_fetch_amd_vcek_chain(&self) -> Vec<String> {
        self.cached_vendor_chain
            .get_or_init(|| {
                let path = std::env::var("POG_AMD_CERT_CHAIN_PATH")
                    .unwrap_or_else(|_| "/etc/pog/amd_vcek_chain.pem".to_string());
                if let Ok(raw) = std::fs::read_to_string(&path) {
                    let parsed: Vec<String> = ::pem::parse_many(raw)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|p| ::pem::encode(&p))
                        .collect();
                    if parsed.len() >= 3 {
                        return parsed;
                    }
                }
                // Fallback: Azure THIM IMDS AMD certification endpoint (untrusted transport;
                // external verifier cryptographically pins AMD ARK root SHA-256).
                if let Ok(resp) = http_imds_request("GET", "/metadata/THIM/amd/certification", None) {
                    if let Ok(v) = serde_json::from_slice::<Value>(&resp) {
                        let vcek = v.get("vcekCert").and_then(|x| x.as_str()).unwrap_or("");
                        let chain = v.get("certificateChain").and_then(|x| x.as_str()).unwrap_or("");
                        let combined = format!("{vcek}\n{chain}\n");
                        let parsed: Vec<String> = ::pem::parse_many(combined)
                            .unwrap_or_default()
                            .into_iter()
                            .map(|p| ::pem::encode(&p))
                            .collect();
                        if parsed.len() >= 3 {
                            return parsed;
                        }
                    }
                }
                Vec::new()
            })
            .clone()
    }

    #[cfg(target_os = "linux")]
    fn load_or_fetch_tdx_quote(&self, td_report_1024: &[u8]) -> Result<Vec<u8>, TeeError> {
        if let Some(q) = self.cached_tdx_quote.get() {
            return Ok(q.clone());
        }
        let path = std::env::var("POG_AZURE_TDX_QUOTE_PATH")
            .unwrap_or_else(|_| "/etc/pog/azure_tdx_quote.bin".to_string());
        if let Ok(raw) = std::fs::read(&path) {
            if raw.len() >= TDX_QUOTE_MIN_LEN {
                let _ = self.cached_tdx_quote.set(raw.clone());
                return Ok(raw);
            }
        }
        let payload = serde_json::json!({ "report": B64_URL.encode(td_report_1024) }).to_string();
        let resp = http_imds_request("POST", "/acc/tdquote", Some(payload.as_bytes()))?;
        let val: Value = serde_json::from_slice(&resp).map_err(|e| {
            TeeError::GenerationFailed(format!("Invalid Azure /acc/tdquote JSON: {e}"))
        })?;
        let q_str = val
            .get("quote")
            .and_then(|x| x.as_str())
            .ok_or_else(|| TeeError::GenerationFailed("Azure /acc/tdquote missing quote field".into()))?;
        let raw = B64_URL
            .decode(q_str)
            .or_else(|_| B64_URL_PAD.decode(q_str))
            .or_else(|_| B64_STD.decode(q_str))
            .map_err(|e| TeeError::GenerationFailed(format!("Invalid Azure /acc/tdquote base64: {e}")))?;
        let _ = self.cached_tdx_quote.set(raw.clone());
        Ok(raw)
    }

    #[cfg(target_os = "linux")]
    fn tpm_transact(&self, cmd: &[u8]) -> Result<Vec<u8>, TeeError> {
        use std::fs::OpenOptions;
        use std::io::{Read, Write};

        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.tpm_device)
            .map_err(|e| TeeError::HardwareDeviceUnavailable(format!("{}: {e}", self.tpm_device)))?;
        f.write_all(cmd)
            .map_err(|e| TeeError::GenerationFailed(format!("TPM write failed: {e}")))?;
        let mut buf = vec![0u8; 4096];
        let n = f
            .read(&mut buf)
            .map_err(|e| TeeError::GenerationFailed(format!("TPM read failed: {e}")))?;
        buf.truncate(n);
        if buf.len() < 10 {
            return Err(TeeError::GenerationFailed("TPM response shorter than 10B header".into()));
        }
        let rc = u32::from_be_bytes(buf[6..10].try_into().unwrap());
        if rc != 0 {
            return Err(TeeError::GenerationFailed(format!(
                "TPM2 command failed with responseCode {rc:#x}"
            )));
        }
        Ok(buf)
    }

    #[cfg(target_os = "linux")]
    fn read_hcl_report(&self) -> Result<Vec<u8>, TeeError> {
        // 1. TPM2_NV_ReadPublic (CC = 0x00000169) on 0x01400001
        let mut cmd = Vec::with_capacity(14);
        cmd.extend_from_slice(&0x8001u16.to_be_bytes()); // TPM_ST_NO_SESSIONS
        cmd.extend_from_slice(&14u32.to_be_bytes());
        cmd.extend_from_slice(&0x0000_0169u32.to_be_bytes());
        cmd.extend_from_slice(&AZURE_HCL_NV_INDEX.to_be_bytes());
        let pub_resp = self.tpm_transact(&cmd)?;
        if pub_resp.len() < 26 {
            return Err(TeeError::GenerationFailed("NV_ReadPublic response truncated".into()));
        }
        let nv_pub_size = u16::from_be_bytes(pub_resp[10..12].try_into().unwrap()) as usize;
        if 12 + nv_pub_size > pub_resp.len() || nv_pub_size < 14 {
            return Err(TeeError::GenerationFailed("NV_Public size out of bounds".into()));
        }
        let nv_pub = &pub_resp[12..12 + nv_pub_size];
        // TPMS_NV_PUBLIC: nvIndex(4) + nameAlg(2) + attributes(4) + authPolicy(2+N) + dataSize(2)
        let auth_len = u16::from_be_bytes(nv_pub[10..12].try_into().unwrap()) as usize;
        let data_size = u16::from_be_bytes(nv_pub[12 + auth_len..14 + auth_len].try_into().unwrap()) as usize;

        // 2. TPM2_NV_Read (CC = 0x0000014E) in 1024B chunks using TPM_RH_OWNER empty password session
        let mut out = Vec::with_capacity(data_size);
        let mut offset = 0usize;
        while offset < data_size {
            let chunk = (data_size - offset).min(1024) as u16;
            let mut rcmd = Vec::with_capacity(35);
            rcmd.extend_from_slice(&0x8002u16.to_be_bytes()); // TPM_ST_SESSIONS
            rcmd.extend_from_slice(&35u32.to_be_bytes());
            rcmd.extend_from_slice(&0x0000_014Eu32.to_be_bytes()); // TPM2_CC_NV_Read
            rcmd.extend_from_slice(&0x4000_0001u32.to_be_bytes()); // TPM_RH_OWNER
            rcmd.extend_from_slice(&AZURE_HCL_NV_INDEX.to_be_bytes());
            rcmd.extend_from_slice(&9u32.to_be_bytes()); // authSize = 9
            rcmd.extend_from_slice(&0x4000_0009u32.to_be_bytes()); // TPM_RS_PW
            rcmd.extend_from_slice(&0u16.to_be_bytes()); // nonceCaller len
            rcmd.push(0x01); // continueSession
            rcmd.extend_from_slice(&0u16.to_be_bytes()); // hmac len
            rcmd.extend_from_slice(&chunk.to_be_bytes());
            rcmd.extend_from_slice(&(offset as u16).to_be_bytes());
            let rresp = self.tpm_transact(&rcmd)?;
            // Response with sessions: header(10) + paramSize(4) + TPM2B_MAX_NV_BUFFER(2 + len)
            if rresp.len() < 16 {
                return Err(TeeError::GenerationFailed("NV_Read response truncated".into()));
            }
            let got = u16::from_be_bytes(rresp[14..16].try_into().unwrap()) as usize;
            if 16 + got > rresp.len() {
                return Err(TeeError::GenerationFailed("NV_Read payload truncated".into()));
            }
            out.extend_from_slice(&rresp[16..16 + got]);
            offset += got;
            if got == 0 {
                break;
            }
        }
        Ok(out)
    }

    #[cfg(target_os = "linux")]
    fn read_sha256_pcrs(&self, indices: &[u32]) -> Result<BTreeMap<u32, String>, TeeError> {
        let mut map = BTreeMap::new();
        for &idx in indices {
            let mut bitmap = [0u8; 3];
            bitmap[(idx / 8) as usize] |= 1 << (idx % 8);
            let mut cmd = Vec::with_capacity(20);
            cmd.extend_from_slice(&0x8001u16.to_be_bytes());
            cmd.extend_from_slice(&20u32.to_be_bytes());
            cmd.extend_from_slice(&0x0000_017Eu32.to_be_bytes()); // TPM2_CC_PCR_Read
            cmd.extend_from_slice(&1u32.to_be_bytes());
            cmd.extend_from_slice(&0x000Bu16.to_be_bytes()); // SHA-256
            cmd.push(3u8);
            cmd.extend_from_slice(&bitmap);
            let resp = self.tpm_transact(&cmd)?;
            // header(10) + pcrUpdateCounter(4) + pcrSelectionOut(4+2+1+3=10) + pcrValues.count(4) + digest(2+32)
            if resp.len() < 62 {
                return Err(TeeError::GenerationFailed(format!("PCR_Read({idx}) truncated")));
            }
            let dlen = u16::from_be_bytes(resp[28..30].try_into().unwrap()) as usize;
            if dlen != 32 || 30 + dlen > resp.len() {
                return Err(TeeError::GenerationFailed(format!("PCR_Read({idx}) bad digest len {dlen}")));
            }
            map.insert(idx, hex::encode(&resp[30..30 + dlen]));
        }
        Ok(map)
    }

    #[cfg(target_os = "linux")]
    fn tpm2_quote(&self, qualifying_data: &[u8; 32], indices: &[u32]) -> Result<(Vec<u8>, Vec<u8>), TeeError> {
        let mut bitmap = [0u8; 3];
        for &idx in indices {
            bitmap[(idx / 8) as usize] |= 1 << (idx % 8);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&AZURE_VTPM_AK_HANDLE.to_be_bytes());
        body.extend_from_slice(&9u32.to_be_bytes()); // authSize
        body.extend_from_slice(&0x4000_0009u32.to_be_bytes()); // TPM_RS_PW
        body.extend_from_slice(&0u16.to_be_bytes());
        body.push(0x01);
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&32u16.to_be_bytes());
        body.extend_from_slice(qualifying_data);
        body.extend_from_slice(&0x0010u16.to_be_bytes()); // TPM_ALG_NULL (use AK default scheme RSASSA-SHA256)
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(&0x000Bu16.to_be_bytes()); // SHA-256
        body.push(3u8);
        body.extend_from_slice(&bitmap);

        let total = (10 + body.len()) as u32;
        let mut cmd = Vec::with_capacity(total as usize);
        cmd.extend_from_slice(&0x8002u16.to_be_bytes());
        cmd.extend_from_slice(&total.to_be_bytes());
        cmd.extend_from_slice(&0x0000_0158u32.to_be_bytes()); // TPM2_CC_Quote
        cmd.extend_from_slice(&body);

        let resp = self.tpm_transact(&cmd)?;
        // header(10) + paramSize(4) + quoted(2 + N) + signature(sigAlg:2 + hashAlg:2 + sigLen:2 + sigBytes)
        if resp.len() < 22 {
            return Err(TeeError::GenerationFailed("TPM2_Quote response truncated".into()));
        }
        let qlen = u16::from_be_bytes(resp[14..16].try_into().unwrap()) as usize;
        let sig_off = 16 + qlen;
        if sig_off + 6 > resp.len() {
            return Err(TeeError::GenerationFailed("TPM2_Quote signature truncated".into()));
        }
        let quoted = resp[16..sig_off].to_vec();
        let slen = u16::from_be_bytes(resp[sig_off + 4..sig_off + 6].try_into().unwrap()) as usize;
        if sig_off + 6 + slen > resp.len() {
            return Err(TeeError::GenerationFailed("TPM2_Quote RSA sig bytes truncated".into()));
        }
        let sig = resp[sig_off + 6..sig_off + 6 + slen].to_vec();
        Ok((quoted, sig))
    }

    /// True ONLY if `/dev/tpmrm0` exists AND NV index `0x01400001` contains a valid Azure CVM
    /// `"HCLA"` SEV-SNP or TDX hardware report (returns `false` on Azure Trusted Launch!).
    pub fn is_available() -> bool {
        #[cfg(target_os = "linux")]
        {
            if !std::path::Path::new("/dev/tpmrm0").exists() {
                return false;
            }
            let prov = Self::new();
            prov.read_hcl_report()
                .ok()
                .and_then(|b| parse_azure_hcl_report(&b).ok())
                .is_some()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
}

impl crate::types::TeeProvider for AzureCvmProvider {
    fn vendor(&self) -> TeeVendor {
        self.detected_vendor
    }

    fn attest(
        &self,
        public_key: &[u8; 32],
        nonce: &[u8],
        gpu_binding: Option<crate::types::GpuAttestationBinding>,
    ) -> Result<TeeAttestationQuote, TeeError> {
        #[cfg(target_os = "linux")]
        {
            let hcl = self.read_hcl_report()?;
            let parsed = parse_azure_hcl_report(&hcl)?;
            let pcr_indices = [0u32, 1, 2, 4, 7, 9, 11, 14];
            let pcr_values = self.read_sha256_pcrs(&pcr_indices)?;
            let qdata = compute_azure_vtpm_qualifying_data(public_key, nonce);
            let (quoted, sig) = self.tpm2_quote(&qdata, &pcr_indices)?;
            let workload_meas = compute_azure_pcr_workload_measurement(&pcr_values)?;
            let report_data = crate::types::compute_report_data(public_key, nonce, gpu_binding.as_ref());

            let (vendor, migration_disabled, debug_disabled, raw_quote_b64, vendor_cert_chain_pem) =
                if parsed.report_type == HCL_REPORT_TYPE_TDX {
                    let tdx_quote = self.load_or_fetch_tdx_quote(&parsed.hw_report)?;
                    if tdx_quote.len() < TDX_QUOTE_MIN_LEN {
                        return Err(TeeError::GenerationFailed(
                            "Azure /acc/tdquote returned quote shorter than TDX v4 minimum".into(),
                        ));
                    }
                    let attrs = u64::from_le_bytes(
                        tdx_quote[TDX_QUOTE_TDATTRIBUTES_OFFSET..TDX_QUOTE_TDATTRIBUTES_OFFSET + 8]
                            .try_into()
                            .unwrap(),
                    );
                    (
                        TeeVendor::IntelTdx,
                        (attrs & TDX_ATTR_MIGRATABLE_BIT) == 0,
                        (attrs & TDX_ATTR_DEBUG_BIT) == 0,
                        B64_STD.encode(&tdx_quote),
                        Vec::new(),
                    )
                } else {
                    let snp = &parsed.hw_report;
                    let snp_policy = u64::from_le_bytes(
                        snp[SEV_SNP_POLICY_OFFSET..SEV_SNP_POLICY_OFFSET + 8]
                            .try_into()
                            .unwrap(),
                    );
                    (
                        TeeVendor::AmdSevSnp,
                        (snp_policy & SEV_SNP_POLICY_MIGRATE_MA_BIT) == 0,
                        (snp_policy & SEV_SNP_POLICY_DEBUG_BIT) == 0,
                        B64_STD.encode(snp),
                        self.load_or_fetch_amd_vcek_chain(),
                    )
                };

            Ok(TeeAttestationQuote {
                vendor,
                public_key_hex: hex::encode(public_key),
                workload_measurement_hex: workload_meas,
                report_data_hex: hex::encode(report_data),
                nonce_hex: hex::encode(nonce),
                migration_disabled,
                debug_disabled,
                secure_tsc_enabled: true,
                gpu_binding,
                raw_quote_b64,
                vendor_cert_chain_pem,
                workload_attestation: Some(WorkloadAttestation::AzureCvmHclVtpm {
                    hcl_report_b64: B64_STD.encode(&hcl),
                    vtpm_quote_b64: B64_STD.encode(&quoted),
                    vtpm_quote_sig_b64: B64_STD.encode(&sig),
                    pcr_values,
                    ak_pub_jwk_json: serde_json::to_string(&parsed.ak_pub).unwrap_or_default(),
                }),
                generated_at_unix_s: chrono::Utc::now().timestamp().max(0) as u64,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (public_key, nonce, gpu_binding);
            Err(TeeError::HardwareDeviceUnavailable(
                "Azure CVM /dev/tpmrm0 HCL+vTPM requires Linux Azure Confidential VM".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sev_snp::{SEV_SNP_SIGNED_BODY_LEN, SEV_SNP_SIG_R_OFFSET, SEV_SNP_SIG_S_OFFSET};
    use crate::types::{compute_report_data, WorkloadKeypair};
    use p384::ecdsa::signature::Signer as P384Signer;
    use p384::ecdsa::{Signature as P384Signature, SigningKey as P384SigningKey};
    use p384::pkcs8::DecodePrivateKey;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, PKCS_ECDSA_P384_SHA384};
    use ring::rand::SystemRandom;
    use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};

    fn parse_pkcs1_rsa_pub_ne(der: &[u8]) -> (&[u8], &[u8]) {
        fn read_tlv(b: &[u8]) -> (u8, &[u8], &[u8]) {
            let tag = b[0];
            let (len, off) = if b[1] & 0x80 == 0 {
                (b[1] as usize, 2)
            } else {
                let n = (b[1] & 0x7f) as usize;
                let mut v = 0usize;
                for &x in &b[2..2 + n] {
                    v = (v << 8) | (x as usize);
                }
                (v, 2 + n)
            };
            (tag, &b[off..off + len], &b[off + len..])
        }
        let (_, seq, _) = read_tlv(der);
        let (_, n_raw, rest) = read_tlv(seq);
        let (_, e_raw, _) = read_tlv(rest);
        (n_raw.strip_prefix(&[0]).unwrap_or(n_raw), e_raw.strip_prefix(&[0]).unwrap_or(e_raw))
    }

    fn build_tpms_attest_blob(extra_data: &[u8], pcr_digest: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&TPM2_GENERATED_VALUE.to_be_bytes());
        out.extend_from_slice(&TPM2_ST_ATTEST_QUOTE.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(b"AK01");
        out.extend_from_slice(&(extra_data.len() as u16).to_be_bytes());
        out.extend_from_slice(extra_data);
        out.extend_from_slice(&[0u8; 25]); // clockInfo (17) + firmwareVersion (8)
        out.extend_from_slice(&1u32.to_be_bytes()); // 1 PCR selection
        out.extend_from_slice(&0x000Bu16.to_be_bytes()); // SHA-256
        out.push(3u8);
        out.extend_from_slice(&[0x90, 0x0A, 0x00]); // PCRs 4,7,9,11
        out.extend_from_slice(&(pcr_digest.len() as u16).to_be_bytes());
        out.extend_from_slice(pcr_digest);
        out
    }

    fn build_synthetic_azure_cvm_bundle(
        now: u64,
        policy_bits: u64,
        hcl_report_type: u32,
        pcrs: &BTreeMap<u32, String>,
        wk: &WorkloadKeypair,
        nonce: &[u8],
    ) -> (TeeAttestationQuote, String) {
        // 1. Generate synthetic AMD ARK -> ASK -> VCEK P-384 chain
        let mut ark_p = CertificateParams::default();
        ark_p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ark_p.distinguished_name.push(DnType::CommonName, "ARK-Genoa-Test");
        let ark_kp = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let ark_c = ark_p.self_signed(&ark_kp).unwrap();
        let ark_fp = hex::encode(Sha256::digest(ark_c.der().as_ref()));

        let mut ask_p = CertificateParams::default();
        ask_p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ask_p.distinguished_name.push(DnType::CommonName, "SEV-Genoa-Test");
        let ask_kp = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let ask_c = ask_p.signed_by(&ask_kp, &ark_c, &ark_kp).unwrap();

        let mut vcek_p = CertificateParams::default();
        vcek_p.distinguished_name.push(DnType::CommonName, "SEV-VCEK-Test");
        let vcek_kp = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let vcek_c = vcek_p.signed_by(&vcek_kp, &ask_c, &ask_kp).unwrap();

        // 2. Generate ephemeral vTPM AK RSA-2048 keypair (canonical PKCS#8 DER across OpenSSL 3 / LibreSSL)
        let pem_out = std::process::Command::new("openssl")
            .args(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"])
            .stderr(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(pem_out.status.success());
        let mut pk8 = std::process::Command::new("openssl")
            .args(["pkcs8", "-topk8", "-nocrypt", "-outform", "DER"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        {
            use std::io::Write;
            pk8.stdin.as_mut().unwrap().write_all(&pem_out.stdout).unwrap();
        }
        let ak_der = pk8.wait_with_output().unwrap().stdout;
        let ak_kp = RsaKeyPair::from_pkcs8(&ak_der)
            .or_else(|_| RsaKeyPair::from_der(&ak_der))
            .unwrap();
        let (ak_n, ak_e) = parse_pkcs1_rsa_pub_ne(ak_kp.public().as_ref());
        let ak_jwk = RsaJwk {
            kty: "RSA".into(),
            kid: Some("HCLAkPub".into()),
            alg: Some("RS256".into()),
            n: B64_URL.encode(ak_n),
            e: B64_URL.encode(ak_e),
        };
        let rdat_json = serde_json::json!({
            "keys": [ak_jwk],
            "vm-configuration": {
                "root-cert-thumbprint": ark_fp,
                "console-enabled": false,
                "secure-boot": true,
                "tpm-enabled": true,
                "tpm-persisted": false
            }
        })
        .to_string();
        let rdat_hash = Sha256::digest(rdat_json.as_bytes());

        // 3. Build & sign 1184-byte AMD SEV-SNP report binding SHA-256(rdat_json) into REPORT_DATA[0..32]
        let mut snp = vec![0u8; SEV_SNP_REPORT_LEN];
        snp[0..4].copy_from_slice(&2u32.to_le_bytes());
        snp[SEV_SNP_POLICY_OFFSET..SEV_SNP_POLICY_OFFSET + 8].copy_from_slice(&policy_bits.to_le_bytes());
        snp[SEV_SNP_REPORT_DATA_OFFSET..SEV_SNP_REPORT_DATA_OFFSET + 32].copy_from_slice(&rdat_hash);
        snp[SEV_SNP_MEASUREMENT_OFFSET..SEV_SNP_MEASUREMENT_OFFSET + 48].copy_from_slice(&[0xCDu8; 48]);

        let vcek_sk = P384SigningKey::from_pkcs8_der(vcek_kp.serialize_der().as_ref()).unwrap();
        let sig: P384Signature = vcek_sk.sign(&snp[..SEV_SNP_SIGNED_BODY_LEN]);
        let sb = sig.to_bytes();
        let mut r_le = [0u8; 72];
        let mut s_le = [0u8; 72];
        for i in 0..48 {
            r_le[i] = sb[47 - i];
            s_le[i] = sb[95 - i];
        }
        snp[SEV_SNP_SIG_R_OFFSET..SEV_SNP_SIG_R_OFFSET + 72].copy_from_slice(&r_le);
        snp[SEV_SNP_SIG_S_OFFSET..SEV_SNP_SIG_S_OFFSET + 72].copy_from_slice(&s_le);

        // 4. Pack Azure HCL Report binary (header + SEV-SNP report + RDAT header + runtime_data JSON)
        let mut hcl = Vec::new();
        hcl.extend_from_slice(&HCL_HEADER_SIGNATURE.to_le_bytes());
        hcl.extend_from_slice(&1u32.to_le_bytes());
        hcl.extend_from_slice(&(SEV_SNP_REPORT_LEN as u32).to_le_bytes());
        hcl.extend_from_slice(&hcl_report_type.to_le_bytes());
        hcl.extend_from_slice(&0u32.to_le_bytes());
        hcl.extend_from_slice(&[0u8; 12]);
        hcl.extend_from_slice(&snp);
        let rdat_total = (20 + rdat_json.len()) as u32;
        hcl.extend_from_slice(&rdat_total.to_le_bytes());
        hcl.extend_from_slice(&1u32.to_le_bytes());
        hcl.extend_from_slice(&hcl_report_type.to_le_bytes());
        hcl.extend_from_slice(&1u32.to_le_bytes());
        hcl.extend_from_slice(&(rdat_json.len() as u32).to_le_bytes());
        hcl.extend_from_slice(rdat_json.as_bytes());

        // 5. Build & sign TPM2_Quote TPMS_ATTEST over sorted PCRs + qualifyingData(pk, nonce)
        let mut pcr_h = Sha256::new();
        for v in pcrs.values() {
            pcr_h.update(hex::decode(v).unwrap());
        }
        let pcr_digest = pcr_h.finalize();
        let extra_data = compute_azure_vtpm_qualifying_data(&wk.public_key_bytes(), nonce);
        let attest_blob = build_tpms_attest_blob(&extra_data, &pcr_digest);
        let mut vtpm_sig = vec![0u8; ak_kp.public().modulus_len()];
        ak_kp
            .sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), &attest_blob, &mut vtpm_sig)
            .unwrap();

        let workload_meas = compute_azure_pcr_workload_measurement(pcrs).unwrap();
        let rd = compute_report_data(&wk.public_key_bytes(), nonce, None);
        let quote = TeeAttestationQuote {
            vendor: TeeVendor::AmdSevSnp,
            public_key_hex: wk.public_key_hex(),
            workload_measurement_hex: workload_meas,
            report_data_hex: hex::encode(rd),
            nonce_hex: hex::encode(nonce),
            migration_disabled: (policy_bits & SEV_SNP_POLICY_MIGRATE_MA_BIT) == 0,
            debug_disabled: (policy_bits & SEV_SNP_POLICY_DEBUG_BIT) == 0,
            secure_tsc_enabled: true,
            gpu_binding: None,
            raw_quote_b64: B64_STD.encode(&snp),
            vendor_cert_chain_pem: vec![vcek_c.pem(), ask_c.pem(), ark_c.pem()],
            workload_attestation: Some(WorkloadAttestation::AzureCvmHclVtpm {
                hcl_report_b64: B64_STD.encode(&hcl),
                vtpm_quote_b64: B64_STD.encode(&attest_blob),
                vtpm_quote_sig_b64: B64_STD.encode(&vtpm_sig),
                pcr_values: pcrs.clone(),
                ak_pub_jwk_json: serde_json::to_string(&ak_jwk).unwrap(),
            }),
            generated_at_unix_s: now,
        };
        (quote, ark_fp)
    }

    #[test]
    fn test_azure_cvm_hcl_vtpm_chain_positive_and_negative_gates() {
        let now = chrono::Utc::now().timestamp() as u64;
        let wk = WorkloadKeypair::generate();
        let nonce = b"azure-cvm-fresh-nonce-2026-32byt";
        let mut pcrs = BTreeMap::new();
        pcrs.insert(4, "11".repeat(32)); // Measured UKI bootloader
        pcrs.insert(7, "22".repeat(32)); // Secure Boot policy
        pcrs.insert(11, "33".repeat(32)); // Measured dm-verity zero-SSH rootfs

        let (quote, ark_fp) = build_synthetic_azure_cvm_bundle(now, 0x0003_0000, HCL_REPORT_TYPE_SNP, &pcrs, &wk, nonce);
        let mut pol = AttestationPolicy::production();
        pol.allowed_measurements = vec![quote.workload_measurement_hex.clone()];

        // 1. Valid synthetic Azure CVM HCL+SEV-SNP+vTPM chain PASSES against its pinned ARK!
        assert!(verify_azure_cvm_quote_with_pinned_roots(&quote, nonce, &pol, now, &[&ark_fp]).unwrap());

        // 2. Unpinned self-signed ARK MUST FAIL against real production pinned AMD ARK roots!
        assert!(verify_azure_cvm_quote(&quote, nonce, &pol, now).is_err());

        // 3. Trusted Launch (report_type = 0 / non-CVM) MUST FAIL!
        let (tl_quote, tl_fp) = build_synthetic_azure_cvm_bundle(now, 0x0003_0000, 0, &pcrs, &wk, nonce);
        assert!(verify_azure_cvm_quote_with_pinned_roots(&tl_quote, nonce, &pol, now, &[&tl_fp]).is_err());

        // 4. Wrong/stale nonce MUST FAIL!
        assert!(verify_azure_cvm_quote_with_pinned_roots(&quote, b"wrong-stale-nonce-00000000000000", &pol, now, &[&ark_fp]).is_err());

        // 5. Debug-enabled SEV-SNP policy bit MUST FAIL!
        let (dbg_q, dbg_fp) = build_synthetic_azure_cvm_bundle(now, 0x0003_0000 | SEV_SNP_POLICY_DEBUG_BIT, HCL_REPORT_TYPE_SNP, &pcrs, &wk, nonce);
        assert!(verify_azure_cvm_quote_with_pinned_roots(&dbg_q, nonce, &pol, now, &[&dbg_fp]).is_err());

        // 6. Tampered PCR value (wrong measured guest workload!) MUST FAIL!
        let mut bad_pcr_q = quote.clone();
        if let Some(WorkloadAttestation::AzureCvmHclVtpm { ref mut pcr_values, .. }) = bad_pcr_q.workload_attestation {
            pcr_values.insert(11, "ff".repeat(32));
        }
        assert!(verify_azure_cvm_quote_with_pinned_roots(&bad_pcr_q, nonce, &pol, now, &[&ark_fp]).is_err());
    }
}
