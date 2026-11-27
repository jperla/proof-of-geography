use crate::types::{
    compute_report_data, AttestationPolicy, GpuAttestationBinding, TeeAttestationQuote, TeeError,
    TeeProvider, TeeVendor, WorkloadAttestation,
};
use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD as B64_URL};
use base64::Engine;
use chrono::Utc;
use ring::signature::{RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Official Google Cloud Confidential Space OIDC issuer.
pub const GCP_CS_ISSUER: &str = "https://confidentialcomputing.googleapis.com";
/// Official Google Cloud Confidential Space OIDC JWKS URI (discovered from
/// `https://confidentialcomputing.googleapis.com/.well-known/openid-configuration`).
pub const GCP_CS_JWKS_URI: &str =
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com";
/// Default OIDC audience bound into Proof of Geography Confidential Space attestation tokens.
pub const GCP_CS_DEFAULT_AUDIENCE: &str = "https://proofofgeography.com";
/// Local Unix domain socket exposed by the Confidential Space production container launcher.
pub const GCP_CS_TEE_SOCKET: &str = "/run/container_launcher/teeserver.sock";

/// Minimal RSA JWK representation matching Google's Confidential Space JWKS endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsaJwk {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    /// Base64url-encoded RSA modulus.
    pub n: String,
    /// Base64url-encoded RSA public exponent.
    pub e: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<RsaJwk>,
}

/// Verified claims extracted from a cryptographically verified GCP Confidential Space OIDC JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedGcpConfidentialSpaceToken {
    pub issuer: String,
    pub audience: String,
    pub hwmodel: String,
    pub swname: String,
    pub dbgstat: String,
    pub secboot: bool,
    pub image_digest: String,
    pub image_digest_hex: String,
    #[serde(default)]
    pub gce_zone: Option<String>,
    #[serde(default)]
    pub gce_project_id: Option<String>,
    #[serde(default)]
    pub gce_instance_name: Option<String>,
    pub iat: u64,
    pub exp: u64,
    pub kid: String,
}

/// Google Cloud Confidential Space Intel TDX provider talking directly to
/// `/run/container_launcher/teeserver.sock` (`POST http://localhost/v1/token`).
///
/// Cryptographically binds:
/// - Intel TDX hardware (`hwmodel == "GCP_INTEL_TDX"`, `secboot == true`, `dbgstat == "disabled-since-boot"`),
/// - The exact pinned zero-shell `FROM scratch` OCI image digest (`submods.container.image_digest`),
/// - Empty `cmd_override` (blocking `--allow-dev-*` boot flag injection),
/// - The enclave-generated ephemeral Ed25519 signing key (`public_key_hex`) and fresh verifier nonce (`eat_nonce`).
pub struct GcpConfidentialSpaceProvider {
    pub socket_path: String,
    pub audience: String,
}

impl Default for GcpConfidentialSpaceProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl GcpConfidentialSpaceProvider {
    pub fn new() -> Self {
        let audience = std::env::var("POG_GCP_CS_AUDIENCE")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| GCP_CS_DEFAULT_AUDIENCE.to_string());
        Self {
            socket_path: GCP_CS_TEE_SOCKET.to_string(),
            audience,
        }
    }

    pub fn with_audience(audience: impl Into<String>) -> Self {
        Self {
            socket_path: GCP_CS_TEE_SOCKET.to_string(),
            audience: audience.into(),
        }
    }

    pub fn is_available() -> bool {
        std::path::Path::new(GCP_CS_TEE_SOCKET).exists()
    }

    #[cfg(target_os = "linux")]
    fn fetch_oidc_token(&self, pk_hex: &str, nonce_hex: &str) -> Result<String, TeeError> {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        // Google Confidential Space `/v1/token` enforces 8..=88 byte strings per nonce (max 6).
        // Both `pk_hex` (64 ASCII chars) and `nonce_hex` (32..=88 chars; truncate/hash if >88)
        // fit cleanly within the specification.
        let nonce_claim = if nonce_hex.len() >= 8 && nonce_hex.len() <= 88 {
            nonce_hex.to_string()
        } else {
            hex::encode(Sha256::digest(nonce_hex.as_bytes()))
        };

        let body = serde_json::json!({
            "audience": self.audience,
            "token_type": "OIDC",
            "nonces": [pk_hex, nonce_claim],
        })
        .to_string();

        let mut stream = UnixStream::connect(&self.socket_path).map_err(|e| {
            TeeError::HardwareDeviceUnavailable(format!(
                "Cannot connect to Confidential Space launcher socket {}: {e}",
                self.socket_path
            ))
        })?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(8)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

        let req = format!(
            "POST /v1/token HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(req.as_bytes()).map_err(|e| {
            TeeError::GenerationFailed(format!("teeserver.sock write failed: {e}"))
        })?;
        stream.flush().map_err(|e| {
            TeeError::GenerationFailed(format!("teeserver.sock flush failed: {e}"))
        })?;

        let mut raw_resp = Vec::new();
        stream.read_to_end(&mut raw_resp).map_err(|e| {
            TeeError::GenerationFailed(format!("teeserver.sock read failed: {e}"))
        })?;

        parse_http_unix_body(&raw_resp)
    }

    #[cfg(not(target_os = "linux"))]
    fn fetch_oidc_token(&self, _pk_hex: &str, _nonce_hex: &str) -> Result<String, TeeError> {
        Err(TeeError::HardwareDeviceUnavailable(
            "GCP Confidential Space teeserver.sock requires Linux Confidential Space TDX VM".into(),
        ))
    }

    #[cfg(target_os = "linux")]
    fn try_fetch_optional_raw_tdx(&self, report_data: [u8; 64]) -> Option<String> {
        let tsm_root = std::path::Path::new("/sys/kernel/config/tsm/report");
        if !tsm_root.exists() {
            return None;
        }
        let dir = tsm_root.join(format!("pog_cs_{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        if std::fs::create_dir_all(&dir).is_ok()
            && std::fs::write(dir.join("inblob"), report_data).is_ok()
        {
            let out = std::fs::read(dir.join("outblob")).ok();
            let _ = std::fs::remove_dir(&dir);
            return out.map(|b| B64_STD.encode(b));
        }
        let _ = std::fs::remove_dir(&dir);
        None
    }

    #[cfg(not(target_os = "linux"))]
    fn try_fetch_optional_raw_tdx(&self, _report_data: [u8; 64]) -> Option<String> {
        None
    }
}

/// Parse an HTTP/1.1 response from `teeserver.sock` (supporting both Content-Length and chunked encoding).
pub fn parse_http_unix_body(raw_resp: &[u8]) -> Result<String, TeeError> {
    let sep = raw_resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| {
            TeeError::GenerationFailed("Malformed HTTP response from teeserver.sock".into())
        })?;
    let head = std::str::from_utf8(&raw_resp[..sep])
        .map_err(|_| TeeError::GenerationFailed("Non-UTF8 HTTP headers from teeserver.sock".into()))?;
    let status_line = head.lines().next().unwrap_or("");
    if !status_line.contains(" 200 ") {
        let body_preview = String::from_utf8_lossy(&raw_resp[sep + 4..]);
        return Err(TeeError::GenerationFailed(format!(
            "teeserver.sock returned {status_line}: {}",
            body_preview.chars().take(240).collect::<String>()
        )));
    }
    let body_bytes = &raw_resp[sep + 4..];
    let is_chunked = head
        .lines()
        .any(|l| l.to_ascii_lowercase().contains("transfer-encoding:") && l.to_ascii_lowercase().contains("chunked"));
    let decoded = if is_chunked {
        decode_chunked_body(body_bytes)?
    } else {
        body_bytes.to_vec()
    };
    let s = String::from_utf8(decoded)
        .map_err(|_| TeeError::GenerationFailed("Non-UTF8 JWT body from teeserver.sock".into()))?
        .trim()
        .trim_matches('"')
        .to_string();
    if s.split('.').count() != 3 {
        return Err(TeeError::GenerationFailed(
            "teeserver.sock response is not a compact 3-part JWT".into(),
        ));
    }
    Ok(s)
}

fn decode_chunked_body(mut input: &[u8]) -> Result<Vec<u8>, TeeError> {
    let mut out = Vec::new();
    while let Some(pos) = input.windows(2).position(|w| w == b"\r\n") {
        let len_str = std::str::from_utf8(&input[..pos])
            .map_err(|_| TeeError::GenerationFailed("Bad chunk header".into()))?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let chunk_len = usize::from_str_radix(len_str, 16)
            .map_err(|_| TeeError::GenerationFailed(format!("Bad chunk size {len_str:?}")))?;
        input = &input[pos + 2..];
        if chunk_len == 0 {
            break;
        }
        if input.len() < chunk_len + 2 {
            return Err(TeeError::GenerationFailed("Truncated chunk body".into()));
        }
        out.extend_from_slice(&input[..chunk_len]);
        input = &input[chunk_len + 2..];
    }
    Ok(out)
}

fn decode_jwt_payload_unverified(jwt: &str) -> Result<Value, TeeError> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(TeeError::VerificationFailed("JWT must have 3 dot-separated segments".into()));
    }
    let payload_bytes = B64_URL
        .decode(parts[1])
        .map_err(|e| TeeError::VerificationFailed(format!("invalid JWT payload base64url: {e}")))?;
    serde_json::from_slice(&payload_bytes)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid JWT payload JSON: {e}")))
}

fn normalize_container_digest(digest: &str) -> Result<(String, String), TeeError> {
    let trimmed = digest.trim().to_ascii_lowercase();
    let hex_part = trimmed.strip_prefix("sha256:").unwrap_or(&trimmed);
    if hex_part.len() != 64 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(TeeError::VerificationFailed(format!(
            "invalid container image_digest {digest:?} (expected sha256:<64-hex>)"
        )));
    }
    Ok((format!("sha256:{hex_part}"), hex_part.to_string()))
}

impl TeeProvider for GcpConfidentialSpaceProvider {
    fn vendor(&self) -> TeeVendor {
        TeeVendor::IntelTdx
    }

    fn attest(
        &self,
        public_key: &[u8; 32],
        nonce: &[u8],
        gpu_binding: Option<GpuAttestationBinding>,
    ) -> Result<TeeAttestationQuote, TeeError> {
        let pk_hex = hex::encode(public_key);
        let nonce_hex = hex::encode(nonce);
        let report_data = compute_report_data(public_key, nonce, gpu_binding.as_ref());
        let jwt = self.fetch_oidc_token(&pk_hex, &nonce_hex)?;
        let claims = decode_jwt_payload_unverified(&jwt)?;

        let hwmodel = claims
            .get("hwmodel")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let swname = claims
            .get("swname")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let dbgstat = claims
            .get("dbgstat")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let secboot = claims
            .get("secboot")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let image_digest_raw = claims
            .pointer("/submods/container/image_digest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                TeeError::GenerationFailed(
                    "Confidential Space token missing submods.container.image_digest".into(),
                )
            })?;
        let (canonical_digest, digest_hex) = normalize_container_digest(image_digest_raw)?;
        let raw_tdx_quote_b64 = self.try_fetch_optional_raw_tdx(report_data);

        Ok(TeeAttestationQuote {
            vendor: TeeVendor::IntelTdx,
            public_key_hex: pk_hex,
            // Bind `workload_measurement_hex` directly to the measured zero-shell OCI image digest!
            workload_measurement_hex: digest_hex,
            report_data_hex: hex::encode(report_data),
            nonce_hex,
            migration_disabled: true,
            debug_disabled: dbgstat == "disabled-since-boot" && secboot,
            secure_tsc_enabled: true,
            gpu_binding,
            raw_quote_b64: B64_STD.encode(jwt.as_bytes()),
            vendor_cert_chain_pem: Vec::new(),
            workload_attestation: Some(WorkloadAttestation::GcpConfidentialSpaceOidc {
                jwt,
                audience: self.audience.clone(),
                image_digest: canonical_digest,
                hwmodel,
                swname,
                raw_tdx_quote_b64,
            }),
            generated_at_unix_s: Utc::now().timestamp().max(0) as u64,
        })
    }
}

/// Cryptographically verify a Google Cloud Confidential Space OIDC JWT against an explicit
/// Google Confidential Computing JWKS keyset (`https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com`),
/// binding Intel TDX hardware, `secboot=true`, `dbgstat=disabled-since-boot`, non-DEBUG release,
/// exact pinned container `image_digest`, empty `cmd_override`, narrow `env_override`, and
/// fresh `eat_nonce` containing BOTH `expected_pk_hex` and `expected_nonce_hex`.
pub fn verify_gcp_confidential_space_jwt(
    jwt: &str,
    jwks: &[RsaJwk],
    expected_audience: &str,
    expected_pk_hex: &str,
    expected_nonce_hex: &str,
    policy: &AttestationPolicy,
    now_unix_s: u64,
) -> Result<VerifiedGcpConfidentialSpaceToken, TeeError> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(TeeError::VerificationFailed(
            "Confidential Space JWT must have 3 dot-separated segments".into(),
        ));
    }
    let header_bytes = B64_URL
        .decode(parts[0])
        .map_err(|e| TeeError::VerificationFailed(format!("invalid JWT header base64url: {e}")))?;
    let header: Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid JWT header JSON: {e}")))?;
    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if alg != "RS256" {
        return Err(TeeError::VerificationFailed(format!(
            "Confidential Space JWT alg must be RS256, got {alg:?}"
        )));
    }
    let kid = header
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| TeeError::VerificationFailed("Confidential Space JWT missing kid".into()))?;

    let jwk = jwks
        .iter()
        .find(|k| k.kty == "RSA" && k.kid.as_deref() == Some(kid))
        .ok_or_else(|| {
            TeeError::VerificationFailed(format!(
                "Confidential Space JWT kid {kid:?} not found in trusted Google JWKS"
            ))
        })?;

    let n_bytes = B64_URL
        .decode(&jwk.n)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid JWK modulus n: {e}")))?;
    let e_bytes = B64_URL
        .decode(&jwk.e)
        .map_err(|e| TeeError::VerificationFailed(format!("invalid JWK exponent e: {e}")))?;
    let sig_bytes = B64_URL
        .decode(parts[2])
        .map_err(|e| TeeError::VerificationFailed(format!("invalid JWT signature base64url: {e}")))?;

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let rsa_pub = RsaPublicKeyComponents {
        n: &n_bytes,
        e: &e_bytes,
    };
    rsa_pub
        .verify(&RSA_PKCS1_2048_8192_SHA256, signing_input.as_bytes(), &sig_bytes)
        .map_err(|_| {
            TeeError::VerificationFailed(
                "Confidential Space JWT RS256 signature verification failed".into(),
            )
        })?;

    let claims = decode_jwt_payload_unverified(jwt)?;

    let iss = claims.get("iss").and_then(|v| v.as_str()).unwrap_or("");
    if iss != GCP_CS_ISSUER {
        return Err(TeeError::VerificationFailed(format!(
            "Confidential Space issuer mismatch: got {iss:?}, expected {GCP_CS_ISSUER:?}"
        )));
    }

    let aud_ok = match claims.get("aud") {
        Some(Value::String(s)) => s == expected_audience,
        Some(Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(expected_audience)),
        _ => false,
    };
    if !aud_ok {
        return Err(TeeError::VerificationFailed(format!(
            "Confidential Space audience mismatch (expected {expected_audience:?})"
        )));
    }

    let exp = claims
        .get("exp")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| TeeError::VerificationFailed("Confidential Space JWT missing exp".into()))?;
    let iat = claims
        .get("iat")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| TeeError::VerificationFailed("Confidential Space JWT missing iat".into()))?;
    let nbf = claims.get("nbf").and_then(|v| v.as_u64()).unwrap_or(iat);

    if now_unix_s >= exp {
        return Err(TeeError::PolicyRejected(format!(
            "Confidential Space JWT expired (now={now_unix_s} >= exp={exp})"
        )));
    }
    if nbf > now_unix_s.saturating_add(policy.max_future_skew_seconds) {
        return Err(TeeError::PolicyRejected(format!(
            "Confidential Space JWT not yet valid (nbf={nbf} > now={now_unix_s})"
        )));
    }
    if iat > now_unix_s.saturating_add(policy.max_future_skew_seconds) {
        return Err(TeeError::PolicyRejected(format!(
            "Confidential Space JWT issued in future (iat={iat} > now={now_unix_s})"
        )));
    }
    if now_unix_s > iat.saturating_add(policy.max_quote_age_seconds) {
        return Err(TeeError::PolicyRejected(format!(
            "Confidential Space JWT stale (age {}s > max {}s)",
            now_unix_s.saturating_sub(iat),
            policy.max_quote_age_seconds
        )));
    }

    let hwmodel = claims.get("hwmodel").and_then(|v| v.as_str()).unwrap_or("");
    if hwmodel != "GCP_INTEL_TDX" {
        return Err(TeeError::PolicyRejected(format!(
            "Confidential Space hwmodel must be GCP_INTEL_TDX, got {hwmodel:?}"
        )));
    }

    let swname = claims.get("swname").and_then(|v| v.as_str()).unwrap_or("");
    if swname != "CONFIDENTIAL_SPACE" {
        return Err(TeeError::PolicyRejected(format!(
            "Confidential Space swname must be CONFIDENTIAL_SPACE, got {swname:?}"
        )));
    }

    let secboot = claims
        .get("secboot")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !secboot {
        return Err(TeeError::PolicyRejected(
            "Confidential Space secboot must be true".into(),
        ));
    }

    let dbgstat = claims.get("dbgstat").and_then(|v| v.as_str()).unwrap_or("");
    if policy.require_debug_disabled && dbgstat != "disabled-since-boot" {
        return Err(TeeError::PolicyRejected(format!(
            "Confidential Space debug mode forbidden (dbgstat={dbgstat:?}, expected disabled-since-boot)"
        )));
    }

    if let Some(attrs) = claims
        .pointer("/submods/confidential_space/support_attributes")
        .and_then(|v| v.as_array())
    {
        if policy.require_debug_disabled
            && attrs
                .iter()
                .any(|a| a.as_str().map(|s| s.eq_ignore_ascii_case("DEBUG")).unwrap_or(false))
        {
            return Err(TeeError::PolicyRejected(
                "Confidential Space DEBUG image attribute is forbidden in production".into(),
            ));
        }
    }

    // Reject any untrusted boot-time command-line override (`tee-cmd`) so flags like `--allow-dev-tee`
    // can never be injected via mutable GCE instance metadata.
    if let Some(cmd_override) = claims
        .pointer("/submods/container/cmd_override")
        .and_then(|v| v.as_array())
    {
        if !cmd_override.is_empty() {
            return Err(TeeError::PolicyRejected(format!(
                "Confidential Space container cmd_override must be empty in production, got {cmd_override:?}"
            )));
        }
    }

    // Permit ONLY `POG_ANCHOR_ID` in `env_override` (reject any other metadata env injection!).
    if let Some(env_override) = claims
        .pointer("/submods/container/env_override")
        .and_then(|v| v.as_object())
    {
        for k in env_override.keys() {
            if k != "POG_ANCHOR_ID" {
                return Err(TeeError::PolicyRejected(format!(
                    "Confidential Space unexpected env_override key {k:?} (only POG_ANCHOR_ID permitted)"
                )));
            }
        }
    }

    let image_digest_raw = claims
        .pointer("/submods/container/image_digest")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            TeeError::VerificationFailed(
                "Confidential Space JWT missing submods.container.image_digest".into(),
            )
        })?;
    let (canonical_digest, digest_hex) = normalize_container_digest(image_digest_raw)?;

    if !policy.allowed_container_digests.is_empty() {
        let matched = policy.allowed_container_digests.iter().any(|d| {
            let norm = d.trim().to_ascii_lowercase();
            let norm_hex = norm.strip_prefix("sha256:").unwrap_or(&norm);
            norm_hex == digest_hex
        });
        if !matched {
            return Err(TeeError::PolicyRejected(format!(
                "Confidential Space container image_digest {canonical_digest} not in allowed_container_digests"
            )));
        }
    }

    if !policy.allowed_measurements.is_empty() {
        let matched = policy.allowed_measurements.iter().any(|m| {
            let norm = m.trim().to_ascii_lowercase();
            let norm_hex = norm.strip_prefix("sha256:").unwrap_or(&norm);
            norm_hex == digest_hex
        });
        if !matched {
            return Err(TeeError::PolicyRejected(format!(
                "Confidential Space workload digest {canonical_digest} not in allowed_measurements"
            )));
        }
    }

    // Bind BOTH ephemeral signing public key (`expected_pk_hex`) AND fresh verifier nonce (`expected_nonce_hex`)
    // via `eat_nonce` (array of strings or single string).
    let eat_nonces: Vec<String> = match claims.get("eat_nonce") {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
            .collect(),
        Some(Value::String(s)) => vec![s.to_ascii_lowercase()],
        _ => Vec::new(),
    };
    let expected_pk_lower = expected_pk_hex.trim().to_ascii_lowercase();
    let expected_nonce_lower = expected_nonce_hex.trim().to_ascii_lowercase();
    let hashed_nonce_lower = hex::encode(Sha256::digest(expected_nonce_lower.as_bytes()));

    if !eat_nonces.iter().any(|n| n == &expected_pk_lower) {
        return Err(TeeError::VerificationFailed(
            "Confidential Space eat_nonce does not bind enclave ephemeral public_key_hex".into(),
        ));
    }
    if !eat_nonces
        .iter()
        .any(|n| n == &expected_nonce_lower || n == &hashed_nonce_lower)
    {
        return Err(TeeError::VerificationFailed(
            "Confidential Space eat_nonce does not bind expected fresh verifier nonce".into(),
        ));
    }

    let gce_zone = claims
        .pointer("/submods/gce/zone")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let gce_project_id = claims
        .pointer("/submods/gce/project_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let gce_instance_name = claims
        .pointer("/submods/gce/instance_name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(VerifiedGcpConfidentialSpaceToken {
        issuer: iss.to_string(),
        audience: expected_audience.to_string(),
        hwmodel: hwmodel.to_string(),
        swname: swname.to_string(),
        dbgstat: dbgstat.to_string(),
        secboot,
        image_digest: canonical_digest,
        image_digest_hex: digest_hex,
        gce_zone,
        gce_project_id,
        gce_instance_name,
        iat,
        exp,
        kid: kid.to_string(),
    })
}

/// Top-level hook invoked by `pog_tee::verify_quote` when a `TeeAttestationQuote` carries
/// `WorkloadAttestation::GcpConfidentialSpaceOidc`.
pub fn verify_gcp_confidential_space_quote(
    quote: &TeeAttestationQuote,
    expected_nonce: &[u8],
    policy: &AttestationPolicy,
    now_unix_s: u64,
) -> Result<bool, TeeError> {
    let Some(WorkloadAttestation::GcpConfidentialSpaceOidc {
        jwt,
        audience,
        image_digest,
        ..
    }) = quote.workload_attestation.as_ref()
    else {
        return Err(TeeError::VerificationFailed(
            "Missing GcpConfidentialSpaceOidc workload_attestation payload".into(),
        ));
    };

    let jwks_json = policy.trusted_gcp_cs_jwks_json.as_deref().ok_or_else(|| {
        TeeError::VerificationFailed(
            "AttestationPolicy.trusted_gcp_cs_jwks_json required to verify GCP Confidential Space RS256 JWKS offline (fail-closed)"
                .into(),
        )
    })?;
    let jwk_set: JwkSet = serde_json::from_str(jwks_json).map_err(|e| {
        TeeError::VerificationFailed(format!("invalid trusted_gcp_cs_jwks_json: {e}"))
    })?;

    let expected_aud = policy
        .expected_gcp_cs_audience
        .as_deref()
        .unwrap_or(GCP_CS_DEFAULT_AUDIENCE);
    if audience != expected_aud {
        return Err(TeeError::VerificationFailed(format!(
            "quote workload audience {audience:?} != expected {expected_aud:?}"
        )));
    }

    let expected_nonce_hex = hex::encode(expected_nonce);
    let verified = verify_gcp_confidential_space_jwt(
        jwt,
        &jwk_set.keys,
        expected_aud,
        &quote.public_key_hex,
        &expected_nonce_hex,
        policy,
        now_unix_s,
    )?;

    if !verified
        .image_digest
        .eq_ignore_ascii_case(image_digest)
        || !verified
            .image_digest_hex
            .eq_ignore_ascii_case(&quote.workload_measurement_hex)
    {
        return Err(TeeError::VerificationFailed(
            "Confidential Space image_digest does not match quote.workload_measurement_hex".into(),
        ));
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{verify_quote, WorkloadKeypair};
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
        let (t0, seq, _) = read_tlv(der);
        assert_eq!(t0, 0x30);
        let (t1, n_raw, rest) = read_tlv(seq);
        assert_eq!(t1, 0x02);
        let (t2, e_raw, _) = read_tlv(rest);
        assert_eq!(t2, 0x02);
        let n = n_raw.strip_prefix(&[0]).unwrap_or(n_raw);
        let e = e_raw.strip_prefix(&[0]).unwrap_or(e_raw);
        (n, e)
    }

    fn generate_test_rsa_keypair() -> (RsaKeyPair, RsaJwk) {
        let child = std::process::Command::new("openssl")
            .args(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("openssl genpkey spawn failed");
        let pem_out = child.wait_with_output().expect("openssl genpkey failed");
        assert!(pem_out.status.success(), "openssl genpkey failed");
        let mut pk8 = std::process::Command::new("openssl")
            .args(["pkcs8", "-topk8", "-nocrypt", "-outform", "DER"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("openssl pkcs8 spawn failed");
        {
            use std::io::Write;
            pk8.stdin.as_mut().unwrap().write_all(&pem_out.stdout).unwrap();
        }
        let der_out = pk8.wait_with_output().expect("openssl pkcs8 failed");
        assert!(der_out.status.success(), "openssl pkcs8 failed");
        let kp = RsaKeyPair::from_pkcs8(&der_out.stdout)
            .or_else(|_| RsaKeyPair::from_der(&der_out.stdout))
            .expect("ring parse pkcs8/der RSA-2048");
        let (n_bytes, e_bytes) = parse_pkcs1_rsa_pub_ne(kp.public().as_ref());
        let jwk = RsaJwk {
            kty: "RSA".into(),
            kid: Some("cs-test-kid-1".into()),
            alg: Some("RS256".into()),
            n: B64_URL.encode(n_bytes),
            e: B64_URL.encode(e_bytes),
        };
        (kp, jwk)
    }

    fn sign_cs_jwt(kp: &RsaKeyPair, kid: &str, claims: &Value) -> String {
        let hdr = B64_URL.encode(
            serde_json::json!({"alg": "RS256", "typ": "JWT", "kid": kid})
                .to_string()
                .as_bytes(),
        );
        let pay = B64_URL.encode(claims.to_string().as_bytes());
        let signing_input = format!("{hdr}.{pay}");
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; kp.public().modulus_len()];
        kp.sign(&RSA_PKCS1_SHA256, &rng, signing_input.as_bytes(), &mut sig)
            .unwrap();
        format!("{signing_input}.{}", B64_URL.encode(&sig))
    }

    #[test]
    fn test_gcp_confidential_space_tdx_positive_and_all_negative_gates() {
        let (rsa_kp, jwk) = generate_test_rsa_keypair();
        let jwks_json = serde_json::to_string(&JwkSet { keys: vec![jwk.clone()] }).unwrap();
        let wk = WorkloadKeypair::generate();
        let pk_hex = wk.public_key_hex();
        let nonce = [0x5Au8; 32];
        let nonce_hex = hex::encode(nonce);
        let now = 1_795_750_000u64;
        let digest_hex = "9c831f4d4ceae94c07f56ea57b66e5aa1e2ceeaf81e74c11993c89f4eec7c7b2";
        let image_digest = format!("sha256:{digest_hex}");

        let make_claims = |hwmodel: &str, dbgstat: &str, attrs: Vec<&str>, digest: &str, cmd_ov: Vec<&str>, eat_n: Vec<String>, exp: u64| {
            serde_json::json!({
                "iss": GCP_CS_ISSUER,
                "aud": GCP_CS_DEFAULT_AUDIENCE,
                "iat": now - 10,
                "nbf": now - 10,
                "exp": exp,
                "hwmodel": hwmodel,
                "swname": "CONFIDENTIAL_SPACE",
                "secboot": true,
                "dbgstat": dbgstat,
                "eat_nonce": eat_n,
                "submods": {
                    "confidential_space": { "support_attributes": attrs },
                    "container": {
                        "image_digest": digest,
                        "cmd_override": cmd_ov,
                        "env_override": { "POG_ANCHOR_ID": "gcp-us-east4-ashburn" }
                    }
                }
            })
        };

        let good_claims = make_claims(
            "GCP_INTEL_TDX",
            "disabled-since-boot",
            vec!["LATEST", "STABLE", "USABLE"],
            &image_digest,
            vec![],
            vec![pk_hex.clone(), nonce_hex.clone()],
            now + 3600,
        );
        let good_jwt = sign_cs_jwt(&rsa_kp, "cs-test-kid-1", &good_claims);

        let mut pol = AttestationPolicy::production();
        pol.trusted_gcp_cs_jwks_json = Some(jwks_json);
        pol.allowed_container_digests = vec![image_digest.clone()];
        pol.allowed_measurements = vec![digest_hex.to_string()];

        let rd = compute_report_data(&wk.public_key_bytes(), &nonce, None);
        let good_quote = TeeAttestationQuote {
            vendor: TeeVendor::IntelTdx,
            public_key_hex: pk_hex.clone(),
            workload_measurement_hex: digest_hex.to_string(),
            report_data_hex: hex::encode(rd),
            nonce_hex: nonce_hex.clone(),
            migration_disabled: true,
            debug_disabled: true,
            secure_tsc_enabled: true,
            gpu_binding: None,
            raw_quote_b64: B64_STD.encode(good_jwt.as_bytes()),
            vendor_cert_chain_pem: Vec::new(),
            workload_attestation: Some(WorkloadAttestation::GcpConfidentialSpaceOidc {
                jwt: good_jwt.clone(),
                audience: GCP_CS_DEFAULT_AUDIENCE.into(),
                image_digest: image_digest.clone(),
                hwmodel: "GCP_INTEL_TDX".into(),
                swname: "CONFIDENTIAL_SPACE".into(),
                raw_tdx_quote_b64: None,
            }),
            generated_at_unix_s: now - 10,
        };

        // 1. Valid Intel TDX Confidential Space token PASSES full verification!
        let verified = verify_quote(&good_quote, &nonce, &pol, now).unwrap();
        assert!(verified.hardware_attested);
        assert!(verified.vendor_chain_verified);
        assert_eq!(verified.workload_measurement_hex, digest_hex);

        // 2. Wrong measurement / container image_digest MUST FAIL!
        let mut wrong_meas_pol = pol.clone();
        wrong_meas_pol.allowed_container_digests = vec!["sha256:0000000000000000000000000000000000000000000000000000000000000001".into()];
        assert!(verify_quote(&good_quote, &nonce, &wrong_meas_pol, now).is_err());

        // 3. Stale / expired token MUST FAIL!
        let expired_jwt = sign_cs_jwt(
            &rsa_kp,
            "cs-test-kid-1",
            &make_claims("GCP_INTEL_TDX", "disabled-since-boot", vec!["STABLE"], &image_digest, vec![], vec![pk_hex.clone(), nonce_hex.clone()], now - 1),
        );
        assert!(verify_gcp_confidential_space_jwt(&expired_jwt, std::slice::from_ref(&jwk), GCP_CS_DEFAULT_AUDIENCE, &pk_hex, &nonce_hex, &pol, now).is_err());

        // 4. Stale / mismatched nonce OR stale key MUST FAIL!
        assert!(verify_gcp_confidential_space_jwt(&good_jwt, std::slice::from_ref(&jwk), GCP_CS_DEFAULT_AUDIENCE, &pk_hex, &"aa".repeat(32), &pol, now).is_err());
        assert!(verify_gcp_confidential_space_jwt(&good_jwt, std::slice::from_ref(&jwk), GCP_CS_DEFAULT_AUDIENCE, &"bb".repeat(32), &nonce_hex, &pol, now).is_err());

        // 5. Debug Confidential Space image MUST FAIL (dbgstat != disabled-since-boot OR DEBUG attr)!
        let dbg_jwt = sign_cs_jwt(
            &rsa_kp,
            "cs-test-kid-1",
            &make_claims("GCP_INTEL_TDX", "enabled", vec!["DEBUG"], &image_digest, vec![], vec![pk_hex.clone(), nonce_hex.clone()], now + 3600),
        );
        assert!(verify_gcp_confidential_space_jwt(&dbg_jwt, std::slice::from_ref(&jwk), GCP_CS_DEFAULT_AUDIENCE, &pk_hex, &nonce_hex, &pol, now).is_err());

        // 6. Boot-time cmd_override (`--allow-dev-tee`) MUST FAIL!
        let cmd_jwt = sign_cs_jwt(
            &rsa_kp,
            "cs-test-kid-1",
            &make_claims("GCP_INTEL_TDX", "disabled-since-boot", vec!["STABLE"], &image_digest, vec!["--allow-dev-tee"], vec![pk_hex.clone(), nonce_hex.clone()], now + 3600),
        );
        assert!(verify_gcp_confidential_space_jwt(&cmd_jwt, std::slice::from_ref(&jwk), GCP_CS_DEFAULT_AUDIENCE, &pk_hex, &nonce_hex, &pol, now).is_err());

        // 7. Non-TDX hwmodel (e.g. Gen-1 SEV downgrade) MUST FAIL!
        let sev_jwt = sign_cs_jwt(
            &rsa_kp,
            "cs-test-kid-1",
            &make_claims("GCP_AMD_SEV", "disabled-since-boot", vec!["STABLE"], &image_digest, vec![], vec![pk_hex.clone(), nonce_hex.clone()], now + 3600),
        );
        assert!(verify_gcp_confidential_space_jwt(&sev_jwt, std::slice::from_ref(&jwk), GCP_CS_DEFAULT_AUDIENCE, &pk_hex, &nonce_hex, &pol, now).is_err());
    }
}
