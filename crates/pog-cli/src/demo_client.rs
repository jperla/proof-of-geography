//! One-command independent external TLS 1.3 client & offline fail-closed verifier for the
//! Proof of Geography Verified LLM demo (`https://llm.proofofgeography.com`).
//!
//! Establishes its OWN real `rustls` TLS 1.3 connection (verified against Mozilla WebPKI roots),
//! exports its OWN 32-byte RFC 8446 §7.5 Exported Keying Material (`EXPORTER-pog-inference-v1`),
//! sends a fresh CSPRNG `X-PoG-Client-Nonce`, downloads `/v1/receipts/{id}` + live official Google
//! Confidential Space JWKS, and independently verifies every cryptographic layer without trusting
//! the demo website!

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use pog_proto::{
    verify_cpu_inference_evidence, AnchorGrid, ClientObservedEvidence,
    ConfidentialCpuEvidenceBundle, CpuInferenceVerificationPolicy, HTTP_HEADER_POG_CLIENT_NONCE,
    HTTP_HEADER_POG_COMMITMENT_SALT, HTTP_HEADER_POG_RECEIPT_ID, PINNED_MODEL_ID,
    TLS_EXPORTER_LABEL,
};
use pog_tee::{AttestationPolicy, GCP_CS_JWKS_URI};
use rand::RngCore;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ProtocolVersion, RootCertStore};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub struct DemoClientArgs {
    pub url: String,
    pub prompt: String,
    pub max_tokens: usize,
    pub temperature: f64,
    pub grid_path: PathBuf,
    pub expected_image_digest: Vec<String>,
    pub out_evidence: Option<PathBuf>,
    pub require_geo_quorum: bool,
}

pub struct VerifyLlmEvidenceArgs {
    pub evidence_json: PathBuf,
    pub grid_path: PathBuf,
    pub jwks_file: Option<PathBuf>,
    pub expected_image_digest: Vec<String>,
    pub expected_audience: String,
    pub require_geo_quorum: bool,
    pub allow_dev_tee: bool,
}

struct TlsExchangeResult {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    tls_exporter_ekm_hex: String,
    server_cert_sha256_hex: String,
}

fn parse_https_url(url: &str) -> Result<(String, u16, String)> {
    let stripped = url
        .trim()
        .strip_prefix("https://")
        .ok_or_else(|| anyhow!("demo-client requires an https:// URL (got {url:?})"))?;
    let (authority, path) = match stripped.find('/') {
        Some(idx) => (&stripped[..idx], stripped[idx..].to_string()),
        None => (stripped, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>()?),
        None => (authority.to_string(), 443),
    };
    Ok((host, port, path))
}

fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(pos) = input.windows(2).position(|w| w == b"\r\n") {
        let len_str = std::str::from_utf8(&input[..pos])?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let len = usize::from_str_radix(len_str, 16)?;
        input = &input[pos + 2..];
        if len == 0 {
            break;
        }
        if input.len() < len + 2 {
            bail!("truncated chunked HTTP response");
        }
        out.extend_from_slice(&input[..len]);
        input = &input[len + 2..];
    }
    Ok(out)
}

async fn real_tls13_http_exchange(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> Result<TlsExchangeResult> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));

    let tcp = tokio::time::timeout(Duration::from_secs(15), TcpStream::connect((host, port)))
        .await
        .context("TCP connect timeout")??;
    let server_name = ServerName::try_from(host.to_string())?;
    let mut tls = tokio::time::timeout(Duration::from_secs(15), connector.connect(server_name, tcp))
        .await
        .context("TLS 1.3 handshake timeout")??;

    let (_, conn) = tls.get_ref();
    if conn.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
        bail!(
            "FAIL-CLOSED: expected TLSv1.3 end-to-end session, negotiated {:?}",
            conn.protocol_version()
        );
    }
    let peer_certs = conn
        .peer_certificates()
        .ok_or_else(|| anyhow!("peer presented no TLS certificate"))?;
    let leaf_sha256_hex = hex::encode(Sha256::digest(peer_certs[0].as_ref()));
    let mut ekm = [0u8; 32];
    conn.export_keying_material(&mut ekm, TLS_EXPORTER_LABEL.as_bytes(), None)
        .map_err(|e| anyhow!("TLS 1.3 EKM export failed: {e}"))?;
    let ekm_hex = hex::encode(ekm);

    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: pog-cli-demo-client/0.1\r\nConnection: close\r\n"
    );
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() || method == "POST" {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");

    tls.write_all(req.as_bytes()).await?;
    if !body.is_empty() {
        tls.write_all(body).await?;
    }
    tls.flush().await?;

    let mut raw = Vec::new();
    match tokio::time::timeout(Duration::from_secs(90), tls.read_to_end(&mut raw)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof && !raw.is_empty() => {}
        Ok(Err(e)) => return Err(e.into()),
        Err(_) if !raw.is_empty() => {}
        Err(_) => bail!("HTTPS response timeout from {host}"),
    }

    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("malformed HTTP response"))?;
    let head = std::str::from_utf8(&raw[..sep])?;
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let body_raw = &raw[sep + 4..];
    let body_out = if headers
        .get("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        decode_chunked(body_raw)?
    } else {
        body_raw.to_vec()
    };

    Ok(TlsExchangeResult {
        status,
        headers,
        body: body_out,
        tls_exporter_ekm_hex: ekm_hex,
        server_cert_sha256_hex: leaf_sha256_hex,
    })
}

pub async fn run_demo_client(args: DemoClientArgs) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (host, port, _) = parse_https_url(&args.url)?;
    let grid = AnchorGrid::from_json_str(&std::fs::read_to_string(&args.grid_path)?)?;

    // 1. Generate unpredictable 32-byte client freshness nonce & OpenAI chat completions payload.
    let mut nonce_raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce_raw);
    let client_nonce_hex = hex::encode(nonce_raw);

    let req_body = serde_json::json!({
        "model": PINNED_MODEL_ID,
        "messages": [{ "role": "user", "content": args.prompt }],
        "max_tokens": args.max_tokens,
        "temperature": args.temperature,
        "stream": false
    })
    .to_string();

    // 2. Establish OUR OWN real TLS 1.3 connection to `/v1/chat/completions`, exporting OUR OWN EKM!
    let infer = real_tls13_http_exchange(
        &host,
        port,
        "POST",
        "/v1/chat/completions",
        &[
            ("Content-Type", "application/json"),
            (HTTP_HEADER_POG_CLIENT_NONCE, &client_nonce_hex),
        ],
        req_body.as_bytes(),
    )
    .await?;

    if infer.status != 200 {
        bail!(
            "Inference endpoint returned HTTP {}: {}",
            infer.status,
            String::from_utf8_lossy(&infer.body)
        );
    }

    let receipt_id = infer
        .headers
        .get(&HTTP_HEADER_POG_RECEIPT_ID.to_ascii_lowercase())
        .cloned()
        .ok_or_else(|| anyhow!("Response missing {HTTP_HEADER_POG_RECEIPT_ID} header"))?;
    let commitment_salt_hex = infer
        .headers
        .get(&HTTP_HEADER_POG_COMMITMENT_SALT.to_ascii_lowercase())
        .cloned()
        .ok_or_else(|| anyhow!("Response missing {HTTP_HEADER_POG_COMMITMENT_SALT} header"))?;
    let raw_resp_str = String::from_utf8(infer.body.clone())?;

    // 3. Fetch full downloadable evidence bundle (`/v1/receipts/{id}`) + live Google Confidential Space JWKS!
    let ev_resp = real_tls13_http_exchange(
        &host,
        port,
        "GET",
        &format!("/v1/receipts/{receipt_id}"),
        &[],
        &[],
    )
    .await?;
    if ev_resp.status != 200 {
        bail!("GET /v1/receipts/{receipt_id} returned HTTP {}", ev_resp.status);
    }
    let mut evidence: ConfidentialCpuEvidenceBundle = serde_json::from_slice(&ev_resp.body)?;

    let (jwks_host, jwks_port, jwks_path) = parse_https_url(GCP_CS_JWKS_URI)?;
    let jwks_resp =
        real_tls13_http_exchange(&jwks_host, jwks_port, "GET", &jwks_path, &[], &[]).await?;
    if jwks_resp.status != 200 {
        bail!("Failed to fetch live Google Confidential Space JWKS: HTTP {}", jwks_resp.status);
    }
    let google_jwks_json = String::from_utf8(jwks_resp.body)?;

    let now = Utc::now().timestamp().max(0) as u64;
    let client_observed = ClientObservedEvidence {
        endpoint_url: format!("https://{host}/v1/chat/completions"),
        client_nonce_hex: client_nonce_hex.clone(),
        commitment_salt_hex,
        tls_exporter_ekm_hex: infer.tls_exporter_ekm_hex.clone(),
        server_cert_sha256_hex: infer.server_cert_sha256_hex.clone(),
        expected_tls_connection_request_seq: Some(1),
        raw_request_body: req_body,
        raw_response_body: raw_resp_str.clone(),
        observed_at_unix_s: now,
    };

    evidence.google_jwks_json = Some(google_jwks_json.clone());
    evidence.client_observed = Some(client_observed.clone());

    if let Some(ref out_path) = args.out_evidence {
        std::fs::write(out_path, serde_json::to_string_pretty(&evidence)?)?;
    }

    let policy =
        CpuInferenceVerificationPolicy::production(args.expected_image_digest, google_jwks_json);
    let report = verify_cpu_inference_evidence(&evidence, &client_observed, &grid, &policy, now)?;

    let completion_val: serde_json::Value = serde_json::from_str(&raw_resp_str)?;
    let answer = completion_val
        .pointer("/choices/0/message/content")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let output = serde_json::json!({
        "url": format!("https://{host}/v1/chat/completions"),
        "receipt_id": receipt_id,
        "model": PINNED_MODEL_ID,
        "completion_text": answer,
        "client_tls_exporter_ekm_hex": infer.tls_exporter_ekm_hex,
        "client_server_cert_sha256_hex": infer.server_cert_sha256_hex,
        "verification_report": report,
    });
    println!("{}", serde_json::to_string_pretty(&output)?);

    if !report.inference_tee_verified {
        std::process::exit(1);
    }
    if args.require_geo_quorum && !report.geographic_proof_verified {
        std::process::exit(2);
    }
    Ok(())
}

pub fn run_verify_llm_evidence(args: VerifyLlmEvidenceArgs) -> Result<()> {
    let grid = AnchorGrid::from_json_str(&std::fs::read_to_string(&args.grid_path)?)?;
    let evidence: ConfidentialCpuEvidenceBundle =
        serde_json::from_str(&std::fs::read_to_string(&args.evidence_json)?)?;
    let client_observed = evidence.client_observed.as_ref().ok_or_else(|| {
        anyhow!("evidence bundle missing client_observed block (capture via `pog-cli demo-client` or `PogVerifiedHttpClient`)")
    })?;
    let jwks_json = if let Some(ref p) = args.jwks_file {
        std::fs::read_to_string(p)?
    } else if let Some(ref embedded) = evidence.google_jwks_json {
        embedded.clone()
    } else {
        String::new()
    };

    let mut policy =
        CpuInferenceVerificationPolicy::production(args.expected_image_digest, jwks_json);
    policy.expected_oidc_audience = args.expected_audience.clone();
    policy.geo_policy.tee_policy.expected_gcp_cs_audience = Some(args.expected_audience);
    if args.allow_dev_tee {
        policy.geo_policy.tee_policy = AttestationPolicy::allow_dev_software();
    }

    // Use the evidence capture timestamp when re-verifying historical saved evidence offline
    // (while still enforcing receipt expiry relative to `observed_at_unix_s`).
    let verify_at = client_observed.observed_at_unix_s.max(Utc::now().timestamp().max(0) as u64);
    let report = verify_cpu_inference_evidence(
        &evidence,
        client_observed,
        &grid,
        &policy,
        verify_at,
    )?;
    println!("{}", serde_json::to_string_pretty(&report)?);

    if !report.inference_tee_verified {
        std::process::exit(1);
    }
    if args.require_geo_quorum && !report.geographic_proof_verified {
        std::process::exit(2);
    }
    Ok(())
}
