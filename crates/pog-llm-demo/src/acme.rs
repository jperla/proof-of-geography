//! Pure-Rust RFC 8555 + RFC 8737 ACME TLS-ALPN-01 client running strictly in enclave RAM.
//!
//! Generates an ephemeral ECDSA P-256 TLS keypair inside Intel TDX memory, proves control of the
//! domain directly over TCP port 443 (`ALPN: acme-tls/1`) with ZERO port 80 and ZERO external TLS
//! termination, and installs the resulting Let's Encrypt certificate chain into `EnclaveCertResolver`.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use base64::Engine;
use rcgen::{CertificateParams, CustomExtension, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair as RingKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use rustls::crypto::ring::sign::any_ecdsa_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::sign::CertifiedKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub const LETS_ENCRYPT_PROD_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_STAGING_DIRECTORY: &str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";

pub struct IssuedTlsMaterial {
    pub certified_key: Arc<CertifiedKey>,
    pub leaf_cert_sha256_hex: String,
    pub issuer_note: String,
}

/// Generate a self-signed in-RAM ECDSA P-256 certificate (used ONLY for local pre-deploy testing).
pub fn generate_self_signed_tls(domain: &str) -> Result<IssuedTlsMaterial> {
    let mut params = CertificateParams::new(vec![domain.to_string()])?;
    params
        .distinguished_name
        .push(DnType::CommonName, domain);
    let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let cert = params.self_signed(&kp)?;
    let leaf_der = cert.der().to_vec();
    let leaf_sha256 = hex::encode(Sha256::digest(&leaf_der));
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(kp.serialize_der()));
    let signing_key = any_ecdsa_type(&key_der).map_err(|e| anyhow!("rustls signing key: {e}"))?;
    let ck = Arc::new(CertifiedKey::new(vec![CertificateDer::from(leaf_der)], signing_key));
    Ok(IssuedTlsMaterial {
        certified_key: ck,
        leaf_cert_sha256_hex: leaf_sha256,
        issuer_note: "self-signed-local-test".into(),
    })
}

/// Minimal HTTPS/1.1 client built strictly on `tokio-rustls` + `webpki-roots` (zero OpenSSL/curl).
pub async fn https_request(
    method: &str,
    url: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let stripped = url
        .strip_prefix("https://")
        .ok_or_else(|| anyhow!("only https:// URLs supported, got {url}"))?;
    let (authority, path) = match stripped.find('/') {
        Some(idx) => (&stripped[..idx], &stripped[idx..]),
        None => (stripped, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>()?),
        None => (authority.to_string(), 443),
    };

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));

    let tcp = tokio::time::timeout(Duration::from_secs(15), TcpStream::connect((host.as_str(), port)))
        .await
        .context("HTTPS connect timeout")??;
    let server_name = ServerName::try_from(host.clone())?;
    let mut tls = tokio::time::timeout(Duration::from_secs(15), connector.connect(server_name, tcp))
        .await
        .context("HTTPS TLS handshake timeout")??;

    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: pog-llm-demo/0.1\r\nConnection: close\r\n"
    );
    if let Some(ct) = content_type {
        req.push_str(&format!("Content-Type: {ct}\r\n"));
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
    tokio::time::timeout(Duration::from_secs(20), tls.read_to_end(&mut raw))
        .await
        .context("HTTPS read timeout")??;

    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("malformed HTTP response from {url}"))?;
    let head = std::str::from_utf8(&raw[..sep])?;
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let mut headers = Vec::new();
    let mut is_chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let kl = k.trim().to_ascii_lowercase();
            let vt = v.trim().to_string();
            if kl == "transfer-encoding" && vt.to_ascii_lowercase().contains("chunked") {
                is_chunked = true;
            }
            headers.push((kl, vt));
        }
    }
    let body_raw = &raw[sep + 4..];
    let body_out = if is_chunked {
        decode_chunked(body_raw)?
    } else {
        body_raw.to_vec()
    };
    Ok((status, headers, body_out))
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
            bail!("truncated chunked HTTP body");
        }
        out.extend_from_slice(&input[..len]);
        input = &input[len + 2..];
    }
    Ok(out)
}

fn header_val<'a>(headers: &'a [(String, String)], key: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}

fn jwk_and_thumbprint(acct_kp: &EcdsaKeyPair) -> Result<(Value, String)> {
    let pub_bytes = acct_kp.public_key().as_ref();
    if pub_bytes.len() != 65 || pub_bytes[0] != 0x04 {
        bail!("unexpected P-256 public key format");
    }
    let x = B64_URL.encode(&pub_bytes[1..33]);
    let y = B64_URL.encode(&pub_bytes[33..65]);
    // RFC 7638 canonical JSON key order: crv, kty, x, y.
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let thumb = B64_URL.encode(Sha256::digest(canonical.as_bytes()));
    let jwk = json!({ "crv": "P-256", "kty": "EC", "x": x, "y": y });
    Ok((jwk, thumb))
}

async fn acme_post(
    url: &str,
    nonce: &mut String,
    acct_kp: &EcdsaKeyPair,
    rng: &SystemRandom,
    kid: Option<&str>,
    jwk: &Value,
    payload: Option<&Value>,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let protected = match kid {
        Some(k) => json!({ "alg": "ES256", "kid": k, "nonce": nonce.as_str(), "url": url }),
        None => json!({ "alg": "ES256", "jwk": jwk, "nonce": nonce.as_str(), "url": url }),
    };
    let protected_b64 = B64_URL.encode(serde_json::to_vec(&protected)?);
    let payload_b64 = match payload {
        Some(p) => B64_URL.encode(serde_json::to_vec(p)?),
        None => String::new(),
    };
    let signing_input = format!("{protected_b64}.{payload_b64}");
    let sig = acct_kp
        .sign(rng, signing_input.as_bytes())
        .map_err(|_| anyhow!("ACME ES256 sign failed"))?;
    let body = serde_json::to_vec(&json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": B64_URL.encode(sig.as_ref()),
    }))?;

    let (status, headers, resp) =
        https_request("POST", url, Some("application/jose+json"), &body).await?;
    if let Some(next_nonce) = header_val(&headers, "replay-nonce") {
        *nonce = next_nonce.to_string();
    }
    Ok((status, headers, resp))
}

/// Complete a full Let's Encrypt ACME **TLS-ALPN-01** issuance strictly in enclave RAM!
///
/// The `install_alpn_challenge_cert` callback installs the ephemeral self-signed `acmeIdentifier`
/// challenge certificate onto our live `:443` `EnclaveCertResolver` for `ALPN: acme-tls/1`, then
/// clears it immediately once validation finishes.
pub async fn obtain_acme_tls_alpn01_cert<F>(
    directory_url: &str,
    domain: &str,
    contact_email: &str,
    install_alpn_challenge_cert: F,
) -> Result<IssuedTlsMaterial>
where
    F: Fn(Option<Arc<CertifiedKey>>),
{
    let rng = SystemRandom::new();
    let acct_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .map_err(|_| anyhow!("ACME P-256 keygen failed"))?;
    let acct_kp = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        acct_pkcs8.as_ref(),
        &rng,
    )
    .map_err(|_| anyhow!("ACME P-256 key parse failed"))?;
    let (jwk, thumbprint) = jwk_and_thumbprint(&acct_kp)?;

    // 1. Fetch ACME directory & initial replay nonce.
    let (dir_st, _, dir_body) = https_request("GET", directory_url, None, &[]).await?;
    if dir_st != 200 {
        bail!("ACME directory returned HTTP {dir_st}");
    }
    let dir: Value = serde_json::from_slice(&dir_body)?;
    let new_nonce_url = dir["newNonce"]
        .as_str()
        .ok_or_else(|| anyhow!("ACME directory missing newNonce"))?;
    let new_account_url = dir["newAccount"]
        .as_str()
        .ok_or_else(|| anyhow!("ACME directory missing newAccount"))?;
    let new_order_url = dir["newOrder"]
        .as_str()
        .ok_or_else(|| anyhow!("ACME directory missing newOrder"))?;

    let (_, nh, _) = https_request("HEAD", new_nonce_url, None, &[]).await?;
    let mut nonce = header_val(&nh, "replay-nonce")
        .ok_or_else(|| anyhow!("ACME newNonce missing replay-nonce"))?
        .to_string();

    // 2. Register ephemeral in-RAM ACME account.
    let acct_payload = json!({
        "termsOfServiceAgreed": true,
        "contact": [format!("mailto:{contact_email}")]
    });
    let (acct_st, acct_hdrs, acct_body) = acme_post(
        new_account_url,
        &mut nonce,
        &acct_kp,
        &rng,
        None,
        &jwk,
        Some(&acct_payload),
    )
    .await?;
    if !(200..300).contains(&acct_st) {
        bail!(
            "ACME newAccount failed HTTP {acct_st}: {}",
            String::from_utf8_lossy(&acct_body)
        );
    }
    let kid = header_val(&acct_hdrs, "location")
        .ok_or_else(|| anyhow!("ACME newAccount missing Location header"))?
        .to_string();

    // 3. Create order for `domain`.
    let order_payload = json!({
        "identifiers": [{ "type": "dns", "value": domain }]
    });
    let (ord_st, ord_hdrs, ord_body) = acme_post(
        new_order_url,
        &mut nonce,
        &acct_kp,
        &rng,
        Some(&kid),
        &jwk,
        Some(&order_payload),
    )
    .await?;
    if !(200..300).contains(&ord_st) {
        bail!(
            "ACME newOrder failed HTTP {ord_st}: {}",
            String::from_utf8_lossy(&ord_body)
        );
    }
    let order_url = header_val(&ord_hdrs, "location")
        .ok_or_else(|| anyhow!("ACME newOrder missing Location"))?
        .to_string();
    let order: Value = serde_json::from_slice(&ord_body)?;
    let authz_url = order["authorizations"][0]
        .as_str()
        .ok_or_else(|| anyhow!("ACME order missing authorizations[0]"))?
        .to_string();
    let finalize_url = order["finalize"]
        .as_str()
        .ok_or_else(|| anyhow!("ACME order missing finalize URL"))?
        .to_string();

    // 4. Fetch authorization & find `tls-alpn-01` challenge.
    let (az_st, _, az_body) = acme_post(
        &authz_url,
        &mut nonce,
        &acct_kp,
        &rng,
        Some(&kid),
        &jwk,
        None,
    )
    .await?;
    if az_st != 200 {
        bail!("ACME authz returned HTTP {az_st}");
    }
    let authz: Value = serde_json::from_slice(&az_body)?;
    if authz["status"].as_str() != Some("valid") {
        let ch = authz["challenges"]
            .as_array()
            .and_then(|arr| arr.iter().find(|c| c["type"].as_str() == Some("tls-alpn-01")))
            .ok_or_else(|| anyhow!("ACME authz did not offer tls-alpn-01 challenge"))?;
        let ch_url = ch["url"]
            .as_str()
            .ok_or_else(|| anyhow!("tls-alpn-01 challenge missing url"))?;
        let token = ch["token"]
            .as_str()
            .ok_or_else(|| anyhow!("tls-alpn-01 challenge missing token"))?;

        // RFC 8737: SHA-256(key_authorization) placed in critical acmeIdentifier extension!
        let key_auth = format!("{token}.{thumbprint}");
        let digest = Sha256::digest(key_auth.as_bytes());
        let mut ch_params = CertificateParams::new(vec![domain.to_string()])?;
        ch_params
            .custom_extensions
            .push(CustomExtension::new_acme_identifier(digest.as_slice()));
        let ch_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let ch_cert = ch_params.self_signed(&ch_kp)?;
        let ch_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ch_kp.serialize_der()));
        let ch_signing_key =
            any_ecdsa_type(&ch_key_der).map_err(|e| anyhow!("acme challenge key: {e}"))?;
        let ch_ck = Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(ch_cert.der().to_vec())],
            ch_signing_key,
        ));
        install_alpn_challenge_cert(Some(ch_ck));

        // Notify Let's Encrypt to probe port 443 with ALPN `acme-tls/1`.
        let (trig_st, _, trig_body) = acme_post(
            ch_url,
            &mut nonce,
            &acct_kp,
            &rng,
            Some(&kid),
            &jwk,
            Some(&json!({})),
        )
        .await?;
        if !(200..300).contains(&trig_st) {
            install_alpn_challenge_cert(None);
            bail!(
                "ACME challenge trigger failed HTTP {trig_st}: {}",
                String::from_utf8_lossy(&trig_body)
            );
        }

        // Poll authorization up to 45s.
        let mut validated = false;
        for _ in 0..22 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let (_, _, poll_body) = acme_post(
                &authz_url,
                &mut nonce,
                &acct_kp,
                &rng,
                Some(&kid),
                &jwk,
                None,
            )
            .await?;
            let poll: Value = serde_json::from_slice(&poll_body)?;
            match poll["status"].as_str() {
                Some("valid") => {
                    validated = true;
                    break;
                }
                Some("invalid") => {
                    install_alpn_challenge_cert(None);
                    bail!("ACME tls-alpn-01 validation failed: {poll}");
                }
                _ => {}
            }
        }
        install_alpn_challenge_cert(None);
        if !validated {
            bail!("ACME tls-alpn-01 validation timed out");
        }
    }

    // 5. Generate fresh nonexportable ECDSA P-256 TLS leaf keypair strictly in enclave RAM & submit CSR.
    let tls_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let csr_params = CertificateParams::new(vec![domain.to_string()])?;
    let csr = csr_params.serialize_request(&tls_kp)?;
    let csr_b64 = B64_URL.encode(csr.der().as_ref());

    let (fin_st, _, fin_body) = acme_post(
        &finalize_url,
        &mut nonce,
        &acct_kp,
        &rng,
        Some(&kid),
        &jwk,
        Some(&json!({ "csr": csr_b64 })),
    )
    .await?;
    if !(200..300).contains(&fin_st) {
        bail!(
            "ACME finalize failed HTTP {fin_st}: {}",
            String::from_utf8_lossy(&fin_body)
        );
    }

    // 6. Poll order until `certificate` URL is ready.
    let mut cert_url: Option<String> = serde_json::from_slice::<Value>(&fin_body)
        .ok()
        .and_then(|v| v["certificate"].as_str().map(|s| s.to_string()));
    for _ in 0..20 {
        if cert_url.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        let (_, _, o_body) = acme_post(
            &order_url,
            &mut nonce,
            &acct_kp,
            &rng,
            Some(&kid),
            &jwk,
            None,
        )
        .await?;
        let o: Value = serde_json::from_slice(&o_body)?;
        if o["status"].as_str() == Some("invalid") {
            bail!("ACME order became invalid: {o}");
        }
        if let Some(cu) = o["certificate"].as_str() {
            cert_url = Some(cu.to_string());
            break;
        }
    }
    let cert_url = cert_url.ok_or_else(|| anyhow!("ACME order timed out before cert issued"))?;

    // 7. Download full PEM chain and install into `rustls::sign::CertifiedKey`.
    let (c_st, _, pem_bytes) = acme_post(
        &cert_url,
        &mut nonce,
        &acct_kp,
        &rng,
        Some(&kid),
        &jwk,
        None,
    )
    .await?;
    if c_st != 200 {
        bail!("ACME certificate download failed HTTP {c_st}");
    }
    let mut reader = std::io::Cursor::new(&pem_bytes);
    let cert_chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut reader).collect::<std::result::Result<Vec<_>, _>>()?;
    if cert_chain.is_empty() {
        bail!("ACME returned empty certificate chain");
    }
    let leaf_sha256 = hex::encode(Sha256::digest(cert_chain[0].as_ref()));
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(tls_kp.serialize_der()));
    let signing_key = any_ecdsa_type(&key_der).map_err(|e| anyhow!("rustls leaf key: {e}"))?;
    let ck = Arc::new(CertifiedKey::new(cert_chain, signing_key));

    Ok(IssuedTlsMaterial {
        certified_key: ck,
        leaf_cert_sha256_hex: leaf_sha256,
        issuer_note: format!("acme-tls-alpn-01 ({directory_url})"),
    })
}
