//! End-to-end TLS 1.3 server terminated directly inside the measured enclave (`rustls`),
//! exporting real RFC 8446 §7.5 Exported Keying Material (`EXPORTER-pog-inference-v1`) per
//! accepted client connection and injecting `ActiveTlsSession` into Axum request handlers.

use crate::acme::IssuedTlsMaterial;
use anyhow::Result;
use axum::{Extension, Router};
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use pog_proto::{sign_tls_cert_binding, TlsSessionBinding, TLS_EXPORTER_LABEL};
use pog_tee::WorkloadKeypair;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ProtocolVersion, ServerConfig};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

#[derive(Debug, Clone)]
pub struct LiveTlsIdentity {
    pub certified_key: Arc<CertifiedKey>,
    pub leaf_cert_sha256_hex: String,
    pub cert_prover_binding_sig_hex: String,
    pub issuer_note: String,
}

#[derive(Debug)]
pub struct EnclaveCertResolver {
    live: RwLock<Option<LiveTlsIdentity>>,
    acme_challenge: RwLock<Option<Arc<CertifiedKey>>>,
}

impl EnclaveCertResolver {
    pub fn new() -> Self {
        Self {
            live: RwLock::new(None),
            acme_challenge: RwLock::new(None),
        }
    }

    pub fn install_live(&self, material: IssuedTlsMaterial, kp: &WorkloadKeypair) {
        let sig = sign_tls_cert_binding(kp, &material.leaf_cert_sha256_hex);
        let id = LiveTlsIdentity {
            certified_key: material.certified_key,
            leaf_cert_sha256_hex: material.leaf_cert_sha256_hex,
            cert_prover_binding_sig_hex: sig,
            issuer_note: material.issuer_note,
        };
        *self.live.write().unwrap() = Some(id);
    }

    pub fn set_acme_challenge(&self, cert: Option<Arc<CertifiedKey>>) {
        *self.acme_challenge.write().unwrap() = cert;
    }

    pub fn current_identity(&self) -> Option<LiveTlsIdentity> {
        self.live.read().unwrap().clone()
    }
}

impl ResolvesServerCert for EnclaveCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let wants_acme = client_hello
            .alpn()
            .map(|mut alpn| alpn.any(|proto| proto == ACME_TLS_ALPN))
            .unwrap_or(false);
        if wants_acme {
            if let Some(ch) = self.acme_challenge.read().unwrap().clone() {
                return Some(ch);
            }
        }
        self.live
            .read()
            .unwrap()
            .as_ref()
            .map(|l| Arc::clone(&l.certified_key))
    }
}

/// Per-TLS-connection binding context injected into every HTTP request carried over this exact
/// end-to-end client <-> enclave TLS 1.3 connection.
#[derive(Debug)]
pub struct ActiveTlsSession {
    pub peer_ip: IpAddr,
    pub tls_protocol_version: String,
    pub tls_exporter_ekm_hex: String,
    pub server_cert_sha256_hex: String,
    pub cert_prover_binding_sig_hex: String,
    pub request_seq: AtomicU64,
}

impl ActiveTlsSession {
    pub fn next_binding(&self) -> TlsSessionBinding {
        let seq = self.request_seq.fetch_add(1, Ordering::SeqCst) + 1;
        TlsSessionBinding {
            tls_protocol_version: self.tls_protocol_version.clone(),
            exporter_label: TLS_EXPORTER_LABEL.to_string(),
            tls_exporter_ekm_hex: self.tls_exporter_ekm_hex.clone(),
            server_cert_sha256_hex: self.server_cert_sha256_hex.clone(),
            cert_prover_binding_sig_hex: self.cert_prover_binding_sig_hex.clone(),
            terminated_in_attested_runtime: true,
            tls_connection_request_seq: seq,
        }
    }
}

/// Build the `rustls::ServerConfig` accepting BOTH normal HTTPS (`http/1.1`) AND RFC 8737 ACME
/// `tls-alpn-01` (`acme-tls/1`) directly on TCP port 443.
pub fn build_tls_acceptor(resolver: Arc<EnclaveCertResolver>) -> Result<TlsAcceptor> {
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec(), ACME_TLS_ALPN.to_vec()];
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// Run the end-to-end enclave TLS 1.3 HTTPS server.
pub async fn serve_enclave_tls(
    listen_addr: SocketAddr,
    resolver: Arc<EnclaveCertResolver>,
    router: Router,
) -> Result<()> {
    let acceptor = build_tls_acceptor(Arc::clone(&resolver))?;
    let listener = TcpListener::bind(listen_addr).await?;
    info!(listen = %listen_addr, "End-to-end enclave TLS 1.3 listener ready");

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(err = %e, "TCP accept error");
                continue;
            }
        };
        let _ = tcp.set_nodelay(true);
        let acc = acceptor.clone();
        let res = Arc::clone(&resolver);
        let app = router.clone();
        tokio::spawn(async move {
            let tls_stream = match tokio::time::timeout(
                std::time::Duration::from_secs(15),
                acc.accept(tcp),
            )
            .await
            {
                Ok(Ok(s)) => s,
                _ => return,
            };

            let (_, server_conn) = tls_stream.get_ref();
            // ACME TLS-ALPN-01 probe completes during handshake and closes cleanly.
            if server_conn.alpn_protocol() == Some(ACME_TLS_ALPN) {
                return;
            }

            let proto_ver = match server_conn.protocol_version() {
                Some(ProtocolVersion::TLSv1_3) => "TLSv1.3".to_string(),
                Some(ProtocolVersion::TLSv1_2) => "TLSv1.2".to_string(),
                _ => "UNKNOWN".to_string(),
            };
            let mut ekm = [0u8; 32];
            if server_conn
                .export_keying_material(&mut ekm, TLS_EXPORTER_LABEL.as_bytes(), None)
                .is_err()
            {
                return;
            }
            let Some(live_id) = res.current_identity() else {
                return;
            };
            let session = Arc::new(ActiveTlsSession {
                peer_ip: peer.ip(),
                tls_protocol_version: proto_ver,
                tls_exporter_ekm_hex: hex::encode(ekm),
                server_cert_sha256_hex: live_id.leaf_cert_sha256_hex,
                cert_prover_binding_sig_hex: live_id.cert_prover_binding_sig_hex,
                request_seq: AtomicU64::new(0),
            });

            let conn_app = app.layer(Extension(session));
            let svc = TowerToHyperService::new(conn_app.into_service());
            let io = TokioIo::new(tls_stream);
            let _ = http1::Builder::new()
                .keep_alive(true)
                .serve_connection(io, svc)
                .await;
        });
    }
}
