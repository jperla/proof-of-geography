use crate::chain::ContinuousGeoLog;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use pog_proto::{verify_proof_bundle, GeoProofBundle};
use serde::Deserialize;
use serde_json::json;
use std::sync::{Arc, RwLock};

pub type SharedLog = Arc<RwLock<ContinuousGeoLog>>;

const PLAYGROUND_HTML: &str = include_str!("playground.html");

#[derive(Deserialize)]
struct VerifyHeaderRequest {
    header_value: String,
}

#[derive(Deserialize)]
struct SilenceQuery {
    max_silence_seconds: Option<u64>,
}

/// Build lightweight DNS / Certificate Transparency style public HTTP API + Interactive Web Playground.
pub fn build_router(state: SharedLog) -> Router {
    Router::new()
        .route("/", get(|| async { Html(PLAYGROUND_HTML) }))
        .route("/health", get(|| async { Json(json!({ "status": "ok" })) }))
        .route("/.well-known/pog-registry", get(get_registry))
        .route("/v1/sth", get(get_sth))
        .route("/v1/verify-header", post(post_verify_header))
        .route("/v1/attestations", post(post_attestation))
        .route("/v1/provers/:prover_id/latest", get(get_prover_latest))
        .route("/v1/provers/:prover_id/history", get(get_prover_history))
        .route("/v1/anomalies/silent", get(get_silent_provers))
        .route("/v1/clusters", get(get_clusters))
        .with_state(state)
}

async fn post_verify_header(
    State(log): State<SharedLog>,
    Json(req): Json<VerifyHeaderRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let bundle = GeoProofBundle::from_header_value(&req.header_value).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("invalid X-PoG-Proof header: {e}") })),
        )
    })?;
    let now = Utc::now().timestamp().max(0) as u64;
    let guard = log.read().unwrap();
    match verify_proof_bundle(&bundle, &guard.grid, &guard.policy, now) {
        Ok(report) => Ok(Json(serde_json::to_value(report).unwrap_or_default())),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )),
    }
}

async fn get_registry(State(log): State<SharedLog>) -> Json<serde_json::Value> {
    let guard = log.read().unwrap();
    Json(serde_json::to_value(&guard.grid).unwrap_or_default())
}

async fn get_sth(State(log): State<SharedLog>) -> Json<serde_json::Value> {
    let guard = log.read().unwrap();
    Json(serde_json::to_value(guard.signed_tree_head()).unwrap_or_default())
}

async fn post_attestation(
    State(log): State<SharedLog>,
    Json(bundle): Json<GeoProofBundle>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let now = Utc::now().timestamp().max(0) as u64;
    let mut guard = log.write().unwrap();
    match guard.append_bundle(bundle, now) {
        Ok(receipt) => Ok(Json(serde_json::to_value(receipt).unwrap_or_default())),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )),
    }
}

async fn get_prover_latest(
    State(log): State<SharedLog>,
    Path(prover_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let guard = log.read().unwrap();
    match guard.prover_status(&prover_id) {
        Some(status) => Ok(Json(serde_json::to_value(status).unwrap_or_default())),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "prover not found" })),
        )),
    }
}

async fn get_prover_history(
    State(log): State<SharedLog>,
    Path(prover_id): Path<String>,
) -> Json<serde_json::Value> {
    let guard = log.read().unwrap();
    Json(serde_json::to_value(guard.prover_history(&prover_id)).unwrap_or_default())
}

async fn get_silent_provers(
    State(log): State<SharedLog>,
    Query(q): Query<SilenceQuery>,
) -> Json<serde_json::Value> {
    let now = Utc::now().timestamp().max(0) as u64;
    let guard = log.read().unwrap();
    let max_s = q
        .max_silence_seconds
        .unwrap_or(guard.max_heartbeat_cadence_seconds);
    let alerts = guard.detect_silent_provers(now, max_s);
    Json(json!({
        "checked_at_unix_s": now,
        "max_silence_seconds": max_s,
        "silent_provers": alerts,
    }))
}

async fn get_clusters(State(log): State<SharedLog>) -> Json<serde_json::Value> {
    let guard = log.read().unwrap();
    let report = guard.analyze_prover_clusters(1.5, 4, 5.0);
    Json(serde_json::to_value(report).unwrap_or_default())
}
