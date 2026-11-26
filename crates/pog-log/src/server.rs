use crate::chain::ContinuousGeoLog;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use pog_proto::GeoProofBundle;
use serde_json::json;
use std::sync::{Arc, RwLock};

pub type SharedLog = Arc<RwLock<ContinuousGeoLog>>;

/// Build lightweight DNS / Certificate Transparency style public HTTP API.
pub fn build_router(state: SharedLog) -> Router {
    Router::new()
        .route("/health", get(|| async { Json(json!({ "status": "ok" })) }))
        .route("/.well-known/pog-registry", get(get_registry))
        .route("/v1/sth", get(get_sth))
        .route("/v1/attestations", post(post_attestation))
        .route("/v1/provers/:prover_id/latest", get(get_prover_latest))
        .route("/v1/provers/:prover_id/history", get(get_prover_history))
        .with_state(state)
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
