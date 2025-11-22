//! Enrollment API for Percepta SIEM

use crate::certificate_authority::CAService;
use crate::storage::StorageService;
use crate::websocket::StreamMessage;
use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{Duration, Utc};
use openssl::nid::Nid;
use openssl::x509::X509Req;
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

// --- Structs for API --- //

#[derive(Debug, Serialize, Deserialize)]
pub struct OtkRequest {
    pub admin_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OtkResponse {
    pub otk: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub hostname: String,
    pub os: String,
    pub ip: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimRequest {
    pub otk: String,
    pub csr: String,
    pub device_info: DeviceInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimResponse {
    pub agent_cert: String,
    pub ca_cert: String,
}

#[derive(Debug, Clone)]
pub struct OtkEntry {
    pub admin_id: String,
    pub expires_at: chrono::DateTime<Utc>,
    pub used: bool,
}

// --- OTK Store --- //

#[derive(Clone)]
pub struct OtkStore {
    tokens: Arc<RwLock<HashMap<String, OtkEntry>>>,
}

impl OtkStore {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn generate(&self, admin_id: String) -> Result<OtkResponse> {
        let otk: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let expires_at = Utc::now() + Duration::minutes(15);

        let entry = OtkEntry {
            admin_id,
            expires_at,
            used: false,
        };

        self.tokens.write().await.insert(otk.clone(), entry);

        info!("Generated OTK for admin: {}", otk);

        Ok(OtkResponse {
            otk,
            expires_at: expires_at.to_rfc3339(),
        })
    }

    pub async fn claim(&self, otk: &str) -> Result<OtkEntry> {
        let mut tokens = self.tokens.write().await;
        if let Some(entry) = tokens.get_mut(otk) {
            if entry.used {
                warn!("Attempt to use already used OTK: {}", otk);
                return Err(anyhow::anyhow!("OTK already used"));
            }
            if entry.expires_at < Utc::now() {
                warn!("Attempt to use expired OTK: {}", otk);
                return Err(anyhow::anyhow!("OTK expired"));
            }
            entry.used = true;
            Ok(entry.clone())
        } else {
            warn!("Attempt to use invalid OTK: {}", otk);
            Err(anyhow::anyhow!("Invalid OTK"))
        }
    }
}

// --- App State --- //

#[derive(Clone)]
pub struct AppState {
    pub otk_store: OtkStore,
    pub ca_service: Arc<CAService>,
    pub storage_service: Arc<StorageService>,
    pub api_key: String,
    pub event_broadcaster: Arc<broadcast::Sender<StreamMessage>>,
    pub alert_service: Arc<percepta_server::alerts::AlertService>,
}

// --- Axum Handlers --- //

pub async fn request_otk(
    State(state): State<AppState>,
    Json(payload): Json<OtkRequest>,
) -> Result<Json<OtkResponse>, AppError> {
    info!("Received OTK request from admin: {}", payload.admin_id);
    let otk_response = state.otk_store.generate(payload.admin_id).await?;
    Ok(Json(otk_response))
}

pub async fn claim_otk(
    State(state): State<AppState>,
    Json(payload): Json<ClaimRequest>,
) -> Result<Json<ClaimResponse>, AppError> {
    // Generate a short trace id for correlating logs for this claim
    let trace_id = Uuid::new_v4().to_string();
    info!(
        "[{}] Received enrollment claim for OTK: {}",
        trace_id, payload.otk
    );

    // Verbose debug output to help diagnose enrollment issues
    debug!("[{}] Claim payload CSR: {}", trace_id, payload.csr);
    debug!(
        "[{}] Claim payload device_info: hostname='{}' os='{}' ip='{}'",
        trace_id, payload.device_info.hostname, payload.device_info.os, payload.device_info.ip
    );

    // 1. Claim OTK
    let otk_entry = state.otk_store.claim(&payload.otk).await?;
    // Use the OTK entry admin id in logs so the field is exercised and for tracing
    info!(
        "[{}] OTK claimed by admin: {}",
        trace_id, otk_entry.admin_id
    );

    // 2. Derive agent ID from CSR (use CN). Using the OTK's admin_id here is wrong
    // because portal-generated OTKs are generic. Extract the Common Name from
    // the CSR so the certificate is linked to the agent identity.
    let csr = X509Req::from_pem(payload.csr.as_bytes())
        .context("Failed to parse CSR when deriving agent id")?;
    let subject = csr.subject_name();
    let common_name = subject
        .entries()
        .find(|entry| entry.object().nid() == Nid::COMMONNAME)
        .and_then(|entry| entry.data().as_utf8().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("CSR missing Common Name (CN)"))?;

    let agent_id = common_name.clone();
    debug!("[{}] Derived agent_id from CSR CN: {}", trace_id, agent_id);
    let issued_cert = state
        .ca_service
        .sign_csr(payload.csr.as_bytes(), Some(agent_id))
        .await?;

    // 3. Get CA cert
    let ca_cert_pem = state.ca_service.get_ca_certificate_pem()?;

    info!(
        "[{}] Successfully enrolled agent for OTK: {}",
        trace_id, payload.otk
    );

    Ok(Json(ClaimResponse {
        agent_cert: issued_cert.certificate_pem,
        ca_cert: ca_cert_pem,
    }))
}

// --- Error Handling --- //

pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
