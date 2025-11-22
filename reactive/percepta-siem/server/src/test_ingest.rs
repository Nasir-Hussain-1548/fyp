//! Test ingestion endpoint for development/testing
//! Allows HTTP POST of events without mTLS for easy testing

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde_json::Value;
use tracing::{info, warn};

use crate::enroll::AppState;
use crate::websocket::StreamMessage;
use percepta_server::percepta::Event;

/// POST /api/test/ingest - Accept test events via HTTP (no auth for testing)
pub async fn test_ingest_event(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    info!("📥 Test event received via HTTP");

    // Try to parse as protobuf Event
    let event: Event = match serde_json::from_value(payload) {
        Ok(e) => e,
        Err(err) => {
            warn!("Failed to parse test event: {}", err);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid event format",
                    "details": err.to_string()
                })),
            );
        }
    };

    // Store the event
    if let Err(e) = state.storage_service.store_event(&event).await {
        warn!("Failed to store test event: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Failed to store event",
                "details": e.to_string()
            })),
        );
    }

    // Broadcast to WebSocket subscribers
    let _ = state
        .event_broadcaster
        .send(StreamMessage::Event(event.clone()));

    info!("✅ Test event stored and broadcast: {}", event.hash);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "event_id": event.hash,
            "message": "Event ingested successfully"
        })),
    )
}
