//! WebSocket Real-Time Event Stream
//! Provides live event and alert streaming to the dashboard

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use futures::{sink::SinkExt, stream::StreamExt};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::enroll::AppState;
use percepta_server::alerts::Alert;
use percepta_server::percepta::Event;

#[derive(Clone, Debug)]
pub enum StreamMessage {
    Event(Event),
    Alert(Alert),
    Stats(serde_json::Value),
}

pub type EventBroadcaster = Arc<broadcast::Sender<StreamMessage>>;

/// WebSocket handler for real-time event streaming
pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state.event_broadcaster.clone()))
}

async fn handle_socket(socket: WebSocket, broadcaster: EventBroadcaster) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = broadcaster.subscribe();

    info!("🔌 New WebSocket connection established");

    // Send initial connection message
    let welcome = serde_json::json!({
        "type": "connected",
        "message": "Connected to Percepta SIEM event stream",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    if let Ok(json) = serde_json::to_string(&welcome) {
        let _ = sender.send(Message::Text(json)).await;
    }

    // Spawn a task to forward broadcasts to this client
    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            let json_str = match msg {
                StreamMessage::Event(event) => {
                    match serde_json::to_string(&serde_json::json!({
                        "type": "event",
                        "data": event,
                    })) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("Failed to serialize event: {}", e);
                            continue;
                        }
                    }
                }
                StreamMessage::Alert(alert) => {
                    match serde_json::to_string(&serde_json::json!({
                        "type": "alert",
                        "data": alert,
                    })) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("Failed to serialize alert: {}", e);
                            continue;
                        }
                    }
                }
                StreamMessage::Stats(stats) => {
                    match serde_json::to_string(&serde_json::json!({
                        "type": "stats",
                        "data": stats,
                    })) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("Failed to serialize stats: {}", e);
                            continue;
                        }
                    }
                }
            };

            debug!("Broadcasting message to WebSocket client");

            if sender.send(Message::Text(json_str)).await.is_err() {
                // Client disconnected
                break;
            }
        }
    });

    // Receive messages from client (mostly for ping/pong)
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Text(text) => {
                    debug!("Received text message: {}", text);
                    // Handle client commands if needed
                }
                Message::Close(_) => {
                    info!("Client initiated close");
                    break;
                }
                Message::Ping(_) | Message::Pong(_) => {
                    // Handled automatically by axum
                }
                _ => {}
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = (&mut send_task) => {
            recv_task.abort();
        }
        _ = (&mut recv_task) => {
            send_task.abort();
        }
    }

    info!("🔌 WebSocket connection closed");
}
