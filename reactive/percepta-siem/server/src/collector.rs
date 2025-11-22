use anyhow::Result;
use async_stream::try_stream;
use futures::Stream;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::certificate_authority::CAService;
use crate::storage::StorageService;
use crate::websocket::{EventBroadcaster, StreamMessage};
use percepta_server::percepta::{
    collector_service_server::CollectorService as CollectorServiceTrait, Event, IngestionResponse,
};
use percepta_server::rule_engine::RuleEngine;

/// CollectorService handles log ingestion for the SIEM system
#[derive(Clone)]
pub struct CollectorService {
    /// List of currently connected agents, protected by async mutex
    connected_agents: Arc<Mutex<Vec<String>>>,
    ca_service: Arc<CAService>,
    storage_service: Arc<StorageService>,
    rule_engine: Arc<RuleEngine>,
    event_broadcaster: EventBroadcaster,
}

impl CollectorService {
    /// Create a new CollectorService instance
    pub async fn new(
        ca_service: Arc<CAService>,
        storage_service: Arc<StorageService>,
        rule_engine: Arc<RuleEngine>,
        event_broadcaster: EventBroadcaster,
    ) -> Result<Self> {
        info!("🔧 Initializing CollectorService...");

        Ok(Self {
            connected_agents: Arc::new(Mutex::new(Vec::new())),
            ca_service,
            storage_service,
            rule_engine,
            event_broadcaster,
        })
    }

    /// Get the current number of connected agents
    pub async fn agent_count(&self) -> usize {
        self.connected_agents.lock().await.len()
    }

    /// Check if an agent is currently connected
    pub async fn is_agent_connected(&self, agent_id: &str) -> bool {
        self.connected_agents
            .lock()
            .await
            .contains(&agent_id.to_string())
    }

    /// Remove an agent from the connected list
    #[allow(dead_code)]
    pub async fn disconnect_agent(&self, agent_id: &str) -> bool {
        let mut agents = self.connected_agents.lock().await;
        if let Some(pos) = agents.iter().position(|id| id == agent_id) {
            agents.remove(pos);
            info!("🔌 Agent disconnected: {}", agent_id);
            true
        } else {
            false
        }
    }

    /// Generate event hash if not provided
    fn ensure_event_hash(&self, event: &mut Event) {
        if event.hash.is_empty() {
            event.hash = Uuid::new_v4().to_string();
            debug!("Generated hash for event: {}", event.hash);
        }
    }
}

#[tonic::async_trait]
impl CollectorServiceTrait for CollectorService {
    type StreamEventsStream =
        std::pin::Pin<Box<dyn Stream<Item = Result<IngestionResponse, Status>> + Send + 'static>>;

    /// Handle streaming events from agents
    async fn stream_events(
        &self,
        request: Request<tonic::Streaming<Event>>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        // --- Application-Layer CRL Check ---
        // Track agent CN from peer certificate for connection bookkeeping
        let mut agent_cn: Option<String> = None;
        if let Some(peer_cert) = request
            .peer_certs()
            .and_then(|certs| certs.iter().next().cloned())
        {
            match openssl::x509::X509::from_der(peer_cert.as_ref()) {
                Ok(cert) => {
                    let serial_bn = cert
                        .serial_number()
                        .to_bn()
                        .map_err(|e| Status::internal(format!("Failed to read serial: {}", e)))?;
                    let serial_dec = serial_bn
                        .to_dec_str()
                        .map_err(|e| Status::internal(format!("Failed to format serial: {}", e)))?;
                    if self.ca_service.is_certificate_revoked(&serial_dec).await {
                        warn!(
                            "Rejecting connection from revoked certificate. Serial: {}",
                            serial_dec
                        );
                        return Err(Status::permission_denied("Certificate has been revoked."));
                    }
                    debug!(
                        "Peer certificate is valid and not revoked. Serial: {}",
                        serial_dec
                    );

                    // Try to extract agent id from certificate subject CN for connected agents tracking
                    for entry in cert.subject_name().entries() {
                        if entry.object().nid().as_raw() == openssl::nid::Nid::COMMONNAME.as_raw() {
                            if let Ok(cn) = entry.data().as_utf8() {
                                agent_cn = Some(cn.to_string());
                                break;
                            }
                        }
                    }

                    if let Some(ref agent_id) = agent_cn {
                        // Add agent to connected list if not present
                        let mut agents = self.connected_agents.lock().await;
                        if !agents.contains(agent_id) {
                            agents.push(agent_id.clone());
                            info!("🔗 Agent connected: {} (total: {})", agent_id, agents.len());
                        }
                        // Log that the helper methods are active
                        let _ = self.is_agent_connected(agent_id).await;
                        let _ = self.agent_count().await;
                    }
                }
                Err(_) => {
                    warn!("Could not parse peer certificate from mTLS connection.");
                    return Err(Status::invalid_argument("Invalid peer certificate"));
                }
            }
        } else {
            warn!("Rejecting connection with no peer certificate. mTLS is required.");
            return Err(Status::unauthenticated("No peer certificate presented."));
        }
        // --- End CRL Check ---

        let mut stream = request.into_inner();
        let service = self.clone();

        info!("🌊 Starting event stream processing...");

        let response_stream = try_stream! {
            while let Some(event) = stream.next().await {
                match event {
                    Ok(mut event) => {
                        // Ensure event has a hash
                        service.ensure_event_hash(&mut event);

                        // Evaluate event against detection rules and broadcast alerts
                        match service.rule_engine.evaluate_event(&event).await {
                            Ok(alerts) => {
                                for alert in alerts {
                                    debug!("🚨 Alert triggered: {}", alert.rule_name);
                                    let _ = service.event_broadcaster.send(StreamMessage::Alert(alert));
                                }
                            }
                            Err(e) => warn!("Failed to evaluate event against rules: {}", e),
                        }

                        // Store event using the new storage service
                        let (ack, message) = match service.storage_service.store_event(&event).await {
                            Ok(_) => {
                                debug!("✅ Event stored successfully: {}", event.hash);
                                // Broadcast to WebSocket subscribers
                                let _ = service.event_broadcaster.send(StreamMessage::Event(event.clone()));
                                (true, "Event received".to_string())
                            }
                            Err(e) => {
                                error!("❌ Failed to store event {}: {}", event.hash, e);
                                // Notify agent of storage failure
                                warn!("⚠️ Reporting storage failure for event: {}", event.hash);
                                (false, format!("Server failed to store event: {}", e))
                            }
                        };

                        // Send acknowledgment response
                        let response = IngestionResponse {
                            ack,
                            event_id: event.hash.clone(),
                            message,
                        };

                        yield response;
                    }
                    Err(e) => {
                        error!("❌ Error receiving event from stream: {}", e);

                        let error_response = IngestionResponse {
                            ack: false,
                            event_id: String::new(),
                            message: format!("Error processing event: {}", e),
                        };

                        yield error_response;
                    }
                }
            }

            info!("🏁 Event stream processing completed");
        };

        // Wrap the response stream so we can perform cleanup when the stream is dropped
        use futures::Stream as FuturesStream;
        use std::pin::Pin;
        use std::task::{Context, Poll};

        struct CleanupStream {
            inner: Pin<
                Box<dyn FuturesStream<Item = Result<IngestionResponse, Status>> + Send + 'static>,
            >,
            agent_id: Option<String>,
            connected_agents: Arc<Mutex<Vec<String>>>,
        }

        impl FuturesStream for CleanupStream {
            type Item = Result<IngestionResponse, Status>;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                Pin::new(&mut self.inner).poll_next(cx)
            }
        }

        impl Drop for CleanupStream {
            fn drop(&mut self) {
                if let Some(agent_id) = &self.agent_id {
                    let agents = self.connected_agents.clone();
                    let agent = agent_id.clone();
                    // spawn a background task to remove the agent from the list
                    let _ = tokio::spawn(async move {
                        let mut list = agents.lock().await;
                        if let Some(pos) = list.iter().position(|id| id == &agent) {
                            list.remove(pos);
                            tracing::info!("🔌 Agent disconnected (cleanup): {}", agent);
                        }
                    });
                }
            }
        }

        let cleanup = CleanupStream {
            inner: Box::pin(response_stream),
            agent_id: agent_cn.clone(),
            connected_agents: self.connected_agents.clone(),
        };

        Ok(Response::new(Box::pin(cleanup)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate_authority::{CAConfig, CAService};
    use tempfile::tempdir;
    use tokio::sync::broadcast;

    async fn create_test_service() -> CollectorService {
        let temp_dir = tempdir().unwrap();
        let ca_config = CAConfig {
            ca_storage_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        let ca_service = Arc::new(CAService::new(ca_config).await.unwrap());

        let storage_dir = tempdir().unwrap();
        let storage_service = Arc::new(StorageService::new(storage_dir.path()).await.unwrap());

        use percepta_server::alerts::AlertService;
        let alert_service = Arc::new(AlertService::new(300));
        let rule_engine = Arc::new(RuleEngine::new(alert_service));

        // Broadcaster for tests
        let (tx, _) = broadcast::channel(16);
        let broadcaster = Arc::new(tx);

        CollectorService::new(ca_service, storage_service, rule_engine, broadcaster)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_collector_service_creation() {
        let service = create_test_service().await;
        assert_eq!(service.agent_count().await, 0);
    }

    // The enrollment tests are removed as they are no longer part of the collector service directly
    // and are handled by the enroll.rs module.

    #[tokio::test]
    async fn test_agent_disconnect() {
        let service = create_test_service().await;

        // First enroll an agent
        {
            let mut agents = service.connected_agents.lock().await;
            agents.push("test-agent".to_string());
        }

        assert_eq!(service.agent_count().await, 1);

        // Then disconnect it
        let disconnected = service.disconnect_agent("test-agent").await;
        assert!(disconnected);
        assert_eq!(service.agent_count().await, 0);
        assert!(!service.is_agent_connected("test-agent").await);
    }

    #[tokio::test]
    async fn test_ensure_event_hash() {
        let service = create_test_service().await;

        let mut event = Event {
            ..Default::default()
        };

        service.ensure_event_hash(&mut event);
        assert!(!event.hash.is_empty());

        // UUID format check
        assert!(Uuid::parse_str(&event.hash).is_ok());
    }
}
