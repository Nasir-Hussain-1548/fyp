use anyhow::Result;
use std::sync::Arc;
use tonic::{Request, Response, Status};

use crate::storage::StorageService;
use percepta_server::percepta::events_service_server::EventsService as EventsServiceTrait;
use percepta_server::percepta::{EventsResponse, GetRecentRequest};

#[derive(Clone)]
pub struct EventsService {
    storage: Arc<StorageService>,
}

impl EventsService {
    pub fn new(storage: Arc<StorageService>) -> Self {
        Self { storage }
    }
}

#[tonic::async_trait]
impl EventsServiceTrait for EventsService {
    async fn get_recent_events(
        &self,
        _request: Request<GetRecentRequest>,
    ) -> Result<Response<EventsResponse>, Status> {
        let events = self.storage.get_recent_events().await;
        let resp = EventsResponse { events };
        Ok(Response::new(resp))
    }
}
