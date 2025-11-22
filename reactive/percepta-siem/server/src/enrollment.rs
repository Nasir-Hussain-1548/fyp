use anyhow::Result;
use std::sync::Arc;
use tonic::{Request, Response, Status};

use crate::certificate_authority::CAService;
use crate::enroll::OtkStore;
use percepta_server::percepta::enrollment_service_server::EnrollmentService as EnrollmentServiceTrait;
use percepta_server::percepta::{EnrollRequest, EnrollResponse};

#[derive(Clone)]
pub struct EnrollmentService {
    otk_store: Arc<OtkStore>,
    ca_service: Arc<CAService>,
}

impl EnrollmentService {
    pub fn new(otk_store: Arc<OtkStore>, ca_service: Arc<CAService>) -> Self {
        Self {
            otk_store,
            ca_service,
        }
    }
}

#[tonic::async_trait]
impl EnrollmentServiceTrait for EnrollmentService {
    async fn enroll_agent(
        &self,
        request: Request<EnrollRequest>,
    ) -> Result<Response<EnrollResponse>, Status> {
        let req = request.into_inner();

        // Validate OTK
        match self.otk_store.claim(&req.otk).await {
            Ok(_) => {}
            Err(e) => {
                return Err(Status::permission_denied(format!(
                    "Invalid or expired OTK: {}",
                    e
                )))
            }
        }

        // If agent provided a CSR, sign it. Otherwise return error (we require CSR for security)
        if req.csr.is_empty() {
            return Err(Status::invalid_argument("CSR is required for enrollment"));
        }

        let issued = self
            .ca_service
            .sign_csr(req.csr.as_bytes(), Some(req.agent_id.clone()))
            .await
            .map_err(|e| Status::internal(format!("Failed to sign CSR: {}", e)))?;

        let ca_pem = self
            .ca_service
            .get_ca_certificate_pem()
            .map_err(|e| Status::internal(format!("Failed to read CA cert: {}", e)))?;

        let resp = EnrollResponse {
            agent_id: req.agent_id,
            certificate_pem: issued.certificate_pem,
            private_key_pem: String::new(), // private key remains on agent
            ca_certificate_pem: ca_pem,
        };

        Ok(Response::new(resp))
    }
}
