use anyhow::Result;
use std::sync::Arc;
use tonic::{Request, Response, Status};

use crate::certificate_authority::CAService;
use crate::tls;
use percepta_server::percepta::admin_service_server::AdminService as AdminServiceTrait;
use percepta_server::percepta::{RevokeRequest, RevokeResponse};

#[derive(Clone)]
pub struct AdminService {
    ca_service: Arc<CAService>,
}

impl AdminService {
    pub fn new(ca_service: Arc<CAService>) -> Self {
        Self { ca_service }
    }
}

#[tonic::async_trait]
impl AdminServiceTrait for AdminService {
    async fn revoke_certificate(
        &self,
        request: Request<RevokeRequest>,
    ) -> Result<Response<RevokeResponse>, Status> {
        let req = request.into_inner();
        let serial = req.serial;

        match self.ca_service.revoke_certificate(&serial).await {
            Ok(_) => {
                // Attempt to reload CRL into TLS artifacts (write certs/crl.pem)
                if let Err(e) = tls::reload_crl_from_ca(self.ca_service.clone()).await {
                    return Err(Status::internal(format!(
                        "Revoked but failed to reload CRL into TLS artifacts: {}",
                        e
                    )));
                }
                Ok(Response::new(RevokeResponse {
                    ok: true,
                    message: "Revoked and CRL generated/reloaded".to_string(),
                }))
            }
            Err(e) => Err(Status::internal(format!("Failed to revoke: {}", e))),
        }
    }
}
