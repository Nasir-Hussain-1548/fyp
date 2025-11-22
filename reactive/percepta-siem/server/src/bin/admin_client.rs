pub mod percepta {
    tonic::include_proto!("percepta.siem.ingestion.v1");
}

use percepta::admin_service_client::AdminServiceClient;
use percepta::RevokeRequest;

// Re-export the library timestamps helpers as `crate::timestamps` so the
// generated proto code (which uses `crate::timestamps::option`) can resolve
// when compiling this binary target.
mod timestamps {
    pub use percepta_server::timestamps::*;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:50051".to_string());
    let serial = std::env::args()
        .nth(2)
        .expect("serial number argument required");

    let mut client = AdminServiceClient::connect(addr).await?;
    let req = tonic::Request::new(RevokeRequest { serial });
    let resp = client.revoke_certificate(req).await?;
    println!("Revoke response: {:?}", resp.into_inner());
    Ok(())
}
