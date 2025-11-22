fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::path::Path;
    let proto_file = "../shared/proto/siem_core.proto";
    let proto_dir = "../shared/proto";

    // Ensure proto exists (helpful for fresh clones/dev envs)
    if !Path::new(proto_file).exists() {
        eprintln!("Warning: Proto file not found at {}", proto_file);
        eprintln!("Creating a minimal proto file for compilation...");

        std::fs::create_dir_all(proto_dir)?;
        let minimal_proto = r#"
syntax = "proto3";
package percepta.siem.ingestion.v1;
import "google/protobuf/timestamp.proto";

message Event {
    google.protobuf.Timestamp event_time = 1;
    google.protobuf.Timestamp ingest_time = 2;
    string hash = 16;
}

message IngestionResponse {
    bool ack = 1;
    string event_id = 2;
    string message = 3;
}

message EnrollRequest {
    string agent_id = 1;
    string hostname = 2;
    string ip_address = 3;
}

message EnrollResponse {
    string agent_id = 1;
    string certificate_pem = 2;
    string private_key_pem = 3;
    string ca_certificate_pem = 4;
}

service CollectorService {
    rpc StreamEvents(stream Event) returns (stream IngestionResponse);
    rpc EnrollAgent(EnrollRequest) returns (EnrollResponse);
}
"#;
        std::fs::write(proto_file, minimal_proto)?;
    }

    // Single, clear codegen pass with serde derives and timestamp field helpers
    tonic_build::configure()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(
            "google.protobuf.Timestamp",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .field_attribute(
            ".percepta.siem.ingestion.v1.Event.event_time",
            "#[serde(with = \"crate::timestamps::option\")]",
        )
        .field_attribute(
            ".percepta.siem.ingestion.v1.Event.ingest_time",
            "#[serde(with = \"crate::timestamps::option\")]",
        )
        .compile(&[proto_file], &[proto_dir])?;

    println!("cargo:rerun-if-changed={}", proto_file);
    Ok(())
}
