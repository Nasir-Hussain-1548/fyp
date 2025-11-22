use anyhow::{Context, Result};
use axum::response::Redirect;
use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use rand::distributions::{Alphanumeric, DistString}; // For API Key generation
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::{codec::CompressionEncoding, transport::Server as TonicServer};
use tower::make::Shared;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Module declarations
mod admin;
mod certificate_authority;
mod collector;
mod enroll;
mod enrollment;
mod events; // gRPC EventsService for querying recent events
mod gui; // New GUI module
mod portal;
mod storage;
mod timestamps;
mod tls; // Timestamp serialization
         // Use rule_engine from the library crate to avoid duplicate types
mod search_api;
mod test_ingest;
mod websocket; // Test HTTP ingestion for development

// Use protobuf definitions from the library crate to avoid duplicate types

use admin::AdminService;
use certificate_authority::{CAConfig, CAService};
use collector::CollectorService;
use enroll::{claim_otk, request_otk, AppState, OtkStore};
use enrollment::EnrollmentService;
use events::EventsService;
use gui::{api_key_auth, get_events_api, serve_gui_page}; // New GUI imports
use percepta_server::percepta::admin_service_server::AdminServiceServer;
use percepta_server::percepta::collector_service_server::CollectorServiceServer;
use percepta_server::percepta::enrollment_service_server::EnrollmentServiceServer;
use percepta_server::percepta::events_service_server::EventsServiceServer;
use portal::{download_agent, serve_portal};
use search_api::{get_alerts, get_stats, search_events};
use storage::StorageService;
use test_ingest::test_ingest_event;
use tokio::sync::broadcast;
use websocket::{websocket_handler, StreamMessage};

use axum::extract::{State, Form};
use axum::response::Html;
use serde::Deserialize;
use chrono::Utc;
use tokio::fs as tokio_fs;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize structured logging
    init_logging()?;

    info!("🔧 Initializing Percepta SIEM Server...");

    // --- Initialize Shared Services ---

    // 1. Certificate Authority Service (prefer writable user dir; override with PERCEPTA_CA_DIR)
    let ca_storage_path = std::env::var("PERCEPTA_CA_DIR")
        .ok()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            std::path::PathBuf::from(format!("{}/.local/share/percepta-siem/certs", home))
        });
    let ca_config = CAConfig {
        ca_storage_path,
        ..Default::default()
    };
    let ca_service = Arc::new(
        CAService::new(ca_config)
            .await
            .context("Failed to initialize CA service")?,
    );

    // 2. Storage Service (prefer writable user dir; override with PERCEPTA_DATA_DIR)
    let data_dir = std::env::var("PERCEPTA_DATA_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        format!("{}/.local/share/percepta-siem", home)
    });
    let storage_service = Arc::new(
        StorageService::new(&data_dir)
            .await
            .context("Failed to initialize Storage service")?,
    );

    // 3. Alert Service and Rule Engine
    let alert_service = Arc::new(percepta_server::alerts::AlertService::new(300));
    let mut rule_engine = percepta_server::rule_engine::RuleEngine::new(alert_service.clone());

    // Load detection rules
    let rules_file = std::path::Path::new("rules.yaml");
    if rules_file.exists() {
        rule_engine
            .load_rules_from_file(rules_file)
            .await
            .context("Failed to load detection rules")?;
    } else {
        warn!("rules.yaml not found, running without detection rules");
    }
    let rule_engine = Arc::new(rule_engine);

    // 4. API Key for GUI
    let api_key = std::env::var("PERCEPTA_API_KEY").unwrap_or_else(|_| {
        let key = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
        warn!("PERCEPTA_API_KEY not set. Using a randomly generated key.");
        println!("🔑 Your one-time GUI API Key is: {}", key);
        key
    });

    // 5. Event Broadcaster for WebSocket streaming
    let (event_broadcaster, _) = broadcast::channel::<StreamMessage>(1000);
    let event_broadcaster = Arc::new(event_broadcaster);

    // Create shared one-time token store for enrollment
    let otk_store = OtkStore::new();

    // --- Spawn Background and Server Tasks ---

    // Spawn WAL compaction task
    let compaction_handle: tokio::task::JoinHandle<Result<(), anyhow::Error>> = {
        let storage_service = storage_service.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600)); // Every hour
            loop {
                interval.tick().await;
                info!("Kicking off hourly WAL compaction task...");
                if let Err(e) = storage_service.compact_wal().await {
                    error!("Error during WAL compaction: {:#}", e);
                }
            }
        })
    };

    // Spawn CRL reload task (every 5 minutes)
    let _crl_reload_handle: tokio::task::JoinHandle<()> = {
        let ca_service_crl = ca_service.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // Every 5 minutes
            loop {
                interval.tick().await;
                info!("🔄 Reloading CRL...");
                match ca_service_crl.generate_crl().await {
                    Ok(_) => info!("✅ CRL reloaded successfully"),
                    Err(e) => warn!("⚠️  CRL reload failed: {}", e),
                }
            }
        })
    };

    // Spawn periodic stats broadcasting task
    let _stats_handle: tokio::task::JoinHandle<()> = {
        let storage_service = storage_service.clone();
        let alert_service = alert_service.clone();
        let event_broadcaster = event_broadcaster.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30)); // Every 30 seconds
            loop {
                interval.tick().await;

                // Gather stats from existing methods
                let event_count = storage_service.get_recent_events().await.len();
                let alert_count = alert_service.get_alerts().await.len();

                let stats = serde_json::json!({
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "events_total": event_count,
                    "alerts_total": alert_count,
                });

                // Broadcast stats to WebSocket clients
                let _ = event_broadcaster.send(StreamMessage::Stats(stats));
            }
        })
    };

    // gRPC server
    let grpc_server_handle = {
        let ca_service_grpc = ca_service.clone();
        let storage_service = storage_service.clone();
        let rule_engine = rule_engine.clone();
        let otk_store = otk_store.clone();
        let event_broadcaster = event_broadcaster.clone();
        tokio::spawn(async move {
            run_grpc_server(
                ca_service_grpc,
                storage_service,
                rule_engine,
                otk_store,
                event_broadcaster,
            )
            .await
        })
    };

    // Web server
    let web_server_handle = {
        // All services are cloned into the web server task
        let ca_service_web = ca_service.clone();
        let otk_store = otk_store.clone();
        let event_broadcaster = event_broadcaster.clone();
        let alert_service = alert_service.clone();
        tokio::spawn(async move {
            run_web_server(
                ca_service_web,
                storage_service,
                api_key,
                otk_store,
                event_broadcaster,
                alert_service,
            )
            .await
        })
    };

    // mDNS service registration (opt-in; default enabled, can disable via PERCEPTA_ENABLE_MDNS=0)
    let enable_mdns = std::env::var("PERCEPTA_ENABLE_MDNS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    let mdns_handle = if enable_mdns {
        tokio::spawn(async { register_mdns_service().await })
    } else {
        info!("mDNS disabled via PERCEPTA_ENABLE_MDNS");
        tokio::spawn(async { Ok(()) })
    };

    // Wait for all tasks to complete
    let (grpc_res, web_res, mdns_res, compaction_res) = tokio::try_join!(
        grpc_server_handle,
        web_server_handle,
        mdns_handle,
        compaction_handle
    )?;

    if let Err(e) = grpc_res {
        error!("gRPC server failed: {:#}", e);
    }

    if let Err(e) = web_res {
        error!("Web server failed: {:#}", e);
    }

    if let Err(e) = mdns_res {
        error!("mDNS service failed: {:#}", e);
    }

    if let Err(e) = compaction_res {
        error!("WAL compaction task failed: {:#}", e);
    }

    Ok(())
}

/// Run the gRPC server for agent communication
async fn run_grpc_server(
    ca_service: Arc<CAService>,
    storage_service: Arc<StorageService>,
    rule_engine: Arc<percepta_server::rule_engine::RuleEngine>,
    otk_store: OtkStore,
    event_broadcaster: Arc<broadcast::Sender<StreamMessage>>,
) -> Result<()> {
    // Allow dynamic bind address via PERCEPTA_BIND (integration tests rely on this).
    // Fallback to default if unset.
    let bind_str = std::env::var("PERCEPTA_BIND").unwrap_or_else(|_| "0.0.0.0:50051".to_string());
    let addr: SocketAddr = bind_str.parse().context("Invalid PERCEPTA_BIND value")?;

    // Decide whether to use TLS. For dynamic bind ports (not the default 50051) we assume
    // plaintext for test environments so Channel::from_shared("http://...") succeeds.
    // Production keeps TLS on the default port unless explicitly disabled.
    let disable_tls_env = std::env::var("PERCEPTA_DISABLE_TLS").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);
    let use_tls = !disable_tls_env && addr.port() == 50051;
    if use_tls {
        info!("🚀 gRPC server running (mTLS) at https://{}", addr);
    } else {
        info!("🚀 gRPC server running (plaintext) at http://{}", addr);
    }

    let maybe_tls_config = if use_tls {
        Some(
            tls::create_server_tls_config(&ca_service)
                .await
                .context("Failed to create gRPC TLS config")?,
        )
    } else { None };

    // Create gRPC service
    let collector_service = CollectorService::new(
        ca_service.clone(),
        storage_service.clone(),
        rule_engine,
        event_broadcaster,
    )
    .await
    .context("Failed to initialize collector service")?;
    let events_service = EventsService::new(storage_service.clone());
    let enrollment_service =
        EnrollmentService::new(Arc::new(otk_store.clone()), ca_service.clone());
    let admin_service = AdminService::new(ca_service.clone());

    let collector_service = CollectorServiceServer::new(collector_service)
        .accept_compressed(CompressionEncoding::Gzip)
        .send_compressed(CompressionEncoding::Gzip);

    let mut builder = TonicServer::builder();
    if let Some(tls_config) = maybe_tls_config { builder = builder.tls_config(tls_config)?; }

    let server_result = builder
        .add_service(collector_service)
        .add_service(EventsServiceServer::new(events_service))
        .add_service(EnrollmentServiceServer::new(enrollment_service))
        .add_service(AdminServiceServer::new(admin_service))
        .serve(addr)
        .await;
    
    match server_result {
        Ok(_) => Ok(()),
        Err(e) => {
            if e.to_string().contains("Address already in use") || e.to_string().contains("address in use") {
                error!("❌ gRPC port 50051 is already in use. Is another instance of Percepta running?");
                error!("   To fix: Stop the other instance or change the port in the configuration.");
                anyhow::bail!("Port 50051 already in use")
            } else {
                Err(e).context("gRPC server error")
            }
        }
    }
}

/// Run the web server for enrollment, agent download, and the new GUI
async fn run_web_server(
    ca_service: Arc<CAService>,
    storage_service: Arc<StorageService>,
    api_key: String,
    otk_store: OtkStore,
    event_broadcaster: Arc<broadcast::Sender<StreamMessage>>,
    alert_service: Arc<percepta_server::alerts::AlertService>,
) -> Result<()> {
    let addr: SocketAddr = "0.0.0.0:8080".parse()?;
    info!("🌐 Web server running at http://{}", addr);

    // Clones for health/readiness routes before moving into app state
    let health_ca_service = ca_service.clone();
    let health_storage_service = storage_service.clone();

    // Create shared application state
    let app_state = AppState {
        otk_store,
        ca_service,
        storage_service: storage_service.clone(),
        api_key,
        event_broadcaster: event_broadcaster.clone(),
        alert_service: alert_service.clone(),
    };

    // Define routes for the new GUI, protected by the auth middleware
    let gui_routes = Router::new()
        .route("/events", get(serve_gui_page))
        .route("/api/events", get(get_events_api))
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            api_key_auth,
        ));

    // Define search API routes (public for now, can add auth later)
    let search_routes = Router::new()
        .route("/api/search", get(search_events))
        .route("/api/alerts", get(get_alerts))
        .route("/api/stats", get(get_stats));

    // WebSocket route
    let ws_routes = Router::new().route("/api/stream", get(websocket_handler));

    // Dashboard HTML (public - auth handled in JavaScript for API calls)
    // Serve embedded dashboard HTML so it works regardless of CWD
    let dashboard_html: &'static str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/dashboard.html"));

    // Define public routes
    let public_routes = Router::new()
        .route("/", get(|| async { Redirect::temporary("/dashboard") }))
        .route(
            "/dashboard",
            get(move || async move { axum::response::Html(dashboard_html) }),
        )
        // Keep portal available explicitly
        .route("/portal", get(serve_portal))
        // New simple response submission page
        .route("/addresponse", get(add_response_page))
        .route("/api/addresponse", post(submit_response))
        // Common aliases auto-redirect
        .route("/ui", get(|| async { Redirect::temporary("/dashboard") }))
        .route("/app", get(|| async { Redirect::temporary("/dashboard") }))
        .route("/api/download/agent/:os", get(download_agent))
        .route("/api/ca_cert", get(portal::get_ca_cert))
        .route("/api/enroll/request", post(request_otk))
        .route("/api/enroll/claim", post(claim_otk))
        .route("/api/test/ingest", post(test_ingest_event)) // Test endpoint for fake agents
        // Enhanced health and readiness endpoints
        .route("/healthz", get({
            let ca_service = health_ca_service.clone();
            let storage_service = health_storage_service.clone();
            move || async move {
                // Check actual service health
                let mut health = serde_json::json!({
                    "status": "ok",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                });
                
                // Check CA service
                health["ca_service"] = if ca_service.get_ca_certificate_pem().is_ok() {
                    serde_json::json!({"status": "healthy"})
                } else {
                    serde_json::json!({"status": "degraded"})
                };
                
                // Check storage service
                let events = storage_service.get_recent_events().await;
                health["storage_service"] = serde_json::json!({
                    "status": "healthy",
                    "cached_events": events.len()
                });
                
                axum::Json(health)
            }
        }))
        .route("/readyz", get({
            let storage_service = health_storage_service.clone();
            move || async move {
                // Basic readiness: storage available and CA present
                let storage_ok = storage_service.get_recent_events().await; // touch storage
                let status = serde_json::json!({
                    "status": "ok",
                    "storage_events_cached": storage_ok.len()
                });
                axum::Json(status)
            }
        }));

    // Combine all routes and apply the state
    let app = public_routes
        .merge(gui_routes)
        .merge(search_routes)
        .merge(ws_routes)
        // Fallback: any unknown GET path redirects to dashboard
        .fallback(get(|| async { Redirect::temporary("/dashboard") }))
        .with_state(app_state.clone());

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                error!("❌ Web port 8080 is already in use. Is another instance of Percepta running?");
                error!("   To fix: Stop the other instance or change the port in the configuration.");
                anyhow::bail!("Port 8080 already in use")
            } else {
                return Err(e).context("Failed to bind web server to port 8080");
            }
        }
    };
    
    axum::serve(listener, Shared::new(app))
        .await
        .context("Web server error")
}

// ----- Response Submission Page & Handler -----

#[derive(Deserialize)]
struct AddResponseForm { text: String }

/// GET /addresponse - show a simple HTML form and existing submitted responses
async fn add_response_page(State(state): State<AppState>) -> Html<String> {
    let file_path = "server/static/downloads/agent-responses.txt";
    let existing = tokio_fs::read_to_string(file_path).await.unwrap_or_default();
    // Simple HTML escaping without external crate to avoid adding new dependency
    fn escape_html(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for ch in s.chars() {
            match ch {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&#39;"),
                _ => out.push(ch),
            }
        }
        out
    }
    let escaped = escape_html(&existing);
    // Basic HTML page with a form posting to /api/addresponse
    let body = format!(r#"<!DOCTYPE html><html><head><title>Agent Response Upload</title>
<style>body{{font-family:sans-serif;max-width:760px;margin:2rem auto;padding:1rem;}}textarea{{width:100%;height:180px;}}pre{{background:#f6f8fa;padding:1rem;border:1px solid #ddd;white-space:pre-wrap;word-wrap:break-word;}}</style></head><body>
<h1>Submit Agent Response</h1>
<form method="post" action="/api/addresponse">
<textarea name="text" placeholder="Paste diagnostic or response text here" required></textarea>
<br/><button type="submit">Submit</button>
</form>
<h2>Previously Submitted Responses</h2>
<pre>{}</pre>
<p><a href="/dashboard">Return to dashboard</a></p>
</body></html>"#, escaped);
    Html(body)
}

/// POST /api/addresponse - append submitted text to a server-side file with timestamp
async fn submit_response(State(state): State<AppState>, Form(form): Form<AddResponseForm>) -> Redirect {
    let trimmed = form.text.trim();
    if !trimmed.is_empty() {
        let file_path = "server/static/downloads/agent-responses.txt";
        // Ensure directory exists
        if let Some(parent) = std::path::Path::new(file_path).parent() {
            let _ = tokio_fs::create_dir_all(parent).await;
        }
        let line = format!("{} | {}\n\n", Utc::now().to_rfc3339(), trimmed);
        if let Ok(mut f) = tokio_fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)
            .await
        {
            use tokio::io::AsyncWriteExt;
            let _ = f.write_all(line.as_bytes()).await;
        }
    }
    Redirect::temporary("/addresponse")
}

/// Register the SIEM gRPC service with mDNS for automatic discovery
async fn register_mdns_service() -> Result<()> {
    let mdns = ServiceDaemon::new().context("Failed to create mDNS daemon")?;
    let service_type = "_percepta-siem._tcp.local.";
    let instance_name = "percepta-siem-server";
    let host_name = hostname::get()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "percepta-server.local.".to_string());
    let port = 50051;

    let service_info = ServiceInfo::new(
        service_type,
        instance_name,
        &host_name,
        "", // Let the library discover the IP
        port,
        None, // No TXT records
    )
    .context("Failed to create mDNS service info")?;

    mdns.register(service_info)
        .context("Failed to register mDNS service")?;

    info!(
        "📢 mDNS service registered: instance='{}', type='{}', port={}",
        instance_name, service_type, port
    );

    // Keep the daemon alive - use a long sleep instead of pending() for graceful shutdown
    // This allows the server to shut down cleanly via Ctrl+C
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
    }
}

/// Initialize structured logging with JSON output for production
fn init_logging() -> Result<()> {
    let log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&log_level)),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(false)
                .with_span_list(true),
        )
        .init();

    info!("📋 Logging initialized with level: {}", log_level);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_address_parsing() {
        let addr: Result<SocketAddr, _> = "0.0.0.0:50051".parse();
        assert!(addr.is_ok());
        assert_eq!(addr.unwrap().port(), 50051);
    }

    #[test]
    fn test_logging_initialization() {
        let result = init_logging();
        assert!(result.is_ok());
    }
}
