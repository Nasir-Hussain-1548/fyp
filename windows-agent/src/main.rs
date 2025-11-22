//! Windows-Only SIEM Agent
//!
//! - Registers with the Rust SIEM server
//! - Sends heartbeat periodically
//! - Polls Windows Security event log via `wevtutil`
//! - Forwards security & auth events to SIEM server
//!
//! **IMPORTANT**: Must be run as Administrator

use chrono::{DateTime, Utc};
use hostname;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;

const PLATFORM: &str = "windows";

const IMPORTANT_SECURITY_EVENT_IDS: &[u32] = &[
    4624, // Successful logon
    4625, // Failed logon
    4634, // Logoff
    4648, // Logon with explicit credentials
    4672, // Admin logon
    4720, // User account created
    4722, // User account enabled
    4723, // Password change attempted
    4724, // Password reset
    4725, // User account disabled
    4726, // User account deleted
    4728, // Member added to global security group
    4729, // Member removed from global security group
    4732, // Member added to local security group
    4733, // Member removed from local security group
    4740, // Account locked out
];

#[derive(Serialize, Deserialize, Debug)]
struct AgentRegisterRequest {
    agent_name: String,
    host: String,
    platform: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct AgentRegisterResponse {
    agent_id: Uuid,
}

#[derive(Serialize, Deserialize, Debug)]
struct AgentHeartbeatRequest {
    agent_id: Uuid,
}

#[derive(Serialize, Deserialize, Debug)]
struct AgentLogRequest {
    agent_id: Uuid,
    host: String,
    level: String,
    message: String,
    #[serde(serialize_with = "serialize_timestamp")]
    timestamp: DateTime<Utc>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    agent_name: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    event_id: Option<u32>,
}

fn serialize_timestamp<S>(dt: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let s = dt.to_rfc3339();
    serializer.serialize_str(&s)
}

#[derive(Debug, Clone)]
struct ParsedEvent {
    record_id: Option<u64>,
    event_id: Option<u32>,
    level: Option<String>,
    timestamp: Option<DateTime<Utc>>,
    message: String,
    source: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AgentConfig {
    agent_id: Uuid,
    agent_name: String,
    server_url: String,
}

const CONFIG_FILE: &str = "siem-agent-config.json";

#[tokio::main]
async fn main() {
    // Check if running as admin first
    if !is_admin() {
        eprintln!("\n⚠️  CRITICAL: Windows agent requires Administrator privileges!");
        eprintln!("📋 HOW TO FIX:");
        eprintln!("   1. Right-click 'Command Prompt' or 'PowerShell'");
        eprintln!("   2. Select 'Run as administrator'");
        eprintln!("   3. Navigate to agent directory and run the executable again");
        eprintln!("\n⏳ Press Enter to close this window...");
        let _ = std::io::stderr().flush();
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
        std::process::exit(1);
    }

    if let Err(e) = run().await {
        eprintln!("❌ AGENT ERROR: {e:?}");
        eprintln!("\n⚠️  Agent encountered an error. Check details above.");
        eprintln!("⏳ Press Enter to close this window...");
        let _ = std::io::stderr().flush();
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
        std::process::exit(1);
    }
}

fn is_admin() -> bool {
    // On Windows, try to check if running as admin
    #[cfg(target_os = "windows")]
    {
        match Command::new("net")
            .args(&["session"])
            .output() {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }
    
    #[cfg(not(target_os = "windows"))]
    true
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Try to load existing config
    let (server_url, agent_name, agent_id_opt) = if let Ok(config) = load_config() {
        println!("📋 Loaded existing configuration");
        (config.server_url, config.agent_name, Some(config.agent_id))
    } else {
        // Try multiple possible server URLs
        let server_url_env = env::var("SIEM_SERVER_URL").ok();
        
        eprintln!("DEBUG: SIEM_SERVER_URL env var = {:?}", server_url_env);
        
        let server_url = if let Some(url) = server_url_env {
            eprintln!("DEBUG: Using environment variable: {}", url);
            url
        } else {
            let candidate_urls = vec![
                "http://127.0.0.1:8080",
                "http://192.168.100.16:8080",
                "http://192.168.100.82:8080",
                "http://localhost:8080",
            ];
            
            let mut found_url = None;
            for url in candidate_urls {
                eprintln!("DEBUG: Trying server at {}", url);
                match tokio::time::timeout(
                    Duration::from_secs(2),
                    reqwest::Client::builder()
                        .timeout(Duration::from_secs(2))
                        .build()?
                        .head(&format!("{}/api/dashboard/stats", url))
                        .send()
                ).await {
                    Ok(Ok(_)) => {
                        eprintln!("DEBUG: Successfully connected to {}", url);
                        found_url = Some(url.to_string());
                        break;
                    }
                    _ => {
                        eprintln!("DEBUG: Failed to connect to {}", url);
                    }
                }
            }
            
            // If no server found, try 127.0.0.1 first (most common)
            found_url.unwrap_or_else(|| "http://127.0.0.1:8080".to_string())
        };

        // Generate auto-incremented agent name
        let agent_name = env::var("SIEM_AGENT_NAME")
            .unwrap_or_else(|_| generate_agent_name());
        
        (server_url, agent_name, None)
    };
    
    let host = hostname::get()
        .unwrap_or_else(|_| "unknown-host".into())
        .to_string_lossy()
        .to_string();
    let ip = get_primary_ip().unwrap_or_else(|| "unknown".to_string());

    println!("╔════════════════════════════════════════╗");
    println!("║     Windows SIEM Agent                 ║");
    println!("╚════════════════════════════════════════╝");
    println!("");
    println!("🚀 Windows Agent Starting...");
    println!("📡 Server URL: {}", server_url);
    println!("🖥️  Host: {}", host);
    println!("🌐 IP: {}", ip);
    println!("👤 Agent Name: {}", agent_name);
    println!("🔧 Platform: {}", PLATFORM);
    println!("");

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    // Register or reuse agent
    let agent_id = if let Some(id) = agent_id_opt {
        println!("✅ Using previously registered agent ID: {}", id);
        id
    } else {
        println!("📝 Registering agent with server...");
        eprintln!("DEBUG: Attempting to register at: {}/api/agent/register", server_url);
        
        let reg_req = AgentRegisterRequest {
            agent_name: agent_name.clone(),
            host: host.clone(),
            platform: PLATFORM.to_string(),
        };
        eprintln!("DEBUG: Sending request: {:#?}", reg_req);

        let reg_response = client
            .post(format!("{}/api/agent/register", server_url))
            .json(&reg_req)
            .send()
            .await
            .map_err(|e| {
                eprintln!("❌ Failed to connect to server at: {}", server_url);
                eprintln!("   Make sure:");
                eprintln!("   1. Server is running");
                eprintln!("   2. Firewall allows port 8080 (or your configured port)");
                eprintln!("   3. Network connection is working");
                eprintln!("   4. Server URL is correct (set SIEM_SERVER_URL env var if needed)");
                e
            })?
            .json::<AgentRegisterResponse>()
            .await?;

        let id = reg_response.agent_id;
        println!("✅ Agent registered with ID: {}", id);
        
        // Save config for future runs
        let config = AgentConfig {
            agent_id: id,
            agent_name: agent_name.clone(),
            server_url: server_url.clone(),
        };
        if let Err(e) = save_config(&config) {
            eprintln!("⚠️  Failed to save config: {}", e);
        }
        
        id
    };

    println!("\n🔄 Starting heartbeat and log collection...");

    let mut error_count = 0;
    const MAX_ERRORS: i32 = 10;

    loop {
        // Send heartbeat
        if let Err(e) = send_heartbeat(&client, &server_url, agent_id).await {
            eprintln!("⚠️  Heartbeat failed: {}", e);
            error_count += 1;
        } else {
            error_count = 0; // Reset on success
        }

        // Fetch and send Windows events
        match fetch_windows_events(&agent_id, &host, &agent_name, &ip) {
            Ok(events) => {
                if !events.is_empty() {
                    println!("✅ Fetched {} events", events.len());
                    for event in events {
                        if let Err(e) = send_log(&client, &server_url, event).await {
                            eprintln!("⚠️  Failed to send log: {}", e);
                        }
                    }
                } else {
                    println!("ℹ️  No new events in this cycle");
                }
            }
            Err(e) => {
                eprintln!("❌ Failed to fetch events: {}", e);
                eprintln!("   Make sure you're running as Administrator!");
                eprintln!("   The 'wevtutil' command requires Admin privileges.");
                error_count += 1;
            }
        }

        if error_count >= MAX_ERRORS {
            eprintln!("\n❌ Too many consecutive errors. Agent shutting down.");
            eprintln!("Please check:");
            eprintln!("  1. Running as Administrator?");
            eprintln!("  2. Server running at: {}", server_url);
            eprintln!("  3. Network connection?");
            std::process::exit(1);
        }

        sleep(Duration::from_secs(3)).await;
    }
}

fn fetch_windows_events(
    agent_id: &Uuid,
    host: &str,
    agent_name: &str,
    ip: &str,
) -> Result<Vec<AgentLogRequest>, Box<dyn std::error::Error>> {
    // Use wevtutil to query Windows Security event log
    let output = Command::new("wevtutil")
        .args(&[
            "qe",
            "Security",
            "/c:100",
            "/rd:true",
            "/f:text",
        ])
        .output()
        .map_err(|e| format!("WEVTUTIL ERROR {}: {}", e.raw_os_error().unwrap_or(0), e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("WEVTUTIL ERROR {}: {}", output.status.code().unwrap_or(-1), stderr).into());
    }

    let event_text = String::from_utf8_lossy(&output.stdout);
    let events = parse_wevtutil_output(
        &event_text,
        agent_id,
        host,
        agent_name,
        ip,
    )?;

    Ok(events)
}

fn parse_wevtutil_output(
    output: &str,
    agent_id: &Uuid,
    host: &str,
    agent_name: &str,
    ip: &str,
) -> Result<Vec<AgentLogRequest>, Box<dyn std::error::Error>> {
    let mut events = Vec::new();
    let mut current_event: Option<ParsedEvent> = None;

    for line in output.lines() {
        if line.starts_with("Event[") {
            if let Some(event) = current_event.take() {
                if let Ok(log_req) = convert_to_log_request(&event, agent_id, host, agent_name, ip) {
                    events.push(log_req);
                }
            }
        } else if line.contains("Event ID:") {
            let event_id_str = line.split("Event ID:").nth(1).unwrap_or("").trim();
            let event_id = event_id_str.parse::<u32>().ok();
            
            if event_id.map_or(false, |id| IMPORTANT_SECURITY_EVENT_IDS.contains(&id)) {
                if current_event.is_none() {
                    current_event = Some(ParsedEvent {
                        record_id: None,
                        event_id,
                        level: None,
                        timestamp: None,
                        message: String::new(),
                        source: "Security".to_string(),
                    });
                } else if let Some(ref mut evt) = current_event {
                    evt.event_id = event_id;
                }
            }
        } else if let Some(ref mut evt) = current_event {
            if line.contains("Level:") {
                evt.level = Some(line.split("Level:").nth(1).unwrap_or("").trim().to_string());
            } else if line.contains("TimeCreated:") {
                if let Ok(dt) = DateTime::parse_from_rfc3339(line.split("TimeCreated:").nth(1).unwrap_or("").trim()) {
                    evt.timestamp = Some(dt.with_timezone(&Utc));
                }
            } else if line.contains("RecordId:") {
                evt.record_id = line.split("RecordId:").nth(1).and_then(|s| s.trim().parse().ok());
            } else if !line.is_empty() && !line.starts_with(" ") {
                evt.message.push_str(line);
                evt.message.push(' ');
            }
        }
    }

    if let Some(event) = current_event {
        if let Ok(log_req) = convert_to_log_request(&event, agent_id, host, agent_name, ip) {
            events.push(log_req);
        }
    }

    Ok(events)
}

fn convert_to_log_request(
    event: &ParsedEvent,
    agent_id: &Uuid,
    host: &str,
    agent_name: &str,
    ip: &str,
) -> Result<AgentLogRequest, Box<dyn std::error::Error>> {
    Ok(AgentLogRequest {
        agent_id: *agent_id,
        host: host.to_string(),
        level: event.level.clone().unwrap_or_else(|| "INFO".to_string()),
        message: event.message.trim().to_string(),
        timestamp: event.timestamp.unwrap_or_else(Utc::now),
        source: Some(event.source.clone()),
        agent_name: Some(agent_name.to_string()),
        ip: Some(ip.to_string()),
        event_id: event.event_id,
    })
}

async fn send_heartbeat(
    client: &Client,
    server_url: &str,
    agent_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = AgentHeartbeatRequest { agent_id };
    client
        .post(format!("{}/api/agent/heartbeat", server_url))
        .json(&req)
        .send()
        .await?;
    Ok(())
}

async fn send_log(
    client: &Client,
    server_url: &str,
    log: AgentLogRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    client
        .post(format!("{}/api/agent/logs", server_url))
        .json(&log)
        .send()
        .await?;
    Ok(())
}

fn get_primary_ip() -> Option<String> {
    Some("127.0.0.1".to_string())
}

fn load_config() -> Result<AgentConfig, Box<dyn std::error::Error>> {
    use std::fs;
    let content = fs::read_to_string(CONFIG_FILE)?;
    let config: AgentConfig = serde_json::from_str(&content)?;
    Ok(config)
}

fn save_config(config: &AgentConfig) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    let json = serde_json::to_string_pretty(config)?;
    fs::write(CONFIG_FILE, json)?;
    println!("💾 Saved configuration to {}", CONFIG_FILE);
    Ok(())
}

fn generate_agent_name() -> String {
    use std::fs;
    
    // Count existing windows-agent entries in registry.json
    const REGISTRY_FILE: &str = "data/registry.json";
    let count = if let Ok(content) = fs::read_to_string(REGISTRY_FILE) {
        if let Ok(regs) = serde_json::from_str::<Vec<serde_json::Value>>(&content) {
            regs.iter()
                .filter(|r| {
                    r.get("agent_name")
                        .and_then(|n| n.as_str())
                        .map(|n| n.starts_with("windows-agent"))
                        .unwrap_or(false)
                })
                .count()
        } else {
            0
        }
    } else {
        0
    };
    
    format!("windows-agent-{:03}", count + 1)
}
