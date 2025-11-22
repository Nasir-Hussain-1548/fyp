//! Cross-Platform SIEM agent (Windows & Linux)
//!
//! - Registers with the Rust SIEM server
//! - Sends heartbeat periodically
//! - Windows: Polls Windows Security event log via `wevtutil`
//! - Linux: Tails syslog, security, kernel, and operational logs from /var/log/
//! - Forwards ONLY important security / auth events
//!
//! **IMPORTANT**: 
//! - Windows: Must be run as Administrator
//! - Linux: Must be run with sudo for log access

use chrono::{DateTime, Utc};
use futures;
use hostname;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;

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

// Platform detection
#[cfg(target_os = "windows")]
const PLATFORM: &str = "windows";

#[cfg(target_os = "linux")]
const PLATFORM: &str = "linux";

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
const PLATFORM: &str = "unknown";

// Linux log paths
#[cfg(target_os = "linux")]
const LINUX_LOG_PATHS: &[&str] = &[
    "/var/log/syslog",           // Syslog all
    "/var/log/auth.log",         // Security/Auth all
    "/var/log/kern.log",         // Kernel all
    "/var/log/messages",         // Operational all (some systems)
    "/var/log/secure",           // Security/Auth all (RedHat systems)
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

// Helper function to serialize timestamp as RFC3339 string
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
    source: String, // "Security", "Kernel", "Syslog", etc.
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
    if let Err(e) = run().await {
        eprintln!("❌ AGENT ERROR: {e:?}");
        
        #[cfg(target_os = "windows")]
        {
            eprintln!("\n⚠️  CRITICAL: Windows agent requires Administrator privileges!");
            eprintln!("📋 HOW TO FIX:");
            eprintln!("   1. Right-click 'Command Prompt' or 'PowerShell'");
            eprintln!("   2. Select 'Run as administrator'");
            eprintln!("   3. Navigate to agent directory and run the executable again");
            eprintln!("\n⏳ Press Enter to close this window...");
            let _ = std::io::Write::flush(&mut std::io::stderr());
            let mut input = String::new();
            let _ = std::io::stdin().read_line(&mut input);
        }
        
        #[cfg(target_os = "linux")]
        {
            eprintln!("\n⚠️  CRITICAL: Linux agent requires root/sudo privileges!");
            eprintln!("📋 HOW TO FIX:");
            eprintln!("   1. Run with: sudo ./siem-agent");
        }
        
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Try to load existing config
    let (server_url, agent_name, agent_id_opt) = if let Ok(config) = load_config() {
        println!("📋 Loaded existing configuration");
        (config.server_url, config.agent_name, Some(config.agent_id))
    } else {
        // Try multiple possible server URLs
        let server_url_env = env::var("SIEM_SERVER_URL").ok();
        
        let server_url = if let Some(url) = server_url_env {
            url
        } else {
            // Try to connect to multiple URLs, use the first one that works
            let candidate_urls = vec![
                "http://127.0.0.1:8080",
                "http://192.168.100.16:8080",
                "http://192.168.100.82:8080",
                "http://localhost:8080",
            ];
            
            let mut found_url = None;
            for url in candidate_urls {
                eprintln!("DEBUG: Trying server at {}", url);
                if reqwest::Client::builder()
                    .timeout(Duration::from_secs(2))
                    .build()?
                    .head(&format!("{}/api/dashboard/stats", url))
                    .send()
                    .await
                    .is_ok() {
                    eprintln!("DEBUG: Successfully connected to {}", url);
                    found_url = Some(url.to_string());
                    break;
                }
            }
            
            found_url.unwrap_or_else(|| "http://localhost:8080".to_string())
        };
        
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
    println!("║     SIEM Agent Starting                ║");
    println!("╚════════════════════════════════════════╝");
    println!("");
    println!("🚀 SIEM Agent Starting...");
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
        
        let register_request = AgentRegisterRequest {
            agent_name: agent_name.clone(),
            host: host.clone(),
            platform: PLATFORM.to_string(),
        };
        
        eprintln!("DEBUG: Sending request: {:?}", register_request);
        
        let response = match client
            .post(format!("{}/api/agent/register", server_url))
            .json(&register_request)
            .send()
            .await {
                Ok(resp) => resp,
                Err(e) => {
                    eprintln!("DEBUG: Request error: {}", e);
                    eprintln!("❌ Failed to connect to server at: {}", server_url);
                    eprintln!("   Make sure:");
                    eprintln!("   1. Server is running");
                    eprintln!("   2. Firewall allows port 8080 (or your configured port)");
                    eprintln!("   3. Network connection is working");
                    eprintln!("   4. Server URL is correct (set SIEM_SERVER_URL env var if needed)");
                    return Err(Box::new(e));
                }
            };

        let register_resp = response
            .error_for_status()?
            .json::<AgentRegisterResponse>()
            .await?;

        let id = register_resp.agent_id;
        println!("✅ Agent registered with ID: {}\n", id);
        
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

    println!("🔄 Starting heartbeat and log collection...\n");

    let mut last_record_ids: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut consecutive_errors: u32 = 0;
    const MAX_ERRORS: u32 = 10;

    loop {
        // Send heartbeat
        if let Err(e) = send_heartbeat(&client, &server_url, agent_id).await {
            eprintln!("❌ Heartbeat error: {}", e);
            consecutive_errors += 1;
        } else {
            consecutive_errors = 0;
        }

        // Fetch and send events based on platform
        match fetch_platform_events(&last_record_ids).await {
            Ok(events) => {
                eprintln!("DEBUG: fetch_platform_events returned {} events", events.len());
                if !events.is_empty() {
                    println!("📊 Found {} events", events.len());
                    for (idx, ev) in events.iter().enumerate() {
                        eprintln!("  Event {}: ID={:?}, Level={:?}, Source={}", 
                                  idx + 1, ev.event_id, ev.level, ev.source);
                    }
                    
                    // Build log requests
                    let mut log_requests = Vec::new();
                    for ev in &events {
                        let level = map_level(ev.level.as_deref());
                        let ts = ev.timestamp.unwrap_or_else(Utc::now);

                        let req = AgentLogRequest {
                            agent_id,
                            host: host.clone(),
                            level,
                            message: ev.message.clone(),
                            timestamp: ts,
                            source: Some(ev.source.clone()),
                            agent_name: Some(agent_name.clone()),
                            ip: Some(ip.clone()),
                            event_id: ev.event_id,
                        };
                        log_requests.push((ev.source.clone(), req));

                        if let Some(rec_id) = ev.record_id {
                            let entry = last_record_ids.entry(ev.source.clone())
                                .or_insert(0);
                            *entry = (*entry).max(rec_id);
                        }
                    }

                    // Send all logs concurrently
                    if !log_requests.is_empty() {
                        let futures: Vec<_> = log_requests
                            .iter()
                            .map(|(_, req)| send_log(&client, &server_url, req))
                            .collect();
                        
                        let results = futures::future::join_all(futures).await;
                        let sent_count = results.iter().filter(|r| r.is_ok()).count();
                        
                        if sent_count > 0 {
                            println!("✅ Successfully sent {} events", sent_count);
                        }
                        
                        if sent_count == log_requests.len() {
                            consecutive_errors = 0;
                        } else {
                            consecutive_errors += 1;
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("❌ Failed to fetch events: {}", e);
                consecutive_errors += 1;
            }
        }

        if consecutive_errors >= MAX_ERRORS {
            eprintln!("\n❌ Too many consecutive errors. Exiting...");
            return Err("Maximum error threshold reached".into());
        }

        sleep(Duration::from_secs(3)).await;
    }
}

fn map_level(level: Option<&str>) -> String {
    let lvl = level.unwrap_or("").to_lowercase();
    if lvl.contains("error") {
        "ERROR".to_string()
    } else if lvl.contains("warn") || lvl.contains("critical") {
        "WARN".to_string()
    } else {
        "INFO".to_string()
    }
}

async fn send_heartbeat(
    client: &Client,
    server_url: &str,
    agent_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = AgentHeartbeatRequest { agent_id };
    let resp = client
        .post(format!("{}/api/agent/heartbeat", server_url))
        .json(&payload)
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(format!("Heartbeat failed: {}", resp.status()).into());
    }
    Ok(())
}

async fn send_log(
    client: &Client,
    server_url: &str,
    log: &AgentLogRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    // Serialize to JSON
    let json_body = serde_json::to_string(&log)?;

    let resp = client
        .post(format!("{}/api/agent/logs", server_url))
        .header("Content-Type", "application/json")
        .body(json_body)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let error_body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "Log submission failed ({}): {}",
            status, error_body
        )
        .into());
    }
    Ok(())
}

async fn fetch_platform_events(
    last_record_ids: &std::collections::HashMap<String, u64>,
) -> Result<Vec<ParsedEvent>, Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        fetch_windows_events(last_record_ids).await
    }
    
    #[cfg(target_os = "linux")]
    {
        fetch_linux_events(last_record_ids).await
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Err("Unsupported platform".into())
    }
}

#[cfg(target_os = "windows")]
async fn fetch_windows_events(
    last_record_ids: &std::collections::HashMap<String, u64>,
) -> Result<Vec<ParsedEvent>, Box<dyn std::error::Error>> {
    // Try Security log first (requires admin)
    let output = Command::new("wevtutil")
        .args(["qe", "Security", "/f:text", "/c:100", "/rd:true"])
        .output()?;

    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if code == 5 {
            eprintln!("⚠️  WARNING: Access Denied - Agent must run as Administrator to access Security log!");
            eprintln!("📌 Falling back to System event log (less detailed)...");
            
            // Fall back to System log which might be more accessible
            let output = Command::new("wevtutil")
                .args(["qe", "System", "/f:text", "/c:100", "/rd:true"])
                .output()?;
                
            if !output.status.success() {
                let error_msg = format!("Cannot access System log either: {}", String::from_utf8_lossy(&output.stderr));
                eprintln!("❌ {}", error_msg);
                return Err(error_msg.into());
            }
            
            let text = String::from_utf8_lossy(&output.stdout);
            eprintln!("DEBUG: System log output length: {} bytes", text.len());
            let last_record = last_record_ids.get("System").copied();
            let events = parse_wevtutil_text_system(&text, last_record);
            eprintln!("DEBUG: System log parsed {} events", events.len());
            return Ok(events);
        }

        let error_msg = match code {
            127 => "WEVTUTIL not found - Windows Event Log tools may not be installed".to_string(),
            _ => format!("WEVTUTIL failed with code {}: {}", code, stderr),
        };

        return Err(error_msg.into());
    }

    let text = String::from_utf8_lossy(&output.stdout);
    eprintln!("DEBUG: Security log output length: {} bytes", text.len());
    if text.len() > 0 {
        eprintln!("DEBUG: First 500 chars of output:\n{}", &text.chars().take(500).collect::<String>());
    } else {
        eprintln!("DEBUG: Security log returned no output!");
    }
    let last_record = last_record_ids.get("Security").copied();
    let events = parse_wevtutil_text(&text, last_record);
    eprintln!("DEBUG: Security log parsed {} events", events.len());
    Ok(events)
}

#[cfg(target_os = "linux")]
async fn fetch_linux_events(
    last_record_ids: &std::collections::HashMap<String, u64>,
) -> Result<Vec<ParsedEvent>, Box<dyn std::error::Error>> {
    let mut all_events = Vec::new();

    for log_path in LINUX_LOG_PATHS {
        if !Path::new(log_path).exists() {
            continue;
        }

        let source = match Path::new(log_path).file_name().and_then(|n| n.to_str()) {
            Some("syslog") => "Syslog",
            Some("auth.log") | Some("secure") => "Security",
            Some("kern.log") => "Kernel",
            Some("messages") => "Operational",
            _ => "System",
        };

        let last_line_num = last_record_ids.get(source).copied().unwrap_or(0);
        match parse_linux_log_file(log_path, source, last_line_num as usize) {
            Ok(mut events) => all_events.append(&mut events),
            Err(e) => eprintln!("⚠️  Error parsing {}: {}", log_path, e),
        }
    }

    Ok(all_events)
}

#[cfg(target_os = "linux")]
fn parse_linux_log_file(
    path: &str,
    source: &str,
    last_line_num: usize,
) -> Result<Vec<ParsedEvent>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let lines: Vec<&str> = content.lines().collect();
    let mut events = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        if idx <= last_line_num || line.trim().is_empty() {
            continue;
        }

        let (level, message) = parse_linux_log_line(line);
        events.push(ParsedEvent {
            record_id: Some((idx + 1) as u64),
            event_id: None,
            level: Some(level),
            timestamp: parse_linux_timestamp(line),
            message,
            source: source.to_string(),
        });
    }

    Ok(events)
}

#[cfg(target_os = "linux")]
fn parse_linux_log_line(line: &str) -> (String, String) {
    let level = if line.to_uppercase().contains("ERROR") || line.to_uppercase().contains("CRIT") {
        "ERROR".to_string()
    } else if line.to_uppercase().contains("WARN") || line.to_uppercase().contains("WARNING") {
        "WARN".to_string()
    } else if line.to_uppercase().contains("FAILED") || line.to_uppercase().contains("FAILURE") {
        "WARN".to_string()
    } else {
        "INFO".to_string()
    };

    (level, line.to_string())
}

#[cfg(target_os = "linux")]
fn parse_linux_timestamp(line: &str) -> Option<DateTime<Utc>> {
    // Try to parse common syslog timestamp formats: "Nov 27 09:38:11" or with year
    let re = Regex::new(r"([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})").ok()?;
    let caps = re.captures(line)?;
    
    let month_str = caps.get(1)?.as_str();
    let day: u32 = caps.get(2)?.as_str().parse().ok()?;
    let hour: u32 = caps.get(3)?.as_str().parse().ok()?;
    let min: u32 = caps.get(4)?.as_str().parse().ok()?;
    let sec: u32 = caps.get(5)?.as_str().parse().ok()?;

    let month = match month_str {
        "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4, "May" => 5, "Jun" => 6,
        "Jul" => 7, "Aug" => 8, "Sep" => 9, "Oct" => 10, "Nov" => 11, "Dec" => 12,
        _ => return None,
    };

    let year = chrono::Local::now().year();
    let date = chrono::NaiveDate::from_ymd_opt(year, month, day)?;
    let time = chrono::NaiveTime::from_hms_opt(hour, min, sec)?;
    let naive_dt = chrono::NaiveDateTime::new(date, time);
    
    Some(DateTime::<Utc>::from_naive_utc_and_offset(naive_dt, Utc))
}

fn parse_wevtutil_text(text: &str, last_record_id: Option<u64>) -> Vec<ParsedEvent> {
    parse_wevtutil_text_internal(text, last_record_id, "Security")
}

fn parse_wevtutil_text_system(text: &str, last_record_id: Option<u64>) -> Vec<ParsedEvent> {
    parse_wevtutil_text_internal(text, last_record_id, "System")
}

fn parse_wevtutil_text_internal(text: &str, last_record_id: Option<u64>, source: &str) -> Vec<ParsedEvent> {
    let mut events = Vec::new();
    let chunks: Vec<&str> = text.split("Event[").collect();
    
    eprintln!("DEBUG: parse_wevtutil_text_internal({}) - Found {} event chunks", source, chunks.len() - 1);

    let re_event_id = Regex::new(r"(?m)^\s*Event ID:\s*(\d+)").unwrap();
    let re_record_id = Regex::new(r"(?m)^\s*Record ID:\s*(\d+)").unwrap();
    let re_level = Regex::new(r"(?m)^\s*Level:\s*(.+)$").unwrap();
    let re_date = Regex::new(r"(?m)^\s*Date:\s*(.+)$").unwrap();

    for (chunk_idx, chunk) in chunks.iter().enumerate() {
        let chunk = chunk.trim();
        if chunk.is_empty() {
            continue;
        }

        let record_id = re_record_id
            .captures(chunk)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().trim().parse::<u64>().ok());

        if let (Some(last), Some(rec)) = (last_record_id, record_id) {
            if rec <= last {
                eprintln!("DEBUG: Skipping record {} (already seen)", rec);
                continue;
            }
        }

        let event_id = re_event_id
            .captures(chunk)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().trim().parse::<u32>().ok());

        eprintln!("DEBUG: Chunk {} - RecordID: {:?}, EventID: {:?}", chunk_idx, record_id, event_id);

        // Include events - prioritize important ones but accept all for visibility
        // (Important events are still tracked, but we don't skip non-important ones)
        if event_id.is_none() {
            continue;
        }

        let level = re_level
            .captures(chunk)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string());

        let ts = re_date
            .captures(chunk)
            .and_then(|c| c.get(1))
            .and_then(|m| {
                let s = m.as_str().trim();
                DateTime::parse_from_rfc3339(s)
                    .map(|dt| dt.with_timezone(&Utc))
                    .ok()
            });

        let message = extract_clean_message(chunk);

        events.push(ParsedEvent {
            record_id,
            event_id,
            level,
            timestamp: ts,
            message,
            source: source.to_string(),
        });
    }

    events
}

fn extract_clean_message(event_chunk: &str) -> String {
    // Extract the detailed description part of the Windows Security event
    // Skip the Event[] header and extract only meaningful content
    let mut description_lines = Vec::new();

    for line in event_chunk.lines() {
        let trimmed = line.trim();

        // Skip metadata lines that are not needed
        if trimmed.starts_with("Event[") || trimmed.starts_with("Log Name:") ||
           trimmed.starts_with("Source:") || trimmed.starts_with("Date:") ||
           trimmed.starts_with("Event ID:") || trimmed.starts_with("Task:") ||
           trimmed.starts_with("Level:") || trimmed.starts_with("Opcode:") ||
           trimmed.starts_with("Keyword:") || trimmed.starts_with("User:") ||
           trimmed.starts_with("Computer:") || trimmed.starts_with("Record ID:") ||
           trimmed.is_empty() {
            continue;
        }

        description_lines.push(trimmed.to_string());
    }

    // Join the description lines with minimal whitespace
    let message = description_lines.join(" ");

    // Clean up multiple spaces
    message.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn get_primary_ip() -> Option<String> {
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                return Some(addr.ip().to_string());
            }
        }
    }
    None
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
    use uuid::Uuid;
    
    // Use hostname + unique UUID suffix for uniqueness
    let hostname = hostname::get()
        .unwrap_or_else(|_| "unknown-host".into())
        .to_string_lossy()
        .to_string();
    
    let short_uuid = Uuid::new_v4().to_string()[..8].to_string();
    
    format!("{}-agent-{}", PLATFORM, short_uuid)
}