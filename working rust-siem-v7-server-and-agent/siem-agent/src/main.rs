//! Windows SIEM agent
//!
//! - Registers with the Rust SIEM server
//! - Sends heartbeat periodically
//! - Polls Windows Security event log via `wevtutil`
//! - Forwards ONLY important security / auth events (no random noise)
//!
//! This agent is designed to talk to the Axum server you already have:
//!   POST /api/agent/register
//!   POST /api/agent/heartbeat
//!   POST /api/agent/logs

use chrono::{DateTime, Utc};
use hostname;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;

/// Important Windows Security event IDs we care about.
/// (Auth + account / group changes)
const IMPORTANT_SECURITY_EVENT_IDS: &[u32] = &[
    4624, // Successful logon
    4625, // Failed logon
    4634, // Logoff
    4648, // Logon with explicit credentials
    4672, // Admin logon (special privileges)
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
    #[serde(with = "chrono::serde::ts_seconds")]
    timestamp: DateTime<Utc>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    agent_name: Option<String>,
    #[serde(default)]
    ip: Option<String>,
}

#[derive(Debug)]
struct ParsedWinEvent {
    record_id: Option<u64>,
    event_id: Option<u32>,
    level: Option<String>,
    timestamp: Option<DateTime<Utc>>,
    message: String,
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("agent error: {e:?}");
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // ----------- basic config from env -----------
    let server_url =
        env::var("SIEM_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:9200".to_string());
    let agent_name = env::var("SIEM_AGENT_NAME").unwrap_or_else(|_| "win-agent-001".to_string());
    let host = hostname::get()
        .unwrap_or_else(|_| "unknown-host".into())
        .to_string_lossy()
        .to_string();
    let ip = get_primary_ip().unwrap_or_else(|| "unknown".to_string());

    println!("Connecting to SIEM server at {server_url}");
    println!("Host: {host}, IP: {ip}, Agent name: {agent_name}");

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    // ----------- register agent -----------
    let register_resp = client
        .post(format!("{server_url}/api/agent/register"))
        .json(&AgentRegisterRequest {
            agent_name: agent_name.clone(),
            host: host.clone(),
        })
        .send()
        .await?
        .error_for_status()?
        .json::<AgentRegisterResponse>()
        .await?;

    let agent_id = register_resp.agent_id;
    println!("Registered agent with id: {agent_id}");

    // Track last Security event record ID so we don't resend duplicates
    let mut last_security_record_id: Option<u64> = None;

    // Main loop: heartbeat + log forwarding
    loop {
        // 1) Send heartbeat
        if let Err(e) = send_heartbeat(&client, &server_url, agent_id).await {
            eprintln!("heartbeat error: {e:?}");
        }

        // 2) Poll Security log and forward important events
        match fetch_security_events(last_security_record_id).await {
            Ok(events) => {
                if !events.is_empty() {
                    // keep max record_id to avoid duplicates next time
                    let mut max_rec: Option<u64> = last_security_record_id;
                    for ev in events {
                        if let Some(event_id) = ev.event_id {
                            if !IMPORTANT_SECURITY_EVENT_IDS.contains(&event_id) {
                                // skip non-important security events
                                continue;
                            }
                        } else {
                            // if we can't parse event id, drop it
                            continue;
                        }

                        // map Windows "Level" to SIEM level
                        let level = map_level(ev.level.as_deref());

                        let ts = ev.timestamp.unwrap_or_else(Utc::now);

                        let req = AgentLogRequest {
                            agent_id,
                            host: host.clone(),
                            level,
                            message: ev.message.clone(),
                            timestamp: ts,
                            source: Some("Security".to_string()),
                            agent_name: Some(agent_name.clone()),
                            ip: Some(ip.clone()),
                        };

                        if let Err(e) = send_log(&client, &server_url, &req).await {
                            eprintln!("send_log error: {e:?}");
                        }

                        if let Some(rec_id) = ev.record_id {
                            max_rec = Some(max_rec.map(|m| m.max(rec_id)).unwrap_or(rec_id));
                        }
                    }
                    last_security_record_id = max_rec;
                }
            }
            Err(e) => {
                eprintln!("fetch_security_events error: {e:?}");
            }
        }

        // Sleep before next cycle
        sleep(Duration::from_secs(15)).await;
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
        .post(format!("{server_url}/api/agent/heartbeat"))
        .json(&payload)
        .send()
        .await?;
    if !resp.status().is_success() {
        eprintln!("heartbeat failed, status = {}", resp.status());
    }
    Ok(())
}

async fn send_log(
    client: &Client,
    server_url: &str,
    log: &AgentLogRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client
        .post(format!("{server_url}/api/agent/logs"))
        .json(log)
        .send()
        .await?;
    if !resp.status().is_success() {
        eprintln!("send_log failed, status = {}", resp.status());
    }
    Ok(())
}

/// Call `wevtutil` to query the Security log and parse the output into structured events.
///
/// We keep this intentionally simple and robust:
/// - Use text format (`/f:text`)
/// - Limit count (`/c:50`)
/// - Reverse direction (`/rd:true`) so newest events first
async fn fetch_security_events(
    last_record_id: Option<u64>,
) -> Result<Vec<ParsedWinEvent>, Box<dyn std::error::Error>> {
    // wevtutil qe Security /f:text /c:50 /rd:true
    let output = Command::new("wevtutil")
        .args(["qe", "Security", "/f:text", "/c:50", "/rd:true"])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "wevtutil failed with status {:?}",
            output.status.code()
        )
        .into());
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let events = parse_wevtutil_text(&text, last_record_id);
    Ok(events)
}

/// Very simple parser for `wevtutil /f:text` output.
/// It is not perfect, but good enough for lab / demo usage.
/// You can tweak the regexes if your Windows language/format is different.
fn parse_wevtutil_text(text: &str, last_record_id: Option<u64>) -> Vec<ParsedWinEvent> {
    let mut events = Vec::new();

    // Split by "Event[" which starts a new block
    let chunks: Vec<&str> = text.split("Event[").collect();

    let re_event_id = Regex::new(r"(?m)^\s*Event ID:\s*(\d+)").unwrap();
    let re_record_id = Regex::new(r"(?m)^\s*Record ID:\s*(\d+)").unwrap();
    let re_level = Regex::new(r"(?m)^\s*Level:\s*(.+)$").unwrap();
    let re_date = Regex::new(r"(?m)^\s*Date:\s*(.+)$").unwrap();

    for chunk in chunks {
        let chunk = chunk.trim();
        if chunk.is_empty() {
            continue;
        }

        // Parse record ID, if any
        let record_id = re_record_id
            .captures(chunk)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().trim().parse::<u64>().ok());

        // Skip if record_id is older than last_record_id
        if let (Some(last), Some(rec)) = (last_record_id, record_id) {
            if rec <= last {
                continue;
            }
        }

        let event_id = re_event_id
            .captures(chunk)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().trim().parse::<u32>().ok());

        let level = re_level
            .captures(chunk)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string());

        let ts = re_date
            .captures(chunk)
            .and_then(|c| c.get(1))
            .and_then(|m| {
                let s = m.as_str().trim();
                // Try RFC3339-ish, else fallback to now
                DateTime::parse_from_rfc3339(s)
                    .map(|dt| dt.with_timezone(&Utc))
                    .ok()
            });

        // For message, just use the entire chunk; frontend can filter/search text.
        let message = chunk.to_string();

        events.push(ParsedWinEvent {
            record_id,
            event_id,
            level,
            timestamp: ts,
            message,
        });
    }

    events
}

/// Try to discover a primary local IP using a UDP socket trick.
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
