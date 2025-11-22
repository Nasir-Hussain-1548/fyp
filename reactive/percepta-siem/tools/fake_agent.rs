//! Fake Agent Simulator for Testing Percepta SIEM
//! Generates realistic security events and sends them to the server

use anyhow::{Context, Result};
use rand::Rng;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<()> {
    println!("🤖 Starting Fake Agent Simulator...");
    println!("📡 Target Server: http://localhost:8080");

    let agent_id = format!("fake-agent-{}", rand::random::<u16>());
    let hostname = format!("test-host-{}", rand::random::<u16>());

    println!("🆔 Agent ID: {}", agent_id);
    println!("💻 Hostname: {}", hostname);
    println!("⏱️  Sending events every 2 seconds...\n");

    let client = reqwest::Client::new();
    let mut event_count = 0;

    loop {
        let event = generate_random_event(&agent_id, &hostname);

        match send_event(&client, &event).await {
            Ok(_) => {
                event_count += 1;
                println!(
                    "✅ Event #{} sent: {}",
                    event_count,
                    event
                        .get("event")
                        .and_then(|e| e.get("summary"))
                        .and_then(|s| s.as_str())
                        .unwrap_or("N/A")
                );
            }
            Err(e) => {
                eprintln!("❌ Failed to send event: {}", e);
            }
        }

        sleep(Duration::from_secs(2)).await;
    }
}

fn generate_random_event(agent_id: &str, hostname: &str) -> serde_json::Value {
    let mut rng = rand::thread_rng();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let event_type = rng.gen_range(0..5);

    let (category, action, outcome, summary, user, process) = match event_type {
        0 => {
            // Failed login attempt
            let username = ["admin", "root", "user", "test", "guest"][rng.gen_range(0..5)];
            (
                1, // AUTH
                "logon".to_string(),
                1, // failure
                format!("Failed login attempt for user {}", username),
                Some(json!({
                    "name": username,
                    "id": format!("uid-{}", rng.gen_range(1000..2000))
                })),
                None,
            )
        }
        1 => {
            // Successful login
            let username = ["alice", "bob", "charlie", "admin"][rng.gen_range(0..4)];
            (
                1, // AUTH
                "logon".to_string(),
                0, // success
                format!("Successful login for user {}", username),
                Some(json!({
                    "name": username,
                    "id": format!("uid-{}", rng.gen_range(1000..2000))
                })),
                None,
            )
        }
        2 => {
            // Process execution
            let processes = [
                ("cmd.exe", "cmd.exe /c whoami"),
                ("powershell.exe", "powershell.exe -ExecutionPolicy Bypass"),
                ("bash", "/bin/bash -c 'ls -la'"),
                ("python", "python3 script.py"),
            ];
            let (name, cmdline) = processes[rng.gen_range(0..processes.len())];
            (
                4, // PROCESS
                "start".to_string(),
                0, // success
                format!("Process started: {}", name),
                Some(json!({
                    "name": "system",
                    "id": "0"
                })),
                Some(json!({
                    "name": name,
                    "pid": rng.gen_range(1000..30000),
                    "command_line": cmdline
                })),
            )
        }
        3 => {
            // File access
            let files = [
                "/etc/passwd",
                "/etc/shadow",
                "C:\\Windows\\System32\\config\\SAM",
                "/home/user/.ssh/id_rsa",
                "/var/log/auth.log",
            ];
            let file = files[rng.gen_range(0..files.len())];
            (
                3, // FILE
                "read".to_string(),
                0, // success
                format!("File accessed: {}", file),
                Some(json!({
                    "name": "user",
                    "id": format!("uid-{}", rng.gen_range(1000..2000))
                })),
                None,
            )
        }
        _ => {
            // Network connection
            let ports = [22, 80, 443, 3389, 445, 3306, 5432, 8080];
            let port = ports[rng.gen_range(0..ports.len())];
            let ip = format!(
                "10.{}.{}.{}",
                rng.gen_range(0..255),
                rng.gen_range(0..255),
                rng.gen_range(0..255)
            );
            (
                2, // NETWORK
                "connection".to_string(),
                0, // success
                format!("Network connection to {}:{}", ip, port),
                Some(json!({
                    "name": "system",
                    "id": "0"
                })),
                None,
            )
        }
    };

    let mut event_json = json!({
        "hash": format!("evt-{}-{}", now, rng.gen_range(10000..99999)),
        "event_time": {
            "seconds": now,
            "nanos": 0
        },
        "agent": {
            "id": agent_id,
            "hostname": hostname,
            "version": "1.0.0-fake"
        },
        "host": {
            "ip": [format!("192.168.1.{}", rng.gen_range(10..250))],
            "os": "Linux"
        },
        "event": {
            "category": category,
            "action": action,
            "outcome": outcome,
            "summary": summary,
            "provider": "FakeAgent",
            "original_message": format!("Simulated event at {}", now)
        }
    });

    if let Some(user) = user {
        event_json["user"] = user;
    }

    if let Some(proc) = process {
        event_json["process"] = proc;
    }

    event_json
}

async fn send_event(client: &reqwest::Client, event: &serde_json::Value) -> Result<()> {
    // For now, we'll use the HTTP REST API since we don't have mTLS certs
    // In production, agents would use gRPC with mTLS

    // Since the server doesn't have a direct HTTP event ingestion endpoint,
    // we'll store it via a custom endpoint or use the storage directly
    // For testing, let's just print and simulate

    // Actually, let's POST to a test endpoint we'll create
    let response = client
        .post("http://localhost:8080/api/test/ingest")
        .json(event)
        .send()
        .await
        .context("Failed to send HTTP request")?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Server returned error: {}",
            response.status()
        ))
    }
}
