//! Web portal for agent download and enrollment

use crate::enroll::AppState;
use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap},
    response::{Html, IntoResponse, Response},
};
use std::io::Write;
use tracing::info;
use zip::write::{FileOptions, ZipWriter};

// Serve a small HTML portal and produce a ZIP containing the Windows agent, an
// install.ps1 script (dynamically generated with an OTK and server URL), and
// the CA certificate.

pub async fn serve_portal(State(_state): State<AppState>) -> Html<String> {
    // Check for presence of a Windows binary in common locations so the portal
    // can show a Windows download button when available.
    let possible_paths = [
        // Prefer single-file installer if present
        "server/agent_builds/percepta-agent-setup.exe",
        "server/agent_builds/percepta-agent.exe",
        "target/x86_64-pc-windows-gnu/release/percepta-agent.exe",
    ];

    let mut windows_available = false;
    for p in possible_paths {
        if tokio::fs::metadata(p).await.is_ok() {
            windows_available = true;
            break;
        }
    }

    Html(get_portal_html(windows_available))
}

/// Return CA certificate PEM for clients to use during enrollment
pub async fn get_ca_cert(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    let ca_cert_pem = state.ca_service.get_ca_certificate_pem()?;
    let headers = [(header::CONTENT_TYPE, "text/plain".to_string())];
    Ok((headers, ca_cert_pem).into_response())
}

pub async fn download_agent(
    Path(os): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    info!("Agent download request for OS: {}", os);

    match os.as_str() {
        "windows" => download_windows_agent(state, headers).await,
        "linux" => download_linux_agent(state, headers).await,
        _ => Err(AppError(anyhow::anyhow!(
            "Unsupported OS: {}. Supported: windows, linux",
            os
        ))),
    }
}

async fn download_windows_agent(state: AppState, headers: HeaderMap) -> Result<Response, AppError> {
    // If a single-file installer exists, serve it directly.
    if let Ok(bytes) = tokio::fs::read("server/agent_builds/percepta-agent-setup.exe").await {
        let headers = [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"percepta-agent-setup.exe\"".to_string(),
            ),
        ];
        return Ok((headers, bytes).into_response());
    }

    // Determine server URL and gRPC address. Prefer explicit publish host if configured,
    // otherwise extract the hostname from the Host header.
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("Request missing Host header"))?;
    // Allow an operator to override the published host/IP (useful when behind NAT)
    let server_host = std::env::var("PERCEPTA_PUBLIC_HOST")
        .ok()
        .unwrap_or_else(|| host.split(':').next().unwrap_or(host).to_string());
    // Use gRPC port (50051) for agent connection, HTTP port (8080) for enrollment
    let server_url = format!("http://{}:8080", server_host);
    let grpc_addr = format!("{}:50051", server_host);

    // Generate OTK
    let otk = state
        .otk_store
        .generate("portal-download".to_string())
        .await?;

    // Create PowerShell installer content (include gRPC address)
    // Note: refer to percepta-agent-core.exe explicitly to match packaged name
    let ps_script_content = get_install_ps1(&otk.otk, &server_url, &grpc_addr);

    // Primary Windows agent: unified GUI+service+collector binary
    let windows_agent_candidates = [
        "server/agent_builds/percepta-agent-windows.exe",
        "target/x86_64-pc-windows-gnu/release/percepta-agent-windows.exe",
    ];
    
    let mut windows_agent_bytes = None;
    for p in &windows_agent_candidates {
        if let Ok(b) = tokio::fs::read(p).await {
            windows_agent_bytes = Some(b);
            break;
        }
    }
    
    let windows_agent_bytes = windows_agent_bytes.ok_or_else(|| {
        anyhow::anyhow!(
            "Windows GUI agent not found. Expected at '{}' or '{}'. Build with: cargo build --release --target x86_64-pc-windows-gnu -p percepta-agent --bin percepta-agent-windows --features gui",
            windows_agent_candidates[0],
            windows_agent_candidates[1]
        )
    })?;

    // Get CA certificate
    let ca_cert_pem = state.ca_service.get_ca_certificate_pem()?;

    // Build ZIP in memory
    let mut buf: Vec<u8> = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = ZipWriter::new(cursor);
        let options = FileOptions::default().unix_permissions(0o755);

        // Write the unified Windows GUI agent
        zip.start_file("percepta-agent-windows.exe", options)?;
        zip.write_all(&windows_agent_bytes)?;

        // Also include the installer and CA cert separately
        zip.start_file("install.ps1", options)?;
        zip.write_all(ps_script_content.as_bytes())?;

        zip.start_file("ca_cert.pem", options)?;
        zip.write_all(ca_cert_pem.as_bytes())?;

        let server_config = format!("enroll_url={}\ngrpc_server={}\nnote=Use these values when running the agent manually.\n", server_url, grpc_addr);
        zip.start_file("server-config.txt", options)?;
        zip.write_all(server_config.as_bytes())?;

        // Include the OTK in a separate file so GUI/installer can run enrollment automatically
        zip.start_file("otk.txt", options)?;
        zip.write_all(otk.otk.as_bytes())?;

        zip.finish()?;
    }

    let headers = [
        (header::CONTENT_TYPE, "application/zip".to_string()),
        (
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"percepta-agent-windows.zip\"".to_string(),
        ),
    ];

    Ok((headers, buf).into_response())
}

async fn download_linux_agent(state: AppState, headers: HeaderMap) -> Result<Response, AppError> {
    // Determine server URL. Prefer explicit publish host if configured,
    // otherwise extract hostname from the Host header.
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("Request missing Host header"))?;
    let server_host = std::env::var("PERCEPTA_PUBLIC_HOST")
        .ok()
        .unwrap_or_else(|| host.split(':').next().unwrap_or(host).to_string());
    // Use gRPC port (50051) for agent connection, HTTP port (8080) for enrollment
    let server_url = format!("http://{}:8080", server_host);
    let grpc_addr = format!("{}:50051", server_host);

    // Generate OTK
    let otk = state
        .otk_store
        .generate("portal-download".to_string())
        .await?;

    // Create bash installer content
    let install_sh_content = get_install_sh(&otk.otk, &server_url, &grpc_addr);

    // Read agent binary
    let agent_binary_path = "server/static/downloads/percepta-agent-linux-x64";
    let agent_binary_bytes = tokio::fs::read(agent_binary_path).await.context(format!(
        "Failed to read agent binary from '{}'. Run 'cargo build --release -p percepta-agent' to build it.",
        agent_binary_path
    ))?;

    // Get CA certificate
    let ca_cert_pem = state.ca_service.get_ca_certificate_pem()?;

    // Build ZIP in memory
    let mut buf: Vec<u8> = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = ZipWriter::new(cursor);
        let options = FileOptions::default().unix_permissions(0o755);

        zip.start_file("percepta-agent", options)?;
        zip.write_all(&agent_binary_bytes)?;

        zip.start_file("install.sh", options)?;
        zip.write_all(install_sh_content.as_bytes())?;

        zip.start_file("ca_cert.pem", options)?;
        zip.write_all(ca_cert_pem.as_bytes())?;

        let server_config = format!(
            "server_url={}\nnote=Use this server URL when running the agent manually.\n",
            server_url
        );
        zip.start_file("server-config.txt", options)?;
        zip.write_all(server_config.as_bytes())?;

        zip.finish()?;
    }

    let headers = [
        (header::CONTENT_TYPE, "application/zip".to_string()),
        (
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"percepta-agent-linux.zip\"".to_string(),
        ),
    ];

    Ok((headers, buf).into_response())
}

fn get_portal_html(windows_available: bool) -> String {
    let windows_button = if windows_available {
        r#"<a href="/api/download/agent/windows" class="button" style="background-color: #007bff; margin: 0.5rem;">Download for Windows (Single EXE)</a>"#
    } else {
        r#"<a class="button" style="background-color: #6c757d; margin: 0.5rem; pointer-events: none; opacity: 0.7;">Windows build not found</a>"#
    };

    // Note: keep Linux button prominent; insert Windows button above the note section
    let template = r###"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Percepta SIEM Agent Download</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f2f5; margin: 0; }
        .container { background: white; padding: 2.5rem; border-radius: 8px; box-shadow: 0 10px 25px rgba(0,0,0,0.1); text-align: center; max-width: 500px; width: 90%; }
        h1 { color: #1d2129; margin-bottom: 0.5rem; }
        p { color: #606770; margin-top: 0; margin-bottom: 2rem; }
        .button { display: inline-block; background-color: #007bff; color: white; padding: 1rem 2rem; text-decoration: none; border-radius: 6px; font-size: 1.1rem; font-weight: 600; transition: background-color 0.3s, transform 0.2s; }
        .button:hover { background-color: #0056b3; transform: translateY(-2px); }
    </style>
</head>
<body>
    <div class="container">
        <h1>Percepta SIEM Agent</h1>
        <p>Download the agent for your operating system. The installer is pre-configured for this server.</p>
    __WINDOWS_BUTTON__
    <br><br>
    <a href="/api/download/agent/linux" class="button" style="background-color: #28a745; margin: 0.5rem;">Download for Linux (x64)</a>
    <br><br>
        <p style="font-size: 0.9rem; color: #666; margin-top: 1rem;">
            <strong>Note:</strong> Windows agent requires cross-compilation if not provided by the server.<br>
            To build Windows agent locally: Install mingw-w64 and run:<br>
            <code style="background: #f0f0f0; padding: 2px 6px; border-radius: 3px;">
                cargo build --release --target x86_64-pc-windows-gnu -p percepta-agent
            </code>
        </p>
        <p style="font-size: 0.9rem; color: #999; margin-top: 1rem;">Agent includes automatic enrollment with one-time token</p>
    </div>
</body>
</html>
    "###;

    template.replace("__WINDOWS_BUTTON__", windows_button)
}

fn get_install_ps1(otk: &str, server_url: &str, grpc_addr: &str) -> String {
    let template = r###"#

#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs and enrolls the Percepta SIEM Agent.
.DESCRIPTION
    This script prepares certificates, enrolls the agent with the server,
    and then installs the agent as a persistent Windows service.
#>

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "[+] Percepta SIEM Agent Installer" -ForegroundColor Green

# --- Configuration ---
$Otk = "__OTK__"
$ServerUrl = "__SERVER__"
$GrpcAddr = "__GRPC__"
$AgentExe = Join-Path $ScriptDir "percepta-agent-windows.exe"
$CertDir = r"C:\ProgramData\percepta_agent\certs"
$CaCertSource = Join-Path $ScriptDir "ca_cert.pem"
$CaCertDest = Join-Path $CertDir "ca_cert.pem"

# --- Certificate Setup ---
Write-Host "[+] Setting up certificate directory: $CertDir"
New-Item -ItemType Directory -Force -Path $CertDir
Write-Host "[+] Copying CA certificate to $CaCertDest"
Copy-Item -Path $CaCertSource -Destination $CaCertDest -Force

# --- Enrollment ---
Write-Host "[+] Enrolling agent with server: $ServerUrl"
try {
    # Use the gRPC address for agent connection during enrollment/runtime
    & $AgentExe --enroll $Otk --server $GrpcAddr
}
catch {
    Write-Host "[!] Enrollment failed. The error was:" -ForegroundColor Red
    Write-Host $_
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "[+] Enrollment successful!" -ForegroundColor Green

# --- Service Installation ---
Write-Host "[+] Installing agent as a Windows Service..."
# Export runtime server env for the service (the service will inherit this when started via sc create binPath)
Write-Host "[+] Setting PERCEPTA_SERVER environment for the service: $GrpcAddr"
[Environment]::SetEnvironmentVariable("PERCEPTA_SERVER", $GrpcAddr, "Machine")

# Use sc.exe to create the service with a binPath that includes --server so the agent auto-connects
$ServiceName = "PerceptaAgent"
$BinPath = "`"$AgentExe`" --server $GrpcAddr --service"
try {
    sc.exe create $ServiceName binPath= $BinPath start= auto
    sc.exe description $ServiceName "Percepta SIEM Agent service"
    sc.exe start $ServiceName
}
catch {
    Write-Host "[!] Service installation failed. The error was:" -ForegroundColor Red
    Write-Host $_
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "[+] Agent service installed successfully." -ForegroundColor Green
Write-Host "The agent will now run in the background and start automatically with Windows."
Read-Host "Press Enter to exit"

# End of script
"###;

    template
        .replace("__OTK__", otk)
        .replace("__SERVER__", server_url)
        .replace("__GRPC__", grpc_addr)
}

fn get_install_sh(otk: &str, server_url: &str, grpc_addr: &str) -> String {
    let template = r###"#!/bin/bash
#
# Percepta SIEM Agent Installer for Linux
# This script prepares certificates, enrolls the agent with the server,
# and installs the agent as a systemd service.

set -e

if [ "$EUID" -ne 0 ]; then 
    echo "[!] Please run as root (use sudo)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OTK="__OTK__"
ENROLL_URL="__ENROLL_URL__"
GRPC_SERVER="__GRPC_SERVER__"
AGENT_BIN="$SCRIPT_DIR/percepta-agent"
INSTALL_DIR="/opt/percepta-agent"
CERT_DIR="/etc/percepta-agent/certs"
DATA_DIR="/var/lib/percepta-agent"
CA_CERT_SOURCE="$SCRIPT_DIR/ca_cert.pem"

echo "[+] Percepta SIEM Agent Installer"

# --- Setup directories ---
echo "[+] Creating installation directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$CERT_DIR"
mkdir -p "$DATA_DIR/outgoing/archives"

# --- Install binary ---
echo "[+] Installing agent binary to $INSTALL_DIR/percepta-agent"
cp "$AGENT_BIN" "$INSTALL_DIR/percepta-agent"
chmod +x "$INSTALL_DIR/percepta-agent"

# --- Certificate Setup ---
echo "[+] Copying CA certificate to $CERT_DIR/ca_cert.pem"
cp "$CA_CERT_SOURCE" "$CERT_DIR/ca_cert.pem"

# --- Enrollment ---
echo "[+] Enrolling agent with server: $ENROLL_URL"
# Set cert dir environment variable for enrollment
export PERCEPTA_CERT_DIR="$CERT_DIR"
if ! "$INSTALL_DIR/percepta-agent" --enroll "$OTK" --server "$ENROLL_URL"; then
    echo "[!] Enrollment failed"
    echo "[!] Check that the server is accessible at: $ENROLL_URL"
    echo "[!] Try: curl -v $ENROLL_URL/api/health"
    exit 1
fi

echo "[+] Enrollment successful!"

# --- Systemd Service Installation ---
echo "[+] Creating systemd service..."

cat > /etc/systemd/system/percepta-agent.service <<EOF
[Unit]
Description=Percepta SIEM Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$DATA_DIR
Environment="PERCEPTA_SERVER=$GRPC_SERVER"
Environment="PERCEPTA_CERT_DIR=$CERT_DIR"
Environment="PERCEPTA_OUT=$DATA_DIR/outgoing"
ExecStart=$INSTALL_DIR/percepta-agent
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# --- Enable and start service ---
echo "[+] Enabling and starting percepta-agent service..."
systemctl daemon-reload
systemctl enable percepta-agent.service
systemctl start percepta-agent.service

echo "[+] Agent service installed successfully!"
echo "[+] The agent is now running and will start automatically on boot."
echo ""
echo "Useful commands:"
echo "  Check status:  sudo systemctl status percepta-agent"
echo "  View logs:     sudo journalctl -u percepta-agent -f"
echo "  Restart:       sudo systemctl restart percepta-agent"
echo "  Stop:          sudo systemctl stop percepta-agent"

# End of script
"###;

    template
        .replace("__OTK__", otk)
        .replace("__ENROLL_URL__", server_url)
        .replace("__GRPC_SERVER__", grpc_addr)
}

// --- Error Handling --- //

pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
