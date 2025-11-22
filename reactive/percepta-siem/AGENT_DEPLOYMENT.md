# Percepta SIEM Agent Deployment Guide

This guide covers deploying the Percepta SIEM agent to Windows and Linux systems via the web portal.

## Quick Start

### 1. Build the Agent

The Linux binary is already built at:
```bash
target/release/percepta-agent
```

For Windows cross-compilation (optional), run:
```bash
./scripts/build_agent_windows.sh
```

### 2. Start the Server

```bash
cargo run --release -p percepta-server
```

The server will start on `http://localhost:8080`

### 3. Access the Download Portal

Open a browser and navigate to:
```
http://YOUR_SERVER_IP:8080/portal
```

You'll see download options for both Windows and Linux.

## Agent Download and Installation

### Linux Installation

1. **Download the agent package** from the portal:
   - Click "Download for Linux" button
   - Save `percepta-agent-linux.zip`

2. **Extract and run the installer**:
   ```bash
   unzip percepta-agent-linux.zip
   cd percepta-agent-linux/
   sudo bash install.sh
   ```

3. **Verify the agent is running**:
   ```bash
   sudo systemctl status percepta-agent
   sudo journalctl -u percepta-agent -f
   ```

#### Manual Linux Installation

If you prefer manual setup:

```bash
# Create directories
sudo mkdir -p /opt/percepta-agent
sudo mkdir -p /etc/percepta-agent/certs
sudo mkdir -p /var/lib/percepta-agent/outgoing/archives

# Copy files
sudo cp percepta-agent /opt/percepta-agent/
sudo chmod +x /opt/percepta-agent/percepta-agent
sudo cp ca_cert.pem /etc/percepta-agent/certs/

# Set environment variables
export PERCEPTA_SERVER="your-server:50051"
export PERCEPTA_CERT_DIR="/etc/percepta-agent/certs"
export PERCEPTA_OUT="/var/lib/percepta-agent/outgoing"

# Enroll (get OTK from server admin)
sudo /opt/percepta-agent/percepta-agent --enroll YOUR_OTK --server $PERCEPTA_SERVER

# Run agent
sudo /opt/percepta-agent/percepta-agent
```

### Windows Installation

1. **Download the agent package** from the portal:
   - Click "Download for Windows" button
   - Save `percepta-agent-windows.zip`

2. **Extract and run the installer**:
   - Right-click `percepta-agent-windows.zip` → Extract All
   - Right-click `install.ps1` → Run with PowerShell (as Administrator)
   - Follow the prompts

3. **Verify the agent is running**:
   ```powershell
   Get-Service PerceptaAgent
   Get-EventLog -LogName Application -Source PerceptaAgent -Newest 10
   ```

#### Manual Windows Installation

If you prefer manual setup:

```powershell
# Create directories
New-Item -ItemType Directory -Force -Path "C:\ProgramData\percepta_agent\certs"
New-Item -ItemType Directory -Force -Path "C:\ProgramData\percepta_agent\outgoing\archives"

# Copy files to C:\Program Files\Percepta\
# Copy ca_cert.pem to C:\ProgramData\percepta_agent\certs\

# Set environment variables (Machine level)
[Environment]::SetEnvironmentVariable("PERCEPTA_SERVER", "your-server:50051", "Machine")
[Environment]::SetEnvironmentVariable("PERCEPTA_CERT_DIR", "C:\ProgramData\percepta_agent\certs", "Machine")

# Enroll
.\percepta-agent.exe --enroll YOUR_OTK --server your-server:50051

# Install as service
sc.exe create PerceptaAgent binPath= "C:\Path\To\percepta-agent.exe" start= auto
sc.exe start PerceptaAgent
```

## Environment Variables

The agent uses the following environment variables:

| Variable | Required | Default (Linux) | Default (Windows) | Description |
|----------|----------|-----------------|-------------------|-------------|
| `PERCEPTA_SERVER` | Yes* | - | - | Server address (host:port), e.g., `192.168.1.100:50051` |
| `PERCEPTA_CERT_DIR` | No | `./certs` | `C:\ProgramData\percepta_agent\certs` | Certificate directory path |
| `PERCEPTA_OUT` | No | `./outgoing` | `C:\ProgramData\percepta_agent\outgoing` | Outgoing events directory |
| `PERCEPTA_AGENT_ID` | No | Auto-generated | Auto-generated | Unique agent identifier |
| `PERCEPTA_LOG_LEVEL` | No | `info` | `info` | Logging level (trace, debug, info, warn, error) |

\* Can be auto-discovered via mDNS if not set and server is on local network.

## Command-Line Options

```bash
# Show help
percepta-agent --help

# Enroll with server
percepta-agent --enroll <OTK> --server <SERVER_URL>

# Run in simulation mode (for testing)
percepta-agent --simulate

# Specify server address
percepta-agent --server 192.168.1.100:50051
```

## Troubleshooting

### Agent Won't Connect

1. **Check server address**:
   ```bash
   # Linux
   echo $PERCEPTA_SERVER
   
   # Windows
   [Environment]::GetEnvironmentVariable("PERCEPTA_SERVER", "Machine")
   ```

2. **Verify network connectivity**:
   ```bash
   # Test gRPC port
   telnet YOUR_SERVER_IP 50051
   # or
   nc -zv YOUR_SERVER_IP 50051
   ```

3. **Check certificates**:
   ```bash
   # Linux
   ls -la /etc/percepta-agent/certs/
   
   # Windows
   dir C:\ProgramData\percepta_agent\certs\
   ```

### View Agent Logs

**Linux (systemd)**:
```bash
sudo journalctl -u percepta-agent -f
sudo journalctl -u percepta-agent --since "1 hour ago"
```

**Linux (manual run)**:
```bash
# Set log level
export RUST_LOG=debug
/opt/percepta-agent/percepta-agent
```

**Windows (Service)**:
```powershell
Get-EventLog -LogName Application -Source PerceptaAgent -Newest 50
```

**Windows (manual run)**:
```powershell
$env:RUST_LOG="debug"
.\percepta-agent.exe
```

### Re-enrollment

If you need to re-enroll the agent:

1. Stop the agent service
2. Remove old certificates
3. Get a new OTK from server admin
4. Run enrollment again

```bash
# Linux
sudo systemctl stop percepta-agent
sudo rm /etc/percepta-agent/certs/*.pem
sudo /opt/percepta-agent/percepta-agent --enroll NEW_OTK --server YOUR_SERVER
sudo systemctl start percepta-agent

# Windows
Stop-Service PerceptaAgent
Remove-Item C:\ProgramData\percepta_agent\certs\*.pem
.\percepta-agent.exe --enroll NEW_OTK --server YOUR_SERVER
Start-Service PerceptaAgent
```

## Uninstallation

### Linux

```bash
# Stop and disable service
sudo systemctl stop percepta-agent
sudo systemctl disable percepta-agent

# Remove service file
sudo rm /etc/systemd/system/percepta-agent.service
sudo systemctl daemon-reload

# Remove agent files
sudo rm -rf /opt/percepta-agent
sudo rm -rf /etc/percepta-agent
sudo rm -rf /var/lib/percepta-agent
```

### Windows

```powershell
# Stop and remove service
Stop-Service PerceptaAgent
sc.exe delete PerceptaAgent

# Remove agent files
Remove-Item -Recurse -Force "C:\Program Files\Percepta\"
Remove-Item -Recurse -Force "C:\ProgramData\percepta_agent\"

# Remove environment variables
[Environment]::SetEnvironmentVariable("PERCEPTA_SERVER", $null, "Machine")
[Environment]::SetEnvironmentVariable("PERCEPTA_CERT_DIR", $null, "Machine")
```

## Security Considerations

1. **TLS/mTLS**: The agent uses mutual TLS (mTLS) for secure communication with the server
2. **Certificate Management**: Each agent gets a unique client certificate during enrollment
3. **One-Time Keys (OTK)**: Enrollment uses single-use tokens that expire after use
4. **Network Isolation**: Run the server on a private network or use VPN for remote agents
5. **Firewall Rules**: Open only port 50051 (gRPC) on the server

## Production Checklist

- [ ] Build release binaries (`cargo build --release`)
- [ ] Copy Linux binary to `server/static/downloads/percepta-agent-linux-x64`
- [ ] For Windows: Run `./scripts/build_agent_windows.sh` (requires cross-compilation toolchain)
- [ ] Test agent download from portal
- [ ] Verify auto-enrollment works
- [ ] Test agent connection and event forwarding
- [ ] Configure firewall rules
- [ ] Set up monitoring for agent health
- [ ] Document your OTK generation process for team
- [ ] Set up log rotation for agent logs

## Architecture Overview

```
┌─────────────────┐
│  Percepta SIEM  │
│     Server      │
│  (port 8080)    │ ← HTTP Portal
│  (port 50051)   │ ← gRPC Agent Connection
└────────┬────────┘
         │
         │ mTLS/gRPC
         │
    ┌────┴─────┬──────────┬──────────┐
    │          │          │          │
┌───▼────┐ ┌──▼─────┐ ┌──▼─────┐ ┌──▼─────┐
│ Agent  │ │ Agent  │ │ Agent  │ │ Agent  │
│ Linux  │ │ Linux  │ │Windows │ │Windows │
│   #1   │ │   #2   │ │   #1   │ │   #2   │
└────────┘ └────────┘ └────────┘ └────────┘
```

## Support

For issues or questions:
- Check server logs: `journalctl -u percepta-server -f`
- Check agent logs (see Troubleshooting section)
- Review GitHub issues
- Contact your SIEM administrator
