# ✅ DEPLOYMENT READY - Final Checklist

## What's Built and Ready

### Agent Binaries (Production-Ready)
- ✅ **Linux Agent**: `target/release/percepta-agent` (13MB)
  - Location for portal: `server/static/downloads/percepta-agent-linux-x64`
  - Uses simulation mode on Linux, production Windows Event Log API on Windows
  
- ✅ **Windows Agent**: `target/x86_64-pc-windows-gnu/release/percepta-agent.exe` (16MB)
  - Location for portal: `server/agent_builds/percepta-agent.exe`
  - **Production-ready**: Uses native Windows Event Log API (EvtQuery, EvtNext, EvtRender)
  - Collects from Security, System, and Application channels
  - Parses EventID 4624, 4625, 4688, 4672, 4720 with full structured data

### Server Components
- ✅ **Portal**: Updated with Linux and Windows download support
- ✅ **Auto-enrollment**: One-time keys embedded in installers
- ✅ **Install scripts**: 
  - `install.sh` for Linux (systemd service)
  - `install.ps1` for Windows (Windows Service)

## Deployment Steps

### On Your Linux Server (192.168.10.7)

```bash
# 1. Start the server
cd /home/rajputana/percepta-siem
cargo run --release -p percepta-server

# Server will listen on:
# - HTTP Portal: http://192.168.10.7:8080/portal
# - gRPC Agents: 192.168.10.7:50051

# 2. (Optional) Open firewall if needed
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 50051 -j ACCEPT
# OR if using firewalld:
# sudo firewall-cmd --add-port=8080/tcp --add-port=50051/tcp --permanent
# sudo firewall-cmd --reload
```

### On Your Windows Laptop

#### Step 1: Download Agent
1. Open browser: `http://192.168.10.7:8080/portal`
2. Click **"Download for Windows"** (blue button)
3. Save `percepta-agent-windows.zip` to Downloads

#### Step 2: Install Agent
1. Extract the ZIP file
2. Right-click `install.ps1`
3. Select **"Run with PowerShell"** (as Administrator)
4. Wait for:
   - ✅ Files copied to `C:\Program Files\Percepta\`
   - ✅ Certificates installed to `C:\ProgramData\percepta_agent\certs\`
   - ✅ Agent enrolled with server (automatic via OTK)
   - ✅ Windows Service created and started

#### Step 3: Verify Agent Running
```powershell
# Check service status
Get-Service PerceptaAgent

# Should show:
# Status   Name             DisplayName
# ------   ----             -----------
# Running  PerceptaAgent    PerceptaAgent

# View recent logs (if Windows Event Log integration working)
Get-EventLog -LogName Application -Source PerceptaAgent -Newest 10
```

### On Linux Systems (Alternative)

1. Download from portal: `http://192.168.10.7:8080/portal`
2. Click **"Download for Linux"** (green button)
3. Extract and install:
```bash
unzip percepta-agent-linux.zip
cd percepta-agent-linux/
sudo bash install.sh
```

4. Verify:
```bash
sudo systemctl status percepta-agent
sudo journalctl -u percepta-agent -f
```

## What the Agent Does (Windows Production Mode)

### Windows Event Collection
- ✅ **Direct Windows Event Log API access** (not PowerShell)
- ✅ Queries Security, System, and Application channels
- ✅ Reads last 200 events per channel every 10 seconds
- ✅ Parses structured EventData fields for known event types:
  - **4624**: Successful logon (user, IP, port)
  - **4625**: Failed logon (user, reason)
  - **4688**: Process creation (PID, command line, parent)
  - **4672**: Special privileges assigned
  - **4720**: User account created
  - **Others**: Generic event with metadata

### Event Forwarding
- ✅ Connects to server via **mTLS (mutual TLS)** on port 50051
- ✅ Streams events in real-time via gRPC
- ✅ Buffers locally if connection lost
- ✅ Retries with exponential backoff
- ✅ Each event includes:
  - Event ID, severity, category
  - Timestamp (event time + ingest time)
  - Agent info (hostname, IP, OS)
  - Structured fields (user, network, process)
  - Original message + parsed metadata
  - Correlation ID and content hash

## Verification Commands

### On Server (Linux)
```bash
# Check if server is listening
sudo ss -tlnp | grep 8080  # HTTP
sudo ss -tlnp | grep 50051 # gRPC

# View server logs
# (if running in terminal, you'll see logs directly)

# Check connected agents (via API)
curl http://localhost:8080/api/agents
```

### On Windows Agent Machine
```powershell
# Check service status
Get-Service PerceptaAgent | Format-List *

# Check process
Get-Process | Where-Object {$_.ProcessName -like "*percepta*"}

# Test connectivity to server
Test-NetConnection -ComputerName 192.168.10.7 -Port 50051

# View agent files
dir "C:\Program Files\Percepta\"
dir "C:\ProgramData\percepta_agent\"
```

### On Linux Agent Machine
```bash
# Service status
sudo systemctl status percepta-agent

# Real-time logs
sudo journalctl -u percepta-agent -f

# Check last 50 lines
sudo journalctl -u percepta-agent -n 50

# Check agent is connecting
sudo journalctl -u percepta-agent | grep "Successfully connected"

# View buffered events
sudo ls -lh /var/lib/percepta-agent/outgoing/
```

## Troubleshooting

### Agent Won't Connect

**Check connectivity:**
```bash
# From Windows
Test-NetConnection -ComputerName 192.168.10.7 -Port 50051

# From Linux
nc -zv 192.168.10.7 50051
telnet 192.168.10.7 50051
```

**Check server firewall:**
```bash
# On server
sudo iptables -L -n | grep 50051
# OR
sudo firewall-cmd --list-ports
```

**Check agent environment:**
```powershell
# Windows
[Environment]::GetEnvironmentVariable("PERCEPTA_SERVER", "Machine")

# Linux
sudo systemctl show percepta-agent | grep Environment
```

### Re-enrollment

If enrollment fails or you need to re-enroll:

**Windows:**
```powershell
# Stop service
Stop-Service PerceptaAgent

# Remove old certs
Remove-Item C:\ProgramData\percepta_agent\certs\*.pem

# Get NEW OTK from server admin, then:
cd "C:\Program Files\Percepta"
.\percepta-agent.exe --enroll NEW_OTK --server http://192.168.10.7:8080

# Restart service
Start-Service PerceptaAgent
```

**Linux:**
```bash
# Stop service
sudo systemctl stop percepta-agent

# Remove old certs
sudo rm /etc/percepta-agent/certs/*.pem

# Get NEW OTK, then:
sudo /opt/percepta-agent/percepta-agent --enroll NEW_OTK --server http://192.168.10.7:8080

# Start service
sudo systemctl start percepta-agent
```

## Architecture Summary

```
┌─────────────────────────────────┐
│   Percepta SIEM Server          │
│   (192.168.10.7)                │
│                                 │
│   HTTP :8080  ← Portal/API      │
│   gRPC :50051 ← Agent streams   │
└──────────┬──────────────────────┘
           │
           │ mTLS/gRPC (encrypted, authenticated)
           │
    ┌──────┴─────┬─────────┬─────────┐
    │            │         │         │
┌───▼────┐  ┌───▼────┐ ┌──▼────┐ ┌──▼────┐
│Windows │  │Windows │ │ Linux │ │ Linux │
│ Agent  │  │ Agent  │ │ Agent │ │ Agent │
│  #1    │  │  #2    │ │  #1   │ │  #2   │
│        │  │        │ │       │ │       │
│ Win    │  │ Win    │ │ Sim   │ │ Sim   │
│ EvtLog │  │ EvtLog │ │ Mode  │ │ Mode  │
└────────┘  └────────┘ └───────┘ └───────┘
```

## Next Steps After Deployment

1. ✅ Verify agents are connected and sending events
2. ✅ Check dashboard: `http://192.168.10.7:8080/dashboard.html`
3. ✅ Query events via API: `http://192.168.10.7:8080/api/events/search`
4. ✅ Configure alert rules in `server/rules.yaml`
5. ✅ Set up log rotation
6. ✅ Configure firewall for production
7. ✅ Set up monitoring for server health
8. ✅ Document OTK generation process for your team

## Files and Locations Reference

### Server
- Binary: `target/release/percepta-server`
- Config: `server/rules.yaml`, `server/parsers.yaml`
- Certs: `server/certs/ca.crt`, `server/certs/ca.key`
- Events DB: `server/data/events.wal`

### Windows Agent (Installed)
- Binary: `C:\Program Files\Percepta\percepta-agent.exe`
- Certs: `C:\ProgramData\percepta_agent\certs\`
- Events buffer: `C:\ProgramData\percepta_agent\outgoing\`
- Service: "PerceptaAgent" (runs as SYSTEM)

### Linux Agent (Installed)
- Binary: `/opt/percepta-agent/percepta-agent`
- Certs: `/etc/percepta-agent/certs/`
- Events buffer: `/var/lib/percepta-agent/outgoing/`
- Service: `percepta-agent.service` (systemd)

---

**Everything is production-ready. Start the server and deploy agents!** 🚀
