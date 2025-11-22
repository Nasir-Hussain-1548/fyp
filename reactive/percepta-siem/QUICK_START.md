# Quick Start - Percepta SIEM

## ✅ What's Ready for Windows Demonstration

✅ **Windows GUI Agent**: Complete single-exe agent with:
  - Real Windows Event Log collection (Security, System, Application)
  - System tray icon with status
  - Enrollment UI
  - Windows Service support with auto-restart on boot
  - Built-in mTLS client for secure server communication

✅ **Server Portal**: Running at `http://YOUR_IP:8080/portal`
  - Automatic Windows agent download (ZIP with installer)
  - Embedded one-time enrollment tokens
  - CA certificate included for trust-on-first-use

✅ **gRPC Server**: Running at `YOUR_IP:50051`
  - Mutual TLS authentication
  - Bidirectional event streaming
  - Per-event acknowledgment

✅ **Web Dashboard**: `http://YOUR_IP:8080/dashboard`
  - Live WebSocket event stream
  - Alert monitoring
  - Event search and statistics

## Windows Agent Deployment (3 Steps)

### Step 1: Start the Percepta Server

On your Linux server:

```bash
cd /home/rajputana/percepta-siem
cargo run --release -p percepta-server
```

The server will start and show:
```
🚀 gRPC server running at https://0.0.0.0:50051
🌐 Web server running at http://0.0.0.0:8080
📢 mDNS service registered: instance='percepta-siem-server'
```

**Server is now ready at:**
- Portal: `http://YOUR_SERVER_IP:8080/portal`
- Dashboard: `http://YOUR_SERVER_IP:8080/dashboard`
- gRPC (for agents): `YOUR_SERVER_IP:50051`

### Step 2: Download Windows Agent

On your **Windows machine**:

1. Open browser: `http://YOUR_SERVER_IP:8080/portal`
2. Click **"Download for Windows"** (blue button)
3. Save `percepta-agent-windows.zip`
4. Extract the ZIP to a folder (e.g., `C:\Temp\percepta-agent\`)

**The ZIP contains:**
- `percepta-agent-windows.exe` - Complete GUI agent
- `install.ps1` - Automated PowerShell installer
- `ca_cert.pem` - Server CA certificate
- `otk.txt` - One-time enrollment token
- `server-config.txt` - Connection details

### Step 3: Install on Windows

**Right-click PowerShell** → **Run as Administrator**, then:

```powershell
cd C:\Temp\percepta-agent
.\install.ps1
```

The installer will:
1. ✅ Copy CA certificate to `C:\ProgramData\percepta_agent\certs\`
2. ✅ Enroll agent with server using OTK
3. ✅ Install as Windows Service (PerceptaAgent)
4. ✅ Configure auto-start on boot
5. ✅ Start collecting and sending Windows Event Logs

**After installation:**
- 🟢 Agent runs in background as Windows Service
- 🟢 System tray icon shows connection status
- 🟢 Collects Security, System, and Application event logs
- 🟢 Auto-starts on Windows reboot

### Verify Agent is Running

```bash
# Check service status
sudo systemctl status percepta-agent

# View live logs
sudo journalctl -u percepta-agent -f

# Check connection
sudo journalctl -u percepta-agent | grep "Successfully connected"
```

## What the Agent Does

1. **Auto-discovers** server (or uses `PERCEPTA_SERVER` env var)
2. **Enrolls** automatically using embedded one-time key
3. **Collects** system events (Windows Event Log on Windows, simulated on Linux)
4. **Forwards** events to server via encrypted gRPC stream
5. **Buffers** events locally if server is unreachable
6. **Retries** failed events with exponential backoff

## Environment Variables (Optional)

The installer sets these automatically, but you can override:

```bash
export PERCEPTA_SERVER="192.168.1.100:50051"
export PERCEPTA_CERT_DIR="/etc/percepta-agent/certs"
export PERCEPTA_OUT="/var/lib/percepta-agent/outgoing"
export PERCEPTA_LOG_LEVEL="debug"  # For troubleshooting
```

## Common Commands

```bash
# View agent status
sudo systemctl status percepta-agent

# Restart agent
sudo systemctl restart percepta-agent

# Stop agent
sudo systemctl stop percepta-agent

# View logs (last 100 lines)
sudo journalctl -u percepta-agent -n 100

# Follow logs in real-time
sudo journalctl -u percepta-agent -f

# View only errors
sudo journalctl -u percepta-agent -p err

# Check disk usage of buffered events
du -sh /var/lib/percepta-agent/outgoing/
```

## Testing on Same Machine

If you want to test the agent on the same machine as the server:

```bash
# In terminal 1: Start server
cargo run --release -p percepta-server

# In terminal 2: Download from localhost
curl http://localhost:8080/api/download/agent/linux -o agent.zip
unzip agent.zip
cd percepta-agent-linux/
sudo bash install.sh

# View logs to confirm connection
sudo journalctl -u percepta-agent -f
```

## Troubleshooting

### Agent won't connect?

```bash
# Check if server is reachable
telnet YOUR_SERVER_IP 50051
# or
nc -zv YOUR_SERVER_IP 50051

# Check agent logs for errors
sudo journalctl -u percepta-agent -p err
```

### Need to re-enroll?

```bash
# Stop agent
sudo systemctl stop percepta-agent

# Remove old certs
sudo rm /etc/percepta-agent/certs/*.pem

# Get new OTK from server admin, then:
sudo /opt/percepta-agent/percepta-agent --enroll NEW_OTK --server YOUR_SERVER:50051

# Start agent
sudo systemctl start percepta-agent
```

### Change server address?

```bash
# Edit service file
sudo nano /etc/systemd/system/percepta-agent.service
# Update: Environment="PERCEPTA_SERVER=new-server:50051"

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart percepta-agent
```

## What's Next?

- 📊 View events in server dashboard: `http://YOUR_SERVER:8080/dashboard.html`
- 🔍 Query events via API: `http://YOUR_SERVER:8080/api/events/search`
- 🚨 Configure alerts in `server/rules.yaml`
- 📈 Monitor agent health from server logs

## Full Documentation

See `AGENT_DEPLOYMENT.md` for:
- Windows deployment
- Manual installation
- Security considerations
- Production checklist
- Architecture overview
