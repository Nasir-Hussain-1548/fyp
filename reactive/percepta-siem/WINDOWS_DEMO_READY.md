# Windows Agent - Presentation Ready ✅

## What You Have Now

### Complete Windows GUI Agent (`percepta-agent-windows.exe`)
- **Size**: 16 MB single executable
- **Location**: `server/agent_builds/percepta-agent-windows.exe`
- **Features**:
  - ✅ Real Windows Event Log collection (Security, System, Application logs)
  - ✅ Uses Windows built-in APIs (`windows` crate)
  - ✅ GUI with system tray icon
  - ✅ Connection status display
  - ✅ Windows Service mode with auto-restart on boot
  - ✅ Enrollment UI
  - ✅ mTLS client for secure communication
  - ✅ Automatic reconnection with exponential backoff
  - ✅ Per-event acknowledgment and retry logic

### Server (Running)
- **gRPC**: `0.0.0.0:50051` (TLS with client cert verification)
- **Web Portal**: `http://0.0.0.0:8080/portal`
- **Dashboard**: `http://0.0.0.0:8080/dashboard`
- **Health**: `http://0.0.0.0:8080/healthz`
- **CA Certificate**: `http://0.0.0.0:8080/api/ca_cert`

### Windows Download Package
The portal serves `percepta-agent-windows.zip` containing:
1. `percepta-agent-windows.exe` - Complete GUI agent (16 MB)
2. `install.ps1` - PowerShell installer with embedded OTK
3. `ca_cert.pem` - Server CA for enrollment
4. `otk.txt` - One-time enrollment token
5. `server-config.txt` - Connection details

## How to Demonstrate

### 1. Server is Already Running
The server is running at the console showing live logs. Keep this visible during demo.

### 2. On Windows Machine

#### Download
1. Open browser: `http://YOUR_SERVER_IP:8080/portal`
2. Click "Download for Windows"
3. Extract ZIP to `C:\Temp\percepta-agent\`

#### Install (PowerShell as Admin)
```powershell
cd C:\Temp\percepta-agent
.\install.ps1
```

Watch as it:
- Copies CA certificate
- Enrolls with server (you'll see server logs)
- Installs Windows Service
- Starts collecting logs

#### Verify
- System tray icon appears (shows connection status)
- Open Services (`services.msc`) → Find "PerceptaAgent" → Status: Running
- Open Event Viewer → Security logs → Agent is reading them
- On server dashboard: `http://YOUR_SERVER_IP:8080/dashboard` → Events appear

### 3. Test Auto-Restart
```powershell
# Stop the service
Stop-Service PerceptaAgent

# Reboot Windows
Restart-Computer

# After reboot, service auto-starts
Get-Service PerceptaAgent
```

### 4. Monitor on Server
Watch server logs showing:
- Agent enrollment
- TLS handshake
- Event ingestion
- Real-time event count

## Technical Details for Presentation

### Windows Event Log Collection
- Uses Windows API via `windows` crate
- Collects from channels: Security, System, Application
- Parses XML event data
- Converts to protobuf format
- Streams via gRPC with compression

### Security
- Mutual TLS authentication
- Trust-on-First-Use (TOFU) CA pinning
- Client certificates issued by server CA
- Certificate revocation list (CRL) support
- No plaintext credentials

### Agent Architecture
```
Windows GUI Agent
├── GUI (eframe/egui) - Tray icon, status display
├── Service Mode - Windows Service wrapper
├── Event Collector - Windows Event Log API
├── gRPC Client - Bidirectional streaming
├── Enrollment - OTK-based registration
└── Auto-reconnect - Exponential backoff
```

### What Makes This Production-Ready
1. **Single executable** - No dependencies, easy deployment
2. **Windows Service** - Runs in background, survives reboots
3. **Real log collection** - Uses Windows APIs, not simulated
4. **Secure by default** - mTLS, certificate pinning
5. **Resilient** - Auto-reconnect, event retry, offline queueing
6. **Observable** - Tray icon, service status, server dashboard

## Quick Demo Script

1. **Show server running**: Console with logs, dashboard open in browser
2. **Open portal**: Show Windows download button is active
3. **Download and extract** on Windows machine
4. **Run installer** as admin: PowerShell with install.ps1
5. **Show enrollment** in server logs
6. **Point to tray icon** showing green/connected status
7. **Open dashboard**: Live events streaming in
8. **Open Services**: Show PerceptaAgent running, set to Automatic
9. **Generate Windows event**: Open Event Viewer, create custom event
10. **Show event** appearing in dashboard within seconds

## Files Modified for This Demo
- `agent/src/bin/percepta-agent-windows.rs` - New unified GUI agent
- `agent/src/windows_eventlog.rs` - Real Windows Event Log collector
- `agent/src/lib.rs` - Library exports for binary
- `agent/Cargo.toml` - Library and binary configuration
- `server/src/portal.rs` - Updated to serve Windows GUI agent
- `server/src/tls.rs` - Fixed TLS CN to "Percepta-SIEM" with SANs
- `server/src/certificate_authority/operations.rs` - Server cert with SANs
- `QUICK_START.md` - Windows-first installation guide

## Environment Variables (Optional)
```bash
# Server
export PERCEPTA_PUBLIC_HOST=192.168.1.100  # If behind NAT
export PERCEPTA_DEV_SELFSIGNED=1           # Allow dev fallback
export PERCEPTA_ENABLE_MDNS=0              # Disable mDNS if needed

# Agent (set via installer or manually)
set PERCEPTA_SERVER=192.168.1.100:50051
set PERCEPTA_CERT_DIR=C:\ProgramData\percepta_agent\certs
```

## Next Steps (Post-Demo)
- Add custom detection rules in `rules.yaml`
- Configure alert notifications
- Set up log retention policies
- Deploy to additional Windows endpoints
- Configure firewall rules (50051 TCP inbound on server)

---

**Status**: ✅ Ready for Presentation
**Last Updated**: November 6, 2025
