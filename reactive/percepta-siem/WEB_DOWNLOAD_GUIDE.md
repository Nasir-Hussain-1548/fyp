## 🌐 How to Download Agent from Web Interface

### For Your Windows Laptop

#### Step 1: Start the Percepta Server (on Linux machine)

```bash
cd /home/rajputana/percepta-siem
cargo run --release -p percepta-server
```

The server will display startup messages including the listening address.

#### Step 2: Get Your Linux Machine's IP Address

On your Linux machine (where server is running):

```bash
# Find your IP address
hostname -I | awk '{print $1}'
# OR
ip addr show | grep "inet " | grep -v 127.0.0.1
```

Example output: `192.168.1.50`

#### Step 3: Open Portal on Windows Laptop

On your Windows laptop, open a web browser and navigate to:

```
http://YOUR_LINUX_IP:8080/portal
```

Example:
```
http://192.168.1.50:8080/portal
```

You'll see a clean page with two download buttons:
- 🪟 **"Download for Windows"** (blue button)
- 🐧 **"Download for Linux"** (green button)

#### Step 4: Download the Agent

1. Click **"Download for Windows"** button
2. Your browser will download: `percepta-agent-windows.zip` (or `percepta-agent-linux.zip` for Linux)
3. The ZIP includes everything needed:
   - ✅ `percepta-agent.exe` (or `percepta-agent` binary)
   - ✅ `install.ps1` (or `install.sh`) - auto-enrollment script
   - ✅ `ca_cert.pem` - server certificate
   - ✅ `server-config.txt` - connection info

#### Step 5: Install on Windows Laptop

1. **Extract the ZIP file**:
   - Right-click `percepta-agent-windows.zip`
   - Select "Extract All..."
   - Extract to a folder (e.g., `C:\Temp\percepta-agent-windows\`)

2. **Run the installer as Administrator**:
   - Open the extracted folder
   - Right-click `install.ps1`
   - Select "Run with PowerShell"
   - Click "Yes" when asked to run as Administrator

3. **The installer will**:
   - ✅ Copy agent to `C:\Program Files\Percepta\`
   - ✅ Install certificates to `C:\ProgramData\percepta_agent\certs\`
   - ✅ Enroll with the server automatically (using embedded one-time key)
   - ✅ Install as Windows Service named "PerceptaAgent"
   - ✅ Start the agent service

#### Step 6: Verify Agent is Running

Open PowerShell as Administrator:

```powershell
# Check service status
Get-Service PerceptaAgent

# Should show: Status = Running

# View agent logs (if available)
Get-EventLog -LogName Application -Source PerceptaAgent -Newest 10
```

---

## 🐧 For Linux Systems

Same process, but:

1. Navigate to `http://YOUR_LINUX_IP:8080/portal` in browser
2. Click **"Download for Linux"** (green button)
3. Extract: `unzip percepta-agent-linux.zip`
4. Install: `sudo bash install.sh`
5. Verify: `sudo systemctl status percepta-agent`

---

## 🔍 Troubleshooting

### Can't Access Portal?

**Check if server is running:**
```bash
# On Linux machine where server runs
ss -tlnp | grep 8080
# Should show the server listening on port 8080
```

**Check firewall:**
```bash
# Allow port 8080 on Linux machine
sudo ufw allow 8080/tcp
# or
sudo firewall-cmd --add-port=8080/tcp --permanent
sudo firewall-cmd --reload
```

**Test from Windows laptop:**
```powershell
# PowerShell - test connection
Test-NetConnection -ComputerName YOUR_LINUX_IP -Port 8080
```

### Windows SmartScreen Warning?

When running `install.ps1`, Windows may show a SmartScreen warning because the script is not signed.

**To bypass:**
1. Click "More info"
2. Click "Run anyway"

OR run manually:
```powershell
# Open PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
cd C:\Temp\percepta-agent-windows\
.\install.ps1
```

### Agent Not Connecting?

**Check connectivity from Windows laptop:**
```powershell
# Test gRPC port (50051)
Test-NetConnection -ComputerName YOUR_LINUX_IP -Port 50051
```

**Allow port 50051 on Linux server:**
```bash
sudo ufw allow 50051/tcp
# or
sudo firewall-cmd --add-port=50051/tcp --permanent
sudo firewall-cmd --reload
```

---

## 📋 Quick Reference

### URLs to Access (from Windows laptop)

| Service | URL | Purpose |
|---------|-----|---------|
| **Portal** | `http://YOUR_SERVER_IP:8080/portal` | Download agent |
| **Dashboard** | `http://YOUR_SERVER_IP:8080/dashboard.html` | View events |
| **API** | `http://YOUR_SERVER_IP:8080/api/events` | Query events |

### Ports Used

| Port | Protocol | Purpose |
|------|----------|---------|
| **8080** | HTTP | Web portal & dashboard |
| **50051** | gRPC | Agent communication |

### Required Firewall Rules (Linux Server)

```bash
# Allow web portal
sudo ufw allow 8080/tcp

# Allow agent connections
sudo ufw allow 50051/tcp

# Check status
sudo ufw status
```

---

## 🎯 Example: Complete Setup

### On Linux Server (192.168.1.50):

```bash
# Start server
cd /home/rajputana/percepta-siem
cargo run --release -p percepta-server

# Allow firewall
sudo ufw allow 8080/tcp
sudo ufw allow 50051/tcp
```

### On Windows Laptop:

1. Open browser: `http://192.168.1.50:8080/portal`
2. Click "Download for Windows"
3. Extract ZIP file
4. Right-click `install.ps1` → Run with PowerShell (as Admin)
5. Wait for "Agent service installed successfully!"
6. Verify: `Get-Service PerceptaAgent` shows "Running"

### View Events on Server:

Browser: `http://192.168.1.50:8080/dashboard.html`

---

## ✅ What's Happening Behind the Scenes

1. **Portal generates One-Time Key (OTK)** - unique for each download
2. **OTK embedded in install script** - no manual copy/paste needed
3. **Agent enrolls automatically** - exchanges OTK for client certificate
4. **mTLS established** - secure encrypted channel between agent and server
5. **Events stream continuously** - agent forwards system events in real-time

The whole process is automated - no manual configuration needed! 🚀
