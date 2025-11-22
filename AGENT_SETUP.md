# SIEM Agent Setup Guide

## Overview
The SIEM system includes cross-platform agents for Windows and Linux log collection.

---

## Windows Agent

### Requirements
- **Windows 7/10/11 or Server 2008+**
- **Administrator Privileges** (Required!)
- **Network access to SIEM Server**

### Installation & Setup

#### Step 1: Download the Agent
1. Access the SIEM Dashboard: `http://192.168.100.82:8080`
2. Login with credentials: `admin:admin`
3. Navigate to **Agents** page
4. Click **"Download Windows Agent"**

#### Step 2: Run as Administrator

**Method 1: PowerShell (Recommended)**
```powershell
# 1. Right-click PowerShell
# 2. Select "Run as administrator"
# 3. Navigate to agent directory
cd C:\path\to\agent

# 4. Run the agent
.\siem-agent.exe
```

**Method 2: Command Prompt**
```cmd
# 1. Right-click Command Prompt
# 2. Select "Run as administrator"
# 3. Navigate to agent directory
cd C:\path\to\agent

# 4. Run the agent
siem-agent.exe
```

#### Step 3: Configure (Optional)

Set environment variables to customize the agent:

```powershell
# Set server URL (default: http://127.0.0.1:8080)
$env:SIEM_SERVER_URL = "http://192.168.100.82:8080"

# Set agent name (default: windows-agent-001)
$env:SIEM_AGENT_NAME = "my-windows-pc"

# Then run the agent
.\siem-agent.exe
```

### Troubleshooting

**Error: "Windows agent requires Administrator privileges!"**
- Solution: Run PowerShell or Command Prompt as Administrator
- Right-click the application → "Run as administrator"

**Agent window closes immediately**
- The error message appears and then closes
- Check the error message carefully - it will pause for you to read

**Can't connect to server**
- Verify server is running: `http://192.168.100.82:8080` in browser
- Check firewall allows port 8080
- Verify network connectivity to the SIEM server

---

## Linux Agent

### Requirements
- **Linux (Ubuntu/Debian/CentOS/Fedora)**
- **Root/sudo privileges** (Required!)
- **curl** package installed
- **Network access to SIEM Server**

### Installation & Setup

#### Step 1: Download the Agent
```bash
# Create agent directory
mkdir -p ~/siem-agent
cd ~/siem-agent

# Download from server (replace IP with your server IP)
curl -O http://192.168.100.82:8080/download/agent/linux
chmod +x siem-agent
```

#### Step 2: Run with sudo

```bash
# Run the agent with sudo
sudo ./siem-agent
```

The agent will:
1. Display startup information
2. Register with the SIEM server
3. Start collecting security events
4. Send heartbeats and logs periodically

#### Step 3: Configure (Optional)

Set environment variables before running:

```bash
# Set server URL (default: http://127.0.0.1:8080)
export SIEM_SERVER_URL="http://192.168.100.82:8080"

# Set agent name (default: linux-agent-001)
export SIEM_AGENT_NAME="my-linux-server"

# Then run with sudo
sudo ./siem-agent
```

### Troubleshooting

**Error: "command not found"**
- Check file permissions: `ls -la siem-agent`
- Make executable: `chmod +x siem-agent`
- Verify it's a valid file: `file siem-agent`

**Error: "This agent must be run as root/sudo"**
- Solution: Always prefix with `sudo`
- Correct: `sudo ./siem-agent`
- Incorrect: `./siem-agent`

**curl not found**
- Install curl: `sudo apt-get install curl` (Debian/Ubuntu)
- Or: `sudo yum install curl` (RedHat/CentOS)

**Can't connect to server**
- Verify server IP and port are correct
- Check firewall: `sudo ufw allow 8080` (if using UFW)
- Test connectivity: `curl http://192.168.100.82:8080`

---

## Agent Features

### Windows Agent Features
- Monitors Windows Event Viewer for security events
- Detects failed login attempts
- Tracks user account changes
- Monitors privilege escalation
- Sends events to SIEM server every 3 seconds
- Auto-registers with unique UUID

### Linux Agent Features
- Monitors `/var/log/auth.log` for authentication events
- Detects failed login attempts
- Collects security-related syslog events
- Sends events to SIEM server every 3 seconds
- Auto-registers with unique UUID

---

## Viewing Agent Status

1. Access SIEM Dashboard: `http://192.168.100.82:8080`
2. Navigate to **Agents** page
3. View list of registered agents
4. Check last heartbeat time
5. View logs collected from each agent

---

## Event Types Monitored

### Windows
- Successful/Failed logons (Event IDs 4624, 4625)
- User account modifications (4720-4726)
- Group membership changes (4728-4733)
- Account lockouts (4740)
- Admin logons (4672)

### Linux
- Failed password attempts
- Public key authentication failures
- User login events
- SSH connection attempts

---

## Support

For issues or questions:
1. Check the agent output for error messages
2. Verify server is running and accessible
3. Check network connectivity
4. Review firewall settings
5. Consult the troubleshooting section above
