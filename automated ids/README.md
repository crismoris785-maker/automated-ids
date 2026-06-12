# 🛡️ HoneyHiest: Advanced SOAR & Deceptive Defense System

HoneyHiest is a high-interaction, autonomous security orchestration and response platform. It combines a **Deceptive Defense (Honeypots)** layer with a **Real-time SOAR (Security Orchestration, Automation, and Response)** engine to detect, identify, and neutralize threats instantly.

---

## 🌟 Core Features

### 1. Deceptive Defense (Honeypots)
*   **Protocol Decoys**: High-interaction simulations for **MySQL (3306), RDP (3389), PostgreSQL (5432), and VNC (5900)**.
*   **Hacker Console**: A high-interaction SSH intercept on port **2222** that logs and broadcasts attacker commands LIVE to the dashboard.
*   **Phishing Portal**: A "Enterprise Login" bait page designed to capture and alert on credential harvesting attempts.
*   **Honey-Tokens**: Sensitive bait files (e.g., `passwords.txt`) monitored by a File Integrity Monitor (FIM).

### 2. Live Intelligence & SOAR
*   **Autonomous Banning**: Real-time `iptables` integration with temporal banning (30m, 1h, 24h).
*   **Global Threat Map**: Animated attack arcs showing the path from the source IP to your server.
*   **Threat Intelligence**: Automatic reputation checks via **AbuseIPDB** and malware scanning via **VirusTotal**.
*   **Attacker Persona**: Behavioral profiling (e.g., "Aggressive Scanner", "Phishing Hunter", "Data Thief").

### 3. Management & Governance
*   **Tactical Login**: Secure JWT-authenticated dashboard.
*   **System Audit Logs**: Mandatory justifications for unblocking and full tracking of administrative actions.
*   **Remote Monitoring**: Deployment-ready `agent.py` to monitor remote servers.

---

## 🚀 Installation & Setup

### Prerequisites
*   Linux (Ubuntu/Debian recommended)
*   Python 3.10+
*   MongoDB
*   Root/Sudo privileges (for `iptables` management)

### 1. Clone & Prepare
```bash
git clone https://github.com/your-repo/honeyhiest.git
cd honeyhiest
python3 -m venv venv
source venv/bin/python3
pip install -r requirements.txt
```

### 2. Database Setup
Ensure MongoDB is running locally. The system will automatically create the `incident_response_db` on first run.

### 3. Start the Engines
You need two terminals running:

**Terminal 1: The Web Dashboard & API**
```bash
sudo ./venv/bin/python3 app.py
```
*Accessible at: `http://your-server-ip:5000`*

**Terminal 2: The SOAR Monitoring Engine**
```bash
sudo python3 monitor.py
```

---

## 🎮 How to Use

### 1. Logging In
*   **URL**: `http://localhost:5000/login`
*   **Default Username**: `admin`
*   **Default Password**: `admin`

### 2. Configuring Integrations
Go to the **SETTINGS** page to add your API keys:
*   **AbuseIPDB**: For global reputation scores.
*   **VirusTotal**: For scanning modified files.
*   **Slack/Discord Webhooks**: For instant mobile alerts.

### 3. Handling Incidents
*   **Jail Control**: View blocked IPs on the main dashboard.
*   **Unblocking**: Click **UNBLOCK** and provide a reason (e.g., "Confirmed false positive").
*   **Whitelisting**: Add trusted IPs/Subnets in Settings to prevent accidental bans.

### 4. Remote Agents
To monitor another server:
1. Copy `agent.py` to the remote machine.
2. Edit `SERVER_URL` in the script to point to your main HoneyHiest server.
3. Run with `sudo python3 agent.py`.

---

## 🧪 Testing the System
Refer to the [**TEST_GUIDE.md**](./TEST_GUIDE.md) for specific Kali Linux commands to verify:
*   Nmap Decoy Hits
*   SSH Intercepts
*   WAF/Web Attacks
*   FIM Violations

---

## 📂 Project Structure
*   `app.py`: Flask Web Server & JWT Auth.
*   `monitor.py`: The SOAR bridge & log analyzer.
*   `decoys.py`: Protocol decoy implementation (MySQL/RDP).
*   `ssh_honeypot.py`: High-interaction SSH trap.
*   `agent.py`: Remote endpoint monitor.
*   `/templates`: Modern Glassmorphism UI.

---

## 🛡️ License
Proprietary / Research Purposes Only. Unauthorized use of high-interaction honeypots on public clouds may violate ToS. Use responsibly.
