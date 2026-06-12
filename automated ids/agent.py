import requests
import time
import os
import re
import socket
import platform

# --- CONFIGURATION ---
SERVER_URL = "http://localhost:5000" # Change to HoneyHiest Server IP
API_ENDPOINT = f"{SERVER_URL}/api/agent/report"
HOSTNAME = socket.gethostname()
LOG_PATH = "/var/log/auth.log" # Default for most Linux systems

# --- PATTERNS ---
SSH_FAIL_PATTERN = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port")

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

LOCAL_IP = get_local_ip()

def report_threat(threat_type, source_ip, details):
    payload = {
        "source_ip": source_ip,
        "type": threat_type,
        "details": f"[{HOSTNAME}] {details}",
        "agent": HOSTNAME,
        "agent_ip": LOCAL_IP,
        "os": platform.system()
    }
    try:
        requests.post(API_ENDPOINT, json=payload, timeout=5)
        print(f"🚀 Reported: {threat_type} from {source_ip}")
    except Exception as e:
        print(f"❌ Failed to report: {e}")

def monitor_auth():
    if not os.path.exists(LOG_PATH):
        print(f"❌ Error: {LOG_PATH} not found.")
        return

    print(f"🛰️ HoneyHiest Remote Agent Online.")
    print(f"Monitoring: {LOG_PATH} on {HOSTNAME} ({LOCAL_IP})")
    
    with open(LOG_PATH, "r") as f:
        f.seek(0, 2) # Go to end
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            
            match = SSH_FAIL_PATTERN.search(line)
            if match:
                user = match.group(1)
                ip = match.group(2)
                report_threat("ssh_brute_force", ip, f"Failed login attempt for user '{user}'")

if __name__ == "__main__":
    monitor_auth()
