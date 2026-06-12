import time
import re
import yaml
import subprocess
import os
import platform
import requests
import threading
import socket
import shutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from database.connection import get_db_connection
from decoys import run_decoys

# Configuration
AUTH_LOG = '/var/log/auth.log'
WEB_LOG = '/var/log/nginx/access.log' # Can be changed to apache2/access.log
PLAYBOOKS_DIR = 'playbooks/'
MAX_RETRIES = 3

# Regex Patterns
SSH_FAIL_PATTERN = re.compile(r"Failed password for (?:invalid user )?.*? from (\d+\.\d+\.\d+\.\d+)")
# Standard Apache/Nginx Log Pattern
WEB_LOG_PATTERN = re.compile(r'^(\d+\.\d+\.\d+\.\d+) .*? "(?:GET|POST|HEAD) (.*?) HTTP/.*?"')

# Decoy Ports for Port Scan Detection
DECOY_PORTS = [21, 23, 445, 1433, 3306, 3389, 5900, 8080, 8443]
PORT_SCAN_THRESHOLD = 3 # Number of unique ports to hit before ban
PORT_SCAN_WINDOW = 60   # Seconds to track history for an IP

# Critical Files for FIM (File Integrity Monitoring)
CRITICAL_FILES = [
    '/etc/passwd',
    '/etc/shadow',
    '/etc/hosts',
    os.path.abspath('app.py'),
    os.path.abspath('monitor.py'),
    os.path.abspath('honey_tokens/passwords.txt'),
    os.path.abspath('honey_tokens/api_keys.conf'),
    os.path.abspath('honey_tokens/config.backup'),
    os.path.abspath('honey_tokens/salary_2026_confidential.xlsx'),
    os.path.abspath('honey_tokens/network_topology_private.pdf')
]

# Malicious Web Patterns
WEB_THREAT_PATTERNS = [
    (re.compile(r"(?:\.\.\/|\/etc\/passwd|\/etc\/shadow|\.env|\.git|\.ssh|config\.php|wp-config)"), "directory_traversal"),
    (re.compile(r"(?:<script|alert\(|onerror=|onload=|confirm\(|prompt\()"), "xss_attack"),
    (re.compile(r"(?:'|\"|union\s+select|select\s+.*?\s+from|insert\s+into|update\s+.*?set|drop\s+table|--|1=1)"), "sql_injection"),
    (re.compile(r"(?:;|\||&|\$|`)\s*(?:ls|cat|whoami|pwd|id|ifconfig|ip|ping|nc|bash|sh|curl|wget|python|perl|ruby|php)"), "command_injection"),
    (re.compile(r"(?:\/admin|\/setup|\/config|\/install|\/phpmyadmin|\/console)"), "privilege_escalation_attempt")
]

import hashlib

def get_config():
    """Retrieve global settings from MongoDB."""
    db = get_db_connection()
    return db.config.find_one({"type": "general"}, {'_id': 0}) or {}

def get_file_hash(filepath):
    """Generate SHA256 hash for a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except: return None

def check_virustotal(file_hash):
    """Check file hash on VirusTotal."""
    if not file_hash: return None
    config = get_config()
    key = config.get('vt_key')
    if not key: return None
    
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {'x-apikey': key}
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data['data']['attributes'].get('last_analysis_stats', {}).get('malicious', 0)
    except: pass
    return None

def check_abuse_ipdb(ip):
    """Check IP reputation on AbuseIPDB."""
    config = get_config()
    key = config.get('abuseipdb_key')
    if not key: return 0
    
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': key}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            return response.json()['data'].get('abuseConfidenceScore', 0)
    except: pass
    return 0

def dispatch_alert(message, raw_data=None):
    """Dispatch alert to Slack or Discord webhook."""
    config = get_config()
    webhook = config.get('slack_webhook') # We use the same field for both
    if not webhook: return
    
    try:
        # Discord Support
        if "discord.com" in webhook:
            payload = {
                "username": "HoneyHiest SOAR",
                "avatar_url": "https://cdn-icons-png.flaticon.com/512/2092/2092663.png",
                "embeds": [{
                    "title": "🛡️ Security Threat Neutralized",
                    "description": message.replace('*', '**'), # Discord uses double asterisks for bold
                    "color": 15548997, # Crimson Red
                    "footer": {"text": "HoneyHiest Deceptive Defense System"}
                }]
            }
            requests.post(webhook, json=payload, timeout=5)
        # Slack Support
        else:
            requests.post(webhook, json={"text": f"🛡️ *HoneyHiest Alert*:\n{message}"}, timeout=5)
    except Exception as e:
        print(f"Alert Dispatch Error: {e}")

def get_geoip_data(ip):
    """Fetch GeoIP data and calculate a simple threat score."""
    try:
        # Private IP check
        private_patterns = ('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                           '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', 
                           '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '127.')
        if ip.startswith(private_patterns):
            return {
                "country": "Internal Network",
                "countryCode": "LOCAL",
                "city": "Private IP",
                "lat": 0,
                "lon": 0,
                "threat_score": 10
            }
            
        # Call Free GeoIP API
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,lat,lon,proxy,hosting", timeout=5)
        data = response.json()
        
        if data.get('status') == 'success':
            # Local heuristics
            score = 15
            if data.get('proxy'): score += 40
            if data.get('hosting'): score += 20
            
            # 🌍 External Intelligence: AbuseIPDB
            abuse_score = check_abuse_ipdb(ip)
            if abuse_score > 0:
                print(f"[INTEL] AbuseIPDB confidence score for {ip}: {abuse_score}%")
                score = max(score, abuse_score) # Use higher of local/global

            return {
                "country": data.get('country'),
                "countryCode": data.get('countryCode'),
                "city": data.get('city'),
                "lat": data.get('lat'),
                "lon": data.get('lon'),
                "threat_score": min(score, 100)
            }
    except Exception as e:
        print(f"GeoIP Error for {ip}: {e}")
    
    return {
        "country": "Unknown", "countryCode": "UN", "city": "Unknown", "lat": 0, "lon": 0, "threat_score": 0
    }


# State tracking
failed_attempts = {}
port_scan_history = {} # {ip: {ports: set(), first_seen: timestamp}}
request_history = {}   # {ip: [timestamps]}

# Thresholds for DoS/Brute Force
DOS_THRESHOLD = 50     # requests
DOS_WINDOW = 60        # seconds

def load_playbooks():
    playbooks = []
    if not os.path.exists(PLAYBOOKS_DIR):
        print(f"Playbooks directory {PLAYBOOKS_DIR} not found.")
        return playbooks
        
    for filename in os.listdir(PLAYBOOKS_DIR):
        if filename.endswith('.yaml') or filename.endswith('.yml'):
            with open(os.path.join(PLAYBOOKS_DIR, filename), 'r') as f:
                playbooks.append(yaml.safe_load(f))
    return playbooks

def execute_action(action, context):
    """Execute a single action from a playbook."""
    if action['type'] == 'command':
        cmd_str = action['cmd'].format(**context)
        is_root = os.getuid() == 0
        parts = cmd_str.split()
        
        # Handle sudo and path mapping
        effective_cmd_idx = 0
        if parts[0] == 'sudo':
            if is_root:
                parts = parts[1:]
            elif not shutil.which('sudo'):
                parts = parts[1:]
            else:
                effective_cmd_idx = 1 # Skip 'sudo'

        # Ensure iptables path for the command parts
        if len(parts) > effective_cmd_idx and parts[effective_cmd_idx] == 'iptables':
            bin_path = shutil.which('iptables') or '/usr/sbin/iptables'
            if os.path.exists(bin_path):
                parts[effective_cmd_idx] = bin_path

        print(f"EXECUTION: {' '.join(parts)}")
        
        if platform.system() == 'Linux':
            try:
                # Capture stderr for debug but ignore if successful
                result = subprocess.run(parts, capture_output=True, text=True)
                if result.returncode == 0:
                    # Mark successful iptables for easy detection in handle_threat
                    prefix = "Executed: "
                    if "iptables" in ' '.join(parts):
                        prefix = "Blocked-Iptables: "
                    return f"{prefix}{' '.join(parts)}"
                else:
                    return f"Failed: {result.stderr.strip()}"
            except Exception as e:
                return f"Error: {e}"
        else:
            return f"Simulated: {' '.join(parts)}"
    return "Unknown action type"

# Ban Durations in seconds
BAN_TIMES = {
    "ssh_brute_force": 1800,        # 30 mins
    "port_scan": 3600,              # 1 hour
    "web_attack": 7200,             # 2 hours
    "command_injection": 14400,     # 4 hours
    "privilege_escalation_attempt": 14400, # 4 hours
    "denial_of_service": 86400,     # 24 hours
    "credential_harvesting": 14400, # 4 hours
    "mysql_exploit_attempt": 86400, # 24 hours
    "rdp_exploit_attempt": 86400,   # 24 hours
    "file_integrity_violation": 86400 # 24 hours
}
DEFAULT_BAN_TIME = 1800

def handle_threat(ip, threat_type, details=None):
    source = ip if ip else "Local System"
    db = get_db_connection()
    
    # 0. Check Whitelist
    if ip:
        is_whitelisted = db.whitelist.find_one({"ip": ip})
        if is_whitelisted:
            print(f"WHITELIST: Ignoring threat '{threat_type}' from whitelisted IP {ip}")
            return

    print(f"THREAT DETECTED: {threat_type} from {source}")
    
    # 1. Fetch GeoIP Intelligence
    geo_data = get_geoip_data(ip) if ip and not ip.startswith('127.') else {
        "country": "Local System", "countryCode": "LOCAL", "city": "Internal", "threat_score": 0
    }
    
    # 2. Load matching playbooks
    playbooks = load_playbooks()
    actions_taken = []
    
    # Only run firewall playbooks if we have a real remote IP
    is_blocked = False
    if ip and not ip.startswith(('127.', 'Local')):
        context = {'source_ip': ip, 'threat_type': threat_type}
        for playbook in playbooks:
            if playbook.get('trigger') == 'threat_detected' or playbook.get('trigger') == threat_type:
                for action in playbook['actions']:
                    result = execute_action(action, context)
                    actions_taken.append(result)
                    if "Blocked-Iptables" in result:
                        is_blocked = True

    # 3. Attacker Persona Logic (Behavioral Profiling)
    persona = "Unknown Voyager"
    if ip:
        prev_incidents = list(db.incidents.find({"source_ip": ip}))
        incident_count = len(prev_incidents)
        unique_types = len(set([i['type'] for i in prev_incidents]))
        
        if threat_type == "port_scan":
            persona = "Aggressive Scanner"
        elif threat_type == "credential_harvesting":
            persona = "Phishing Hunter"
        elif incident_count > 10:
            persona = "Persistent Adversary"
        elif unique_types >= 3:
            persona = "Full-Spectrum Attacker"
        elif threat_type == "ssh_brute_force" and incident_count > 2:
            persona = "Brute Force Bot"
        elif any(token in (details or "") for token in ["honey_tokens", "passwords.txt"]):
            persona = "Data Thief / Canary Tripped"
        elif "file_integrity" in threat_type:
            persona = "Internal Threat / Rootkit"
        else:
            persona = "Script Kiddie / Probe"

    # 4. Dynamic Banning Logic
    ban_duration = BAN_TIMES.get(threat_type, DEFAULT_BAN_TIME)
    expiry_time = time.time() + ban_duration if is_blocked else None
    
    # 5. Log incident
    incident = {
        "timestamp": time.time(),
        "source_ip": source,
        "type": threat_type,
        "details": details,
        "persona": persona,
        "actions_taken": actions_taken,
        "status": "Resolved" if actions_taken else "Detected",
        "geo": geo_data,
        "expiry_time": expiry_time,
        "is_active_block": is_blocked
    }
    db.incidents.insert_one(incident)
    print(f"Incident logged: {threat_type} from {source} (Persona: {persona}, Jail duration: {ban_duration/60} mins)")
    
    # 🔊 Dispatch Real-time Alert
    alert_msg = f"*Threat Level:* Critical\n*Type:* {threat_type}\n*Persona:* {persona}\n*Source:* {source} ({geo_data.get('country', 'Unknown')})\n*Action:* {'Blocked' if is_blocked else 'Logged'}"
    dispatch_alert(alert_msg)

def follow(file):
    """Generator that yields new lines from a file."""
    file.seek(0, 2)  # Go to end
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

def monitor_auth_logs():
    log_path = AUTH_LOG
    if not os.path.exists(log_path):
        print(f"WARNING: {log_path} not found. Creating a dummy file.")
        if not os.path.exists(os.path.dirname(log_path)) and os.path.dirname(log_path):
             log_path = 'dummy_auth.log'
        else:
            with open(log_path, 'a') as f: pass
            
    print(f"Monitoring SSH: {log_path}")
    try:
        with open(log_path, 'r') as logfile:
            for line in follow(logfile):
                match = SSH_FAIL_PATTERN.search(line)
                if match:
                    ip = match.group(1)
                    count = failed_attempts.get(ip, 0) + 1
                    failed_attempts[ip] = count
                    print(f"[SSH] Failed attempt {count}/3 from {ip}")
                    if count >= MAX_RETRIES:
                        handle_threat(ip, "ssh_brute_force")
                        del failed_attempts[ip]
    except Exception as e:
        print(f"Auth Monitor Error: {e}")

def monitor_web_logs(log_path):
    """Monitor a single web log file for security threats."""
    # If standard path doesn't exist, check alternative or use dummy
    if not os.path.exists(log_path):
        if log_path == WEB_LOG:
            alt_path = '/var/log/apache2/access.log'
            if os.path.exists(alt_path):
                log_path = alt_path
            else:
                log_path = 'dummy_access.log'
                if not os.path.exists(log_path):
                    with open(log_path, 'w') as f: f.write("Web monitor started\n")
        else:
            # For other specific logs, just wait for them to be created
            print(f"Waiting for log file: {log_path}...")
            while not os.path.exists(log_path):
                time.sleep(5)

    print(f"Monitoring Web: {log_path}")
    try:
        with open(log_path, 'r') as logfile:
            for line in follow(logfile):
                match = WEB_LOG_PATTERN.search(line)
                if match:
                    ip = match.group(1)
                    request_path = match.group(2).lower()
                    
                    # --- NEW: DOS / High Frequency Detection ---
                    now = time.time()
                    if ip not in request_history:
                        request_history[ip] = []
                    request_history[ip].append(now)
                    # Cleanup old entries
                    request_history[ip] = [t for t in request_history[ip] if now - t < DOS_WINDOW]
                    
                    if len(request_history[ip]) > DOS_THRESHOLD:
                        print(f"[DOS] High traffic detected from {ip}: {len(request_history[ip])} req/min")
                        handle_threat(ip, "denial_of_service", details=f"Frequency: {len(request_history[ip])} requests in {DOS_WINDOW}s")
                        request_history[ip] = [] # Reset after trigger
                    # ------------------------------------------

                    for pattern, threat_type in WEB_THREAT_PATTERNS:
                        if pattern.search(request_path):
                            print(f"[WAF] Malicious request from {ip} on {log_path}: {request_path}")
                            handle_threat(ip, threat_type, details=f"Log: {os.path.basename(log_path)} | Request: {request_path}")
                            break
    except Exception as e:
        print(f"Web Monitor Error for {log_path}: {e}")

def monitor_honeypot_ports():
    """Create decoy sockets to detect port scanning with threshold logic."""
    sockets = []
    active_ports = []
    
    print(f"Initializing Honeypot on decoy ports...")
    for port in DECOY_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', port))
            s.listen(10)
            s.settimeout(0.5)
            sockets.append(s)
            active_ports.append(port)
        except:
            continue # Port likely in use, skip silently

    if not sockets:
        print("CRITICAL: All decoy ports are in use. Port Scan Detection OFFLINE.")
        return

    print(f"Port Scan Detection ONLINE (Monitoring: {active_ports})")
    
    try:
        while True:
            for s in sockets:
                try:
                    conn, addr = s.accept()
                    ip = addr[0]
                    port = s.getsockname()[1]
                    conn.close()

                    now = time.time()
                    if ip not in port_scan_history or now - port_scan_history[ip]['first_seen'] > PORT_SCAN_WINDOW:
                        port_scan_history[ip] = {'ports': {port}, 'first_seen': now}
                    else:
                        port_scan_history[ip]['ports'].add(port)

                    count = len(port_scan_history[ip]['ports'])
                    print(f"[SCAN] Connection attempt from {ip} on decoy port {port} ({count}/{PORT_SCAN_THRESHOLD})")

                    if count >= PORT_SCAN_THRESHOLD:
                        handle_threat(ip, "port_scan", details=f"Hit decoy ports: {list(port_scan_history[ip]['ports'])}")
                        del port_scan_history[ip]
                except socket.timeout:
                    continue
                except:
                    pass
            time.sleep(0.1)
    except Exception as e:
        print(f"Honeypot Loop Error: {e}")
    finally:
        for s in sockets: s.close()

class FIMHandler(FileSystemEventHandler):
    """Handle file modification events for FIM."""
    def __init__(self):
        self.last_triggered = {}

    def on_modified(self, event):
        if event.is_directory: return
        
        file_path = os.path.abspath(event.src_path)
        if file_path in CRITICAL_FILES:
            # Prevent double-triggering (some editors save twice)
            now = time.time()
            if now - self.last_triggered.get(file_path, 0) < 2:
                return
            self.last_triggered[file_path] = now
            
            print(f"[FIM] CRITICAL FILE MODIFIED: {file_path}")
            
            vt_result = ""
            file_hash = get_file_hash(file_path)
            if file_hash:
                malicious_count = check_virustotal(file_hash)
                if malicious_count is not None:
                    vt_result = f" | VirusTotal: {malicious_count} hits"
                    if malicious_count > 0:
                        print(f"[INTEL] MALICIOUS FILE DETECTED: {file_path} ({malicious_count} hits)")
            
            handle_threat(None, "file_integrity_violation", details=f"Modified: {file_path}{vt_result}")

def monitor_fim():
    """Monitor critical files for changes."""
    print(f"Starting FIM on {len(CRITICAL_FILES)} files...")
    event_handler = FIMHandler()
    observer = Observer()
    
    # Watchdog monitors directories, so we watch the parent of each critical file
    watched_dirs = set(os.path.dirname(f) for f in CRITICAL_FILES if os.path.exists(f))
    
    for d in watched_dirs:
        if d: # Avoid empty dir strings
            observer.schedule(event_handler, d, recursive=False)
    
    observer.start()
    try:
        while True:
            time.sleep(1)
    except Exception as e:
        print(f"FIM Monitor Error: {e}")
    finally:
        observer.stop()
        observer.join()

def monitor_external_incidents():
    """Watch the DB for incidents inserted by other modules (like the web portal)."""
    db = get_db_connection()
    last_processed_ts = time.time()
    
    while True:
        try:
            # Find new incidents that were detected but not yet 'Resolved' (banned/acted upon)
            new_incidents = list(db.incidents.find({
                "timestamp": {"$gt": last_processed_ts},
                "status": "Detected",
                "is_active_block": False
            }))
            
            for incident in new_incidents:
                ip = incident.get('source_ip')
                threat_type = incident.get('type')
                if ip and threat_type:
                    print(f"[BRIDGE] Processing external threat: {threat_type} from {ip}")
                    # Re-trigger through handle_threat to apply banning logic & persona
                    handle_threat(ip, threat_type, details=incident.get('details'))
                    # Update the original record so we don't double-process
                    db.incidents.update_one({"_id": incident["_id"]}, {"$set": {"status": "SOAR_Processed"}})
                
                last_processed_ts = max(last_processed_ts, incident['timestamp'])
        except Exception as e:
            print(f"Incident Bridge Error: {e}")
        time.sleep(5)

def run_monitor():
    # Log files to monitor (e.g., system logs and our new vulnerable site)
    web_logs = [WEB_LOG, '/home/pop3/p/honeyhiest/vulnerable_access.log']
    
    threads = [
        threading.Thread(target=monitor_auth_logs, daemon=True),
        threading.Thread(target=monitor_honeypot_ports, daemon=True),
        threading.Thread(target=monitor_fim, daemon=True),
        threading.Thread(target=monitor_external_incidents, daemon=True),
        threading.Thread(target=run_decoys, daemon=True)
    ]
    
    # Add multiple web log monitoring threads
    for log_path in web_logs:
        threads.append(threading.Thread(target=monitor_web_logs, args=(log_path,), daemon=True))
    
    for t in threads:
        t.start()
        
    print("SOAR Detection Engine Online. Monitoring logs...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping monitor...")

if __name__ == "__main__":
    run_monitor()
