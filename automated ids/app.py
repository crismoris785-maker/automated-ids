from flask import Flask, render_template, jsonify, request, redirect, url_for, make_response
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, set_access_cookies, unset_jwt_cookies
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_socketio import SocketIO, emit
from database.connection import get_db_connection
from ssh_honeypot import run_ssh_honeypot
import threading
import time
import subprocess
import platform
import psutil
import os
import shutil
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'honey-secret-key-32-characters-long-!!!!'
app.config['JWT_SECRET_KEY'] = 'jwt-honey-secret-a-very-long-string-for-security'
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = False # Simplified for demo
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'

jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*", manage_session=False)

@jwt.unauthorized_loader
def custom_unauthorized_response(_err):
    return redirect(url_for('login_page'))

@jwt.expired_token_loader
def custom_expired_token_response(_header, _payload):
    return redirect(url_for('login_page'))

@jwt.invalid_token_loader
def custom_invalid_token_response(_err):
    return redirect(url_for('login_page'))

@jwt.needs_fresh_token_loader
def custom_fresh_token_response(_header, _payload):
    return redirect(url_for('login_page'))

# Global WAF State
WAF_ENABLED = True

# Mini-WAF Patterns (Synced with monitor.py)
WAF_PATTERNS = [
    (re.compile(r"(?:\.\.\/|\/etc\/passwd|\/etc\/shadow|\.env|\.git|\.ssh|config\.php|wp-config)"), "directory_traversal"),
    (re.compile(r"(?:<script|alert\(|onerror=|onload=|confirm\(|prompt\()"), "xss_attack"),
    (re.compile(r"(?:'|\"|union\s+select|select\s+.*?\s+from|insert\s+into|update\s+.*?set|drop\s+table|--|1=1)"), "sql_injection"),
    (re.compile(r"(?:;|\||&|\$|`)\s*(?:ls|cat|whoami|pwd|id|ifconfig|ip|ping|nc|bash|sh|curl|wget|python|perl|ruby|php)"), "command_injection")
]

from urllib.parse import unquote

@app.before_request
def waf_check():
    """Intercept malicious patterns in the request path or args."""
    global WAF_ENABLED
    if not WAF_ENABLED: return
    
    # Don't check static files or simple root
    if request.path.startswith('/static'): return
    
    path = request.path.lower()
    query = request.query_string.decode().lower()
    
    # 🔥 FIX: Decode URL-encoded characters (like %20, %27) so regex can find them
    decoded_query = unquote(query)
    full_request = f"{path}?{decoded_query}"
    
    ip = request.remote_addr
    
    for pattern, threat_type in WAF_PATTERNS:
        if pattern.search(full_request):
            print(f"[WAF_ACTIVE] Detected {threat_type} from {ip}")
            # Use global db connection
            db.incidents.insert_one({
                "timestamp": time.time(),
                "source_ip": ip,
                "type": threat_type,
                "details": f"WAF Intercept: {full_request}",
                "status": "Detected",
                "is_active_block": False
            })
            # Return a fake error or just let it through to see the response (trap)
            return "Security Alert: Malicious activity detected. Your IP has been flagged.", 403

def run_system_command(cmd_str):
    """Run a command, prefixing with sudo only if necessary."""
    is_root = os.getuid() == 0
    # Split command, handling cases where it might already start with sudo
    parts = cmd_str.split()
    if parts[0] == 'sudo':
        if is_root:
            parts = parts[1:] # Already root, strip sudo
        else:
            # Check if sudo exists
            if not shutil.which('sudo'):
                parts = parts[1:] # No sudo available, try running directly
    
    # Ensure iptables has full path if possible
    if parts[0] == 'iptables' and shutil.which('iptables'):
        parts[0] = shutil.which('iptables')
    elif parts[0] == 'iptables' and os.path.exists('/usr/sbin/iptables'):
        parts[0] = '/usr/sbin/iptables'

    print(f"DEBUG: Executing command: {' '.join(parts)}")
    return subprocess.run(parts, capture_output=True, text=True)

db = get_db_connection()

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    user = db.users.find_one({"username": username})
    if user and check_password_hash(user['password'], password):
        access_token = create_access_token(identity=username)
        resp = jsonify({"status": "success", "message": "Login successful"})
        set_access_cookies(resp, access_token)
        # Log audit
        db.audit_logs.insert_one({
            "timestamp": time.time(),
            "action": "LOGIN",
            "user": username,
            "details": "User logged in to dashboard"
        })
        return resp
    
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401

@app.route('/api/logout', methods=['POST'])
def api_logout():
    resp = jsonify({"status": "success"})
    unset_jwt_cookies(resp)
    return resp

@app.route('/')
@jwt_required()
def index():
    return render_template('index.html')

@app.route('/settings')
@jwt_required()
def settings():
    return render_template('settings.html')

@app.route('/stream')
@jwt_required()
def stream():
    return render_template('stream.html')

@app.route('/analytics')
@jwt_required()
def analytics():
    return render_template('analytics.html')

@app.route('/security-lab')
@jwt_required()
def security_lab():
    return render_template('security_lab.html')


@app.route('/api/waf/toggle', methods=['POST'])
@jwt_required()
def toggle_waf():
    global WAF_ENABLED
    WAF_ENABLED = not WAF_ENABLED
    return jsonify({"status": "success", "waf_enabled": WAF_ENABLED})

@app.route('/api/waf/status')
@jwt_required()
def waf_status():
    global WAF_ENABLED
    return jsonify({"waf_enabled": WAF_ENABLED})

@app.route('/portal')
def honeypot_portal():
    """High-Interaction Honeypot: Fake Login Portal."""
    return render_template('honeypot_login.html')

@app.route('/portal/login', methods=['POST'])
def honeypot_login_handle():
    """Capture credentials from the honeypot portal."""
    username = request.form.get('username')
    password = request.form.get('password')
    ip = request.remote_addr
    
    # Log the captured credentials (Security Team access only)
    db.captured_creds.insert_one({
        "timestamp": time.time(),
        "ip": ip,
        "username": username,
        "password": password,
        "ua": request.headers.get('User-Agent')
    })
    
    # Trigger an incident so the SOAR engine knows about it
    # We use a custom type so the monitor can persona it correctly
    db.incidents.insert_one({
        "timestamp": time.time(),
        "source_ip": ip,
        "type": "credential_harvesting",
        "details": f"Captured credentials for user: {username}",
        "status": "Detected",
        "is_active_block": False # Monitor will pick this up or we can trigger it
    })
    
    # Show a fake error to keep them trying
    time.sleep(1.5) # Simulate 'checking'
    return "Invalid credentials. Incident has been reported to the Enterprise Security Team.", 401

@app.route('/api/incidents')
@jwt_required()
def get_incidents():
    # Return incidents sorted by latest first with global total count
    total = db.incidents.count_documents({})
    incidents = list(db.incidents.find({}, {'_id': 0}).sort("timestamp", -1).limit(100))
    return jsonify({"incidents": incidents, "total": total})

@app.route('/api/audit-logs')
@jwt_required()
def get_audit_logs():
    logs = list(db.audit_logs.find({}, {'_id': 0}).sort("timestamp", -1).limit(100))
    return jsonify(logs)

@app.route('/api/agent/report', methods=['POST'])
def agent_report():
    """Endpoint for remote agents to report incidents."""
    data = request.json
    # Validation
    if not data or 'source_ip' not in data:
        return jsonify({"status": "error", "message": "Missing source_ip"}), 400
    
    data['timestamp'] = time.time()
    data['status'] = "External_Detected"
    db.incidents.insert_one(data)
    
    return jsonify({"status": "success", "message": "Report received"})

@app.route('/api/ssh-logs')
@jwt_required()
def get_ssh_logs():
    logs = list(db.ssh_logs.find({}, {'_id': 0}).sort("timestamp", -1).limit(100))
    return jsonify(logs)

@app.route('/api/stats/trends')
@jwt_required()
def get_stats_trends():
    """Aggregate incidents per hour for the last 24 hours aligned to whole hours."""
    now = time.time()
    
    # 1. Exact count for the "Last 24h" card (rolling duration)
    one_day_ago = now - 86400
    total_24h = db.incidents.count_documents({"timestamp": {"$gte": one_day_ago}})
    
    # 2. Bins for the velocity chart (aligned to hour boundaries)
    # This aligns graphs across reloads and prevents "shifting" based on current minutes
    current_hour_start = (now // 3600) * 3600
    start_ts = current_hour_start - (23 * 3600) # Bin 0 starts at the top of the hour 23 hours ago
    
    # Fetch incidents for the plot (start_ts is likely <= one_day_ago)
    plot_incidents = list(db.incidents.find({"timestamp": {"$gte": start_ts}}, {"timestamp": 1}))
    
    counts = [0] * 24
    for inc in plot_incidents:
        idx = int((inc['timestamp'] - start_ts) // 3600)
        if 0 <= idx < 24:
            counts[idx] += 1
    
    # Generate labels (HH:00) strictly in UTC (matches system 'date')
    labels = []
    for i in range(24):
        ts = start_ts + (i * 3600)
        tm = time.gmtime(ts)
        labels.append(f"{tm.tm_hour:02d}:00")
    
    active_jails = db.incidents.count_documents({"is_active_block": True})
    
    return jsonify({
        "labels": labels,
        "counts": counts,
        "total_24h": total_24h,
        "active_jails": active_jails
    })

@app.route('/api/settings', methods=['GET', 'POST'])
@jwt_required()
def api_settings():
    if request.method == 'GET':
        # Don't return actual keys for now to keep it somewhat secure in UI, 
        # but for this local tool we'll return them so they can be edited.
        config = db.config.find_one({"type": "general"}, {'_id': 0}) or {}
        return jsonify(config)
    
    if request.method == 'POST':
        data = request.json
        # Only allow specific keys for safety
        allowed_keys = ['abuseipdb_key', 'vt_key', 'slack_webhook']
        update_data = {k: v for k, v in data.items() if k in allowed_keys}
        
        db.config.update_one(
            {"type": "general"},
            {"$set": update_data},
            upsert=True
        )
        return jsonify({"status": "success", "message": "Settings updated"})

@app.route('/api/status')
def get_status():
    # Simple system status check
    # Check if we can connect to DB
    try:
        db.command('ping')
        db_status = "Online"
    except:
        db_status = "Offline"
        
    return jsonify({
        "system_status": "Active",
        "database": db_status
    })

def perform_unblock(ip):
    """Core logic to remove an IP from iptables and update DB."""
    if platform.system() != 'Linux':
        print(f"SIMULATED UNBLOCK for {ip}")
        # Update DB for simulation too
        db.incidents.update_many(
            {"source_ip": ip}, 
            {"$set": {"status": "Unblocked", "is_active_block": False, "expiry_time": None}}
        )
        return True

    unblocked_any = False
    try:
        while True:
            # We'll try to remove ALL occurrences of the block
            result = run_system_command(f"sudo iptables -D INPUT -s {ip} -j DROP")
            
            if result.returncode == 0:
                unblocked_any = True
                print(f"Successfully removed one block rule for {ip}")
                continue 
            else:
                stderr = result.stderr.lower()
                # If rule doesn't exist, we consider it "unblocked" anyway for consistency
                if "bad rule" in stderr or "does a matching rule exist" in stderr or "no such rule" in stderr:
                    break # No more rules
                elif "password" in stderr or "permission denied" in stderr or "root" in stderr:
                    print(f"CRITICAL: Permission/Sudo error unblocking {ip}. Stderr: {result.stderr}")
                    raise PermissionError(f"System requires sudo password or root privileges to unblock {ip}")
                else:
                    if not unblocked_any:
                        print(f"Iptables unexpected error unblocking {ip}: {result.stderr}")
                        raise Exception(f"Iptables error: {result.stderr.strip()}")
                    break
                    
        db.incidents.update_many(
            {"source_ip": ip}, 
            {"$set": {"status": "Unblocked", "is_active_block": False, "expiry_time": None}}
        )
        return True, "IP unblocked successfully"
    except PermissionError as pe:
        return False, str(pe)
    except Exception as e:
        print(f"Unexpected error unblocking {ip}: {e}")
        return False, f"Unexpected error: {str(e)}"

@app.route('/api/unblock', methods=['POST'])
@jwt_required()
def unblock_route():
    data = request.json
    ip = data.get('ip')
    reason = data.get('reason', 'Manual override')
    admin_user = get_jwt_identity()
    
    if not ip:
        return jsonify({"status": "error", "message": "No IP provided"}), 400

    print(f"MANUAL UNBLOCK: Requested for {ip} by {admin_user} Reason: {reason}")
    success, message = perform_unblock(ip)
    if success:
        # Log audit
        db.audit_logs.insert_one({
            "timestamp": time.time(),
            "action": "UNBLOCK",
            "user": admin_user,
            "details": f"Unblocked IP {ip}. Reason: {reason}"
        })
        return jsonify({"status": "success", "message": message})
    else:
        return jsonify({"status": "error", "message": message}), 500

@app.route('/api/whitelist', methods=['GET', 'POST', 'DELETE'])
@jwt_required()
def whitelist_route():
    if request.method == 'GET':
        whitelist = list(db.whitelist.find({}, {'_id': 0}))
        return jsonify(whitelist)
    
    if request.method == 'POST':
        data = request.json
        ip = data.get('ip')
        desc = data.get('description', 'Manual entry')
        if not ip: return jsonify({"status": "error", "message": "No IP"}), 400
        
        db.whitelist.update_one({"ip": ip}, {"$set": {"ip": ip, "description": desc, "added_at": time.time()}}, upsert=True)
        return jsonify({"status": "success", "message": f"IP {ip} whitelisted"})

    if request.method == 'DELETE':
        ip = request.args.get('ip')
        if not ip: return jsonify({"status": "error", "message": "No IP"}), 400
        db.whitelist.delete_one({"ip": ip})
        return jsonify({"status": "success", "message": f"IP {ip} removed from whitelist"})

def auto_unblock_thread():
    """Periodically check for and release expired blocks."""
    while True:
        try:
            now = time.time()
            expired_incidents = list(db.incidents.find({
                "is_active_block": True,
                "expiry_time": {"$lte": now}
            }))
            
            for incident in expired_incidents:
                ip = incident['source_ip']
                print(f"AUTO-UNBLOCK: Timer expired for {ip}")
                success, msg = perform_unblock(ip)
                print(f"AUTO-UNBLOCK Result for {ip}: {msg}")
        except Exception as e:
            print(f"Auto-unblock error: {e}")
        time.sleep(30) # Check every 30 seconds

def background_thread():
    """Emit new incidents to clients as they happen."""
    last_count = 0
    while True:
        try:
            count = db.incidents.count_documents({})
            if count > last_count:
                # Fetch latest
                latest = list(db.incidents.find({}, {'_id': 0}).sort("timestamp", -1).limit(count - last_count))
                socketio.emit('new_incident', latest)
                last_count = count
        except:
            pass
        time.sleep(2)

def system_metrics_thread():
    """Periodically emit system resource usage."""
    while True:
        try:
            cpu = psutil.cpu_percent(interval=1)
            ram = psutil.virtual_memory().percent
            net = psutil.net_io_counters()
            # Convert bytes to MB for readout
            sent = round(net.bytes_sent / (1024 * 1024), 2)
            recv = round(net.bytes_recv / (1024 * 1024), 2)
            
            socketio.emit('system_metrics', {
                'cpu': cpu,
                'ram': ram,
                'net_sent': sent,
                'net_recv': recv
            })
        except:
            pass
        time.sleep(2)

@socketio.on('connect')
def test_connect():
    print('Client connected')

if __name__ == '__main__':
    # Start background threads
    t1 = threading.Thread(target=background_thread)
    t1.daemon = True
    t1.start()
    
    t2 = threading.Thread(target=system_metrics_thread)
    t2.daemon = True
    t2.start()

    # Start SSH Honeypot and Auto-Unblock (Only in the main process, not the reloader)
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or not app.debug:
        def ssh_callback(data):
            data['timestamp'] = time.time()
            # Save to DB
            db.ssh_logs.insert_one(data)
            # Broadcast live
            socketio.emit('ssh_hacker_command', data)

        t3 = threading.Thread(target=run_ssh_honeypot, kwargs={'port': 2222, 'callback': ssh_callback})
        t3.daemon = True
        t3.start()

        # Start Auto-Unblocker
        t4 = threading.Thread(target=auto_unblock_thread)
        t4.daemon = True
        t4.start()
    
    socketio.run(app, debug=True, port=5000, host='0.0.0.0')
