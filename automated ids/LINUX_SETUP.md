# SOAR Tool Linux Setup Guide

## 1. Prerequisites
Ensure you are running on a Linux distribution (Ubuntu/Kali) and have Python 3 and MongoDB installed.

```bash
sudo apt update
sudo apt install python3 python3-pip mongodb
```

## 2. Directory Structure Setup
Ensure the project files are in place.
- `/playbooks/block_ip.yaml`
- `app.py`
- `monitor.py`
- `requirements.txt`

## 3. Install Python Dependencies
```bash
pip install -r requirements.txt
```

## 4. Permissions for Action Execution (IMPORTANT)
The `monitor.py` script needs to execute `iptables` commands which require root privileges. You have two options:

### Option A: Run everything as root (Easier for testing)
```bash
sudo python3 monitor.py
```

### Option B: Configure Sudoers (Safer)
Allow the user running the script to execute iptables without a password.
1. Edit sudoers file:
   ```bash
   sudo visudo
   ```
2. Add the following line at the bottom (replace `your_username` with your actual username):
   ```
   your_username ALL=(root) NOPASSWD: /usr/sbin/iptables
   ```

## 5. Running the Application

### Terminal 1: Start the Web Dashboard
```bash
python3 app.py
```
Access at: `http://localhost:5000`

### Terminal 2: Start the Detection Engine
```bash
sudo python3 monitor.py
```

## 6. Testing the System
To simulate an SSH brute force attack, you can manually append lines to the auth log (or use the dummy logging feature if testing locally).

**Command to simulate a threat:**
```bash
logger "Failed password for root from 192.168.1.100 port 22 ssh2"
logger "Failed password for root from 192.168.1.100 port 22 ssh2"
logger "Failed password for root from 192.168.1.100 port 22 ssh2"
```

The monitor should detect this, add an iptables rule, and update the dashboard instantly.
