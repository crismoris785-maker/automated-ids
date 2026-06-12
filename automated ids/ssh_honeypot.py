import paramiko
import threading
import socket
import sys
import os
import time

# Dummy host key generation for the honeypot
def get_host_key():
    key_path = "ssh_host_rsa_key"
    if not os.path.exists(key_path):
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(key_path)
    else:
        key = paramiko.RSAKey(filename=key_path)
    return key

class HoneypotSSHServer(paramiko.ServerInterface):
    def __init__(self, callback=None, remote_addr=None):
        self.event = threading.Event()
        self.callback = callback
        self.remote_addr = remote_addr

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Accept any login!
        print(f"[SSH] Access granted for user '{username}' with password '{password}' from {self.remote_addr}")
        if self.callback:
            self.callback({
                "type": "login",
                "username": username,
                "password": password,
                "ip": self.remote_addr
            })
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

def handle_ssh_connection(client, addr, callback):
    transport = paramiko.Transport(client)
    transport.add_server_key(get_host_key())
    
    server = HoneypotSSHServer(callback=callback, remote_addr=addr[0])
    
    try:
        transport.start_server(server=server)
    except paramiko.SSHException:
        return

    # Wait for authentication
    chan = transport.accept(20)
    if chan is None:
        return

    server.event.wait(10)
    if not server.event.is_set():
        chan.close()
        return

    # Mock shell interactive loop
    chan.send("\r\n\r\nWelcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-43-generic x86_64)\r\n\r\n")
    chan.send(" * Documentation:  https://help.ubuntu.com\r\n")
    chan.send(" * Management:     https://landscape.canonical.com\r\n")
    chan.send(" * Support:        https://ubuntu.com/advantage\r\n\r\n")
    
    prompt = "root@ubuntu:~# "
    chan.send(prompt)

    command = ""
    while True:
        try:
            byte = chan.recv(1)
            if not byte:
                break
            
            char = byte.decode('utf-8', errors='ignore')

            # Handle backspace
            if char == '\x7f':
                if len(command) > 0:
                    command = command[:-1]
                    chan.send('\b \b')
            # Handle Enter
            elif char == '\r' or char == '\n':
                chan.send('\r\n')
                if command.strip():
                    print(f"[SSH COMMAND] {addr[0]}: {command}")
                    if callback:
                        callback({
                            "type": "command",
                            "command": command,
                            "ip": addr[0]
                        })
                    
                    # Mock some outputs for common commands
                    cmd_norm = command.strip().lower()
                    if cmd_norm == "ls":
                        chan.send("Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos\r\n")
                    elif cmd_norm == "whoami":
                        chan.send("root\r\n")
                    elif cmd_norm == "uname -a":
                        chan.send("Linux ubuntu 5.15.0-43-generic #46-Ubuntu SMP Tue Jul 12 10:30:17 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux\r\n")
                    elif cmd_norm == "id":
                        chan.send("uid=0(root) gid=0(root) groups=0(root)\r\n")
                    else:
                        chan.send(f"bash: {command.split()[0]}: command not found\r\n")
                
                command = ""
                chan.send(prompt)
            else:
                command += char
                chan.send(char) # Echo back
        except:
            break
    
    chan.close()
    transport.close()

def run_ssh_honeypot(port=2222, callback=None):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind(('0.0.0.0', port))
    except Exception as e:
        print(f"[SSH] Error binding to port {port}: {e}")
        return

    server_socket.listen(100)
    print(f"[SSH Honeypot] Listening on port {port}...")

    while True:
        try:
            client_socket, client_addr = server_socket.accept()
            print(f"[SSH] New connection from {client_addr[0]}:{client_addr[1]}")
            threading.Thread(target=handle_ssh_connection, args=(client_socket, client_addr, callback), daemon=True).start()
        except:
            break

if __name__ == "__main__":
    def test_callback(data):
        print(f"Callback data: {data}")
    run_ssh_honeypot(port=2222, callback=test_callback)
