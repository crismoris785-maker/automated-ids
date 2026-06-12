import socket
import threading
import time
from database.connection import get_db_connection

class DecoyService:
    def __init__(self, port, name, handshake=None):
        self.port = port
        self.name = name
        self.handshake = handshake
        self.db = get_db_connection()

    def start(self):
        thread = threading.Thread(target=self._listen, daemon=True)
        thread.start()
        print(f"[DECOY] {self.name} started on port {self.port}")

    def _listen(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(('0.0.0.0', self.port))
            server.listen(5)
            while True:
                client, addr = server.accept()
                threading.Thread(target=self._handle_client, args=(client, addr), daemon=True).start()
        except Exception as e:
            print(f"[DECOY] {self.name} error: {e}")

    def _handle_client(self, client, addr):
        ip = addr[0]
        try:
            # Send initial handshake if defined
            if self.handshake:
                client.send(self.handshake)

            # Receive data (capture queries/exploit attempts)
            data = client.recv(1024)
            data_hex = data.hex() if data else "No data"
            
            # Log as high-interaction hit
            self.db.incidents.insert_one({
                "timestamp": time.time(),
                "source_ip": ip,
                "type": f"{self.name.lower()}_exploit_attempt",
                "details": f"Hit {self.name} Decoy. Received: {data_hex[:200]}",
                "status": "Detected",
                "is_active_block": False
            })
            
            time.sleep(1) # Linger a bit
            client.close()
        except:
            client.close()

def run_decoys():
    # MySQL Decoy Handshake (Common 5.5.x greeting)
    mysql_handshake = b'\x4a\x00\x00\x00\x0a\x35\x2e\x35\x2e\x36\x32\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xf7\x08\x02\x00\x0f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf7\x01\x00'
    
    # RDP Handshake (Terminal Services Greeting)
    rdp_handshake = b'\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00'

    decoys = [
        DecoyService(3306, "MySQL", mysql_handshake),
        DecoyService(3389, "RDP", rdp_handshake),
        DecoyService(5432, "PostgreSQL"),
        DecoyService(5900, "VNC")
    ]

    for decoy in decoys:
        decoy.start()

if __name__ == "__main__":
    run_decoys()
    while True:
        time.sleep(10)
