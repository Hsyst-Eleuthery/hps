import asyncio
import aiohttp
from aiohttp import web
import socketio
import json
import logging
import os
import hashlib
import base64
from datetime import datetime
from typing import Dict, List, Optional, Any, Set, Tuple
import sqlite3
import time
import uuid
import mimetypes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import aiofiles
from pathlib import Path
import threading
import secrets
import random
import math
import struct
import cmd
import sys
import ssl
import urllib.parse
import re

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("HPS-Server")

class HPSAdminConsole(cmd.Cmd):
    intro = 'HPS Administration Console\nType "help" for commands\n'
    prompt = '(hps-admin) '

    def __init__(self, server):
        super().__init__()
        self.server = server

    def do_online_users(self, arg):
        online_count = len([c for c in self.server.connected_clients.values() if c['authenticated']])
        print(f"Online users: {online_count}")
        for sid, client in self.server.connected_clients.items():
            if client['authenticated']:
                print(f"  {client['username']} - {client['node_type']} - {client['address']}")

    def do_ban_user(self, arg):
        args = arg.split()
        if len(args) < 3:
            print("Usage: ban_user <username> <duration_seconds> <reason>")
            return
        username, duration, reason = args[0], int(args[1]), ' '.join(args[2:])
        for sid, client in self.server.connected_clients.items():
            if client['username'] == username:
                asyncio.run_coroutine_threadsafe(
                    self.server.ban_client(client['client_identifier'], duration, reason),
                    self.server.loop
                )
                print(f"User {username} banned for {duration} seconds")
                return
        print(f"User {username} not found online")

    def do_reputation(self, arg):
        args = arg.split()
        if not args:
            print("Usage: reputation <username> [new_reputation]")
            return
        username = args[0]
        with sqlite3.connect(self.server.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT reputation FROM user_reputations WHERE username = ?', (username,))
            row = cursor.fetchone()
            if row:
                if len(args) > 1:
                    new_rep = int(args[1])
                    cursor.execute('UPDATE user_reputations SET reputation = ? WHERE username = ?', (new_rep, username))
                    cursor.execute('UPDATE users SET reputation = ? WHERE username = ?', (new_rep, username))
                    conn.commit()
                    for sid, client in self.server.connected_clients.items():
                        if client['username'] == username:
                            asyncio.run_coroutine_threadsafe(
                                self.server.sio.emit('reputation_update', {'reputation': new_rep}, room=sid),
                                self.server.loop
                            )
                    print(f"Reputation of {username} changed to {new_rep}")
                else:
                    print(f"Reputation of {username}: {row[0]}")
            else:
                print(f"User {username} not found")

    def do_server_stats(self, arg):
        with sqlite3.connect(self.server.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM users')
            total_users = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM content')
            total_content = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM dns_records')
            total_dns = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM network_nodes WHERE is_online = 1')
            online_nodes = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM content_reports WHERE resolved = 0')
            pending_reports = cursor.fetchone()[0]
        print(f"Total users: {total_users}")
        print(f"Total content: {total_content}")
        print(f"DNS records: {total_dns}")
        print(f"Online nodes: {online_nodes}")
        print(f"Connected clients: {len(self.server.connected_clients)}")
        print(f"Known servers: {len(self.server.known_servers)}")
        print(f"Pending reports: {pending_reports}")

    def do_content_stats(self, arg):
        with sqlite3.connect(self.server.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
SELECT mime_type, COUNT(*) as count, SUM(size) as total_size
FROM content
GROUP BY mime_type
ORDER BY count DESC
            ''')
            print("Content statistics by MIME type:")
            for row in cursor.fetchall():
                print(f"  {row[0]}: {row[1]} files, {row[2] // (1024*1024)}MB")

    def do_node_stats(self, arg):
        with sqlite3.connect(self.server.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
SELECT node_type, COUNT(*) as count, AVG(reputation) as avg_reputation
FROM network_nodes
WHERE is_online = 1
GROUP BY node_type
            ''')
            print("Node statistics:")
            for row in cursor.fetchall():
                print(f"  {row[0]}: {row[1]} nodes, average reputation: {row[2]:.1f}")

    def do_list_reports(self, arg):
        with sqlite3.connect(self.server.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
SELECT report_id, content_hash, reported_user, reporter, timestamp
FROM content_reports
WHERE resolved = 0
ORDER BY timestamp DESC
            ''')
            rows = cursor.fetchall()
            if not rows:
                print("No pending reports.")
            else:
                print("Pending reports:")
                for row in rows:
                    print(f"  Report ID: {row[0]}")
                    print(f"    Content Hash: {row[1]}")
                    print(f"    Reported User: {row[2]}")
                    print(f"    Reporter: {row[3]}")
                    print(f"    Timestamp: {datetime.fromtimestamp(row[4]).strftime('%Y-%m-%d %H:%M:%S')}")
                    print()

    def do_resolve_report(self, arg):
        args = arg.split()
        if not args:
            print("Usage: resolve_report <report_id> [action: ban|warn|ignore]")
            return
        report_id = args[0]
        action = args[1] if len(args) > 1 else "warn"
        with sqlite3.connect(self.server.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
SELECT content_hash, reported_user, reporter
FROM content_reports
WHERE report_id = ? AND resolved = 0
                ''', (report_id,))
            row = cursor.fetchone()
            if not row:
                print(f"Report {report_id} not found or already resolved")
                return
            content_hash, reported_user, reporter = row
            if action == "ban":
                cursor.execute('UPDATE user_reputations SET reputation = 1 WHERE username = ?', (reported_user,))
                cursor.execute('UPDATE users SET reputation = 1 WHERE username = ?', (reported_user,))
                cursor.execute('DELETE FROM content WHERE content_hash = ?', (content_hash,))
                file_path = os.path.join(self.server.files_dir, f"{content_hash}.dat")
                if os.path.exists(file_path):
                    os.remove(file_path)
                print(f"User {reported_user} banned and content removed")
            elif action == "warn":
                cursor.execute('UPDATE user_reputations SET reputation = MAX(1, reputation - 20) WHERE username = ?', (reported_user,))
                cursor.execute('UPDATE users SET reputation = MAX(1, reputation - 20) WHERE username = ?', (reported_user,))
                print(f"User {reported_user} warned (-20 reputation)")
            cursor.execute('UPDATE content_reports SET resolved = 1 WHERE report_id = ?', (report_id,))
            conn.commit()
            for sid, client in self.server.connected_clients.items():
                if client['username'] == reported_user:
                    cursor.execute('SELECT reputation FROM user_reputations WHERE username = ?', (reported_user,))
                    rep_row = cursor.fetchone()
                    if rep_row:
                        asyncio.run_coroutine_threadsafe(
                            self.server.sio.emit('reputation_update', {'reputation': rep_row[0]}, room=sid),
                            self.server.loop
                        )
            print(f"Report {report_id} resolved")

    def do_sync_network(self, arg):
        print("Starting network synchronization...")
        asyncio.run_coroutine_threadsafe(self.server.sync_with_network(), self.server.loop)
        print("Synchronization started")

    def do_exit(self, arg):
        print("Stopping server...")
        asyncio.run_coroutine_threadsafe(self.server.stop(), self.server.loop)
        return True

    def do_help(self, arg):
        print("\nAvailable commands:")
        print("  online_users - List online users")
        print("  ban_user <user> <seconds> <reason> - Ban a user")
        print("  reputation <user> [new_rep] - Show or change reputation")
        print("  server_stats - Server statistics")
        print("  content_stats - Content statistics")
        print("  node_stats - Node statistics")
        print("  list_reports - List pending reports")
        print("  resolve_report <report_id> [action] - Resolve a report")
        print("  sync_network - Sync with network")
        print("  exit - Stop server")
        print("  help - Show this help\n")

class HPSServer:
    def __init__(self, db_path: str = 'hps_server.db', files_dir: str = 'hps_files',
                 host: str = '0.0.0.0', port: int = 8080, ssl_cert: str = None, ssl_key: str = None):
        self.db_path = db_path
        self.files_dir = files_dir
        self.host = host
        self.port = port
        self.address = f"{host}:{port}"
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.sio = socketio.AsyncServer(async_mode='aiohttp', cors_allowed_origins='*')
        self.app = web.Application()
        self.sio.attach(self.app)
        self.connected_clients: Dict[str, Dict] = {}
        self.authenticated_users: Dict[str, Dict] = {}
        self.known_servers: Set[str] = set()
        self.server_id = str(uuid.uuid4())
        self.is_running = False
        self.sync_lock = asyncio.Lock()
        self.rate_limits: Dict[str, Dict] = {}
        self.client_reputations: Dict[str, int] = {}
        self.banned_clients: Dict[str, float] = {}
        self.pow_challenges: Dict[str, Dict] = {}
        self.login_attempts: Dict[str, List[float]] = {}
        self.client_hashrates: Dict[str, float] = {}
        self.max_upload_size = 100 * 1024 * 1024
        self.max_content_per_user = 1000
        self.max_dns_per_user = 100
        self.violation_counts: Dict[str, int] = {}
        self.server_auth_challenges: Dict[str, Dict] = {}
        self.session_keys: Dict[str, bytes] = {}
        self.server_sync_tasks: Dict[str, asyncio.Task] = {}
        self.stop_event = asyncio.Event()
        self.runner = None
        self.site = None
        self.backup_server = None
        self.private_key = None
        self.public_key_pem = None
        self.connection_attempts_log: Dict[str, List[Tuple[float, str, str]]] = {}
        self.server_connectivity_status: Dict[str, Dict[str, Any]] = {}
        self.generate_server_keys()
        self.setup_routes()
        self.setup_handlers()
        self.init_database()
        self.load_known_servers()
        os.makedirs(files_dir, exist_ok=True)
        self.admin_console = HPSAdminConsole(self)
        self.console_thread = None

    def start_admin_console(self):
        def run_console():
            self.admin_console.cmdloop()
        self.console_thread = threading.Thread(target=run_console, daemon=True)
        self.console_thread.start()

    def generate_server_keys(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
        self.public_key_pem = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    def init_database(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            tables = [
                '''CREATE TABLE IF NOT EXISTS users (
username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, public_key TEXT NOT NULL,
created_at REAL NOT NULL, last_login REAL NOT NULL, reputation INTEGER DEFAULT 100,
client_identifier TEXT, disk_quota INTEGER DEFAULT 524288000, used_disk_space INTEGER DEFAULT 0,
                last_activity REAL NOT NULL)''',
                '''CREATE TABLE IF NOT EXISTS content (
content_hash TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT, mime_type TEXT NOT NULL,
size INTEGER NOT NULL, username TEXT NOT NULL, signature TEXT NOT NULL, public_key TEXT NOT NULL,
timestamp REAL NOT NULL, file_path TEXT NOT NULL, verified INTEGER DEFAULT 0,
                replication_count INTEGER DEFAULT 1, last_accessed REAL NOT NULL)''',
                '''CREATE TABLE IF NOT EXISTS dns_records (
domain TEXT PRIMARY KEY, content_hash TEXT NOT NULL, username TEXT NOT NULL,
original_owner TEXT NOT NULL, timestamp REAL NOT NULL, signature TEXT NOT NULL,
                verified INTEGER DEFAULT 0, last_resolved REAL NOT NULL, ddns_hash TEXT NOT NULL)''',
                '''CREATE TABLE IF NOT EXISTS api_apps (
app_name TEXT PRIMARY KEY, username TEXT NOT NULL, content_hash TEXT NOT NULL,
                timestamp REAL NOT NULL, last_updated REAL NOT NULL)''',
                '''CREATE TABLE IF NOT EXISTS network_nodes (
node_id TEXT PRIMARY KEY, address TEXT NOT NULL, public_key TEXT NOT NULL, username TEXT NOT NULL,
last_seen REAL NOT NULL, reputation INTEGER DEFAULT 100, node_type TEXT NOT NULL CHECK(node_type IN ('server', 'client')),
                is_online INTEGER DEFAULT 1, client_identifier TEXT, connection_count INTEGER DEFAULT 1)''',
                '''CREATE TABLE IF NOT EXISTS content_availability (
content_hash TEXT NOT NULL, node_id TEXT NOT NULL, timestamp REAL NOT NULL, is_primary INTEGER DEFAULT 0,
                PRIMARY KEY (content_hash, node_id))''',
                '''CREATE TABLE IF NOT EXISTS server_nodes (
server_id TEXT PRIMARY KEY, address TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL,
                last_seen REAL NOT NULL, is_active INTEGER DEFAULT 1, reputation INTEGER DEFAULT 100, sync_priority INTEGER DEFAULT 1)''',
                '''CREATE TABLE IF NOT EXISTS server_connections (
local_server_id TEXT NOT NULL, remote_server_id TEXT NOT NULL, remote_address TEXT NOT NULL,
                last_ping REAL NOT NULL, is_active INTEGER DEFAULT 1, PRIMARY KEY (local_server_id, remote_server_id))''',
                '''CREATE TABLE IF NOT EXISTS user_reputations (
username TEXT PRIMARY KEY, reputation INTEGER DEFAULT 100, last_updated REAL NOT NULL,
                client_identifier TEXT, violation_count INTEGER DEFAULT 0)''',
                '''CREATE TABLE IF NOT EXISTS content_reports (
report_id TEXT PRIMARY KEY, content_hash TEXT NOT NULL, reported_user TEXT NOT NULL,
                reporter TEXT NOT NULL, timestamp REAL NOT NULL, resolved INTEGER DEFAULT 0, resolution_type TEXT)''',
                '''CREATE TABLE IF NOT EXISTS server_sync_history (
server_address TEXT NOT NULL, last_sync REAL NOT NULL, sync_type TEXT NOT NULL,
                items_count INTEGER DEFAULT 0, success INTEGER DEFAULT 1, PRIMARY KEY (server_address, sync_type))''',
                '''CREATE TABLE IF NOT EXISTS rate_limits (
client_identifier TEXT NOT NULL, action_type TEXT NOT NULL, last_action REAL NOT NULL,
                attempt_count INTEGER DEFAULT 1, PRIMARY KEY (client_identifier, action_type))''',
                '''CREATE TABLE IF NOT EXISTS pow_history (
client_identifier TEXT NOT NULL, challenge TEXT NOT NULL, target_bits INTEGER NOT NULL,
                timestamp REAL NOT NULL, success INTEGER DEFAULT 0, solve_time REAL DEFAULT 0)''',
                '''CREATE TABLE IF NOT EXISTS known_servers (
                address TEXT PRIMARY KEY, added_date REAL NOT NULL, last_connected REAL NOT NULL, is_active INTEGER DEFAULT 1)''',
                '''CREATE TABLE IF NOT EXISTS client_files (
client_identifier TEXT NOT NULL, content_hash TEXT NOT NULL, file_name TEXT NOT NULL,
                file_size INTEGER NOT NULL, last_sync REAL NOT NULL, PRIMARY KEY (client_identifier, content_hash))''',
                '''CREATE TABLE IF NOT EXISTS client_dns_files (
client_identifier TEXT NOT NULL, domain TEXT NOT NULL, ddns_hash TEXT NOT NULL,
                last_sync REAL NOT NULL, PRIMARY KEY (client_identifier, domain))''',
                '''CREATE TABLE IF NOT EXISTS server_connectivity_log (
server_address TEXT NOT NULL, timestamp REAL NOT NULL, protocol_used TEXT NOT NULL,
success INTEGER DEFAULT 0, error_message TEXT, response_time REAL DEFAULT 0,
                PRIMARY KEY (server_address, timestamp))''',
                '''CREATE TABLE IF NOT EXISTS dns_owner_changes (
change_id TEXT PRIMARY KEY, domain TEXT NOT NULL, previous_owner TEXT NOT NULL,
new_owner TEXT NOT NULL, changer TEXT NOT NULL, timestamp REAL NOT NULL,
                change_file_hash TEXT NOT NULL)''',
                '''CREATE TABLE IF NOT EXISTS api_app_versions (
version_id TEXT PRIMARY KEY, app_name TEXT NOT NULL, content_hash TEXT NOT NULL,
username TEXT NOT NULL, timestamp REAL NOT NULL, version_number INTEGER DEFAULT 1,
                FOREIGN KEY (app_name) REFERENCES api_apps(app_name) ON DELETE CASCADE)''',
                '''CREATE TABLE IF NOT EXISTS content_redirects (
old_hash TEXT PRIMARY KEY, new_hash TEXT NOT NULL, username TEXT NOT NULL,
                redirect_type TEXT NOT NULL, timestamp REAL NOT NULL)'''
            ]
            for table in tables:
                cursor.execute(table)
            conn.commit()

    def load_known_servers(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT address FROM known_servers WHERE is_active = 1')
            self.known_servers = {row[0] for row in cursor.fetchall()}
        logger.info(f"Loaded {len(self.known_servers)} known servers")

    def save_known_servers(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for server_address in self.known_servers:
                cursor.execute('''INSERT OR REPLACE INTO known_servers
                    (address, added_date, last_connected, is_active) VALUES (?, ?, ?, ?)''',
                    (server_address, time.time(), time.time(), 1))
            conn.commit()

    def log_connection_attempt(self, server_address: str, protocol: str, success: bool, error_message: str = "", response_time: float = 0):
        timestamp = time.time()
        if server_address not in self.connection_attempts_log:
            self.connection_attempts_log[server_address] = []

        self.connection_attempts_log[server_address].append((timestamp, protocol, "SUCCESS" if success else f"FAILED: {error_message}"))

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO server_connectivity_log
(server_address, timestamp, protocol_used, success, error_message, response_time)
                VALUES (?, ?, ?, ?, ?, ?)''',
                (server_address, timestamp, protocol, 1 if success else 0, error_message, response_time))
            conn.commit()

        if server_address not in self.server_connectivity_status:
            self.server_connectivity_status[server_address] = {
                'last_attempt': timestamp,
                'last_success': timestamp if success else 0,
                'preferred_protocol': protocol if success else None,
                'consecutive_failures': 0,
                'last_error': error_message
            }
        else:
            status = self.server_connectivity_status[server_address]
            status['last_attempt'] = timestamp
            if success:
                status['last_success'] = timestamp
                status['preferred_protocol'] = protocol
                status['consecutive_failures'] = 0
                status['last_error'] = None
            else:
                status['consecutive_failures'] += 1
                status['last_error'] = error_message

        logger.info(f"Connection to {server_address} via {protocol}: {'SUCCESS' if success else f'FAILED - {error_message}'}")

    async def make_remote_request(self, server_address: str, path: str, method: str = 'GET',
                                  params: Dict = None, data: Any = None, timeout: float = 30.0) -> Tuple[bool, Any, str]:
        protocols_to_try = ['https', 'http']
        last_error = ""

        for protocol in protocols_to_try:
            try:
                start_time = time.time()
                url = f"{protocol}://{server_address}{path}"

                ssl_context = None
                if protocol == 'https':
                    ssl_context = ssl.create_default_context()

                connector = aiohttp.TCPConnector(ssl=ssl_context)
                timeout_obj = aiohttp.ClientTimeout(total=timeout)

                async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj) as session:
                    if method.upper() == 'GET':
                        async with session.get(url, params=params) as response:
                            content = await response.read()
                            response_time = time.time() - start_time
                            if response.status == 200:
                                self.log_connection_attempt(server_address, protocol, True, "", response_time)
                                return True, content, protocol
                            else:
                                error_msg = f"HTTP {response.status}"
                                self.log_connection_attempt(server_address, protocol, False, error_msg, response_time)
                                last_error = error_msg
                    elif method.upper() == 'POST':
                        async with session.post(url, params=params, data=data) as response:
                            content = await response.read()
                            response_time = time.time() - start_time
                            if response.status == 200:
                                self.log_connection_attempt(server_address, protocol, True, "", response_time)
                                return True, content, protocol
                            else:
                                error_msg = f"HTTP {response.status}"
                                self.log_connection_attempt(server_address, protocol, False, error_msg, response_time)
                                last_error = error_msg
            except ssl.SSLCertVerificationError as e:
                error_msg = f"SSL certificate error: {str(e)}"
                self.log_connection_attempt(server_address, protocol, False, error_msg, time.time() - start_time)
                last_error = error_msg
            except aiohttp.ClientConnectorSSLError as e:
                error_msg = f"SSL connection error: {str(e)}"
                self.log_connection_attempt(server_address, protocol, False, error_msg, time.time() - start_time)
                last_error = error_msg
            except aiohttp.ClientConnectorError as e:
                error_msg = f"Connection error: {str(e)}"
                self.log_connection_attempt(server_address, protocol, False, error_msg, time.time() - start_time)
                last_error = error_msg
            except asyncio.TimeoutError:
                error_msg = f"Timeout after {timeout}s"
                self.log_connection_attempt(server_address, protocol, False, error_msg, timeout)
                last_error = error_msg
            except Exception as e:
                error_msg = f"Unexpected error: {str(e)}"
                self.log_connection_attempt(server_address, protocol, False, error_msg, time.time() - start_time)
                last_error = error_msg

        logger.warning(f"All connection attempts failed for {server_address}{path}: {last_error}")
        return False, None, last_error

    async def make_remote_request_json(self, server_address: str, path: str, method: str = 'GET',
                                       params: Dict = None, data: Any = None, timeout: float = 30.0) -> Tuple[bool, Any, str]:
        success, content, protocol_or_error = await self.make_remote_request(server_address, path, method, params, data, timeout)
        if success:
            try:
                json_data = json.loads(content.decode('utf-8'))
                return True, json_data, protocol_or_error
            except Exception as e:
                error_msg = f"JSON decode error: {str(e)}"
                logger.error(f"Failed to parse JSON from {server_address}{path}: {error_msg}")
                return False, None, error_msg
        return False, None, protocol_or_error

    def leading_zero_bits(self, h: bytes) -> int:
        count = 0
        for byte in h:
            if byte == 0: count += 8
            else:
                count += bin(byte)[2:].zfill(8).index('1')
                break
        return count

    def compute_target_bits(self, hashrate: float, target_seconds: float) -> int:
        if hashrate <= 0: return 1
        expected_hashes_needed = hashrate * target_seconds
        if expected_hashes_needed <= 1: return 1
        b = math.ceil(math.log2(expected_hashes_needed))
        return max(1, min(256, int(b)))

    def generate_pow_challenge(self, client_identifier: str, action_type: str = "login") -> Dict[str, Any]:
        now = time.time()
        if client_identifier not in self.login_attempts:
            self.login_attempts[client_identifier] = []
        self.login_attempts[client_identifier] = [t for t in self.login_attempts[client_identifier] if now - t < 300]
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT attempt_count FROM rate_limits WHERE client_identifier = ? AND action_type = ?',
                           (client_identifier, action_type))
            row = cursor.fetchone()
            attempt_count = row[0] if row else 1
        base_bits = 12
        target_seconds = 30.0
        if action_type == "upload": base_bits, target_seconds = 8, 20.0
        elif action_type == "dns": base_bits, target_seconds = 6, 15.0
        elif action_type == "report": base_bits, target_seconds = 6, 10.0
        recent_count = len(self.login_attempts[client_identifier]) + attempt_count
        if recent_count > 0:
            base_bits += min(10, recent_count)
            target_seconds += min(120, recent_count * 10)
        client_hashrate = self.client_hashrates.get(client_identifier, 100000)
        if client_hashrate <= 0: client_hashrate = 100000
        target_bits = self.compute_target_bits(client_hashrate, target_seconds)
        target_bits = max(base_bits, target_bits)
        challenge_message = secrets.token_bytes(32)
        challenge = base64.b64encode(challenge_message).decode('utf-8')
        self.pow_challenges[client_identifier] = {
            'challenge': challenge, 'target_bits': target_bits, 'timestamp': now,
            'target_seconds': target_seconds, 'action_type': action_type
        }
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO pow_history (client_identifier, challenge, target_bits, timestamp) VALUES (?, ?, ?, ?)',
                           (client_identifier, challenge, target_bits, now))
            conn.commit()
        return {'challenge': challenge, 'target_bits': target_bits, 'message': f'Solve PoW for {action_type}', 'target_seconds': target_seconds, 'action_type': action_type}

    def verify_pow_solution(self, client_identifier: str, nonce: str, hashrate_observed: float, action_type: str) -> bool:
        if client_identifier not in self.pow_challenges: return False
        challenge_data = self.pow_challenges[client_identifier]
        if challenge_data['action_type'] != action_type: return False
        if time.time() - challenge_data['timestamp'] > 300:
            del self.pow_challenges[client_identifier]
            return False
        challenge = challenge_data['challenge']
        target_bits = challenge_data['target_bits']
        try:
            challenge_bytes = base64.b64decode(challenge)
            nonce_int = int(nonce)
            data = challenge_bytes + struct.pack(">Q", nonce_int)
            hash_result = hashlib.sha256(data).digest()
            lzb = self.leading_zero_bits(hash_result)
            if lzb >= target_bits:
                solve_time = time.time() - challenge_data['timestamp']
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('UPDATE pow_history SET success = 1, solve_time = ? WHERE client_identifier = ? AND challenge = ?',
                                   (solve_time, client_identifier, challenge))
                    conn.commit()
                del self.pow_challenges[client_identifier]
                self.login_attempts[client_identifier].append(time.time())
                if hashrate_observed > 0:
                    self.client_hashrates[client_identifier] = hashrate_observed
                return True
        except Exception as e:
            logger.error(f"PoW verification error for {client_identifier}: {e}")
        return False

    def check_rate_limit(self, client_identifier, action_type):
        now = time.time()
        if client_identifier in self.banned_clients:
            ban_until = self.banned_clients[client_identifier]
            if now < ban_until:
                return False, f"Banned for {int(ban_until - now)} seconds", int(ban_until - now)
            else:
                del self.banned_clients[client_identifier]
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT last_action, attempt_count FROM rate_limits WHERE client_identifier = ? AND action_type = ?',
                           (client_identifier, action_type))
            row = cursor.fetchone()
            if not row: return True, "", 0
            last_time, attempt_count = row
            min_interval = 60
            if action_type == "upload": min_interval = 60
            elif action_type == "login": min_interval = 60
            elif action_type == "dns": min_interval = 60
            elif action_type == "report": min_interval = 30
            if now - last_time < min_interval:
                remaining = min_interval - int(now - last_time)
                return False, f"Rate limit: {remaining}s remaining", remaining
            return True, "", 0

    def update_rate_limit(self, client_identifier, action_type):
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT attempt_count FROM rate_limits WHERE client_identifier = ? AND action_type = ?',
                           (client_identifier, action_type))
            row = cursor.fetchone()
            attempt_count = 1
            if row: attempt_count = row[0] + 1
            cursor.execute('''INSERT OR REPLACE INTO rate_limits
                (client_identifier, action_type, last_action, attempt_count) VALUES (?, ?, ?, ?)''',
                (client_identifier, action_type, now, attempt_count))
            conn.commit()

    async def ban_client(self, client_identifier, duration=3600, reason="Unknown"):
        self.banned_clients[client_identifier] = time.time() + duration
        logger.warning(f"Client {client_identifier} banned for {duration} seconds. Reason: {reason}")
        for sid, client_info in self.connected_clients.items():
            if client_info.get('client_identifier') == client_identifier:
                await self.sio.emit('ban_notification', {'duration': duration, 'reason': reason}, room=sid)
                self.connected_clients[sid]['authenticated'] = False
                self.connected_clients[sid]['username'] = None
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE user_reputations SET reputation = 1 WHERE client_identifier = ?', (client_identifier,))
            cursor.execute('UPDATE users SET reputation = 1 WHERE client_identifier = ?', (client_identifier,))
            conn.commit()

    def increment_violation(self, client_identifier):
        if client_identifier not in self.violation_counts:
            self.violation_counts[client_identifier] = 0
        self.violation_counts[client_identifier] += 1
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE user_reputations SET violation_count = violation_count + 1 WHERE client_identifier = ?',
                           (client_identifier,))
            conn.commit()
        return self.violation_counts[client_identifier]

    def extract_app_name(self, title):
        match = re.search(r'\(HPS!api\)\{app\}:\{"([^"]+)"\}', title)
        if match:
            return match.group(1).strip()
        return None

    def process_app_update(self, content_item, cursor, username, content_hash):
        app_name = self.extract_app_name(content_item['title'])
        if not app_name:
            return False, "Invalid app name format"

        cursor.execute('SELECT username, content_hash FROM api_apps WHERE app_name = ?', (app_name,))
        existing_app = cursor.fetchone()

        if existing_app:
            if existing_app[0] != username:
                return False, f"API app '{app_name}' is owned by {existing_app[0]}. Only the owner can update."

            old_hash = existing_app[1]

            if old_hash != content_hash:
                cursor.execute('UPDATE dns_records SET content_hash = ? WHERE content_hash = ?', (content_hash, old_hash))

                cursor.execute('INSERT OR REPLACE INTO content_redirects (old_hash, new_hash, username, redirect_type, timestamp) VALUES (?, ?, ?, ?, ?)',
                               (old_hash, content_hash, username, 'app_update', time.time()))

                cursor.execute('SELECT 1 FROM dns_records WHERE content_hash = ?', (old_hash,))
                dns_using = cursor.fetchone()
                cursor.execute('SELECT 1 FROM client_files WHERE content_hash = ?', (old_hash,))
                client_using = cursor.fetchone()

                if not dns_using and not client_using:
                    cursor.execute('DELETE FROM content WHERE content_hash = ?', (old_hash,))
                    cursor.execute('DELETE FROM content_availability WHERE content_hash = ?', (old_hash,))
                    cursor.execute('DELETE FROM client_files WHERE content_hash = ?', (old_hash,))
                    cursor.execute('DELETE FROM content_redirects WHERE old_hash = ?', (old_hash,))
                    old_file_path = os.path.join(self.files_dir, f"{old_hash}.dat")
                    if os.path.exists(old_file_path):
                        os.remove(old_file_path)

                cursor.execute('UPDATE api_apps SET content_hash = ?, last_updated = ? WHERE app_name = ?',
                               (content_hash, time.time(), app_name))

                cursor.execute('INSERT INTO api_app_versions (version_id, app_name, content_hash, username, timestamp, version_number) VALUES (?, ?, ?, ?, ?, ?)',
                               (str(uuid.uuid4()), app_name, content_hash, username, time.time(),
                                cursor.execute('SELECT COALESCE(MAX(version_number), 0) + 1 FROM api_app_versions WHERE app_name = ?', (app_name,)).fetchone()[0]))

                return True, f"App '{app_name}' updated from {old_hash} to {content_hash}"
        else:
            cursor.execute('INSERT INTO api_apps (app_name, username, content_hash, timestamp, last_updated) VALUES (?, ?, ?, ?, ?)',
                           (app_name, username, content_hash, time.time(), time.time()))
            cursor.execute('INSERT INTO api_app_versions (version_id, app_name, content_hash, username, timestamp, version_number) VALUES (?, ?, ?, ?, ?, ?)',
                           (str(uuid.uuid4()), app_name, content_hash, username, time.time(), 1))
            return True, f"New app '{app_name}' registered"

        return True, "App already up to date"

    def get_redirected_hash(self, old_hash):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT new_hash FROM content_redirects WHERE old_hash = ?', (old_hash,))
            row = cursor.fetchone()
            if row:
                return row[0]
        return None

    def setup_handlers(self):
        @self.sio.event
        async def connect(sid, environ):
            logger.info(f"Client connected: {sid}")
            self.connected_clients[sid] = {
                'authenticated': False, 'username': None, 'node_id': None, 'address': None,
                'public_key': None, 'node_type': None, 'client_identifier': None,
                'pow_solved': False, 'server_authenticated': False, 'connect_time': time.time()
            }
            await self.sio.emit('status', {'message': 'Connected to HPS network'}, room=sid)
            await self.sio.emit('request_server_auth_challenge', {}, room=sid)

        @self.sio.event
        async def disconnect(sid):
            logger.info(f"Client disconnected: {sid}")
            if sid in self.connected_clients:
                client_info = self.connected_clients[sid]
                if client_info['authenticated']:
                    username = client_info['username']
                    if username in self.authenticated_users and self.authenticated_users[username]['sid'] == sid:
                        del self.authenticated_users[username]
                    if client_info['node_id']:
                        self.mark_node_offline(client_info['node_id'])
                del self.connected_clients[sid]
            await self.broadcast_network_state()

        @self.sio.event
        async def request_server_auth_challenge(sid, data):
            challenge = secrets.token_urlsafe(32)
            self.server_auth_challenges[sid] = {'challenge': challenge, 'timestamp': time.time()}
            challenge_signature = self.private_key.sign(challenge.encode('utf-8'),
                                                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            await self.sio.emit('server_auth_challenge', {
                'challenge': challenge, 'server_public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
                'signature': base64.b64encode(challenge_signature).decode('utf-8')}, room=sid)

        @self.sio.event
        async def verify_server_auth_response(sid, data):
            client_challenge = data.get('client_challenge')
            client_signature = data.get('client_signature')
            client_public_key_b64 = data.get('client_public_key')
            if sid not in self.server_auth_challenges:
                await self.sio.emit('server_auth_result', {'success': False, 'error': 'Invalid or expired server auth challenge'}, room=sid)
                return
            challenge_data = self.server_auth_challenges.pop(sid)
            try:
                client_public_key = serialization.load_pem_public_key(base64.b64decode(client_public_key_b64), backend=default_backend())
                client_signature_bytes = base64.b64decode(client_signature)
                client_public_key.verify(client_signature_bytes, client_challenge.encode('utf-8'),
                                         padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                self.connected_clients[sid]['server_authenticated'] = True
                self.connected_clients[sid]['client_public_key'] = client_public_key_b64
                await self.sio.emit('server_auth_result', {'success': True, 'client_challenge': client_challenge}, room=sid)
            except InvalidSignature:
                logger.warning(f"Failed to verify client signature for {sid}")
                await self.sio.emit('server_auth_result', {'success': False, 'error': 'Invalid client signature'}, room=sid)
            except Exception as e:
                logger.error(f"Server auth verification error for {sid}: {e}")
                await self.sio.emit('server_auth_result', {'success': False, 'error': f'Internal server auth error: {str(e)}'}, room=sid)

        @self.sio.event
        async def request_pow_challenge(sid, data):
            try:
                if not self.connected_clients[sid].get('server_authenticated'):
                    await self.sio.emit('pow_challenge', {'error': 'Server not authenticated'}, room=sid)
                    return
                client_identifier = data.get('client_identifier', '')
                action_type = data.get('action_type', 'login')
                if not client_identifier:
                    await self.sio.emit('pow_challenge', {'error': 'Client identifier required'}, room=sid)
                    return
                allowed, message, remaining_time = self.check_rate_limit(client_identifier, action_type)
                if not allowed:
                    await self.sio.emit('pow_challenge', {'error': message, 'blocked_until': time.time() + remaining_time}, room=sid)
                    return
                challenge_data = self.generate_pow_challenge(client_identifier, action_type)
                await self.sio.emit('pow_challenge', challenge_data, room=sid)
            except Exception as e:
                logger.error(f"PoW challenge error for {sid}: {e}")
                await self.sio.emit('pow_challenge', {'error': str(e)}, room=sid)

        @self.sio.event
        async def authenticate(sid, data):
            try:
                if not self.connected_clients[sid].get('server_authenticated'):
                    await self.sio.emit('authentication_result', {'success': False, 'error': 'Server not authenticated'}, room=sid)
                    return
                username = data.get('username', '').strip()
                password_hash = data.get('password_hash', '').strip()
                public_key_b64 = data.get('public_key', '').strip()
                node_type = data.get('node_type', 'client')
                client_identifier = data.get('client_identifier', '')
                pow_nonce = data.get('pow_nonce', '')
                hashrate_observed = data.get('hashrate_observed', 0.0)
                client_challenge_signature = data.get('client_challenge_signature')
                client_challenge = data.get('client_challenge')
                if not all([username, password_hash, public_key_b64, client_identifier, client_challenge_signature, client_challenge]):
                    await self.sio.emit('authentication_result', {'success': False, 'error': 'Missing credentials or challenge signature'}, room=sid)
                    return
                if not self.verify_pow_solution(client_identifier, pow_nonce, hashrate_observed, "login"):
                    await self.sio.emit('authentication_result', {'success': False, 'error': 'Invalid PoW solution'}, room=sid)
                    await self.ban_client(client_identifier, duration=300, reason="Invalid PoW solution")
                    return
                allowed, message, remaining_time = self.check_rate_limit(client_identifier, "login")
                if not allowed:
                    await self.sio.emit('authentication_result', {'success': False, 'error': message, 'blocked_until': time.time() + remaining_time}, room=sid)
                    return
                try:
                    public_key = base64.b64decode(public_key_b64)
                    client_public_key_obj = serialization.load_pem_public_key(public_key, backend=default_backend())
                except Exception as e:
                    await self.sio.emit('authentication_result', {'success': False, 'error': f'Invalid public key: {str(e)}'}, room=sid)
                    await self.ban_client(client_identifier, duration=300, reason="Invalid public key format")
                    return
                stored_client_key = self.connected_clients[sid].get('client_public_key')
                if stored_client_key != public_key_b64:
                    await self.sio.emit('authentication_result', {'success': False, 'error': 'Public key does not match server authentication'}, room=sid)
                    return
                try:
                    client_signature_bytes = base64.b64decode(client_challenge_signature)
                    client_public_key_obj.verify(client_signature_bytes, client_challenge.encode('utf-8'),
                                                 padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                except InvalidSignature:
                    logger.warning(f"Failed to verify client challenge signature for {sid}")
                    await self.sio.emit('authentication_result', {'success': False, 'error': 'Invalid client challenge signature'}, room=sid)
                    return
                except Exception as e:
                    logger.error(f"Client challenge signature verification error for {sid}: {e}")
                    await self.sio.emit('authentication_result', {'success': False, 'error': f'Internal client challenge signature error: {str(e)}'}, room=sid)
                    return
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT password_hash, public_key, reputation FROM users WHERE username = ?', (username,))
                    row = cursor.fetchone()
                    reputation = 100
                    if row:
                        stored_hash, stored_key, rep = row
                        reputation = rep
                        if stored_hash == password_hash:
                            cursor.execute('UPDATE users SET last_login = ?, public_key = ?, client_identifier = ?, last_activity = ? WHERE username = ?',
                                           (time.time(), public_key_b64, client_identifier, time.time(), username))
                            conn.commit()
                            self.connected_clients[sid]['authenticated'] = True
                            self.connected_clients[sid]['username'] = username
                            self.connected_clients[sid]['public_key'] = public_key_b64
                            self.connected_clients[sid]['node_type'] = node_type
                            self.connected_clients[sid]['client_identifier'] = client_identifier
                            self.connected_clients[sid]['pow_solved'] = True
                            self.authenticated_users[username] = {
                                'sid': sid, 'public_key': public_key_b64, 'node_type': node_type, 'client_identifier': client_identifier
                            }
                            await self.sio.emit('authentication_result', {'success': True, 'username': username, 'reputation': reputation}, room=sid)
                            logger.info(f"User authenticated: {username}")
                            await self.sync_client_files(client_identifier, sid)
                            server_list = []
                            with sqlite3.connect(self.db_path) as conn:
                                cursor = conn.cursor()
                                cursor.execute('SELECT address, public_key, last_seen, reputation FROM server_nodes WHERE is_active = 1 ORDER BY reputation DESC')
                                for row in cursor.fetchall():
                                    server_list.append({'address': row[0], 'public_key': row[1], 'last_seen': row[2], 'reputation': row[3]})
                            await self.sio.emit('server_list', {'servers': server_list}, room=sid)
                            backup_server = await self.select_backup_server()
                            if backup_server:
                                await self.sio.emit('backup_server', {'server': backup_server, 'timestamp': time.time()}, room=sid)
                        else:
                            await self.sio.emit('authentication_result', {'success': False, 'error': 'Invalid password'}, room=sid)
                            violation_count = self.increment_violation(client_identifier)
                            if violation_count >= 3:
                                await self.ban_client(client_identifier, duration=300, reason="Multiple invalid passwords")
                    else:
                        cursor.execute('SELECT reputation FROM user_reputations WHERE client_identifier = ?', (client_identifier,))
                        rep_row = cursor.fetchone()
                        if rep_row: reputation = rep_row[0]
                        else: reputation = 100
                        cursor.execute('''INSERT INTO users
(username, password_hash, public_key, created_at, last_login, reputation, client_identifier, last_activity)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                            (username, password_hash, public_key_b64, time.time(), time.time(), reputation, client_identifier, time.time()))
                        cursor.execute('''INSERT OR REPLACE INTO user_reputations
                            (username, reputation, last_updated, client_identifier) VALUES (?, ?, ?, ?)''',
                            (username, reputation, time.time(), client_identifier))
                        conn.commit()
                        self.connected_clients[sid]['authenticated'] = True
                        self.connected_clients[sid]['username'] = username
                        self.connected_clients[sid]['public_key'] = public_key_b64
                        self.connected_clients[sid]['node_type'] = node_type
                        self.connected_clients[sid]['client_identifier'] = client_identifier
                        self.connected_clients[sid]['pow_solved'] = True
                        self.authenticated_users[username] = {
                            'sid': sid, 'public_key': public_key_b64, 'node_type': node_type, 'client_identifier': client_identifier
                        }
                        await self.sio.emit('authentication_result', {'success': True, 'username': username, 'reputation': reputation}, room=sid)
                        logger.info(f"New user registered: {username}")
                        server_list = []
                        with sqlite3.connect(self.db_path) as conn:
                            cursor = conn.cursor()
                            cursor.execute('SELECT address, public_key, last_seen, reputation FROM server_nodes WHERE is_active = 1 ORDER BY reputation DESC')
                            for row in cursor.fetchall():
                                server_list.append({'address': row[0], 'public_key': row[1], 'last_seen': row[2], 'reputation': row[3]})
                        await self.sio.emit('server_list', {'servers': server_list}, room=sid)
                        backup_server = await self.select_backup_server()
                        if backup_server:
                            await self.sio.emit('backup_server', {'server': backup_server, 'timestamp': time.time()}, room=sid)
                self.update_rate_limit(client_identifier, "login")
            except Exception as e:
                logger.error(f"Authentication error for {sid}: {e}")
                await self.sio.emit('authentication_result', {'success': False, 'error': f'Internal server error: {str(e)}'}, room=sid)

        @self.sio.event
        async def join_network(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']:
                    await self.sio.emit('network_joined', {'success': False, 'error': 'Not authenticated'}, room=sid)
                    return
                node_id = data.get('node_id')
                address = data.get('address')
                public_key_b64 = data.get('public_key')
                username = data.get('username')
                node_type = data.get('node_type', 'client')
                client_identifier = data.get('client_identifier', '')
                if not all([node_id, address, public_key_b64, username]):
                    await self.sio.emit('network_joined', {'success': False, 'error': 'Missing node information'}, room=sid)
                    return
                try:
                    public_key = base64.b64decode(public_key_b64)
                    serialization.load_pem_public_key(public_key, backend=default_backend())
                except Exception as e:
                    await self.sio.emit('network_joined', {'success': False, 'error': f'Invalid public key: {str(e)}'}, room=sid)
                    return
                self.connected_clients[sid]['node_id'] = node_id
                self.connected_clients[sid]['address'] = address
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT reputation FROM user_reputations WHERE username = ?', (username,))
                    rep_row = cursor.fetchone()
                    reputation = rep_row[0] if rep_row else 100
                    cursor.execute('SELECT connection_count FROM network_nodes WHERE node_id = ?', (node_id,))
                    node_row = cursor.fetchone()
                    connection_count = 1
                    if node_row: connection_count = node_row[0] + 1
                    cursor.execute('''INSERT OR REPLACE INTO network_nodes
(node_id, address, public_key, username, last_seen, reputation, node_type, is_online, client_identifier, connection_count)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                        (node_id, address, public_key_b64, username, time.time(), reputation, node_type, 1, client_identifier, connection_count))
                    conn.commit()
                await self.sio.emit('network_joined', {'success': True}, room=sid)
                await self.broadcast_network_state()
                logger.info(f"Node joined network: {node_id} ({username}) - Type: {node_type}")
            except Exception as e:
                logger.error(f"Network join error for {sid}: {e}")
                await self.sio.emit('network_joined', {'success': False, 'error': f'Internal server error: {str(e)}'}, room=sid)

        @self.sio.event
        async def search_content(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']:
                    await self.sio.emit('search_results', {'error': 'Not authenticated'}, room=sid)
                    return
                query = data.get('query', '')
                limit = data.get('limit', 50)
                offset = data.get('offset', 0)
                content_type = data.get('content_type', '')
                sort_by = data.get('sort_by', 'reputation')

                if query.startswith('(HPS!api)'):
                    app_name = self.extract_app_name(query)
                    if app_name:
                        with sqlite3.connect(self.db_path) as conn:
                            cursor = conn.cursor()
                            cursor.execute('''SELECT c.content_hash, c.title, c.description, c.mime_type, c.size,
c.username, c.signature, c.public_key, c.verified, c.replication_count,
COALESCE(u.reputation, 100) as reputation
FROM api_apps a
JOIN content c ON a.content_hash = c.content_hash
LEFT JOIN user_reputations u ON c.username = u.username
                                WHERE a.app_name = ?''', (app_name,))
                            row = cursor.fetchone()
                            results = []
                            if row:
                                results.append({
                                    'content_hash': row[0], 'title': row[1], 'description': row[2], 'mime_type': row[3], 'size': row[4],
                                    'username': row[5], 'signature': row[6], 'public_key': row[7], 'verified': bool(row[8]),
                                    'replication_count': row[9], 'reputation': row[10]
                                })
                            await self.sio.emit('search_results', {'results': results}, room=sid)
                            return

                order_clause = ""
                if sort_by == "reputation": order_clause = "ORDER BY COALESCE(u.reputation, 100) DESC, c.verified DESC, c.replication_count DESC"
                elif sort_by == "recent": order_clause = "ORDER BY c.timestamp DESC"
                elif sort_by == "popular": order_clause = "ORDER BY c.replication_count DESC, c.last_accessed DESC"
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    query_params = []
                    where_clauses = []
                    if query:
                        where_clauses.append("(c.title LIKE ? OR c.description LIKE ? OR c.content_hash LIKE ? OR c.username LIKE ?)")
                        query_params.extend([f'%{query}%', f'%{query}%', f'%{query}%', f'%{query}%'])
                    if content_type:
                        where_clauses.append("c.mime_type LIKE ?")
                        query_params.append(f'%{content_type}%')
                    where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
                    sql_query = f'''
SELECT c.content_hash, c.title, c.description, c.mime_type, c.size,
c.username, c.signature, c.public_key, c.verified, c.replication_count,
COALESCE(u.reputation, 100) as reputation
FROM content c
LEFT JOIN user_reputations u ON c.username = u.username
                        {where_sql}
                        {order_clause}
LIMIT ? OFFSET ?
                        '''
                    query_params.extend([limit, offset])
                    cursor.execute(sql_query, tuple(query_params))
                    rows = cursor.fetchall()
                results = []
                for row in rows:
                    results.append({
                        'content_hash': row[0], 'title': row[1], 'description': row[2], 'mime_type': row[3], 'size': row[4],
                        'username': row[5], 'signature': row[6], 'public_key': row[7], 'verified': bool(row[8]),
                        'replication_count': row[9], 'reputation': row[10]
                    })
                await self.sio.emit('search_results', {'results': results}, room=sid)
                logger.info(f"Search by {self.connected_clients[sid].get('username', 'Unknown')}: '{query}' -> {len(results)} results")
            except Exception as e:
                logger.error(f"Search error for {sid}: {e}")
                await self.sio.emit('search_results', {'error': f'Search failed: {str(e)}'}, room=sid)

        @self.sio.event
        async def publish_content(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']:
                    await self.sio.emit('publish_result', {'success': False, 'error': 'Not authenticated'}, room=sid)
                    return
                client_info = self.connected_clients[sid]
                client_identifier = client_info['client_identifier']
                username = client_info['username']
                pow_nonce = data.get('pow_nonce', '')
                hashrate_observed = data.get('hashrate_observed', 0.0)
                if not self.verify_pow_solution(client_identifier, pow_nonce, hashrate_observed, "upload"):
                    await self.sio.emit('publish_result', {'success': False, 'error': 'Invalid PoW solution'}, room=sid)
                    await self.ban_client(client_identifier, duration=300, reason="Invalid PoW solution")
                    return
                allowed, message, remaining_time = self.check_rate_limit(client_identifier, "upload")
                if not allowed:
                    violation_count = self.increment_violation(client_identifier)
                    if violation_count >= 3:
                        await self.ban_client(client_identifier, duration=300, reason="Multiple rate limit violations")
                    await self.sio.emit('publish_result', {'success': False, 'error': message, 'blocked_until': time.time() + remaining_time}, room=sid)
                    return
                content_hash = data.get('content_hash')
                title = data.get('title')
                description = data.get('description', '')
                mime_type = data.get('mime_type')
                size = data.get('size')
                signature = data.get('signature')
                public_key_b64 = data.get('public_key')
                content_b64 = data.get('content_b64')
                if not all([content_hash, title, mime_type, size, signature, public_key_b64, content_b64]):
                    await self.sio.emit('publish_result', {'success': False, 'error': 'Missing required fields'}, room=sid)
                    return
                try:
                    content = base64.b64decode(content_b64)
                except Exception as e:
                    await self.sio.emit('publish_result', {'success': False, 'error': 'Invalid base64 content'}, room=sid)
                    return
                actual_hash = hashlib.sha256(content).hexdigest()
                if actual_hash != content_hash:
                    await self.sio.emit('publish_result', {'success': False, 'error': 'Content hash mismatch'}, room=sid)
                    return

                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()

                    if title.startswith('(HPS!api)'):
                        app_name = self.extract_app_name(title)
                        if app_name:
                            success, message = self.process_app_update({'title': title}, cursor, username, content_hash)
                            if not success:
                                await self.sio.emit('publish_result', {'success': False, 'error': message}, room=sid)
                                if os.path.exists(file_path):
                                    os.remove(file_path)
                                return
                            conn.commit()

                    elif title == '(HPS!dns_change){change_dns_owner=true, proceed=true}':
                        try:
                            content_str = content.decode('utf-8')
                            if not content_str.startswith('# HSYST P2P SERVICE'):
                                await self.sio.emit('publish_result', {'success': False, 'error': 'Missing HSYST header in DNS change file'}, room=sid)
                                return
                            if '### MODIFY:' not in content_str or '# change_dns_owner = true' not in content_str:
                                await self.sio.emit('publish_result', {'success': False, 'error': 'Invalid DNS change file format'}, room=sid)
                                return
                            lines = content_str.splitlines()
                            domain = None
                            new_owner = None
                            in_dns_section = False
                            for line in lines:
                                line = line.strip()
                                if line == '### DNS:':
                                    in_dns_section = True
                                    continue
                                if line == '### :END DNS':
                                    in_dns_section = False
                                    continue
                                if in_dns_section and line.startswith('# NEW_DNAME:'):
                                    parts = line.split('=')
                                    if len(parts) == 2:
                                        domain = parts[1].strip()
                                if line.startswith('# NEW_DOWNER:'):
                                    parts = line.split('=')
                                    if len(parts) == 2:
                                        new_owner = parts[1].strip()
                            if not domain or not new_owner:
                                await self.sio.emit('publish_result', {'success': False, 'error': 'Missing domain or new owner in DNS change file'}, room=sid)
                                return
                            cursor.execute('SELECT username, original_owner FROM dns_records WHERE domain = ?', (domain,))
                            dns_record = cursor.fetchone()
                            if not dns_record:
                                await self.sio.emit('publish_result', {'success': False, 'error': f'Domain {domain} not found'}, room=sid)
                                return
                            current_owner, original_owner = dns_record
                            if current_owner != username:
                                await self.sio.emit('publish_result', {
                                    'success': False,
                                    'error': f'You are not the current owner of domain {domain}. Current owner: {current_owner}'
                                }, room=sid)
                                return
                            cursor.execute('UPDATE dns_records SET username = ?, original_owner = ? WHERE domain = ?',
                                           (new_owner, new_owner, domain))
                            change_id = str(uuid.uuid4())
                            cursor.execute('INSERT INTO dns_owner_changes (change_id, domain, previous_owner, new_owner, changer, timestamp, change_file_hash) VALUES (?, ?, ?, ?, ?, ?, ?)',
                                           (change_id, domain, current_owner, new_owner, username, time.time(), content_hash))
                            conn.commit()
                            logger.info(f"DNS ownership transferred: {domain} from {current_owner} to {new_owner} by {username}")
                        except Exception as e:
                            logger.error(f"DNS change processing error: {e}")
                            await self.sio.emit('publish_result', {'success': False, 'error': f'DNS change processing error: {str(e)}'}, room=sid)
                            return

                    file_path = os.path.join(self.files_dir, f"{content_hash}.dat")
                    try:
                        async with aiofiles.open(file_path, 'wb') as f:
                            await f.write(content)
                    except Exception as e:
                        await self.sio.emit('publish_result', {'success': False, 'error': f'Error saving file: {str(e)}'}, room=sid)
                        return

                    cursor.execute('SELECT COUNT(*) FROM content WHERE username = ?', (username,))
                    content_count = cursor.fetchone()[0]
                    if content_count >= self.max_content_per_user:
                        await self.sio.emit('publish_result', {'success': False, 'error': f'Maximum content limit reached ({self.max_content_per_user})'}, room=sid)
                        if os.path.exists(file_path):
                            os.remove(file_path)
                        return
                    cursor.execute('SELECT disk_quota, used_disk_space FROM users WHERE username = ?', (username,))
                    user_quota_row = cursor.fetchone()
                    if user_quota_row:
                        disk_quota, used_disk_space = user_quota_row
                        if (used_disk_space + size) > disk_quota:
                            await self.sio.emit('publish_result', {'success': False, 'error': f'Disk quota exceeded. Available space: {(disk_quota - used_disk_space) / (1024*1024):.2f}MB'}, room=sid)
                            if os.path.exists(file_path):
                                os.remove(file_path)
                            return

                    verified = 1
                    cursor.execute('''INSERT OR REPLACE INTO content
(content_hash, title, description, mime_type, size, username, signature, public_key, timestamp, file_path, verified, last_accessed)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                        (content_hash, title, description, mime_type, size, username, signature, public_key_b64, time.time(), file_path, verified, time.time()))
                    cursor.execute('INSERT OR REPLACE INTO content_availability (content_hash, node_id, timestamp, is_primary) VALUES (?, ?, ?, ?)',
                                   (content_hash, self.connected_clients[sid]['node_id'], time.time(), 1))
                    cursor.execute('UPDATE users SET used_disk_space = used_disk_space + ? WHERE username = ?', (size, username))
                    conn.commit()
                await self.sio.emit('publish_result', {'success': True, 'content_hash': content_hash, 'verified': 1}, room=sid)
                self.update_rate_limit(client_identifier, "upload")
                logger.info(f"Content published: {content_hash} by {username}")
                if not title.startswith('(HPS!api)') and title != '(HPS!dns_change){change_dns_owner=true, proceed=true}':
                    await self.propagate_content_to_network(content_hash)
            except Exception as e:
                logger.error(f"Content publish error for {sid}: {e}")
                await self.sio.emit('publish_result', {'success': False, 'error': f'Internal server error: {str(e)}'}, room=sid)

        @self.sio.event
        async def request_content(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']:
                    await self.sio.emit('content_response', {'error': 'Not authenticated'}, room=sid)
                    return
                content_hash = data.get('content_hash')
                if not content_hash:
                    await self.sio.emit('content_response', {'error': 'Missing content hash'}, room=sid)
                    return

                redirected_hash = self.get_redirected_hash(content_hash)
                if redirected_hash:
                    message = f'Arquivo desatualizado, Novo Hash: {redirected_hash}'
                    await self.sio.emit('content_response', {
                        'success': True,
                        'content': base64.b64encode(message.encode('utf-8')).decode('utf-8'),
                        'title': 'Redirecionamento',
                        'description': 'Este arquivo foi atualizado',
                        'mime_type': 'text/plain',
                        'username': 'system',
                        'signature': '',
                        'public_key': '',
                        'verified': 0,
                        'content_hash': content_hash,
                        'reputation': 0
                    }, room=sid)
                    return

                file_path = os.path.join(self.files_dir, f"{content_hash}.dat")
                content_metadata = None
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''SELECT title, description, mime_type, username, signature, public_key, verified, size
                        FROM content WHERE content_hash = ?''', (content_hash,))
                    content_metadata = cursor.fetchone()
                    if not content_metadata:
                        cursor.execute('SELECT content_hash FROM dns_records WHERE domain = ?', (content_hash,))
                        dns_redirect = cursor.fetchone()
                        if dns_redirect:
                            new_hash = dns_redirect[0]
                            cursor.execute('''SELECT title, description, mime_type, username, signature, public_key, verified, size
                                FROM content WHERE content_hash = ?''', (new_hash,))
                            content_metadata = cursor.fetchone()
                            if content_metadata:
                                content_hash = new_hash
                                file_path = os.path.join(self.files_dir, f"{new_hash}.dat")
                if not os.path.exists(file_path):
                    logger.info(f"Content {content_hash} not found locally, searching network.")
                    await self.sio.emit('content_search_status', {'status': 'searching_network', 'content_hash': content_hash}, room=sid)
                    content_found = await self.fetch_content_from_network(content_hash)
                    if not content_found:
                        await self.sio.emit('content_response', {'success': False, 'error': 'Content not found in network'}, room=sid)
                        return
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('''SELECT title, description, mime_type, username, signature, public_key, verified, size
                            FROM content WHERE content_hash = ?''', (content_hash,))
                        content_metadata = cursor.fetchone()
                if not content_metadata:
                    await self.sio.emit('content_response', {'success': False, 'error': 'Content metadata not found'}, room=sid)
                    return
                try:
                    async with aiofiles.open(file_path, 'rb') as f:
                        content = await f.read()
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('UPDATE content SET last_accessed = ?, replication_count = replication_count + 1 WHERE content_hash = ?',
                                       (time.time(), content_hash))
                        conn.commit()
                    title, description, mime_type, username, signature, public_key, verified, size = content_metadata
                    await self.sio.emit('content_response', {
                        'success': True, 'content': base64.b64encode(content).decode('utf-8'), 'title': title,
                        'description': description, 'mime_type': mime_type, 'username': username, 'signature': signature,
                        'public_key': public_key, 'verified': verified, 'content_hash': content_hash,
                        'reputation': self.get_user_reputation(username)
                    }, room=sid)
                except Exception as e:
                    logger.error(f"Failed to read content {content_hash} for {sid}: {e}")
                    await self.sio.emit('content_response', {'success': False, 'error': f'Failed to read content: {str(e)}'}, room=sid)
            except Exception as e:
                logger.error(f"Content request error for {sid}: {e}")
                await self.sio.emit('content_response', {'success': False, 'error': f'Internal server error: {str(e)}'}, room=sid)

        @self.sio.event
        async def register_dns(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']:
                    await self.sio.emit('dns_result', {'success': False, 'error': 'Not authenticated'}, room=sid)
                    return
                client_info = self.connected_clients[sid]
                client_identifier = client_info['client_identifier']
                username = client_info['username']
                pow_nonce = data.get('pow_nonce', '')
                hashrate_observed = data.get('hashrate_observed', 0.0)
                if not self.verify_pow_solution(client_identifier, pow_nonce, hashrate_observed, "dns"):
                    await self.sio.emit('dns_result', {'success': False, 'error': 'Invalid PoW solution'}, room=sid)
                    await self.ban_client(client_identifier, duration=300, reason="Invalid PoW solution")
                    return
                allowed, message, remaining_time = self.check_rate_limit(client_identifier, "dns")
                if not allowed:
                    violation_count = self.increment_violation(client_identifier)
                    if violation_count >= 3:
                        await self.ban_client(client_identifier, duration=300, reason="Multiple rate limit violations")
                    await self.sio.emit('dns_result', {'success': False, 'error': message, 'blocked_until': time.time() + remaining_time}, room=sid)
                    return
                domain = data.get('domain', '').lower().strip()
                ddns_content_b64 = data.get('ddns_content', '')
                signature = data.get('signature', '')
                if not all([domain, ddns_content_b64, signature]):
                    await self.sio.emit('dns_result', {'success': False, 'error': 'Missing domain, ddns content or signature'}, room=sid)
                    return
                if not self.is_valid_domain(domain):
                    await self.sio.emit('dns_result', {'success': False, 'error': 'Invalid domain'}, room=sid)
                    return
                try:
                    ddns_content = base64.b64decode(ddns_content_b64)
                except Exception as e:
                    await self.sio.emit('dns_result', {'success': False, 'error': 'Invalid base64 ddns content'}, room=sid)
                    return
                ddns_hash = hashlib.sha256(ddns_content).hexdigest()
                if not ddns_content.startswith(b'# HSYST P2P SERVICE'):
                    await self.sio.emit('dns_result', {'success': False, 'error': 'Missing HSYST header in ddns file'}, room=sid)
                    return
                header_end = b'### :END START'
                if header_end not in ddns_content:
                    await self.sio.emit('dns_result', {'success': False, 'error': 'Invalid HSYST header format in ddns file'}, room=sid)
                    return
                header_part, ddns_data_signed = ddns_content.split(header_end, 1)
                try:
                    public_key = client_info['public_key']
                    public_key_obj = serialization.load_pem_public_key(base64.b64decode(public_key), backend=default_backend())
                    signature_bytes = base64.b64decode(signature)
                    public_key_obj.verify(signature_bytes, ddns_data_signed,
                                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                    verified = 1
                except InvalidSignature:
                    verified = 0
                    logger.warning(f"Invalid signature for DNS {domain} by {username}")
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('UPDATE user_reputations SET reputation = MAX(1, reputation - 5) WHERE username = ?', (username,))
                        cursor.execute('SELECT reputation FROM user_reputations WHERE username = ?', (username,))
                        rep_row = cursor.fetchone()
                        new_reputation = rep_row[0] if rep_row else 50
                        conn.commit()
                    await self.sio.emit('reputation_update', {'reputation': new_reputation}, room=sid)
                except Exception as e:
                    logger.error(f"Signature verification failed for DNS {domain}: {e}")
                    await self.sio.emit('dns_result', {'success': False, 'error': f'Signature verification failed: {str(e)}'}, room=sid)
                    return
                ddns_file_path = os.path.join(self.files_dir, f"{ddns_hash}.ddns")
                try:
                    async with aiofiles.open(ddns_file_path, 'wb') as f:
                        await f.write(ddns_content)
                except Exception as e:
                    await self.sio.emit('dns_result', {'success': False, 'error': f'Error saving ddns file: {str(e)}'}, room=sid)
                    return
                content_hash = self.extract_content_hash_from_ddns(ddns_content)
                if not content_hash:
                    await self.sio.emit('dns_result', {'success': False, 'error': 'Could not extract content hash from ddns file'}, room=sid)
                    return
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT username FROM dns_records WHERE domain = ?', (domain,))
                    existing_record = cursor.fetchone()
                    if existing_record:
                        existing_owner = existing_record[0]
                        if existing_owner != username:
                            await self.sio.emit('dns_result', {
                                'success': False,
                                'error': f'Domain "{domain}" is already registered by {existing_owner}. Domains are non-transferable via regular registration.'
                            }, room=sid)
                            violation_count = self.increment_violation(client_identifier)
                            if violation_count >= 3:
                                await self.ban_client(client_identifier, duration=600, reason="Multiple domain takeover attempts")
                            return
                        cursor.execute('SELECT COUNT(*) FROM dns_records WHERE username = ?', (username,))
                        dns_count = cursor.fetchone()[0]
                        if dns_count >= self.max_dns_per_user:
                            await self.sio.emit('dns_result', {
                                'success': False,
                                'error': f'Maximum DNS records limit reached ({self.max_dns_per_user})'
                            }, room=sid)
                            return
                        cursor.execute('''UPDATE dns_records SET
content_hash = ?, username = ?, timestamp = ?, signature = ?, verified = ?, last_resolved = ?, ddns_hash = ?
                            WHERE domain = ?''',
                            (content_hash, username, time.time(), signature, verified, time.time(), ddns_hash, domain))
                    else:
                        cursor.execute('SELECT COUNT(*) FROM dns_records WHERE username = ?', (username,))
                        dns_count = cursor.fetchone()[0]
                        if dns_count >= self.max_dns_per_user:
                            await self.sio.emit('dns_result', {
                                'success': False,
                                'error': f'Maximum DNS records limit reached ({self.max_dns_per_user})'
                            }, room=sid)
                            return
                        cursor.execute('''INSERT INTO dns_records
(domain, content_hash, username, original_owner, timestamp, signature, verified, last_resolved, ddns_hash)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                            (domain, content_hash, username, username, time.time(), signature, verified, time.time(), ddns_hash))
                    if verified == 1:
                        cursor.execute('UPDATE user_reputations SET reputation = MIN(100, reputation + 1) WHERE username = ?', (username,))
                        cursor.execute('SELECT reputation FROM user_reputations WHERE username = ?', (username,))
                        rep_row = cursor.fetchone()
                        new_reputation = rep_row[0] if rep_row else 100
                        conn.commit()
                        await self.sio.emit('reputation_update', {'reputation': new_reputation}, room=sid)
                    conn.commit()
                await self.sio.emit('dns_result', {'success': True, 'domain': domain, 'verified': verified, 'original_owner': username}, room=sid)
                self.update_rate_limit(client_identifier, "dns")
                logger.info(f"DNS registered: {domain} -> {content_hash} by {username} (verified: {verified})")
                await self.propagate_dns_to_network(domain)
            except Exception as e:
                logger.error(f"DNS register error for {sid}: {e}")
                await self.sio.emit('dns_result', {'success': False, 'error': f'Internal server error: {str(e)}'}, room=sid)

        @self.sio.event
        async def resolve_dns(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']:
                    await self.sio.emit('dns_resolution', {'success': False, 'error': 'Not authenticated'}, room=sid)
                    return
                domain = data.get('domain', '').lower().strip()
                if not domain:
                    await self.sio.emit('dns_resolution', {'success': False, 'error': 'Missing domain'}, room=sid)
                    return

                resolved_data = None
                ddns_file_path = None
                ddns_hash = None

                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''SELECT d.content_hash, d.username, d.signature, d.verified, d.ddns_hash, d.original_owner,
COALESCE(u.reputation, 100)
FROM dns_records d
LEFT JOIN user_reputations u ON d.username = u.username
WHERE d.domain = ?
ORDER BY COALESCE(u.reputation, 100) DESC, d.verified DESC
                        LIMIT 1''', (domain,))
                    row = cursor.fetchone()
                    if row:
                        content_hash, username, signature, verified, ddns_hash, original_owner, reputation = row
                        resolved_data = {
                            'content_hash': content_hash, 'username': username, 'signature': signature,
                            'verified': bool(verified), 'ddns_hash': ddns_hash, 'original_owner': original_owner, 'reputation': reputation
                        }
                        cursor.execute('UPDATE dns_records SET last_resolved = ? WHERE domain = ?', (time.time(), domain))
                        conn.commit()

                if resolved_data:
                    ddns_hash = resolved_data['ddns_hash']
                    ddns_file_path = os.path.join(self.files_dir, f"{ddns_hash}.ddns")

                    if not os.path.exists(ddns_file_path):
                        logger.info(f"DDNS file for DNS {domain} not found locally, searching network.")
                        await self.sio.emit('dns_search_status', {'status': 'searching_network', 'domain': domain}, room=sid)
                        ddns_found = await self.fetch_ddns_from_network(domain, ddns_hash)
                        if not ddns_found:
                            await self.sio.emit('dns_resolution', {'success': False, 'error': 'DDNS file not found in network'}, room=sid)
                            return
                        ddns_file_path = os.path.join(self.files_dir, f"{ddns_hash}.ddns")

                    if os.path.exists(ddns_file_path):
                        content_hash = resolved_data['content_hash']
                        file_path = os.path.join(self.files_dir, f"{content_hash}.dat")
                        if not os.path.exists(file_path):
                            logger.info(f"Content for DNS {domain} ({content_hash}) not found locally, searching network.")
                            await self.sio.emit('dns_search_status', {'status': 'searching_network', 'domain': domain}, room=sid)
                            content_found = await self.fetch_content_from_network(content_hash)
                            if not content_found:
                                await self.sio.emit('dns_resolution', {'success': False, 'error': 'Content referenced by domain not found'}, room=sid)
                                return
                        await self.sio.emit('dns_resolution', {
                            'success': True, 'domain': domain, 'content_hash': resolved_data['content_hash'],
                            'username': resolved_data['username'], 'verified': resolved_data['verified'],
                            'original_owner': resolved_data['original_owner']
                        }, room=sid)
                    else:
                        await self.sio.emit('dns_resolution', {'success': False, 'error': 'DDNS file not available'}, room=sid)
                else:
                    logger.info(f"Domain {domain} not found locally, searching network.")
                    await self.sio.emit('dns_search_status', {'status': 'searching_network', 'domain': domain}, room=sid)
                    resolved = await self.resolve_dns_from_network(domain)
                    if resolved and resolved.get('success'):
                        await self.sio.emit('dns_resolution', {
                            'success': True, 'domain': domain, 'content_hash': resolved['content_hash'],
                            'username': resolved['username'], 'verified': resolved['verified'],
                            'original_owner': resolved.get('original_owner', resolved['username'])
                        }, room=sid)
                    else:
                        await self.sio.emit('dns_resolution', {'success': False, 'error': 'Domain not found'}, room=sid)
            except Exception as e:
                logger.error(f"DNS resolution error for {sid}: {e}")
                await self.sio.emit('dns_resolution', {'success': False, 'error': f'Internal server error: {str(e)}'}, room=sid)

        @self.sio.event
        async def report_content(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']:
                    await self.sio.emit('report_result', {'success': False, 'error': 'Not authenticated'}, room=sid)
                    return
                client_info = self.connected_clients[sid]
                client_identifier = client_info['client_identifier']
                reporter = client_info['username']
                pow_nonce = data.get('pow_nonce', '')
                hashrate_observed = data.get('hashrate_observed', 0.0)
                if not self.verify_pow_solution(client_identifier, pow_nonce, hashrate_observed, "report"):
                    await self.sio.emit('report_result', {'success': False, 'error': 'Invalid PoW solution'}, room=sid)
                    await self.ban_client(client_identifier, duration=300, reason="Invalid PoW solution")
                    return
                content_hash = data.get('content_hash')
                reported_user = data.get('reported_user')
                if not content_hash or not reported_user:
                    await self.sio.emit('report_result', {'success': False, 'error': 'Missing hash or user'}, room=sid)
                    return
                if reporter == reported_user:
                    await self.sio.emit('report_result', {'success': False, 'error': 'Cannot report your own content'}, room=sid)
                    return
                report_id = str(uuid.uuid4())
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''INSERT INTO content_reports
(report_id, content_hash, reported_user, reporter, timestamp)
                        VALUES (?, ?, ?, ?, ?)''',
                        (report_id, content_hash, reported_user, reporter, time.time()))
                    conn.commit()
                await self.sio.emit('report_result', {'success': True}, room=sid)
                logger.info(f"Content reported: {content_hash} by {reporter} against {reported_user}")
                await self.process_content_report(report_id, content_hash, reported_user, reporter)
            except Exception as e:
                logger.error(f"Content report error for {sid}: {e}")
                await self.sio.emit('report_result', {'success': False, 'error': f'Internal server error: {str(e)}'}, room=sid)

        @self.sio.event
        async def get_network_state(sid, data):
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT COUNT(*) FROM network_nodes WHERE is_online = 1')
                    online_nodes = cursor.fetchone()[0]
                    cursor.execute('SELECT COUNT(*) FROM content')
                    total_content = cursor.fetchone()[0]
                    cursor.execute('SELECT COUNT(*) FROM dns_records')
                    total_dns = cursor.fetchone()[0]
                    cursor.execute('SELECT node_type, COUNT(*) FROM network_nodes WHERE is_online = 1 GROUP BY node_type')
                    node_types = {}
                    for row in cursor.fetchall():
                        node_types[row[0]] = row[1]
                await self.sio.emit('network_state', {
                    'online_nodes': online_nodes, 'total_content': total_content, 'total_dns': total_dns,
                    'node_types': node_types, 'timestamp': time.time()
                }, room=sid)
            except Exception as e:
                logger.error(f"Network state error for {sid}: {e}")
                await self.sio.emit('network_state', {'error': f'Internal server error: {str(e)}'}, room=sid)

        @self.sio.event
        async def get_servers(sid, data):
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT address, public_key, last_seen, reputation FROM server_nodes WHERE is_active = 1 ORDER BY reputation DESC')
                    rows = cursor.fetchall()
                servers = []
                for row in rows:
                    servers.append({'address': row[0], 'public_key': row[1], 'last_seen': row[2], 'reputation': row[3]})
                await self.sio.emit('server_list', {'servers': servers}, room=sid)
            except Exception as e:
                logger.error(f"Server list error for {sid}: {e}")
                await self.sio.emit('server_list', {'error': f'Internal server error: {str(e)}'}, room=sid)

        @self.sio.event
        async def sync_servers(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']: return
                servers = data.get('servers', [])
                for server in servers:
                    if server not in self.known_servers and server != self.address:
                        self.known_servers.add(server)
                        asyncio.create_task(self.sync_with_server(server))
                self.save_known_servers()
            except Exception as e:
                logger.error(f"Server sync error for {sid}: {e}")

        @self.sio.event
        async def user_activity(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']: return
                username = self.connected_clients[sid]['username']
                activity_type = data.get('type', 'general')
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('UPDATE users SET last_activity = ? WHERE username = ?', (time.time(), username))
                    conn.commit()
                logger.debug(f"User activity {username}: {activity_type}")
            except Exception as e:
                logger.error(f"User activity error for {sid}: {e}")

        @self.sio.event
        async def server_ping(sid, data):
            try:
                remote_server_id = data.get('server_id')
                remote_address = data.get('address')
                remote_public_key = data.get('public_key')
                if not remote_server_id or not remote_address or not remote_public_key:
                    logger.warning(f"Invalid server ping from {sid}")
                    return
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''INSERT OR REPLACE INTO server_nodes
(server_id, address, public_key, last_seen, is_active, reputation, sync_priority)
                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                        (remote_server_id, remote_address, remote_public_key, time.time(), 1, 100, 1))
                    cursor.execute('''INSERT OR REPLACE INTO server_connections
(local_server_id, remote_server_id, remote_address, last_ping, is_active)
                        VALUES (?, ?, ?, ?, ?)''',
                        (self.server_id, remote_server_id, remote_address, time.time(), 1))
                    conn.commit()
                self.known_servers.add(remote_address)
                await self.sio.emit('server_pong', {
                    'server_id': self.server_id, 'address': self.address,
                    'public_key': base64.b64encode(self.public_key_pem).decode('utf-8')
                }, room=sid)
                logger.debug(f"Ping received from {remote_address}, responding with pong.")
            except Exception as e:
                logger.error(f"Server ping error from {sid}: {e}")

        @self.sio.event
        async def get_backup_server(sid, data):
            try:
                if self.backup_server:
                    await self.sio.emit('backup_server', {'server': self.backup_server, 'timestamp': time.time()}, room=sid)
                else:
                    await self.sio.emit('backup_server', {'error': 'No backup server available'}, room=sid)
            except Exception as e:
                logger.error(f"Backup server request error for {sid}: {e}")

        @self.sio.event
        async def sync_client_files(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']: return
                client_identifier = self.connected_clients[sid]['client_identifier']
                files = data.get('files', [])
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    for file_info in files:
                        content_hash = file_info['content_hash']
                        file_name = file_info['file_name']
                        file_size = file_info['file_size']
                        cursor.execute('INSERT OR REPLACE INTO client_files (client_identifier, content_hash, file_name, file_size, last_sync) VALUES (?, ?, ?, ?, ?)',
                                       (client_identifier, content_hash, file_name, file_size, time.time()))
                    conn.commit()
                logger.info(f"Synced {len(files)} files from client {client_identifier}")
            except Exception as e:
                logger.error(f"Client files sync error for {sid}: {e}")

        @self.sio.event
        async def sync_client_dns_files(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']: return
                client_identifier = self.connected_clients[sid]['client_identifier']
                dns_files = data.get('dns_files', [])
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    for dns_file in dns_files:
                        domain = dns_file['domain']
                        ddns_hash = dns_file['ddns_hash']
                        cursor.execute('INSERT OR REPLACE INTO client_dns_files (client_identifier, domain, ddns_hash, last_sync) VALUES (?, ?, ?, ?)',
                                       (client_identifier, domain, ddns_hash, time.time()))
                    conn.commit()
                logger.info(f"Synced {len(dns_files)} DNS files from client {client_identifier}")
            except Exception as e:
                logger.error(f"Client DNS files sync error for {sid}: {e}")

        @self.sio.event
        async def request_client_files(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']: return
                client_identifier = self.connected_clients[sid]['client_identifier']
                content_hashes = data.get('content_hashes', [])
                missing_files = []
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    for content_hash in content_hashes:
                        cursor.execute('SELECT 1 FROM content WHERE content_hash = ?', (content_hash,))
                        if not cursor.fetchone():
                            missing_files.append(content_hash)
                await self.sio.emit('client_files_response', {'missing_files': missing_files}, room=sid)
            except Exception as e:
                logger.error(f"Client files request error for {sid}: {e}")

        @self.sio.event
        async def request_client_dns_files(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']: return
                client_identifier = self.connected_clients[sid]['client_identifier']
                domains = data.get('domains', [])
                missing_dns = []
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    for domain in domains:
                        cursor.execute('SELECT 1 FROM dns_records WHERE domain = ?', (domain,))
                        if not cursor.fetchone():
                            missing_dns.append(domain)
                await self.sio.emit('client_dns_files_response', {'missing_dns': missing_dns}, room=sid)
            except Exception as e:
                logger.error(f"Client DNS files request error for {sid}: {e}")

        @self.sio.event
        async def request_content_from_client(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']: return
                content_hash = data.get('content_hash')
                if not content_hash: return
                file_path = os.path.join(self.files_dir, f"{content_hash}.dat")
                if os.path.exists(file_path):
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT 1 FROM content WHERE content_hash = ?', (content_hash,))
                        if cursor.fetchone(): return
                    async with aiofiles.open(file_path, 'rb') as f:
                        content = await f.read()
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT title, description, mime_type, username, signature, public_key, verified FROM content WHERE content_hash = ?', (content_hash,))
                        row = cursor.fetchone()
                        if not row: return
                        title, description, mime_type, username, signature, public_key, verified = row
                    await self.sio.emit('content_from_client', {
                        'content_hash': content_hash, 'content': base64.b64encode(content).decode('utf-8'),
                        'title': title, 'description': description, 'mime_type': mime_type, 'username': username,
                        'signature': signature, 'public_key': public_key, 'verified': verified
                    }, room=sid)
                    logger.info(f"Content {content_hash} shared from client {self.connected_clients[sid]['username']}")
            except Exception as e:
                logger.error(f"Error sharing content from client: {e}")

        @self.sio.event
        async def request_ddns_from_client(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']: return
                domain = data.get('domain')
                if not domain: return
                ddns_file_path = os.path.join(self.files_dir, f"{domain}.ddns")
                if not os.path.exists(ddns_file_path):
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT ddns_hash FROM dns_records WHERE domain = ?', (domain,))
                        row = cursor.fetchone()
                        if row:
                            ddns_hash = row[0]
                            ddns_file_path = os.path.join(self.files_dir, f"{ddns_hash}.ddns")
                if os.path.exists(ddns_file_path):
                    async with aiofiles.open(ddns_file_path, 'rb') as f:
                        ddns_content = await f.read()
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT content_hash, username, signature, public_key, verified FROM dns_records WHERE domain = ?', (domain,))
                        row = cursor.fetchone()
                        if not row: return
                        content_hash, username, signature, public_key, verified = row
                    await self.sio.emit('ddns_from_client', {
                        'domain': domain, 'ddns_content': base64.b64encode(ddns_content).decode('utf-8'),
                        'content_hash': content_hash, 'username': username, 'signature': signature,
                        'public_key': public_key, 'verified': verified
                    }, room=sid)
                    logger.info(f"DDNS {domain} shared from client {self.connected_clients[sid]['username']}")
            except Exception as e:
                logger.error(f"Error sharing DDNS from client: {e}")

        @self.sio.event
        async def content_from_client(sid, data):
            try:
                content_hash = data.get('content_hash')
                content_b64 = data.get('content')
                title = data.get('title')
                description = data.get('description')
                mime_type = data.get('mime_type')
                username = data.get('username')
                signature = data.get('signature')
                public_key = data.get('public_key')
                verified = data.get('verified', False)
                if not all([content_hash, content_b64, title, mime_type, username, signature, public_key]): return
                content = base64.b64decode(content_b64)
                file_path = os.path.join(self.files_dir, f"{content_hash}.dat")
                if not os.path.exists(file_path):
                    async with aiofiles.open(file_path, 'wb') as f:
                        await f.write(content)
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT 1 FROM content WHERE content_hash = ?', (content_hash,))
                    if not cursor.fetchone():
                        cursor.execute('''INSERT INTO content
(content_hash, title, description, mime_type, size, username, signature, public_key, timestamp, file_path, verified, last_accessed)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                            (content_hash, title, description, mime_type, len(content), username, signature, public_key, time.time(), file_path, verified, time.time()))
                        conn.commit()
                        logger.info(f"Content {content_hash} saved from client share")
            except Exception as e:
                logger.error(f"Error processing content from client: {e}")

        @self.sio.event
        async def ddns_from_client(sid, data):
            try:
                domain = data.get('domain')
                ddns_content_b64 = data.get('ddns_content')
                content_hash = data.get('content_hash')
                username = data.get('username')
                signature = data.get('signature')
                public_key = data.get('public_key')
                verified = data.get('verified', False)
                if not all([domain, ddns_content_b64, content_hash, username, signature, public_key]): return
                ddns_content = base64.b64decode(ddns_content_b64)
                ddns_hash = hashlib.sha256(ddns_content).hexdigest()
                file_path = os.path.join(self.files_dir, f"{ddns_hash}.ddns")
                if not os.path.exists(file_path):
                    async with aiofiles.open(file_path, 'wb') as f:
                        await f.write(ddns_content)
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT 1 FROM dns_records WHERE domain = ?', (domain,))
                    if not cursor.fetchone():
                        cursor.execute('''INSERT INTO dns_records
(domain, content_hash, username, original_owner, timestamp, signature, verified, last_resolved, ddns_hash)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                            (domain, content_hash, username, username, time.time(), signature, verified, time.time(), ddns_hash))
                        conn.commit()
                        logger.info(f"DNS {domain} saved from client share")
            except Exception as e:
                logger.error(f"Error processing DDNS from client: {e}")

    def setup_routes(self):
        self.app.router.add_post('/upload', self.handle_upload)
        self.app.router.add_get('/content/{content_hash}', self.handle_content_request)
        self.app.router.add_get('/dns/{domain}', self.handle_dns_request)
        self.app.router.add_get('/ddns/{domain}', self.handle_ddns_request)
        self.app.router.add_get('/sync/content', self.handle_sync_content)
        self.app.router.add_get('/sync/dns', self.handle_sync_dns)
        self.app.router.add_get('/sync/users', self.handle_sync_users)
        self.app.router.add_get('/health', self.handle_health)
        self.app.router.add_get('/server_info', self.handle_server_info)

    async def handle_upload(self, request):
        try:
            reader = await request.multipart()
            file_field = await reader.next()
            if not file_field or file_field.name != 'file':
                logger.warning("Upload attempt without file.")
                return web.json_response({'success': False, 'error': 'File missing'}, status=400)
            file_data = await file_field.read()
            username = request.headers.get('X-Username', '')
            signature = request.headers.get('X-Signature', '')
            public_key_b64 = request.headers.get('X-Public-Key', '')
            client_identifier = request.headers.get('X-Client-ID', '')
            if not all([username, signature, public_key_b64, client_identifier]):
                logger.warning(f"Upload attempt without auth headers from {request.remote}.")
                return web.json_response({'success': False, 'error': 'Missing auth headers'}, status=401)
            allowed, message, remaining_time = self.check_rate_limit(client_identifier, "upload")
            if not allowed:
                logger.warning(f"Upload blocked by rate limit for {client_identifier}: {message}")
                return web.json_response({'success': False, 'error': message, 'blocked_until': time.time() + remaining_time}, status=429)
            content_hash = hashlib.sha256(file_data).hexdigest()
            file_path = os.path.join(self.files_dir, f"{content_hash}.dat")
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT disk_quota, used_disk_space FROM users WHERE username = ?', (username,))
                user_quota_row = cursor.fetchone()
                if user_quota_row:
                    disk_quota, used_disk_space = user_quota_row
                    if (used_disk_space + len(file_data)) > disk_quota:
                        logger.warning(f"Upload from {username} exceeded disk quota.")
                        return web.json_response({'success': False, 'error': f'Disk quota exceeded. Available space: {(disk_quota - used_disk_space) / (1024*1024):.2f}MB'}, status=413)
            async with aiofiles.open(file_path, 'wb') as f:
                await f.write(file_data)
            self.update_rate_limit(client_identifier, "upload")
            logger.info(f"File {content_hash} received via HTTP from {username}.")
            return web.json_response({'success': True, 'content_hash': content_hash, 'message': 'File received successfully'})
        except Exception as e:
            logger.error(f"HTTP upload error from {request.remote}: {e}")
            return web.json_response({'success': False, 'error': f'Internal server error: {str(e)}'}, status=500)

    async def handle_content_request(self, request):
        content_hash = request.match_info['content_hash']

        redirected_hash = self.get_redirected_hash(content_hash)
        if redirected_hash:
            message = f'Arquivo desatualizado, Novo Hash: {redirected_hash}'
            return web.Response(text=message, content_type='text/plain')

        file_path = os.path.join(self.files_dir, f"{content_hash}.dat")
        if not os.path.exists(file_path):
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT content_hash FROM dns_records WHERE domain = ?', (content_hash,))
                dns_redirect = cursor.fetchone()
                if dns_redirect:
                    new_hash = dns_redirect[0]
                    content_hash = new_hash
                    file_path = os.path.join(self.files_dir, f"{new_hash}.dat")
        if not os.path.exists(file_path):
            logger.info(f"Content {content_hash} requested via HTTP not found locally.")
            return web.json_response({'success': False, 'error': 'Content not found'}, status=404)
        try:
            async with aiofiles.open(file_path, 'rb') as f:
                content = await f.read()
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE content SET last_accessed = ?, replication_count = replication_count + 1 WHERE content_hash = ?',
                               (time.time(), content_hash))
                conn.commit()
            logger.info(f"Content {content_hash} served via HTTP.")
            return web.FileResponse(file_path)
        except Exception as e:
            logger.error(f"Error serving content {content_hash} via HTTP: {e}")
            return web.json_response({'success': False, 'error': f'Internal server error: {str(e)}'}, status=500)

    async def handle_dns_request(self, request):
        domain = request.match_info['domain']
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT d.content_hash, d.username, d.signature, d.verified, d.original_owner
                FROM dns_records d WHERE d.domain = ? ORDER BY d.verified DESC LIMIT 1''', (domain,))
            row = cursor.fetchone()
            if row:
                cursor.execute('UPDATE dns_records SET last_resolved = ? WHERE domain = ?', (time.time(), domain))
                conn.commit()
        if row:
            content_hash, username, signature, verified, original_owner = row
            logger.info(f"DNS {domain} resolved via HTTP to {content_hash}.")
            return web.json_response({
                'success': True, 'domain': domain, 'content_hash': content_hash,
                'username': username, 'signature': signature, 'verified': bool(verified), 'original_owner': original_owner
            })
        else:
            logger.info(f"DNS {domain} requested via HTTP not found.")
            return web.json_response({'success': False, 'error': 'Domain not found'}, status=404)

    async def handle_ddns_request(self, request):
        domain = request.match_info['domain']
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT ddns_hash FROM dns_records WHERE domain = ?', (domain,))
            row = cursor.fetchone()
        if row:
            ddns_hash = row[0]
            file_path = os.path.join(self.files_dir, f"{ddns_hash}.ddns")
            if os.path.exists(file_path):
                return web.FileResponse(file_path)
        return web.json_response({'success': False, 'error': 'DDNS file not found'}, status=404)

    async def handle_sync_content(self, request):
        limit = int(request.query.get('limit', 100))
        offset = int(request.query.get('offset', 0))
        since = float(request.query.get('since', 0))
        content_hash_param = request.query.get('content_hash')
        content_list = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            if content_hash_param:
                cursor.execute('''SELECT content_hash, title, description, mime_type, size, username,
                    signature, public_key, verified, replication_count, timestamp FROM content WHERE content_hash = ?''',
                    (content_hash_param,))
            elif since > 0:
                cursor.execute('''SELECT content_hash, title, description, mime_type, size, username,
signature, public_key, verified, replication_count, timestamp FROM content
                    WHERE timestamp > ? ORDER BY timestamp DESC LIMIT ? OFFSET ?''',
                    (since, limit, offset))
            else:
                cursor.execute('''SELECT content_hash, title, description, mime_type, size, username,
signature, public_key, verified, replication_count, timestamp FROM content
                    ORDER BY replication_count DESC, last_accessed DESC LIMIT ? OFFSET ?''',
                    (limit, offset))
            rows = cursor.fetchall()
        for row in rows:
            content_list.append({
                'content_hash': row[0], 'title': row[1], 'description': row[2], 'mime_type': row[3], 'size': row[4],
                'username': row[5], 'signature': row[6], 'public_key': row[7], 'verified': bool(row[8]),
                'replication_count': row[9], 'timestamp': row[10]
            })
        logger.info(f"Serving {len(content_list)} content items for sync (since={since}, hash={content_hash_param}).")
        return web.json_response(content_list)

    async def handle_sync_dns(self, request):
        since = float(request.query.get('since', 0))
        dns_list = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            if since > 0:
                cursor.execute('''SELECT domain, content_hash, username, original_owner, signature, verified, last_resolved, timestamp, ddns_hash
                    FROM dns_records WHERE timestamp > ? ORDER BY timestamp DESC''', (since,))
            else:
                cursor.execute('''SELECT domain, content_hash, username, original_owner, signature, verified, last_resolved, timestamp, ddns_hash
                FROM dns_records ORDER BY last_resolved DESC''')
            rows = cursor.fetchall()
        for row in rows:
            dns_list.append({
                'domain': row[0], 'content_hash': row[1], 'username': row[2], 'original_owner': row[3], 'signature': row[4], 'verified': bool(row[5]),
                'last_resolved': row[6], 'timestamp': row[7], 'ddns_hash': row[8]
            })
        logger.info(f"Serving {len(dns_list)} DNS records for sync (since={since}).")
        return web.json_response(dns_list)

    async def handle_sync_users(self, request):
        since = float(request.query.get('since', 0))
        users_list = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            if since > 0:
                cursor.execute('''SELECT username, reputation, last_updated, client_identifier, violation_count
                    FROM user_reputations WHERE last_updated > ? ORDER BY reputation DESC''', (since,))
            else:
                cursor.execute('''SELECT username, reputation, last_updated, client_identifier, violation_count
                FROM user_reputations ORDER BY reputation DESC''')
            rows = cursor.fetchall()
        for row in rows:
            users_list.append({
                'username': row[0], 'reputation': row[1], 'last_updated': row[2], 'client_identifier': row[3], 'violation_count': row[4]
            })
        logger.info(f"Serving {len(users_list)} user reputations for sync (since={since}).")
        return web.json_response(users_list)

    async def handle_health(self, request):
        health_data = {
            'status': 'healthy', 'server_id': self.server_id, 'address': self.address,
            'online_clients': len([c for c in self.connected_clients.values() if c['authenticated']]),
            'total_users': 0, 'total_content': 0, 'total_dns': 0,
            'uptime': time.time() - self.start_time if hasattr(self, 'start_time') else 0, 'timestamp': time.time()
        }
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM users')
            health_data['total_users'] = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM content')
            health_data['total_content'] = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM dns_records')
            health_data['total_dns'] = cursor.fetchone()[0]
        return web.json_response(health_data)

    async def handle_server_info(self, request):
        return web.json_response({
            'server_id': self.server_id, 'address': self.address,
            'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'), 'timestamp': time.time()
        })

    def mark_node_offline(self, node_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE network_nodes SET is_online = 0 WHERE node_id = ?', (node_id,))
            conn.commit()
        logger.info(f"Node {node_id} marked offline.")

    async def broadcast_network_state(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM network_nodes WHERE is_online = 1')
                online_nodes = cursor.fetchone()[0]
                cursor.execute('SELECT COUNT(*) FROM content')
                total_content = cursor.fetchone()[0]
                cursor.execute('SELECT COUNT(*) FROM dns_records')
                total_dns = cursor.fetchone()[0]
                cursor.execute('SELECT node_type, COUNT(*) FROM network_nodes WHERE is_online = 1 GROUP BY node_type')
                node_types = {}
                for row in cursor.fetchall():
                    node_types[row[0]] = row[1]
            await self.sio.emit('network_state', {
                'online_nodes': online_nodes, 'total_content': total_content, 'total_dns': total_dns,
                'node_types': node_types, 'timestamp': time.time()
            })
            logger.debug("Network state broadcast to connected clients.")
        except Exception as e:
            logger.error(f"Network state broadcast error: {e}")

    def is_valid_domain(self, domain):
        if len(domain) < 3 or len(domain) > 63: return False
        if not all(c.isalnum() or c == '-' or c == '.' for c in domain): return False
        if domain.startswith('-') or domain.endswith('-'): return False
        if '..' in domain: return False
        return True

    def extract_content_hash_from_ddns(self, ddns_content):
        try:
            lines = ddns_content.decode('utf-8').splitlines()
            in_dns_section = False
            for line in lines:
                if line.strip() == '### DNS:':
                    in_dns_section = True
                    continue
                if line.strip() == '### :END DNS':
                    break
                if in_dns_section and line.strip().startswith('# DNAME:'):
                    parts = line.strip().split('=')
                    if len(parts) == 2:
                        return parts[1].strip()
            return None
        except Exception as e:
            logger.error(f"Error extracting content hash from ddns: {e}")
            return None

    async def propagate_content_to_network(self, content_hash):
        for server_address in list(self.known_servers):
            if server_address != self.address:
                asyncio.create_task(self.sync_content_with_server(server_address, content_hash=content_hash))

    async def propagate_dns_to_network(self, domain):
        for server_address in list(self.known_servers):
            if server_address != self.address:
                asyncio.create_task(self.sync_dns_with_server(server_address, domain=domain))

    async def fetch_content_from_network(self, content_hash):
        redirected_hash = self.get_redirected_hash(content_hash)
        if redirected_hash:
            return await self.fetch_content_from_network(redirected_hash)

        servers_to_try = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT address FROM server_nodes WHERE is_active = 1 AND address != ? ORDER BY reputation DESC', (self.address,))
            servers_to_try = [row[0] for row in cursor.fetchall()]

        for server in servers_to_try:
            try:
                success, content_data, protocol_used = await self.make_remote_request(server, f'/content/{content_hash}')
                if success:
                    file_path = os.path.join(self.files_dir, f"{content_hash}.dat")

                    async with aiofiles.open(file_path, 'wb') as f:
                        await f.write(content_data)

                    success_meta, content_meta, _ = await self.make_remote_request_json(server, f'/sync/content', params={'content_hash': content_hash})
                    if success_meta and content_meta and isinstance(content_meta, list) and len(content_meta) > 0:
                        content_meta = content_meta[0]
                        with sqlite3.connect(self.db_path) as conn:
                            cursor = conn.cursor()
                            cursor.execute('SELECT 1 FROM content WHERE content_hash = ?', (content_hash,))
                            if not cursor.fetchone():
                                cursor.execute('''INSERT INTO content
(content_hash, title, description, mime_type, size, username, signature, public_key, timestamp, file_path, verified, replication_count, last_accessed)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                    (content_hash, content_meta.get('title', 'Synced'), content_meta.get('description', 'Content synced from network'),
                                     content_meta.get('mime_type', 'application/octet-stream'), len(content_data), content_meta.get('username', 'System'),
                                     content_meta.get('signature', ''), content_meta.get('public_key', ''), content_meta.get('timestamp', time.time()),
                                     file_path, content_meta.get('verified', 0), content_meta.get('replication_count', 1), time.time()))
                            else:
                                cursor.execute('''UPDATE content SET title=?, description=?, mime_type=?, size=?, username=?,
signature=?, public_key=?, timestamp=?, verified=?, replication_count=?, last_accessed=?
                                    WHERE content_hash=?''',
                                    (content_meta.get('title', 'Synced'), content_meta.get('description', 'Content synced from network'),
                                     content_meta.get('mime_type', 'application/octet-stream'), len(content_data), content_meta.get('username', 'System'),
                                     content_meta.get('signature', ''), content_meta.get('public_key', ''), content_meta.get('timestamp', time.time()),
                                     content_meta.get('verified', 0), content_meta.get('replication_count', 1), time.time(), content_hash))
                            conn.commit()
                        logger.info(f"Content {content_hash} and metadata synced from {server} via {protocol_used}.")
                        return True
                    else:
                        logger.warning(f"Could not get metadata for {content_hash} from {server}.")

                logger.info(f"Content {content_hash} synced from {server} via {protocol_used}.")
                return True
            except Exception as e:
                logger.error(f"Unexpected error fetching content {content_hash} from {server}: {e}")

        client_sids = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT client_identifier FROM client_files WHERE content_hash = ?', (content_hash,))
            rows = cursor.fetchall()
            for row in rows:
                client_identifier = row[0]
                for sid, client in self.connected_clients.items():
                    if client.get('client_identifier') == client_identifier and client.get('authenticated'):
                        client_sids.append(sid)
                        break

        for sid in client_sids:
            try:
                await self.sio.emit('request_content_from_client', {'content_hash': content_hash}, room=sid)
                await asyncio.sleep(2)
                file_path = os.path.join(self.files_dir, f"{content_hash}.dat")
                if os.path.exists(file_path):
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT 1 FROM content WHERE content_hash = ?', (content_hash,))
                        if cursor.fetchone():
                            logger.info(f"Content {content_hash} received from client {sid}")
                            return True
            except Exception as e:
                logger.error(f"Error requesting content from client {sid}: {e}")

        return False

    async def fetch_ddns_from_network(self, domain, ddns_hash):
        servers_to_try = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT address FROM server_nodes WHERE is_active = 1 AND address != ? ORDER BY reputation DESC', (self.address,))
            servers_to_try = [row[0] for row in cursor.fetchall()]

        for server in servers_to_try:
            try:
                success, ddns_content, protocol_used = await self.make_remote_request(server, f'/ddns/{domain}')
                if success:
                    file_path = os.path.join(self.files_dir, f"{ddns_hash}.ddns")
                    async with aiofiles.open(file_path, 'wb') as f:
                        await f.write(ddns_content)

                    logger.info(f"DDNS {domain} synced from {server} via {protocol_used}.")
                    return True
            except Exception as e:
                logger.error(f"Unexpected error fetching DDNS {domain} from {server}: {e}")

        client_sids = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT client_identifier FROM client_dns_files WHERE domain = ?', (domain,))
            rows = cursor.fetchall()
            for row in rows:
                client_identifier = row[0]
                for sid, client in self.connected_clients.items():
                    if client.get('client_identifier') == client_identifier and client.get('authenticated'):
                        client_sids.append(sid)
                        break

        for sid in client_sids:
            try:
                await self.sio.emit('request_ddns_from_client', {'domain': domain}, room=sid)
                await asyncio.sleep(2)
                file_path = os.path.join(self.files_dir, f"{ddns_hash}.ddns")
                if os.path.exists(file_path):
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT 1 FROM dns_records WHERE domain = ?', (domain,))
                        if cursor.fetchone():
                            logger.info(f"DDNS {domain} received from client {sid}")
                            return True
            except Exception as e:
                logger.error(f"Error requesting DDNS from client {sid}: {e}")

        return False

    async def resolve_dns_from_network(self, domain):
        servers_to_try = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT address FROM server_nodes WHERE is_active = 1 AND address != ? ORDER BY reputation DESC', (self.address,))
            servers_to_try = [row[0] for row in cursor.fetchall()]

        for server in servers_to_try:
            try:
                success, dns_data, protocol_used = await self.make_remote_request_json(server, f'/dns/{domain}')
                if success and dns_data.get('success'):
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('''INSERT OR REPLACE INTO dns_records
(domain, content_hash, username, original_owner, timestamp, signature, verified, last_resolved, ddns_hash)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                            (domain, dns_data['content_hash'], dns_data['username'], dns_data.get('original_owner', dns_data['username']),
                             dns_data.get('timestamp', time.time()), dns_data.get('signature', ''), dns_data.get('verified', 0),
                             time.time(), dns_data.get('ddns_hash', '')))
                        conn.commit()

                    success_ddns, ddns_content, _ = await self.make_remote_request(server, f'/ddns/{domain}')
                    if success_ddns:
                        ddns_hash = hashlib.sha256(ddns_content).hexdigest()
                        file_path = os.path.join(self.files_dir, f"{ddns_hash}.ddns")
                        async with aiofiles.open(file_path, 'wb') as f:
                            await f.write(ddns_content)

                    logger.info(f"DNS {domain} resolved from {server} via {protocol_used}.")
                    return dns_data
            except Exception as e:
                logger.error(f"Unexpected error resolving DNS {domain} from {server}: {e}")

        return None

    async def process_content_report(self, report_id, content_hash, reported_user, reporter):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM content_reports WHERE content_hash = ? AND reporter != ? AND resolved = 0',
                           (content_hash, reporter))
            other_reports = cursor.fetchone()[0]
            if other_reports >= 2:
                logger.info(f"Report {report_id} for {content_hash} reached report threshold. Auto-processing.")
                cursor.execute('UPDATE user_reputations SET reputation = MAX(1, reputation - 20) WHERE username = ?', (reported_user,))
                cursor.execute('UPDATE users SET reputation = MAX(1, reputation - 20) WHERE username = ?', (reported_user,))
                cursor.execute('UPDATE user_reputations SET reputation = MIN(100, reputation + 5) WHERE username = ?', (reporter,))
                cursor.execute('UPDATE content_reports SET resolved = 1, resolution_type = "auto_warn" WHERE report_id = ?', (report_id,))
                conn.commit()
                for sid, client in self.connected_clients.items():
                    if client.get('username') == reported_user:
                        cursor.execute('SELECT reputation FROM user_reputations WHERE username = ?', (reported_user,))
                        rep_row = cursor.fetchone()
                        if rep_row:
                            await self.sio.emit('reputation_update', {'reputation': rep_row[0]}, room=sid)
                            await self.sio.emit('notification', {'message': 'Your reputation was reduced due to content reports.'}, room=sid)
                logger.info(f"Report processed: {report_id} - {reported_user} penalized, {reporter} rewarded")
            else:
                logger.info(f"Report received: {report_id} - waiting for more reports ({other_reports+1}/3)")

    async def sync_with_server(self, server_address):
        if server_address in self.server_sync_tasks:
            logger.debug(f"Sync with {server_address} already in progress.")
            return

        try:
            self.server_sync_tasks[server_address] = asyncio.current_task()

            success, remote_info, protocol_used = await self.make_remote_request_json(server_address, '/server_info')
            if success:
                remote_server_id = remote_info['server_id']
                remote_public_key = remote_info['public_key']
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''INSERT OR REPLACE INTO server_nodes
(server_id, address, public_key, last_seen, is_active, reputation, sync_priority)
                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                        (remote_server_id, server_address, remote_public_key, time.time(), 1, 100, 1))
                    conn.commit()
                self.known_servers.add(server_address)
            else:
                logger.warning(f"Could not get server info from {server_address}.")
                return

            last_sync_content = 0
            last_sync_dns = 0
            last_sync_users = 0
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT last_sync FROM server_sync_history WHERE server_address = ? AND sync_type = ?', (server_address, 'content'))
                row = cursor.fetchone()
                if row: last_sync_content = row[0]
                cursor.execute('SELECT last_sync FROM server_sync_history WHERE server_address = ? AND sync_type = ?', (server_address, 'dns'))
                row = cursor.fetchone()
                if row: last_sync_dns = row[0]
                cursor.execute('SELECT last_sync FROM server_sync_history WHERE server_address = ? AND sync_type = ?', (server_address, 'users'))
                row = cursor.fetchone()
                if row: last_sync_users = row[0]

            await self.sync_content_with_server(server_address, since=last_sync_content)
            await self.sync_dns_with_server(server_address, since=last_sync_dns)
            await self.sync_users_with_server(server_address, since=last_sync_users)

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''INSERT OR REPLACE INTO server_sync_history
(server_address, last_sync, sync_type, items_count, success)
                    VALUES (?, ?, ?, ?, ?)''',
                    (server_address, time.time(), 'full', 0, 1))
                conn.commit()

            logger.info(f"Full sync with {server_address} completed successfully.")
        except Exception as e:
            logger.error(f"Unexpected error during sync with {server_address}: {e}")
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''INSERT OR REPLACE INTO server_sync_history
(server_address, last_sync, sync_type, items_count, success)
                    VALUES (?, ?, ?, ?, ?)''',
                    (server_address, time.time(), 'full', 0, 0))
                conn.commit()
        finally:
            if server_address in self.server_sync_tasks:
                del self.server_sync_tasks[server_address]

    async def sync_content_with_server(self, server_address, since=0, content_hash=None):
        try:
            params = {}
            if content_hash:
                params['content_hash'] = content_hash
            else:
                params['since'] = since
                params['limit'] = 100

            success, content_list, protocol_used = await self.make_remote_request_json(server_address, '/sync/content', params=params)
            if success and isinstance(content_list, list):
                count = 0
                for content_item in content_list:
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()
                        if content_item['title'].startswith('(HPS!api)'):
                            app_name = self.extract_app_name(content_item['title'])
                            if app_name:
                                cursor.execute('SELECT username FROM api_apps WHERE app_name = ?', (app_name,))
                                app_owner = cursor.fetchone()
                                if app_owner and app_owner[0] != content_item['username']:
                                    continue

                                cursor.execute('SELECT content_hash FROM api_apps WHERE app_name = ?', (app_name,))
                                existing_app = cursor.fetchone()
                                if existing_app:
                                    old_hash = existing_app[0]
                                    if old_hash != content_item['content_hash']:
                                        cursor.execute('UPDATE dns_records SET content_hash = ? WHERE content_hash = ?', (content_item['content_hash'], old_hash))
                                        cursor.execute('INSERT OR REPLACE INTO content_redirects (old_hash, new_hash, username, redirect_type, timestamp) VALUES (?, ?, ?, ?, ?)',
                                                       (old_hash, content_item['content_hash'], content_item['username'], 'app_update', time.time()))

                                        cursor.execute('SELECT 1 FROM dns_records WHERE content_hash = ?', (old_hash,))
                                        dns_using = cursor.fetchone()
                                        cursor.execute('SELECT 1 FROM client_files WHERE content_hash = ?', (old_hash,))
                                        client_using = cursor.fetchone()

                                        if not dns_using and not client_using:
                                            cursor.execute('DELETE FROM content WHERE content_hash = ?', (old_hash,))
                                            cursor.execute('DELETE FROM content_availability WHERE content_hash = ?', (old_hash,))
                                            cursor.execute('DELETE FROM client_files WHERE content_hash = ?', (old_hash,))
                                            cursor.execute('DELETE FROM content_redirects WHERE old_hash = ?', (old_hash,))
                                            old_file_path = os.path.join(self.files_dir, f"{old_hash}.dat")
                                            if os.path.exists(old_file_path):
                                                os.remove(old_file_path)

                                        cursor.execute('UPDATE api_apps SET content_hash = ?, last_updated = ? WHERE app_name = ?',
                                                       (content_item['content_hash'], time.time(), app_name))
                                        cursor.execute('INSERT INTO api_app_versions (version_id, app_name, content_hash, username, timestamp, version_number) VALUES (?, ?, ?, ?, ?, ?)',
                                                       (str(uuid.uuid4()), app_name, content_item['content_hash'], content_item['username'], time.time(),
                                                        cursor.execute('SELECT COALESCE(MAX(version_number), 0) + 1 FROM api_app_versions WHERE app_name = ?', (app_name,)).fetchone()[0]))
                                else:
                                    cursor.execute('INSERT INTO api_apps (app_name, username, content_hash, timestamp, last_updated) VALUES (?, ?, ?, ?, ?)',
                                                   (app_name, content_item['username'], content_item['content_hash'], time.time(), time.time()))
                                    cursor.execute('INSERT INTO api_app_versions (version_id, app_name, content_hash, username, timestamp, version_number) VALUES (?, ?, ?, ?, ?, ?)',
                                                   (str(uuid.uuid4()), app_name, content_item['content_hash'], content_item['username'], time.time(), 1))
                                conn.commit()

                        cursor.execute('SELECT 1 FROM content WHERE content_hash = ?', (content_item['content_hash'],))
                        existing_content = cursor.fetchone()
                        if existing_content:
                            continue

                    success_content, content_data, _ = await self.make_remote_request(server_address, f'/content/{content_item["content_hash"]}')
                    if not success_content:
                        continue

                    file_path = os.path.join(self.files_dir, f"{content_item['content_hash']}.dat")
                    async with aiofiles.open(file_path, 'wb') as f:
                        await f.write(content_data)

                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('''INSERT INTO content
(content_hash, title, description, mime_type, size, username, signature, public_key, timestamp, file_path, verified, replication_count, last_accessed)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                            (content_item['content_hash'], content_item.get('title', 'Synced'), content_item.get('description', 'Content synced from network'),
                             content_item.get('mime_type', 'application/octet-stream'), len(content_data), content_item.get('username', 'System'),
                             content_item.get('signature', ''), content_item.get('public_key', ''), content_item.get('timestamp', time.time()),
                             file_path, content_item.get('verified', 0), content_item.get('replication_count', 1), time.time()))
                        conn.commit()
                    count += 1
                    logger.debug(f"Content {content_item['content_hash']} synced from {server_address} via {protocol_used}.")

                if count > 0:
                    logger.info(f"Synced {count} content items from {server_address} via {protocol_used}.")

                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''INSERT OR REPLACE INTO server_sync_history
(server_address, last_sync, sync_type, items_count, success)
                        VALUES (?, ?, ?, ?, ?)''',
                        (server_address, time.time(), 'content', count, 1))
                    conn.commit()
                return count
            else:
                logger.warning(f"Could not sync content from {server_address}.")
                return 0
        except Exception as e:
            logger.error(f"Unexpected error syncing content from {server_address}: {e}")
            return 0

    async def sync_dns_with_server(self, server_address, since=0, domain=None):
        try:
            if domain:
                success, dns_data, protocol_used = await self.make_remote_request_json(server_address, f'/dns/{domain}')
                if success and dns_data.get('success'):
                    success_ddns, ddns_content, _ = await self.make_remote_request(server_address, f'/ddns/{domain}')
                    if success_ddns:
                        ddns_hash = hashlib.sha256(ddns_content).hexdigest()
                        file_path = os.path.join(self.files_dir, f"{ddns_hash}.ddns")
                        async with aiofiles.open(file_path, 'wb') as f:
                            await f.write(ddns_content)

                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT 1 FROM dns_records WHERE domain = ?', (domain,))
                        if not cursor.fetchone():
                            cursor.execute('''INSERT INTO dns_records
(domain, content_hash, username, original_owner, timestamp, signature, verified, last_resolved, ddns_hash)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                (domain, dns_data['content_hash'], dns_data['username'], dns_data.get('original_owner', dns_data['username']),
                                 dns_data.get('timestamp', time.time()), dns_data.get('signature', ''), dns_data.get('verified', 0), time.time(), ddns_hash))
                            conn.commit()
                            logger.info(f"DNS {domain} synced from {server_address} via {protocol_used}.")
                            return 1
                return 0
            else:
                params = {'since': since} if since > 0 else {}
                success, dns_list, protocol_used = await self.make_remote_request_json(server_address, '/sync/dns', params=params)
                if success and isinstance(dns_list, list):
                    count = 0
                    for dns_item in dns_list:
                        with sqlite3.connect(self.db_path) as conn:
                            cursor = conn.cursor()
                            cursor.execute('SELECT 1 FROM dns_records WHERE domain = ?', (dns_item['domain'],))
                            if not cursor.fetchone():
                                success_ddns, ddns_content, _ = await self.make_remote_request(server_address, f'/ddns/{dns_item["domain"]}')
                                if success_ddns:
                                    ddns_hash = hashlib.sha256(ddns_content).hexdigest()
                                    file_path = os.path.join(self.files_dir, f"{ddns_hash}.ddns")
                                    async with aiofiles.open(file_path, 'wb') as f:
                                        await f.write(ddns_content)

                                cursor.execute('''INSERT INTO dns_records
(domain, content_hash, username, original_owner, timestamp, signature, verified, last_resolved, ddns_hash)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                    (dns_item['domain'], dns_item['content_hash'], dns_item['username'], dns_item.get('original_owner', dns_item['username']),
                                     dns_item.get('timestamp', time.time()), dns_item.get('signature', ''), dns_item.get('verified', 0), time.time(), ddns_hash))
                                conn.commit()
                                count += 1

                    if count > 0:
                        logger.info(f"Synced {count} DNS records from {server_address} via {protocol_used}.")

                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('''INSERT OR REPLACE INTO server_sync_history
(server_address, last_sync, sync_type, items_count, success)
                            VALUES (?, ?, ?, ?, ?)''',
                            (server_address, time.time(), 'dns', count, 1))
                        conn.commit()
                    return count
                else:
                    logger.warning(f"Could not sync DNS from {server_address}.")
                    return 0
        except Exception as e:
            logger.error(f"Unexpected error syncing DNS from {server_address}: {e}")
            return 0

    async def sync_users_with_server(self, server_address, since=0):
        try:
            params = {'since': since} if since > 0 else {}
            success, users_list, protocol_used = await self.make_remote_request_json(server_address, '/sync/users', params=params)
            if success and isinstance(users_list, list):
                count = 0
                for user_item in users_list:
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT reputation FROM user_reputations WHERE username = ?', (user_item['username'],))
                        row = cursor.fetchone()
                        if row:
                            current_reputation = row[0]
                            if user_item['last_updated'] > since:
                                cursor.execute('UPDATE user_reputations SET reputation = ?, last_updated = ?, client_identifier = ?, violation_count = ? WHERE username = ?',
                                               (user_item['reputation'], user_item['last_updated'], user_item.get('client_identifier', ''), user_item.get('violation_count', 0), user_item['username']))
                                cursor.execute('UPDATE users SET reputation = ? WHERE username = ?', (user_item['reputation'], user_item['username']))
                                count += 1
                        else:
                            cursor.execute('''INSERT INTO user_reputations
(username, reputation, last_updated, client_identifier, violation_count)
                                VALUES (?, ?, ?, ?, ?)''',
                                (user_item['username'], user_item['reputation'], user_item['last_updated'], user_item.get('client_identifier', ''), user_item.get('violation_count', 0)))
                            cursor.execute('INSERT OR IGNORE INTO users (username, password_hash, public_key, created_at, last_login, reputation, client_identifier, last_activity) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                                           (user_item['username'], '', '', time.time(), time.time(), user_item['reputation'], user_item.get('client_identifier', ''), time.time()))
                            count += 1
                        conn.commit()

                if count > 0:
                    logger.info(f"Synced {count} user reputations from {server_address} via {protocol_used}.")

                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''INSERT OR REPLACE INTO server_sync_history
(server_address, last_sync, sync_type, items_count, success)
                        VALUES (?, ?, ?, ?, ?)''',
                        (server_address, time.time(), 'users', count, 1))
                    conn.commit()
                return count
            else:
                logger.warning(f"Could not sync users from {server_address}.")
                return 0
        except Exception as e:
            logger.error(f"Unexpected error syncing users from {server_address}: {e}")
            return 0

    async def sync_with_network(self):
        logger.info("Starting network synchronization...")
        tasks = []
        for server_address in list(self.known_servers):
            if server_address != self.address:
                tasks.append(asyncio.create_task(self.sync_with_server(server_address)))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("Network synchronization completed.")

    async def select_backup_server(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT address, reputation FROM server_nodes WHERE is_active = 1 AND address != ? ORDER BY reputation DESC, last_seen DESC LIMIT 1', (self.address,))
            row = cursor.fetchone()
            if row:
                self.backup_server = row[0]
                return row[0]
        return None

    async def sync_client_files(self, client_identifier, sid):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT content_hash, file_name, file_size FROM client_files WHERE client_identifier = ?', (client_identifier,))
                client_files = [{'content_hash': row[0], 'file_name': row[1], 'file_size': row[2]} for row in cursor.fetchall()]
                cursor.execute('SELECT domain, ddns_hash FROM client_dns_files WHERE client_identifier = ?', (client_identifier,))
                client_dns_files = [{'domain': row[0], 'ddns_hash': row[1]} for row in cursor.fetchall()]
            if client_files:
                await self.sio.emit('sync_client_files', {'files': client_files}, room=sid)
            if client_dns_files:
                await self.sio.emit('sync_client_dns_files', {'dns_files': client_dns_files}, room=sid)
        except Exception as e:
            logger.error(f"Error syncing client files for {client_identifier}: {e}")

    def get_user_reputation(self, username):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT reputation FROM user_reputations WHERE username = ?', (username,))
            row = cursor.fetchone()
            return row[0] if row else 100

    async def periodic_sync(self):
        while not self.stop_event.is_set():
            try:
                await asyncio.sleep(300)
                logger.info("Starting periodic network sync...")
                await self.sync_with_network()
                backup_server = await self.select_backup_server()
                if backup_server:
                    for sid, client in self.connected_clients.items():
                        if client.get('authenticated'):
                            await self.sio.emit('backup_server', {'server': backup_server, 'timestamp': time.time()}, room=sid)
                logger.info("Periodic network sync completed.")
            except Exception as e:
                logger.error(f"Periodic sync error: {e}")

    async def periodic_cleanup(self):
        while not self.stop_event.is_set():
            try:
                await asyncio.sleep(3600)
                logger.info("Starting periodic cleanup...")
                now = time.time()
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('DELETE FROM rate_limits WHERE last_action < ?', (now - 86400,))
                    cursor.execute('DELETE FROM pow_history WHERE timestamp < ?', (now - 604800,))
                    cursor.execute('DELETE FROM server_sync_history WHERE last_sync < ?', (now - 2592000,))
                    cursor.execute('DELETE FROM server_connectivity_log WHERE timestamp < ?', (now - 2592000,))
                    cursor.execute('UPDATE network_nodes SET is_online = 0 WHERE last_seen < ?', (now - 3600,))
                    cursor.execute('UPDATE server_nodes SET is_active = 0 WHERE last_seen < ?', (now - 86400,))
                    cursor.execute('UPDATE known_servers SET is_active = 0 WHERE last_connected < ?', (now - 604800,))
                    cursor.execute('DELETE FROM client_files WHERE last_sync < ?', (now - 2592000,))
                    cursor.execute('DELETE FROM client_dns_files WHERE last_sync < ?', (now - 2592000,))
                    conn.commit()
                logger.info("Periodic cleanup completed.")
            except Exception as e:
                logger.error(f"Periodic cleanup error: {e}")

    async def periodic_ping(self):
        while not self.stop_event.is_set():
            try:
                await asyncio.sleep(60)
                for server_address in list(self.known_servers):
                    if server_address != self.address:
                        try:
                            success, server_info, protocol_used = await self.make_remote_request_json(server_address, '/server_info')
                            if success:
                                with sqlite3.connect(self.db_path) as conn:
                                    cursor = conn.cursor()
                                    cursor.execute('UPDATE server_nodes SET last_seen = ?, reputation = MIN(100, reputation + 1) WHERE address = ?',
                                                   (time.time(), server_address))
                                    conn.commit()
                            else:
                                with sqlite3.connect(self.db_path) as conn:
                                    cursor = conn.cursor()
                                    cursor.execute('UPDATE server_nodes SET reputation = MAX(1, reputation - 1) WHERE address = ?',
                                                   (server_address,))
                                    conn.commit()
                        except Exception as e:
                            logger.debug(f"Ping to {server_address} failed: {e}")
            except Exception as e:
                logger.error(f"Periodic ping error: {e}")

    async def start(self):
        if self.is_running:
            logger.warning("Server is already running.")
            return
        self.is_running = True
        self.start_time = time.time()
        logger.info(f"Starting HPS Server on {self.host}:{self.port}")
        if self.ssl_cert and self.ssl_key:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(self.ssl_cert, self.ssl_key)
            self.runner = web.AppRunner(self.app)
            await self.runner.setup()
            self.site = web.TCPSite(self.runner, self.host, self.port, ssl_context=ssl_context)
            logger.info("SSL enabled for server.")
        else:
            self.runner = web.AppRunner(self.app)
            await self.runner.setup()
            self.site = web.TCPSite(self.runner, self.host, self.port)
            logger.warning("SSL not enabled for server.")
        await self.site.start()
        self.start_admin_console()
        asyncio.create_task(self.periodic_sync())
        asyncio.create_task(self.periodic_cleanup())
        asyncio.create_task(self.periodic_ping())
        logger.info(f"HPS Server started successfully on {self.host}:{self.port}")
        await self.stop_event.wait()

    async def stop(self):
        if not self.is_running:
            logger.warning("Server is not running.")
            return
        logger.info("Stopping HPS Server...")
        self.stop_event.set()
        for task in self.server_sync_tasks.values():
            task.cancel()
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()
        self.is_running = False
        logger.info("HPS Server stopped.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='HPS Server')
    parser.add_argument('--db', default='hps_server.db', help='Database file path')
    parser.add_argument('--files', default='hps_files', help='Files directory')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind to')
    parser.add_argument('--ssl-cert', help='SSL certificate file')
    parser.add_argument('--ssl-key', help='SSL private key file')
    args = parser.parse_args()
    server = HPSServer(db_path=args.db, files_dir=args.files, host=args.host, port=args.port, ssl_cert=args.ssl_cert, ssl_key=args.ssl_key)
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        asyncio.run(server.stop())
    except Exception as e:
        logger.error(f"Server error: {e}")
        asyncio.run(server.stop())
