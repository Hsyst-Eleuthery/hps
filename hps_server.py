# hps_server.py (versão completa com sistema de contratos e correções)
import asyncio
import aiohttp
from aiohttp import web
import socket
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
from contextlib import contextmanager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("HPS-Server")

DB_LOCK = threading.RLock()
CUSTODY_USERNAME = "custody"
OWNER_USERNAME_DEFAULT = "owner"
PENDING_PUBLIC_KEY = "pending"

@contextmanager
def get_db_conn(db_path: str):
    with DB_LOCK:
        conn = sqlite3.connect(db_path, timeout=60)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

class HPSAdminConsole(cmd.Cmd):
    intro = 'HPS Administration Console\nType "help" for commands\n'
    prompt = '(hps-admin) '

    def __init__(self, server):
        super().__init__()
        self.server = server

    def do_contracts(self, arg):
        """Buscar contratos por hash, domínio, usuário ou tipo"""
        args = arg.split()
        search_type = args[0] if args else "all"
        search_value = args[1] if len(args) > 1 else ""
        
        with get_db_conn(self.server.db_path) as conn:
            cursor = conn.cursor()
            
            if search_type == "hash":
                cursor.execute('''
                    SELECT contract_id, action_type, content_hash, domain, username, 
                           signature, timestamp, verified, contract_content
                    FROM contracts 
                    WHERE content_hash LIKE ? 
                    ORDER BY timestamp DESC
                ''', (f'%{search_value}%',))
            elif search_type == "domain":
                cursor.execute('''
                    SELECT contract_id, action_type, content_hash, domain, username, 
                           signature, timestamp, verified, contract_content
                    FROM contracts 
                    WHERE domain LIKE ? 
                    ORDER BY timestamp DESC
                ''', (f'%{search_value}%',))
            elif search_type == "user":
                cursor.execute('''
                    SELECT contract_id, action_type, content_hash, domain, username, 
                           signature, timestamp, verified, contract_content
                    FROM contracts 
                    WHERE username LIKE ? 
                    ORDER BY timestamp DESC
                ''', (f'%{search_value}%',))
            elif search_type == "type":
                cursor.execute('''
                    SELECT contract_id, action_type, content_hash, domain, username, 
                           signature, timestamp, verified, contract_content
                    FROM contracts 
                    WHERE action_type = ? 
                    ORDER BY timestamp DESC
                ''', (search_value,))
            else:
                cursor.execute('''
                    SELECT contract_id, action_type, content_hash, domain, username, 
                           signature, timestamp, verified, contract_content
                    FROM contracts 
                    ORDER BY timestamp DESC 
                    LIMIT 50
                ''')
            
            rows = cursor.fetchall()
            
            if not rows:
                print("Nenhum contrato encontrado.")
                return
            
            print(f"\n{'='*80}")
            print(f"{'CONTRATOS ENCONTRADOS':^80}")
            print(f"{'='*80}")
            
            for row in rows:
                contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content = row
                print(f"\nID: {contract_id}")
                print(f"Ação: {action_type}")
                print(f"Hash: {content_hash[:16]}..." if content_hash else "Hash: N/A")
                print(f"Domínio: {domain}" if domain else "Domínio: N/A")
                print(f"Usuário: {username}")
                print(f"Assinatura válida: {'SIM' if verified else 'NÃO'}")
                print(f"Data: {datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"{'-'*40}")
                
                if contract_content:
                    try:
                        contract_text = base64.b64decode(contract_content).decode('utf-8')
                        lines = contract_text.split('\n')
                        print("Conteúdo do contrato:")
                        for i, line in enumerate(lines[:20]):
                            print(f"  {line}")
                        if len(lines) > 20:
                            print(f"  ... ({len(lines)-20} linhas restantes)")
                    except:
                        print("  [Conteúdo binário ou inválido]")
                
                print(f"{'-'*40}")
                print("Opções:")
                print("  1. Verificar assinatura")
                print("  2. Ver conteúdo completo")
                print("  3. Sincronizar com rede")
                print("  0. Próximo contrato")
                
                choice = input("Escolha (0-3, padrão=0): ").strip()
                if choice == '1':
                    self.server.verify_contract_signature(contract_id)
                elif choice == '2':
                    if contract_content:
                        try:
                            contract_text = base64.b64decode(contract_content).decode('utf-8')
                            print(f"\n{'='*80}")
                            print(contract_text)
                            print(f"{'='*80}")
                        except:
                            print("Erro ao decodificar conteúdo do contrato.")
                elif choice == '3':
                    asyncio.run_coroutine_threadsafe(
                        self.server.propagate_contract_to_network(contract_id),
                        self.server.loop
                    )
                    print("Sincronização iniciada.")
            
            print(f"\nTotal de contratos: {len(rows)}")

    def do_verify_contract(self, arg):
        """Verificar assinatura de um contrato específico"""
        if not arg:
            print("Uso: verify_contract <contract_id>")
            return
        
        contract_id = arg.strip()
        success = self.server.verify_contract_signature(contract_id)
        
        if success:
            print(f"Contrato {contract_id} verificado com sucesso.")
        else:
            print(f"Falha ao verificar contrato {contract_id}.")

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
        with get_db_conn(self.server.db_path) as conn:
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
        with get_db_conn(self.server.db_path) as conn:
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
            cursor.execute('SELECT COUNT(*) FROM contracts')
            total_contracts = cursor.fetchone()[0]
        print(f"Total users: {total_users}")
        print(f"Total content: {total_content}")
        print(f"DNS records: {total_dns}")
        print(f"Online nodes: {online_nodes}")
        print(f"Connected clients: {len(self.server.connected_clients)}")
        print(f"Known servers: {len(self.server.known_servers)}")
        print(f"Pending reports: {pending_reports}")
        print(f"Total contracts: {total_contracts}")

    def do_content_stats(self, arg):
        with get_db_conn(self.server.db_path) as conn:
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
        with get_db_conn(self.db_path) as conn:
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
        with get_db_conn(self.db_path) as conn:
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
        with get_db_conn(self.db_path) as conn:
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

    def do_generate_voucher(self, arg):
        """Gerar voucher sem PoW: generate_voucher <user> <quantidade>"""
        args = arg.split()
        if len(args) < 2:
            print("Usage: generate_voucher <user> <quantidade>")
            return
        username = args[0].strip()
        try:
            value = int(args[1])
        except Exception:
            print("Quantidade invalida.")
            return
        if value <= 0:
            print("Quantidade invalida.")
            return
        owner_key = self.server.get_user_public_key(username) or self.server.get_registered_public_key(username)
        if not owner_key:
            print("Usuario sem chave publica registrada.")
            return
        offer = self.server.create_voucher_offer(
            owner=username,
            owner_public_key=owner_key,
            value=value,
            reason="admin_test",
            pow_info=None,
            conditions={"type": "admin_test"}
        )
        user_info = self.server.authenticated_users.get(username, {})
        user_sid = user_info.get("sid")
        if user_sid:
            asyncio.run_coroutine_threadsafe(
                self.server.sio.emit('hps_voucher_offer', {
                    'offer_id': offer["offer_id"],
                    'voucher_id': offer["voucher_id"],
                    'payload': offer["payload"],
                    'expires_at': offer["expires_at"]
                }, room=user_sid),
                self.server.loop
            )
        print(f"Voucher gerado: {offer.get('voucher_id')} ({value} HPS)")

    def do_exit(self, arg):
        print("Stopping server...")
        asyncio.run_coroutine_threadsafe(self.server.stop(), self.server.loop)
        return True

    def do_help(self, arg):
        print("\nAvailable commands:")
        print("  contracts [type] [value] - Buscar contratos (hash, domain, user, type)")
        print("  verify_contract <id> - Verificar assinatura de contrato")
        print("  online_users - List online users")
        print("  ban_user <user> <seconds> <reason> - Ban a user")
        print("  reputation <user> [new_rep] - Show or change reputation")
        print("  server_stats - Server statistics")
        print("  content_stats - Content statistics")
        print("  node_stats - Node statistics")
        print("  list_reports - List pending reports")
        print("  resolve_report <report_id> [action] - Resolve a report")
        print("  sync_network - Sync with network")
        print("  generate_voucher <user> <quantidade> - Gerar voucher sem PoW")
        print("  exit - Stop server")
        print("  help - Show this help\n")

class HPSServer:
    def __init__(self, db_path: str = 'hps_server.db', files_dir: str = 'hps_files',
                 host: str = '0.0.0.0', port: int = 8080, ssl_cert: str = None, ssl_key: str = None,
                 owner_enabled: bool = False, owner_username: str = OWNER_USERNAME_DEFAULT):
        self.db_path = db_path
        self.files_dir = files_dir
        self.host = host
        self.port = port
        self.bind_address = f"{host}:{port}"
        self.advertise_host = self.detect_advertise_host()
        self.address = f"{self.advertise_host}:{port}"
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.sio = socketio.AsyncServer(
            async_mode='aiohttp',
            cors_allowed_origins='*',
            ping_timeout=180,
            ping_interval=25,
            max_http_buffer_size=200 * 1024 * 1024
        )
        self.app = web.Application(client_max_size=200 * 1024 * 1024)
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
        self.usage_contract_text = ""
        self.usage_contract_hash = ""
        self.hps_voucher_offers: Dict[str, Dict[str, Any]] = {}
        self.hps_stream_rules: Dict[str, Any] = {}
        self.hps_voucher_unit_bits = 8
        self.hps_voucher_max_value = 50
        self.hps_issuer_invalidated = False
        self.owner_enabled = owner_enabled
        self.owner_username = owner_username or OWNER_USERNAME_DEFAULT
        self.owner_password_path = os.path.join(self.files_dir, "owner_credentials.txt")
        self.owner_password_hash = None
        self.exchange_fee_rate = 0.02
        self.exchange_fee_min = 1
        self.exchange_quote_ttl = 600
        self.exchange_tokens: Dict[str, Dict[str, Any]] = {}
        self.exchange_quotes: Dict[str, Dict[str, Any]] = {}
        self.deferred_action_handlers: Dict[str, Any] = {}
        self.hps_pow_costs = {
            "upload": 4,
            "dns": 4,
            "report": 4,
            "contract_transfer": 4,
            "contract_reset": 4,
            "contract_certify": 4,
            "usage_contract": 4,
            "hps_transfer": 4
        }
        self.generate_server_keys()
        self.setup_routes()
        self.setup_handlers()
        self.init_database()
        self.load_known_servers()
        os.makedirs(files_dir, exist_ok=True)
        os.makedirs(os.path.join(files_dir, "contracts"), exist_ok=True)
        os.makedirs(os.path.join(files_dir, "vouchers"), exist_ok=True)
        self.load_usage_contract_template()
        self.load_stream_rules()
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
        with get_db_conn(self.db_path) as conn:
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
                client_identifier TEXT, violation_count INTEGER DEFAULT 0,
                contract_penalty_base INTEGER)''',
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
                redirect_type TEXT NOT NULL, timestamp REAL NOT NULL)''',
                '''CREATE TABLE IF NOT EXISTS contracts (
contract_id TEXT PRIMARY KEY, action_type TEXT NOT NULL, content_hash TEXT,
domain TEXT, username TEXT NOT NULL, signature TEXT NOT NULL, timestamp REAL NOT NULL,
                verified INTEGER DEFAULT 0, contract_content BLOB NOT NULL,
                FOREIGN KEY (content_hash) REFERENCES content(content_hash) ON DELETE CASCADE)''',
                '''CREATE TABLE IF NOT EXISTS contract_violations (
violation_id TEXT PRIMARY KEY, violation_type TEXT NOT NULL, content_hash TEXT,
domain TEXT, owner_username TEXT NOT NULL, reported_by TEXT NOT NULL,
timestamp REAL NOT NULL, reason TEXT NOT NULL,
UNIQUE(violation_type, content_hash, domain))''',
                '''CREATE TABLE IF NOT EXISTS contract_certifications (
cert_id TEXT PRIMARY KEY, target_type TEXT NOT NULL, target_id TEXT NOT NULL,
original_owner TEXT NOT NULL, certifier TEXT NOT NULL, timestamp REAL NOT NULL,
UNIQUE(target_type, target_id))''',
                '''CREATE TABLE IF NOT EXISTS pending_transfers (
transfer_id TEXT PRIMARY KEY, transfer_type TEXT NOT NULL, target_user TEXT NOT NULL,
original_owner TEXT NOT NULL, custody_user TEXT NOT NULL, content_hash TEXT,
domain TEXT, app_name TEXT, contract_id TEXT, status TEXT NOT NULL,
timestamp REAL NOT NULL)''',
                '''CREATE TABLE IF NOT EXISTS contract_valid_archive (
archive_id TEXT PRIMARY KEY, target_type TEXT NOT NULL, target_id TEXT NOT NULL,
contract_content BLOB NOT NULL, updated_at REAL NOT NULL,
UNIQUE(target_type, target_id))''',
                '''CREATE TABLE IF NOT EXISTS client_contracts (
client_identifier TEXT NOT NULL, contract_id TEXT NOT NULL, last_sync REAL NOT NULL,
                PRIMARY KEY (client_identifier, contract_id))''',
                '''CREATE TABLE IF NOT EXISTS usage_contract_acceptance (
username TEXT NOT NULL, contract_hash TEXT NOT NULL, accepted_at REAL NOT NULL,
                PRIMARY KEY (username, contract_hash))''',
                '''CREATE TABLE IF NOT EXISTS hps_vouchers (
voucher_id TEXT PRIMARY KEY, issuer TEXT NOT NULL, owner TEXT NOT NULL,
value INTEGER NOT NULL, reason TEXT NOT NULL, issued_at REAL NOT NULL,
payload TEXT NOT NULL, issuer_signature TEXT NOT NULL, owner_signature TEXT NOT NULL,
status TEXT NOT NULL, session_id TEXT, invalidated INTEGER DEFAULT 0, last_updated REAL NOT NULL)''',
                '''CREATE TABLE IF NOT EXISTS miner_stats (
username TEXT PRIMARY KEY, minted_count INTEGER DEFAULT 0, minted_total REAL DEFAULT 0,
pending_signatures INTEGER DEFAULT 0, last_updated REAL NOT NULL,
banned_until REAL DEFAULT 0, ban_reason TEXT)''',
                '''CREATE TABLE IF NOT EXISTS miner_debt_entries (
entry_id TEXT PRIMARY KEY, username TEXT NOT NULL, entry_type TEXT NOT NULL,
amount INTEGER DEFAULT 0, status TEXT NOT NULL,
created_at REAL NOT NULL, resolved_at REAL, metadata TEXT)''',
                '''CREATE TABLE IF NOT EXISTS monetary_transfers (
transfer_id TEXT PRIMARY KEY, transfer_type TEXT NOT NULL, sender TEXT NOT NULL,
receiver TEXT NOT NULL, amount INTEGER NOT NULL, created_at REAL NOT NULL,
status TEXT NOT NULL, contract_id TEXT, locked_voucher_ids TEXT,
assigned_miner TEXT, deadline REAL, miner_deadline REAL,
fee_amount INTEGER DEFAULT 0, fee_source TEXT, inter_server_payload TEXT,
signed_by TEXT, signed_at REAL)''',
                '''CREATE TABLE IF NOT EXISTS pending_monetary_actions (
action_id TEXT PRIMARY KEY, transfer_id TEXT NOT NULL, action_name TEXT NOT NULL,
username TEXT NOT NULL, client_identifier TEXT, payload TEXT NOT NULL,
response_event TEXT NOT NULL, status TEXT NOT NULL, created_at REAL NOT NULL,
updated_at REAL NOT NULL)''',
                '''CREATE TABLE IF NOT EXISTS transfer_signatures (
signature_id TEXT PRIMARY KEY, transfer_id TEXT NOT NULL, miner TEXT NOT NULL,
signature TEXT NOT NULL, contract_content BLOB NOT NULL, created_at REAL NOT NULL)''',
                '''CREATE TABLE IF NOT EXISTS hps_voucher_offers (
offer_id TEXT PRIMARY KEY, voucher_id TEXT NOT NULL, owner TEXT NOT NULL,
payload TEXT NOT NULL, value INTEGER NOT NULL, reason TEXT NOT NULL,
issued_at REAL NOT NULL, expires_at REAL NOT NULL, status TEXT NOT NULL)''',
                '''CREATE TABLE IF NOT EXISTS hps_transfer_sessions (
session_id TEXT PRIMARY KEY, offer_id TEXT NOT NULL, voucher_id TEXT NOT NULL,
payer TEXT NOT NULL, target TEXT NOT NULL, voucher_ids TEXT NOT NULL,
amount INTEGER NOT NULL, total_value INTEGER NOT NULL,
status TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL)''',
                '''CREATE TABLE IF NOT EXISTS hps_issuer_invalidations (
issuer TEXT PRIMARY KEY, reason TEXT NOT NULL, session_id TEXT, invalidated_at REAL NOT NULL)'''
                ,'''CREATE TABLE IF NOT EXISTS hps_economy_stats (
stat_key TEXT PRIMARY KEY, stat_value REAL NOT NULL)'''
                ,'''CREATE TABLE IF NOT EXISTS fraud_restrictions (
username TEXT NOT NULL, issuer TEXT NOT NULL, reason TEXT NOT NULL,
restricted_at REAL NOT NULL, PRIMARY KEY (username, issuer))'''
            ]
            for table in tables:
                cursor.execute(table)
            self.ensure_user_reputation_columns(conn)
            self.ensure_hps_economy_stats(conn)
            self.ensure_miner_stats_columns(conn)
            self.ensure_pending_transfer_columns(conn)
            self.ensure_monetary_transfer_columns(conn)
            self.ensure_custody_user(conn)
            self.ensure_owner_user(conn)
            conn.commit()

    def ensure_user_reputation_columns(self, conn: sqlite3.Connection) -> None:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(user_reputations)")
        columns = {row[1] for row in cursor.fetchall()}
        if "contract_penalty_base" not in columns:
            cursor.execute("ALTER TABLE user_reputations ADD COLUMN contract_penalty_base INTEGER")

    def ensure_hps_economy_stats(self, conn: sqlite3.Connection) -> None:
        cursor = conn.cursor()
        defaults = {
            "total_minted": 0.0,
            "custody_balance": 0.0,
            "owner_balance": 0.0,
            "rebate_balance": 0.0,
            "last_economy_hash": "",
            "last_economy_update_ts": 0.0,
            "last_economy_event_ts": 0.0,
            "last_economy_event_reason": ""
        }
        for key, value in defaults.items():
            cursor.execute('SELECT stat_value FROM hps_economy_stats WHERE stat_key = ?', (key,))
            row = cursor.fetchone()
            if row is None:
                cursor.execute('INSERT INTO hps_economy_stats (stat_key, stat_value) VALUES (?, ?)', (key, value))

    def ensure_miner_stats_columns(self, conn: sqlite3.Connection) -> None:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(miner_stats)")
        columns = {row[1] for row in cursor.fetchall()}
        if "pending_fines" not in columns:
            cursor.execute("ALTER TABLE miner_stats ADD COLUMN pending_fines INTEGER DEFAULT 0")
        if "fine_promise_amount" not in columns:
            cursor.execute("ALTER TABLE miner_stats ADD COLUMN fine_promise_amount REAL DEFAULT 0")
        if "fine_promise_active" not in columns:
            cursor.execute("ALTER TABLE miner_stats ADD COLUMN fine_promise_active INTEGER DEFAULT 0")

    def ensure_pending_transfer_columns(self, conn: sqlite3.Connection) -> None:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(pending_transfers)")
        columns = {row[1] for row in cursor.fetchall()}
        if "hps_amount" not in columns:
            cursor.execute("ALTER TABLE pending_transfers ADD COLUMN hps_amount INTEGER")
        if "hps_total_value" not in columns:
            cursor.execute("ALTER TABLE pending_transfers ADD COLUMN hps_total_value INTEGER")
        if "hps_voucher_ids" not in columns:
            cursor.execute("ALTER TABLE pending_transfers ADD COLUMN hps_voucher_ids TEXT")
        if "hps_session_id" not in columns:
            cursor.execute("ALTER TABLE pending_transfers ADD COLUMN hps_session_id TEXT")

    def ensure_monetary_transfer_columns(self, conn: sqlite3.Connection) -> None:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(monetary_transfers)")
        columns = {row[1] for row in cursor.fetchall()}
        if "inter_server_payload" not in columns:
            cursor.execute("ALTER TABLE monetary_transfers ADD COLUMN inter_server_payload TEXT DEFAULT ''")
    def ensure_custody_user(self, conn: sqlite3.Connection) -> None:
        cursor = conn.cursor()
        cursor.execute('SELECT public_key FROM users WHERE username = ?', (CUSTODY_USERNAME,))
        row = cursor.fetchone()
        server_key_b64 = base64.b64encode(self.public_key_pem).decode("utf-8")
        if not row:
            password_hash = hashlib.sha256(CUSTODY_USERNAME.encode("utf-8")).hexdigest()
            cursor.execute('''INSERT OR IGNORE INTO users
                (username, password_hash, public_key, created_at, last_login, reputation, client_identifier, last_activity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (CUSTODY_USERNAME, password_hash, server_key_b64, time.time(), time.time(), 100, "system", time.time()))
        elif row[0] != server_key_b64:
            cursor.execute('UPDATE users SET public_key = ? WHERE username = ?', (server_key_b64, CUSTODY_USERNAME))

    def ensure_owner_user(self, conn: sqlite3.Connection) -> None:
        if not self.owner_enabled:
            return
        password = self.load_or_create_owner_password()
        if not password:
            return
        self.owner_password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash, public_key FROM users WHERE username = ?', (self.owner_username,))
        row = cursor.fetchone()
        if not row:
            cursor.execute('''INSERT OR IGNORE INTO users
                (username, password_hash, public_key, created_at, last_login, reputation, client_identifier, last_activity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (self.owner_username, self.owner_password_hash, PENDING_PUBLIC_KEY, time.time(), 0.0, 100, "system", time.time()))
            cursor.execute('''INSERT OR REPLACE INTO user_reputations
                (username, reputation, last_updated, client_identifier) VALUES (?, ?, ?, ?)''',
                (self.owner_username, 100, time.time(), "system"))
        else:
            stored_hash, stored_key = row
            if stored_hash != self.owner_password_hash:
                cursor.execute('UPDATE users SET password_hash = ? WHERE username = ?', (self.owner_password_hash, self.owner_username))
            if stored_key in ("", None):
                cursor.execute('UPDATE users SET public_key = ? WHERE username = ?', (PENDING_PUBLIC_KEY, self.owner_username))

    def load_or_create_owner_password(self) -> Optional[str]:
        os.makedirs(self.files_dir, exist_ok=True)
        if os.path.exists(self.owner_password_path):
            try:
                with open(self.owner_password_path, "r", encoding="ascii") as f:
                    value = f.read().strip()
                if ":" in value:
                    _, password = value.split(":", 1)
                    return password.strip()
                return value.strip()
            except Exception as e:
                logger.error(f"Failed to load owner credentials: {e}")
                return None
        password = secrets.token_urlsafe(12)
        try:
            with open(self.owner_password_path, "w", encoding="ascii") as f:
                f.write(f"{self.owner_username}:{password}\n")
        except Exception as e:
            logger.error(f"Failed to write owner credentials: {e}")
            return None
        return password

    def load_known_servers(self):
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT address FROM known_servers WHERE is_active = 1')
            self.known_servers = {row[0] for row in cursor.fetchall()}
        logger.info(f"Loaded {len(self.known_servers)} known servers")

    def load_usage_contract_template(self) -> None:
        os.makedirs(self.files_dir, exist_ok=True)
        contract_path = os.path.join(self.files_dir, "usage_contract.txt")
        if not os.path.exists(contract_path):
            default_text = (
                "TERMO DE USO DA REDE HSYST\n"
                "\n"
                "1) Este contrato confirma que voce reconhece o uso da sua chave privada\n"
                "   para assinar operacoes nesta rede.\n"
                "2) Voce e responsavel por manter suas credenciais em seguranca.\n"
                "3) Operacoes assinadas serao tratadas como autorizadas pelo titular.\n"
                "\n"
                "Ao continuar, voce declara estar de acordo com estes termos.\n"
            )
            with open(contract_path, "w", encoding="utf-8") as f:
                f.write(default_text)
            logger.info("Contrato de uso inicial criado em files_dir/usage_contract.txt")
        with open(contract_path, "r", encoding="utf-8") as f:
            text = f.read().strip()
        self.usage_contract_text = text
        self.usage_contract_hash = hashlib.sha256(text.encode('utf-8')).hexdigest()

    def load_stream_rules(self) -> None:
        rules_path = os.path.join(self.files_dir, "stream_rules.json")
        if not os.path.exists(rules_path):
            default_rules = {
                "base_cost": 1,
                "size_cost_per_kb": 0.02,
                "min_cost": 1,
                "interval_tiers": [
                    {"max_interval": 2, "multiplier": 4.0},
                    {"max_interval": 5, "multiplier": 2.0},
                    {"max_interval": 10, "multiplier": 1.0},
                    {"max_interval": 30, "multiplier": 0.6},
                    {"max_interval": 60, "multiplier": 0.3}
                ]
            }
            with open(rules_path, "w", encoding="ascii") as f:
                json.dump(default_rules, f, indent=2)
        try:
            with open(rules_path, "r", encoding="ascii") as f:
                self.hps_stream_rules = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load stream rules: {e}")
            self.hps_stream_rules = {}

    def canonicalize_payload(self, payload: Dict[str, Any]) -> str:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    def sanitize_payload_field(self, data: Any) -> Dict[str, Any]:
        if data is None:
            return {}
        if not isinstance(data, dict):
            return {}
        try:
            return json.loads(json.dumps(data, ensure_ascii=True))
        except RecursionError:
            logger.error("Recursion error while sanitizing payload field")
        except Exception:
            pass
        return {}

    def compute_voucher_integrity_hash(self, payload: Dict[str, Any], signatures: Dict[str, Any]) -> str:
        data = json.dumps(
            {"payload": payload, "signatures": signatures},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True
        )
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def attach_voucher_integrity(self, voucher: Dict[str, Any]) -> Dict[str, Any]:
        payload = voucher.get("payload", {})
        signatures = voucher.get("signatures", {})
        voucher["integrity"] = {
            "hash": self.compute_voucher_integrity_hash(payload, signatures),
            "algo": "sha256"
        }
        return voucher

    def build_economy_report(self) -> Dict[str, Any]:
        payload = {
            "issuer": self.address,
            "issuer_public_key": base64.b64encode(self.public_key_pem).decode("utf-8"),
            "timestamp": time.time(),
            "total_minted": self.get_economy_stat("total_minted", 0.0),
            "custody_balance": self.get_economy_stat("custody_balance", 0.0),
            "owner_balance": self.get_economy_stat("owner_balance", 0.0),
            "rebate_balance": self.get_economy_stat("rebate_balance", 0.0),
            "multiplier": self.get_economy_multiplier(),
            "exchange_fee_rate": self.exchange_fee_rate,
            "exchange_fee_min": self.exchange_fee_min,
            "pow_costs": {k: self.get_hps_pow_cost(k, apply_discount=False) for k in self.hps_pow_costs.keys()}
        }
        signature = self.sign_payload(payload)
        return {"payload": payload, "signature": signature}

    def verify_economy_report(self, report: Dict[str, Any]) -> bool:
        payload = report.get("payload", {})
        signature = report.get("signature", "")
        issuer_key = payload.get("issuer_public_key", "")
        if not payload or not signature or not issuer_key:
            return False
        return self.verify_payload_signature(payload, signature, issuer_key)

    def detect_advertise_host(self) -> str:
        if self.host not in ("0.0.0.0", "::"):
            return self.host
        try:
            candidate = socket.gethostbyname(socket.gethostname())
            if candidate and not candidate.startswith("127."):
                return candidate
        except Exception:
            pass
        return "127.0.0.1"

    def is_local_issuer(self, issuer: str) -> bool:
        return issuer in {self.address, self.bind_address}

    def verify_voucher_blob(self, voucher: Dict[str, Any]) -> Tuple[bool, str]:
        payload = voucher.get("payload", {})
        signatures = voucher.get("signatures", {})
        if not payload or not signatures:
            return False, "Voucher payload/signatures missing"
        owner_key = payload.get("owner_public_key", "")
        issuer_key = payload.get("issuer_public_key", "")
        if not owner_key or not issuer_key:
            return False, "Voucher public keys missing"
        if not self.verify_payload_signature(payload, signatures.get("owner", ""), owner_key):
            return False, "Owner signature invalid"
        if not self.verify_payload_signature(payload, signatures.get("issuer", ""), issuer_key):
            return False, "Issuer signature invalid"
        return True, ""

    def verify_voucher_pow_payload(self, payload: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
        pow_info = payload.get("pow", {}) or {}
        challenge = pow_info.get("challenge", "")
        nonce = pow_info.get("nonce", "")
        target_bits = int(pow_info.get("target_bits", 0) or 0)
        action_type = pow_info.get("action_type", "") or ""
        voucher_id = payload.get("voucher_id", "")
        pow_voucher_id = pow_info.get("voucher_id", "")
        details = {
            "challenge": challenge,
            "nonce": nonce,
            "target_bits": target_bits,
            "action_type": action_type,
            "voucher_id_match": pow_voucher_id == voucher_id if pow_voucher_id else False,
            "leading_zero_bits": 0
        }
        if not challenge or nonce == "" or target_bits <= 0:
            return False, "pow_missing", details
        if pow_voucher_id and pow_voucher_id != voucher_id:
            return False, "pow_voucher_mismatch", details
        try:
            challenge_bytes = base64.b64decode(challenge)
            nonce_int = int(nonce)
            data = challenge_bytes + struct.pack(">Q", nonce_int)
            hash_result = hashlib.sha256(data).digest()
            lzb = self.leading_zero_bits(hash_result)
            details["leading_zero_bits"] = lzb
            if lzb < target_bits:
                return False, "pow_invalid", details
        except Exception:
            return False, "pow_invalid", details
        if action_type == "hps_mint":
            try:
                challenge_text = base64.b64decode(challenge).decode("ascii", errors="replace")
            except Exception:
                challenge_text = ""
            if not challenge_text.startswith(f"HPSMINT:{voucher_id}:"):
                return False, "pow_challenge_mismatch", details
        return True, "", details

    def get_trace_source_vouchers(self, voucher_id: str) -> List[str]:
        if not voucher_id:
            return []
        trace_ids: List[str] = []
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT action_type, contract_content FROM contracts
                              WHERE content_hash = ? AND action_type IN (?, ?, ?, ?)
                              ORDER BY timestamp DESC''',
                           (voucher_id, "hps_spend_refund", "hps_transfer_refund", "hps_transfer_custody_refund",
                            "miner_fine_refund"))
            rows = cursor.fetchall()
        for action_type, contract_b64 in rows:
            if not contract_b64:
                continue
            try:
                contract_bytes = base64.b64decode(contract_b64)
                valid, _, contract_info = self.validate_contract_structure(contract_bytes)
            except Exception:
                continue
            if not valid:
                continue
            if action_type in ("hps_spend_refund", "miner_fine_refund", "hps_transfer_custody_refund"):
                raw_list = self.extract_contract_detail(contract_info, "VOUCHERS")
                if raw_list:
                    try:
                        trace_ids.extend(json.loads(raw_list))
                    except Exception:
                        continue
            elif action_type == "hps_transfer_refund":
                source_id = self.extract_contract_detail(contract_info, "ORIGINAL_VOUCHER_ID")
                if source_id:
                    trace_ids.append(source_id)
        return list(dict.fromkeys(trace_ids))

    def is_user_fraud_restricted(self, username: str) -> bool:
        if not username:
            return False
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT 1 FROM fraud_restrictions WHERE username = ? LIMIT 1', (username,))
            return bool(cursor.fetchone())

    def set_user_fraud_restriction(self, username: str, issuer: str, reason: str) -> None:
        if not username or not issuer:
            return
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT OR REPLACE INTO fraud_restrictions (username, issuer, reason, restricted_at) VALUES (?, ?, ?, ?)',
                (username, issuer, reason or "fraud_report", time.time())
            )
            cursor.execute('UPDATE user_reputations SET reputation = MAX(1, reputation - 30) WHERE username = ?', (username,))
            cursor.execute('UPDATE users SET reputation = MAX(1, reputation - 30) WHERE username = ?', (username,))
            conn.commit()

    def register_fraudulent_issuer(self, issuer: str, report: Dict[str, Any]) -> Optional[str]:
        if not issuer:
            return None
        contract_id = self.save_server_contract(
            "economy_alert",
            [
                ("ISSUER", issuer),
                ("REASON", "fraud_report"),
                ("EVIDENCE", json.dumps(report, ensure_ascii=True))
            ]
        )
        asyncio.create_task(self.propagate_contract_to_network(contract_id))
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT OR REPLACE INTO hps_issuer_invalidations (issuer, reason, session_id, invalidated_at) VALUES (?, ?, ?, ?)',
                (issuer, "fraud_report", report.get("contract_id", ""), time.time())
            )
            conn.commit()
            cursor.execute('SELECT DISTINCT owner FROM hps_vouchers WHERE reason = ?', (f"exchange_from:{issuer}",))
            owners = [row[0] for row in cursor.fetchall()]
        for owner in owners:
            self.set_user_fraud_restriction(owner, issuer, "fraud_exchange")
        return contract_id

    def get_voucher_audit_info(self, voucher_id: str) -> Optional[Dict[str, Any]]:
        if not voucher_id:
            return None
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT payload, issuer_signature, owner_signature, status, invalidated
                              FROM hps_vouchers WHERE voucher_id = ?''', (voucher_id,))
            row = cursor.fetchone()
            if not row:
                return None
            payload_text, issuer_signature, owner_signature, status, invalidated = row
            try:
                payload = json.loads(payload_text)
            except Exception:
                payload = {}
            cursor.execute('''SELECT contract_content FROM contracts
                              WHERE action_type = ? AND content_hash = ?
                              ORDER BY timestamp DESC LIMIT 1''', ("voucher_issue", voucher_id))
            issue_row = cursor.fetchone()
            issue_contract = issue_row[0] if issue_row else None
            cursor.execute('''SELECT contract_content FROM contracts
                              WHERE action_type = ? AND content_hash = ?
                              ORDER BY timestamp DESC LIMIT 1''', ("voucher_invalidate", voucher_id))
            invalid_row = cursor.fetchone()
            invalid_contract = invalid_row[0] if invalid_row else None
            cursor.execute('''SELECT contract_id, action_type, contract_content FROM contracts
                              WHERE content_hash = ? AND action_type IN (?, ?, ?, ?)
                              ORDER BY timestamp DESC''',
                           (voucher_id, "hps_spend_refund", "hps_transfer_refund",
                            "hps_transfer_custody_refund", "miner_fine_refund"))
            trace_contracts = [
                {
                    "contract_id": row[0],
                    "action_type": row[1],
                    "contract_content": row[2] or ""
                }
                for row in cursor.fetchall()
            ]
        return {
            "voucher_id": voucher_id,
            "payload": payload,
            "signatures": {
                "owner": owner_signature,
                "issuer": issuer_signature
            },
            "status": status,
            "invalidated": bool(invalidated),
            "issue_contract": issue_contract or "",
            "invalidate_contract": invalid_contract or "",
            "trace_contracts": trace_contracts
        }

    def validate_vouchers(self, voucher_ids: List[str], enforce_pow: bool = True) -> Tuple[bool, Dict[str, str]]:
        failures: Dict[str, str] = {}
        pow_cache: Dict[str, bool] = {}
        def trace_has_pow(voucher_id: str, visited: set, depth: int) -> bool:
            if depth <= 0 or not voucher_id:
                return False
            if voucher_id in pow_cache:
                return pow_cache[voucher_id]
            info = self.get_voucher_audit_info(voucher_id)
            if not info:
                pow_cache[voucher_id] = False
                return False
            payload = info.get("payload", {}) or {}
            pow_ok, _, pow_details = self.verify_voucher_pow_payload(payload)
            if pow_ok and pow_details.get("action_type") == "hps_mint":
                pow_cache[voucher_id] = True
                return True
            trace_ids = self.get_trace_source_vouchers(voucher_id)
            conditions = payload.get("conditions", {}) or {}
            if conditions.get("type") == "exchange" and conditions.get("issuer_voucher_ids"):
                trace_ids = conditions.get("issuer_voucher_ids", []) or trace_ids
            for source_id in trace_ids:
                if not source_id or source_id in visited:
                    continue
                visited.add(source_id)
                if trace_has_pow(source_id, visited, depth - 1):
                    pow_cache[voucher_id] = True
                    return True
            pow_cache[voucher_id] = False
            return False
        for voucher_id in voucher_ids:
            info = self.get_voucher_audit_info(voucher_id)
            if not info:
                failures[voucher_id] = "voucher_missing"
                continue
            status = info.get("status")
            if info.get("invalidated") or status not in ("valid", "reserved", "locked"):
                failures[voucher_id] = "voucher_invalidated"
                continue
            voucher = {
                "payload": info.get("payload", {}),
                "signatures": info.get("signatures", {}),
                "integrity": {}
            }
            ok, error = self.verify_voucher_blob(voucher)
            if not ok:
                failures[voucher_id] = error or "voucher_signature_invalid"
                continue
            issue_contract = info.get("issue_contract") or ""
            if not issue_contract:
                failures[voucher_id] = "missing_issue_contract"
                continue
            try:
                contract_bytes = base64.b64decode(issue_contract)
            except Exception:
                failures[voucher_id] = "issue_contract_decode_error"
                continue
            valid, error_msg, contract_info = self.validate_contract_structure(contract_bytes)
            if not valid or contract_info.get("action") != "voucher_issue":
                failures[voucher_id] = "issue_contract_invalid"
                continue
            if not self.verify_contract_signature(
                contract_content=contract_bytes,
                username=contract_info.get("user"),
                signature=contract_info.get("signature")
            ):
                failures[voucher_id] = "issue_contract_signature_invalid"
                continue
            expected_id = self.extract_contract_detail(contract_info, "VOUCHER_ID")
            expected_owner = self.extract_contract_detail(contract_info, "OWNER")
            expected_issuer = self.extract_contract_detail(contract_info, "ISSUER")
            expected_value = self.extract_contract_detail(contract_info, "VALUE")
            payload = info.get("payload", {}) or {}
            if expected_id and expected_id != voucher_id:
                failures[voucher_id] = "issue_contract_voucher_mismatch"
                continue
            if expected_owner and expected_owner != payload.get("owner"):
                failures[voucher_id] = "issue_contract_owner_mismatch"
                continue
            if expected_issuer and expected_issuer != payload.get("issuer"):
                failures[voucher_id] = "issue_contract_issuer_mismatch"
                continue
            if expected_value is not None and str(expected_value) != str(payload.get("value")):
                failures[voucher_id] = "issue_contract_value_mismatch"
                continue
            if enforce_pow:
                pow_ok, pow_reason, pow_details = self.verify_voucher_pow_payload(payload)
                pow_mint_ok = bool(pow_ok) and (pow_details.get("action_type") == "hps_mint")
                if not pow_mint_ok:
                    if not trace_has_pow(voucher_id, {voucher_id}, 5):
                        failures[voucher_id] = pow_reason or "pow_invalid"
                        continue
        return len(failures) == 0, failures

    def cleanup_exchange_tokens(self) -> None:
        now = time.time()
        expired = [token_id for token_id, info in self.exchange_tokens.items()
                   if now > info.get("expires_at", 0)]
        for token_id in expired:
            info = self.exchange_tokens.pop(token_id, {})
            session_id = info.get("session_id")
            if session_id:
                self.release_vouchers_for_session(session_id)
        expired_quotes = [quote_id for quote_id, quote in self.exchange_quotes.items()
                          if now > quote.get("expires_at", 0)]
        for quote_id in expired_quotes:
            self.exchange_quotes.pop(quote_id, None)

    def is_exchange_blocked(self, issuer: str) -> bool:
        if not issuer:
            return True
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT 1 FROM hps_issuer_invalidations WHERE issuer = ? LIMIT 1', (issuer,))
            if cursor.fetchone():
                return True
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT contract_content, timestamp FROM contracts
                              WHERE action_type = ? ORDER BY timestamp DESC LIMIT 50''', ("economy_alert",))
            rows = cursor.fetchall()
        for content_b64, timestamp in rows:
            if not content_b64:
                continue
            try:
                contract_bytes = base64.b64decode(content_b64)
                valid, _, contract_info = self.validate_contract_structure(contract_bytes)
                if not valid:
                    continue
                alert_issuer = self.extract_contract_detail(contract_info, "ISSUER")
                if alert_issuer == issuer and (time.time() - float(timestamp)) < 86400:
                    return True
            except Exception:
                continue
        return False

    def sign_payload(self, payload: Dict[str, Any]) -> str:
        message = self.canonicalize_payload(payload).encode("utf-8")
        signature = self.private_key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode("utf-8")

    def verify_payload_signature(self, payload: Dict[str, Any], signature_b64: str, public_key_pem: str) -> bool:
        try:
            public_key = self.load_public_key_from_value(public_key_pem)
            if not public_key:
                return False
            public_key.verify(
                base64.b64decode(signature_b64),
                self.canonicalize_payload(payload).encode("utf-8"),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def verify_content_signature(self, content: bytes, signature_b64: str, public_key_pem: str) -> bool:
        try:
            public_key = self.load_public_key_from_value(public_key_pem)
            if not public_key:
                return False
            public_key.verify(
                base64.b64decode(signature_b64),
                content,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def build_hps_voucher_payload(self, owner: str, owner_public_key: str, value: int, reason: str,
                                  pow_info: Optional[Dict[str, Any]] = None,
                                  conditions: Optional[Dict[str, Any]] = None,
                                  voucher_id: Optional[str] = None) -> Dict[str, Any]:
        pow_info = self.sanitize_payload_field(pow_info)
        conditions = self.sanitize_payload_field(conditions)
        payload = {
            "voucher_type": "HPS",
            "version": 1,
            "voucher_id": voucher_id or str(uuid.uuid4()),
            "value": int(value),
            "issuer": self.address,
            "issuer_public_key": base64.b64encode(self.public_key_pem).decode("utf-8"),
            "owner": owner,
            "owner_public_key": owner_public_key,
            "reason": reason,
            "issued_at": time.time(),
            "pow": pow_info or {},
            "conditions": conditions or {}
        }
        return payload

    def calculate_stream_segment_cost(self, interval_seconds: float, segment_size: int) -> int:
        rules = self.hps_stream_rules or {}
        base_cost = float(rules.get("base_cost", 1))
        size_cost_per_kb = float(rules.get("size_cost_per_kb", 0.0))
        min_cost = float(rules.get("min_cost", 1))
        tiers = rules.get("interval_tiers", []) or []
        multiplier = 1.0
        for tier in tiers:
            try:
                if interval_seconds <= float(tier.get("max_interval", 0)):
                    multiplier = float(tier.get("multiplier", 1.0))
                    break
            except Exception:
                continue
        size_kb = max(1.0, segment_size / 1024.0)
        inflation = 1.0 + min(self.get_economy_stat("total_minted", 0.0) / 10000.0, 5.0)
        raw_base = (base_cost + (size_kb * size_cost_per_kb)) * multiplier
        raw_inflated = raw_base * inflation
        min_inflated = min_cost * inflation
        if raw_inflated >= min_inflated:
            effective = self.apply_custody_discount(raw_base, raw_inflated, "stream")
            return max(int(math.ceil(effective)), int(math.ceil(min_cost)))
        effective_min = self.apply_custody_discount(min_cost, min_inflated, "stream_min")
        return max(int(math.ceil(effective_min)), int(math.ceil(min_cost)))

    def calculate_stream_total_cost(self, duration: float, desired_interval: float, max_segment_size: int) -> int:
        if duration <= 0 or desired_interval <= 0:
            return 0
        segments = int(math.ceil(duration / desired_interval))
        per_segment = self.calculate_stream_segment_cost(desired_interval, max_segment_size)
        return segments * per_segment

    def store_voucher_file(self, voucher_id: str, voucher_data: Dict[str, Any]) -> None:
        voucher_dir = os.path.join(self.files_dir, "vouchers")
        os.makedirs(voucher_dir, exist_ok=True)
        voucher_path = os.path.join(voucher_dir, f"{voucher_id}.hps")
        with open(voucher_path, "w", encoding="ascii") as f:
            f.write(self.format_hps_voucher_hsyst(voucher_data))

    def render_voucher_html(self, voucher: Dict[str, Any]) -> str:
        payload = voucher.get("payload", {})
        value = payload.get("value", 0)
        owner = payload.get("owner", "")
        issuer = payload.get("issuer", "")
        reason = payload.get("reason", "")
        issued_at = payload.get("issued_at", 0)
        issued_text = datetime.fromtimestamp(issued_at).strftime("%Y-%m-%d %H:%M:%S") if issued_at else ""
        conditions = payload.get("conditions", {})
        conditions_text = json.dumps(conditions, ensure_ascii=True)
        return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>HPS Voucher</title>
  <style>
    body {{ font-family: Arial, sans-serif; background: #f5f1e6; }}
    .note {{ width: 520px; margin: 40px auto; padding: 24px; border: 3px solid #8b6b3f; background: #f2e6c9; }}
    .header {{ display: flex; justify-content: space-between; font-weight: bold; color: #5a432a; }}
    .row {{ margin-top: 10px; color: #5a432a; }}
    .label {{ font-weight: bold; }}
  </style>
</head>
<body>
  <div class="note">
    <div class="header">
      <div>HPS</div>
      <div>{value} HPS</div>
    </div>
    <div class="row"><span class="label">Owner:</span> {owner}</div>
    <div class="row"><span class="label">Issuer:</span> {issuer}</div>
    <div class="row"><span class="label">Reason:</span> {reason}</div>
    <div class="row"><span class="label">Issued at:</span> {issued_text}</div>
    <div class="row"><span class="label">Conditions:</span> {conditions_text}</div>
  </div>
</body>
</html>"""

    def create_voucher_offer(self, owner: str, owner_public_key: str, value: int, reason: str,
                             pow_info: Optional[Dict[str, Any]] = None,
                             conditions: Optional[Dict[str, Any]] = None,
                             session_id: Optional[str] = None,
                             voucher_id: Optional[str] = None,
                             status: str = "pending") -> Dict[str, Any]:
        payload = self.build_hps_voucher_payload(owner, owner_public_key, value, reason, pow_info, conditions, voucher_id)
        offer_id = str(uuid.uuid4())
        now = time.time()
        expires_at = now + 600
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT OR REPLACE INTO hps_voucher_offers
                              (offer_id, voucher_id, owner, payload, value, reason, issued_at, expires_at, status)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                           (offer_id, payload["voucher_id"], owner, self.canonicalize_payload(payload),
                            payload["value"], reason, now, expires_at, status))
            conn.commit()
        offer = {
            "offer_id": offer_id,
            "voucher_id": payload["voucher_id"],
            "payload": payload,
            "expires_at": expires_at,
            "session_id": session_id
        }
        return offer

    def format_hps_voucher_hsyst(self, voucher: Dict[str, Any]) -> str:
        payload = voucher.get("payload", {})
        signatures = voucher.get("signatures", {})
        integrity = voucher.get("integrity", {})
        pow_info = payload.get("pow", {})
        conditions = payload.get("conditions", {})
        lines = [
            "# HSYST P2P SERVICE",
            "## HPS VOUCHER:",
            "### DETAILS:",
            f"# VERSION: {payload.get('version', 1)}",
            f"# VOUCHER_ID: {payload.get('voucher_id', '')}",
            f"# VALUE: {payload.get('value', 0)}",
            f"# ISSUER: {payload.get('issuer', '')}",
            f"# ISSUER_PUBLIC_KEY: {payload.get('issuer_public_key', '')}",
            f"# OWNER: {payload.get('owner', '')}",
            f"# OWNER_PUBLIC_KEY: {payload.get('owner_public_key', '')}",
            f"# REASON: {payload.get('reason', '')}",
            f"# ISSUED_AT: {payload.get('issued_at', 0)}",
            f"# POW: {json.dumps(pow_info, ensure_ascii=True)}",
            f"# CONDITIONS: {json.dumps(conditions, ensure_ascii=True)}",
            "### :END DETAILS",
            "### SIGNATURES:",
            f"# OWNER: {signatures.get('owner', '')}",
            f"# ISSUER: {signatures.get('issuer', '')}",
            f"# INTEGRITY_HASH: {integrity.get('hash', '')}",
            f"# INTEGRITY_ALGO: {integrity.get('algo', 'sha256')}",
            "### :END SIGNATURES",
            "## :END HPS VOUCHER"
        ]
        return "\n".join(lines) + "\n"

    def parse_hps_voucher_hsyst(self, text: str) -> Optional[Dict[str, Any]]:
        if not text.startswith("# HSYST P2P SERVICE"):
            return None
        details = {}
        signatures = {}
        section = None
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if line.startswith("### "):
                if line.endswith(":"):
                    section = line[4:-1].lower()
                elif line.startswith("### :END"):
                    section = None
                continue
            if not line.startswith("# "):
                continue
            key_value = line[2:]
            if ":" not in key_value:
                continue
            key, value = key_value.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            if section == "details":
                details[key] = value
            elif section == "signatures":
                signatures[key] = value
        if not details:
            return None
        def parse_json_field(value_text):
            try:
                return json.loads(value_text)
            except Exception:
                return {}
        payload = {
            "voucher_type": "HPS",
            "version": int(details.get("version", "1") or 1),
            "voucher_id": details.get("voucher_id", ""),
            "value": int(details.get("value", "0") or 0),
            "issuer": details.get("issuer", ""),
            "issuer_public_key": details.get("issuer_public_key", ""),
            "owner": details.get("owner", ""),
            "owner_public_key": details.get("owner_public_key", ""),
            "reason": details.get("reason", ""),
            "issued_at": float(details.get("issued_at", "0") or 0),
            "pow": parse_json_field(details.get("pow", "{}")),
            "conditions": parse_json_field(details.get("conditions", "{}"))
        }
        voucher = {
            "voucher_type": "HPS",
            "payload": payload,
            "signatures": {
                "owner": signatures.get("owner", ""),
                "issuer": signatures.get("issuer", "")
            },
            "integrity": {
                "hash": signatures.get("integrity_hash", ""),
                "algo": signatures.get("integrity_algo", "sha256")
            }
        }
        return voucher

    def finalize_voucher(self, voucher_id: str, owner_signature: str) -> Optional[Dict[str, Any]]:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT payload, owner, status FROM hps_voucher_offers WHERE voucher_id = ?''', (voucher_id,))
            row = cursor.fetchone()
            if not row:
                return None
            payload_text, owner, status = row
            if status != "pending":
                return None
            payload = json.loads(payload_text)
            if not self.verify_payload_signature(payload, owner_signature, payload["owner_public_key"]):
                return None
            issuer_signature = self.sign_payload(payload)
            voucher = {
                "voucher_type": "HPS",
                "payload": payload,
                "signatures": {
                    "owner": owner_signature,
                    "issuer": issuer_signature
                }
            }
            self.attach_voucher_integrity(voucher)
            now = time.time()
            cursor.execute('''INSERT OR REPLACE INTO hps_vouchers
                              (voucher_id, issuer, owner, value, reason, issued_at, payload, issuer_signature,
                               owner_signature, status, session_id, invalidated, last_updated)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                           (voucher_id, payload["issuer"], owner, payload["value"], payload["reason"],
                            payload["issued_at"], self.canonicalize_payload(payload), issuer_signature,
                            owner_signature, "valid", None, 0, now))
            cursor.execute('UPDATE hps_voucher_offers SET status = ? WHERE voucher_id = ?', ("issued", voucher_id))
            conn.commit()
        self.store_voucher_file(voucher_id, voucher)
        try:
            payload = voucher.get("payload", {}) or {}
            self.save_server_contract(
                "voucher_issue",
                [
                    ("VOUCHER_ID", payload.get("voucher_id", "")),
                    ("OWNER", payload.get("owner", "")),
                    ("ISSUER", payload.get("issuer", "")),
                    ("VALUE", payload.get("value", 0)),
                    ("REASON", payload.get("reason", "")),
                    ("ISSUED_AT", payload.get("issued_at", 0))
                ],
                op_id=payload.get("voucher_id", "")
            )
        except Exception as e:
            logger.error(f"Failed to record voucher contract for {voucher_id}: {e}")
        return voucher

    def list_user_vouchers(self, owner: str) -> List[Dict[str, Any]]:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT voucher_id, issuer, value, reason, issued_at, payload,
                              issuer_signature, owner_signature, status, invalidated
                              FROM hps_vouchers WHERE owner = ? ORDER BY issued_at DESC''',
                           (owner,))
            rows = cursor.fetchall()
        vouchers = []
        for row in rows:
            payload = json.loads(row[5])
            vouchers.append({
                "voucher_id": row[0],
                "issuer": row[1],
                "value": row[2],
                "reason": row[3],
                "issued_at": row[4],
                "payload": payload,
                "signatures": {"issuer": row[6], "owner": row[7]},
                "status": row[8],
                "invalidated": bool(row[9])
            })
        for voucher in vouchers:
            self.attach_voucher_integrity(voucher)
        return vouchers

    async def send_pending_voucher_offers(self, owner: str, sid: str) -> None:
        now = time.time()
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT offer_id, voucher_id, payload, expires_at FROM hps_voucher_offers
                              WHERE owner = ? AND status = ? AND expires_at > ?''',
                           (owner, "pending", now))
            rows = cursor.fetchall()
        for row in rows:
            try:
                payload = json.loads(row[2])
            except Exception:
                continue
            await self.sio.emit('hps_voucher_offer', {
                'offer_id': row[0],
                'voucher_id': row[1],
                'payload': payload,
                'expires_at': row[3]
            }, room=sid)

    def get_withheld_offer_summary(self, owner: str) -> Dict[str, Any]:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT COUNT(*), COALESCE(SUM(value), 0) FROM hps_voucher_offers
                              WHERE owner = ? AND status = ?''', (owner, "withheld"))
            row = cursor.fetchone()
        return {
            "count": int(row[0] or 0),
            "total": int(row[1] or 0)
        }

    def release_withheld_offers_for_miner(self, username: str) -> int:
        now = time.time()
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT offer_id, voucher_id, payload, expires_at FROM hps_voucher_offers
                              WHERE owner = ? AND status = ?''', (username, "withheld"))
            rows = cursor.fetchall()
            for offer_id, voucher_id, _, expires_at in rows:
                if expires_at and expires_at <= now:
                    cursor.execute('UPDATE hps_voucher_offers SET status = ? WHERE offer_id = ?',
                                   ("expired", offer_id))
                else:
                    cursor.execute('UPDATE hps_voucher_offers SET status = ? WHERE offer_id = ?',
                                   ("pending", offer_id))
            conn.commit()
        miner_info = self.authenticated_users.get(username, {})
        sid = miner_info.get("sid")
        if sid:
            asyncio.run_coroutine_threadsafe(
                self.send_pending_voucher_offers(username, sid),
                self.loop
            )
        return len(rows)

    def consume_withheld_offers(self, username: str, needed_amount: int) -> Tuple[int, int]:
        if needed_amount <= 0:
            return 0, 0
        used_amount = 0
        change_amount = 0
        now = time.time()
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT offer_id, voucher_id, payload, value FROM hps_voucher_offers
                              WHERE owner = ? AND status = ? ORDER BY issued_at ASC''',
                           (username, "withheld"))
            rows = cursor.fetchall()
            for offer_id, voucher_id, payload_text, value in rows:
                if used_amount >= needed_amount:
                    break
                value_int = int(value or 0)
                if value_int <= 0:
                    cursor.execute('UPDATE hps_voucher_offers SET status = ? WHERE offer_id = ?',
                                   ("expired", offer_id))
                    continue
                remaining = needed_amount - used_amount
                if value_int <= remaining:
                    used_amount += value_int
                    cursor.execute('UPDATE hps_voucher_offers SET status = ? WHERE offer_id = ?',
                                   ("spent", offer_id))
                else:
                    used_amount += remaining
                    change_amount = value_int - remaining
                    cursor.execute('UPDATE hps_voucher_offers SET status = ? WHERE offer_id = ?',
                                   ("spent", offer_id))
                    break
            conn.commit()
        if change_amount > 0:
            owner_key = self.get_user_public_key(username)
            self.create_voucher_offer(
                owner=username,
                owner_public_key=owner_key,
                value=change_amount,
                reason="withheld_change",
                conditions={"type": "withheld_change"},
                status="pending"
            )
        return used_amount, change_amount

    def issue_custody_voucher(self, value: int, reason: str,
                              pow_info: Optional[Dict[str, Any]] = None,
                              conditions: Optional[Dict[str, Any]] = None) -> Optional[str]:
        if value <= 0:
            return None
        self.increment_economy_stat("custody_balance", value)
        self.record_economy_event(reason)
        self.record_economy_contract(reason)
        owner_key = base64.b64encode(self.public_key_pem).decode("utf-8")
        offer = self.create_voucher_offer(
            owner=CUSTODY_USERNAME,
            owner_public_key=owner_key,
            value=value,
            reason=reason,
            pow_info=pow_info,
            conditions=conditions or {},
            status="pending"
        )
        owner_signature = self.sign_payload(offer["payload"])
        voucher = self.finalize_voucher(offer["voucher_id"], owner_signature)
        if not voucher:
            return None
        return offer["voucher_id"]

    async def issue_change_offer(self, username: str, change_value: int, reason: str,
                                 session_id: str, contract_action: Optional[str] = None,
                                 contract_details: Optional[List[Tuple[str, Any]]] = None) -> Optional[str]:
        if change_value <= 0:
            return None
        owner_key = self.get_user_public_key(username)
        if not owner_key:
            return None
        offer = self.create_voucher_offer(
            owner=username,
            owner_public_key=owner_key,
            value=change_value,
            reason=reason,
            pow_info=None,
            conditions={"type": "change", "reason": reason},
            session_id=session_id
        )
        if contract_action and contract_details is not None:
            self.save_server_contract(
                contract_action,
                contract_details + [
                    ("CHANGE_VALUE", change_value),
                    ("CHANGE_VOUCHER_ID", offer.get("voucher_id", "")),
                    ("SESSION_ID", session_id)
                ],
                op_id=offer.get("voucher_id")
            )
        user_info = self.authenticated_users.get(username, {})
        user_sid = user_info.get("sid")
        if user_sid:
            await self.sio.emit('hps_voucher_offer', {
                'offer_id': offer["offer_id"],
                'voucher_id': offer["voucher_id"],
                'payload': offer["payload"],
                'expires_at': offer["expires_at"]
            }, room=user_sid)
        return offer.get("voucher_id")

    def reserve_vouchers_for_session(self, owner: str, session_id: str, voucher_ids: List[str]) -> Tuple[bool, int, str]:
        if not voucher_ids:
            return False, 0, "No vouchers provided"
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            total = 0
            for voucher_id in voucher_ids:
                cursor.execute('''SELECT value, issuer, status, invalidated FROM hps_vouchers
                                  WHERE voucher_id = ? AND owner = ?''', (voucher_id, owner))
                row = cursor.fetchone()
                if not row:
                    return False, 0, f"Voucher {voucher_id} not found"
                value, issuer, status, invalidated = row
                if issuer != self.address:
                    return False, 0, f"Voucher {voucher_id} has different issuer"
                if status not in ("valid", "reserved"):
                    return False, 0, f"Voucher {voucher_id} is not available"
                if invalidated:
                    return False, 0, f"Voucher {voucher_id} invalidated"
                total += int(value)
            for voucher_id in voucher_ids:
                cursor.execute('''UPDATE hps_vouchers SET status = ?, session_id = ?, last_updated = ?
                                  WHERE voucher_id = ?''', ("reserved", session_id, time.time(), voucher_id))
            conn.commit()
        return True, total, ""

    def mark_vouchers_spent(self, session_id: str) -> None:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''UPDATE hps_vouchers SET status = ?, last_updated = ?
                              WHERE session_id = ? AND status = ?''',
                           ("spent", time.time(), session_id, "reserved"))
            conn.commit()

    def release_vouchers_for_session(self, session_id: str) -> None:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''UPDATE hps_vouchers SET status = ?, session_id = NULL, last_updated = ?
                              WHERE session_id = ? AND status = ?''',
                           ("valid", time.time(), session_id, "reserved"))
            conn.commit()

    def get_hps_pow_cost(self, action_type: str, apply_discount: bool = True) -> int:
        base_cost = float(self.hps_pow_costs.get(action_type, 0))
        if base_cost <= 0:
            return 0
        inflation = 1.0 + min(self.get_economy_stat("total_minted", 0.0) / 10000.0, 5.0)
        inflated = base_cost * inflation
        return max(1, int(math.ceil(inflated)))

    async def send_hps_wallet_sync(self, username: str) -> None:
        user_info = self.authenticated_users.get(username)
        if not user_info:
            return
        sid = user_info.get('sid')
        if not sid:
            return
        await self.sio.emit('hps_wallet_sync', {
            'vouchers': self.list_user_vouchers(username),
            'debt_status': self.safe_get_miner_debt_status(username)
        }, room=sid)

    def extend_miner_deadline(self, transfer_id: str, extra_seconds: float = 5.0) -> None:
        transfer = self.get_monetary_transfer(transfer_id)
        if not transfer:
            return
        miner = transfer.get("assigned_miner")
        if not miner:
            return
        now = time.time()
        current_deadline = float(transfer.get("miner_deadline") or 0)
        new_deadline = max(current_deadline, now + extra_seconds)
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''UPDATE monetary_transfers SET miner_deadline = ? WHERE transfer_id = ?''',
                           (new_deadline, transfer_id))
            conn.commit()
        asyncio.run_coroutine_threadsafe(
            self.enforce_miner_signature_deadline(transfer_id, miner, new_deadline),
            self.loop
        )

    def get_economy_stat(self, key: str, default: float = 0.0) -> float:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT stat_value FROM hps_economy_stats WHERE stat_key = ?', (key,))
            row = cursor.fetchone()
        if not row:
            return self.parse_numeric(default, 0.0)
        try:
            return float(row[0])
        except Exception:
            return self.parse_numeric(default, 0.0)

    def parse_numeric(self, value: Any, default: float = 0.0) -> float:
        if value is None:
            return float(default)
        if isinstance(value, (int, float)):
            return float(value)
        try:
            value_text = str(value).strip()
            if not value_text:
                return float(default)
            return float(value_text)
        except Exception:
            return float(default)

    def get_economy_stat_text(self, key: str, default: str = "") -> str:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT stat_value FROM hps_economy_stats WHERE stat_key = ?', (key,))
            row = cursor.fetchone()
        if not row:
            return default
        if row[0] is None:
            return default
        return str(row[0])

    def set_economy_stat(self, key: str, value: float) -> None:
        numeric_value = self.parse_numeric(value, 0.0)
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT OR REPLACE INTO hps_economy_stats (stat_key, stat_value) VALUES (?, ?)', (key, float(numeric_value)))
            conn.commit()

    def set_economy_stat_text(self, key: str, value: str) -> None:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT OR REPLACE INTO hps_economy_stats (stat_key, stat_value) VALUES (?, ?)', (key, str(value)))
            conn.commit()

    def increment_economy_stat(self, key: str, delta: float) -> float:
        current = self.get_economy_stat(key, 0.0)
        new_value = current + float(delta)
        self.set_economy_stat(key, new_value)
        return new_value

    def get_economy_multiplier(self) -> float:
        total_minted = self.get_economy_stat("total_minted", 0.0)
        custody_balance = self.get_economy_stat("custody_balance", 0.0)
        inflation = 1.0 + min(total_minted / 10000.0, 5.0)
        if custody_balance > 0:
            effective = max(1.0, inflation - min(inflation - 1.0, custody_balance))
        else:
            effective = inflation
        return max(1.0, min(10.0, effective))

    def apply_custody_discount(self, base_cost: float, inflated_cost: float, reason: str,
                               apply: bool = True) -> float:
        if inflated_cost <= base_cost:
            return inflated_cost
        custody_balance = self.get_economy_stat("custody_balance", 0.0)
        if custody_balance <= 0:
            return inflated_cost
        delta = inflated_cost - base_cost
        covered = min(delta, custody_balance)
        if covered <= 0:
            return inflated_cost
        if apply:
            new_balance = custody_balance - covered
            self.set_economy_stat("custody_balance", new_balance)
            self.record_economy_event(f"custody_price_support:{reason}")
            self.record_economy_contract(f"custody_price_support:{reason}")
        return inflated_cost - covered

    def build_economy_contract_text(self, reason: str, snapshot: Dict[str, Any], prev_hash: str) -> str:
        lines = [
            "# HSYST P2P SERVICE",
            "## CONTRACT:",
            "### DETAILS:",
            "# ACTION: economy_update",
            f"# REASON: {reason}",
            f"# TOTAL_MINTED: {snapshot.get('total_minted', 0)}",
            f"# CUSTODY_BALANCE: {snapshot.get('custody_balance', 0)}",
            f"# OWNER_BALANCE: {snapshot.get('owner_balance', 0)}",
            f"# MULTIPLIER: {snapshot.get('multiplier', 1.0)}",
            f"# PREV_HASH: {prev_hash or ''}",
            "### :END DETAILS",
            "### START:",
            f"# USER: {CUSTODY_USERNAME}",
            "# SIGNATURE: ",
            "### :END START",
            "## :END CONTRACT"
        ]
        return "\n".join(lines) + "\n"

    def sign_contract_text(self, contract_text: str) -> str:
        lines = contract_text.splitlines()
        signed_content = []
        for line in lines:
            if not line.strip().startswith("# SIGNATURE:"):
                signed_content.append(line)
        signed_text = "\n".join(signed_content)
        signature = self.private_key.sign(
            signed_text.encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode("utf-8")

    def build_server_contract_text(self, action_type: str, details: List[Tuple[str, Any]],
                                   username: str = CUSTODY_USERNAME) -> str:
        lines = [
            "# HSYST P2P SERVICE",
            "## CONTRACT:",
            "### DETAILS:",
            f"# ACTION: {action_type}"
        ]
        for key, value in details:
            lines.append(f"# {key}: {value}")
        lines.extend([
            "### :END DETAILS",
            "### START:",
            f"# USER: {username}",
            "# SIGNATURE: ",
            "### :END START",
            "## :END CONTRACT"
        ])
        return "\n".join(lines) + "\n"

    def save_server_contract(self, action_type: str, details: List[Tuple[str, Any]],
                             op_id: Optional[str] = None) -> str:
        contract_text = self.build_server_contract_text(action_type, details, CUSTODY_USERNAME)
        signature = self.sign_contract_text(contract_text)
        signed_text = contract_text.replace("# SIGNATURE: ", f"# SIGNATURE: {signature}", 1)
        contract_bytes = signed_text.encode("utf-8")
        return self.save_contract(
            action_type=action_type,
            content_hash=op_id,
            domain=None,
            username=CUSTODY_USERNAME,
            signature=signature,
            contract_content=contract_bytes
        )

    def record_economy_contract(self, reason: str) -> None:
        snapshot = self.get_economy_status()
        prev_hash = self.get_economy_stat_text("last_economy_hash", "")
        contract_text = self.build_economy_contract_text(reason, snapshot, prev_hash)
        signature = self.sign_contract_text(contract_text)
        signed_text = contract_text.replace("# SIGNATURE: ", f"# SIGNATURE: {signature}", 1)
        contract_bytes = signed_text.encode("utf-8")
        self.save_contract(
            action_type="economy_update",
            content_hash=None,
            domain=None,
            username=CUSTODY_USERNAME,
            signature=signature,
            contract_content=contract_bytes
        )
        contract_hash = hashlib.sha256(contract_bytes).hexdigest()
        self.set_economy_stat_text("last_economy_hash", contract_hash)
        self.set_economy_stat("last_economy_update_ts", time.time())

    def record_economy_event(self, reason: str) -> None:
        self.set_economy_stat("last_economy_event_ts", time.time())
        self.set_economy_stat_text("last_economy_event_reason", reason)

    def get_inflation_rate(self) -> float:
        total_minted = self.get_economy_stat("total_minted", 0.0)
        inflation = 1.0 + min(total_minted / 10000.0, 5.0)
        return max(0.0, inflation - 1.0)

    def get_miner_stats(self, username: str) -> Dict[str, Any]:
        if not username:
            return {
                "minted_count": 0,
                "minted_total": 0.0,
                "pending_signatures": 0,
                "pending_fines": 0,
                "banned_until": 0.0,
                "ban_reason": "",
                "fine_promise_amount": 0.0,
                "fine_promise_active": 0
            }
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT minted_count, minted_total, pending_signatures, pending_fines,
                              banned_until, ban_reason, fine_promise_amount, fine_promise_active
                              FROM miner_stats WHERE username = ?''', (username,))
            row = cursor.fetchone()
            if not row:
                cursor.execute('''INSERT INTO miner_stats
                                  (username, minted_count, minted_total, pending_signatures, pending_fines, last_updated,
                                   banned_until, ban_reason, fine_promise_amount, fine_promise_active)
                                  VALUES (?, 0, 0, 0, 0, ?, 0, "", 0, 0)''',
                               (username, time.time()))
                conn.commit()
                return {
                    "minted_count": 0,
                    "minted_total": 0.0,
                    "pending_signatures": 0,
                    "pending_fines": 0,
                    "banned_until": 0.0,
                    "ban_reason": "",
                    "fine_promise_amount": 0.0,
                    "fine_promise_active": 0
                }
            return {
                "minted_count": int(row[0] or 0),
                "minted_total": float(row[1] or 0.0),
                "pending_signatures": int(row[2] or 0),
                "pending_fines": int(row[3] or 0),
                "banned_until": float(row[4] or 0.0),
                "ban_reason": row[5] or "",
                "fine_promise_amount": float(row[6] or 0.0),
                "fine_promise_active": int(row[7] or 0)
            }

    def update_miner_stats(self, username: str, **fields) -> None:
        if not username or not fields:
            return
        updates = []
        values = []
        for key, value in fields.items():
            updates.append(f"{key} = ?")
            values.append(value)
        updates.append("last_updated = ?")
        values.append(time.time())
        values.append(username)
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                f'''UPDATE miner_stats SET {", ".join(updates)} WHERE username = ?''',
                tuple(values)
            )
            conn.commit()

    def add_miner_debt_entry(self, username: str, entry_type: str, amount: int = 0,
                             metadata: Optional[Dict[str, Any]] = None) -> None:
        if not username or not entry_type:
            return
        entry_id = str(uuid.uuid4())
        payload = json.dumps(metadata or {}, ensure_ascii=True)
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT INTO miner_debt_entries
                   (entry_id, username, entry_type, amount, status, created_at, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (entry_id, username, entry_type, int(amount), "pending", time.time(), payload)
            )
            conn.commit()

    def list_miner_debt_entries(self, username: str, status: Optional[str] = "pending",
                                entry_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        if not username:
            return []
        query = '''SELECT entry_id, entry_type, amount, status, created_at, resolved_at, metadata
                   FROM miner_debt_entries WHERE username = ?'''
        values: List[Any] = [username]
        if status:
            query += " AND status = ?"
            values.append(status)
        if entry_types:
            placeholders = ",".join(["?"] * len(entry_types))
            query += f" AND entry_type IN ({placeholders})"
            values.extend(entry_types)
        query += " ORDER BY created_at ASC"
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(values))
            rows = cursor.fetchall()
        entries = []
        for row in rows:
            metadata = {}
            try:
                metadata = json.loads(row[6] or "{}")
            except Exception:
                metadata = {}
            entries.append({
                "entry_id": row[0],
                "entry_type": row[1],
                "amount": int(row[2] or 0),
                "status": row[3],
                "created_at": float(row[4] or 0.0),
                "resolved_at": float(row[5] or 0.0) if row[5] else None,
                "metadata": metadata
            })
        return entries

    def resolve_miner_debt_entries(self, username: str, entry_types: List[str],
                                   limit: Optional[int] = None) -> List[str]:
        if not username or not entry_types:
            return []
        entries = self.list_miner_debt_entries(username, status="pending", entry_types=entry_types)
        if limit is not None:
            entries = entries[:max(0, int(limit))]
        if not entries:
            return []
        entry_ids = [entry["entry_id"] for entry in entries]
        placeholders = ",".join(["?"] * len(entry_ids))
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                f'''UPDATE miner_debt_entries SET status = ?, resolved_at = ?
                    WHERE entry_id IN ({placeholders})''',
                tuple(["resolved", time.time()] + entry_ids)
            )
            conn.commit()
        return entry_ids

    def get_miner_pending_counts(self, username: str) -> Tuple[int, int]:
        if not username:
            return 0, 0
        self.bootstrap_miner_debt_entries(username)
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''SELECT
                       SUM(CASE WHEN entry_type LIKE 'signature_%' AND status = 'pending' THEN 1 ELSE 0 END),
                       SUM(CASE WHEN entry_type LIKE 'fine_%' AND status = 'pending' THEN 1 ELSE 0 END)
                   FROM miner_debt_entries WHERE username = ?''',
                (username,)
            )
            row = cursor.fetchone()
        pending_signatures = int(row[0] or 0)
        pending_fines = int(row[1] or 0)
        return pending_signatures, pending_fines

    def sync_miner_pending_counts(self, username: str) -> Tuple[int, int]:
        pending_signatures, pending_fines = self.get_miner_pending_counts(username)
        self.update_miner_stats(
            username,
            pending_signatures=pending_signatures,
            pending_fines=pending_fines
        )
        return pending_signatures, pending_fines

    def bootstrap_miner_debt_entries(self, username: str) -> None:
        if not username:
            return
        stats = self.get_miner_stats(username)
        pending_signatures = int(stats.get("pending_signatures", 0))
        if pending_signatures <= 0:
            return
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT 1 FROM miner_debt_entries WHERE username = ? LIMIT 1', (username,))
            if cursor.fetchone():
                return
        minted_count = int(stats.get("minted_count", 0))
        start = max(1, minted_count - pending_signatures + 1)
        for count in range(start, minted_count + 1):
            signature_type = "signature_immediate" if count % 2 == 0 else "signature_last_resort"
            self.add_miner_debt_entry(username, signature_type)
        self.update_miner_stats(
            username,
            pending_signatures=pending_signatures,
            pending_fines=0
        )

    def compute_delay_fine_amount(self, entry: Dict[str, Any]) -> int:
        metadata = entry.get("metadata", {}) or {}
        fee_amount = int(metadata.get("fee_amount", 0))
        deadline = float(metadata.get("deadline", 0.0))
        if fee_amount <= 0 or deadline <= 0:
            return 0
        delay = max(0.0, time.time() - deadline)
        periods = max(1, int(math.ceil(delay / 3.0)))
        return int(periods * fee_amount * 2)

    def get_miner_fine_entries(self, username: str) -> List[Dict[str, Any]]:
        self.bootstrap_miner_debt_entries(username)
        return self.list_miner_debt_entries(
            username,
            status="pending",
            entry_types=["fine_delay", "fine_report_invalid"]
        )

    def get_miner_signature_entries(self, username: str, allow_last_resort: bool = False) -> List[Dict[str, Any]]:
        self.bootstrap_miner_debt_entries(username)
        entry_types = ["signature_immediate"]
        if allow_last_resort:
            entry_types.append("signature_last_resort")
        return self.list_miner_debt_entries(username, status="pending", entry_types=entry_types)

    def get_last_pending_signature_type(self, username: str) -> Optional[str]:
        if not username:
            return None
        entries = self.list_miner_debt_entries(
            username,
            status=None,
            entry_types=["signature_immediate", "signature_last_resort"]
        )
        if not entries:
            return None
        return entries[-1].get("entry_type")

    def compute_miner_fine_amount(self, username: str, pending: Optional[int] = None) -> int:
        entries = self.get_miner_fine_entries(username)
        total = 0
        for entry in entries:
            if entry.get("entry_type") == "fine_delay":
                total += self.compute_delay_fine_amount(entry)
            else:
                total += int(entry.get("amount", 0))
        if total > 0:
            return int(total)
        return 0

    def get_miner_fine_quote(self, username: str, include_signature_last_resort: bool = False) -> Dict[str, Any]:
        fine_entries = self.get_miner_fine_entries(username)
        fine_amount = 0
        for entry in fine_entries:
            if entry.get("entry_type") == "fine_delay":
                fine_amount += self.compute_delay_fine_amount(entry)
            else:
                fine_amount += int(entry.get("amount", 0))
        fine_count = len(fine_entries)
        signature_immediate = len(self.get_miner_signature_entries(username, allow_last_resort=False))
        signature_last_resort = len(self.list_miner_debt_entries(username, status="pending", entry_types=["signature_last_resort"]))
        if include_signature_last_resort:
            signature_count = signature_immediate + signature_last_resort
        else:
            signature_count = signature_immediate
        signature_amount = signature_count * self.compute_miner_fine_per_pending(username)
        total_amount = int(fine_amount + signature_amount)
        return {
            "total_amount": total_amount,
            "fine_amount": int(fine_amount),
            "fine_count": int(fine_count),
            "signature_amount": int(signature_amount),
            "signature_count": signature_count,
            "signature_immediate": signature_immediate,
            "signature_last_resort": signature_last_resort
        }

    def increment_miner_mint(self, username: str, minted_value: float) -> int:
        stats = self.get_miner_stats(username)
        minted_count = stats["minted_count"] + 1
        minted_total = stats["minted_total"] + float(minted_value)
        if minted_count % 2 == 0:
            last_pending = self.get_last_pending_signature_type(username)
            if last_pending == "signature_last_resort":
                signature_type = "signature_immediate"
            else:
                signature_type = "signature_last_resort"
            self.add_miner_debt_entry(username, signature_type)
        pending_signatures, pending_fines = self.sync_miner_pending_counts(username)
        self.update_miner_stats(
            username,
            minted_count=minted_count,
            minted_total=minted_total,
            pending_signatures=pending_signatures,
            pending_fines=pending_fines
        )
        return pending_signatures

    def get_miner_signature_punctuality(self, username: str, limit: int = 50) -> Dict[str, Any]:
        entries = []
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''SELECT created_at, miner_deadline, signed_at FROM monetary_transfers
                   WHERE signed_by = ? ORDER BY signed_at DESC LIMIT ?''',
                (username, int(limit))
            )
            entries = cursor.fetchall()
        ratios = []
        for created_at, miner_deadline, signed_at in entries:
            if not miner_deadline or not signed_at:
                continue
            duration = float(miner_deadline) - float(created_at or 0)
            if duration <= 0:
                continue
            ratio = (float(signed_at) - float(created_at)) / duration
            ratios.append(max(0.0, min(1.0, ratio)))
        count = len(ratios)
        if count <= 0:
            return {"count": 0, "avg_ratio": 0.0, "penalty_pct": 0.0}
        avg_ratio = sum(ratios) / max(1, count)
        penalty_pct = max(0.0, min(25.0, avg_ratio * 25.0))
        return {"count": count, "avg_ratio": avg_ratio, "penalty_pct": penalty_pct}

    def get_miner_recent_signature_participation(self, username: str,
                                                 window_seconds: float = 86400.0,
                                                 target_count: int = 20) -> Dict[str, Any]:
        cutoff = time.time() - window_seconds
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''SELECT COUNT(*) FROM monetary_transfers
                   WHERE signed_by = ? AND signed_at IS NOT NULL AND signed_at >= ?''',
                (username, cutoff)
            )
            row = cursor.fetchone()
        count = int(row[0] or 0)
        ratio = 0.0
        if target_count > 0:
            ratio = min(1.0, max(0.0, count / float(target_count)))
        bonus_pct = min(25.0, max(0.0, ratio * 25.0))
        return {"count": count, "ratio": ratio, "bonus_pct": bonus_pct}

    def compute_miner_fine_per_pending(self, username: str) -> int:
        return 5

    def round_debt_limit(self, value: float) -> int:
        if value >= 9.5:
            return 10
        return int(math.floor(value))

    def get_miner_debt_status(self, username: str) -> Dict[str, Any]:
        stats = self.get_miner_stats(username)
        pending, pending_fines = self.get_miner_pending_counts(username)
        promise_active = int(stats.get("fine_promise_active", 0))
        promise_amount = float(stats.get("fine_promise_amount", 0.0))
        minted_count = int(stats.get("minted_count", 0))
        reputation = float(self.get_user_reputation(username) or 0)
        mined_balance = float(self.get_user_mined_balance(username))
        total_minted = float(self.get_economy_stat("total_minted", 0.0))
        mining_share = 0.0
        if total_minted > 0:
            mining_share = min(1.0, max(0.0, mined_balance / total_minted))
        mining_pct = min(50.0, max(0.0, mining_share * 50.0))
        punctuality_info = self.get_miner_signature_punctuality(username)
        punctuality_pct = float(punctuality_info.get("penalty_pct", 25.0))
        participation_info = self.get_miner_recent_signature_participation(username)
        participation_bonus = float(participation_info.get("bonus_pct", 0.0))
        rep_clamped = min(100.0, max(0.0, reputation))
        reputation_pct = max(0.0, min(25.0, (1.0 - (rep_clamped / 100.0)) * 25.0))
        combined_pct = min(100.0, max(0.0, mining_pct + punctuality_pct + reputation_pct - participation_bonus))
        limit_raw = 10.0 - (combined_pct / 10.0)
        limit = self.round_debt_limit(limit_raw)
        limit = max(2, min(10, limit))
        signature_blocked = pending >= limit
        signature_immediate = len(self.get_miner_signature_entries(username, allow_last_resort=False))
        signature_last_resort = len(self.list_miner_debt_entries(username, status="pending", entry_types=["signature_last_resort"]))
        signature_fines = signature_immediate + (signature_last_resort if signature_blocked else 0)
        signature_fine_amount = signature_fines * self.compute_miner_fine_per_pending(username)
        fine_amount = self.compute_miner_fine_amount(username, pending=pending_fines) + signature_fine_amount
        fine_per_pending = self.compute_miner_fine_per_pending(username)
        withheld_summary = self.get_withheld_offer_summary(username)
        next_signature_increment = 1 if (minted_count + 1) % 2 == 0 else 0
        next_pending_increase = bool(next_signature_increment)
        next_pending = pending + next_signature_increment
        next_pending_fines = pending_fines
        fine_grace = 2
        pending_delay_fines = len(self.list_miner_debt_entries(username, status="pending", entry_types=["fine_delay"]))
        return {
            "pending_signatures": pending,
            "pending_fines": pending_fines,
            "signature_fines": signature_fines,
            "signature_immediate": signature_immediate,
            "signature_last_resort": signature_last_resort,
            "debt_limit": limit,
            "debt_limit_raw": limit_raw,
            "combined_pct": combined_pct,
            "minted_count": minted_count,
            "next_pending_increase": next_pending_increase,
            "next_pending": next_pending,
            "next_pending_fines": next_pending_fines,
            "pending_delay_fines": pending_delay_fines,
            "mined_balance": mined_balance,
            "total_minted": total_minted,
            "mining_share": mining_share,
            "mining_pct": mining_pct,
            "punctuality_pct": punctuality_pct,
            "punctuality_count": int(punctuality_info.get("count", 0)),
            "punctuality_avg_ratio": float(punctuality_info.get("avg_ratio", 1.0)),
            "participation_bonus_pct": participation_bonus,
            "participation_count": int(participation_info.get("count", 0)),
            "participation_ratio": float(participation_info.get("ratio", 0.0)),
            "reputation": rep_clamped,
            "reputation_pct": reputation_pct,
            "fine_amount": fine_amount,
            "fine_per_pending": fine_per_pending,
            "withheld_count": int(withheld_summary.get("count", 0)),
            "withheld_total": int(withheld_summary.get("total", 0)),
            "promise_active": promise_active,
            "promise_amount": promise_amount,
            "fine_grace": fine_grace,
            "limit_min": 2,
            "limit_max": 10
        }

    def safe_get_miner_debt_status(self, username: str) -> Dict[str, Any]:
        try:
            return self.get_miner_debt_status(username)
        except RecursionError:
            logger.error(f"Recursion error computing debt status for {username}")
        except Exception as e:
            logger.error(f"Error computing debt status for {username}: {e}")
        stats = self.get_miner_stats(username)
        return {
            "pending_signatures": int(stats.get("pending_signatures", 0)),
            "pending_fines": int(stats.get("pending_fines", 0)),
            "debt_limit": 2,
            "fine_amount": 0,
            "fine_per_pending": 0,
            "withheld_count": 0,
            "withheld_total": 0,
            "signature_fines": 0,
            "signature_immediate": 0,
            "signature_last_resort": 0,
            "promise_active": int(stats.get("fine_promise_active", 0)),
            "promise_amount": float(stats.get("fine_promise_amount", 0.0)),
            "fine_grace": 2,
            "pending_delay_fines": 0
        }

    def is_miner_minting_suspended(self, username: str) -> Tuple[bool, Dict[str, Any]]:
        status = self.safe_get_miner_debt_status(username)
        pending_signatures = int(status.get("pending_signatures", 0))
        pending_fines = int(status.get("pending_fines", 0))
        pending_delay_fines = int(status.get("pending_delay_fines", 0))
        fine_grace = int(status.get("fine_grace", 2))
        signature_blocked = pending_signatures >= int(status.get("debt_limit", 0))
        fine_blocked = pending_fines > fine_grace and not status.get("promise_active")
        delay_blocked = pending_delay_fines > 0
        return signature_blocked or fine_blocked or delay_blocked, status

    def is_miner_banned(self, username: str) -> bool:
        stats = self.get_miner_stats(username)
        return stats.get("banned_until", 0) > time.time()

    def get_user_mined_balance(self, username: str) -> int:
        total = 0
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT value, payload, status, invalidated
                              FROM hps_vouchers WHERE owner = ?''', (username,))
            rows = cursor.fetchall()
        for value, payload_text, status, invalidated in rows:
            if invalidated:
                continue
            if status not in ("valid", "locked"):
                continue
            try:
                payload = json.loads(payload_text)
            except Exception:
                continue
            pow_info = payload.get("pow", {}) or {}
            if pow_info.get("action_type") == "hps_mint":
                total += int(value or 0)
        return total

    def compute_signature_fee(self, amount: int) -> int:
        if amount <= 0:
            return 0
        rate = self.get_inflation_rate()
        return max(0, int(math.ceil(amount * rate)))

    def allocate_signature_fee(self, amount: int) -> Tuple[int, str, int]:
        fee_amount = self.compute_signature_fee(amount)
        if fee_amount <= 0:
            return 0, "", amount
        custody_balance = self.get_economy_stat("custody_balance", 0.0)
        if custody_balance >= fee_amount:
            return fee_amount, "custody", amount
        adjusted = max(1, amount - fee_amount)
        fee_amount = max(0, amount - adjusted)
        return fee_amount, "receiver", adjusted

    def select_miner_for_signature(self, exclude_users: Optional[Set[str]] = None) -> Optional[str]:
        candidates = []
        exclude_users = exclude_users or set()
        for username, info in self.authenticated_users.items():
            if not info.get("sid"):
                continue
            if username in exclude_users:
                continue
            stats = self.get_miner_stats(username)
            if stats.get("minted_count", 0) <= 0:
                continue
            if stats.get("banned_until", 0) > time.time():
                continue
            pending_signatures, _ = self.get_miner_pending_counts(username)
            candidates.append((pending_signatures, stats.get("minted_count", 0), username))
        if not candidates:
            return None
        candidates.sort(key=lambda item: (-item[0], -item[1], item[2]))
        return candidates[0][2]

    def create_monetary_transfer(self, transfer_type: str, sender: str, receiver: str, amount: int,
                                 locked_voucher_ids: List[str], contract_id: str,
                                 fee_amount: int, fee_source: str,
                                 inter_server_payload: Optional[Dict[str, Any]] = None) -> str:
        transfer_id = str(uuid.uuid4())
        assigned_miner = self.select_miner_for_signature(exclude_users={sender, receiver})
        now = time.time()
        deadline = now + 60.0
        miner_deadline = now + 5.0 if assigned_miner else 0.0
        inter_server_text = json.dumps(inter_server_payload or {}, ensure_ascii=True)
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO monetary_transfers
                              (transfer_id, transfer_type, sender, receiver, amount, created_at, status,
                               contract_id, locked_voucher_ids, assigned_miner, deadline, miner_deadline,
                               fee_amount, fee_source, inter_server_payload)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                           (transfer_id, transfer_type, sender, receiver, int(amount), now, "pending_signature",
                            contract_id or "", json.dumps(locked_voucher_ids or [], ensure_ascii=True),
                            assigned_miner or "", deadline, miner_deadline, int(fee_amount or 0), fee_source or "",
                            inter_server_text))
            conn.commit()
        if assigned_miner:
            self.notify_miner_signature_request(transfer_id)
        self.notify_monetary_transfer_pending(transfer_id)
        return transfer_id

    def create_pending_monetary_action(self, transfer_id: str, action_name: str, username: str,
                                       client_identifier: str, payload: Dict[str, Any],
                                       response_event: str) -> str:
        action_id = str(uuid.uuid4())
        now = time.time()
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT INTO pending_monetary_actions
                   (action_id, transfer_id, action_name, username, client_identifier, payload,
                    response_event, status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (
                    action_id,
                    transfer_id,
                    action_name,
                    username,
                    client_identifier or "",
                    json.dumps(payload, ensure_ascii=True),
                    response_event,
                    "pending",
                    now,
                    now
                )
            )
            conn.commit()
        return action_id

    def get_pending_monetary_action(self, transfer_id: str) -> Optional[Dict[str, Any]]:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''SELECT action_id, transfer_id, action_name, username, client_identifier,
                          payload, response_event, status, created_at, updated_at
                   FROM pending_monetary_actions WHERE transfer_id = ?''',
                (transfer_id,)
            )
            row = cursor.fetchone()
        if not row:
            return None
        payload = {}
        try:
            payload = json.loads(row[5]) if row[5] else {}
        except Exception:
            payload = {}
        return {
            "action_id": row[0],
            "transfer_id": row[1],
            "action_name": row[2],
            "username": row[3],
            "client_identifier": row[4],
            "payload": payload,
            "response_event": row[6],
            "status": row[7],
            "created_at": row[8],
            "updated_at": row[9]
        }

    def update_pending_monetary_action_status(self, action_id: str, status: str) -> None:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''UPDATE pending_monetary_actions SET status = ?, updated_at = ?
                   WHERE action_id = ?''',
                (status, time.time(), action_id)
            )
            conn.commit()

    def delete_pending_monetary_action(self, action_id: str) -> None:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM pending_monetary_actions WHERE action_id = ?', (action_id,))
            conn.commit()

    def notify_monetary_transfer_pending(self, transfer_id: str) -> None:
        transfer = self.get_monetary_transfer(transfer_id)
        if not transfer:
            return
        assigned = transfer.get("assigned_miner") or ""
        status = "assigned" if assigned else "awaiting_miner"
        payload = {
            "transfer_id": transfer_id,
            "transfer_type": transfer.get("transfer_type"),
            "sender": transfer.get("sender"),
            "receiver": transfer.get("receiver"),
            "amount": transfer.get("amount"),
            "assigned_miner": assigned,
            "status": status
        }
        for sid, client in self.connected_clients.items():
            if client.get("username") in (transfer.get("sender"), transfer.get("receiver")):
                asyncio.run_coroutine_threadsafe(
                    self.sio.emit("monetary_transfer_pending", payload, room=sid),
                    self.loop
                )

    def notify_monetary_transfer_update(self, transfer_id: str, status: str,
                                        reason: str = "", details: Optional[Dict[str, Any]] = None) -> None:
        transfer = self.get_monetary_transfer(transfer_id)
        if not transfer:
            return
        payload = {
            "transfer_id": transfer_id,
            "transfer_type": transfer.get("transfer_type"),
            "sender": transfer.get("sender"),
            "receiver": transfer.get("receiver"),
            "status": status,
            "assigned_miner": transfer.get("assigned_miner") or "",
            "reason": reason or ""
        }
        if details:
            payload["details"] = details
        for sid, client in self.connected_clients.items():
            if client.get("username") in (transfer.get("sender"), transfer.get("receiver")):
                asyncio.run_coroutine_threadsafe(
                    self.sio.emit("monetary_transfer_update", payload, room=sid),
                    self.loop
                )

    def assign_unassigned_transfers(self) -> None:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT transfer_id, sender, receiver FROM monetary_transfers
                              WHERE status = ? AND (assigned_miner IS NULL OR assigned_miner = "")''',
                           ("pending_signature",))
            rows = cursor.fetchall()
        for transfer_id, sender, receiver in rows:
            miner = self.select_miner_for_signature(exclude_users={sender, receiver})
            if not miner:
                continue
            now = time.time()
            miner_deadline = now + 5.0
            with get_db_conn(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    '''UPDATE monetary_transfers SET assigned_miner = ?, miner_deadline = ?
                       WHERE transfer_id = ?''',
                    (miner, miner_deadline, transfer_id)
                )
                conn.commit()
            self.notify_miner_signature_request(transfer_id)
            self.notify_monetary_transfer_update(transfer_id, "assigned")

    def build_pending_monetary_ack(self, transfer_id: str) -> Dict[str, Any]:
        transfer = self.get_monetary_transfer(transfer_id)
        miner = transfer.get("assigned_miner") if transfer else ""
        if miner:
            message = f"Transacao em analise pelo minerador {miner}."
        else:
            message = "Aguardando mineradores disponiveis para analisar a transacao."
        return {
            "success": True,
            "pending": True,
            "transfer_id": transfer_id,
            "message": message
        }

    async def emit_to_user(self, username: str, event: str, payload: Dict[str, Any]) -> None:
        if not username:
            return
        user_info = self.authenticated_users.get(username, {})
        sid = user_info.get("sid")
        if not sid:
            return
        await self.sio.emit(event, payload, room=sid)

    def notify_miner_signature_request(self, transfer_id: str) -> None:
        transfer = self.get_monetary_transfer(transfer_id)
        if not transfer:
            return
        miner = transfer.get("assigned_miner")
        if not miner:
            return
        miner_info = self.authenticated_users.get(miner, {})
        sid = miner_info.get("sid")
        if not sid:
            return
        pending = self.get_miner_stats(miner).get("pending_signatures", 0)
        payload = {
            "transfer_id": transfer_id,
            "transfer_type": transfer.get("transfer_type"),
            "sender": transfer.get("sender"),
            "receiver": transfer.get("receiver"),
            "amount": transfer.get("amount"),
            "fee_amount": transfer.get("fee_amount", 0),
            "fee_source": transfer.get("fee_source", ""),
            "contract_id": transfer.get("contract_id", ""),
            "locked_voucher_ids": transfer.get("locked_voucher_ids", []),
            "deadline": transfer.get("deadline", 0),
            "miner_deadline": transfer.get("miner_deadline", 0),
            "pending_signatures": pending
        }
        inter_server_payload = transfer.get("inter_server_payload") or {}
        if inter_server_payload:
            payload["inter_server"] = inter_server_payload
        asyncio.run_coroutine_threadsafe(
            self.sio.emit('miner_signature_request', payload, room=sid),
            self.loop
        )
        self.notify_monetary_transfer_update(transfer_id, "assigned")
        if transfer.get("miner_deadline"):
            asyncio.run_coroutine_threadsafe(
                self.enforce_miner_signature_deadline(transfer_id, miner, transfer.get("miner_deadline")),
                self.loop
            )

    async def enforce_miner_signature_deadline(self, transfer_id: str, miner: str, deadline: float) -> None:
        await asyncio.sleep(max(0.0, deadline - time.time()))
        transfer = self.get_monetary_transfer(transfer_id)
        if not transfer:
            return
        current_deadline = float(transfer.get("miner_deadline") or 0)
        if current_deadline > deadline + 0.5:
            asyncio.run_coroutine_threadsafe(
                self.enforce_miner_signature_deadline(transfer_id, miner, current_deadline),
                self.loop
            )
            return
        if transfer.get("status") == "signed":
            return
        fee_amount = int(transfer.get("fee_amount", 0))
        self.add_miner_debt_entry(
            miner,
            "fine_delay",
            amount=0,
            metadata={
                "transfer_id": transfer_id,
                "deadline": deadline,
                "fee_amount": fee_amount
            }
        )
        self.sync_miner_pending_counts(miner)
        miner_info = self.authenticated_users.get(miner, {})
        sid = miner_info.get("sid")
        if sid:
            asyncio.run_coroutine_threadsafe(
                self.sio.emit('miner_signature_update', {
                    'pending_signatures': self.get_miner_pending_counts(miner)[0],
                    'debt_status': self.safe_get_miner_debt_status(miner)
                }, room=sid),
                self.loop
            )

    def reassign_miner_for_transfer(self, transfer_id: str, exclude_user: Optional[str] = None) -> Optional[str]:
        transfer = self.get_monetary_transfer(transfer_id)
        if not transfer:
            return None
        sender = transfer.get("sender")
        receiver = transfer.get("receiver")
        exclude = {sender, receiver}
        if exclude_user:
            exclude.add(exclude_user)
        new_miner = self.select_miner_for_signature(exclude_users=exclude)
        if not new_miner:
            return None
        now = time.time()
        miner_deadline = now + 5.0
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''UPDATE monetary_transfers SET assigned_miner = ?, miner_deadline = ?
                   WHERE transfer_id = ?''',
                (new_miner, miner_deadline, transfer_id)
            )
            conn.commit()
        self.notify_miner_signature_request(transfer_id)
        return new_miner

    def ban_miner(self, username: str, reason: str, transfer_id: str = "") -> None:
        ban_until = time.time() + 10 * 365 * 24 * 3600
        self.update_miner_stats(username, banned_until=ban_until, ban_reason=reason)
        self.lock_miner_minted_vouchers(username)
        self.save_server_contract(
            "miner_ban",
            [
                ("MINER", username),
                ("REASON", reason),
                ("TRANSFER_ID", transfer_id or "")
            ]
        )
        miner_info = self.authenticated_users.get(username, {})
        sid = miner_info.get("sid")
        if sid:
            asyncio.run_coroutine_threadsafe(
                self.sio.emit('miner_ban', {"reason": reason, "transfer_id": transfer_id or ""}, room=sid),
                self.loop
            )

    def lock_miner_minted_vouchers(self, username: str) -> None:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT voucher_id, payload, status, invalidated
                              FROM hps_vouchers WHERE owner = ?''', (username,))
            rows = cursor.fetchall()
            lock_ids = []
            for voucher_id, payload_text, status, invalidated in rows:
                if invalidated:
                    continue
                if status != "valid":
                    continue
                try:
                    payload = json.loads(payload_text)
                except Exception:
                    continue
                pow_info = payload.get("pow", {}) or {}
                if pow_info.get("action_type") == "hps_mint":
                    lock_ids.append(voucher_id)
            for voucher_id in lock_ids:
                cursor.execute('''UPDATE hps_vouchers SET status = ?, last_updated = ?
                                  WHERE voucher_id = ?''', ("locked", time.time(), voucher_id))
            conn.commit()

    def get_monetary_transfer(self, transfer_id: str) -> Optional[Dict[str, Any]]:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT transfer_id, transfer_type, sender, receiver, amount, created_at, status,
                              contract_id, locked_voucher_ids, assigned_miner, deadline, miner_deadline,
                              fee_amount, fee_source, signed_by, signed_at, inter_server_payload
                              FROM monetary_transfers WHERE transfer_id = ?''', (transfer_id,))
            row = cursor.fetchone()
        if not row:
            return None
        inter_server_payload = {}
        if row[16]:
            try:
                inter_server_payload = json.loads(row[16])
            except Exception:
                inter_server_payload = {}
        return {
            "transfer_id": row[0],
            "transfer_type": row[1],
            "sender": row[2],
            "receiver": row[3],
            "amount": row[4],
            "created_at": row[5],
            "status": row[6],
            "contract_id": row[7],
            "locked_voucher_ids": json.loads(row[8] or "[]"),
            "assigned_miner": row[9],
            "deadline": row[10],
            "miner_deadline": row[11],
            "fee_amount": row[12],
            "fee_source": row[13],
            "signed_by": row[14],
            "signed_at": row[15],
            "inter_server_payload": inter_server_payload
        }

    def has_pending_signature_transfers(self, miner: str) -> bool:
        if not miner:
            return False
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT 1 FROM monetary_transfers
                              WHERE assigned_miner = ? AND status = ?
                              LIMIT 1''', (miner, "pending_signature"))
            return cursor.fetchone() is not None

    def get_transfer_by_voucher_id(self, voucher_id: str) -> Optional[Dict[str, Any]]:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT transfer_id FROM monetary_transfers
                              WHERE locked_voucher_ids LIKE ?''', (f'%{voucher_id}%',))
            row = cursor.fetchone()
        if not row:
            return None
        return self.get_monetary_transfer(row[0])

    def lock_transfer_vouchers(self, transfer_id: str) -> None:
        transfer = self.get_monetary_transfer(transfer_id)
        if not transfer:
            return
        voucher_ids = transfer.get("locked_voucher_ids", [])
        if not voucher_ids:
            return
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            for voucher_id in voucher_ids:
                cursor.execute('''UPDATE hps_vouchers SET status = ?, last_updated = ?
                                  WHERE voucher_id = ?''', ("locked", time.time(), voucher_id))
            conn.commit()

    def unlock_transfer_vouchers(self, transfer_id: str) -> None:
        transfer = self.get_monetary_transfer(transfer_id)
        if not transfer:
            return
        voucher_ids = transfer.get("locked_voucher_ids", [])
        if not voucher_ids:
            return
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            for voucher_id in voucher_ids:
                cursor.execute('''UPDATE hps_vouchers SET status = ?, last_updated = ?
                                  WHERE voucher_id = ? AND status = ?''',
                               ("valid", time.time(), voucher_id, "locked"))
            conn.commit()

    async def settle_miner_signature(self, transfer_id: str, miner: str, contract_content: bytes, signature: str) -> None:
        transfer = self.get_monetary_transfer(transfer_id)
        if not transfer:
            return
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''UPDATE monetary_transfers SET status = ?, signed_by = ?, signed_at = ?
                              WHERE transfer_id = ?''', ("signed", miner, time.time(), transfer_id))
            signature_id = str(uuid.uuid4())
            cursor.execute('''INSERT INTO transfer_signatures
                              (signature_id, transfer_id, miner, signature, contract_content, created_at)
                              VALUES (?, ?, ?, ?, ?, ?)''',
                           (signature_id, transfer_id, miner, signature,
                            base64.b64encode(contract_content).decode("utf-8"), time.time()))
            conn.commit()
        stats = self.get_miner_stats(miner)
        resolved_entries = self.resolve_miner_debt_entries(
            miner,
            ["signature_immediate", "signature_last_resort"],
            limit=1
        )
        if resolved_entries:
            pending_signatures, _ = self.sync_miner_pending_counts(miner)
            if pending_signatures <= 0:
                self.release_withheld_offers_for_miner(miner)
        self.unlock_transfer_vouchers(transfer_id)
        self.pay_miner_signature_fee(transfer, miner)
        self.notify_monetary_transfer_update(
            transfer_id,
            "signed",
            reason="miner_signed",
            details={"message": "Assinatura do minerador confirmada."}
        )
        if str(transfer.get("transfer_type", "")).startswith("spend_hps:"):
            await self.process_pending_monetary_action(transfer_id)

    def pay_miner_signature_fee(self, transfer: Dict[str, Any], miner: str) -> None:
        fee_amount = int(transfer.get("fee_amount", 0))
        if fee_amount <= 0:
            return
        fee_source = transfer.get("fee_source", "")
        if fee_source == "custody" or transfer.get("receiver") == CUSTODY_USERNAME:
            custody_balance = self.get_economy_stat("custody_balance", 0.0)
            if custody_balance > 0:
                self.set_economy_stat("custody_balance", max(0.0, custody_balance - fee_amount))
        offer = self.create_voucher_offer(
            owner=miner,
            owner_public_key=self.get_user_public_key(miner),
            value=fee_amount,
            reason=f"signature_fee:{transfer.get('transfer_id')}",
            pow_info=None,
            conditions={"type": "signature_fee", "transfer_id": transfer.get("transfer_id")}
        )
        miner_info = self.authenticated_users.get(miner, {})
        miner_sid = miner_info.get("sid")
        if miner_sid:
            asyncio.run_coroutine_threadsafe(
                self.sio.emit('hps_voucher_offer', {
                    'offer_id': offer["offer_id"],
                    'voucher_id': offer["voucher_id"],
                    'payload': offer["payload"],
                    'expires_at': offer["expires_at"]
                }, room=miner_sid),
                self.loop
            )
        self.record_economy_event("miner_signature_fee")
        self.record_economy_contract("miner_signature_fee")

    async def finalize_spend_hps_payment(self, payment_info: Dict[str, Any]) -> None:
        session_id = payment_info.get("session_id", "")
        username = payment_info.get("username", "")
        voucher_ids = payment_info.get("voucher_ids", []) or []
        actual_cost = int(payment_info.get("actual_cost", 0))
        total_value = int(payment_info.get("total_value", 0))
        action_type = payment_info.get("action_type", "")
        contract_id = payment_info.get("contract_id", "")
        if not session_id or not username:
            return
        self.mark_vouchers_spent(session_id)
        self.allocate_economy_revenue(actual_cost, f"spend_hps:{action_type}")
        self.save_server_contract(
            "hps_spend_receipt",
            [
                ("PAYER", username),
                ("ACTION", action_type),
                ("COST", actual_cost),
                ("VOUCHERS", json.dumps(voucher_ids, ensure_ascii=True)),
                ("CONTRACT_ID", contract_id)
            ],
            op_id=session_id
        )
        change_value = int(total_value) - int(actual_cost)
        if change_value > 0:
            await self.issue_change_offer(
                username=username,
                change_value=change_value,
                reason=f"spend_hps_change:{action_type}",
                session_id=session_id,
                contract_action="hps_spend_refund",
                contract_details=[
                    ("PAYER", username),
                    ("ACTION", action_type),
                    ("ORIGINAL_COST", actual_cost),
                    ("VOUCHERS", json.dumps(voucher_ids, ensure_ascii=True))
                ]
            )
        await self.send_hps_wallet_sync(username)
        await self.send_hps_economy_status()

    async def process_pending_monetary_action(self, transfer_id: str) -> None:
        action = self.get_pending_monetary_action(transfer_id)
        if not action:
            return
        if action.get("status") != "pending":
            return
        action_id = action.get("action_id")
        self.update_pending_monetary_action_status(action_id, "processing")
        payload = action.get("payload", {}) or {}
        payment_info = payload.get("payment", {}) or {}
        try:
            await self.finalize_spend_hps_payment(payment_info)
            handler = self.deferred_action_handlers.get(action.get("action_name"))
            if not handler:
                await self.emit_to_user(action.get("username", ""), action.get("response_event", ""), {
                    "success": False,
                    "error": "Ação pendente sem handler"
                })
                self.update_pending_monetary_action_status(action_id, "failed")
                return
            data = payload.get("data", {}) or {}
            data["_deferred_payment"] = True
            data["_deferred_username"] = action.get("username", "")
            data["_deferred_client_identifier"] = action.get("client_identifier", "")
            node_id = payload.get("node_id")
            if node_id:
                data["_deferred_node_id"] = node_id
            public_key = payload.get("public_key")
            if public_key:
                data["_deferred_public_key"] = public_key
            user_info = self.authenticated_users.get(action.get("username", ""), {})
            sid = user_info.get("sid", "")
            await handler(sid, data)
            self.update_pending_monetary_action_status(action_id, "completed")
        except Exception as e:
            logger.error(f"Deferred monetary action failed for {transfer_id}: {e}")
            await self.emit_to_user(action.get("username", ""), action.get("response_event", ""), {
                "success": False,
                "error": str(e)
            })
            self.update_pending_monetary_action_status(action_id, "failed")

    async def cancel_pending_monetary_action(self, transfer_id: str, reason: str) -> None:
        action = self.get_pending_monetary_action(transfer_id)
        if not action:
            return
        action_id = action.get("action_id")
        payload = action.get("payload", {}) or {}
        payment_info = payload.get("payment", {}) or {}
        session_id = payment_info.get("session_id", "")
        if session_id:
            self.release_vouchers_for_session(session_id)
        self.update_pending_monetary_action_status(action_id, "cancelled")
        await self.emit_to_user(action.get("username", ""), action.get("response_event", ""), {
            "success": False,
            "error": reason
        })
    def allocate_economy_revenue(self, amount: int, reason: str = "spend_hps") -> None:
        if amount <= 0:
            return
        if self.owner_enabled:
            owner_share = int(amount // 2)
            custody_share = int(amount - owner_share)
            self.increment_economy_stat("owner_balance", owner_share)
            self.increment_economy_stat("custody_balance", custody_share)
            self.issue_owner_share(owner_share, reason)
            self.save_server_contract(
                "hps_owner_share",
                [
                    ("OWNER", self.owner_username),
                    ("VALUE", owner_share),
                    ("REASON", reason)
                ]
            )
        else:
            custody_share = int(amount)
            self.increment_economy_stat("custody_balance", custody_share)
        self.record_economy_event(reason)
        self.record_economy_contract(reason)

    def allocate_exchange_fee(self, amount: int) -> None:
        if amount <= 0:
            return
        custody_share = int(amount)
        self.increment_economy_stat("custody_balance", custody_share)
        self.record_economy_event("exchange_fee")
        self.record_economy_contract("exchange_fee")

    def issue_owner_share(self, amount: float, reason: str) -> None:
        if amount <= 0:
            return
        owner_key = self.get_user_public_key(self.owner_username)
        if not owner_key or owner_key == PENDING_PUBLIC_KEY:
            return
        offer = self.create_voucher_offer(
            owner=self.owner_username,
            owner_public_key=owner_key,
            value=int(math.floor(amount)),
            reason=f"owner_share:{reason}",
            pow_info=None,
            conditions={"type": "owner_share", "reason": reason}
        )
        owner_info = self.authenticated_users.get(self.owner_username, {})
        owner_sid = owner_info.get("sid")
        if owner_sid:
            asyncio.run_coroutine_threadsafe(
                self.sio.emit('hps_voucher_offer', {
                    'offer_id': offer["offer_id"],
                    'voucher_id': offer["voucher_id"],
                    'payload': offer["payload"],
                    'expires_at': offer["expires_at"]
                }, room=owner_sid),
                self.loop
            )

    def get_economy_status(self) -> Dict[str, Any]:
        return {
            "total_minted": self.get_economy_stat("total_minted", 0.0),
            "custody_balance": self.get_economy_stat("custody_balance", 0.0),
            "owner_balance": self.get_economy_stat("owner_balance", 0.0),
            "rebate_balance": 0.0,
            "multiplier": self.get_economy_multiplier(),
            "pow_costs": {k: self.get_hps_pow_cost(k, apply_discount=False) for k in self.hps_pow_costs.keys()},
            "owner_enabled": self.owner_enabled,
            "owner_username": self.owner_username,
            "exchange_fee_rate": self.exchange_fee_rate,
            "exchange_fee_min": self.exchange_fee_min,
            "last_economy_update_ts": self.get_economy_stat("last_economy_update_ts", 0.0),
            "last_economy_event_ts": self.get_economy_stat("last_economy_event_ts", 0.0)
        }

    async def send_hps_economy_status(self, sid: Optional[str] = None) -> None:
        payload = self.get_economy_status()
        if sid:
            await self.sio.emit('hps_economy_status', payload, room=sid)
            return
        await self.sio.emit('hps_economy_status', payload)

    def check_economy_consistency(self) -> Optional[str]:
        last_event = self.get_economy_stat("last_economy_event_ts", 0.0)
        last_update = self.get_economy_stat("last_economy_update_ts", 0.0)
        reason = self.get_economy_stat_text("last_economy_event_reason", "")
        if last_event > 0 and (last_event - last_update) > 5.0:
            return f"missing_economy_update:{reason}"
        return None

    async def spend_hps_for_action(self, username: str, hps_payment: Dict[str, Any],
                                   action_type: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        cost = self.get_hps_pow_cost(action_type)
        if cost <= 0:
            return False, "HPS cost not configured", None
        voucher_ids = hps_payment.get("voucher_ids", []) or []
        contract_content_b64 = hps_payment.get("contract_content")
        if not contract_content_b64:
            return False, "Missing spend contract", None
        contract_content = base64.b64decode(contract_content_b64)
        valid, error_msg, contract_info = self.validate_contract_structure(contract_content)
        if not valid:
            return False, f"Invalid spend contract: {error_msg}", None
        if contract_info['action'] != "spend_hps":
            return False, "Invalid spend contract action", None
        if contract_info['user'] != username:
            return False, "Spend contract user mismatch", None
        if not self.verify_contract_signature(
            contract_content=contract_content,
            username=username,
            signature=contract_info['signature']
        ):
            return False, "Invalid spend contract signature", None
        contract_action_type = (self.extract_contract_detail(contract_info, "ACTION_TYPE") or "").strip()
        if contract_action_type and contract_action_type != action_type:
            return False, "Spend contract action type mismatch", None
        contract_cost = self.extract_contract_detail(contract_info, "COST")
        quoted_cost = self.get_hps_pow_cost(action_type, apply_discount=False)
        if contract_cost is not None:
            try:
                contract_cost_value = int(float(contract_cost))
            except Exception:
                return False, "Spend contract cost mismatch", None
            actual_cost_preview = self.get_hps_pow_cost(action_type, apply_discount=True)
            if contract_cost_value < actual_cost_preview:
                return False, "Spend contract cost mismatch", None
        contract_vouchers = self.extract_contract_detail(contract_info, "VOUCHERS")
        if contract_vouchers:
            try:
                contract_list = json.loads(contract_vouchers)
            except Exception:
                return False, "Spend contract vouchers invalid", None
            if set(contract_list) != set(voucher_ids):
                return False, "Spend contract vouchers mismatch", None
        contract_id = self.save_contract(
            action_type="spend_hps",
            content_hash=None,
            domain=None,
            username=username,
            signature=contract_info['signature'],
            contract_content=contract_content
        )
        session_id = f"pow-{uuid.uuid4()}"
        ok, total_value, error = self.reserve_vouchers_for_session(username, session_id, voucher_ids)
        if not ok:
            return False, error, None
        actual_cost = self.get_hps_pow_cost(action_type, apply_discount=True)
        if actual_cost > quoted_cost:
            self.release_vouchers_for_session(session_id)
            return False, "Spend contract cost mismatch", None
        if total_value < actual_cost:
            self.release_vouchers_for_session(session_id)
            return False, "Insufficient HPS balance", None
        fee_amount, fee_source, _ = self.allocate_signature_fee(actual_cost)
        transfer_id = self.create_monetary_transfer(
            transfer_type=f"spend_hps:{action_type}",
            sender=username,
            receiver=CUSTODY_USERNAME,
            amount=actual_cost,
            locked_voucher_ids=voucher_ids,
            contract_id=contract_id,
            fee_amount=fee_amount,
            fee_source=fee_source
        )
        await self.send_hps_wallet_sync(username)
        pending_info = {
            "transfer_id": transfer_id,
            "session_id": session_id,
            "contract_id": contract_id,
            "voucher_ids": voucher_ids,
            "actual_cost": actual_cost,
            "total_value": total_value,
            "action_type": action_type,
            "username": username
        }
        return True, "", pending_info

    async def authorize_pow_or_hps(self, client_identifier: str, username: str, action_type: str,
                                   pow_nonce: str, hashrate_observed: float,
                                   hps_payment: Optional[Dict[str, Any]]) -> Tuple[bool, str, bool, Optional[Dict[str, Any]]]:
        if self.is_user_fraud_restricted(username):
            return False, "Conta restrita por fraude; apenas cambio permitido", False, None
        if pow_nonce:
            valid, pow_info = self.verify_pow_solution_details(client_identifier, pow_nonce, hashrate_observed, action_type)
            if valid:
                if action_type not in ("hps_mint", "login"):
                    pow_info = pow_info or {}
                    pow_info["nonce"] = pow_nonce
                    pow_value = self.get_hps_pow_cost(action_type, apply_discount=False)
                    if pow_value > 0:
                        self.issue_custody_voucher(
                            value=pow_value,
                            reason=f"pow:{action_type}",
                            pow_info=pow_info,
                            conditions={"type": "pow_action", "action": action_type, "user": username}
                        )
                return True, "", False, None
            if hps_payment:
                ok, error, pending_info = await self.spend_hps_for_action(username, hps_payment, action_type)
                return ok, error, False, pending_info
            return False, "Invalid PoW solution", True, None
        if hps_payment:
            ok, error, pending_info = await self.spend_hps_for_action(username, hps_payment, action_type)
            return ok, error, False, pending_info
        return False, "Missing PoW or HPS payment", False, None

    def get_hps_transfer_session_by_voucher(self, voucher_id: str) -> Optional[Dict[str, Any]]:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT session_id, payer, target, voucher_ids, amount, total_value, status, expires_at
                              FROM hps_transfer_sessions WHERE voucher_id = ?''', (voucher_id,))
            row = cursor.fetchone()
        if not row:
            return None
        return {
            "session_id": row[0],
            "payer": row[1],
            "target": row[2],
            "voucher_ids": row[3],
            "amount": int(row[4]),
            "total_value": int(row[5]),
            "status": row[6],
            "expires_at": float(row[7])
        }

    def get_hps_transfer_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT session_id, offer_id, voucher_id, payer, target, voucher_ids,
                                     amount, total_value, status, expires_at
                              FROM hps_transfer_sessions WHERE session_id = ?''', (session_id,))
            row = cursor.fetchone()
        if not row:
            return None
        return {
            "session_id": row[0],
            "offer_id": row[1],
            "voucher_id": row[2],
            "payer": row[3],
            "target": row[4],
            "voucher_ids": row[5],
            "amount": int(row[6]),
            "total_value": int(row[7]),
            "status": row[8],
            "expires_at": float(row[9])
        }

    def get_monetary_transfer_by_contract(self, contract_id: str, transfer_type: str) -> Optional[Dict[str, Any]]:
        if not contract_id:
            return None
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT transfer_id FROM monetary_transfers
                              WHERE contract_id = ? AND transfer_type = ?
                              ORDER BY created_at DESC LIMIT 1''',
                           (contract_id, transfer_type))
            row = cursor.fetchone()
        if not row:
            return None
        return self.get_monetary_transfer(row[0])

    def update_hps_transfer_session_offer(self, session_id: str, offer_id: str, voucher_id: str, expires_at: float) -> None:
        if not session_id:
            return
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''UPDATE hps_transfer_sessions
                              SET offer_id = ?, voucher_id = ?, status = ?, expires_at = ?
                              WHERE session_id = ?''',
                           (offer_id or "", voucher_id or "", "pending", float(expires_at), session_id))
            conn.commit()

    def delete_hps_transfer_session(self, session_id: str) -> None:
        if not session_id:
            return
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM hps_transfer_sessions WHERE session_id = ?', (session_id,))
            conn.commit()

    def update_hps_transfer_session_target(self, session_id: str, target: str) -> None:
        if not session_id:
            return
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''UPDATE hps_transfer_sessions SET target = ? WHERE session_id = ?''',
                           (target, session_id))
            conn.commit()

    def update_transfer_locked_vouchers(self, transfer_id: str, voucher_ids: List[str]) -> None:
        if not transfer_id:
            return
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''UPDATE monetary_transfers SET locked_voucher_ids = ?
                              WHERE transfer_id = ?''',
                           (json.dumps(voucher_ids or [], ensure_ascii=True), transfer_id))
            conn.commit()

    def delete_pending_transfers_by_session_id(self, session_id: str) -> None:
        if not session_id:
            return
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM pending_transfers WHERE hps_session_id = ?', (session_id,))
            conn.commit()

    async def create_hps_transfer_session(self, payer: str, target: str, voucher_ids: List[str],
                                          amount: int) -> Tuple[Optional[Dict[str, Any]], str]:
        session_id = str(uuid.uuid4())
        ok, total_value, error = self.reserve_vouchers_for_session(payer, session_id, voucher_ids)
        if not ok:
            return None, error
        if total_value < amount:
            self.release_vouchers_for_session(session_id)
            return None, "Insufficient HPS balance"
        expires_at = time.time() + (7 * 24 * 3600)
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT OR REPLACE INTO hps_transfer_sessions
                              (session_id, offer_id, voucher_id, payer, target, voucher_ids,
                               amount, total_value, status, created_at, expires_at)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                           (session_id, "", "", payer, target,
                            json.dumps(voucher_ids, ensure_ascii=True), amount, total_value, "pending_confirmation",
                            time.time(), expires_at))
            conn.commit()
        return {
            "session_id": session_id,
            "payer": payer,
            "target": target,
            "amount": amount,
            "total_value": total_value,
            "expires_at": expires_at
        }, ""

    async def complete_hps_transfer(self, voucher_id: str) -> None:
        transfer = self.get_hps_transfer_session_by_voucher(voucher_id)
        if not transfer or transfer.get("status") != "pending":
            return
        session_id = transfer["session_id"]
        payer = transfer["payer"]
        amount = transfer["amount"]
        total_value = transfer["total_value"]
        self.mark_vouchers_spent(session_id)
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE hps_transfer_sessions SET status = ? WHERE session_id = ?', ("completed", session_id))
            conn.commit()
        self.save_server_contract(
            "hps_transfer_complete",
            [
                ("PAYER", payer),
                ("TARGET", transfer.get("target", "")),
                ("AMOUNT", amount),
                ("TOTAL_VALUE", total_value),
                ("VOUCHERS", transfer.get("voucher_ids", "")),
                ("TRANSFER_VOUCHER_ID", voucher_id)
            ],
            op_id=session_id
        )
        refund_value = total_value - amount
        if refund_value > 0:
            owner_key = self.get_user_public_key(payer)
            if owner_key:
                refund_offer = self.create_voucher_offer(
                    owner=payer,
                    owner_public_key=owner_key,
                    value=refund_value,
                    reason=f"hps_transfer_refund:{voucher_id}",
                    pow_info=None,
                    conditions=None,
                    session_id=session_id
                )
                self.save_server_contract(
                    "hps_transfer_refund",
                    [
                        ("PAYER", payer),
                        ("REFUND_VALUE", refund_value),
                        ("ORIGINAL_VOUCHER_ID", voucher_id),
                        ("REFUND_VOUCHER_ID", refund_offer.get("voucher_id", "")),
                        ("SESSION_ID", session_id)
                    ],
                    op_id=refund_offer.get("voucher_id")
                )
                payer_info = self.authenticated_users.get(payer, {})
                payer_sid = payer_info.get("sid")
                if payer_sid:
                    await self.sio.emit('hps_voucher_offer', {
                        'offer_id': refund_offer["offer_id"],
                        'voucher_id': refund_offer["voucher_id"],
                        'payload': refund_offer["payload"],
                        'expires_at': refund_offer["expires_at"]
                    }, room=payer_sid)
        await self.send_hps_wallet_sync(payer)
        await self.send_hps_wallet_sync(transfer["target"])

    async def move_hps_transfer_to_custody(self, transfer: Dict[str, Any]) -> None:
        session_id = transfer.get("hps_session_id", "")
        if not session_id:
            return
        session = self.get_hps_transfer_session(session_id)
        if not session:
            return
        if session.get("status") not in ("pending_confirmation", "pending"):
            return
        payer = session.get("payer", "")
        amount = int(session.get("amount", 0))
        total_value = int(session.get("total_value", 0))
        self.mark_vouchers_spent(session_id)
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE hps_transfer_sessions SET status = ? WHERE session_id = ?',
                           ("custody", session_id))
            conn.commit()
        if amount > 0:
            self.issue_custody_voucher(amount, reason=f"hps_transfer_custody:{session_id}")
        refund_value = total_value - amount
        if refund_value > 0 and payer:
            owner_key = self.get_user_public_key(payer)
            if owner_key:
                refund_offer = self.create_voucher_offer(
                    owner=payer,
                    owner_public_key=owner_key,
                    value=refund_value,
                    reason=f"hps_transfer_custody_refund:{session_id}",
                    pow_info=None,
                    conditions=None,
                    session_id=session_id
                )
                self.save_server_contract(
                    "hps_transfer_custody_refund",
                    [
                        ("PAYER", payer),
                        ("REFUND_VALUE", refund_value),
                        ("SESSION_ID", session_id),
                        ("VOUCHERS", session.get("voucher_ids", ""))
                    ],
                    op_id=refund_offer.get("voucher_id")
                )
                payer_info = self.authenticated_users.get(payer, {})
                payer_sid = payer_info.get("sid")
                if payer_sid:
                    await self.sio.emit('hps_voucher_offer', {
                        'offer_id': refund_offer["offer_id"],
                        'voucher_id': refund_offer["voucher_id"],
                        'payload': refund_offer["payload"],
                        'expires_at': refund_offer["expires_at"]
                    }, room=payer_sid)
        await self.send_hps_wallet_sync(payer)
        await self.send_hps_economy_status()

    async def cleanup_hps_transfer_sessions(self) -> None:
        now = time.time()
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT session_id, payer FROM hps_transfer_sessions
                              WHERE status IN (?, ?) AND expires_at < ?''', ("pending", "pending_confirmation", now))
            rows = cursor.fetchall()
        for row in rows:
            session_id, payer = row
            self.release_vouchers_for_session(session_id)
            with get_db_conn(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE hps_transfer_sessions SET status = ? WHERE session_id = ?', ("expired", session_id))
                conn.commit()
            self.delete_pending_transfers_by_session_id(session_id)
            if payer:
                await self.send_hps_wallet_sync(payer)
    async def invalidate_issuer(self, reason: str, session_id: Optional[str] = None) -> None:
        if self.hps_issuer_invalidated:
            return
        self.hps_issuer_invalidated = True
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT voucher_id, owner, value, reason, issued_at
                              FROM hps_vouchers WHERE issuer = ?''', (self.address,))
            vouchers = cursor.fetchall()
            cursor.execute('''INSERT OR REPLACE INTO hps_issuer_invalidations
                              (issuer, reason, session_id, invalidated_at)
                              VALUES (?, ?, ?, ?)''',
                           (self.address, reason, session_id or "", time.time()))
            cursor.execute('''UPDATE hps_vouchers SET invalidated = 1, status = ?, last_updated = ?
                              WHERE issuer = ?''',
                           ("invalid", time.time(), self.address))
            conn.commit()
        for voucher_id, owner, value, voucher_reason, issued_at in vouchers:
            self.save_server_contract(
                "voucher_invalidate",
                [
                    ("VOUCHER_ID", voucher_id),
                    ("OWNER", owner),
                    ("ISSUER", self.address),
                    ("VALUE", value),
                    ("REASON", voucher_reason),
                    ("ISSUED_AT", issued_at),
                    ("INVALIDATION_REASON", reason),
                    ("SESSION_ID", session_id or "")
                ],
                op_id=voucher_id
            )
        for sid in self.connected_clients:
            await self.sio.emit('hps_issuer_invalidated', {
                'issuer': self.address,
                'reason': reason,
                'session_id': session_id or ""
            }, room=sid)

    def user_needs_usage_contract(self, username: str) -> bool:
        if not username:
            return True
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT contract_hash FROM usage_contract_acceptance
                              WHERE username = ? ORDER BY accepted_at DESC LIMIT 1''',
                           (username,))
            row = cursor.fetchone()
        if not row:
            return True
        return row[0] != self.usage_contract_hash

    def store_usage_contract_acceptance(self, username: str) -> None:
        if not username or not self.usage_contract_hash:
            return
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT OR REPLACE INTO usage_contract_acceptance
                              (username, contract_hash, accepted_at)
                              VALUES (?, ?, ?)''',
                           (username, self.usage_contract_hash, time.time()))
            conn.commit()

    def extract_terms_from_usage_contract(self, contract_text: str) -> str:
        in_terms = False
        lines = []
        for raw in contract_text.splitlines():
            line = raw.strip()
            if line.startswith("### "):
                if line == "### TERMS:":
                    in_terms = True
                    continue
                if line.startswith("### :END "):
                    if in_terms:
                        break
                    in_terms = False
                    continue
            if in_terms and line.startswith("# "):
                lines.append(line[2:])
        return "\n".join(lines).strip()

    async def finalize_authentication(self, sid: str, username: str, public_key_b64: str,
                                      node_type: str, client_identifier: str, reputation: int) -> None:
        self.connected_clients[sid]['authenticated'] = True
        self.connected_clients[sid]['username'] = username
        self.connected_clients[sid]['public_key'] = public_key_b64
        self.connected_clients[sid]['node_type'] = node_type
        self.connected_clients[sid]['client_identifier'] = client_identifier
        self.connected_clients[sid]['pow_solved'] = True
        self.authenticated_users[username] = {
            'sid': sid, 'public_key': public_key_b64, 'node_type': node_type, 'client_identifier': client_identifier
        }
        await self.sio.emit('authentication_result', {
            'success': True,
            'username': username,
            'reputation': reputation,
            'server_address': self.address
        }, room=sid)
        logger.info(f"User authenticated: {username}")
        await self.sync_client_files(client_identifier, sid)
        self.notify_contract_violations_for_user(username)
        self.notify_pending_transfers(username)
        await self.sio.emit('hps_wallet_sync', {'vouchers': self.list_user_vouchers(username)}, room=sid)
        await self.send_pending_voucher_offers(username, sid)
        await self.send_hps_economy_status(sid)
        self.assign_unassigned_transfers()
        alert_reason = self.check_economy_consistency()
        if alert_reason:
            contract_id = self.save_server_contract(
                "economy_alert",
                [
                    ("ISSUER", self.address),
                    ("REASON", alert_reason),
                    ("LAST_EVENT_TS", self.get_economy_stat("last_economy_event_ts", 0.0)),
                    ("LAST_UPDATE_TS", self.get_economy_stat("last_economy_update_ts", 0.0))
                ]
            )
            asyncio.create_task(self.propagate_contract_to_network(contract_id))
            await self.sio.emit('economy_alert', {
                "reason": alert_reason,
                "issuer": self.address,
                "contract_id": contract_id
            }, room=sid)
        server_list = []
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT address, public_key, last_seen, reputation FROM server_nodes WHERE is_active = 1 ORDER BY reputation DESC')
            for row in cursor.fetchall():
                server_list.append({'address': row[0], 'public_key': row[1], 'last_seen': row[2], 'reputation': row[3]})
        await self.sio.emit('server_list', {'servers': server_list}, room=sid)
        backup_server = await self.select_backup_server()
        if backup_server:
            await self.sio.emit('backup_server', {'server': backup_server, 'timestamp': time.time()}, room=sid)

    def save_known_servers(self):
        with get_db_conn(self.db_path) as conn:
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

        with get_db_conn(self.db_path) as conn:
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
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

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
                        headers = {}
                        payload = data
                        if data is not None and not isinstance(data, (bytes, str)):
                            payload = json.dumps(data, ensure_ascii=True).encode("utf-8")
                            headers["Content-Type"] = "application/json"
                        async with session.post(url, params=params, data=payload, headers=headers) as response:
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
        with get_db_conn(self.db_path) as conn:
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
        elif action_type == "hps_mint": base_bits, target_seconds = 12, 30.0
        elif action_type == "login": base_bits, target_seconds = 12, 20.0
        elif action_type == "usage_contract": base_bits, target_seconds = 10, 20.0
        elif action_type == "contract_transfer": base_bits, target_seconds = 10, 20.0
        elif action_type == "contract_reset": base_bits, target_seconds = 10, 20.0
        elif action_type == "contract_certify": base_bits, target_seconds = 10, 20.0
        elif action_type == "hps_transfer": base_bits, target_seconds = 10, 20.0
        recent_count = len(self.login_attempts[client_identifier]) + attempt_count
        if recent_count > 0:
            base_bits += min(10, recent_count)
        client_hashrate = self.client_hashrates.get(client_identifier, 100000)
        if client_hashrate <= 0: client_hashrate = 100000
        target_bits = self.compute_target_bits(client_hashrate, target_seconds)
        target_bits = max(base_bits, target_bits)
        voucher_id = None
        if action_type == "hps_mint":
            voucher_id = str(uuid.uuid4())
            challenge_message = f"HPSMINT:{voucher_id}:{secrets.token_hex(16)}".encode("ascii")
        else:
            challenge_message = secrets.token_bytes(32)
        challenge = base64.b64encode(challenge_message).decode('utf-8')
        self.pow_challenges[client_identifier] = {
            'challenge': challenge, 'target_bits': target_bits, 'timestamp': now,
            'target_seconds': target_seconds, 'action_type': action_type,
            'voucher_id': voucher_id
        }
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO pow_history (client_identifier, challenge, target_bits, timestamp) VALUES (?, ?, ?, ?)',
                           (client_identifier, challenge, target_bits, now))
            conn.commit()
        payload = {
            'challenge': challenge,
            'target_bits': target_bits,
            'message': f'Solve PoW for {action_type}',
            'target_seconds': target_seconds,
            'action_type': action_type
        }
        if voucher_id:
            payload['voucher_id'] = voucher_id
        return payload

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
                with get_db_conn(self.db_path) as conn:
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

    def verify_pow_solution_details(self, client_identifier: str, nonce: str, hashrate_observed: float,
                                    action_type: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        if client_identifier not in self.pow_challenges:
            return False, None
        challenge_data = self.pow_challenges[client_identifier]
        if challenge_data['action_type'] != action_type:
            return False, None
        if time.time() - challenge_data['timestamp'] > 300:
            del self.pow_challenges[client_identifier]
            return False, None
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
                with get_db_conn(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('UPDATE pow_history SET success = 1, solve_time = ? WHERE client_identifier = ? AND challenge = ?',
                                   (solve_time, client_identifier, challenge))
                    conn.commit()
                del self.pow_challenges[client_identifier]
                self.login_attempts[client_identifier].append(time.time())
                if hashrate_observed > 0:
                    self.client_hashrates[client_identifier] = hashrate_observed
                return True, {
                    "challenge": challenge,
                    "target_bits": target_bits,
                    "target_seconds": challenge_data.get("target_seconds", 0),
                    "action_type": action_type,
                    "solve_time": solve_time,
                    "hashrate_observed": hashrate_observed,
                    "voucher_id": challenge_data.get("voucher_id")
                }
        except Exception as e:
            logger.error(f"PoW verification error for {client_identifier}: {e}")
        return False, None

    def check_rate_limit(self, client_identifier, action_type):
        now = time.time()
        if action_type == "hps_mint":
            return True, "", 0
        if client_identifier in self.banned_clients:
            ban_until = self.banned_clients[client_identifier]
            if now < ban_until:
                return False, f"Banned for {int(ban_until - now)} seconds", int(ban_until - now)
            else:
                del self.banned_clients[client_identifier]
        with get_db_conn(self.db_path) as conn:
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
            elif action_type == "hps_mint": min_interval = 20
            if now - last_time < min_interval:
                remaining = min_interval - int(now - last_time)
                return False, f"Rate limit: {remaining}s remaining", remaining
            return True, "", 0

    def update_rate_limit(self, client_identifier, action_type):
        if action_type == "hps_mint":
            return
        now = time.time()
        with get_db_conn(self.db_path) as conn:
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
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE user_reputations SET reputation = 1 WHERE client_identifier = ?', (client_identifier,))
            cursor.execute('UPDATE users SET reputation = 1 WHERE client_identifier = ?', (client_identifier,))
            conn.commit()

    def increment_violation(self, client_identifier):
        if client_identifier not in self.violation_counts:
            self.violation_counts[client_identifier] = 0
        self.violation_counts[client_identifier] += 1
        with get_db_conn(self.db_path) as conn:
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

    def parse_transfer_title(self, title: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        if not title:
            return None, None, None
        match = re.search(r'\(HPS!transfer\)\{type=([^,}]+),\s*to=([^,}]+)(?:,\s*app=([^}]+))?\}', title)
        if match:
            transfer_type = match.group(1).strip().lower()
            target_user = match.group(2).strip()
            app_name = match.group(3).strip() if match.group(3) else None
            return transfer_type, target_user, app_name
        return None, None, None

    def extract_contract_detail(self, contract_info: Dict, key: str) -> Optional[str]:
        details = contract_info.get('details', {}).get('details', [])
        for line in details:
            if line.startswith(f"# {key}:"):
                return line.split(":", 1)[1].strip()
        return None

    def resolve_contract_target(self, contract_info: Optional[Dict],
                                content_hash: Optional[str] = None,
                                domain: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
        if contract_info:
            target_type = self.extract_contract_detail(contract_info, "TARGET_TYPE")
            target_id = self.extract_contract_detail(contract_info, "TARGET_ID")
            if target_type and target_id:
                target_type = target_type.lower()
                if target_type == "domain":
                    domain = target_id
                elif target_type in ("content", "content_hash", "file"):
                    content_hash = target_id
            details_domain = self.extract_contract_detail(contract_info, "DOMAIN")
            details_content = self.extract_contract_detail(contract_info, "CONTENT_HASH")
            if details_domain:
                domain = details_domain
            if details_content:
                content_hash = details_content
        return content_hash, domain

    def should_sync_contract_target(self, content_hash: Optional[str], domain: Optional[str]) -> bool:
        if domain:
            with get_db_conn(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT ddns_hash FROM dns_records WHERE domain = ?', (domain,))
                row = cursor.fetchone()
                if not row:
                    return False
                ddns_hash = row[0]
            ddns_path = os.path.join(self.files_dir, f"{ddns_hash}.ddns")
            legacy_ddns_path = os.path.join(self.files_dir, f"{domain}.ddns")
            if not (os.path.exists(ddns_path) or os.path.exists(legacy_ddns_path)):
                return False
            with get_db_conn(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT 1 FROM contracts WHERE domain = ? LIMIT 1', (domain,))
                if cursor.fetchone():
                    return False
            return True
        if content_hash:
            with get_db_conn(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT file_path FROM content WHERE content_hash = ?', (content_hash,))
                row = cursor.fetchone()
            if not row:
                return False
            file_path = row[0]
            content_path = os.path.join(self.files_dir, f"{content_hash}.dat")
            if not ((file_path and os.path.exists(file_path)) or os.path.exists(content_path)):
                return False
            with get_db_conn(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT 1 FROM contracts WHERE content_hash = ? LIMIT 1', (content_hash,))
                if cursor.fetchone():
                    return False
            return True
        return True

    def extract_contract_owner_from_db(self, content_hash: Optional[str], domain: Optional[str]) -> Optional[str]:
        if not content_hash and not domain:
            return None
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            if domain:
                cursor.execute('''SELECT contract_content FROM contracts
                                  WHERE domain = ? ORDER BY timestamp DESC LIMIT 1''', (domain,))
            else:
                cursor.execute('''SELECT contract_content FROM contracts
                                  WHERE content_hash = ? ORDER BY timestamp DESC LIMIT 1''', (content_hash,))
            row = cursor.fetchone()
        if not row or not row[0]:
            return None
        try:
            contract_text = base64.b64decode(row[0]).decode('utf-8', errors='replace')
        except Exception:
            try:
                contract_text = row[0].decode('utf-8', errors='replace')
            except Exception:
                return None
        for line in contract_text.splitlines():
            line = line.strip()
            if line.startswith("# USER:"):
                return line.split(":", 1)[1].strip()
        return None

    def create_pending_transfer(self, transfer_type: str, target_user: str, original_owner: str,
                                content_hash: Optional[str], domain: Optional[str], app_name: Optional[str],
                                contract_id: Optional[str], conn: sqlite3.Connection = None,
                                hps_amount: Optional[int] = None, hps_total_value: Optional[int] = None,
                                hps_voucher_ids: Optional[List[str]] = None,
                                hps_session_id: Optional[str] = None) -> str:
        transfer_id = str(uuid.uuid4())
        hps_voucher_ids_text = ""
        if hps_voucher_ids:
            hps_voucher_ids_text = json.dumps(hps_voucher_ids, ensure_ascii=True)
        if conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO pending_transfers
                              (transfer_id, transfer_type, target_user, original_owner, custody_user, content_hash,
                               domain, app_name, contract_id, status, timestamp,
                               hps_amount, hps_total_value, hps_voucher_ids, hps_session_id)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                           (transfer_id, transfer_type, target_user, original_owner, CUSTODY_USERNAME,
                            content_hash, domain, app_name, contract_id, "pending", time.time(),
                            hps_amount, hps_total_value, hps_voucher_ids_text, hps_session_id))
            return transfer_id
        with get_db_conn(self.db_path) as db_conn:
            cursor = db_conn.cursor()
            cursor.execute('''INSERT INTO pending_transfers
                              (transfer_id, transfer_type, target_user, original_owner, custody_user, content_hash,
                               domain, app_name, contract_id, status, timestamp,
                               hps_amount, hps_total_value, hps_voucher_ids, hps_session_id)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                           (transfer_id, transfer_type, target_user, original_owner, CUSTODY_USERNAME,
                            content_hash, domain, app_name, contract_id, "pending", time.time(),
                            hps_amount, hps_total_value, hps_voucher_ids_text, hps_session_id))
        return transfer_id

    def resolve_original_owner(self, content_hash: Optional[str], domain: Optional[str], app_name: Optional[str]) -> Optional[str]:
        if content_hash:
            with get_db_conn(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT username FROM content WHERE content_hash = ?', (content_hash,))
                row = cursor.fetchone()
                if row and row[0] and row[0] not in (CUSTODY_USERNAME, "system"):
                    return row[0]
                cursor.execute('''SELECT original_owner FROM pending_transfers
                                  WHERE content_hash = ? AND status = 'pending'
                                  ORDER BY timestamp DESC LIMIT 1''', (content_hash,))
                row = cursor.fetchone()
                if row:
                    return row[0]
        if domain:
            with get_db_conn(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT username FROM dns_records WHERE domain = ?', (domain,))
                row = cursor.fetchone()
                if row and row[0] and row[0] not in (CUSTODY_USERNAME, "system"):
                    return row[0]
                cursor.execute('''SELECT original_owner FROM pending_transfers
                                  WHERE domain = ? AND status = 'pending'
                                  ORDER BY timestamp DESC LIMIT 1''', (domain,))
                row = cursor.fetchone()
                if row:
                    return row[0]
        if app_name:
            with get_db_conn(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT username FROM api_apps WHERE app_name = ?', (app_name,))
                row = cursor.fetchone()
                if row and row[0] and row[0] not in (CUSTODY_USERNAME, "system"):
                    return row[0]
        return None

    def move_transfer_to_custody(self, transfer: Dict[str, Any]) -> None:
        transfer_type = transfer.get('transfer_type')
        content_hash = transfer.get('content_hash')
        domain = transfer.get('domain')
        app_name = transfer.get('app_name')
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            if transfer_type == "domain" and domain:
                cursor.execute('UPDATE dns_records SET username = ? WHERE domain = ?', (CUSTODY_USERNAME, domain))
            elif transfer_type == "api_app" and app_name:
                cursor.execute('UPDATE api_apps SET username = ? WHERE app_name = ?', (CUSTODY_USERNAME, app_name))
            elif transfer_type in ("content", "file") and content_hash:
                cursor.execute('UPDATE content SET username = ? WHERE content_hash = ?', (CUSTODY_USERNAME, content_hash))
            conn.commit()

    def get_pending_transfers_for_user(self, username: str) -> List[Dict]:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT transfer_id, transfer_type, target_user, original_owner, custody_user,
                                     content_hash, domain, app_name, contract_id, status, timestamp,
                                     hps_amount, hps_total_value, hps_voucher_ids, hps_session_id
                              FROM pending_transfers
                              WHERE target_user = ? AND status = 'pending'
                              ORDER BY timestamp DESC''', (username,))
            rows = cursor.fetchall()
        transfers = []
        for row in rows:
            hps_voucher_ids = []
            if row[13]:
                try:
                    hps_voucher_ids = json.loads(row[13])
                except Exception:
                    hps_voucher_ids = []
            transfer = {
                'transfer_id': row[0],
                'transfer_type': row[1],
                'target_user': row[2],
                'original_owner': row[3],
                'custody_user': row[4],
                'content_hash': row[5],
                'domain': row[6],
                'app_name': row[7],
                'contract_id': row[8],
                'status': row[9],
                'timestamp': row[10],
                'hps_amount': row[11],
                'hps_total_value': row[12],
                'hps_voucher_ids': hps_voucher_ids,
                'hps_session_id': row[14]
            }
            if row[5]:
                with get_db_conn(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT title, description, mime_type FROM content WHERE content_hash = ?', (row[5],))
                    meta = cursor.fetchone()
                    if meta:
                        transfer.update({
                            'title': meta[0],
                            'description': meta[1] or "",
                            'mime_type': meta[2] or 'application/octet-stream'
                        })
            transfers.append(transfer)
        return transfers

    def get_pending_transfer_for_user_conn(self, cursor, username: str, transfer_type: str,
                                           content_hash: str = None, domain: str = None, app_name: str = None) -> Optional[Dict]:
        cursor.execute('''SELECT transfer_id, transfer_type, target_user, original_owner, custody_user,
                                 content_hash, domain, app_name, contract_id, status, timestamp,
                                 hps_amount, hps_total_value, hps_voucher_ids, hps_session_id
                          FROM pending_transfers
                          WHERE target_user = ? AND transfer_type = ? AND status = 'pending' ''',
                       (username, transfer_type))
        rows = cursor.fetchall()
        for row in rows:
            hps_voucher_ids = []
            if row[13]:
                try:
                    hps_voucher_ids = json.loads(row[13])
                except Exception:
                    hps_voucher_ids = []
            transfer = {
                'transfer_id': row[0],
                'transfer_type': row[1],
                'target_user': row[2],
                'original_owner': row[3],
                'custody_user': row[4],
                'content_hash': row[5],
                'domain': row[6],
                'app_name': row[7],
                'contract_id': row[8],
                'status': row[9],
                'timestamp': row[10],
                'hps_amount': row[11],
                'hps_total_value': row[12],
                'hps_voucher_ids': hps_voucher_ids,
                'hps_session_id': row[14]
            }
            if content_hash and transfer.get('content_hash') == content_hash:
                return transfer
            if domain and transfer.get('domain') == domain:
                return transfer
            if app_name and transfer.get('app_name') == app_name:
                return transfer
        return None

    def get_pending_transfer(self, transfer_id: str) -> Optional[Dict]:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT transfer_id, transfer_type, target_user, original_owner, custody_user,
                                     content_hash, domain, app_name, contract_id, status, timestamp,
                                     hps_amount, hps_total_value, hps_voucher_ids, hps_session_id
                              FROM pending_transfers WHERE transfer_id = ?''', (transfer_id,))
            row = cursor.fetchone()
            if not row:
                return None
            hps_voucher_ids = []
            if row[13]:
                try:
                    hps_voucher_ids = json.loads(row[13])
                except Exception:
                    hps_voucher_ids = []
            return {
                'transfer_id': row[0],
                'transfer_type': row[1],
                'target_user': row[2],
                'original_owner': row[3],
                'custody_user': row[4],
                'content_hash': row[5],
                'domain': row[6],
                'app_name': row[7],
                'contract_id': row[8],
                'status': row[9],
                'timestamp': row[10],
                'hps_amount': row[11],
                'hps_total_value': row[12],
                'hps_voucher_ids': hps_voucher_ids,
                'hps_session_id': row[14]
            }

    def update_pending_transfer_status(self, transfer_id: str, status: str) -> None:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE pending_transfers SET status = ? WHERE transfer_id = ?', (status, transfer_id))
            conn.commit()

    def delete_pending_transfer(self, transfer_id: str) -> None:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM pending_transfers WHERE transfer_id = ?', (transfer_id,))
            conn.commit()

    def delete_pending_transfer_conn(self, cursor: sqlite3.Cursor, transfer_id: str) -> None:
        cursor.execute('DELETE FROM pending_transfers WHERE transfer_id = ?', (transfer_id,))

    def notify_pending_transfers(self, username: str) -> None:
        pending = self.get_pending_transfers_for_user(username)
        for sid, client in self.connected_clients.items():
            if client.get('username') == username:
                asyncio.run_coroutine_threadsafe(
                    self.sio.emit('pending_transfers', {'transfers': pending}, room=sid),
                    self.loop
                )
                asyncio.run_coroutine_threadsafe(
                    self.sio.emit('pending_transfer_notice', {'count': len(pending)}, room=sid),
                    self.loop
                )

    def notify_contract_violations_for_user(self, username: str) -> None:
        self.scan_contracts_for_user(username)
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT violation_type, content_hash, domain, reason
                              FROM contract_violations WHERE owner_username = ?''', (username,))
            rows = cursor.fetchall()
        if not rows:
            return
        logger.info(f"Notificando violacoes contratuais para {username}: {len(rows)}")
        for sid, client in self.connected_clients.items():
            if client.get('username') == username:
                for row in rows:
                    logger.info(f"Emissao de violacao para {username} no SID {sid}: {row}")
                    asyncio.run_coroutine_threadsafe(
                        self.sio.emit('contract_violation_notice', {
                            'violation_type': row[0],
                            'content_hash': row[1],
                            'domain': row[2],
                            'reason': row[3]
                        }, room=sid),
                        self.loop
                    )

    def scan_contracts_for_user(self, username: str) -> None:
        content_targets = []
        domain_targets = []
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT content_hash FROM content WHERE username = ?', (username,))
            content_targets = [row[0] for row in cursor.fetchall() if row[0]]
            cursor.execute('SELECT domain FROM dns_records WHERE username = ? OR original_owner = ?', (username, username))
            domain_targets = [row[0] for row in cursor.fetchall() if row[0]]
        for content_hash in content_targets:
            try:
                self.get_contracts_for_content(content_hash)
            except Exception as e:
                logger.warning(f"Falha ao verificar contratos do conteudo {content_hash}: {e}")
        for domain in domain_targets:
            try:
                self.get_contracts_for_domain(domain)
            except Exception as e:
                logger.warning(f"Falha ao verificar contratos do dominio {domain}: {e}")

    def extract_contract_from_content(self, content: bytes) -> Tuple[Optional[bytes], Optional[bytes]]:
        """Extrai contrato do conteúdo, retorna (conteúdo_sem_contrato, contrato)"""
        # Procura pelo início do contrato no final do arquivo (bytes, para não corromper binários)
        start_marker = b"# HSYST P2P SERVICE"
        end_marker = b"## :END CONTRACT"
        
        start_idx = content.rfind(start_marker)
        if start_idx == -1:
            return content, None
        
        end_idx = content.find(end_marker, start_idx)
        if end_idx == -1:
            return content, None
        
        end_idx += len(end_marker)
        
        contract_text = content[start_idx:end_idx].strip()
        content_without_contract = content[:start_idx] + content[end_idx:].lstrip(b"\r\n")
        
        return content_without_contract, contract_text

    def validate_contract_structure(self, contract_content: bytes) -> Tuple[bool, str, Dict]:
        """Valida a estrutura do contrato e extrai informações"""
        try:
            contract_text = contract_content.decode('utf-8')
            lines = contract_text.strip().split('\n')
            
            # Verifica cabeçalho
            if not contract_text.startswith("# HSYST P2P SERVICE"):
                return False, "Cabeçalho HSYST não encontrado", {}
            
            # Extrai informações
            contract_info = {
                'action': None,
                'user': None,
                'signature': None,
                'details': {}
            }
            
            current_section = None
            for line in lines:
                line = line.strip()
                if line.startswith("## CONTRACT:"):
                    continue
                elif line.startswith("## :END CONTRACT"):
                    break
                elif line.startswith("### "):
                    if line.endswith(":"):
                        current_section = line[4:-1].lower()
                        contract_info['details'][current_section] = []
                elif line.startswith("### :END "):
                    current_section = None
                elif line.startswith("# "):
                    if current_section == 'start':
                        if line.startswith("# USER:"):
                            contract_info['user'] = line.split(":", 1)[1].strip()
                        elif line.startswith("# SIGNATURE:"):
                            contract_info['signature'] = line.split(":", 1)[1].strip()
                    elif current_section == 'details':
                        if line.startswith("# ACTION:"):
                            contract_info['action'] = line.split(":", 1)[1].strip()
                        else:
                            contract_info['details'][current_section].append(line)
                    elif current_section:
                        contract_info['details'][current_section].append(line)
            
            # Valida campos obrigatórios
            if not contract_info['action']:
                return False, "Ação não especificada no contrato", {}
            if not contract_info['user']:
                return False, "Usuário não especificado no contrato", {}
            if not contract_info['signature']:
                return False, "Assinatura não fornecida no contrato", {}
            
            return True, "Contrato válido", contract_info
            
        except Exception as e:
            return False, f"Erro ao validar contrato: {str(e)}", {}

    def get_registered_public_key(self, username: str) -> Optional[str]:
        if not username:
            return None
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT public_key FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            if not row:
                return None
            public_key = (row[0] or "").strip()
            return public_key or None

    def get_server_public_key(self, address: str) -> Optional[str]:
        if not address:
            return None
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT public_key FROM server_nodes WHERE address = ? LIMIT 1', (address,))
            row = cursor.fetchone()
            if row and row[0]:
                return self.normalize_public_key(row[0])
        return None

    def normalize_public_key(self, key_value: str) -> str:
        if not key_value:
            return ""
        key_value = key_value.strip()
        if "BEGIN PUBLIC KEY" in key_value:
            return key_value
        try:
            decoded = base64.b64decode(key_value).decode("utf-8", errors="ignore").strip()
            if "BEGIN PUBLIC KEY" in decoded:
                return decoded
        except Exception:
            pass
        return key_value

    def load_public_key_from_value(self, key_value: str):
        if not key_value:
            return None
        key_value = key_value.strip()
        key_bytes = None
        if "BEGIN PUBLIC KEY" in key_value:
            key_bytes = key_value.encode("utf-8")
        else:
            try:
                decoded = base64.b64decode(key_value)
                key_bytes = decoded
            except Exception:
                key_bytes = None
        if not key_bytes:
            return None
        try:
            return serialization.load_pem_public_key(key_bytes, backend=default_backend())
        except Exception:
            return None

    def get_contract_bytes(self, contract_id: str) -> Optional[bytes]:
        if not contract_id:
            return None
        contract_file_path = os.path.join(self.files_dir, "contracts", f"{contract_id}.contract")
        if os.path.exists(contract_file_path):
            try:
                with open(contract_file_path, 'rb') as f:
                    return f.read()
            except Exception:
                return None
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT contract_content FROM contracts WHERE contract_id = ?', (contract_id,))
            row = cursor.fetchone()
            if row and row[0]:
                try:
                    return base64.b64decode(row[0])
                except Exception:
                    return None
        return None

    def remove_usage_contract_for_user(self, username: str) -> None:
        if not username:
            return
        contract_ids = []
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT contract_id FROM contracts WHERE username = ? AND action_type = ?', (username, "accept_usage"))
            contract_ids = [row[0] for row in cursor.fetchall()]
            cursor.execute('DELETE FROM contracts WHERE username = ? AND action_type = ?', (username, "accept_usage"))
            cursor.execute('DELETE FROM usage_contract_acceptance WHERE username = ?', (username,))
            conn.commit()
        for contract_id in contract_ids:
            contract_file_path = os.path.join(self.files_dir, "contracts", f"{contract_id}.contract")
            if os.path.exists(contract_file_path):
                try:
                    os.remove(contract_file_path)
                except Exception as e:
                    logger.warning(f"Failed to remove contract file {contract_id}: {e}")

    def validate_usage_contract_for_login(self, username: str) -> bool:
        stored_key = self.get_registered_public_key(username)
        if not stored_key:
            return False
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT contract_content, signature FROM contracts
                              WHERE username = ? AND action_type = ?
                              ORDER BY timestamp DESC LIMIT 1''', (username, "accept_usage"))
            row = cursor.fetchone()
            if not row or not row[0]:
                return False
            contract_content = base64.b64decode(row[0])
            signature = row[1]
        return self.verify_contract_signature(
            contract_content=contract_content,
            username=username,
            signature=signature,
            public_key_pem=stored_key
        )

    def verify_contract_signature(self, contract_id: str = None, contract_content: bytes = None, 
                                  username: str = None, signature: str = None,
                                  public_key_pem: Optional[str] = None) -> bool:
        """Verifica a assinatura de um contrato"""
        try:
            if contract_id and not contract_content:
                with get_db_conn(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT contract_content, username, signature FROM contracts WHERE contract_id = ?', 
                                  (contract_id,))
                    row = cursor.fetchone()
                    if not row:
                        return False
                    contract_content = base64.b64decode(row[0])
                    username = row[1]
                    signature = row[2]
            
            if not contract_content or not username or not signature:
                return False
            
            contract_text = contract_content.decode('utf-8')
            
            # Remove a linha da assinatura para verificação
            lines = contract_text.splitlines()
            signed_content = []
            for line in lines:
                if not line.strip().startswith("# SIGNATURE:"):
                    signed_content.append(line)
            
            signed_text = '\n'.join(signed_content)
            
            # Obtém chave pública do usuário
            if not public_key_pem:
                stored_key = self.get_registered_public_key(username)
                if stored_key:
                    public_key_pem = stored_key
                else:
                    return False
            
            # Verifica assinatura
            public_key = self.load_public_key_from_value(public_key_pem)
            if not public_key:
                return False
            signature_bytes = base64.b64decode(signature)
            
            public_key.verify(
                signature_bytes,
                signed_text.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except InvalidSignature:
            logger.warning(f"Assinatura inválida para contrato {contract_id or 'desconhecido'}")
            return False
        except Exception as e:
            logger.error(f"Erro ao verificar assinatura do contrato: {e}")
            return False

    def save_contract(self, action_type: str, content_hash: str = None, domain: str = None, 
                     username: str = None, signature: str = None, contract_content: bytes = None,
                     conn: sqlite3.Connection = None) -> str:
        """Salva um contrato no banco de dados"""
        contract_id = str(uuid.uuid4())
        
        # Verifica se já existe contrato para este conteúdo/domínio
        if conn:
            cursor = conn.cursor()
            if content_hash:
                cursor.execute('SELECT contract_id FROM contracts WHERE content_hash = ? AND action_type = ?',
                              (content_hash, action_type))
            elif domain:
                cursor.execute('SELECT contract_id FROM contracts WHERE domain = ? AND action_type = ?',
                              (domain, action_type))
            else:
                cursor.execute('SELECT contract_id FROM contracts WHERE username = ? AND action_type = ? AND timestamp > ?',
                              (username, action_type, time.time() - 3600))
            
            existing = cursor.fetchone()
            if existing:
                contract_id = existing[0]
            
            public_key_pem = None
            cursor.execute('SELECT public_key FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            if row:
                public_key_pem = row[0]
            verified = self.verify_contract_signature(
                contract_content=contract_content,
                username=username,
                signature=signature,
                public_key_pem=public_key_pem
            )
            
            cursor.execute('''INSERT OR REPLACE INTO contracts 
                (contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (contract_id, action_type, content_hash, domain, username, signature, 
                 time.time(), 1 if verified else 0, base64.b64encode(contract_content).decode('utf-8')))
        else:
            with get_db_conn(self.db_path) as local_conn:
                cursor = local_conn.cursor()
                if content_hash:
                    cursor.execute('SELECT contract_id FROM contracts WHERE content_hash = ? AND action_type = ?',
                                  (content_hash, action_type))
                elif domain:
                    cursor.execute('SELECT contract_id FROM contracts WHERE domain = ? AND action_type = ?',
                                  (domain, action_type))
                else:
                    cursor.execute('SELECT contract_id FROM contracts WHERE username = ? AND action_type = ? AND timestamp > ?',
                                  (username, action_type, time.time() - 3600))
                
                existing = cursor.fetchone()
                if existing:
                    contract_id = existing[0]
                
                public_key_pem = None
                cursor.execute('SELECT public_key FROM users WHERE username = ?', (username,))
                row = cursor.fetchone()
                if row:
                    public_key_pem = row[0]
                verified = self.verify_contract_signature(
                    contract_content=contract_content,
                    username=username,
                    signature=signature,
                    public_key_pem=public_key_pem
                )
                
                cursor.execute('''INSERT OR REPLACE INTO contracts 
                    (contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (contract_id, action_type, content_hash, domain, username, signature, 
                     time.time(), 1 if verified else 0, base64.b64encode(contract_content).decode('utf-8')))

        if verified and contract_content:
            target_type = "domain" if domain else "content"
            target_id = domain or content_hash
            if target_id:
                self.save_contract_archive(target_type, target_id, contract_content, conn=conn)
        
        # Salva arquivo de contrato
        contract_dir = os.path.join(self.files_dir, "contracts")
        os.makedirs(contract_dir, exist_ok=True)
        contract_file = os.path.join(contract_dir, f"{contract_id}.contract")
        
        with open(contract_file, 'wb') as f:
            f.write(contract_content)
        
        logger.info(f"Contrato salvo: {contract_id} - Ação: {action_type} - Verificado: {verified}")
        return contract_id

    def get_contracts_for_content(self, content_hash: str) -> List[Dict]:
        """Obtém todos os contratos para um conteúdo específico"""
        violation_actions = []
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT contract_id, action_type, domain, username, signature, 
                                     timestamp, verified, contract_content
                              FROM contracts WHERE content_hash = ? ORDER BY timestamp DESC''',
                          (content_hash,))
            rows = cursor.fetchall()
            
            contracts = []
            for row in rows:
                contract_id = row[0]
                contract_file_path = os.path.join(self.files_dir, "contracts", f"{contract_id}.contract")
                contract_bytes = None
                contract_text = None
                verified = bool(row[6])
                contract_info = {}
                if os.path.exists(contract_file_path):
                    try:
                        with open(contract_file_path, 'rb') as f:
                            contract_bytes = f.read()
                        contract_text = contract_bytes.decode('utf-8', errors='replace')
                    except Exception:
                        contract_bytes = None
                if contract_bytes is None and row[7]:
                    try:
                        contract_bytes = base64.b64decode(row[7])
                        contract_text = contract_bytes.decode('utf-8', errors='replace')
                    except Exception:
                        contract_bytes = None
                        contract_text = None
                if contract_bytes:
                    valid, _, contract_info = self.validate_contract_structure(contract_bytes)
                    if valid:
                        public_key_pem = self.extract_contract_detail(contract_info, "PUBLIC_KEY")
                        if not public_key_pem:
                            cursor.execute('SELECT public_key FROM users WHERE username = ?', (contract_info['user'],))
                            row_key = cursor.fetchone()
                            if row_key:
                                public_key_pem = row_key[0]
                        verified = self.verify_contract_signature(
                            contract_content=contract_bytes,
                            username=contract_info['user'],
                            signature=contract_info['signature'],
                            public_key_pem=public_key_pem
                        )
                        if not verified:
                            violation_actions.append(("register", "content", content_hash, None, "invalid_signature"))
                        else:
                            violation_actions.append(("clear", "content", content_hash, None, None))
                            self.save_contract_archive("content", content_hash, contract_bytes, conn=conn)
                    else:
                        verified = False
                        violation_actions.append(("register", "content", content_hash, None, "invalid_contract"))
                    cursor.execute('''UPDATE contracts SET contract_content = ?, verified = ?, username = ?, signature = ?
                                      WHERE contract_id = ?''',
                                   (base64.b64encode(contract_bytes).decode('utf-8'),
                                    1 if verified else 0,
                                    contract_info.get('user', row[3]),
                                    contract_info.get('signature', row[4]),
                                    contract_id))
                contracts.append({
                    'contract_id': contract_id,
                    'action_type': row[1],
                    'domain': row[2],
                    'username': row[3],
                    'signature': row[4],
                    'timestamp': row[5],
                    'verified': bool(verified),
                    'integrity_ok': bool(verified),
                    'contract_content': contract_text
                })
            
            result_contracts = contracts
        for action, vtype, c_hash, v_domain, reason in violation_actions:
            if action == "register":
                self.register_contract_violation(vtype, content_hash=c_hash, domain=v_domain, reason=reason)
            else:
                self.clear_contract_violation(vtype, content_hash=c_hash, domain=v_domain)
        return result_contracts

    def get_contracts_for_domain(self, domain: str) -> List[Dict]:
        """Obtém todos os contratos para um domínio específico"""
        violation_actions = []
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT contract_id, action_type, content_hash, username, signature, 
                                     timestamp, verified, contract_content
                              FROM contracts WHERE domain = ? ORDER BY timestamp DESC''',
                          (domain,))
            rows = cursor.fetchall()
            
            contracts = []
            for row in rows:
                contract_id = row[0]
                contract_file_path = os.path.join(self.files_dir, "contracts", f"{contract_id}.contract")
                contract_bytes = None
                contract_text = None
                verified = bool(row[6])
                contract_info = {}
                if os.path.exists(contract_file_path):
                    try:
                        with open(contract_file_path, 'rb') as f:
                            contract_bytes = f.read()
                        contract_text = contract_bytes.decode('utf-8', errors='replace')
                    except Exception:
                        contract_bytes = None
                if contract_bytes is None and row[7]:
                    try:
                        contract_bytes = base64.b64decode(row[7])
                        contract_text = contract_bytes.decode('utf-8', errors='replace')
                    except Exception:
                        contract_bytes = None
                        contract_text = None
                if contract_bytes:
                    valid, _, contract_info = self.validate_contract_structure(contract_bytes)
                    if valid:
                        public_key_pem = self.extract_contract_detail(contract_info, "PUBLIC_KEY")
                        if not public_key_pem:
                            cursor.execute('SELECT public_key FROM users WHERE username = ?', (contract_info['user'],))
                            row_key = cursor.fetchone()
                            if row_key:
                                public_key_pem = row_key[0]
                        verified = self.verify_contract_signature(
                            contract_content=contract_bytes,
                            username=contract_info['user'],
                            signature=contract_info['signature'],
                            public_key_pem=public_key_pem
                        )
                        if not verified:
                            violation_actions.append(("register", "domain", None, domain, "invalid_signature"))
                        else:
                            violation_actions.append(("clear", "domain", None, domain, None))
                            self.save_contract_archive("domain", domain, contract_bytes, conn=conn)
                    else:
                        verified = False
                        violation_actions.append(("register", "domain", None, domain, "invalid_contract"))
                    cursor.execute('''UPDATE contracts SET contract_content = ?, verified = ?, username = ?, signature = ?
                                      WHERE contract_id = ?''',
                                   (base64.b64encode(contract_bytes).decode('utf-8'),
                                    1 if verified else 0,
                                    contract_info.get('user', row[3]),
                                    contract_info.get('signature', row[4]),
                                    contract_id))
                contracts.append({
                    'contract_id': contract_id,
                    'action_type': row[1],
                    'content_hash': row[2],
                    'username': row[3],
                    'signature': row[4],
                    'timestamp': row[5],
                    'verified': bool(verified),
                    'integrity_ok': bool(verified),
                    'contract_content': contract_text
                })
            
            result_contracts = contracts
        for action, vtype, c_hash, v_domain, reason in violation_actions:
            if action == "register":
                self.register_contract_violation(vtype, content_hash=c_hash, domain=v_domain, reason=reason)
            else:
                self.clear_contract_violation(vtype, content_hash=c_hash, domain=v_domain)
        return result_contracts

    def get_contract_violation(self, violation_type: str, content_hash: str = None, domain: str = None) -> Optional[Dict]:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT violation_id, owner_username, reported_by, timestamp, reason
                              FROM contract_violations
                              WHERE violation_type = ? AND content_hash IS ? AND domain IS ?''',
                           (violation_type, content_hash, domain))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                'violation_id': row[0],
                'owner_username': row[1],
                'reported_by': row[2],
                'timestamp': row[3],
                'reason': row[4]
            }

    def update_contract_violation_reason(self, violation_id: str, reason: str) -> None:
        if not violation_id or not reason:
            return
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''UPDATE contract_violations SET reason = ?, timestamp = ? WHERE violation_id = ?''',
                           (reason, time.time(), violation_id))
            conn.commit()

    def sync_contract_violation_reason(self, violation_type: str, reason: str,
                                       content_hash: str = None, domain: str = None) -> Optional[Dict]:
        violation = self.get_contract_violation(violation_type, content_hash=content_hash, domain=domain)
        if violation:
            if violation.get('reason') != reason:
                self.update_contract_violation_reason(violation['violation_id'], reason)
                self.emit_contract_violation_notice(
                    violation_type,
                    violation['owner_username'],
                    content_hash=content_hash,
                    domain=domain,
                    reason=reason
                )
                violation = dict(violation)
                violation['reason'] = reason
            return violation
        self.register_contract_violation(
            violation_type,
            content_hash=content_hash,
            domain=domain,
            reason=reason
        )
        return self.get_contract_violation(violation_type, content_hash=content_hash, domain=domain)

    def save_contract_archive(self, target_type: str, target_id: str, contract_content: bytes,
                              conn: sqlite3.Connection = None) -> None:
        if not target_type or not target_id or not contract_content:
            return
        if conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT OR REPLACE INTO contract_valid_archive
                              (archive_id, target_type, target_id, contract_content, updated_at)
                              VALUES (?, ?, ?, ?, ?)''',
                           (str(uuid.uuid4()), target_type, target_id,
                            base64.b64encode(contract_content).decode('utf-8'), time.time()))
            return
        with get_db_conn(self.db_path) as db_conn:
            cursor = db_conn.cursor()
            cursor.execute('''INSERT OR REPLACE INTO contract_valid_archive
                              (archive_id, target_type, target_id, contract_content, updated_at)
                              VALUES (?, ?, ?, ?, ?)''',
                           (str(uuid.uuid4()), target_type, target_id,
                            base64.b64encode(contract_content).decode('utf-8'), time.time()))

    def get_contract_archive(self, target_type: str, target_id: str) -> Optional[bytes]:
        if not target_type or not target_id:
            return None
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT contract_content FROM contract_valid_archive
                              WHERE target_type = ? AND target_id = ?''',
                           (target_type, target_id))
            row = cursor.fetchone()
        if not row or not row[0]:
            return None
        try:
            return base64.b64decode(row[0])
        except Exception:
            return None

    def delete_contract_archive(self, target_type: str, target_id: str) -> None:
        if not target_type or not target_id:
            return
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM contract_valid_archive WHERE target_type = ? AND target_id = ?',
                           (target_type, target_id))
            conn.commit()

    def emit_contract_violation_notice(self, violation_type: str, owner_username: str,
                                       content_hash: str = None, domain: str = None,
                                       reason: str = "invalid_contract") -> None:
        if not owner_username:
            return
        payload = {
            'violation_type': violation_type,
            'content_hash': content_hash,
            'domain': domain,
            'reason': reason
        }
        logger.info(f"Enviando aviso de violacao para {owner_username}: {payload}")
        for sid, client in self.connected_clients.items():
            if client.get('username') == owner_username:
                logger.info(f"Aviso de violacao enviado para SID {sid}")
                asyncio.run_coroutine_threadsafe(
                    self.sio.emit('contract_violation_notice', payload, room=sid),
                    self.loop
                )

    def emit_contract_violation_cleared(self, violation_type: str, owner_username: str,
                                        content_hash: str = None, domain: str = None) -> None:
        if not owner_username:
            return
        payload = {
            'violation_type': violation_type,
            'content_hash': content_hash,
            'domain': domain
        }
        for sid, client in self.connected_clients.items():
            if client.get('username') == owner_username:
                asyncio.run_coroutine_threadsafe(
                    self.sio.emit('contract_violation_cleared', payload, room=sid),
                    self.loop
                )

    def register_contract_violation(self, violation_type: str, reported_by: str = "system",
                                    content_hash: str = None, domain: str = None,
                                    reason: str = "missing_contract", apply_penalty: bool = True) -> Optional[str]:
        existing = self.get_contract_violation(violation_type, content_hash=content_hash, domain=domain)
        if existing:
            if reason == "missing_contract" and existing.get('reason') != reason:
                self.update_contract_violation_reason(existing['violation_id'], reason)
                existing = dict(existing)
                existing['reason'] = reason
            app_name = None
            if content_hash:
                with get_db_conn(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT app_name FROM api_apps WHERE content_hash = ?', (content_hash,))
                    row = cursor.fetchone()
                    if row:
                        app_name = row[0]
            self.emit_contract_violation_notice(
                violation_type,
                existing['owner_username'],
                content_hash=content_hash,
                domain=domain,
                reason=existing['reason']
            )
            original_owner = self.resolve_original_owner(content_hash, domain, app_name)
            if original_owner and original_owner != existing['owner_username']:
                self.emit_contract_violation_notice(
                    violation_type,
                    original_owner,
                    content_hash=content_hash,
                    domain=domain,
                    reason=existing['reason']
                )
            return existing['violation_id']
        owner_username = None
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            if violation_type == "content" and content_hash:
                cursor.execute('SELECT username FROM content WHERE content_hash = ?', (content_hash,))
                row = cursor.fetchone()
                owner_username = row[0] if row else None
            elif violation_type == "domain" and domain:
                cursor.execute('SELECT username FROM dns_records WHERE domain = ?', (domain,))
                row = cursor.fetchone()
                owner_username = row[0] if row else None
            elif violation_type == "voucher" and content_hash:
                cursor.execute('SELECT owner FROM hps_vouchers WHERE voucher_id = ?', (content_hash,))
                row = cursor.fetchone()
                owner_username = row[0] if row else None

            app_name = None
            if content_hash:
                cursor.execute('SELECT app_name FROM api_apps WHERE content_hash = ?', (content_hash,))
                row = cursor.fetchone()
                if row:
                    app_name = row[0]
            if not owner_username or owner_username in (CUSTODY_USERNAME, "system"):
                owner_username = self.resolve_original_owner(content_hash, domain, app_name)
            if not owner_username:
                owner_username = self.extract_contract_owner_from_db(content_hash, domain)
            if not owner_username:
                return None

            violation_id = str(uuid.uuid4())
            try:
                cursor.execute('''INSERT INTO contract_violations
                                  (violation_id, violation_type, content_hash, domain, owner_username, reported_by, timestamp, reason)
                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                               (violation_id, violation_type, content_hash, domain, owner_username,
                                reported_by, time.time(), reason))
            except sqlite3.IntegrityError:
                return None

            if apply_penalty:
                cursor.execute('SELECT reputation, contract_penalty_base FROM user_reputations WHERE username = ?',
                               (owner_username,))
                rep_row = cursor.fetchone()
                if rep_row:
                    current_rep, base_rep = rep_row[0], rep_row[1]
                else:
                    cursor.execute('SELECT reputation FROM users WHERE username = ?', (owner_username,))
                    rep_value = cursor.fetchone()
                    current_rep = rep_value[0] if rep_value else 100
                    base_rep = None
                    cursor.execute('''INSERT OR IGNORE INTO user_reputations
                                      (username, reputation, last_updated, client_identifier, violation_count, contract_penalty_base)
                                      VALUES (?, ?, ?, ?, ?, ?)''',
                                   (owner_username, current_rep, time.time(), "", 0, None))
                if base_rep is None:
                    cursor.execute('UPDATE user_reputations SET contract_penalty_base = ? WHERE username = ?',
                                   (current_rep, owner_username))
                cursor.execute('UPDATE user_reputations SET reputation = MAX(1, reputation - 30), last_updated = ? WHERE username = ?',
                               (time.time(), owner_username))
                cursor.execute('UPDATE users SET reputation = MAX(1, reputation - 30) WHERE username = ?',
                               (owner_username,))
            conn.commit()

        for sid, client in self.connected_clients.items():
            if client.get('username') == owner_username:
                asyncio.run_coroutine_threadsafe(
                    self.sio.emit('reputation_update', {'reputation': self.get_user_reputation(owner_username)}, room=sid),
                    self.loop
                )
                self.emit_contract_violation_notice(
                    violation_type,
                    owner_username,
                    content_hash=content_hash,
                    domain=domain,
                    reason=reason
                )
        app_name = None
        if content_hash:
            with get_db_conn(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT app_name FROM api_apps WHERE content_hash = ?', (content_hash,))
                row = cursor.fetchone()
                if row:
                    app_name = row[0]
        original_owner = self.resolve_original_owner(content_hash, domain, app_name)
        if original_owner and original_owner != owner_username:
            self.emit_contract_violation_notice(
                violation_type,
                original_owner,
                content_hash=content_hash,
                domain=domain,
                reason=reason
            )
        logger.warning(f"Contrato ausente reportado: {violation_type} - owner={owner_username} - reason={reason}")
        return violation_id

    def clear_contract_violation(self, violation_type: str, content_hash: str = None, domain: str = None) -> None:
        owner_username = None
        app_name = None
        restored_reputation = None
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT owner_username
                              FROM contract_violations
                              WHERE violation_type = ? AND content_hash IS ? AND domain IS ?''',
                           (violation_type, content_hash, domain))
            row = cursor.fetchone()
            if row:
                owner_username = row[0]
            cursor.execute('''DELETE FROM contract_violations
                              WHERE violation_type = ? AND content_hash IS ? AND domain IS ?''',
                           (violation_type, content_hash, domain))
            if owner_username:
                cursor.execute('SELECT COUNT(*) FROM contract_violations WHERE owner_username = ?', (owner_username,))
                remaining = cursor.fetchone()[0]
                if remaining == 0:
                    cursor.execute('SELECT reputation, contract_penalty_base FROM user_reputations WHERE username = ?',
                                   (owner_username,))
                    rep_row = cursor.fetchone()
                    if rep_row and rep_row[1] is not None:
                        current_rep, base_rep = rep_row[0], rep_row[1]
                        restore_target = min(100, base_rep + 20)
                        restored_reputation = max(current_rep or 0, restore_target)
                        cursor.execute('''UPDATE user_reputations
                                          SET reputation = ?, contract_penalty_base = NULL, last_updated = ?
                                          WHERE username = ?''',
                                       (restored_reputation, time.time(), owner_username))
                        cursor.execute('UPDATE users SET reputation = ? WHERE username = ?',
                                       (restored_reputation, owner_username))
            conn.commit()
        if content_hash:
            with get_db_conn(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT app_name FROM api_apps WHERE content_hash = ?', (content_hash,))
                row = cursor.fetchone()
                if row:
                    app_name = row[0]
        if owner_username:
            self.emit_contract_violation_cleared(
                violation_type,
                owner_username,
                content_hash=content_hash,
                domain=domain
            )
            if restored_reputation is not None:
                for sid, client in self.connected_clients.items():
                    if client.get('username') == owner_username:
                        asyncio.run_coroutine_threadsafe(
                            self.sio.emit('reputation_update', {'reputation': restored_reputation}, room=sid),
                            self.loop
                        )
        original_owner = self.resolve_original_owner(content_hash, domain, app_name)
        if original_owner and original_owner != owner_username:
            self.emit_contract_violation_cleared(
                violation_type,
                original_owner,
                content_hash=content_hash,
                domain=domain
            )

    def evaluate_contract_violation_for_content(self, content_hash: str) -> Tuple[bool, str, List[Dict]]:
        contracts = self.get_contracts_for_content(content_hash)
        violation = self.get_contract_violation("content", content_hash=content_hash)
        invalid_contracts = [c for c in contracts if not c.get('verified', False)]
        if not contracts:
            violation = self.sync_contract_violation_reason(
                "content",
                "missing_contract",
                content_hash=content_hash
            )
            violation_reason = "missing_contract"
        elif invalid_contracts:
            desired_reason = "invalid_contract"
            if violation and violation.get('reason') == "invalid_signature":
                desired_reason = "invalid_signature"
            violation = self.sync_contract_violation_reason(
                "content",
                desired_reason,
                content_hash=content_hash
            )
            violation_reason = desired_reason
        elif violation:
            violation_reason = violation['reason']
        else:
            violation_reason = ""
        contract_violation = bool(violation or not contracts or invalid_contracts)
        return contract_violation, violation_reason, contracts

    def evaluate_contract_violation_for_domain(self, domain: str) -> Tuple[bool, str, List[Dict]]:
        contracts = self.get_contracts_for_domain(domain)
        violation = self.get_contract_violation("domain", domain=domain)
        invalid_contracts = [c for c in contracts if not c.get('verified', False)]
        if not contracts:
            violation = self.sync_contract_violation_reason(
                "domain",
                "missing_contract",
                domain=domain
            )
            violation_reason = "missing_contract"
        elif invalid_contracts:
            desired_reason = "invalid_contract"
            if violation and violation.get('reason') == "invalid_signature":
                desired_reason = "invalid_signature"
            violation = self.sync_contract_violation_reason(
                "domain",
                desired_reason,
                domain=domain
            )
            violation_reason = desired_reason
        elif violation:
            violation_reason = violation['reason']
        else:
            violation_reason = ""
        contract_violation = bool(violation or not contracts or invalid_contracts)
        return contract_violation, violation_reason, contracts

    def evaluate_contract_violation_for_domain(self, domain: str) -> Tuple[bool, str, List[Dict]]:
        contracts = self.get_contracts_for_domain(domain)
        violation = self.get_contract_violation("domain", domain=domain)
        invalid_contracts = [c for c in contracts if not c.get('verified', False)]
        if invalid_contracts and not violation:
            self.register_contract_violation("domain", domain=domain, reason="invalid_contract")
            violation = self.get_contract_violation("domain", domain=domain)
        contract_violation = bool(violation or not contracts or invalid_contracts)
        if violation:
            violation_reason = violation['reason']
        elif not contracts:
            violation_reason = "missing_contract"
            self.register_contract_violation("domain", domain=domain, reason="missing_contract")
        elif invalid_contracts:
            violation_reason = "invalid_contract"
        else:
            violation_reason = ""
        return contract_violation, violation_reason, contracts

    def get_contract_certification(self, target_type: str, target_id: str) -> Optional[Dict]:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT original_owner, certifier, timestamp
                              FROM contract_certifications WHERE target_type = ? AND target_id = ?''',
                           (target_type, target_id))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                'original_owner': row[0],
                'certifier': row[1],
                'timestamp': row[2]
            }

    def set_contract_certification(self, target_type: str, target_id: str,
                                   original_owner: str, certifier: str) -> None:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''INSERT OR REPLACE INTO contract_certifications
                              (cert_id, target_type, target_id, original_owner, certifier, timestamp)
                              VALUES (?, ?, ?, ?, ?, ?)''',
                           (str(uuid.uuid4()), target_type, target_id, original_owner, certifier, time.time()))
            conn.commit()

    def clear_contract_certification(self, target_type: str, target_id: str) -> None:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''DELETE FROM contract_certifications WHERE target_type = ? AND target_id = ?''',
                           (target_type, target_id))
            conn.commit()

    def get_api_app_versions_from_contracts(self, title: str, app_name: Optional[str]) -> List[Dict]:
        title_match = title.strip().lower() if title else ""
        app_match = app_name.strip().lower() if app_name else ""
        versions = []
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT contract_id, action_type, content_hash, username, timestamp, contract_content
                              FROM contracts ORDER BY timestamp ASC''')
            rows = cursor.fetchall()
        for row in rows:
            contract_id, action_type, content_hash, username, timestamp, contract_b64 = row
            if not contract_b64:
                continue
            try:
                contract_text = base64.b64decode(contract_b64).decode('utf-8', errors='replace')
            except Exception:
                continue
            if title_match and f"# title: {title_match}" in contract_text.lower():
                matched = True
            elif app_match and f"# app: {app_match}" in contract_text.lower():
                matched = True
            else:
                matched = False
            if not matched:
                continue
            versions.append({
                'contract_id': contract_id,
                'action_type': action_type,
                'content_hash': content_hash,
                'username': username,
                'timestamp': timestamp
            })
        return versions

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
                # Atualiza registros DNS que apontam para o app antigo
                cursor.execute('UPDATE dns_records SET content_hash = ? WHERE content_hash = ?', (content_hash, old_hash))

                # Cria registro de redirecionamento
                cursor.execute('INSERT OR REPLACE INTO content_redirects (old_hash, new_hash, username, redirect_type, timestamp) VALUES (?, ?, ?, ?, ?)',
                               (old_hash, content_hash, username, 'app_update', time.time()))

                # Mantém conteúdo antigo como legado para acesso explícito

                # Atualiza app
                cursor.execute('UPDATE api_apps SET content_hash = ?, last_updated = ? WHERE app_name = ?',
                               (content_hash, time.time(), app_name))

                # Registra versão
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
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT new_hash FROM content_redirects WHERE old_hash = ?', (old_hash,))
            row = cursor.fetchone()
            if row:
                return row[0]
        return None

    def invalidate_content(self, content_hash: str, keep_violation: bool = False) -> None:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM contracts WHERE content_hash = ?', (content_hash,))
            conn.commit()
        if not keep_violation:
            self.clear_contract_violation("content", content_hash=content_hash)
        self.clear_contract_certification("content", content_hash)
        self.delete_contract_archive("content", content_hash)

    def invalidate_domain(self, domain: str, keep_violation: bool = False) -> None:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM contracts WHERE domain = ?', (domain,))
            conn.commit()
        if not keep_violation:
            self.clear_contract_violation("domain", domain=domain)
        self.clear_contract_certification("domain", domain)
        self.delete_contract_archive("domain", domain)

    def remove_invalid_contracts(self, content_hash: Optional[str], domain: Optional[str]) -> None:
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            if domain:
                cursor.execute('SELECT contract_id FROM contracts WHERE domain = ? AND verified = 0', (domain,))
            else:
                cursor.execute('SELECT contract_id FROM contracts WHERE content_hash = ? AND verified = 0', (content_hash,))
            rows = cursor.fetchall()
            contract_ids = [row[0] for row in rows]
            if domain:
                cursor.execute('DELETE FROM contracts WHERE domain = ? AND verified = 0', (domain,))
            else:
                cursor.execute('DELETE FROM contracts WHERE content_hash = ? AND verified = 0', (content_hash,))
            conn.commit()
        for contract_id in contract_ids:
            contract_file_path = os.path.join(self.files_dir, "contracts", f"{contract_id}.contract")
            if os.path.exists(contract_file_path):
                try:
                    os.remove(contract_file_path)
                except Exception as e:
                    logger.warning(f"Failed to remove contract file {contract_id}: {e}")

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
                    try:
                        await self.sio.emit('economy_report', self.build_economy_report(), room=sid)
                    except Exception:
                        pass
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
                if action_type == "hps_mint":
                    username = self.connected_clients[sid].get('username', '')
                    if self.is_miner_banned(username):
                        await self.sio.emit('pow_challenge', {'error': 'Miner banned from minting'}, room=sid)
                        return
                self.connected_clients[sid]['client_identifier'] = client_identifier
                allowed, message, remaining_time = self.check_rate_limit(client_identifier, action_type)
                if not allowed:
                    await self.sio.emit('pow_challenge', {'error': message, 'blocked_until': time.time() + remaining_time}, room=sid)
                    return
                challenge_data = self.generate_pow_challenge(client_identifier, action_type)
                if action_type == "hps_mint":
                    username = self.connected_clients[sid].get('username', '')
                    debt_status = self.safe_get_miner_debt_status(username)
                    challenge_data["debt_status"] = debt_status
                    pending_signatures = int(debt_status.get("pending_signatures", 0))
                    pending_fines = int(debt_status.get("pending_fines", 0))
                    pending_delay_fines = int(debt_status.get("pending_delay_fines", 0))
                    fine_grace = int(debt_status.get("fine_grace", 2))
                    promise_active = int(debt_status.get("promise_active", 0))
                    suspended = pending_signatures >= int(debt_status.get("debt_limit", 0))
                    if not promise_active and pending_fines > fine_grace:
                        suspended = True
                    if pending_delay_fines > 0:
                        suspended = True
                    if suspended:
                        challenge_data["minting_withheld"] = True
                    next_pending = debt_status.get("next_pending", debt_status.get("pending_signatures", 0))
                    next_pending_fines = debt_status.get("next_pending_fines", debt_status.get("pending_fines", 0))
                    if (
                        (next_pending >= debt_status.get("debt_limit", 0) and pending_signatures < debt_status.get("debt_limit", 0))
                        or (not promise_active and next_pending_fines > fine_grace and pending_fines <= fine_grace)
                    ):
                        challenge_data["debt_warning"] = True
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
                if username.lower() == CUSTODY_USERNAME:
                    await self.sio.emit('authentication_result', {
                        'success': False,
                        'error': 'O nome de usuário "custody" é de uso especial para a administração do servidor.'
                    }, room=sid)
                    return
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
                if self.user_needs_usage_contract(username):
                    await self.sio.emit('authentication_result', {'success': False, 'error': 'Usage contract required'}, room=sid)
                    return
                with get_db_conn(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT password_hash, public_key, reputation FROM users WHERE username = ?', (username,))
                    row = cursor.fetchone()
                    reputation = 100
                    if row:
                        stored_hash, stored_key, rep = row
                        reputation = rep
                        if self.owner_enabled and username == self.owner_username:
                            if self.owner_password_hash and stored_hash != self.owner_password_hash:
                                await self.sio.emit('authentication_result', {'success': False, 'error': 'Senha do owner invalida'}, room=sid)
                                return
                            if stored_key == PENDING_PUBLIC_KEY:
                                cursor.execute('UPDATE users SET public_key = ? WHERE username = ?', (public_key_b64, username))
                                conn.commit()
                                stored_key = public_key_b64
                        if stored_hash == password_hash:
                            if stored_key and stored_key != public_key_b64:
                                self.remove_usage_contract_for_user(username)
                                await self.sio.emit('authentication_result', {
                                    'success': False,
                                    'error': 'Chave Pública inválida, utilize sua chave pública inicial na aba de configurações'
                                }, room=sid)
                                return
                            if not self.validate_usage_contract_for_login(username):
                                self.remove_usage_contract_for_user(username)
                                await self.sio.emit('authentication_result', {
                                    'success': False,
                                    'error': 'Chave Pública inválida, utilize sua chave pública inicial na aba de configurações'
                                }, room=sid)
                                return
                            cursor.execute('UPDATE users SET last_login = ?, client_identifier = ?, last_activity = ? WHERE username = ?',
                                           (time.time(), client_identifier, time.time(), username))
                            conn.commit()
                            await self.finalize_authentication(sid, username, public_key_b64, node_type, client_identifier, reputation)
                        else:
                            await self.sio.emit('authentication_result', {'success': False, 'error': 'Invalid password'}, room=sid)
                            violation_count = self.increment_violation(client_identifier)
                            if violation_count >= 3:
                                await self.ban_client(client_identifier, duration=300, reason="Multiple invalid passwords")
                    else:
                        cursor.execute('SELECT reputation FROM user_reputations WHERE client_identifier = ?', (client_identifier,))
                        rep_row = cursor.fetchone()
                        if rep_row:
                            reputation = rep_row[0]
                        else:
                            reputation = 100
                        if self.owner_enabled and username == self.owner_username:
                            if not self.owner_password_hash or password_hash != self.owner_password_hash:
                                await self.sio.emit('authentication_result', {'success': False, 'error': 'Senha do owner invalida'}, room=sid)
                                return
                        cursor.execute('''INSERT INTO users
(username, password_hash, public_key, created_at, last_login, reputation, client_identifier, last_activity)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                            (username, password_hash, public_key_b64, time.time(), time.time(), reputation, client_identifier, time.time()))
                        cursor.execute('''INSERT OR REPLACE INTO user_reputations
                            (username, reputation, last_updated, client_identifier) VALUES (?, ?, ?, ?)''',
                            (username, reputation, time.time(), client_identifier))
                        conn.commit()
                        await self.finalize_authentication(sid, username, public_key_b64, node_type, client_identifier, reputation)
                self.update_rate_limit(client_identifier, "login")
            except Exception as e:
                logger.error(f"Authentication error for {sid}: {e}")
                await self.sio.emit('authentication_result', {'success': False, 'error': f'Internal server error: {str(e)}'}, room=sid)

        @self.sio.event
        async def request_hps_wallet(sid, data):
            try:
                if not self.connected_clients[sid].get('authenticated'):
                    await self.sio.emit('hps_wallet_sync', {'error': 'Not authenticated'}, room=sid)
                    return
                username = self.connected_clients[sid]['username']
                vouchers = self.list_user_vouchers(username)
                await self.sio.emit('hps_wallet_sync', {'vouchers': vouchers}, room=sid)
                await self.send_pending_voucher_offers(username, sid)
            except Exception as e:
                logger.error(f"HPS wallet sync error for {sid}: {e}")
                await self.sio.emit('hps_wallet_sync', {'error': str(e)}, room=sid)

        @self.sio.event
        async def mint_hps_voucher(sid, data):
            try:
                client_info = self.connected_clients.get(sid)
                if not client_info or not client_info.get('authenticated'):
                    await self.sio.emit('hps_voucher_error', {'error': 'Not authenticated'}, room=sid)
                    return
                client_identifier = client_info.get('client_identifier')
                username = client_info.get('username')
                if self.is_miner_banned(username):
                    await self.sio.emit('hps_voucher_error', {'error': 'Miner banned from minting'}, room=sid)
                    return
                suspended, debt_status = self.is_miner_minting_suspended(username)
                pow_nonce = data.get('pow_nonce', '')
                hashrate_observed = data.get('hashrate_observed', 0.0)
                reason = data.get('reason', 'mining')
                contract_content_b64 = data.get('contract_content')
                valid, pow_info = self.verify_pow_solution_details(client_identifier, pow_nonce, hashrate_observed, "hps_mint")
                if not valid or not pow_info:
                    await self.sio.emit('hps_voucher_error', {'error': 'Invalid PoW solution'}, room=sid)
                    await self.ban_client(client_identifier, duration=300, reason="Invalid PoW solution")
                    return
                if contract_content_b64:
                    contract_content = base64.b64decode(contract_content_b64)
                    valid_contract, error_msg, contract_info = self.validate_contract_structure(contract_content)
                    if not valid_contract:
                        await self.sio.emit('hps_voucher_error', {'error': f'Invalid contract: {error_msg}'}, room=sid)
                        return
                    if contract_info['action'] != 'hps_mint':
                        await self.sio.emit('hps_voucher_error', {'error': 'Invalid contract action'}, room=sid)
                        return
                    if contract_info['user'] != username:
                        await self.sio.emit('hps_voucher_error', {'error': 'Contract user mismatch'}, room=sid)
                        return
                    if not self.verify_contract_signature(
                        contract_content=contract_content,
                        username=username,
                        signature=contract_info['signature']
                    ):
                        await self.sio.emit('hps_voucher_error', {'error': 'Invalid contract signature'}, room=sid)
                        return
                    self.save_contract(
                        action_type="hps_mint",
                        content_hash=None,
                        domain=None,
                        username=username,
                        signature=contract_info['signature'],
                        contract_content=contract_content
                    )
                self.update_rate_limit(client_identifier, "hps_mint")
                target_bits = pow_info.get("target_bits", 0)
                value = max(1, int(math.ceil(target_bits / max(1, self.hps_voucher_unit_bits))))
                value = min(value, self.hps_voucher_max_value)
                pow_info["nonce"] = pow_nonce
                voucher_id = pow_info.get("voucher_id") or str(uuid.uuid4())
                pow_info["voucher_id"] = voucher_id
                owner_key = client_info.get("public_key", "")
                stats = self.get_miner_stats(username)
                promise_active = int(stats.get("fine_promise_active", 0))
                promise_remaining = float(stats.get("fine_promise_amount", 0.0))
                if promise_active and promise_remaining > 0:
                    if value <= promise_remaining:
                        self.issue_custody_voucher(
                            value=value,
                            reason="miner_fine_promise",
                            pow_info=pow_info,
                            conditions={"type": "miner_fine_promise", "miner": username}
                        )
                        new_remaining = max(0.0, promise_remaining - value)
                        self.update_miner_stats(
                            username,
                            fine_promise_amount=new_remaining,
                            fine_promise_active=1 if new_remaining > 0 else 0
                        )
                        if new_remaining <= 0:
                            self.release_withheld_offers_for_miner(username)
                        await self.sio.emit('hps_voucher_withheld', {
                            'voucher_id': voucher_id,
                            'value': value,
                            'debt_status': self.safe_get_miner_debt_status(username),
                            'mode': 'promise'
                        }, room=sid)
                        return
                    self.issue_custody_voucher(
                        value=int(promise_remaining),
                        reason="miner_fine_promise",
                        pow_info=pow_info,
                        conditions={"type": "miner_fine_promise", "miner": username}
                    )
                    value = value - int(promise_remaining)
                    self.update_miner_stats(username, fine_promise_amount=0, fine_promise_active=0)
                    self.release_withheld_offers_for_miner(username)
                if suspended:
                    offer = self.create_voucher_offer(
                        owner=username,
                        owner_public_key=owner_key,
                        value=value,
                        reason=reason,
                        pow_info=pow_info,
                        voucher_id=voucher_id,
                        status="withheld",
                        conditions={"withheld": True}
                    )
                    await self.sio.emit('hps_voucher_withheld', {
                        'voucher_id': offer["voucher_id"],
                        'value': value,
                        'debt_status': debt_status
                    }, room=sid)
                else:
                    offer = self.create_voucher_offer(
                        owner=username,
                        owner_public_key=owner_key,
                        value=value,
                        reason=reason,
                        pow_info=pow_info,
                        voucher_id=voucher_id
                    )
                    await self.sio.emit('hps_voucher_offer', {
                        'offer_id': offer["offer_id"],
                        'voucher_id': offer["voucher_id"],
                        'payload': offer["payload"],
                        'expires_at': offer["expires_at"]
                    }, room=sid)
            except Exception as e:
                logger.error(f"HPS mint error for {sid}: {e}")
                await self.sio.emit('hps_voucher_error', {'error': str(e)}, room=sid)

        @self.sio.event
        async def confirm_hps_voucher(sid, data):
            try:
                client_info = self.connected_clients.get(sid)
                if not client_info or not client_info.get('authenticated'):
                    await self.sio.emit('hps_voucher_error', {'error': 'Not authenticated'}, room=sid)
                    return
                voucher_id = data.get('voucher_id')
                owner_signature = data.get('owner_signature', '')
                if not voucher_id or not owner_signature:
                    await self.sio.emit('hps_voucher_error', {'error': 'Missing voucher confirmation data'}, room=sid)
                    return
                voucher = self.finalize_voucher(voucher_id, owner_signature)
                if not voucher:
                    await self.sio.emit('hps_voucher_error', {'error': 'Voucher confirmation failed'}, room=sid)
                    return
                pow_action = (voucher.get("payload", {}).get("pow", {}) or {}).get("action_type", "")
                if pow_action == "hps_mint":
                    minted_value = self.parse_numeric(voucher.get("payload", {}).get("value", 0), 0.0)
                    self.increment_economy_stat("total_minted", minted_value)
                    self.record_economy_event("hps_mint")
                    self.record_economy_contract("hps_mint")
                    pending = self.increment_miner_mint(
                        voucher.get("payload", {}).get("owner", ""),
                        minted_value
                    )
                    miner_username = voucher.get("payload", {}).get("owner", "")
                    miner_info = self.authenticated_users.get(miner_username, {})
                    miner_sid = miner_info.get("sid")
                    if miner_sid:
                        debt_status = self.safe_get_miner_debt_status(miner_username)
                        await self.sio.emit('miner_signature_update', {
                            "pending_signatures": pending,
                            "debt_status": debt_status
                        }, room=miner_sid)
                    await self.send_hps_economy_status()
                    payload = voucher.get("payload", {})
                    pow_payload = payload.get("pow", {}) or {}
                    self.save_server_contract(
                        "hps_mint_receipt",
                        [
                            ("MINER", payload.get("owner", "")),
                            ("VOUCHER_ID", payload.get("voucher_id", "")),
                            ("VALUE", payload.get("value", 0)),
                            ("POW_CHALLENGE", pow_payload.get("challenge", "")),
                            ("POW_NONCE", pow_payload.get("nonce", "")),
                            ("TARGET_BITS", pow_payload.get("target_bits", 0)),
                            ("TARGET_SECONDS", pow_payload.get("target_seconds", 0)),
                            ("ACTION", pow_payload.get("action_type", ""))
                        ],
                        op_id=payload.get("voucher_id")
                    )
                transfer = self.get_transfer_by_voucher_id(voucher_id)
                if transfer and transfer.get("status") == "pending_signature":
                    self.lock_transfer_vouchers(transfer.get("transfer_id"))
                await self.sio.emit('hps_voucher_issued', {'voucher': voucher}, room=sid)
                await self.complete_hps_transfer(voucher_id)
            except Exception as e:
                logger.error(f"HPS voucher confirm error for {sid}: {e}")
                await self.sio.emit('hps_voucher_error', {'error': str(e)}, room=sid)

        @self.sio.event
        async def sign_transfer(sid, data):
            try:
                client_info = self.connected_clients.get(sid)
                if not client_info or not client_info.get('authenticated'):
                    await self.sio.emit('miner_signature_ack', {'success': False, 'error': 'Not authenticated'}, room=sid)
                    return
                username = client_info.get('username', '')
                transfer_id = data.get("transfer_id", "")
                contract_content_b64 = data.get("contract_content")
                report_content_b64 = data.get("report_content")
                if not transfer_id or not contract_content_b64 or not report_content_b64:
                    await self.sio.emit('miner_signature_ack', {'success': False, 'error': 'Missing signature data'}, room=sid)
                    return
                transfer = self.get_monetary_transfer(transfer_id)
                if not transfer:
                    await self.sio.emit('miner_signature_ack', {'success': False, 'error': 'Transfer not found'}, room=sid)
                    return
                if transfer.get("sender") == username or transfer.get("receiver") == username:
                    reassigned = self.reassign_miner_for_transfer(transfer_id, exclude_user=username)
                    if reassigned:
                        await self.sio.emit('miner_signature_ack', {
                            'success': False,
                            'error': 'Miner cannot sign own transfer; reassigned',
                            'transfer_id': transfer_id
                        }, room=sid)
                    else:
                        await self.sio.emit('miner_signature_ack', {
                            'success': False,
                            'error': 'Miner cannot sign own transfer',
                            'transfer_id': transfer_id
                        }, room=sid)
                    return
                if transfer.get("assigned_miner") and transfer.get("assigned_miner") != username:
                    await self.sio.emit('miner_signature_ack', {'success': False, 'error': 'Miner not assigned'}, room=sid)
                    return
                if transfer.get("status") == "signed":
                    await self.sio.emit('miner_signature_ack', {'success': False, 'error': 'Transfer already signed'}, room=sid)
                    return
                report_content = base64.b64decode(report_content_b64)
                valid, error_msg, report_info = self.validate_contract_structure(report_content)
                if not valid:
                    await self.sio.emit('miner_signature_ack', {'success': False, 'error': f'Invalid report: {error_msg}'}, room=sid)
                    return
                if report_info['action'] != 'miner_signature_report':
                    await self.sio.emit('miner_signature_ack', {'success': False, 'error': 'Invalid report action'}, room=sid)
                    return
                if report_info['user'] != username:
                    await self.sio.emit('miner_signature_ack', {'success': False, 'error': 'Report user mismatch'}, room=sid)
                    return
                if not self.verify_contract_signature(
                    contract_content=report_content,
                    username=username,
                    signature=report_info['signature']
                ):
                    await self.sio.emit('miner_signature_ack', {'success': False, 'error': 'Invalid report signature'}, room=sid)
                    return
                report_transfer_id = self.extract_contract_detail(report_info, "TRANSFER_ID")
                report_contract_id = self.extract_contract_detail(report_info, "CONTRACT_ID")
                report_transfer_type = self.extract_contract_detail(report_info, "TRANSFER_TYPE")
                report_sender = self.extract_contract_detail(report_info, "SENDER")
                report_receiver = self.extract_contract_detail(report_info, "RECEIVER")
                report_amount = self.extract_contract_detail(report_info, "AMOUNT")
                report_fee_amount = self.extract_contract_detail(report_info, "FEE_AMOUNT")
                report_fee_source = self.extract_contract_detail(report_info, "FEE_SOURCE")
                report_vouchers = self.extract_contract_detail(report_info, "LOCKED_VOUCHERS")
                report_pow_audit = self.extract_contract_detail(report_info, "VOUCHER_POW_AUDIT")
                report_trace = self.extract_contract_detail(report_info, "VOUCHER_TRACE")
                expected_vouchers = transfer.get("locked_voucher_ids", [])
                report_voucher_list = []
                if report_vouchers:
                    try:
                        report_voucher_list = json.loads(report_vouchers)
                    except Exception:
                        report_voucher_list = []
                report_ok = True
                report_errors = []
                if not report_transfer_id or report_transfer_id != transfer_id:
                    report_ok = False
                    report_errors.append("transfer_id_mismatch")
                if transfer.get("contract_id") and report_contract_id != transfer.get("contract_id"):
                    report_ok = False
                    report_errors.append("contract_id_mismatch")
                if transfer.get("contract_id") and not self.verify_contract_signature(contract_id=transfer.get("contract_id")):
                    report_ok = False
                    report_errors.append("contract_signature_invalid")
                if not report_transfer_type or report_transfer_type != transfer.get("transfer_type"):
                    report_ok = False
                    report_errors.append("transfer_type_mismatch")
                if not report_sender or report_sender != transfer.get("sender"):
                    report_ok = False
                    report_errors.append("sender_mismatch")
                if not report_receiver or report_receiver != transfer.get("receiver"):
                    report_ok = False
                    report_errors.append("receiver_mismatch")
                if report_amount is None or int(report_amount) != int(transfer.get("amount", 0)):
                    report_ok = False
                    report_errors.append("amount_mismatch")
                if report_fee_amount is None or int(report_fee_amount) != int(transfer.get("fee_amount", 0)):
                    report_ok = False
                    report_errors.append("fee_amount_mismatch")
                if report_fee_source is None or report_fee_source != (transfer.get("fee_source") or ""):
                    report_ok = False
                    report_errors.append("fee_source_mismatch")
                if expected_vouchers and sorted(report_voucher_list) != sorted(expected_vouchers):
                    report_ok = False
                    report_errors.append("voucher_list_mismatch")
                if not report_pow_audit or not report_trace:
                    report_ok = False
                    report_errors.append("pow_or_trace_missing")
                else:
                    try:
                        pow_entries = json.loads(report_pow_audit)
                        trace_entries = json.loads(report_trace)
                    except Exception:
                        pow_entries = []
                        trace_entries = []
                        report_ok = False
                        report_errors.append("pow_or_trace_invalid")
                    pow_map = {entry.get("voucher_id"): entry for entry in pow_entries if isinstance(entry, dict)}
                    trace_map = {entry.get("voucher_id"): entry for entry in trace_entries if isinstance(entry, dict)}
                    for voucher_id in expected_vouchers:
                        pow_entry = pow_map.get(voucher_id)
                        trace_entry = trace_map.get(voucher_id)
                        if not pow_entry or not trace_entry:
                            report_ok = False
                            report_errors.append(f"pow_trace_missing:{voucher_id}")
                            break
                        info = self.get_voucher_audit_info(voucher_id)
                        if not info:
                            report_ok = False
                            report_errors.append(f"voucher_missing:{voucher_id}")
                            break
                        payload = info.get("payload", {}) or {}
                        pow_ok, _, pow_details = self.verify_voucher_pow_payload(payload)
                        pow_mint_ok = bool(pow_ok) and (pow_details.get("action_type") == "hps_mint")
                        if bool(pow_entry.get("pow_ok")) != bool(pow_ok):
                            report_ok = False
                            report_errors.append(f"pow_mismatch:{voucher_id}")
                            break
                        if not pow_mint_ok:
                            expected_sources = self.get_trace_source_vouchers(voucher_id)
                            inter_server_payload = transfer.get("inter_server_payload") or {}
                            if transfer.get("transfer_type") == "exchange_in":
                                expected_sources = inter_server_payload.get("issuer_voucher_ids", []) or expected_sources
                            trace_sources = trace_entry.get("source_vouchers", []) or []
                            if expected_sources and sorted(expected_sources) != sorted(trace_sources):
                                report_ok = False
                                report_errors.append(f"trace_sources_mismatch:{voucher_id}")
                                break
                            source_audits = trace_entry.get("source_audits", []) or []
                            trace_ok = False
                            for audit in source_audits:
                                if not isinstance(audit, dict):
                                    continue
                                source_payload = audit.get("payload", {}) or {}
                                source_signatures = audit.get("signatures", {}) or {}
                                owner_key = source_payload.get("owner_public_key", "")
                                issuer_key = source_payload.get("issuer_public_key", "")
                                if not owner_key or not issuer_key:
                                    continue
                                if not self.verify_payload_signature(source_payload, source_signatures.get("owner", ""), owner_key):
                                    continue
                                if not self.verify_payload_signature(source_payload, source_signatures.get("issuer", ""), issuer_key):
                                    continue
                                source_ok, _, source_details = self.verify_voucher_pow_payload(source_payload)
                                if source_ok and source_details.get("action_type") == "hps_mint":
                                    trace_ok = True
                                    break
                            if bool(trace_entry.get("trace_ok")) != bool(trace_ok):
                                report_ok = False
                                report_errors.append(f"trace_mismatch:{voucher_id}")
                                break
                if transfer.get("transfer_type") == "exchange_in":
                    inter_server_payload = transfer.get("inter_server_payload") or {}
                    issuer_address = inter_server_payload.get("issuer") or transfer.get("sender")
                    report_reserved_id = self.extract_contract_detail(report_info, "ISSUER_RESERVED_CONTRACT_ID")
                    report_reserved_content = self.extract_contract_detail(report_info, "ISSUER_RESERVED_CONTRACT")
                    report_out_id = self.extract_contract_detail(report_info, "ISSUER_OUT_CONTRACT_ID")
                    report_out_content = self.extract_contract_detail(report_info, "ISSUER_OUT_CONTRACT")
                    report_owner_key_id = self.extract_contract_detail(report_info, "ISSUER_OWNER_KEY_CONTRACT_ID")
                    report_owner_key_content = self.extract_contract_detail(report_info, "ISSUER_OWNER_KEY_CONTRACT")
                    report_exchange_contract_id = self.extract_contract_detail(report_info, "CLIENT_EXCHANGE_CONTRACT_ID")
                    report_exchange_contract_hash = self.extract_contract_detail(report_info, "CLIENT_EXCHANGE_CONTRACT_HASH")
                    expected_reserved_id = inter_server_payload.get("issuer_reserved_contract_id", "")
                    expected_out_id = inter_server_payload.get("issuer_out_contract_id", "")
                    expected_owner_key_id = inter_server_payload.get("issuer_owner_key_contract_id", "")
                    expected_exchange_contract_id = inter_server_payload.get("exchange_contract_id", "")
                    expected_exchange_hash = inter_server_payload.get("exchange_contract_hash", "")
                    expected_issuer_vouchers = inter_server_payload.get("issuer_voucher_ids", []) or []
                    if not all([
                        issuer_address,
                        report_reserved_id, report_reserved_content,
                        report_out_id, report_out_content,
                        report_owner_key_id, report_owner_key_content,
                        report_exchange_contract_id, report_exchange_contract_hash
                    ]):
                        report_ok = False
                        report_errors.append("issuer_report_missing_fields")
                    if report_reserved_id != expected_reserved_id or report_out_id != expected_out_id:
                        report_ok = False
                        report_errors.append("issuer_contract_id_mismatch")
                    if report_owner_key_id != expected_owner_key_id:
                        report_ok = False
                        report_errors.append("issuer_owner_key_id_mismatch")
                    if report_exchange_contract_id != expected_exchange_contract_id:
                        report_ok = False
                        report_errors.append("exchange_contract_id_mismatch")
                    if report_exchange_contract_hash != expected_exchange_hash:
                        report_ok = False
                        report_errors.append("exchange_contract_hash_mismatch")
                    issuer_public_key = self.get_server_public_key(issuer_address) or ""
                    if not issuer_public_key:
                        success_info, info, _ = await self.make_remote_request_json(issuer_address, "/server_info")
                        if success_info and info and info.get("public_key"):
                            issuer_public_key = self.normalize_public_key(info["public_key"])
                    if not issuer_public_key:
                        report_ok = False
                        report_errors.append("issuer_public_key_missing")
                    if report_ok:
                        try:
                            reserved_bytes = base64.b64decode(report_reserved_content)
                            out_bytes = base64.b64decode(report_out_content)
                            owner_key_bytes = base64.b64decode(report_owner_key_content)
                        except Exception:
                            report_ok = False
                            report_errors.append("issuer_contract_decode_failed")
                    if report_ok:
                        valid, _, reserved_info = self.validate_contract_structure(reserved_bytes)
                        valid_out, _, out_info = self.validate_contract_structure(out_bytes)
                        valid_owner, _, owner_info = self.validate_contract_structure(owner_key_bytes)
                        if not (valid and valid_out and valid_owner):
                            report_ok = False
                            report_errors.append("issuer_contract_invalid")
                        if valid and reserved_info.get("action") != "hps_exchange_reserved":
                            report_ok = False
                            report_errors.append("issuer_reserved_action_mismatch")
                        if valid_out and out_info.get("action") != "hps_exchange_out":
                            report_ok = False
                            report_errors.append("issuer_out_action_mismatch")
                        if valid_owner and owner_info.get("action") != "hps_exchange_owner_key":
                            report_ok = False
                            report_errors.append("issuer_owner_key_action_mismatch")
                        issuer_check = self.extract_contract_detail(reserved_info, "ISSUER") if valid else ""
                        if issuer_check and issuer_check != issuer_address:
                            report_ok = False
                            report_errors.append("issuer_reserved_address_mismatch")
                        issuer_check = self.extract_contract_detail(out_info, "ISSUER") if valid_out else ""
                        if issuer_check and issuer_check != issuer_address:
                            report_ok = False
                            report_errors.append("issuer_out_address_mismatch")
                        issuer_check = self.extract_contract_detail(owner_info, "ISSUER") if valid_owner else ""
                        if issuer_check and issuer_check != issuer_address:
                            report_ok = False
                            report_errors.append("issuer_owner_key_address_mismatch")
                        if valid and not self.verify_contract_signature(
                            contract_content=reserved_bytes,
                            username=reserved_info.get("user"),
                            signature=reserved_info.get("signature"),
                            public_key_pem=issuer_public_key
                        ):
                            report_ok = False
                            report_errors.append("issuer_reserved_signature_invalid")
                        if valid_out and not self.verify_contract_signature(
                            contract_content=out_bytes,
                            username=out_info.get("user"),
                            signature=out_info.get("signature"),
                            public_key_pem=issuer_public_key
                        ):
                            report_ok = False
                            report_errors.append("issuer_out_signature_invalid")
                        if valid_owner and not self.verify_contract_signature(
                            contract_content=owner_key_bytes,
                            username=owner_info.get("user"),
                            signature=owner_info.get("signature"),
                            public_key_pem=issuer_public_key
                        ):
                            report_ok = False
                            report_errors.append("issuer_owner_key_signature_invalid")
                        vouchers_reserved = self.extract_contract_detail(reserved_info, "VOUCHERS") if valid else ""
                        vouchers_out = self.extract_contract_detail(out_info, "VOUCHERS") if valid_out else ""
                        try:
                            vouchers_reserved_list = json.loads(vouchers_reserved) if vouchers_reserved else []
                            vouchers_out_list = json.loads(vouchers_out) if vouchers_out else []
                        except Exception:
                            vouchers_reserved_list = []
                            vouchers_out_list = []
                        if expected_issuer_vouchers:
                            if sorted(vouchers_reserved_list) != sorted(expected_issuer_vouchers):
                                report_ok = False
                                report_errors.append("issuer_reserved_vouchers_mismatch")
                            if sorted(vouchers_out_list) != sorted(expected_issuer_vouchers):
                                report_ok = False
                                report_errors.append("issuer_out_vouchers_mismatch")
                        owner_public_key = self.extract_contract_detail(owner_info, "OWNER_PUBLIC_KEY") if valid_owner else ""
                        exchange_contract_id = expected_exchange_contract_id
                        exchange_bytes = self.get_contract_bytes(exchange_contract_id) if exchange_contract_id else None
                        if not exchange_bytes:
                            report_ok = False
                            report_errors.append("exchange_contract_missing")
                        else:
                            exchange_hash = hashlib.sha256(exchange_bytes).hexdigest()
                            if exchange_hash != report_exchange_contract_hash:
                                report_ok = False
                                report_errors.append("exchange_contract_hash_mismatch_local")
                            valid_exchange, _, exchange_info = self.validate_contract_structure(exchange_bytes)
                            if not valid_exchange:
                                report_ok = False
                                report_errors.append("exchange_contract_invalid")
                            if valid_exchange and owner_public_key:
                                if not self.verify_contract_signature(
                                    contract_content=exchange_bytes,
                                    username=exchange_info.get("user"),
                                    signature=exchange_info.get("signature"),
                                    public_key_pem=owner_public_key
                                ):
                                    report_ok = False
                                    report_errors.append("exchange_contract_signature_invalid")
                            elif valid_exchange:
                                report_ok = False
                                report_errors.append("exchange_owner_key_missing")
                if not report_ok:
                    fee_amount = int(transfer.get("fee_amount", 0))
                    if fee_amount > 0:
                        self.add_miner_debt_entry(username, "fine_report_invalid", amount=fee_amount)
                        self.sync_miner_pending_counts(username)
                        await self.sio.emit('miner_signature_update', {
                            'pending_signatures': self.get_miner_pending_counts(username)[0],
                            'debt_status': self.safe_get_miner_debt_status(username)
                        }, room=sid)
                    error_note = "Invalid signature report"
                    if report_errors:
                        error_note = f"{error_note}: {','.join(report_errors[:6])}"
                    await self.sio.emit('miner_signature_ack', {'success': False, 'error': error_note}, room=sid)
                    return
                if expected_vouchers:
                    ok, failures = self.validate_vouchers(expected_vouchers, enforce_pow=False)
                    if not ok:
                        await self.sio.emit('miner_signature_ack', {
                            'success': False,
                            'error': 'Voucher validation failed',
                            'invalid_vouchers': failures
                        }, room=sid)
                        return
                contract_content = base64.b64decode(contract_content_b64)
                valid, error_msg, contract_info = self.validate_contract_structure(contract_content)
                if not valid:
                    await self.sio.emit('miner_signature_ack', {'success': False, 'error': f'Invalid contract: {error_msg}'}, room=sid)
                    return
                if contract_info['action'] != 'transfer_signature':
                    await self.sio.emit('miner_signature_ack', {'success': False, 'error': 'Invalid contract action'}, room=sid)
                    return
                if contract_info['user'] != username:
                    await self.sio.emit('miner_signature_ack', {'success': False, 'error': 'Contract user mismatch'}, room=sid)
                    return
                contract_transfer_id = self.extract_contract_detail(contract_info, "TRANSFER_ID")
                if contract_transfer_id and contract_transfer_id != transfer_id:
                    await self.sio.emit('miner_signature_ack', {'success': False, 'error': 'Transfer ID mismatch'}, room=sid)
                    return
                if not self.verify_contract_signature(
                    contract_content=contract_content,
                    username=username,
                    signature=contract_info['signature']
                ):
                    await self.sio.emit('miner_signature_ack', {'success': False, 'error': 'Invalid contract signature'}, room=sid)
                    return
                self.save_contract(
                    action_type="miner_signature_report",
                    content_hash=transfer_id,
                    domain=None,
                    username=username,
                    signature=report_info['signature'],
                    contract_content=report_content
                )
                self.save_contract(
                    action_type="transfer_signature",
                    content_hash=transfer_id,
                    domain=None,
                    username=username,
                    signature=contract_info['signature'],
                    contract_content=contract_content
                )
                await self.settle_miner_signature(transfer_id, username, contract_content, contract_info['signature'])
                await self.sio.emit('miner_signature_ack', {
                    'success': True,
                    'transfer_id': transfer_id,
                    'debt_status': self.safe_get_miner_debt_status(username)
                }, room=sid)
            except Exception as e:
                logger.error(f"Miner signature error for {sid}: {e}")
                await self.sio.emit('miner_signature_ack', {'success': False, 'error': str(e)}, room=sid)

        @self.sio.event
        async def request_voucher_audit(sid, data):
            try:
                client_info = self.connected_clients.get(sid)
                if not client_info or not client_info.get('authenticated'):
                    await self.sio.emit('voucher_audit', {'success': False, 'error': 'Not authenticated'}, room=sid)
                    return
                voucher_ids = data.get('voucher_ids', []) or []
                request_id = data.get('request_id') or str(uuid.uuid4())
                transfer_id = data.get('transfer_id') or ""
                if transfer_id:
                    self.extend_miner_deadline(transfer_id, extra_seconds=6.0)
                results = []
                missing_ids = []
                for voucher_id in voucher_ids:
                    info = self.get_voucher_audit_info(voucher_id)
                    if info:
                        info["issuer_server"] = self.address
                        info["issuer_server_key"] = base64.b64encode(self.public_key_pem).decode("utf-8")
                        results.append(info)
                    else:
                        missing_ids.append(voucher_id)
                if missing_ids:
                    for server in sorted(self.known_servers):
                        if server == self.address:
                            continue
                        success, payload, _ = await self.make_remote_request_json(
                            server,
                            "/voucher/audit",
                            method="POST",
                            data={"voucher_ids": missing_ids}
                        )
                        if not success or not payload or not payload.get("success"):
                            continue
                        remote_vouchers = payload.get("vouchers", []) or []
                        for info in remote_vouchers:
                            vid = info.get("voucher_id")
                            if vid in missing_ids:
                                results.append(info)
                                missing_ids.remove(vid)
                        if not missing_ids:
                            break
                await self.sio.emit('voucher_audit', {
                    'success': True,
                    'request_id': request_id,
                    'vouchers': results
                }, room=sid)
            except Exception as e:
                await self.sio.emit('voucher_audit', {'success': False, 'error': str(e)}, room=sid)

        @self.sio.event
        async def request_exchange_trace(sid, data):
            try:
                client_info = self.connected_clients.get(sid)
                if not client_info or not client_info.get('authenticated'):
                    await self.sio.emit('exchange_trace', {'success': False, 'error': 'Not authenticated'}, room=sid)
                    return
                voucher_ids = data.get('voucher_ids', []) or []
                request_id = data.get('request_id') or str(uuid.uuid4())
                traces = []
                for voucher_id in voucher_ids:
                    if not voucher_id:
                        continue
                    transfer = self.get_transfer_by_voucher_id(voucher_id)
                    if not transfer or transfer.get("transfer_type") != "exchange_in":
                        continue
                    transfer_id = transfer.get("transfer_id", "")
                    inter_server_payload = transfer.get("inter_server_payload") or {}
                    report_contract_id = ""
                    report_contract_hash = ""
                    report_trace = []
                    if transfer_id:
                        with get_db_conn(self.db_path) as conn:
                            cursor = conn.cursor()
                            cursor.execute('''SELECT contract_id, contract_content FROM contracts
                                              WHERE action_type = ? AND content_hash = ?
                                              ORDER BY timestamp DESC LIMIT 1''',
                                           ("miner_signature_report", transfer_id))
                            row = cursor.fetchone()
                        if row:
                            report_contract_id = row[0] or ""
                            report_b64 = row[1] or ""
                            try:
                                report_bytes = base64.b64decode(report_b64)
                                report_contract_hash = hashlib.sha256(report_bytes).hexdigest()
                                valid, _, report_info = self.validate_contract_structure(report_bytes)
                                if valid:
                                    trace_raw = self.extract_contract_detail(report_info, "VOUCHER_TRACE")
                                    if trace_raw:
                                        report_trace = json.loads(trace_raw)
                            except Exception:
                                report_trace = []
                    traces.append({
                        "voucher_id": voucher_id,
                        "transfer_id": transfer_id,
                        "inter_server_payload": inter_server_payload,
                        "report_contract_id": report_contract_id,
                        "report_contract_hash": report_contract_hash,
                        "report_trace": report_trace
                    })
                await self.sio.emit('exchange_trace', {
                    'success': True,
                    'request_id': request_id,
                    'traces': traces
                }, room=sid)
            except Exception as e:
                await self.sio.emit('exchange_trace', {'success': False, 'error': str(e)}, room=sid)

        @self.sio.event
        async def invalidate_vouchers(sid, data):
            for attempt in range(3):
                try:
                    client_info = self.connected_clients.get(sid)
                    if not client_info or not client_info.get('authenticated'):
                        await self.sio.emit('voucher_invalidate_ack', {'success': False, 'error': 'Not authenticated'}, room=sid)
                        return
                    username = client_info.get('username', '')
                    contract_content_b64 = data.get('contract_content')
                    if not contract_content_b64:
                        await self.sio.emit('voucher_invalidate_ack', {'success': False, 'error': 'Missing contract content'}, room=sid)
                        return
                    contract_content = base64.b64decode(contract_content_b64)
                    valid, error_msg, contract_info = self.validate_contract_structure(contract_content)
                    if not valid:
                        await self.sio.emit('voucher_invalidate_ack', {'success': False, 'error': f'Invalid contract: {error_msg}'}, room=sid)
                        return
                    if contract_info['action'] != 'voucher_invalidate':
                        await self.sio.emit('voucher_invalidate_ack', {'success': False, 'error': 'Invalid contract action'}, room=sid)
                        return
                    if contract_info['user'] != username:
                        await self.sio.emit('voucher_invalidate_ack', {'success': False, 'error': 'Contract user mismatch'}, room=sid)
                        return
                    if not self.verify_contract_signature(
                        contract_content=contract_content,
                        username=username,
                        signature=contract_info['signature']
                    ):
                        await self.sio.emit('voucher_invalidate_ack', {'success': False, 'error': 'Invalid contract signature'}, room=sid)
                        return
                    transfer_id = self.extract_contract_detail(contract_info, "TRANSFER_ID") or ""
                    voucher_list_raw = self.extract_contract_detail(contract_info, "VOUCHERS")
                    reason = self.extract_contract_detail(contract_info, "REASON")
                    if not reason:
                        await self.sio.emit('voucher_invalidate_ack', {'success': False, 'error': 'Missing invalidation reason', 'transfer_id': transfer_id}, room=sid)
                        return
                    if not voucher_list_raw:
                        await self.sio.emit('voucher_invalidate_ack', {'success': False, 'error': 'Missing vouchers list', 'transfer_id': transfer_id}, room=sid)
                        return
                    try:
                        voucher_ids = json.loads(voucher_list_raw)
                    except Exception:
                        await self.sio.emit('voucher_invalidate_ack', {'success': False, 'error': 'Invalid vouchers list', 'transfer_id': transfer_id}, room=sid)
                        return
                    ok, failures = self.validate_vouchers(voucher_ids)
                    if ok:
                        self.save_contract(
                            action_type="voucher_invalidate",
                            content_hash=voucher_ids[0] if voucher_ids else None,
                            domain=None,
                            username=username,
                            signature=contract_info['signature'],
                            contract_content=contract_content
                        )
                        if transfer_id:
                            self.save_server_contract(
                                "transfer_rejected",
                                [
                                    ("TRANSFER_ID", transfer_id),
                                    ("REASON", reason or "miner_invalidated"),
                                    ("MINER", username)
                                ],
                                op_id=transfer_id
                            )
                            with get_db_conn(self.db_path) as conn:
                                cursor = conn.cursor()
                                cursor.execute('''UPDATE monetary_transfers SET status = ? WHERE transfer_id = ?''',
                                               ("invalidated", transfer_id))
                                cursor.execute('''UPDATE pending_transfers SET status = ? WHERE transfer_id = ?''',
                                               ("invalidated", transfer_id))
                                conn.commit()
                            self.notify_monetary_transfer_update(
                                transfer_id,
                                "invalidated",
                                reason=reason or "miner_invalidated",
                                details={"message": "Transacao recusada pelo minerador."}
                            )
                            await self.cancel_pending_monetary_action(transfer_id, "miner_invalidated")
                        await self.sio.emit('voucher_invalidate_ack', {
                            'success': True,
                            'failures': failures,
                            'transfer_id': transfer_id,
                            'note': 'transfer_rejected_only'
                        }, room=sid)
                        return
                    invalid_ids = list(failures.keys())
                    owners: Dict[str, Dict[str, Any]] = {}
                    with get_db_conn(self.db_path) as conn:
                        cursor = conn.cursor()
                        for voucher_id in invalid_ids:
                            cursor.execute('''SELECT owner, value FROM hps_vouchers WHERE voucher_id = ?''', (voucher_id,))
                            row = cursor.fetchone()
                            if not row:
                                continue
                            owner, value = row
                            owners.setdefault(owner, {"total": 0, "vouchers": []})
                            owners[owner]["total"] += int(value or 0)
                            owners[owner]["vouchers"].append(voucher_id)
                            cursor.execute('''UPDATE hps_vouchers
                                              SET invalidated = 1, status = ?, last_updated = ?
                                              WHERE voucher_id = ?''', ("invalid", time.time(), voucher_id))
                        conn.commit()
                    for owner, info in owners.items():
                        with get_db_conn(self.db_path) as conn:
                            cursor = conn.cursor()
                            cursor.execute('UPDATE user_reputations SET reputation = MAX(1, reputation - 20) WHERE username = ?', (owner,))
                            cursor.execute('UPDATE users SET reputation = MAX(1, reputation - 20) WHERE username = ?', (owner,))
                            conn.commit()
                        self.save_server_contract(
                            "burn_money",
                            [
                                ("OWNER", owner),
                                ("VOUCHERS", json.dumps(info["vouchers"], ensure_ascii=True)),
                                ("TOTAL_VALUE", info["total"]),
                                ("REASON", reason or "voucher_invalidated"),
                                ("MINER", username)
                            ],
                            op_id=str(uuid.uuid4())
                        )
                        await self.send_hps_wallet_sync(owner)
                    with get_db_conn(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('''SELECT transfer_id FROM monetary_transfers
                                          WHERE status = ? AND locked_voucher_ids != ""''', ("pending_signature",))
                        transfers = [row[0] for row in cursor.fetchall()]
                        for transfer_id in transfers:
                            transfer = self.get_monetary_transfer(transfer_id)
                            locked_ids = set(transfer.get("locked_voucher_ids", []))
                            if locked_ids.intersection(set(invalid_ids)):
                                cursor.execute('''UPDATE monetary_transfers SET status = ? WHERE transfer_id = ?''',
                                               ("invalidated", transfer_id))
                                self.notify_monetary_transfer_update(
                                    transfer_id,
                                    "invalidated",
                                    reason=reason or "voucher_invalidated",
                                    details={"invalid_vouchers": failures}
                                )
                                await self.cancel_pending_monetary_action(transfer_id, "voucher_invalidated")
                        cursor.execute('''SELECT transfer_id, original_owner FROM pending_transfers
                                          WHERE transfer_type = ? AND hps_voucher_ids IS NOT NULL''', ("hps_transfer",))
                        pending_rows = cursor.fetchall()
                        for transfer_id, owner in pending_rows:
                            cursor.execute('SELECT hps_voucher_ids FROM pending_transfers WHERE transfer_id = ?', (transfer_id,))
                            row = cursor.fetchone()
                            if not row or not row[0]:
                                continue
                            try:
                                pending_ids = set(json.loads(row[0]))
                            except Exception:
                                pending_ids = set()
                            if pending_ids.intersection(set(invalid_ids)):
                                cursor.execute('UPDATE pending_transfers SET status = ? WHERE transfer_id = ?',
                                               ("invalidated", transfer_id))
                                if owner:
                                    self.notify_pending_transfers(owner)
                        conn.commit()
                    self.save_contract(
                        action_type="voucher_invalidate",
                        content_hash=invalid_ids[0] if invalid_ids else None,
                        domain=None,
                        username=username,
                        signature=contract_info['signature'],
                        contract_content=contract_content
                    )
                    await self.sio.emit('voucher_invalidate_ack', {'success': True, 'failures': failures, 'transfer_id': transfer_id}, room=sid)
                    return
                except sqlite3.OperationalError as e:
                    if "locked" in str(e).lower() and attempt < 2:
                        await asyncio.sleep(0.25 * (attempt + 1))
                        continue
                    logger.error(f"Voucher invalidate error for {sid}: {e}")
                    await self.sio.emit('voucher_invalidate_ack', {'success': False, 'error': str(e)}, room=sid)
                    return
                except Exception as e:
                    logger.error(f"Voucher invalidate error for {sid}: {e}")
                    await self.sio.emit('voucher_invalidate_ack', {'success': False, 'error': str(e)}, room=sid)
                    return

        @self.sio.event
        async def submit_fraud_report(sid, data):
            try:
                client_info = self.connected_clients.get(sid)
                if not client_info or not client_info.get('authenticated'):
                    await self.sio.emit('fraud_report_ack', {'success': False, 'error': 'Not authenticated'}, room=sid)
                    return
                reports = data.get("reports", []) or []
                confirmed = []
                for report in reports:
                    issuer = (report.get("server_address") or "").strip()
                    contract_b64 = report.get("contract_content") or ""
                    if not issuer or not contract_b64:
                        continue
                    try:
                        contract_bytes = base64.b64decode(contract_b64)
                    except Exception:
                        continue
                    valid, _, contract_info = self.validate_contract_structure(contract_bytes)
                    if not valid or contract_info.get("action") != "voucher_invalidate":
                        continue
                    miner_username = contract_info.get("user", "")
                    if not self.verify_contract_signature(
                        contract_content=contract_bytes,
                        username=miner_username,
                        signature=contract_info.get("signature")
                    ):
                        continue
                    raw_list = self.extract_contract_detail(contract_info, "VOUCHERS")
                    if not raw_list:
                        continue
                    try:
                        voucher_ids = json.loads(raw_list)
                    except Exception:
                        continue
                    if not voucher_ids:
                        continue
                    success, payload, _ = await self.make_remote_request_json(
                        issuer,
                        "/voucher/audit",
                        method="POST",
                        data={"voucher_ids": voucher_ids}
                    )
                    if not success or not payload or not payload.get("success"):
                        continue
                    remote_vouchers = payload.get("vouchers", []) or []
                    invalidated_ok = all(bool(item.get("invalidated")) for item in remote_vouchers)
                    if invalidated_ok:
                        continue
                    report["voucher_ids"] = voucher_ids
                    contract_id = self.register_fraudulent_issuer(issuer, report)
                    confirmed.append({"issuer": issuer, "contract_id": contract_id or ""})
                await self.sio.emit('fraud_report_ack', {'success': True, 'confirmed': confirmed}, room=sid)
            except Exception as e:
                logger.error(f"Fraud report error for {sid}: {e}")
                await self.sio.emit('fraud_report_ack', {'success': False, 'error': str(e)}, room=sid)

        @self.sio.event
        async def request_miner_fine(sid, data):
            try:
                client_info = self.connected_clients.get(sid)
                if not client_info or not client_info.get('authenticated'):
                    await self.sio.emit('miner_fine_quote', {'success': False, 'error': 'Not authenticated'}, room=sid)
                    return
                username = client_info.get('username', '')
                debt_status = self.safe_get_miner_debt_status(username)
                pending_signatures = int(debt_status.get("pending_signatures", 0))
                debt_limit = int(debt_status.get("debt_limit", 0))
                allow_last_resort = pending_signatures >= debt_limit
                quote = self.get_miner_fine_quote(username, include_signature_last_resort=allow_last_resort)
                fine_amount = quote.get("total_amount", 0)
                await self.sio.emit('miner_fine_quote', {
                    'success': True,
                    'fine_amount': fine_amount,
                    'pending_fines': quote.get("fine_count", 0),
                    'signature_fines': quote.get("signature_count", 0),
                    'signature_amount': quote.get("signature_amount", 0),
                    'signature_immediate': quote.get("signature_immediate", 0),
                    'signature_last_resort': quote.get("signature_last_resort", 0),
                    'pending_total': int(quote.get("fine_count", 0)) + int(quote.get("signature_count", 0)),
                    'mined_balance': self.get_user_mined_balance(username),
                    'debt_status': debt_status
                }, room=sid)
            except Exception as e:
                logger.error(f"Miner fine quote error for {sid}: {e}")
                await self.sio.emit('miner_fine_quote', {'success': False, 'error': str(e)}, room=sid)

        @self.sio.event
        async def pay_miner_fine(sid, data):
            username = ""
            payment_applied = False
            try:
                client_info = self.connected_clients.get(sid)
                if not client_info or not client_info.get('authenticated'):
                    await self.sio.emit('miner_fine_ack', {'success': False, 'error': 'Not authenticated'}, room=sid)
                    return
                username = client_info.get('username', '')
                voucher_ids = data.get('voucher_ids', []) or []
                use_withheld = bool(data.get("use_withheld", False))
                promise = bool(data.get("promise", False))
                contract_content_b64 = data.get('contract_content')
                if (not voucher_ids and not use_withheld and not promise) or not contract_content_b64:
                    await self.sio.emit('miner_fine_ack', {'success': False, 'error': 'Missing fine payment data'}, room=sid)
                    return
                contract_content = base64.b64decode(contract_content_b64)
                valid, error_msg, contract_info = self.validate_contract_structure(contract_content)
                if not valid:
                    await self.sio.emit('miner_fine_ack', {'success': False, 'error': f'Invalid contract: {error_msg}'}, room=sid)
                    return
                if contract_info['action'] != 'miner_fine':
                    await self.sio.emit('miner_fine_ack', {'success': False, 'error': 'Invalid contract action'}, room=sid)
                    return
                if contract_info['user'] != username:
                    await self.sio.emit('miner_fine_ack', {'success': False, 'error': 'Contract user mismatch'}, room=sid)
                    return
                if not self.verify_contract_signature(
                    contract_content=contract_content,
                    username=username,
                    signature=contract_info['signature']
                ):
                    await self.sio.emit('miner_fine_ack', {'success': False, 'error': 'Invalid contract signature'}, room=sid)
                    return
                contract_amount = self.extract_contract_detail(contract_info, "AMOUNT")
                if contract_amount is None:
                    await self.sio.emit('miner_fine_ack', {'success': False, 'error': 'Missing fine amount'}, room=sid)
                    return
                fine_amount = int(float(contract_amount))
                debt_status = self.safe_get_miner_debt_status(username)
                pending_signatures = int(debt_status.get("pending_signatures", 0))
                debt_limit = int(debt_status.get("debt_limit", 0))
                allow_last_resort = pending_signatures >= debt_limit
                quote = self.get_miner_fine_quote(username, include_signature_last_resort=allow_last_resort)
                expected_fine = int(quote.get("total_amount", 0))
                if expected_fine <= 0:
                    await self.sio.emit('miner_fine_ack', {'success': False, 'error': 'No pending fines'}, room=sid)
                    return
                if self.has_pending_signature_transfers(username) and int(quote.get("signature_count", 0)) <= 0:
                    await self.sio.emit('miner_fine_ack', {'success': False, 'error': 'Existem assinaturas pendentes disponiveis'}, room=sid)
                    return
                mined_balance = self.get_user_mined_balance(username)
                if fine_amount != expected_fine:
                    await self.sio.emit('miner_fine_ack', {'success': False, 'error': 'Fine amount mismatch'}, room=sid)
                    return
                contract_id = self.save_contract(
                    action_type="miner_fine",
                    content_hash=None,
                    domain=None,
                    username=username,
                    signature=contract_info['signature'],
                    contract_content=contract_content
                )
                session_id = f"fine-{uuid.uuid4()}"
                signature_types = ["signature_immediate"]
                if allow_last_resort:
                    signature_types.append("signature_last_resort")
                if promise:
                    withheld_used, _ = self.consume_withheld_offers(username, fine_amount)
                    remaining = max(0, fine_amount - withheld_used)
                    self.resolve_miner_debt_entries(username, ["fine_delay", "fine_report_invalid"])
                    self.resolve_miner_debt_entries(username, signature_types)
                    if remaining <= 0:
                        self.update_miner_stats(username, fine_promise_amount=0, fine_promise_active=0)
                    else:
                        self.update_miner_stats(
                            username,
                            fine_promise_amount=remaining,
                            fine_promise_active=1
                        )
                    self.sync_miner_pending_counts(username)
                    payment_applied = True
                    self.release_withheld_offers_for_miner(username)
                    await self.sio.emit('miner_signature_update', {
                        'pending_signatures': self.get_miner_pending_counts(username)[0],
                        'debt_status': self.safe_get_miner_debt_status(username)
                    }, room=sid)
                    await self.send_hps_wallet_sync(username)
                    await self.send_hps_economy_status()
                    await self.sio.emit('miner_fine_ack', {
                        'success': True,
                        'amount': fine_amount,
                        'mode': 'promise',
                        'debt_status': self.safe_get_miner_debt_status(username)
                    }, room=sid)
                    return

                total_value = 0
                if voucher_ids:
                    ok, total_value, error = self.reserve_vouchers_for_session(username, session_id, voucher_ids)
                    if not ok:
                        await self.sio.emit('miner_fine_ack', {'success': False, 'error': error}, room=sid)
                        return
                withheld_used = 0
                if use_withheld:
                    remaining = max(0, fine_amount - total_value)
                    withheld_used, _ = self.consume_withheld_offers(username, remaining)
                if total_value < fine_amount:
                    combined = total_value + withheld_used
                    if combined < fine_amount:
                        if voucher_ids:
                            self.release_vouchers_for_session(session_id)
                        await self.sio.emit('miner_fine_ack', {'success': False, 'error': 'Insufficient balance'}, room=sid)
                        return
                self.mark_vouchers_spent(session_id)
                self.increment_economy_stat("custody_balance", fine_amount)
                self.record_economy_event("miner_fine")
                self.record_economy_contract("miner_fine")
                change_value = max(0, int(total_value) - int(fine_amount))
                if change_value > 0:
                    await self.issue_change_offer(
                        username=username,
                        change_value=change_value,
                        reason="miner_fine_change",
                        session_id=session_id,
                        contract_action="miner_fine_refund",
                        contract_details=[
                            ("MINER", username),
                            ("FINE_AMOUNT", fine_amount),
                            ("VOUCHERS", json.dumps(voucher_ids, ensure_ascii=True))
                        ]
                    )
                self.save_server_contract(
                    "miner_fine_receipt",
                    [
                        ("MINER", username),
                        ("AMOUNT", fine_amount),
                        ("CONTRACT_ID", contract_id),
                        ("VOUCHERS", json.dumps(voucher_ids, ensure_ascii=True))
                    ],
                    op_id=session_id
                )
                self.resolve_miner_debt_entries(username, ["fine_delay", "fine_report_invalid"])
                self.resolve_miner_debt_entries(username, signature_types)
                self.update_miner_stats(username, fine_promise_amount=0, fine_promise_active=0)
                self.sync_miner_pending_counts(username)
                payment_applied = True
                self.release_withheld_offers_for_miner(username)
                await self.sio.emit('miner_signature_update', {
                    'pending_signatures': self.get_miner_pending_counts(username)[0],
                    'debt_status': self.safe_get_miner_debt_status(username)
                }, room=sid)
                await self.send_hps_wallet_sync(username)
                await self.send_hps_economy_status()
                await self.sio.emit('miner_fine_ack', {
                    'success': True,
                    'amount': fine_amount,
                    'debt_status': self.safe_get_miner_debt_status(username)
                }, room=sid)
            except RecursionError:
                pending_signatures, pending_fines = self.get_miner_pending_counts(username)
                if pending_fines == 0 and payment_applied:
                    await self.sio.emit('miner_fine_ack', {
                        'success': True,
                        'amount': 0,
                        'debt_status': self.safe_get_miner_debt_status(username)
                    }, room=sid)
                    return
                await self.sio.emit('miner_fine_ack', {'success': False, 'error': 'Recursion error'}, room=sid)
            except Exception as e:
                logger.error(f"Miner fine payment error for {sid}: {e}")
                await self.sio.emit('miner_fine_ack', {'success': False, 'error': str(e)}, room=sid)
        @self.sio.event
        async def request_exchange_quote(sid, data):
            try:
                client_info = self.connected_clients.get(sid)
                if not client_info or not client_info.get('authenticated'):
                    await self.sio.emit('exchange_quote', {'success': False, 'error': 'Not authenticated'}, room=sid)
                    return
                vouchers = data.get("vouchers", []) or []
                client_signature = data.get("client_signature", "")
                client_public_key = data.get("client_public_key", "")
                timestamp = float(data.get("timestamp", 0))
                fallback_report = data.get("fallback_report")
                contract_content_b64 = data.get("contract_content")
                if not vouchers or not client_signature or not client_public_key:
                    await self.sio.emit('exchange_quote', {'success': False, 'error': 'Missing exchange data'}, room=sid)
                    return
                if abs(time.time() - timestamp) > 600:
                    await self.sio.emit('exchange_quote', {'success': False, 'error': 'Timestamp out of range'}, room=sid)
                    return
                issuer = vouchers[0].get("payload", {}).get("issuer", "")
                if not issuer or self.is_local_issuer(issuer):
                    await self.sio.emit('exchange_quote', {'success': False, 'error': 'Invalid issuer'}, room=sid)
                    return
                if self.is_exchange_blocked(issuer):
                    await self.sio.emit('exchange_quote', {'success': False, 'error': 'Issuer blocked for exchange'}, room=sid)
                    return
                voucher_ids = []
                total_value = 0
                owner = None
                owner_key = None
                issuer_key = None
                for voucher in vouchers:
                    ok, error = self.verify_voucher_blob(voucher)
                    if not ok:
                        await self.sio.emit('exchange_quote', {'success': False, 'error': error}, room=sid)
                        return
                    payload = voucher.get("payload", {})
                    if payload.get("issuer") != issuer:
                        await self.sio.emit('exchange_quote', {'success': False, 'error': 'Mixed issuers not supported'}, room=sid)
                        return
                    if not owner:
                        owner = payload.get("owner")
                        owner_key = payload.get("owner_public_key")
                        issuer_key = payload.get("issuer_public_key")
                    if payload.get("owner") != owner:
                        await self.sio.emit('exchange_quote', {'success': False, 'error': 'Voucher owner mismatch'}, room=sid)
                        return
                    if owner_key != client_public_key:
                        await self.sio.emit('exchange_quote', {'success': False, 'error': 'Owner key mismatch'}, room=sid)
                        return
                    if issuer_key and payload.get("issuer_public_key") != issuer_key:
                        await self.sio.emit('exchange_quote', {'success': False, 'error': 'Issuer key mismatch'}, room=sid)
                        return
                    voucher_ids.append(payload.get("voucher_id", ""))
                    total_value += int(payload.get("value", 0))
                target_server = data.get("target_server") or self.address
                if target_server != self.address:
                    logger.warning(f"Exchange target server mismatch: client={target_server} local={self.address}")
                proof_payload = {
                    "issuer": issuer,
                    "target_server": target_server,
                    "voucher_ids": sorted(voucher_ids),
                    "timestamp": timestamp
                }
                if not self.verify_payload_signature(proof_payload, client_signature, client_public_key):
                    await self.sio.emit('exchange_quote', {'success': False, 'error': 'Client proof invalid'}, room=sid)
                    return
                contract_id = None
                if contract_content_b64:
                    contract_content = base64.b64decode(contract_content_b64)
                    valid, error_msg, contract_info = self.validate_contract_structure(contract_content)
                    if not valid:
                        await self.sio.emit('exchange_quote', {'success': False, 'error': f'Invalid contract: {error_msg}'}, room=sid)
                        return
                    if contract_info['action'] != 'exchange_hps':
                        await self.sio.emit('exchange_quote', {'success': False, 'error': 'Invalid contract action'}, room=sid)
                        return
                    if contract_info['user'] != client_info.get("username"):
                        await self.sio.emit('exchange_quote', {'success': False, 'error': 'Contract user mismatch'}, room=sid)
                        return
                    if not self.verify_contract_signature(
                        contract_content=contract_content,
                        username=client_info.get("username"),
                        signature=contract_info['signature'],
                        public_key_pem=client_public_key
                    ):
                        await self.sio.emit('exchange_quote', {'success': False, 'error': 'Invalid contract signature'}, room=sid)
                        return
                    contract_id = self.save_contract(
                        action_type="exchange_hps",
                        content_hash=None,
                        domain=None,
                        username=client_info.get("username"),
                        signature=contract_info['signature'],
                        contract_content=contract_content
                    )
                issuer_address = data.get("issuer_address") or issuer
                success_report, economy_report, _ = await self.make_remote_request_json(issuer_address, "/economy_report")
                if not success_report or not economy_report or not self.verify_economy_report(economy_report):
                    if fallback_report and self.verify_economy_report(fallback_report):
                        report_ts = float(fallback_report.get("payload", {}).get("timestamp", 0))
                        if abs(time.time() - report_ts) <= 600:
                            economy_report = fallback_report
                        else:
                            await self.sio.emit('exchange_quote', {'success': False, 'error': 'Issuer economy report expired'}, room=sid)
                            return
                    else:
                        await self.sio.emit('exchange_quote', {'success': False, 'error': 'Issuer economy report invalid'}, room=sid)
                        return
                report_payload = economy_report.get("payload", {})
                report_key = report_payload.get("issuer_public_key", "")
                if issuer_key and report_key and issuer_key != report_key:
                    await self.sio.emit('exchange_quote', {'success': False, 'error': 'Issuer report key mismatch'}, room=sid)
                    return
                issuer_multiplier = float(economy_report["payload"].get("multiplier", 1.0))
                request_id = str(uuid.uuid4())
                success_validate, validation, validation_error = await self.make_remote_request_json(
                    issuer_address,
                    "/exchange/validate",
                    method="POST",
                    data={
                        "voucher_ids": voucher_ids,
                        "target_server": target_server,
                        "client_signature": client_signature,
                        "client_public_key": client_public_key,
                        "timestamp": timestamp,
                        "request_id": request_id
                    }
                )
                if not success_validate or not validation or not validation.get("success"):
                    if validation and validation.get("error"):
                        error_msg = validation.get("error")
                    else:
                        error_msg = f"Issuer validation failed: {validation_error}"
                    await self.sio.emit('exchange_quote', {'success': False, 'error': error_msg}, room=sid)
                    return
                local_multiplier = self.get_economy_multiplier()
                rate = local_multiplier / max(issuer_multiplier, 0.0001)
                converted_value = int(math.floor(total_value * rate))
                if converted_value <= 0:
                    await self.sio.emit('exchange_quote', {'success': False, 'error': 'Conversion result too small'}, room=sid)
                    return
                fee_amount = max(self.exchange_fee_min, int(math.ceil(converted_value * self.exchange_fee_rate)))
                receive_amount = max(0, converted_value - fee_amount)
                quote_id = str(uuid.uuid4())
                expires_at = time.time() + self.exchange_quote_ttl
                self.exchange_quotes[quote_id] = {
                    "issuer": issuer,
                    "owner": owner,
                    "voucher_ids": voucher_ids,
                    "total_value": total_value,
                    "rate": rate,
                    "converted_value": converted_value,
                    "fee_amount": fee_amount,
                    "receive_amount": receive_amount,
                    "economy_report": economy_report,
                    "exchange_token": validation.get("token"),
                    "exchange_signature": validation.get("signature"),
                    "issuer_reserved_contract_id": validation.get("contract_id") or "",
                    "issuer_owner_key_contract_id": validation.get("owner_key_contract_id") or "",
                    "expires_at": expires_at,
                    "client_contract_id": contract_id
                }
                await self.sio.emit('exchange_quote', {
                    "success": True,
                    "quote_id": quote_id,
                    "issuer": issuer,
                    "rate": rate,
                    "converted_value": converted_value,
                    "fee_amount": fee_amount,
                    "receive_amount": receive_amount,
                    "expires_at": expires_at,
                    "client_contract_id": contract_id
                }, room=sid)
            except Exception as e:
                logger.error(f"Exchange quote error for {sid}: {e}")
                await self.sio.emit('exchange_quote', {'success': False, 'error': str(e)}, room=sid)

        @self.sio.event
        async def confirm_exchange(sid, data):
            try:
                client_info = self.connected_clients.get(sid)
                if not client_info or not client_info.get('authenticated'):
                    await self.sio.emit('exchange_complete', {'success': False, 'error': 'Not authenticated'}, room=sid)
                    return
                quote_id = data.get("quote_id", "")
                quote = self.exchange_quotes.get(quote_id)
                if not quote:
                    await self.sio.emit('exchange_complete', {'success': False, 'error': 'Quote not found'}, room=sid)
                    return
                if time.time() > quote.get("expires_at", 0):
                    await self.sio.emit('exchange_complete', {'success': False, 'error': 'Quote expired'}, room=sid)
                    return
                issuer = quote.get("issuer")
                token_payload = quote.get("exchange_token", {})
                token_signature = quote.get("exchange_signature", "")
                success_confirm, confirm_data, _ = await self.make_remote_request_json(
                    issuer,
                    "/exchange/confirm",
                    method="POST",
                    data={
                        "token": token_payload,
                        "signature": token_signature
                    }
                )
                if not success_confirm or not confirm_data or not confirm_data.get("success"):
                    error_msg = (confirm_data or {}).get("error", "Issuer confirmation failed")
                    await self.sio.emit('exchange_complete', {'success': False, 'error': error_msg}, room=sid)
                    return
                issuer_contract_id = (confirm_data.get("payload") or {}).get("contract_id", "")
                issuer_reserved_contract_id = quote.get("issuer_reserved_contract_id") or ""
                issuer_owner_key_contract_id = quote.get("issuer_owner_key_contract_id") or ""
                if issuer_reserved_contract_id:
                    await self.sync_contract_with_server(issuer, contract_id=issuer_reserved_contract_id)
                if issuer_owner_key_contract_id:
                    await self.sync_contract_with_server(issuer, contract_id=issuer_owner_key_contract_id)
                if issuer_contract_id:
                    await self.sync_contract_with_server(issuer, contract_id=issuer_contract_id)
                owner_key = client_info.get("public_key", "")
                fee_amount, fee_source, adjusted_receive = self.allocate_signature_fee(int(quote.get("receive_amount", 0)))
                offer = self.create_voucher_offer(
                    owner=client_info.get("username"),
                    owner_public_key=owner_key,
                    value=adjusted_receive,
                    reason=f"exchange_from:{issuer}",
                    pow_info=None,
                    conditions={
                        "type": "exchange",
                        "issuer": issuer,
                        "rate": quote.get("rate", 1.0),
                        "fee": quote.get("fee_amount", 0),
                        "issuer_voucher_ids": quote.get("voucher_ids", [])
                    }
                )
                self.allocate_exchange_fee(int(quote.get("fee_amount", 0)))
                exchange_contract_id = quote.get("client_contract_id") or ""
                exchange_contract_bytes = self.get_contract_bytes(exchange_contract_id) if exchange_contract_id else None
                exchange_contract_hash = hashlib.sha256(exchange_contract_bytes).hexdigest() if exchange_contract_bytes else ""
                exchange_contract_b64 = base64.b64encode(exchange_contract_bytes).decode("utf-8") if exchange_contract_bytes else ""
                inter_server_payload = {
                    "issuer": issuer,
                    "issuer_voucher_ids": quote.get("voucher_ids", []),
                    "issuer_reserved_contract_id": issuer_reserved_contract_id,
                    "issuer_out_contract_id": issuer_contract_id,
                    "issuer_owner_key_contract_id": issuer_owner_key_contract_id,
                    "exchange_contract_id": exchange_contract_id,
                    "exchange_contract_hash": exchange_contract_hash,
                    "exchange_contract_content": exchange_contract_b64
                }
                transfer_id = self.create_monetary_transfer(
                    transfer_type="exchange_in",
                    sender=issuer,
                    receiver=client_info.get("username", ""),
                    amount=adjusted_receive,
                    locked_voucher_ids=[offer.get("voucher_id")],
                    contract_id=None,
                    fee_amount=fee_amount,
                    fee_source=fee_source,
                    inter_server_payload=inter_server_payload
                )
                contract_id = self.save_server_contract(
                    "hps_exchange_in",
                    [
                        ("CLIENT", client_info.get("username", "")),
                        ("ISSUER", issuer),
                        ("TOTAL_VALUE", quote.get("total_value", 0)),
                        ("RATE", quote.get("rate", 1.0)),
                        ("FEE", quote.get("fee_amount", 0)),
                        ("RECEIVED", adjusted_receive),
                        ("MINER_FEE", fee_amount),
                        ("FEE_SOURCE", fee_source),
                        ("VOUCHERS", json.dumps(quote.get("voucher_ids", []), ensure_ascii=True)),
                        ("CLIENT_CONTRACT_ID", quote.get("client_contract_id") or ""),
                        ("ISSUER_CONTRACT_ID", issuer_contract_id)
                    ],
                    op_id=offer.get("voucher_id")
                )
                await self.sio.emit('hps_voucher_offer', {
                    'offer_id': offer["offer_id"],
                    'voucher_id': offer["voucher_id"],
                    'payload': offer["payload"],
                    'expires_at': offer["expires_at"]
                }, room=sid)
                await self.sio.emit('exchange_complete', {
                    "success": True,
                    "quote_id": quote_id,
                    "contract_id": contract_id,
                    "spent_voucher_ids": quote.get("voucher_ids", []),
                    "new_voucher_id": offer.get("voucher_id"),
                    "received_amount": adjusted_receive,
                    "transfer_id": transfer_id
                }, room=sid)
                self.exchange_quotes.pop(quote_id, None)
            except Exception as e:
                logger.error(f"Exchange confirm error for {sid}: {e}")
                await self.sio.emit('exchange_complete', {'success': False, 'error': str(e)}, room=sid)

        @self.sio.event
        async def request_economy_report(sid, data):
            try:
                report = self.build_economy_report()
                await self.sio.emit('economy_report', report, room=sid)
            except Exception as e:
                await self.sio.emit('economy_report', {'success': False, 'error': str(e)}, room=sid)

        @self.sio.event
        async def transfer_hps(sid, data):
            try:
                deferred = data.get("_deferred_payment")
                if deferred:
                    deferred_public_key = data.get("_deferred_public_key", "")
                    client_info = {"public_key": deferred_public_key}
                    client_identifier = data.get("_deferred_client_identifier", "")
                    username = data.get("_deferred_username", "")
                else:
                    client_info = self.connected_clients.get(sid)
                    if not client_info or not client_info.get('authenticated'):
                        await self.sio.emit('hps_transfer_ack', {'success': False, 'error': 'Not authenticated'}, room=sid)
                        return
                    client_identifier = client_info.get('client_identifier', '')
                    username = client_info.get('username', '')
                target_user = (data.get('target_user') or "").strip()
                amount = int(data.get('amount', 0))
                voucher_ids = data.get('voucher_ids', []) or []
                contract_content_b64 = data.get('contract_content')
                pow_nonce = data.get('pow_nonce', '')
                hashrate_observed = data.get('hashrate_observed', 0.0)
                hps_payment = data.get('hps_payment')
                if not target_user or amount <= 0:
                    await self.sio.emit('hps_transfer_ack', {'success': False, 'error': 'Invalid transfer data'}, room=sid)
                    return
                if not contract_content_b64:
                    await self.sio.emit('hps_transfer_ack', {'success': False, 'error': 'Missing contract content'}, room=sid)
                    return
                contract_content = base64.b64decode(contract_content_b64)
                valid, error_msg, contract_info = self.validate_contract_structure(contract_content)
                if not valid:
                    await self.sio.emit('hps_transfer_ack', {'success': False, 'error': f'Invalid contract: {error_msg}'}, room=sid)
                    return
                if contract_info['action'] != 'transfer_hps':
                    await self.sio.emit('hps_transfer_ack', {'success': False, 'error': 'Invalid contract action'}, room=sid)
                    return
                if contract_info['user'] != username:
                    await self.sio.emit('hps_transfer_ack', {'success': False, 'error': 'Contract user mismatch'}, room=sid)
                    return
                contract_vouchers = self.extract_contract_detail(contract_info, "VOUCHERS")
                if contract_vouchers:
                    try:
                        contract_list = json.loads(contract_vouchers)
                    except Exception:
                        await self.sio.emit('hps_transfer_ack', {'success': False, 'error': 'Invalid vouchers in contract'}, room=sid)
                        return
                    if set(contract_list) != set(voucher_ids):
                        await self.sio.emit('hps_transfer_ack', {'success': False, 'error': 'Contract vouchers mismatch'}, room=sid)
                        return
                if not self.verify_contract_signature(
                    contract_content=contract_content,
                    username=username,
                    signature=contract_info['signature']
                ):
                    if deferred:
                        await self.emit_to_user(username, 'hps_transfer_ack', {'success': False, 'error': 'Invalid contract signature'})
                    else:
                        await self.sio.emit('hps_transfer_ack', {'success': False, 'error': 'Invalid contract signature'}, room=sid)
                    return
                if not deferred:
                    ok, error, should_ban, pending_info = await self.authorize_pow_or_hps(
                        client_identifier=client_identifier,
                        username=username,
                        action_type="hps_transfer",
                        pow_nonce=pow_nonce,
                        hashrate_observed=hashrate_observed,
                        hps_payment=hps_payment
                    )
                    if not ok:
                        await self.sio.emit('hps_transfer_ack', {'success': False, 'error': error or 'Invalid PoW solution'}, room=sid)
                        if should_ban:
                            await self.ban_client(client_identifier, duration=300, reason="Invalid PoW solution")
                        return
                    if pending_info:
                        payload = {
                            "data": data,
                            "public_key": client_info.get("public_key"),
                            "payment": pending_info
                        }
                        self.create_pending_monetary_action(
                            pending_info.get("transfer_id", ""),
                            "transfer_hps",
                            username,
                            client_identifier,
                            payload,
                            "hps_transfer_ack"
                        )
                        await self.sio.emit('hps_transfer_ack',
                                            self.build_pending_monetary_ack(pending_info.get("transfer_id", "")),
                                            room=sid)
                        return
                contract_id = self.save_contract(
                    action_type="transfer_hps",
                    content_hash=None,
                    domain=None,
                    username=username,
                    signature=contract_info['signature'],
                    contract_content=contract_content
                )
                fee_amount, fee_source, adjusted_amount = self.allocate_signature_fee(amount)
                session, error = await self.create_hps_transfer_session(
                    payer=username,
                    target=target_user,
                    voucher_ids=voucher_ids,
                    amount=adjusted_amount
                )
                if not session:
                    await self.sio.emit('hps_transfer_ack', {'success': False, 'error': error}, room=sid)
                    return
                total_value = int(session.get("total_value") or 0)
                if total_value != amount and fee_source != "custody":
                    self.release_vouchers_for_session(session.get("session_id", ""))
                    self.delete_hps_transfer_session(session.get("session_id", ""))
                    await self.sio.emit('hps_transfer_ack', {
                        'success': False,
                        'error': 'Custodia sem saldo para cobrir taxas do troco'
                    }, room=sid)
                    return
                pending_transfer_id = self.create_pending_transfer(
                    transfer_type="hps_transfer",
                    target_user=target_user,
                    original_owner=username,
                    content_hash=None,
                    domain=None,
                    app_name=None,
                    contract_id=contract_id,
                    hps_amount=adjusted_amount,
                    hps_total_value=session.get("total_value"),
                    hps_voucher_ids=voucher_ids,
                    hps_session_id=session.get("session_id")
                )
                self.create_monetary_transfer(
                    transfer_type="hps_transfer",
                    sender=username,
                    receiver=target_user,
                    amount=adjusted_amount,
                    locked_voucher_ids=voucher_ids,
                    contract_id=contract_id,
                    fee_amount=fee_amount,
                    fee_source=fee_source
                )
                await self.send_hps_wallet_sync(username)
                self.notify_pending_transfers(target_user)
                fee_note = ""
                if fee_amount and fee_source == "receiver" and adjusted_amount < amount:
                    fee_note = f" (taxa do minerador: {fee_amount} HPS)"
                change_note = ""
                if total_value != amount:
                    change_note = " Troco será emitido pela custódia."
                response = {
                    'success': True,
                    'message': (
                        f'Transferência de {adjusted_amount} HPS enviada para {target_user}.{fee_note}{change_note} '
                        'Saldo reservado até confirmação do destinatário.'
                    ),
                    'transfer_id': pending_transfer_id
                }
                if deferred:
                    await self.emit_to_user(username, 'hps_transfer_ack', response)
                else:
                    await self.sio.emit('hps_transfer_ack', response, room=sid)
            except Exception as e:
                logger.error(f"HPS transfer error for {sid}: {e}")
                if data.get("_deferred_payment"):
                    await self.emit_to_user(data.get("_deferred_username", ""), 'hps_transfer_ack', {'success': False, 'error': str(e)})
                else:
                    await self.sio.emit('hps_transfer_ack', {'success': False, 'error': str(e)}, room=sid)

        @self.sio.event
        async def request_usage_contract(sid, data):
            try:
                if not self.connected_clients[sid].get('server_authenticated'):
                    await self.sio.emit('usage_contract_status', {'success': False, 'error': 'Server not authenticated'}, room=sid)
                    return
                username = (data.get('username') or "").strip()
                if not username:
                    await self.sio.emit('usage_contract_status', {'success': False, 'error': 'Missing username'}, room=sid)
                    return
                if username.lower() == CUSTODY_USERNAME:
                    await self.sio.emit('usage_contract_status', {
                        'success': False,
                        'error': 'O nome de usuário "custody" é de uso especial para a administração do servidor.'
                    }, room=sid)
                    return
                if self.user_needs_usage_contract(username):
                    await self.sio.emit('usage_contract_required', {
                        'contract_text': self.usage_contract_text,
                        'contract_hash': self.usage_contract_hash
                    }, room=sid)
                    return
                await self.sio.emit('usage_contract_status', {'success': True, 'required': False}, room=sid)
            except Exception as e:
                logger.error(f"Usage contract request error for {sid}: {e}")
                await self.sio.emit('usage_contract_status', {'success': False, 'error': str(e)}, room=sid)

        @self.sio.event
        async def accept_usage_contract(sid, data):
            try:
                deferred = data.get("_deferred_payment")
                if deferred:
                    client_identifier = data.get("_deferred_client_identifier", "")
                    username = data.get("_deferred_username", "") or data.get('username', '')
                else:
                    client_identifier = data.get('client_identifier') or self.connected_clients[sid].get('client_identifier') or ''
                    if not client_identifier:
                        await self.sio.emit('usage_contract_ack', {'success': False, 'error': 'Missing client identifier'}, room=sid)
                        return
                    username = data.get('username', '') or self.connected_clients[sid].get('username', '')
                pow_nonce = data.get('pow_nonce', '')
                hashrate_observed = data.get('hashrate_observed', 0.0)
                hps_payment = data.get('hps_payment')
                if not deferred:
                    ok, error, should_ban, pending_info = await self.authorize_pow_or_hps(
                        client_identifier=client_identifier,
                        username=username,
                        action_type="usage_contract",
                        pow_nonce=pow_nonce,
                        hashrate_observed=hashrate_observed,
                        hps_payment=hps_payment
                    )
                    if not ok:
                        await self.sio.emit('usage_contract_ack', {'success': False, 'error': error or 'Invalid PoW solution'}, room=sid)
                        if should_ban:
                            await self.ban_client(client_identifier, duration=300, reason="Invalid PoW solution")
                        return
                    if pending_info:
                        payload = {
                            "data": data,
                            "payment": pending_info
                        }
                        self.create_pending_monetary_action(
                            pending_info.get("transfer_id", ""),
                            "accept_usage_contract",
                            username,
                            client_identifier,
                            payload,
                            "usage_contract_ack"
                        )
                        await self.sio.emit('usage_contract_ack',
                                            self.build_pending_monetary_ack(pending_info.get("transfer_id", "")),
                                            room=sid)
                        return
                contract_content_b64 = data.get('contract_content')
                public_key_b64 = data.get('public_key')
                if not contract_content_b64:
                    await self.sio.emit('usage_contract_ack', {'success': False, 'error': 'Missing contract content'}, room=sid)
                    return
                if not public_key_b64:
                    await self.sio.emit('usage_contract_ack', {'success': False, 'error': 'Missing public key'}, room=sid)
                    return
                contract_bytes = base64.b64decode(contract_content_b64)
                valid, error_msg, contract_info = self.validate_contract_structure(contract_bytes)
                if not valid:
                    await self.sio.emit('usage_contract_ack', {'success': False, 'error': f'Invalid contract: {error_msg}'}, room=sid)
                    return
                if contract_info['action'] != "accept_usage":
                    await self.sio.emit('usage_contract_ack', {'success': False, 'error': 'Invalid usage contract action'}, room=sid)
                    return
                username = contract_info['user']
                stored_key = self.get_registered_public_key(username)
                if stored_key and stored_key != public_key_b64:
                    self.remove_usage_contract_for_user(username)
                    await self.sio.emit('usage_contract_ack', {
                        'success': False,
                        'error': 'Chave Pública inválida, utilize sua chave pública inicial na aba de configurações'
                    }, room=sid)
                    return
                if not self.verify_contract_signature(
                    contract_content=contract_bytes,
                    username=username,
                    signature=contract_info['signature'],
                    public_key_pem=public_key_b64
                ):
                    await self.sio.emit('usage_contract_ack', {'success': False, 'error': 'Invalid contract signature'}, room=sid)
                    return
                contract_text = contract_bytes.decode('utf-8', errors='replace')
                expected_marker = f"# USAGE_CONTRACT_HASH: {self.usage_contract_hash}"
                if expected_marker not in contract_text:
                    await self.sio.emit('usage_contract_ack', {'success': False, 'error': 'Usage contract version mismatch'}, room=sid)
                    return

                self.save_contract(
                    action_type="accept_usage",
                    content_hash=None,
                    domain=None,
                    username=username,
                    signature=contract_info['signature'],
                    contract_content=contract_bytes
                )
                self.store_usage_contract_acceptance(username)
                await self.sio.emit('usage_contract_ack', {'success': True}, room=sid)
            except Exception as e:
                logger.error(f"Usage contract error for {sid}: {e}")
                await self.sio.emit('usage_contract_ack', {'success': False, 'error': str(e)}, room=sid)

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
                with get_db_conn(self.db_path) as conn:
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
                        with get_db_conn(self.db_path) as conn:
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
                with get_db_conn(self.db_path) as conn:
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
                deferred = data.get("_deferred_payment")
                if deferred:
                    client_info = {}
                    client_identifier = data.get("_deferred_client_identifier", "")
                    username = data.get("_deferred_username", "")
                    node_id = data.get("_deferred_node_id", "")
                else:
                    client_info = self.connected_clients.get(sid)
                    if not client_info:
                        logger.warning(f"Publish requested for disconnected client: {sid}")
                        return
                    if not client_info.get('authenticated'):
                        await self.sio.emit('publish_result', {'success': False, 'error': 'Not authenticated'}, room=sid)
                        return
                    client_identifier = client_info['client_identifier']
                    username = client_info['username']
                    node_id = client_info.get('node_id', '')
                content_hash = data.get('content_hash')
                title = data.get('title') or ''
                description = data.get('description', '')
                mime_type = data.get('mime_type')
                size = data.get('size')
                signature = data.get('signature')
                public_key_b64 = data.get('public_key')
                content_b64 = data.get('content_b64')
                live_session_id = None
                is_live = False
                live_session = None
                app_name = self.extract_app_name(title) if title.startswith('(HPS!api)') else None

                if not is_live:
                    pow_nonce = data.get('pow_nonce', '')
                    hashrate_observed = data.get('hashrate_observed', 0.0)
                    hps_payment = data.get('hps_payment')
                    allowed, message, remaining_time = self.check_rate_limit(client_identifier, "upload")
                    if not allowed:
                        violation_count = self.increment_violation(client_identifier)
                        if violation_count >= 3:
                            await self.ban_client(client_identifier, duration=300, reason="Multiple rate limit violations")
                        await self.sio.emit('publish_result', {'success': False, 'error': message, 'blocked_until': time.time() + remaining_time}, room=sid)
                        return
                    if not deferred:
                        ok, error, should_ban, pending_info = await self.authorize_pow_or_hps(
                            client_identifier=client_identifier,
                            username=username,
                            action_type="upload",
                            pow_nonce=pow_nonce,
                            hashrate_observed=hashrate_observed,
                            hps_payment=hps_payment
                        )
                        if not ok:
                            await self.sio.emit('publish_result', {'success': False, 'error': error or 'Invalid PoW solution'}, room=sid)
                            if should_ban:
                                await self.ban_client(client_identifier, duration=300, reason="Invalid PoW solution")
                            return
                        if pending_info:
                            payload = {
                                "data": data,
                                "node_id": node_id,
                                "payment": pending_info
                            }
                            self.create_pending_monetary_action(
                                pending_info.get("transfer_id", ""),
                                "publish_content",
                                username,
                                client_identifier,
                                payload,
                                "publish_result"
                            )
                            await self.sio.emit('publish_result',
                                                self.build_pending_monetary_ack(pending_info.get("transfer_id", "")),
                                                room=sid)
                            return
                if not all([content_hash, title, mime_type, size, signature, public_key_b64, content_b64]):
                    if is_live:
                        await reject_live("missing_required_fields")
                    else:
                        await self.sio.emit('publish_result', {'success': False, 'error': 'Missing required fields'}, room=sid)
                    return
                try:
                    content = base64.b64decode(content_b64)
                except Exception as e:
                    if is_live:
                        await reject_live("invalid_base64_content")
                    else:
                        await self.sio.emit('publish_result', {'success': False, 'error': 'Invalid base64 content'}, room=sid)
                    return

                # Extrai e valida contrato do conteúdo
                content_without_contract, contract_content = self.extract_contract_from_content(content)
                if not contract_content:
                    if is_live:
                        await reject_live("missing_contract")
                    else:
                        await self.sio.emit('publish_result', {'success': False, 'error': 'Contrato obrigatório não encontrado'}, room=sid)
                    return

                valid, error_msg, contract_info = self.validate_contract_structure(contract_content)
                if not valid:
                    if is_live:
                        await reject_live("invalid_contract")
                    else:
                        await self.sio.emit('publish_result', {
                            'success': False,
                            'error': f'Contrato inválido: {error_msg}\n\nExemplo de contrato válido:\n' +
                                    '# HSYST P2P SERVICE\n' +
                                    '## CONTRACT:\n' +
                                    '### DETAILS:\n' +
                                    '# ACTION: upload_file\n' +
                                    '### :END DETAILS\n' +
                                    '### START:\n' +
                                    f'# USER: {username}\n' +
                                    f'# SIGNATURE: [sua assinatura aqui]\n' +
                                    '### :END START\n' +
                                    '## :END CONTRACT'
                        }, room=sid)
                    return

                allowed_actions = {"upload_file"}
                if title == '(HPS!dns_change){change_dns_owner=true, proceed=true}':
                    allowed_actions.add("transfer_domain")
                transfer_title_type, transfer_title_target, transfer_title_app = self.parse_transfer_title(title)
                if transfer_title_type == "file":
                    allowed_actions.add("transfer_content")
                elif transfer_title_type == "api_app":
                    allowed_actions.add("transfer_api_app")
                if title.startswith('(HPS!api)'):
                    allowed_actions.add("change_api_app")

                if contract_info['action'] not in allowed_actions:
                    if is_live:
                        await reject_live("invalid_contract_action")
                    else:
                        await self.sio.emit('publish_result', {
                            'success': False,
                            'error': f'Ação do contrato inválida para este upload: {contract_info["action"]}'
                        }, room=sid)
                    return

                if contract_info['user'] != username:
                    if is_live:
                        await reject_live("contract_user_mismatch")
                    else:
                        await self.sio.emit('publish_result', {
                            'success': False,
                            'error': f'Usuário no contrato ({contract_info["user"]}) não corresponde ao usuário atual ({username})'
                        }, room=sid)
                    return

                public_key_override = self.extract_contract_detail(contract_info, "PUBLIC_KEY") or public_key_b64
                if not self.verify_contract_signature(
                    contract_content=contract_content,
                    username=username,
                    signature=contract_info['signature'],
                    public_key_pem=public_key_override
                ):
                    if is_live:
                        await reject_live("invalid_contract_signature")
                    else:
                        await self.sio.emit('publish_result', {
                            'success': False,
                            'error': 'Assinatura do contrato inválida'
                        }, room=sid)
                    return

                contract_saved = False

                # Usa conteúdo sem contrato para hash e armazenamento
                content = content_without_contract
                actual_hash = hashlib.sha256(content).hexdigest()
                if actual_hash != content_hash:
                    if is_live:
                        await reject_live("content_hash_mismatch")
                    else:
                        await self.sio.emit('publish_result', {
                            'success': False,
                            'error': 'Hash do conteúdo (sem contrato) não corresponde ao hash fornecido'
                        }, room=sid)
                    return

                transfer_to = self.extract_contract_detail(contract_info, "TRANSFER_TO")
                transfer_type = self.extract_contract_detail(contract_info, "TRANSFER_TYPE")
                declared_file_hash = self.extract_contract_detail(contract_info, "FILE_HASH") or self.extract_contract_detail(contract_info, "CONTENT_HASH")
                if contract_info['action'] in ("transfer_content", "transfer_api_app", "transfer_domain"):
                    if not transfer_to:
                        await self.sio.emit('publish_result', {'success': False, 'error': 'Missing transfer target in contract'}, room=sid)
                        return
                    if transfer_type and transfer_type not in ("file", "content", "api_app", "domain"):
                        await self.sio.emit('publish_result', {'success': False, 'error': 'Invalid transfer type in contract'}, room=sid)
                        return
                if contract_info['action'] == "transfer_content":
                    if not declared_file_hash:
                        await self.sio.emit('publish_result', {'success': False, 'error': 'Missing FILE_HASH in contract'}, room=sid)
                        return
                    if declared_file_hash != actual_hash:
                        await self.sio.emit('publish_result', {'success': False, 'error': 'FILE_HASH does not match content hash'}, room=sid)
                        return

                pending_notify_targets = []
                for attempt in range(5):
                    try:
                        with get_db_conn(self.db_path) as conn:
                            cursor = conn.cursor()
                            if contract_info['action'] == "transfer_content":
                                cursor.execute('SELECT username FROM content WHERE content_hash = ?', (content_hash,))
                                row = cursor.fetchone()
                                if not row:
                                    await self.sio.emit('publish_result', {'success': False, 'error': 'Content not found for transfer'}, room=sid)
                                    return
                                owner_username = row[0]
                                if owner_username != username:
                                    pending_match = self.get_pending_transfer_for_user_conn(
                                        cursor,
                                        username,
                                        "content",
                                        content_hash=content_hash
                                    )
                                    if not pending_match:
                                        await self.sio.emit('publish_result', {'success': False, 'error': 'Only the content owner can transfer this content'}, room=sid)
                                        return
                            if contract_info['action'] == "transfer_api_app":
                                app_name = self.extract_contract_detail(contract_info, "APP")
                                if not app_name:
                                    await self.sio.emit('publish_result', {'success': False, 'error': 'Missing API app name for transfer'}, room=sid)
                                    return
                                cursor.execute('SELECT username FROM api_apps WHERE app_name = ?', (app_name,))
                                row = cursor.fetchone()
                                if not row:
                                    await self.sio.emit('publish_result', {'success': False, 'error': 'API app not found for transfer'}, room=sid)
                                    return
                                owner_username = row[0]
                                if owner_username != username:
                                    pending_match = self.get_pending_transfer_for_user_conn(
                                        cursor,
                                        username,
                                        "api_app",
                                        app_name=app_name
                                    )
                                    if not pending_match:
                                        await self.sio.emit('publish_result', {'success': False, 'error': 'Only the API app owner can transfer this app'}, room=sid)
                                        return

                            if title.startswith('(HPS!api)'):
                                app_name = self.extract_app_name(title)
                                if app_name:
                                    success, message = self.process_app_update({'title': title}, cursor, username, content_hash)
                                    if not success:
                                        if is_live:
                                            await reject_live("api_app_update_failed")
                                        else:
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
                                    contract_domain = self.extract_contract_detail(contract_info, "DOMAIN")
                                    if contract_domain and contract_domain != domain:
                                        await self.sio.emit('publish_result', {'success': False, 'error': 'Domain mismatch between contract and DNS change file'}, room=sid)
                                        return
                                    if not transfer_to:
                                        transfer_to = new_owner
                                    if not transfer_type:
                                        transfer_type = "domain"
                                    cursor.execute('SELECT username, original_owner FROM dns_records WHERE domain = ?', (domain,))
                                    dns_record = cursor.fetchone()
                                    if not dns_record:
                                        await self.sio.emit('publish_result', {'success': False, 'error': f'Domain {domain} not found'}, room=sid)
                                        return
                                    current_owner, original_owner = dns_record
                                    if current_owner not in (username, CUSTODY_USERNAME, "system"):
                                        await self.sio.emit('publish_result', {
                                            'success': False,
                                            'error': f'You are not the current owner of domain {domain}. Current owner: {current_owner}'
                                        }, room=sid)
                                        return
                                    pending_match = None
                                    if transfer_to and username == transfer_to:
                                        pending_items = self.get_pending_transfers_for_user(transfer_to)
                                        for item in pending_items:
                                            if item['transfer_type'] == "domain" and item.get('domain') == domain:
                                                pending_match = item
                                                break
                                        if not pending_match and new_owner and new_owner != username:
                                            transfer_to = new_owner
                                    if transfer_to and username != transfer_to:
                                        cursor.execute('UPDATE dns_records SET username = ? WHERE domain = ?', (CUSTODY_USERNAME, domain))
                                        change_id = str(uuid.uuid4())
                                        cursor.execute('INSERT INTO dns_owner_changes (change_id, domain, previous_owner, new_owner, changer, timestamp, change_file_hash) VALUES (?, ?, ?, ?, ?, ?, ?)',
                                                       (change_id, domain, current_owner, CUSTODY_USERNAME, username, time.time(), content_hash))
                                        conn.commit()
                                        logger.info(f"DNS moved to custody: {domain} from {current_owner} to {CUSTODY_USERNAME} for {transfer_to}")
                                    elif transfer_to and username == transfer_to:
                                        if not pending_match:
                                            await self.sio.emit('publish_result', {'success': False, 'error': 'No pending transfer for this domain'}, room=sid)
                                            return
                                        cursor.execute('UPDATE dns_records SET username = ?, original_owner = ? WHERE domain = ?',
                                                       (transfer_to, transfer_to, domain))
                                        change_id = str(uuid.uuid4())
                                        cursor.execute('INSERT INTO dns_owner_changes (change_id, domain, previous_owner, new_owner, changer, timestamp, change_file_hash) VALUES (?, ?, ?, ?, ?, ?, ?)',
                                                       (change_id, domain, current_owner, transfer_to, username, time.time(), content_hash))
                                        conn.commit()
                                        self.delete_pending_transfer_conn(cursor, pending_match['transfer_id'])
                                        logger.info(f"DNS ownership transferred: {domain} from {current_owner} to {transfer_to} by {username}")
                                    
                                    # Salva contrato de transferência
                                    if contract_content:
                                        transfer_contract_id = self.save_contract(
                                            action_type=contract_info['action'],
                                            content_hash=content_hash,
                                            domain=domain,
                                            username=username,
                                            signature=contract_info['signature'],
                                            contract_content=contract_content,
                                            conn=conn
                                        )
                                        contract_saved = True
                                        if transfer_to and username != transfer_to:
                                            self.create_pending_transfer(
                                                transfer_type="domain",
                                                target_user=transfer_to,
                                                original_owner=username,
                                                content_hash=content_hash,
                                                domain=domain,
                                                app_name=None,
                                                contract_id=transfer_contract_id,
                                                conn=conn
                                            )
                                            pending_notify_targets.append(transfer_to)
                                except Exception as e:
                                    logger.error(f"DNS change processing error: {e}")
                                    await self.sio.emit('publish_result', {'success': False, 'error': f'DNS change processing error: {str(e)}'}, room=sid)
                                    return

                            file_path = os.path.join(self.files_dir, f"{content_hash}.dat")
                            try:
                                async with aiofiles.open(file_path, 'wb') as f:
                                    await f.write(content)
                            except Exception as e:
                                if is_live:
                                    await reject_live("file_save_error")
                                else:
                                    await self.sio.emit('publish_result', {'success': False, 'error': f'Error saving file: {str(e)}'}, room=sid)
                                return

                            cursor.execute('SELECT COUNT(*) FROM content WHERE username = ?', (username,))
                            content_count = cursor.fetchone()[0]
                            if content_count >= self.max_content_per_user:
                                if is_live:
                                    await reject_live("content_limit_reached")
                                else:
                                    await self.sio.emit('publish_result', {'success': False, 'error': f'Maximum content limit reached ({self.max_content_per_user})'}, room=sid)
                                if os.path.exists(file_path):
                                    os.remove(file_path)
                                return
                            cursor.execute('SELECT disk_quota, used_disk_space FROM users WHERE username = ?', (username,))
                            user_quota_row = cursor.fetchone()
                            if user_quota_row:
                                disk_quota, used_disk_space = user_quota_row
                                if (used_disk_space + size) > disk_quota:
                                    if is_live:
                                        await reject_live("disk_quota_exceeded")
                                    else:
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
                                           (content_hash, node_id, time.time(), 1))
                            cursor.execute('UPDATE users SET used_disk_space = used_disk_space + ? WHERE username = ?', (size, username))
                            
                            # Salva contrato se existir
                            if contract_content and not contract_saved:
                                transfer_contract_id = self.save_contract(
                                    action_type=contract_info['action'],
                                    content_hash=content_hash,
                                    username=username,
                                    signature=contract_info['signature'],
                                    contract_content=contract_content,
                                    conn=conn
                                )
                                if contract_info['action'] in ("transfer_content", "transfer_api_app"):
                                    if contract_info['action'] == "transfer_content":
                                        transfer_type = "content"
                                    else:
                                        transfer_type = "api_app"
                                    if contract_info['action'] == "transfer_api_app":
                                        app_name = self.extract_contract_detail(contract_info, "APP")
                                        if not app_name:
                                            await self.sio.emit('publish_result', {'success': False, 'error': 'Missing API app name for transfer'}, room=sid)
                                            return
                                    else:
                                        app_name = None
                                    if username != transfer_to:
                                        if contract_info['action'] == "transfer_api_app":
                                            cursor.execute('UPDATE api_apps SET username = ? WHERE app_name = ?', (CUSTODY_USERNAME, app_name))
                                        else:
                                            cursor.execute('UPDATE content SET username = ? WHERE content_hash = ?', (CUSTODY_USERNAME, content_hash))
                                        self.create_pending_transfer(
                                            transfer_type=transfer_type,
                                            target_user=transfer_to,
                                            original_owner=username,
                                            content_hash=content_hash,
                                            domain=None,
                                            app_name=app_name,
                                            contract_id=transfer_contract_id,
                                            conn=conn
                                        )
                                        pending_notify_targets.append(transfer_to)
                                    else:
                                        matched = self.get_pending_transfer_for_user_conn(
                                            cursor,
                                            transfer_to,
                                            transfer_type,
                                            content_hash=content_hash if transfer_type == "content" else None,
                                            app_name=app_name if transfer_type == "api_app" else None
                                        )
                                        if not matched:
                                            await self.sio.emit('publish_result', {'success': False, 'error': 'No pending transfer for this content'}, room=sid)
                                            return
                                        self.delete_pending_transfer_conn(cursor, matched['transfer_id'])
                                        if contract_info['action'] == "transfer_api_app":
                                            cursor.execute('UPDATE api_apps SET username = ? WHERE app_name = ?', (transfer_to, app_name))
                                        else:
                                            cursor.execute('UPDATE content SET username = ? WHERE content_hash = ?', (transfer_to, content_hash))
                            
                            conn.commit()
                        break
                    except sqlite3.OperationalError as e:
                        if "locked" in str(e).lower() and attempt < 4:
                            await asyncio.sleep(0.5 * (attempt + 1))
                            continue
                        raise
                await self.sio.emit('publish_result', {
                    'success': True,
                    'content_hash': content_hash,
                    'verified': 1
                }, room=sid)
                for target in set(pending_notify_targets):
                    pending = self.get_pending_transfers_for_user(target)
                    for target_sid, client in self.connected_clients.items():
                        if client.get('username') == target:
                            await self.sio.emit('pending_transfers', {'transfers': pending}, room=target_sid)
                            await self.sio.emit('pending_transfer_notice', {'count': len(pending)}, room=target_sid)
                if not is_live:
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
                allow_legacy = data.get('allow_legacy', False)
                if not content_hash:
                    await self.sio.emit('content_response', {'error': 'Missing content hash'}, room=sid)
                    return

                redirected_hash = self.get_redirected_hash(content_hash)
                if redirected_hash and not allow_legacy:
                    # Verifica se é um API App atualizado
                    with get_db_conn(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT app_name FROM api_apps WHERE content_hash = ?', (redirected_hash,))
                        app_row = cursor.fetchone()
                        if app_row:
                            # Obtém contratos de alteração
                            contracts = self.get_contracts_for_content(redirected_hash)
                            change_contracts = [c for c in contracts if c['action_type'] == 'change_api_app']
                            
                            await self.sio.emit('content_response', {
                                'success': True,
                                'content': base64.b64encode(json.dumps({
                                    'message': 'API App atualizado',
                                    'new_hash': redirected_hash,
                                    'app_name': app_row[0],
                                    'change_contracts': change_contracts[:3]  # Últimas 3 alterações
                                }).encode('utf-8')).decode('utf-8'),
                                'title': 'API App Atualizado',
                                'description': f'Este API App foi atualizado para o hash {redirected_hash[:16]}...',
                                'mime_type': 'application/json',
                                'username': 'system',
                                'signature': '',
                                'public_key': '',
                                'verified': 0,
                                'content_hash': content_hash,
                                'reputation': 0,
                                'is_api_app_update': True
                            }, room=sid)
                            return
                    
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
                with get_db_conn(self.db_path) as conn:
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
                    with get_db_conn(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('''SELECT title, description, mime_type, username, signature, public_key, verified, size
                            FROM content WHERE content_hash = ?''', (content_hash,))
                        content_metadata = cursor.fetchone()
                if not content_metadata:
                    await self.sio.emit('content_response', {'success': False, 'error': 'Content metadata not found'}, room=sid)
                    return
                try:
                    contract_violation, violation_reason, contracts = self.evaluate_contract_violation_for_content(content_hash)
                    certification = self.get_contract_certification("content", content_hash)
                    if contract_violation:
                        await self.sio.emit('content_response', {
                            'success': False,
                            'error': 'contract_violation',
                            'contract_violation_reason': violation_reason,
                            'content_hash': content_hash,
                            'contracts': contracts,
                            'original_owner': certification['original_owner'] if certification else "",
                            'certifier': certification['certifier'] if certification else ""
                        }, room=sid)
                        return
                    async with aiofiles.open(file_path, 'rb') as f:
                        content = await f.read()
                    with get_db_conn(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('UPDATE content SET last_accessed = ?, replication_count = replication_count + 1 WHERE content_hash = ?',
                                       (time.time(), content_hash))
                        conn.commit()
                    title, description, mime_type, username, signature, public_key, verified, size = content_metadata
                    if username in (CUSTODY_USERNAME, "system"):
                        with get_db_conn(self.db_path) as conn:
                            cursor = conn.cursor()
                            cursor.execute('''SELECT original_owner FROM pending_transfers
                                              WHERE content_hash = ? AND status = 'pending' ORDER BY timestamp DESC LIMIT 1''',
                                           (content_hash,))
                            row = cursor.fetchone()
                            if row:
                                username = row[0]
                    
                    await self.sio.emit('content_response', {
                        'success': True, 
                        'content': base64.b64encode(content).decode('utf-8'), 
                        'title': title,
                        'description': description, 
                        'mime_type': mime_type, 
                        'username': username, 
                        'signature': signature,
                        'public_key': public_key, 
                        'verified': verified, 
                        'content_hash': content_hash,
                        'reputation': self.get_user_reputation(username),
                        'contracts': contracts,
                        'contract_violation': False,
                        'contract_violation_reason': "",
                        'original_owner': certification['original_owner'] if certification else username,
                        'certifier': certification['certifier'] if certification else ""
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
                deferred = data.get("_deferred_payment")
                if deferred:
                    client_info = {}
                    client_identifier = data.get("_deferred_client_identifier", "")
                    username = data.get("_deferred_username", "")
                else:
                    if not self.connected_clients[sid]['authenticated']:
                        await self.sio.emit('dns_result', {'success': False, 'error': 'Not authenticated'}, room=sid)
                        return
                    client_info = self.connected_clients[sid]
                    client_identifier = client_info['client_identifier']
                    username = client_info['username']
                pow_nonce = data.get('pow_nonce', '')
                hashrate_observed = data.get('hashrate_observed', 0.0)
                hps_payment = data.get('hps_payment')
                allowed, message, remaining_time = self.check_rate_limit(client_identifier, "dns")
                if not allowed:
                    violation_count = self.increment_violation(client_identifier)
                    if violation_count >= 3:
                        await self.ban_client(client_identifier, duration=300, reason="Multiple rate limit violations")
                    await self.sio.emit('dns_result', {'success': False, 'error': message, 'blocked_until': time.time() + remaining_time}, room=sid)
                    return
                if not deferred:
                    ok, error, should_ban, pending_info = await self.authorize_pow_or_hps(
                        client_identifier=client_identifier,
                        username=username,
                        action_type="dns",
                        pow_nonce=pow_nonce,
                        hashrate_observed=hashrate_observed,
                        hps_payment=hps_payment
                    )
                    if not ok:
                        await self.sio.emit('dns_result', {'success': False, 'error': error or 'Invalid PoW solution'}, room=sid)
                        if should_ban:
                            await self.ban_client(client_identifier, duration=300, reason="Invalid PoW solution")
                        return
                    if pending_info:
                        payload = {
                            "data": data,
                            "payment": pending_info
                        }
                        self.create_pending_monetary_action(
                            pending_info.get("transfer_id", ""),
                            "register_dns",
                            username,
                            client_identifier,
                            payload,
                            "dns_result"
                        )
                        await self.sio.emit('dns_result',
                                            self.build_pending_monetary_ack(pending_info.get("transfer_id", "")),
                                            room=sid)
                        return
                domain = data.get('domain', '').lower().strip()
                ddns_content_b64 = data.get('ddns_content', '')
                signature = data.get('signature', '')
                public_key_b64 = data.get('public_key') or client_info.get('public_key') or self.get_user_public_key(username)
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
                content_without_contract, contract_content = self.extract_contract_from_content(ddns_content)
                if not contract_content:
                    await self.sio.emit('dns_result', {'success': False, 'error': 'Contrato obrigatório não encontrado no DDNS'}, room=sid)
                    return
                valid, error_msg, contract_info = self.validate_contract_structure(contract_content)
                if not valid:
                    await self.sio.emit('dns_result', {'success': False, 'error': f'Contrato inválido: {error_msg}'}, room=sid)
                    return
                if contract_info['action'] != 'register_dns':
                    await self.sio.emit('dns_result', {'success': False, 'error': f"Ação do contrato inválida: {contract_info['action']}"}, room=sid)
                    return
                if contract_info['user'] != username:
                    await self.sio.emit('dns_result', {'success': False, 'error': 'Usuário no contrato não corresponde ao usuário atual'}, room=sid)
                    return
                public_key_override = self.extract_contract_detail(contract_info, "PUBLIC_KEY") or public_key_b64
                if not self.verify_contract_signature(
                    contract_content=contract_content,
                    username=username,
                    signature=contract_info['signature'],
                    public_key_pem=public_key_override
                ):
                    await self.sio.emit('dns_result', {'success': False, 'error': 'Assinatura do contrato inválida'}, room=sid)
                    return
                
                ddns_content = content_without_contract
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
                    if not public_key_b64:
                        raise ValueError("public_key")
                    public_key_obj = serialization.load_pem_public_key(base64.b64decode(public_key_b64), backend=default_backend())
                    signature_bytes = base64.b64decode(signature)
                    public_key_obj.verify(signature_bytes, ddns_data_signed,
                                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                    verified = 1
                except InvalidSignature:
                    verified = 0
                    logger.warning(f"Invalid signature for DNS {domain} by {username}")
                    with get_db_conn(self.db_path) as conn:
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
                with get_db_conn(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT username, original_owner FROM dns_records WHERE domain = ?', (domain,))
                    existing_record = cursor.fetchone()
                    if existing_record:
                        existing_owner = existing_record[0]
                        if existing_owner in (CUSTODY_USERNAME, "system"):
                            cursor.execute('''SELECT COUNT(*) FROM pending_transfers
                                              WHERE domain = ? AND status = 'pending' ''', (domain,))
                            pending_count = cursor.fetchone()[0]
                            if pending_count > 0:
                                await self.sio.emit('dns_result', {
                                    'success': False,
                                    'error': f'Domain "{domain}" esta sob custodia com transferencia pendente.'
                                }, room=sid)
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
content_hash = ?, username = ?, original_owner = ?, timestamp = ?, signature = ?, verified = ?, last_resolved = ?, ddns_hash = ?
                                WHERE domain = ?''',
                                (content_hash, username, username, time.time(), signature, verified, time.time(), ddns_hash, domain))
                        elif existing_owner != username:
                            await self.sio.emit('dns_result', {
                                'success': False,
                                'error': f'Domain "{domain}" is already registered by {existing_owner}. Domains are non-transferable via regular registration.'
                            }, room=sid)
                            violation_count = self.increment_violation(client_identifier)
                            if violation_count >= 3:
                                await self.ban_client(client_identifier, duration=600, reason="Multiple domain takeover attempts")
                            return
                        else:
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
                    
                    # Salva contrato do DNS
                    contract_id = self.save_contract(
                        action_type='register_dns',
                        domain=domain,
                        username=username,
                        signature=contract_info['signature'],
                        contract_content=contract_content,
                        conn=conn
                    )
                    
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

                with get_db_conn(self.db_path) as conn:
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
                        
                        contracts = []
                        certification = None
                        contract_violation = False
                        violation_reason = ""
                        for attempt in range(3):
                            try:
                                contract_violation, violation_reason, contracts = self.evaluate_contract_violation_for_domain(domain)
                                certification = self.get_contract_certification("domain", domain)
                                break
                            except sqlite3.OperationalError as e:
                                if "locked" in str(e).lower() and attempt < 2:
                                    await asyncio.sleep(0.3 * (attempt + 1))
                                    continue
                                raise
                        if resolved_data['username'] in (CUSTODY_USERNAME, "system") and not certification:
                            with get_db_conn(self.db_path) as conn:
                                cursor = conn.cursor()
                                cursor.execute('''SELECT original_owner FROM pending_transfers
                                                  WHERE domain = ? AND status = 'pending' ORDER BY timestamp DESC LIMIT 1''',
                                               (domain,))
                                row = cursor.fetchone()
                                if row:
                                    resolved_data['original_owner'] = row[0]

                        if contract_violation:
                            await self.sio.emit('dns_resolution', {
                                'success': False,
                                'error': 'contract_violation',
                                'contract_violation_reason': violation_reason,
                                'domain': domain,
                                'content_hash': resolved_data['content_hash'],
                                'contracts': contracts,
                                'original_owner': resolved_data['original_owner'],
                                'certifier': certification['certifier'] if certification else ""
                            }, room=sid)
                            return
                        
                        await self.sio.emit('dns_resolution', {
                            'success': True, 
                            'domain': domain, 
                            'content_hash': resolved_data['content_hash'],
                            'username': resolved_data['username'], 
                            'verified': resolved_data['verified'],
                            'original_owner': resolved_data['original_owner'],
                            'contracts': contracts,
                            'contract_violation': False,
                            'contract_violation_reason': "",
                            'certifier': certification['certifier'] if certification else ""
                        }, room=sid)
                    else:
                        await self.sio.emit('dns_resolution', {'success': False, 'error': 'DDNS file not available'}, room=sid)
                else:
                    logger.info(f"Domain {domain} not found locally, searching network.")
                    await self.sio.emit('dns_search_status', {'status': 'searching_network', 'domain': domain}, room=sid)
                    resolved = await self.resolve_dns_from_network(domain)
                    if resolved and resolved.get('success'):
                        await self.sio.emit('dns_resolution', {
                            'success': True, 
                            'domain': domain, 
                            'content_hash': resolved['content_hash'],
                            'username': resolved['username'], 
                            'verified': resolved['verified'],
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
                deferred = data.get("_deferred_payment")
                if deferred:
                    client_info = {}
                    client_identifier = data.get("_deferred_client_identifier", "")
                    reporter = data.get("_deferred_username", "")
                else:
                    if not self.connected_clients[sid]['authenticated']:
                        await self.sio.emit('report_result', {'success': False, 'error': 'Not authenticated'}, room=sid)
                        return
                    client_info = self.connected_clients[sid]
                    client_identifier = client_info['client_identifier']
                    reporter = client_info['username']
                pow_nonce = data.get('pow_nonce', '')
                hashrate_observed = data.get('hashrate_observed', 0.0)
                hps_payment = data.get('hps_payment')
                if not deferred:
                    ok, error, should_ban, pending_info = await self.authorize_pow_or_hps(
                        client_identifier=client_identifier,
                        username=reporter,
                        action_type="report",
                        pow_nonce=pow_nonce,
                        hashrate_observed=hashrate_observed,
                        hps_payment=hps_payment
                    )
                    if not ok:
                        await self.sio.emit('report_result', {'success': False, 'error': error or 'Invalid PoW solution'}, room=sid)
                        if should_ban:
                            await self.ban_client(client_identifier, duration=300, reason="Invalid PoW solution")
                        return
                    if pending_info:
                        payload = {
                            "data": data,
                            "payment": pending_info
                        }
                        self.create_pending_monetary_action(
                            pending_info.get("transfer_id", ""),
                            "report_content",
                            reporter,
                            client_identifier,
                            payload,
                            "report_result"
                        )
                        await self.sio.emit('report_result',
                                            self.build_pending_monetary_ack(pending_info.get("transfer_id", "")),
                                            room=sid)
                        return
                content_hash = data.get('content_hash')
                reported_user = data.get('reported_user')
                contract_content_b64 = data.get('contract_content')
                if not content_hash or not reported_user:
                    await self.sio.emit('report_result', {'success': False, 'error': 'Missing hash or user'}, room=sid)
                    return
                if not contract_content_b64:
                    await self.sio.emit('report_result', {'success': False, 'error': 'Contrato obrigatório não encontrado'}, room=sid)
                    return
                try:
                    contract_content = base64.b64decode(contract_content_b64)
                except Exception:
                    await self.sio.emit('report_result', {'success': False, 'error': 'Contrato inválido (base64)'}, room=sid)
                    return
                valid, error_msg, contract_info = self.validate_contract_structure(contract_content)
                if not valid:
                    await self.sio.emit('report_result', {'success': False, 'error': f'Contrato inválido: {error_msg}'}, room=sid)
                    return
                if contract_info['action'] != 'report_content':
                    await self.sio.emit('report_result', {'success': False, 'error': f"Ação do contrato inválida: {contract_info['action']}"}, room=sid)
                    return
                if contract_info['user'] != reporter:
                    await self.sio.emit('report_result', {'success': False, 'error': 'Usuário no contrato não corresponde ao usuário atual'}, room=sid)
                    return
                if not self.verify_contract_signature(
                    contract_content=contract_content,
                    username=reporter,
                    signature=contract_info['signature']
                ):
                    await self.sio.emit('report_result', {'success': False, 'error': 'Assinatura do contrato inválida'}, room=sid)
                    return
                if reporter == reported_user:
                    await self.sio.emit('report_result', {'success': False, 'error': 'Cannot report your own content'}, room=sid)
                    return
                report_id = str(uuid.uuid4())
                with get_db_conn(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''INSERT INTO content_reports
(report_id, content_hash, reported_user, reporter, timestamp)
                        VALUES (?, ?, ?, ?, ?)''',
                        (report_id, content_hash, reported_user, reporter, time.time()))
                    conn.commit()
                await self.sio.emit('report_result', {'success': True}, room=sid)
                logger.info(f"Content reported: {content_hash} by {reporter} against {reported_user}")
                self.save_contract(
                    action_type='report_content',
                    content_hash=content_hash,
                    username=reporter,
                    signature=contract_info['signature'],
                    contract_content=contract_content
                )
                await self.process_content_report(report_id, content_hash, reported_user, reporter)
            except Exception as e:
                logger.error(f"Content report error for {sid}: {e}")
                await self.sio.emit('report_result', {'success': False, 'error': f'Internal server error: {str(e)}'}, room=sid)

        @self.sio.event
        async def get_network_state(sid, data):
            try:
                with get_db_conn(self.db_path) as conn:
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
                with get_db_conn(self.db_path) as conn:
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
                with get_db_conn(self.db_path) as conn:
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
                with get_db_conn(self.db_path) as conn:
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
                with get_db_conn(self.db_path) as conn:
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
                with get_db_conn(self.db_path) as conn:
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
        async def sync_client_contracts(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']: return
                client_identifier = self.connected_clients[sid]['client_identifier']
                contracts = data.get('contracts', [])
                with get_db_conn(self.db_path) as conn:
                    cursor = conn.cursor()
                    for contract_info in contracts:
                        contract_id = contract_info['contract_id']
                        content_hash = contract_info.get('content_hash')
                        domain = contract_info.get('domain')
                        if (content_hash or domain) and not self.should_sync_contract_target(content_hash, domain):
                            continue
                        cursor.execute('INSERT OR REPLACE INTO client_contracts (client_identifier, contract_id, last_sync) VALUES (?, ?, ?)',
                                       (client_identifier, contract_id, time.time()))
                    conn.commit()
                logger.info(f"Synced {len(contracts)} contracts from client {client_identifier}")
            except Exception as e:
                logger.error(f"Client contracts sync error for {sid}: {e}")

        @self.sio.event
        async def request_client_files(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']: return
                client_identifier = self.connected_clients[sid]['client_identifier']
                content_hashes = data.get('content_hashes', [])
                missing_files = []
                with get_db_conn(self.db_path) as conn:
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
                with get_db_conn(self.db_path) as conn:
                    cursor = conn.cursor()
                    for domain in domains:
                        cursor.execute('SELECT 1 FROM dns_records WHERE domain = ?', (domain,))
                        if not cursor.fetchone():
                            missing_dns.append(domain)
                await self.sio.emit('client_dns_files_response', {'missing_dns': missing_dns}, room=sid)
            except Exception as e:
                logger.error(f"Client DNS files request error for {sid}: {e}")

        @self.sio.event
        async def request_client_contracts(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']: return
                client_identifier = self.connected_clients[sid]['client_identifier']
                contract_ids = data.get('contract_ids', [])
                contracts = data.get('contracts', [])
                missing_contracts = []
                with get_db_conn(self.db_path) as conn:
                    cursor = conn.cursor()
                    if contracts:
                        for contract_info in contracts:
                            contract_id = contract_info.get('contract_id')
                            if not contract_id:
                                continue
                            content_hash = contract_info.get('content_hash')
                            domain = contract_info.get('domain')
                            if (content_hash or domain) and not self.should_sync_contract_target(content_hash, domain):
                                continue
                            cursor.execute('SELECT 1 FROM contracts WHERE contract_id = ?', (contract_id,))
                            if not cursor.fetchone():
                                missing_contracts.append(contract_id)
                    else:
                        for contract_id in contract_ids:
                            cursor.execute('SELECT 1 FROM contracts WHERE contract_id = ?', (contract_id,))
                            if not cursor.fetchone():
                                missing_contracts.append(contract_id)
                await self.sio.emit('client_contracts_response', {'missing_contracts': missing_contracts}, room=sid)
            except Exception as e:
                logger.error(f"Client contracts request error for {sid}: {e}")

        @self.sio.event
        async def request_content_from_client(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']: return
                content_hash = data.get('content_hash')
                if not content_hash: return
                file_path = os.path.join(self.files_dir, f"{content_hash}.dat")
                if os.path.exists(file_path):
                    with get_db_conn(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT 1 FROM content WHERE content_hash = ?', (content_hash,))
                        if cursor.fetchone(): return
                    async with aiofiles.open(file_path, 'rb') as f:
                        content = await f.read()
                    with get_db_conn(self.db_path) as conn:
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
                    with get_db_conn(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT ddns_hash FROM dns_records WHERE domain = ?', (domain,))
                        row = cursor.fetchone()
                        if row:
                            ddns_hash = row[0]
                            ddns_file_path = os.path.join(self.files_dir, f"{ddns_hash}.ddns")
                if os.path.exists(ddns_file_path):
                    async with aiofiles.open(ddns_file_path, 'rb') as f:
                        ddns_content = await f.read()
                    with get_db_conn(self.db_path) as conn:
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
        async def request_contract_from_client(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']: return
                contract_id = data.get('contract_id')
                if not contract_id: return
                contract_file_path = os.path.join(self.files_dir, "contracts", f"{contract_id}.contract")
                if os.path.exists(contract_file_path):
                    async with aiofiles.open(contract_file_path, 'rb') as f:
                        contract_content = await f.read()
                    with get_db_conn(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT action_type, content_hash, domain, username, signature, verified FROM contracts WHERE contract_id = ?', (contract_id,))
                        row = cursor.fetchone()
                        if not row: return
                        action_type, content_hash, domain, username, signature, verified = row
                    await self.sio.emit('contract_from_client', {
                        'contract_id': contract_id, 
                        'contract_content': base64.b64encode(contract_content).decode('utf-8'),
                        'action_type': action_type, 
                        'content_hash': content_hash,
                        'domain': domain, 
                        'username': username, 
                        'signature': signature,
                        'verified': verified
                    }, room=sid)
                    logger.info(f"Contract {contract_id} shared from client {self.connected_clients[sid]['username']}")
            except Exception as e:
                logger.error(f"Error sharing contract from client: {e}")

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
                with get_db_conn(self.db_path) as conn:
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
                with get_db_conn(self.db_path) as conn:
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

        @self.sio.event
        async def contract_from_client(sid, data):
            try:
                contract_id = data.get('contract_id')
                contract_content_b64 = data.get('contract_content')
                action_type = data.get('action_type')
                content_hash = data.get('content_hash')
                domain = data.get('domain')
                username = data.get('username')
                signature = data.get('signature')
                verified = data.get('verified', False)
                if not all([contract_id, contract_content_b64, action_type, username, signature]): return
                contract_content = base64.b64decode(contract_content_b64)
                valid, _, contract_info = self.validate_contract_structure(contract_content)
                resolved_content_hash, resolved_domain = self.resolve_contract_target(
                    contract_info if valid else None,
                    content_hash=content_hash,
                    domain=domain
                )
                if (resolved_content_hash or resolved_domain) and not self.should_sync_contract_target(resolved_content_hash, resolved_domain):
                    logger.info(f"Skipped contract {contract_id} from client: target already has contract or missing file.")
                    return
                contract_file_path = os.path.join(self.files_dir, "contracts", f"{contract_id}.contract")
                if not os.path.exists(contract_file_path):
                    async with aiofiles.open(contract_file_path, 'wb') as f:
                        await f.write(contract_content)
                with get_db_conn(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT 1 FROM contracts WHERE contract_id = ?', (contract_id,))
                    if not cursor.fetchone():
                        cursor.execute('''INSERT INTO contracts
(contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                            (contract_id, action_type, resolved_content_hash, resolved_domain, username, signature, time.time(), verified, base64.b64encode(contract_content).decode('utf-8')))
                        conn.commit()
                        logger.info(f"Contract {contract_id} saved from client share")
            except Exception as e:
                logger.error(f"Error processing contract from client: {e}")

        @self.sio.event
        async def search_contracts(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']:
                    await self.sio.emit('contracts_results', {'error': 'Not authenticated'}, room=sid)
                    return
                
                search_type = data.get('search_type', 'all')
                search_value = data.get('search_value', '')
                limit = data.get('limit', 50)
                offset = data.get('offset', 0)
                
                with get_db_conn(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    if search_type == 'hash':
                        cursor.execute('''SELECT contract_id, action_type, content_hash, domain, username, 
                                                signature, timestamp, verified
                                         FROM contracts 
                                         WHERE content_hash LIKE ? 
                                         ORDER BY timestamp DESC 
                                         LIMIT ? OFFSET ?''',
                                      (f'%{search_value}%', limit, offset))
                    elif search_type == 'domain':
                        cursor.execute('''SELECT contract_id, action_type, content_hash, domain, username, 
                                                signature, timestamp, verified
                                         FROM contracts 
                                         WHERE domain LIKE ? 
                                         ORDER BY timestamp DESC 
                                         LIMIT ? OFFSET ?''',
                                      (f'%{search_value}%', limit, offset))
                    elif search_type == 'user':
                        cursor.execute('''SELECT contract_id, action_type, content_hash, domain, username, 
                                                signature, timestamp, verified
                                         FROM contracts 
                                         WHERE username LIKE ? 
                                         ORDER BY timestamp DESC 
                                         LIMIT ? OFFSET ?''',
                                      (f'%{search_value}%', limit, offset))
                    elif search_type == 'type':
                        cursor.execute('''SELECT contract_id, action_type, content_hash, domain, username, 
                                                signature, timestamp, verified
                                         FROM contracts 
                                         WHERE action_type = ? 
                                         ORDER BY timestamp DESC 
                                         LIMIT ? OFFSET ?''',
                                      (search_value, limit, offset))
                    else:
                        cursor.execute('''SELECT contract_id, action_type, content_hash, domain, username, 
                                                signature, timestamp, verified
                                         FROM contracts 
                                         ORDER BY timestamp DESC 
                                         LIMIT ? OFFSET ?''',
                                      (limit, offset))
                    
                    rows = cursor.fetchall()
                    contracts = []
                    for row in rows:
                        violation = None
                        if row[2]:
                            violation = self.get_contract_violation("content", content_hash=row[2])
                        if not violation and row[3]:
                            violation = self.get_contract_violation("domain", domain=row[3])
                        integrity_ok = bool(row[7]) and not violation
                        contracts.append({
                            'contract_id': row[0],
                            'action_type': row[1],
                            'content_hash': row[2],
                            'domain': row[3],
                            'username': row[4],
                            'signature': row[5],
                            'timestamp': row[6],
                            'verified': bool(row[7]),
                            'integrity_ok': bool(integrity_ok),
                            'violation_reason': violation['reason'] if violation else ""
                        })
                    
                    await self.sio.emit('contracts_results', {
                        'success': True,
                        'contracts': contracts,
                        'total': len(contracts)
                    }, room=sid)
                    
            except Exception as e:
                logger.error(f"Contracts search error for {sid}: {e}")
                await self.sio.emit('contracts_results', {'success': False, 'error': str(e)}, room=sid)

        @self.sio.event
        async def get_contract(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']:
                    await self.sio.emit('contract_details', {'error': 'Not authenticated'}, room=sid)
                    return
                
                contract_id = data.get('contract_id')
                if not contract_id:
                    await self.sio.emit('contract_details', {'error': 'Missing contract ID'}, room=sid)
                    return
                
                violation_actions = []
                with get_db_conn(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''SELECT contract_id, action_type, content_hash, domain, username, 
                                            signature, timestamp, verified, contract_content
                                     FROM contracts WHERE contract_id = ?''',
                                 (contract_id,))
                    row = cursor.fetchone()
                    
                    if not row:
                        await self.sio.emit('contract_details', {'error': 'Contract not found'}, room=sid)
                        return
                    
                    contract_content = None
                    contract_file_path = os.path.join(self.files_dir, "contracts", f"{contract_id}.contract")
                    verified = bool(row[7])
                    integrity_ok = bool(row[7])
                    if os.path.exists(contract_file_path):
                        try:
                            async with aiofiles.open(contract_file_path, 'rb') as f:
                                contract_bytes = await f.read()
                            contract_content = contract_bytes.decode('utf-8', errors='replace')
                            contract_info = {}
                            valid, _, contract_info = self.validate_contract_structure(contract_bytes)
                            if valid:
                                public_key_pem = None
                                cursor.execute('SELECT public_key FROM users WHERE username = ?', (contract_info['user'],))
                                row_key = cursor.fetchone()
                                if row_key:
                                    public_key_pem = row_key[0]
                                if contract_info.get("action") in ("hps_exchange_reserved", "hps_exchange_out", "hps_exchange_owner_key"):
                                    issuer = self.extract_contract_detail(contract_info, "ISSUER")
                                    issuer_key = self.get_server_public_key(issuer) if issuer else None
                                    if issuer_key:
                                        public_key_pem = issuer_key
                                verified = self.verify_contract_signature(
                                    contract_content=contract_bytes,
                                    username=contract_info['user'],
                                    signature=contract_info['signature'],
                                    public_key_pem=public_key_pem
                                )
                                integrity_ok = bool(verified)
                                if not verified:
                                    if row[3]:
                                        violation_actions.append(("register", "domain", None, row[3], "invalid_signature"))
                                    elif row[2]:
                                        violation_actions.append(("register", "content", row[2], None, "invalid_signature"))
                                else:
                                    if row[3]:
                                        violation_actions.append(("clear", "domain", None, row[3], None))
                                        self.save_contract_archive("domain", row[3], contract_bytes, conn=conn)
                                    elif row[2]:
                                        violation_actions.append(("clear", "content", row[2], None, None))
                                        self.save_contract_archive("content", row[2], contract_bytes, conn=conn)
                            else:
                                verified = False
                                integrity_ok = False
                                if row[3]:
                                    violation_actions.append(("register", "domain", None, row[3], "invalid_contract"))
                                elif row[2]:
                                    violation_actions.append(("register", "content", row[2], None, "invalid_contract"))
                            cursor.execute('''UPDATE contracts
                                              SET contract_content = ?, verified = ?, username = ?, signature = ?
                                              WHERE contract_id = ?''',
                                           (base64.b64encode(contract_bytes).decode('utf-8'),
                                            1 if verified else 0,
                                            contract_info.get('user', row[4]),
                                            contract_info.get('signature', row[5]),
                                            contract_id))
                        except Exception as e:
                            logger.warning(f"Falha ao carregar contrato do arquivo: {e}")
                    if contract_content is None and row[8]:
                        try:
                            contract_content = base64.b64decode(row[8]).decode('utf-8')
                        except Exception:
                            contract_content = row[8]
                    
                for action, vtype, c_hash, v_domain, reason in violation_actions:
                    if action == "register":
                        self.register_contract_violation(vtype, content_hash=c_hash, domain=v_domain, reason=reason)
                    else:
                        self.clear_contract_violation(vtype, content_hash=c_hash, domain=v_domain)

                contract_info = {
                        'contract_id': row[0],
                        'action_type': row[1],
                        'content_hash': row[2],
                        'domain': row[3],
                        'username': row[4],
                        'signature': row[5],
                        'timestamp': row[6],
                        'verified': bool(verified),
                        'integrity_ok': bool(integrity_ok),
                        'contract_content': contract_content
                }
                    
                await self.sio.emit('contract_details', {
                    'success': True,
                    'contract': contract_info
                }, room=sid)
                    
            except Exception as e:
                logger.error(f"Get contract error for {sid}: {e}")
                await self.sio.emit('contract_details', {'success': False, 'error': str(e)}, room=sid)

        @self.sio.event
        async def get_api_app_versions(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']:
                    await self.sio.emit('api_app_versions', {'error': 'Not authenticated'}, room=sid)
                    return
                title = data.get('title', '').strip()
                app_name = data.get('app_name')
                request_id = data.get('request_id')
                versions = self.get_api_app_versions_from_contracts(title, app_name)
                versions = sorted(versions, key=lambda v: v.get('timestamp', 0) or 0)
                for idx, version in enumerate(versions, start=1):
                    version['version_label'] = f"Upload {idx}"
                latest_hash = versions[-1]['content_hash'] if versions else None
                await self.sio.emit('api_app_versions', {
                    'success': True,
                    'request_id': request_id,
                    'title': title,
                    'app_name': app_name,
                    'latest_hash': latest_hash,
                    'versions': versions
                }, room=sid)
            except Exception as e:
                logger.error(f"API app versions error for {sid}: {e}")
                await self.sio.emit('api_app_versions', {'success': False, 'error': str(e)}, room=sid)

        @self.sio.event
        async def contract_violation(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']:
                    await self.sio.emit('contract_violation_ack', {'success': False, 'error': 'Not authenticated'}, room=sid)
                    return
                violation_type = data.get('violation_type')
                content_hash = data.get('content_hash')
                domain = data.get('domain')
                reason = data.get('reason', 'missing_contract')
                reported_by = self.connected_clients[sid]['username']
                violation_id = self.register_contract_violation(
                    violation_type=violation_type,
                    reported_by=reported_by,
                    content_hash=content_hash,
                    domain=domain,
                    reason=reason
                )
                await self.sio.emit('contract_violation_ack', {
                    'success': bool(violation_id),
                    'violation_id': violation_id
                }, room=sid)
            except Exception as e:
                logger.error(f"Contract violation error for {sid}: {e}")
                await self.sio.emit('contract_violation_ack', {'success': False, 'error': str(e)}, room=sid)

        @self.sio.event
        async def get_pending_transfers(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']:
                    await self.sio.emit('pending_transfers', {'error': 'Not authenticated'}, room=sid)
                    return
                username = self.connected_clients[sid]['username']
                pending = self.get_pending_transfers_for_user(username)
                await self.sio.emit('pending_transfers', {'transfers': pending}, room=sid)
                await self.sio.emit('pending_transfer_notice', {'count': len(pending)}, room=sid)
            except Exception as e:
                logger.error(f"Pending transfers error for {sid}: {e}")
                await self.sio.emit('pending_transfers', {'error': str(e)}, room=sid)

        @self.sio.event
        async def get_transfer_payload(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']:
                    await self.sio.emit('transfer_payload', {'error': 'Not authenticated'}, room=sid)
                    return
                transfer_id = data.get('transfer_id')
                if not transfer_id:
                    await self.sio.emit('transfer_payload', {'error': 'Missing transfer ID'}, room=sid)
                    return
                transfer = self.get_pending_transfer(transfer_id)
                if not transfer:
                    await self.sio.emit('transfer_payload', {'error': 'Transfer not found'}, room=sid)
                    return
                username = self.connected_clients[sid]['username']
                if transfer['target_user'] != username:
                    await self.sio.emit('transfer_payload', {'error': 'Unauthorized'}, room=sid)
                    return
                content_hash = transfer.get('content_hash')
                if not content_hash:
                    await self.sio.emit('transfer_payload', {'error': 'Missing content hash'}, room=sid)
                    return
                file_path = os.path.join(self.files_dir, f"{content_hash}.dat")
                if not os.path.exists(file_path):
                    await self.sio.emit('transfer_payload', {'error': 'Transfer file not found'}, room=sid)
                    return
                async with aiofiles.open(file_path, 'rb') as f:
                    content = await f.read()
                with get_db_conn(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT title, description, mime_type FROM content WHERE content_hash = ?', (content_hash,))
                    meta = cursor.fetchone()
                await self.sio.emit('transfer_payload', {
                    'transfer_id': transfer_id,
                    'content_hash': content_hash,
                    'title': meta[0] if meta else '',
                    'description': meta[1] if meta else '',
                    'mime_type': meta[2] if meta else 'application/octet-stream',
                    'content_b64': base64.b64encode(content).decode('utf-8')
                }, room=sid)
            except Exception as e:
                logger.error(f"Transfer payload error for {sid}: {e}")
                await self.sio.emit('transfer_payload', {'error': str(e)}, room=sid)

        @self.sio.event
        async def accept_hps_transfer(sid, data):
            try:
                deferred = data.get("_deferred_payment")
                if deferred:
                    client_info = {}
                    client_identifier = data.get("_deferred_client_identifier", "")
                    username = data.get("_deferred_username", "")
                else:
                    if not self.connected_clients[sid]['authenticated']:
                        await self.sio.emit('accept_hps_transfer_ack', {'success': False, 'error': 'Not authenticated'}, room=sid)
                        return
                    client_info = self.connected_clients[sid]
                    client_identifier = client_info['client_identifier']
                    username = client_info['username']
                pow_nonce = data.get('pow_nonce', '')
                hashrate_observed = data.get('hashrate_observed', 0.0)
                hps_payment = data.get('hps_payment')
                if not deferred:
                    ok, error, should_ban, pending_info = await self.authorize_pow_or_hps(
                        client_identifier=client_identifier,
                        username=username,
                        action_type="contract_transfer",
                        pow_nonce=pow_nonce,
                        hashrate_observed=hashrate_observed,
                        hps_payment=hps_payment
                    )
                    if not ok:
                        await self.sio.emit('accept_hps_transfer_ack', {'success': False, 'error': error or 'Invalid PoW solution'}, room=sid)
                        if should_ban:
                            await self.ban_client(client_identifier, duration=300, reason="Invalid PoW solution")
                        return
                    if pending_info:
                        payload = {
                            "data": data,
                            "payment": pending_info
                        }
                        self.create_pending_monetary_action(
                            pending_info.get("transfer_id", ""),
                            "accept_hps_transfer",
                            username,
                            client_identifier,
                            payload,
                            "accept_hps_transfer_ack"
                        )
                        await self.sio.emit('accept_hps_transfer_ack',
                                            self.build_pending_monetary_ack(pending_info.get("transfer_id", "")),
                                            room=sid)
                        return
                transfer_id = data.get('transfer_id')
                if not transfer_id:
                    await self.sio.emit('accept_hps_transfer_ack', {'success': False, 'error': 'Missing transfer ID'}, room=sid)
                    return
                transfer = self.get_pending_transfer(transfer_id)
                if not transfer or transfer.get('status') != 'pending':
                    await self.sio.emit('accept_hps_transfer_ack', {'success': False, 'error': 'Transfer not found'}, room=sid)
                    return
                if transfer.get('target_user') != username:
                    await self.sio.emit('accept_hps_transfer_ack', {'success': False, 'error': 'Unauthorized'}, room=sid)
                    return
                if transfer.get('transfer_type') != "hps_transfer":
                    await self.sio.emit('accept_hps_transfer_ack', {'success': False, 'error': 'Invalid transfer type'}, room=sid)
                    return
                session_id = transfer.get("hps_session_id", "")
                session = self.get_hps_transfer_session(session_id) if session_id else None
                if not session or session.get("status") not in ("pending_confirmation", "pending"):
                    await self.sio.emit('accept_hps_transfer_ack', {'success': False, 'error': 'Transfer session unavailable'}, room=sid)
                    return
                if session.get("target") and session.get("target") != username:
                    self.update_hps_transfer_session_target(session_id, username)
                amount = int(transfer.get("hps_amount") or session.get("amount") or 0)
                if amount <= 0:
                    await self.sio.emit('accept_hps_transfer_ack', {'success': False, 'error': 'Invalid transfer amount'}, room=sid)
                    return
                target_key = self.get_user_public_key(username) or self.get_registered_public_key(username)
                if not target_key:
                    await self.sio.emit('accept_hps_transfer_ack', {'success': False, 'error': 'Target public key not available'}, room=sid)
                    return
                offer = self.create_voucher_offer(
                    owner=username,
                    owner_public_key=target_key,
                    value=amount,
                    reason=f"transfer_from:{session.get('payer', '')}",
                    pow_info=None,
                    conditions=None,
                    session_id=session_id
                )
                self.update_hps_transfer_session_offer(session_id, offer.get("offer_id"), offer.get("voucher_id"), offer.get("expires_at", 0))
                transfer_record = self.get_monetary_transfer_by_contract(transfer.get("contract_id"), "hps_transfer")
                if transfer_record:
                    self.update_transfer_locked_vouchers(transfer_record.get("transfer_id"), [offer.get("voucher_id")])
                self.delete_pending_transfer(transfer_id)
                await self.sio.emit('hps_voucher_offer', {
                    'offer_id': offer["offer_id"],
                    'voucher_id': offer["voucher_id"],
                    'payload': offer["payload"],
                    'expires_at': offer["expires_at"]
                }, room=sid)
                await self.send_hps_wallet_sync(session.get("payer", ""))
                await self.send_hps_wallet_sync(username)
                self.notify_pending_transfers(username)
                await self.sio.emit('accept_hps_transfer_ack', {
                    'success': True,
                    'amount': amount,
                    'voucher_id': offer.get("voucher_id", "")
                }, room=sid)
            except Exception as e:
                logger.error(f"Accept HPS transfer error for {sid}: {e}")
                await self.sio.emit('accept_hps_transfer_ack', {'success': False, 'error': str(e)}, room=sid)

        @self.sio.event
        async def get_contract_canonical(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']:
                    await self.sio.emit('contract_canonical', {'error': 'Not authenticated'}, room=sid)
                    return
                contract_id = data.get('contract_id')
                if not contract_id:
                    await self.sio.emit('contract_canonical', {'error': 'Missing contract ID'}, room=sid)
                    return
                with get_db_conn(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''SELECT content_hash, domain FROM contracts WHERE contract_id = ?''', (contract_id,))
                    row = cursor.fetchone()
                if not row:
                    await self.sio.emit('contract_canonical', {'error': 'Contract not found'}, room=sid)
                    return
                content_hash, domain = row
                target_type = "domain" if domain else "content"
                target_id = domain or content_hash
                contract_bytes = self.get_contract_archive(target_type, target_id)
                if not contract_bytes:
                    with get_db_conn(self.db_path) as conn:
                        cursor = conn.cursor()
                        if domain:
                            cursor.execute('''SELECT contract_content FROM contracts
                                              WHERE domain = ? AND verified = 1
                                              ORDER BY timestamp DESC LIMIT 1''', (domain,))
                        else:
                            cursor.execute('''SELECT contract_content FROM contracts
                                              WHERE content_hash = ? AND verified = 1
                                              ORDER BY timestamp DESC LIMIT 1''', (content_hash,))
                        row = cursor.fetchone()
                    if row and row[0]:
                        contract_bytes = base64.b64decode(row[0])
                if not contract_bytes:
                    await self.sio.emit('contract_canonical', {'error': 'No valid contract found'}, room=sid)
                    return
                contract_text = contract_bytes.decode('utf-8', errors='replace')
                await self.sio.emit('contract_canonical', {'contract_text': contract_text}, room=sid)
            except Exception as e:
                logger.error(f"Contract canonical error for {sid}: {e}")
                await self.sio.emit('contract_canonical', {'error': str(e)}, room=sid)

        @self.sio.event
        async def reject_transfer(sid, data):
            try:
                deferred = data.get("_deferred_payment")
                if deferred:
                    client_info = {}
                    client_identifier = data.get("_deferred_client_identifier", "")
                    username = data.get("_deferred_username", "")
                else:
                    if not self.connected_clients[sid]['authenticated']:
                        await self.sio.emit('reject_transfer_ack', {'success': False, 'error': 'Not authenticated'}, room=sid)
                        return
                    client_info = self.connected_clients[sid]
                    client_identifier = client_info['client_identifier']
                    username = client_info['username']
                pow_nonce = data.get('pow_nonce', '')
                hashrate_observed = data.get('hashrate_observed', 0.0)
                hps_payment = data.get('hps_payment')
                if not deferred:
                    ok, error, should_ban, pending_info = await self.authorize_pow_or_hps(
                        client_identifier=client_identifier,
                        username=username,
                        action_type="contract_transfer",
                        pow_nonce=pow_nonce,
                        hashrate_observed=hashrate_observed,
                        hps_payment=hps_payment
                    )
                    if not ok:
                        await self.sio.emit('reject_transfer_ack', {'success': False, 'error': error or 'Invalid PoW solution'}, room=sid)
                        if should_ban:
                            await self.ban_client(client_identifier, duration=300, reason="Invalid PoW solution")
                        return
                    if pending_info:
                        payload = {
                            "data": data,
                            "payment": pending_info
                        }
                        self.create_pending_monetary_action(
                            pending_info.get("transfer_id", ""),
                            "reject_transfer",
                            username,
                            client_identifier,
                            payload,
                            "reject_transfer_ack"
                        )
                        await self.sio.emit('reject_transfer_ack',
                                            self.build_pending_monetary_ack(pending_info.get("transfer_id", "")),
                                            room=sid)
                        return
                transfer_id = data.get('transfer_id')
                if not transfer_id:
                    await self.sio.emit('reject_transfer_ack', {'success': False, 'error': 'Missing transfer ID'}, room=sid)
                    return
                transfer = self.get_pending_transfer(transfer_id)
                if not transfer or transfer['status'] != 'pending':
                    await self.sio.emit('reject_transfer_ack', {'success': False, 'error': 'Transfer not found'}, room=sid)
                    return
                if transfer['target_user'] != username:
                    await self.sio.emit('reject_transfer_ack', {'success': False, 'error': 'Unauthorized'}, room=sid)
                    return
                self.update_pending_transfer_status(transfer_id, "rejected")
                if transfer['transfer_type'] == "hps_transfer":
                    if transfer['custody_user'] in (CUSTODY_USERNAME, "system") and transfer['target_user'] == transfer['original_owner']:
                        await self.move_hps_transfer_to_custody(transfer)
                        await self.sio.emit('reject_transfer_ack', {'success': True, 'moved_to_custody': True}, room=sid)
                        return
                    self.update_hps_transfer_session_target(transfer.get("hps_session_id", ""), transfer['original_owner'])
                    new_id = self.create_pending_transfer(
                        transfer_type="hps_transfer",
                        target_user=transfer['original_owner'],
                        original_owner=transfer['original_owner'],
                        content_hash=None,
                        domain=None,
                        app_name=None,
                        contract_id=transfer.get('contract_id'),
                        hps_amount=transfer.get("hps_amount"),
                        hps_total_value=transfer.get("hps_total_value"),
                        hps_voucher_ids=transfer.get("hps_voucher_ids"),
                        hps_session_id=transfer.get("hps_session_id")
                    )
                    self.notify_pending_transfers(transfer['original_owner'])
                    await self.sio.emit('reject_transfer_ack', {'success': True, 'new_transfer_id': new_id}, room=sid)
                    return
                if transfer['custody_user'] in (CUSTODY_USERNAME, "system") and transfer['target_user'] == transfer['original_owner']:
                    self.move_transfer_to_custody(transfer)
                    await self.sio.emit('reject_transfer_ack', {'success': True, 'moved_to_custody': True}, room=sid)
                    return
                if transfer['transfer_type'] == "domain" and transfer.get('domain'):
                    self.set_contract_certification("domain", transfer['domain'], transfer['original_owner'], CUSTODY_USERNAME)
                    new_id = self.create_pending_transfer(
                        transfer_type="domain",
                        target_user=transfer['original_owner'],
                        original_owner=transfer['original_owner'],
                        content_hash=transfer.get('content_hash'),
                        domain=transfer.get('domain'),
                        app_name=None,
                        contract_id=transfer.get('contract_id')
                    )
                else:
                    self.set_contract_certification("content", transfer.get('content_hash'), transfer['original_owner'], CUSTODY_USERNAME)
                    new_id = self.create_pending_transfer(
                        transfer_type=transfer['transfer_type'],
                        target_user=transfer['original_owner'],
                        original_owner=transfer['original_owner'],
                        content_hash=transfer.get('content_hash'),
                        domain=None,
                        app_name=transfer.get('app_name'),
                        contract_id=transfer.get('contract_id')
                    )
                self.notify_pending_transfers(transfer['original_owner'])
                await self.sio.emit('reject_transfer_ack', {'success': True, 'new_transfer_id': new_id}, room=sid)
            except Exception as e:
                logger.error(f"Reject transfer error for {sid}: {e}")
                await self.sio.emit('reject_transfer_ack', {'success': False, 'error': str(e)}, room=sid)

        @self.sio.event
        async def renounce_transfer(sid, data):
            try:
                deferred = data.get("_deferred_payment")
                if deferred:
                    client_info = {}
                    client_identifier = data.get("_deferred_client_identifier", "")
                    username = data.get("_deferred_username", "")
                else:
                    if not self.connected_clients[sid]['authenticated']:
                        await self.sio.emit('renounce_transfer_ack', {'success': False, 'error': 'Not authenticated'}, room=sid)
                        return
                    client_info = self.connected_clients[sid]
                    client_identifier = client_info['client_identifier']
                    username = client_info['username']
                pow_nonce = data.get('pow_nonce', '')
                hashrate_observed = data.get('hashrate_observed', 0.0)
                hps_payment = data.get('hps_payment')
                if not deferred:
                    ok, error, should_ban, pending_info = await self.authorize_pow_or_hps(
                        client_identifier=client_identifier,
                        username=username,
                        action_type="contract_transfer",
                        pow_nonce=pow_nonce,
                        hashrate_observed=hashrate_observed,
                        hps_payment=hps_payment
                    )
                    if not ok:
                        await self.sio.emit('renounce_transfer_ack', {'success': False, 'error': error or 'Invalid PoW solution'}, room=sid)
                        if should_ban:
                            await self.ban_client(client_identifier, duration=300, reason="Invalid PoW solution")
                        return
                    if pending_info:
                        payload = {
                            "data": data,
                            "payment": pending_info
                        }
                        self.create_pending_monetary_action(
                            pending_info.get("transfer_id", ""),
                            "renounce_transfer",
                            username,
                            client_identifier,
                            payload,
                            "renounce_transfer_ack"
                        )
                        await self.sio.emit('renounce_transfer_ack',
                                            self.build_pending_monetary_ack(pending_info.get("transfer_id", "")),
                                            room=sid)
                        return
                transfer_id = data.get('transfer_id')
                if not transfer_id:
                    await self.sio.emit('renounce_transfer_ack', {'success': False, 'error': 'Missing transfer ID'}, room=sid)
                    return
                transfer = self.get_pending_transfer(transfer_id)
                if not transfer or transfer['status'] != 'pending':
                    await self.sio.emit('renounce_transfer_ack', {'success': False, 'error': 'Transfer not found'}, room=sid)
                    return
                if transfer['target_user'] != username:
                    await self.sio.emit('renounce_transfer_ack', {'success': False, 'error': 'Unauthorized'}, room=sid)
                    return
                self.update_pending_transfer_status(transfer_id, "renounced")
                if transfer['transfer_type'] == "hps_transfer":
                    await self.move_hps_transfer_to_custody(transfer)
                    await self.sio.emit('renounce_transfer_ack', {'success': True, 'moved_to_custody': True}, room=sid)
                    return
                self.move_transfer_to_custody(transfer)
                await self.sio.emit('renounce_transfer_ack', {'success': True, 'moved_to_custody': True}, room=sid)
            except Exception as e:
                logger.error(f"Renounce transfer error for {sid}: {e}")
                await self.sio.emit('renounce_transfer_ack', {'success': False, 'error': str(e)}, room=sid)

        @self.sio.event
        async def invalidate_contract(sid, data):
            try:
                deferred = data.get("_deferred_payment")
                if deferred:
                    client_info = {}
                    client_identifier = data.get("_deferred_client_identifier", "")
                    username = data.get("_deferred_username", "")
                else:
                    if not self.connected_clients[sid]['authenticated']:
                        await self.sio.emit('invalidate_contract_ack', {'success': False, 'error': 'Not authenticated'}, room=sid)
                        return
                    client_info = self.connected_clients[sid]
                    client_identifier = client_info['client_identifier']
                    username = client_info['username']
                pow_nonce = data.get('pow_nonce', '')
                hashrate_observed = data.get('hashrate_observed', 0.0)
                hps_payment = data.get('hps_payment')
                if not deferred:
                    ok, error, should_ban, pending_info = await self.authorize_pow_or_hps(
                        client_identifier=client_identifier,
                        username=username,
                        action_type="contract_reset",
                        pow_nonce=pow_nonce,
                        hashrate_observed=hashrate_observed,
                        hps_payment=hps_payment
                    )
                    if not ok:
                        await self.sio.emit('invalidate_contract_ack', {'success': False, 'error': error or 'Invalid PoW solution'}, room=sid)
                        if should_ban:
                            await self.ban_client(client_identifier, duration=300, reason="Invalid PoW solution")
                        return
                    if pending_info:
                        payload = {
                            "data": data,
                            "payment": pending_info
                        }
                        self.create_pending_monetary_action(
                            pending_info.get("transfer_id", ""),
                            "invalidate_contract",
                            username,
                            client_identifier,
                            payload,
                            "invalidate_contract_ack"
                        )
                        await self.sio.emit('invalidate_contract_ack',
                                            self.build_pending_monetary_ack(pending_info.get("transfer_id", "")),
                                            room=sid)
                        return
                contract_id = data.get('contract_id')
                if not contract_id:
                    await self.sio.emit('invalidate_contract_ack', {'success': False, 'error': 'Missing contract ID'}, room=sid)
                    return
                with get_db_conn(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''SELECT contract_id, action_type, content_hash, domain, username
                                      FROM contracts WHERE contract_id = ?''', (contract_id,))
                    row = cursor.fetchone()
                    if not row:
                        await self.sio.emit('invalidate_contract_ack', {'success': False, 'error': 'Contract not found'}, room=sid)
                        return
                    _, action_type, content_hash, domain, owner = row
                if owner != username:
                    await self.sio.emit('invalidate_contract_ack', {'success': False, 'error': 'Not contract owner'}, room=sid)
                    return
                if domain:
                    self.register_contract_violation(
                        "domain",
                        reported_by="system",
                        domain=domain,
                        reason="missing_contract",
                        apply_penalty=False
                    )
                elif content_hash:
                    self.register_contract_violation(
                        "content",
                        reported_by="system",
                        content_hash=content_hash,
                        reason="missing_contract",
                        apply_penalty=False
                    )
                if domain:
                    self.invalidate_domain(domain, keep_violation=True)
                elif content_hash:
                    self.invalidate_content(content_hash, keep_violation=True)
                await self.sio.emit('invalidate_contract_ack', {
                    'success': True,
                    'action_type': action_type,
                    'content_hash': content_hash,
                    'domain': domain
                }, room=sid)
            except Exception as e:
                logger.error(f"Invalidate contract error for {sid}: {e}")
                await self.sio.emit('invalidate_contract_ack', {'success': False, 'error': str(e)}, room=sid)

        @self.sio.event
        async def certify_contract(sid, data):
            try:
                deferred = data.get("_deferred_payment")
                if deferred:
                    client_info = {}
                    client_identifier = data.get("_deferred_client_identifier", "")
                    username = data.get("_deferred_username", "")
                else:
                    if not self.connected_clients[sid]['authenticated']:
                        await self.sio.emit('certify_contract_ack', {'success': False, 'error': 'Not authenticated'}, room=sid)
                        return
                    client_info = self.connected_clients[sid]
                    client_identifier = client_info['client_identifier']
                    username = client_info['username']
                pow_nonce = data.get('pow_nonce', '')
                hashrate_observed = data.get('hashrate_observed', 0.0)
                hps_payment = data.get('hps_payment')
                if not deferred:
                    ok, error, should_ban, pending_info = await self.authorize_pow_or_hps(
                        client_identifier=client_identifier,
                        username=username,
                        action_type="contract_certify",
                        pow_nonce=pow_nonce,
                        hashrate_observed=hashrate_observed,
                        hps_payment=hps_payment
                    )
                    if not ok:
                        await self.sio.emit('certify_contract_ack', {'success': False, 'error': error or 'Invalid PoW solution'}, room=sid)
                        if should_ban:
                            await self.ban_client(client_identifier, duration=300, reason="Invalid PoW solution")
                        return
                    if pending_info:
                        payload = {
                            "data": data,
                            "payment": pending_info
                        }
                        self.create_pending_monetary_action(
                            pending_info.get("transfer_id", ""),
                            "certify_contract",
                            username,
                            client_identifier,
                            payload,
                            "certify_contract_ack"
                        )
                        await self.sio.emit('certify_contract_ack',
                                            self.build_pending_monetary_ack(pending_info.get("transfer_id", "")),
                                            room=sid)
                        return
                contract_id = data.get('contract_id')
                contract_content_b64 = data.get('contract_content')
                if not contract_id or not contract_content_b64:
                    await self.sio.emit('certify_contract_ack', {'success': False, 'error': 'Missing data'}, room=sid)
                    return
                contract_content = base64.b64decode(contract_content_b64)
                valid, error_msg, contract_info = self.validate_contract_structure(contract_content)
                if not valid:
                    await self.sio.emit('certify_contract_ack', {'success': False, 'error': f'Invalid contract: {error_msg}'}, room=sid)
                    return
                if contract_info['user'] != username:
                    await self.sio.emit('certify_contract_ack', {'success': False, 'error': 'Contract user mismatch'}, room=sid)
                    return
                if not self.verify_contract_signature(
                    contract_content=contract_content,
                    username=username,
                    signature=contract_info['signature']
                ):
                    await self.sio.emit('certify_contract_ack', {'success': False, 'error': 'Invalid contract signature'}, room=sid)
                    return
                with get_db_conn(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''SELECT action_type, content_hash, domain, username
                                      FROM contracts WHERE contract_id = ?''', (contract_id,))
                    row = cursor.fetchone()
                    if not row:
                        await self.sio.emit('certify_contract_ack', {'success': False, 'error': 'Contract not found'}, room=sid)
                        return
                    action_type, content_hash, domain, owner = row
                if action_type and action_type.startswith("voucher_"):
                    await self.sio.emit('certify_contract_ack', {'success': False, 'error': 'Voucher contracts cannot be certified'}, room=sid)
                    return
                if owner == username:
                    await self.sio.emit('certify_contract_ack', {'success': False, 'error': 'Owner cannot certify own contract'}, room=sid)
                    return
                violation = None
                target_type = None
                target_id = None
                if domain:
                    target_type = "domain"
                    target_id = domain
                    violation = self.get_contract_violation("domain", domain=domain)
                elif content_hash:
                    if action_type.startswith("voucher_"):
                        target_type = "voucher"
                        target_id = content_hash
                        violation = self.get_contract_violation("voucher", content_hash=content_hash)
                    else:
                        target_type = "content"
                        target_id = content_hash
                        violation = self.get_contract_violation("content", content_hash=content_hash)
                if not violation:
                    await self.sio.emit('certify_contract_ack', {'success': False, 'error': 'No violation to certify'}, room=sid)
                    return
                if target_type == "domain":
                    self.remove_invalid_contracts(None, domain)
                    self.set_contract_certification("domain", target_id, owner, username)
                    self.clear_contract_violation("domain", domain=target_id)
                elif target_type == "content":
                    self.remove_invalid_contracts(target_id, None)
                    self.set_contract_certification("content", target_id, owner, username)
                    self.clear_contract_violation("content", content_hash=target_id)
                elif target_type == "voucher":
                    voucher_owner = None
                    with get_db_conn(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT owner FROM hps_vouchers WHERE voucher_id = ?', (target_id,))
                        row = cursor.fetchone()
                        voucher_owner = row[0] if row else None
                    self.set_contract_certification("voucher", target_id, voucher_owner or owner, username)
                    with get_db_conn(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('''UPDATE hps_vouchers
                                          SET invalidated = 0,
                                              status = CASE WHEN status = "invalid" THEN "valid" ELSE status END,
                                              last_updated = ?
                                          WHERE voucher_id = ?''',
                                       (time.time(), target_id))
                        conn.commit()
                    self.clear_contract_violation("voucher", content_hash=target_id)
                    if voucher_owner:
                        await self.send_hps_wallet_sync(voucher_owner)
                self.save_contract(
                    action_type="certify_contract",
                    content_hash=target_id if target_type == "content" or target_type == "voucher" else None,
                    domain=target_id if target_type == "domain" else None,
                    username=username,
                    signature=contract_info['signature'],
                    contract_content=contract_content
                )
                with get_db_conn(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('UPDATE user_reputations SET reputation = MIN(100, reputation + 80) WHERE username = ?', (username,))
                    cursor.execute('UPDATE users SET reputation = MIN(100, reputation + 80) WHERE username = ?', (username,))
                    conn.commit()
                for sid, client in self.connected_clients.items():
                    if client.get('username') == username:
                        await self.sio.emit('reputation_update', {'reputation': self.get_user_reputation(username)}, room=sid)
                await self.sio.emit('certify_contract_ack', {'success': True}, room=sid)
            except Exception as e:
                logger.error(f"Certify contract error for {sid}: {e}")
                await self.sio.emit('certify_contract_ack', {'success': False, 'error': str(e)}, room=sid)

        @self.sio.event
        async def get_contract_canonical_by_target(sid, data):
            try:
                if not self.connected_clients[sid]['authenticated']:
                    await self.sio.emit('contract_canonical', {'error': 'Not authenticated'}, room=sid)
                    return
                target_type = data.get('target_type')
                target_id = data.get('target_id')
                if target_type not in ("content", "domain") or not target_id:
                    await self.sio.emit('contract_canonical', {'error': 'Missing target'}, room=sid)
                    return
                contract_bytes = self.get_contract_archive(target_type, target_id)
                if not contract_bytes:
                    await self.sio.emit('contract_canonical', {'error': 'No valid contract found'}, room=sid)
                    return
                contract_text = contract_bytes.decode('utf-8', errors='replace')
                await self.sio.emit('contract_canonical', {'contract_text': contract_text}, room=sid)
            except Exception as e:
                logger.error(f"Contract canonical by target error for {sid}: {e}")
                await self.sio.emit('contract_canonical', {'error': str(e)}, room=sid)

        @self.sio.event
        async def certify_missing_contract(sid, data):
            try:
                deferred = data.get("_deferred_payment")
                if deferred:
                    client_info = {}
                    client_identifier = data.get("_deferred_client_identifier", "")
                    username = data.get("_deferred_username", "")
                else:
                    if not self.connected_clients[sid]['authenticated']:
                        await self.sio.emit('certify_missing_contract_ack', {'success': False, 'error': 'Not authenticated'}, room=sid)
                        return
                    client_info = self.connected_clients[sid]
                    client_identifier = client_info['client_identifier']
                    username = client_info['username']
                pow_nonce = data.get('pow_nonce', '')
                hashrate_observed = data.get('hashrate_observed', 0.0)
                hps_payment = data.get('hps_payment')
                if not deferred:
                    ok, error, should_ban, pending_info = await self.authorize_pow_or_hps(
                        client_identifier=client_identifier,
                        username=username,
                        action_type="contract_certify",
                        pow_nonce=pow_nonce,
                        hashrate_observed=hashrate_observed,
                        hps_payment=hps_payment
                    )
                    if not ok:
                        await self.sio.emit('certify_missing_contract_ack', {'success': False, 'error': error or 'Invalid PoW solution'}, room=sid)
                        if should_ban:
                            await self.ban_client(client_identifier, duration=300, reason="Invalid PoW solution")
                        return
                    if pending_info:
                        payload = {
                            "data": data,
                            "payment": pending_info
                        }
                        self.create_pending_monetary_action(
                            pending_info.get("transfer_id", ""),
                            "certify_missing_contract",
                            username,
                            client_identifier,
                            payload,
                            "certify_missing_contract_ack"
                        )
                        await self.sio.emit('certify_missing_contract_ack',
                                            self.build_pending_monetary_ack(pending_info.get("transfer_id", "")),
                                            room=sid)
                        return
                target_type = data.get('target_type')
                target_id = data.get('target_id')
                contract_content_b64 = data.get('contract_content')
                if target_type not in ("content", "domain") or not target_id or not contract_content_b64:
                    await self.sio.emit('certify_missing_contract_ack', {'success': False, 'error': 'Missing data'}, room=sid)
                    return
                contract_content = base64.b64decode(contract_content_b64)
                valid, error_msg, contract_info = self.validate_contract_structure(contract_content)
                if not valid:
                    await self.sio.emit('certify_missing_contract_ack', {'success': False, 'error': f'Invalid contract: {error_msg}'}, room=sid)
                    return
                if contract_info['user'] != username:
                    await self.sio.emit('certify_missing_contract_ack', {'success': False, 'error': 'Contract user mismatch'}, room=sid)
                    return
                if not self.verify_contract_signature(
                    contract_content=contract_content,
                    username=username,
                    signature=contract_info['signature']
                ):
                    await self.sio.emit('certify_missing_contract_ack', {'success': False, 'error': 'Invalid contract signature'}, room=sid)
                    return
                if target_type == "domain":
                    contract_violation, violation_reason, _ = self.evaluate_contract_violation_for_domain(target_id)
                else:
                    contract_violation, violation_reason, _ = self.evaluate_contract_violation_for_content(target_id)
                if not contract_violation or violation_reason != "missing_contract":
                    await self.sio.emit(
                        'certify_missing_contract_ack',
                        {'success': False, 'error': 'Contract is not missing'},
                        room=sid
                    )
                    return
                violation = None
                if target_type == "domain":
                    violation = self.get_contract_violation("domain", domain=target_id)
                else:
                    violation = self.get_contract_violation("content", content_hash=target_id)
                if not violation:
                    await self.sio.emit('certify_missing_contract_ack', {'success': False, 'error': 'No violation to certify'}, room=sid)
                    return
                owner_username = violation.get('owner_username')
                if owner_username and owner_username != username:
                    await self.sio.emit('certify_missing_contract_ack', {'success': False, 'error': 'Only owner can certify missing contract'}, room=sid)
                    return
                if target_type == "domain":
                    self.set_contract_certification("domain", target_id, owner_username or username, username)
                    self.clear_contract_violation("domain", domain=target_id)
                    content_hash = None
                    domain = target_id
                else:
                    self.set_contract_certification("content", target_id, owner_username or username, username)
                    self.clear_contract_violation("content", content_hash=target_id)
                    content_hash = target_id
                    domain = None
                self.save_contract(
                    action_type="certify_contract",
                    content_hash=content_hash,
                    domain=domain,
                    username=username,
                    signature=contract_info['signature'],
                    contract_content=contract_content
                )
                with get_db_conn(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('UPDATE user_reputations SET reputation = MIN(100, reputation + 40) WHERE username = ?', (username,))
                    cursor.execute('UPDATE users SET reputation = MIN(100, reputation + 40) WHERE username = ?', (username,))
                    conn.commit()
                for sid, client in self.connected_clients.items():
                    if client.get('username') == username:
                        await self.sio.emit('reputation_update', {'reputation': self.get_user_reputation(username)}, room=sid)
                await self.sio.emit('certify_missing_contract_ack', {'success': True}, room=sid)
            except Exception as e:
                logger.error(f"Certify missing contract error for {sid}: {e}")
                await self.sio.emit('certify_missing_contract_ack', {'success': False, 'error': str(e)}, room=sid)
        self.deferred_action_handlers.update({
            "transfer_hps": transfer_hps,
            "publish_content": publish_content,
            "register_dns": register_dns,
            "report_content": report_content,
            "accept_usage_contract": accept_usage_contract,
            "accept_hps_transfer": accept_hps_transfer,
            "reject_transfer": reject_transfer,
            "renounce_transfer": renounce_transfer,
            "invalidate_contract": invalidate_contract,
            "certify_contract": certify_contract,
            "certify_missing_contract": certify_missing_contract
        })
    def setup_routes(self):
        self.app.router.add_post('/upload', self.handle_upload)
        self.app.router.add_get('/content/{content_hash}', self.handle_content_request)
        self.app.router.add_get('/dns/{domain}', self.handle_dns_request)
        self.app.router.add_get('/ddns/{domain}', self.handle_ddns_request)
        self.app.router.add_get('/contract/{contract_id}', self.handle_contract_request)
        self.app.router.add_get('/voucher/{voucher_id}', self.handle_voucher_request)
        self.app.router.add_get('/sync/content', self.handle_sync_content)
        self.app.router.add_get('/sync/dns', self.handle_sync_dns)
        self.app.router.add_get('/sync/users', self.handle_sync_users)
        self.app.router.add_get('/sync/contracts', self.handle_sync_contracts)
        self.app.router.add_get('/health', self.handle_health)
        self.app.router.add_get('/server_info', self.handle_server_info)
        self.app.router.add_get('/economy_report', self.handle_economy_report)
        self.app.router.add_post('/exchange/validate', self.handle_exchange_validate)
        self.app.router.add_post('/exchange/confirm', self.handle_exchange_confirm)
        self.app.router.add_post('/voucher/audit', self.handle_voucher_audit)

    async def handle_upload(self, request):
        try:
            reader = await request.multipart()
            file_field = await reader.next()
            if not file_field or file_field.name != 'file':
                logger.warning("Upload attempt without file.")
                return web.json_response({'success': False, 'error': 'File missing'}, status=400)
            file_data = await file_field.read()
            username = request.headers.get('X-Username', '').strip()
            signature = request.headers.get('X-Signature', '').strip()
            public_key_b64 = request.headers.get('X-Public-Key', '').strip()
            client_identifier = request.headers.get('X-Client-ID', '').strip()
            if not all([username, signature, public_key_b64, client_identifier]):
                logger.warning(f"Upload attempt without auth headers from {request.remote}.")
                return web.json_response({'success': False, 'error': 'Missing auth headers'}, status=401)
            if len(file_data) > self.max_upload_size:
                logger.warning(f"Upload from {username} exceeded max upload size.")
                return web.json_response({'success': False, 'error': 'File too large'}, status=413)
            allowed, message, remaining_time = self.check_rate_limit(client_identifier, "upload")
            if not allowed:
                logger.warning(f"Upload blocked by rate limit for {client_identifier}: {message}")
                return web.json_response({'success': False, 'error': message, 'blocked_until': time.time() + remaining_time}, status=429)
            with get_db_conn(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT public_key, client_identifier, disk_quota, used_disk_space FROM users WHERE username = ?', (username,))
                user_row = cursor.fetchone()
                if not user_row:
                    logger.warning(f"Upload attempt for unknown user {username}.")
                    return web.json_response({'success': False, 'error': 'User not found'}, status=401)
                stored_public_key, stored_client_identifier, disk_quota, used_disk_space = user_row
                if stored_public_key == PENDING_PUBLIC_KEY:
                    logger.warning(f"Upload attempt with pending public key for {username}.")
                    return web.json_response({'success': False, 'error': 'Public key pending confirmation'}, status=403)
                if stored_public_key and stored_public_key != public_key_b64:
                    logger.warning(f"Upload attempt with mismatched public key for {username}.")
                    return web.json_response({'success': False, 'error': 'Public key mismatch'}, status=403)
                if stored_client_identifier and stored_client_identifier != client_identifier:
                    logger.warning(f"Upload attempt with mismatched client identifier for {username}.")
                    return web.json_response({'success': False, 'error': 'Client identifier mismatch'}, status=403)
                if not self.verify_content_signature(file_data, signature, public_key_b64):
                    logger.warning(f"Upload attempt with invalid signature for {username}.")
                    return web.json_response({'success': False, 'error': 'Invalid signature'}, status=401)
                if (used_disk_space + len(file_data)) > disk_quota:
                    logger.warning(f"Upload from {username} exceeded disk quota.")
                    return web.json_response({'success': False, 'error': f'Disk quota exceeded. Available space: {(disk_quota - used_disk_space) / (1024*1024):.2f}MB'}, status=413)
            content_hash = hashlib.sha256(file_data).hexdigest()
            file_path = os.path.join(self.files_dir, f"{content_hash}.dat")
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
            with get_db_conn(self.db_path) as conn:
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
        contract_violation, violation_reason, _ = self.evaluate_contract_violation_for_content(content_hash)
        if contract_violation:
            return web.json_response({
                'success': False,
                'error': 'contract_violation',
                'contract_violation_reason': violation_reason,
                'content_hash': content_hash
            }, status=403)
        try:
            async with aiofiles.open(file_path, 'rb') as f:
                content = await f.read()
            with get_db_conn(self.db_path) as conn:
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
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT d.content_hash, d.username, d.signature, d.verified, d.original_owner
                FROM dns_records d WHERE d.domain = ? ORDER BY d.verified DESC LIMIT 1''', (domain,))
            row = cursor.fetchone()
            if row:
                cursor.execute('UPDATE dns_records SET last_resolved = ? WHERE domain = ?', (time.time(), domain))
                conn.commit()
        if row:
            content_hash, username, signature, verified, original_owner = row
            contract_violation, violation_reason, _ = self.evaluate_contract_violation_for_domain(domain)
            if contract_violation:
                return web.json_response({
                    'success': False,
                    'error': 'contract_violation',
                    'contract_violation_reason': violation_reason,
                    'domain': domain,
                    'content_hash': content_hash
                }, status=403)
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
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT ddns_hash FROM dns_records WHERE domain = ?', (domain,))
            row = cursor.fetchone()
        if row:
            ddns_hash = row[0]
            file_path = os.path.join(self.files_dir, f"{ddns_hash}.ddns")
            if os.path.exists(file_path):
                return web.FileResponse(file_path)
        return web.json_response({'success': False, 'error': 'DDNS file not found'}, status=404)

    async def handle_contract_request(self, request):
        contract_id = request.match_info['contract_id']
        contract_file_path = os.path.join(self.files_dir, "contracts", f"{contract_id}.contract")
        if os.path.exists(contract_file_path):
            return web.FileResponse(contract_file_path, headers={'Content-Type': 'text/plain'})
        
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT contract_content FROM contracts WHERE contract_id = ?', (contract_id,))
            row = cursor.fetchone()
            if row and row[0]:
                contract_content = base64.b64decode(row[0])
                return web.Response(body=contract_content, content_type='text/plain')
        
        return web.json_response({'success': False, 'error': 'Contract not found'}, status=404)

    async def handle_voucher_request(self, request):
        voucher_id = request.match_info['voucher_id']
        voucher_path = os.path.join(self.files_dir, "vouchers", f"{voucher_id}.hps")
        if os.path.exists(voucher_path):
            accept = request.headers.get("Accept", "")
            if "text/html" in accept:
                with open(voucher_path, "r", encoding="ascii") as f:
                    raw_text = f.read()
                try:
                    voucher = json.loads(raw_text)
                except Exception:
                    voucher = self.parse_hps_voucher_hsyst(raw_text)
                if not voucher:
                    return web.Response(text=raw_text, content_type="text/plain")
                return web.Response(text=self.render_voucher_html(voucher), content_type="text/html")
            return web.FileResponse(voucher_path, headers={'Content-Type': 'application/hps-voucher'})
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT payload, issuer_signature, owner_signature FROM hps_vouchers
                              WHERE voucher_id = ?''', (voucher_id,))
            row = cursor.fetchone()
        if row:
            payload = json.loads(row[0])
            voucher = {
                "voucher_type": "HPS",
                "payload": payload,
                "signatures": {"issuer": row[1], "owner": row[2]}
            }
            self.attach_voucher_integrity(voucher)
            accept = request.headers.get("Accept", "")
            if "text/html" in accept:
                return web.Response(text=self.render_voucher_html(voucher), content_type="text/html")
            return web.Response(
                text=self.format_hps_voucher_hsyst(voucher),
                content_type='application/hps-voucher'
            )
        return web.json_response({'success': False, 'error': 'Voucher not found'}, status=404)

    async def handle_sync_content(self, request):
        limit = int(request.query.get('limit', 100))
        offset = int(request.query.get('offset', 0))
        since = float(request.query.get('since', 0))
        content_hash_param = request.query.get('content_hash')
        content_list = []
        with get_db_conn(self.db_path) as conn:
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
        with get_db_conn(self.db_path) as conn:
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
        with get_db_conn(self.db_path) as conn:
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

    async def handle_sync_contracts(self, request):
        since = float(request.query.get('since', 0))
        limit = int(request.query.get('limit', 100))
        offset = int(request.query.get('offset', 0))
        contract_type = request.query.get('type')
        
        contracts_list = []
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            
            if contract_type:
                if since > 0:
                    cursor.execute('''SELECT contract_id, action_type, content_hash, domain, username, 
                                            signature, timestamp, verified, contract_content
                                     FROM contracts 
                                     WHERE action_type = ? AND timestamp > ? 
                                     ORDER BY timestamp DESC LIMIT ? OFFSET ?''',
                                 (contract_type, since, limit, offset))
                else:
                    cursor.execute('''SELECT contract_id, action_type, content_hash, domain, username, 
                                            signature, timestamp, verified, contract_content
                                     FROM contracts 
                                     WHERE action_type = ? 
                                     ORDER BY timestamp DESC LIMIT ? OFFSET ?''',
                                 (contract_type, limit, offset))
            elif since > 0:
                cursor.execute('''SELECT contract_id, action_type, content_hash, domain, username, 
                                        signature, timestamp, verified, contract_content
                                 FROM contracts 
                                 WHERE timestamp > ? 
                                 ORDER BY timestamp DESC LIMIT ? OFFSET ?''',
                             (since, limit, offset))
            else:
                cursor.execute('''SELECT contract_id, action_type, content_hash, domain, username, 
                                        signature, timestamp, verified, contract_content
                                 FROM contracts 
                                 ORDER BY timestamp DESC LIMIT ? OFFSET ?''',
                             (limit, offset))
            
            rows = cursor.fetchall()
        
        for row in rows:
            contracts_list.append({
                'contract_id': row[0],
                'action_type': row[1],
                'content_hash': row[2],
                'domain': row[3],
                'username': row[4],
                'signature': row[5],
                'timestamp': row[6],
                'verified': bool(row[7]),
                'contract_content': row[8]  # Já está em base64
            })
        
        logger.info(f"Serving {len(contracts_list)} contracts for sync (since={since}, type={contract_type}).")
        return web.json_response(contracts_list)

    async def handle_health(self, request):
        health_data = {
            'status': 'healthy', 'server_id': self.server_id, 'address': self.address,
            'online_clients': len([c for c in self.connected_clients.values() if c['authenticated']]),
            'total_users': 0, 'total_content': 0, 'total_dns': 0, 'total_contracts': 0,
            'uptime': time.time() - self.start_time if hasattr(self, 'start_time') else 0, 'timestamp': time.time()
        }
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM users')
            health_data['total_users'] = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM content')
            health_data['total_content'] = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM dns_records')
            health_data['total_dns'] = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM contracts')
            health_data['total_contracts'] = cursor.fetchone()[0]
        return web.json_response(health_data)

    async def handle_server_info(self, request):
        return web.json_response({
            'server_id': self.server_id, 'address': self.address,
            'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'), 'timestamp': time.time()
        })

    async def handle_economy_report(self, request):
        try:
            report = self.build_economy_report()
            return web.json_response(report)
        except Exception as e:
            return web.json_response({'success': False, 'error': str(e)}, status=500)

    async def handle_exchange_validate(self, request):
        try:
            data = await request.json()
        except Exception:
            return web.json_response({'success': False, 'error': 'Invalid JSON'}, status=400)
        try:
            voucher_ids = data.get("voucher_ids", []) or []
            target_server = (data.get("target_server") or "").strip()
            client_signature = data.get("client_signature", "")
            client_public_key = data.get("client_public_key", "")
            request_id = data.get("request_id", "")
            timestamp = float(data.get("timestamp", 0))
            if not voucher_ids or not target_server or not client_signature or not client_public_key or not request_id:
                return web.json_response({'success': False, 'error': 'Missing exchange fields'}, status=400)
            if abs(time.time() - timestamp) > 600:
                return web.json_response({'success': False, 'error': 'Timestamp out of range'}, status=400)
            with get_db_conn(self.db_path) as conn:
                cursor = conn.cursor()
                voucher_rows = []
                for voucher_id in voucher_ids:
                    cursor.execute('''SELECT payload, issuer_signature, owner_signature, status, invalidated
                                      FROM hps_vouchers WHERE voucher_id = ?''', (voucher_id,))
                    row = cursor.fetchone()
                    if not row:
                        return web.json_response({'success': False, 'error': f'Voucher {voucher_id} not found'}, status=404)
                    payload = json.loads(row[0])
                    if not self.is_local_issuer(payload.get("issuer", "")):
                        return web.json_response({'success': False, 'error': 'Issuer mismatch'}, status=400)
                    status = row[3]
                    invalidated = row[4]
                    if status != "valid":
                        return web.json_response({'success': False, 'error': f'Voucher {voucher_id} not available'}, status=400)
                    if invalidated:
                        return web.json_response({'success': False, 'error': f'Voucher {voucher_id} invalidated'}, status=400)
                    voucher_rows.append((voucher_id, payload, row[1], row[2]))
            owner = voucher_rows[0][1].get("owner", "")
            owner_key = voucher_rows[0][1].get("owner_public_key", "")
            issuer_for_proof = voucher_rows[0][1].get("issuer", self.address)
            if owner_key != client_public_key:
                return web.json_response({'success': False, 'error': 'Owner key mismatch'}, status=400)
            for _, payload, issuer_sig, owner_sig in voucher_rows:
                if payload.get("owner") != owner:
                    return web.json_response({'success': False, 'error': 'Voucher owner mismatch'}, status=400)
                if not self.verify_payload_signature(payload, owner_sig, owner_key):
                    return web.json_response({'success': False, 'error': 'Owner signature invalid'}, status=400)
                issuer_key = payload.get("issuer_public_key", "")
                if not self.verify_payload_signature(payload, issuer_sig, issuer_key):
                    return web.json_response({'success': False, 'error': 'Issuer signature invalid'}, status=400)
            proof_payload = {
                "issuer": issuer_for_proof,
                "target_server": target_server,
                "voucher_ids": sorted(voucher_ids),
                "timestamp": timestamp
            }
            if not self.verify_payload_signature(proof_payload, client_signature, client_public_key):
                return web.json_response({'success': False, 'error': 'Client proof invalid'}, status=400)
            session_id = f"exchange-{request_id}"
            ok, total_value, error = self.reserve_vouchers_for_session(owner, session_id, voucher_ids)
            if not ok:
                return web.json_response({'success': False, 'error': error}, status=400)
            token_id = str(uuid.uuid4())
            expires_at = time.time() + self.exchange_quote_ttl
            token_payload = {
                "token_id": token_id,
                "issuer": self.address,
                "issuer_public_key": base64.b64encode(self.public_key_pem).decode("utf-8"),
                "target_server": target_server,
                "voucher_ids": sorted(voucher_ids),
                "owner": owner,
                "total_value": int(total_value),
                "session_id": session_id,
                "issued_at": time.time(),
                "expires_at": expires_at
            }
            token_signature = self.sign_payload(token_payload)
            self.exchange_tokens[token_id] = {
                "payload": token_payload,
                "signature": token_signature,
                "session_id": session_id,
                "voucher_ids": voucher_ids,
                "expires_at": expires_at
            }
            owner_key_contract_id = self.save_server_contract(
                "hps_exchange_owner_key",
                [
                    ("ISSUER", self.address),
                    ("OWNER", owner),
                    ("OWNER_PUBLIC_KEY", owner_key),
                    ("TOKEN_ID", token_id),
                    ("TARGET_SERVER", target_server),
                    ("TIMESTAMP", int(time.time()))
                ]
            )
            contract_id = self.save_server_contract(
                "hps_exchange_reserved",
                [
                    ("ISSUER", self.address),
                    ("TOKEN_ID", token_id),
                    ("OWNER", owner),
                    ("TARGET_SERVER", target_server),
                    ("TOTAL_VALUE", total_value),
                    ("VOUCHERS", json.dumps(voucher_ids, ensure_ascii=True))
                ]
            )
            economy_report = self.build_economy_report()
            return web.json_response({
                "success": True,
                "token": token_payload,
                "signature": token_signature,
                "economy_report": economy_report,
                "contract_id": contract_id,
                "owner_key_contract_id": owner_key_contract_id
            })
        except Exception as e:
            logger.error(f"Exchange validate error: {e}")
            return web.json_response({'success': False, 'error': str(e)}, status=500)

    async def handle_exchange_confirm(self, request):
        try:
            data = await request.json()
        except Exception:
            return web.json_response({'success': False, 'error': 'Invalid JSON'}, status=400)
        try:
            token_payload = data.get("token", {}) or {}
            token_signature = data.get("signature", "")
            token_id = token_payload.get("token_id", "")
            if not token_id or not token_signature:
                return web.json_response({'success': False, 'error': 'Missing token'}, status=400)
            stored = self.exchange_tokens.get(token_id)
            if not stored:
                return web.json_response({'success': False, 'error': 'Token not found'}, status=404)
            if stored.get("signature") != token_signature:
                return web.json_response({'success': False, 'error': 'Token signature mismatch'}, status=400)
            if time.time() > stored.get("expires_at", 0):
                return web.json_response({'success': False, 'error': 'Token expired'}, status=400)
            session_id = stored.get("session_id")
            if session_id:
                self.mark_vouchers_spent(session_id)
            self.exchange_tokens.pop(token_id, None)
            contract_id = self.save_server_contract(
                "hps_exchange_out",
                [
                    ("ISSUER", self.address),
                    ("TOKEN_ID", token_id),
                    ("OWNER", token_payload.get("owner", "")),
                    ("TARGET_SERVER", token_payload.get("target_server", "")),
                    ("TOTAL_VALUE", token_payload.get("total_value", 0)),
                    ("VOUCHERS", json.dumps(token_payload.get("voucher_ids", []), ensure_ascii=True))
                ]
            )
            response_payload = {
                "token_id": token_id,
                "issuer": self.address,
                "contract_id": contract_id,
                "confirmed_at": time.time(),
                "voucher_ids": token_payload.get("voucher_ids", []),
                "total_value": token_payload.get("total_value", 0)
            }
            response_signature = self.sign_payload(response_payload)
            return web.json_response({
                "success": True,
                "payload": response_payload,
                "signature": response_signature
            })
        except Exception as e:
            logger.error(f"Exchange confirm error: {e}")
            return web.json_response({'success': False, 'error': str(e)}, status=500)

    async def handle_voucher_audit(self, request):
        try:
            data = await request.json()
        except Exception:
            return web.json_response({'success': False, 'error': 'Invalid JSON'}, status=400)
        voucher_ids = data.get("voucher_ids", []) or []
        if not voucher_ids:
            return web.json_response({'success': False, 'error': 'Missing voucher IDs'}, status=400)
        results = []
        for voucher_id in voucher_ids:
            info = self.get_voucher_audit_info(voucher_id)
            if info:
                info["issuer_server"] = self.address
                info["issuer_server_key"] = base64.b64encode(self.public_key_pem).decode("utf-8")
                results.append(info)
        return web.json_response({'success': True, 'vouchers': results})

    def mark_node_offline(self, node_id):
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE network_nodes SET is_online = 0 WHERE node_id = ?', (node_id,))
            conn.commit()
        logger.info(f"Node {node_id} marked offline.")

    async def broadcast_network_state(self):
        try:
            with get_db_conn(self.db_path) as conn:
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

    async def propagate_contract_to_network(self, contract_id):
        for server_address in list(self.known_servers):
            if server_address != self.address:
                asyncio.create_task(self.sync_contract_with_server(server_address, contract_id=contract_id))

    async def fetch_content_from_network(self, content_hash):
        redirected_hash = self.get_redirected_hash(content_hash)
        if redirected_hash:
            return await self.fetch_content_from_network(redirected_hash)

        servers_to_try = []
        with get_db_conn(self.db_path) as conn:
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
                        with get_db_conn(self.db_path) as conn:
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
        with get_db_conn(self.db_path) as conn:
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
                    with get_db_conn(self.db_path) as conn:
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
        with get_db_conn(self.db_path) as conn:
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
        with get_db_conn(self.db_path) as conn:
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
                    with get_db_conn(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT 1 FROM dns_records WHERE domain = ?', (domain,))
                        if cursor.fetchone():
                            logger.info(f"DDNS {domain} received from client {sid}")
                            return True
            except Exception as e:
                logger.error(f"Error requesting DDNS from client {sid}: {e}")

        return False

    async def fetch_contract_from_network(self, contract_id):
        servers_to_try = []
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT address FROM server_nodes WHERE is_active = 1 AND address != ? ORDER BY reputation DESC', (self.address,))
            servers_to_try = [row[0] for row in cursor.fetchall()]

        for server in servers_to_try:
            try:
                success, contract_content, protocol_used = await self.make_remote_request(server, f'/contract/{contract_id}')
                if success:
                    contract_file_path = os.path.join(self.files_dir, "contracts", f"{contract_id}.contract")
                    async with aiofiles.open(contract_file_path, 'wb') as f:
                        await f.write(contract_content)

                    logger.info(f"Contract {contract_id} synced from {server} via {protocol_used}.")
                    return True
            except Exception as e:
                logger.error(f"Unexpected error fetching contract {contract_id} from {server}: {e}")

        client_sids = []
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT client_identifier FROM client_contracts WHERE contract_id = ?', (contract_id,))
            rows = cursor.fetchall()
            for row in rows:
                client_identifier = row[0]
                for sid, client in self.connected_clients.items():
                    if client.get('client_identifier') == client_identifier and client.get('authenticated'):
                        client_sids.append(sid)
                        break

        for sid in client_sids:
            try:
                await self.sio.emit('request_contract_from_client', {'contract_id': contract_id}, room=sid)
                await asyncio.sleep(2)
                contract_file_path = os.path.join(self.files_dir, "contracts", f"{contract_id}.contract")
                if os.path.exists(contract_file_path):
                    with get_db_conn(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT 1 FROM contracts WHERE contract_id = ?', (contract_id,))
                        if cursor.fetchone():
                            logger.info(f"Contract {contract_id} received from client {sid}")
                            return True
            except Exception as e:
                logger.error(f"Error requesting contract from client {sid}: {e}")

        return False

    async def resolve_dns_from_network(self, domain):
        servers_to_try = []
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT address FROM server_nodes WHERE is_active = 1 AND address != ? ORDER BY reputation DESC', (self.address,))
            servers_to_try = [row[0] for row in cursor.fetchall()]

        for server in servers_to_try:
            try:
                success, dns_data, protocol_used = await self.make_remote_request_json(server, f'/dns/{domain}')
                if success and dns_data.get('success'):
                    with get_db_conn(self.db_path) as conn:
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
        with get_db_conn(self.db_path) as conn:
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
                remote_public_key = self.normalize_public_key(remote_info.get('public_key', ''))
                with get_db_conn(self.db_path) as conn:
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
            last_sync_contracts = 0
            with get_db_conn(self.db_path) as conn:
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
                cursor.execute('SELECT last_sync FROM server_sync_history WHERE server_address = ? AND sync_type = ?', (server_address, 'contracts'))
                row = cursor.fetchone()
                if row: last_sync_contracts = row[0]

            await self.sync_content_with_server(server_address, since=last_sync_content)
            await self.sync_dns_with_server(server_address, since=last_sync_dns)
            await self.sync_users_with_server(server_address, since=last_sync_users)
            await self.sync_contracts_with_server(server_address, since=last_sync_contracts)

            with get_db_conn(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''INSERT OR REPLACE INTO server_sync_history
(server_address, last_sync, sync_type, items_count, success)
                    VALUES (?, ?, ?, ?, ?)''',
                    (server_address, time.time(), 'full', 0, 1))
                conn.commit()

            logger.info(f"Full sync with {server_address} completed successfully.")
        except Exception as e:
            logger.error(f"Unexpected error during sync with {server_address}: {e}")
            with get_db_conn(self.db_path) as conn:
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
                    with get_db_conn(self.db_path) as conn:
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

                    with get_db_conn(self.db_path) as conn:
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

                with get_db_conn(self.db_path) as conn:
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

                    with get_db_conn(self.db_path) as conn:
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
                        with get_db_conn(self.db_path) as conn:
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

                    with get_db_conn(self.db_path) as conn:
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
                    with get_db_conn(self.db_path) as conn:
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

                with get_db_conn(self.db_path) as conn:
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

    async def sync_contracts_with_server(self, server_address, since=0, contract_id=None):
        try:
            if contract_id:
                success, contract_content, protocol_used = await self.make_remote_request(server_address, f'/contract/{contract_id}')
                if success:
                    # Obtém metadados do contrato
                    success_meta, contract_meta, _ = await self.make_remote_request_json(server_address, f'/sync/contracts', params={'type': 'any'})
                    if success_meta and isinstance(contract_meta, list):
                        for c in contract_meta:
                            if c.get('contract_id') == contract_id:
                                if (c.get('content_hash') or c.get('domain')) and not self.should_sync_contract_target(
                                    c.get('content_hash'),
                                    c.get('domain')
                                ):
                                    logger.info(f"Skipped contract {contract_id} from {server_address}: target already has contract or missing file.")
                                    return 0
                                contract_file_path = os.path.join(self.files_dir, "contracts", f"{contract_id}.contract")
                                async with aiofiles.open(contract_file_path, 'wb') as f:
                                    await f.write(contract_content)
                                with get_db_conn(self.db_path) as conn:
                                    cursor = conn.cursor()
                                    cursor.execute('SELECT 1 FROM contracts WHERE contract_id = ?', (contract_id,))
                                    if not cursor.fetchone():
                                        cursor.execute('''INSERT INTO contracts
(contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content)
                                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                            (contract_id, c['action_type'], c.get('content_hash'), c.get('domain'), 
                                             c['username'], c['signature'], c['timestamp'], c['verified'], c['contract_content']))
                                        conn.commit()
                                break

                    logger.info(f"Contract {contract_id} synced from {server_address} via {protocol_used}.")
                    return 1
                return 0
            else:
                params = {'since': since, 'limit': 100}
                success, contracts_list, protocol_used = await self.make_remote_request_json(server_address, '/sync/contracts', params=params)
                if success and isinstance(contracts_list, list):
                    count = 0
                    for contract_item in contracts_list:
                        if (contract_item.get('content_hash') or contract_item.get('domain')) and not self.should_sync_contract_target(
                            contract_item.get('content_hash'),
                            contract_item.get('domain')
                        ):
                            continue
                        with get_db_conn(self.db_path) as conn:
                            cursor = conn.cursor()
                            cursor.execute('SELECT 1 FROM contracts WHERE contract_id = ?', (contract_item['contract_id'],))
                            if not cursor.fetchone():
                                # Baixa o conteúdo do contrato
                                success_content, contract_content, _ = await self.make_remote_request(server_address, f'/contract/{contract_item["contract_id"]}')
                                if success_content:
                                    contract_file_path = os.path.join(self.files_dir, "contracts", f"{contract_item['contract_id']}.contract")
                                    async with aiofiles.open(contract_file_path, 'wb') as f:
                                        await f.write(contract_content)

                                cursor.execute('''INSERT INTO contracts
(contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                    (contract_item['contract_id'], contract_item['action_type'], contract_item.get('content_hash'), 
                                     contract_item.get('domain'), contract_item['username'], contract_item['signature'], 
                                     contract_item['timestamp'], contract_item['verified'], contract_item.get('contract_content', '')))
                                count += 1
                            conn.commit()

                    if count > 0:
                        logger.info(f"Synced {count} contracts from {server_address} via {protocol_used}.")

                    with get_db_conn(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('''INSERT OR REPLACE INTO server_sync_history
(server_address, last_sync, sync_type, items_count, success)
                            VALUES (?, ?, ?, ?, ?)''',
                            (server_address, time.time(), 'contracts', count, 1))
                        conn.commit()
                    return count
                else:
                    logger.warning(f"Could not sync contracts from {server_address}.")
                    return 0
        except Exception as e:
            logger.error(f"Unexpected error syncing contracts from {server_address}: {e}")
            return 0

    async def sync_contract_with_server(self, server_address, contract_id):
        return await self.sync_contracts_with_server(server_address, contract_id=contract_id)

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
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT address, reputation FROM server_nodes WHERE is_active = 1 AND address != ? ORDER BY reputation DESC, last_seen DESC LIMIT 1', (self.address,))
            row = cursor.fetchone()
            if row:
                self.backup_server = row[0]
                return row[0]
        return None

    async def sync_client_files(self, client_identifier, sid):
        try:
            with get_db_conn(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT content_hash, file_name, file_size FROM client_files WHERE client_identifier = ?', (client_identifier,))
                client_files = [{'content_hash': row[0], 'file_name': row[1], 'file_size': row[2]} for row in cursor.fetchall()]
                cursor.execute('SELECT domain, ddns_hash FROM client_dns_files WHERE client_identifier = ?', (client_identifier,))
                client_dns_files = [{'domain': row[0], 'ddns_hash': row[1]} for row in cursor.fetchall()]
                cursor.execute('SELECT contract_id FROM client_contracts WHERE client_identifier = ?', (client_identifier,))
                client_contracts = [{'contract_id': row[0]} for row in cursor.fetchall()]
            if client_files:
                await self.sio.emit('sync_client_files', {'files': client_files}, room=sid)
            if client_dns_files:
                await self.sio.emit('sync_client_dns_files', {'dns_files': client_dns_files}, room=sid)
            if client_contracts:
                await self.sio.emit('sync_client_contracts', {'contracts': client_contracts}, room=sid)
        except Exception as e:
            logger.error(f"Error syncing client files for {client_identifier}: {e}")

    def get_user_reputation(self, username):
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT reputation FROM user_reputations WHERE username = ?', (username,))
            row = cursor.fetchone()
            return row[0] if row else 100

    def get_user_public_key(self, username: str) -> str:
        if username in self.authenticated_users:
            return self.authenticated_users[username].get("public_key", "")
        with get_db_conn(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT public_key FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            return row[0] if row else ""

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
                with get_db_conn(self.db_path) as conn:
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
                    cursor.execute('DELETE FROM client_contracts WHERE last_sync < ?', (now - 2592000,))
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
                                with get_db_conn(self.db_path) as conn:
                                    cursor = conn.cursor()
                                    cursor.execute('UPDATE server_nodes SET last_seen = ?, reputation = MIN(100, reputation + 1) WHERE address = ?',
                                                   (time.time(), server_address))
                                    conn.commit()
                            else:
                                with get_db_conn(self.db_path) as conn:
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
        self.loop = asyncio.get_running_loop()
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
    parser.add_argument('--owner-enabled', action='store_true', help='Enable owner account revenue split')
    parser.add_argument('--owner-username', default=OWNER_USERNAME_DEFAULT, help='Owner username')
    parser.add_argument('--exchange-fee-rate', type=float, default=0.02, help='Exchange fee rate')
    parser.add_argument('--exchange-fee-min', type=int, default=1, help='Minimum exchange fee')
    args = parser.parse_args()
    server = HPSServer(
        db_path=args.db,
        files_dir=args.files,
        host=args.host,
        port=args.port,
        ssl_cert=args.ssl_cert,
        ssl_key=args.ssl_key,
        owner_enabled=args.owner_enabled,
        owner_username=args.owner_username
    )
    server.exchange_fee_rate = args.exchange_fee_rate
    server.exchange_fee_min = args.exchange_fee_min
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        asyncio.run(server.stop())
    except Exception as e:
        logger.error(f"Server error: {e}")
        asyncio.run(server.stop())
