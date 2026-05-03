#!/usr/bin/env python3
"""
AutoPentestX - Native Scanner & Fingerprinting
==============================================
Standalone TCP/UDP banner grabbing, HTTP fingerprinting, web crawler and
service identification that works WITHOUT external tools (no Nikto, no SQLMap,
no whatweb, no wappalyzer).  Used as both:

  * A primary scanner when external tools are missing or fail.
  * A fallback so that loss of any single tool doesn't degrade the assessment.

Capabilities:
  • Multi-threaded TCP connect scanner with banner grab (no raw sockets needed)
  • Service identification by banner regex + port-default mapping
  • Native HTTP/HTTPS fingerprinting:
      - Server, X-Powered-By, frameworks (Django/Flask/Rails/Spring/Laravel/etc.)
      - CMS detection (WordPress/Drupal/Joomla/Ghost/Shopify/Magento/etc.)
      - JS frameworks (React/Vue/Angular/Svelte/Next/Nuxt) from HTML+meta
      - WAF detection via response anomalies under attack probes
  • Native web crawler:
      - Same-origin BFS up to configurable depth
      - HTML <a>, <form>, <script src>, <link href> extraction
      - robots.txt + sitemap.xml ingestion
      - JS file regex-based endpoint discovery (fetch/axios/api/ patterns)
      - Form parameter inventory for downstream injection testing
  • CVE matching against the local KB in vuln_scanner.KB_VULNS
  • Optional EPSS-aware risk weighting (lazy-loaded)

Everything is pure-Python stdlib + (optional) requests for crawler convenience.
No subprocesses, no nmap dependency in this module.
"""

from __future__ import annotations

import concurrent.futures
import gzip
import hashlib
import html
import io
import json
import os
import re
import socket
import ssl
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple


# ─────────────────────────────────────────────────────────────────────────────
#  PORT → DEFAULT SERVICE MAPPING (only used when banner is silent)
# ─────────────────────────────────────────────────────────────────────────────
PORT_DEFAULTS: Dict[int, str] = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc', 139: 'netbios-ssn',
    143: 'imap', 161: 'snmp', 389: 'ldap', 443: 'https', 445: 'microsoft-ds',
    465: 'smtps', 514: 'syslog', 587: 'submission', 631: 'ipp',
    636: 'ldaps', 873: 'rsync', 993: 'imaps', 995: 'pop3s',
    1080: 'socks', 1433: 'mssql', 1521: 'oracle', 1723: 'pptp',
    2049: 'nfs', 2375: 'docker', 2376: 'docker-tls', 2379: 'etcd',
    3000: 'http-alt', 3128: 'squid-proxy', 3306: 'mysql',
    3389: 'rdp', 4369: 'epmd', 4443: 'https-alt', 5000: 'http-alt',
    5432: 'postgresql', 5601: 'kibana', 5672: 'amqp', 5900: 'vnc',
    5984: 'couchdb', 6379: 'redis', 7001: 'weblogic', 7474: 'neo4j',
    8000: 'http-alt', 8008: 'http-alt', 8080: 'http-proxy', 8081: 'http-alt',
    8086: 'influxdb', 8161: 'activemq', 8443: 'https-alt',
    8500: 'consul', 8888: 'http-alt', 9000: 'http-alt', 9042: 'cassandra',
    9090: 'prometheus', 9200: 'elasticsearch', 9300: 'elasticsearch',
    9418: 'git', 9999: 'http-alt', 10000: 'webmin', 11211: 'memcached',
    15672: 'rabbitmq-mgmt', 27017: 'mongodb', 50070: 'hadoop',
}


# ─────────────────────────────────────────────────────────────────────────────
#  BANNER FINGERPRINTS — (regex, service, product[, version_group])
# ─────────────────────────────────────────────────────────────────────────────
BANNER_PATTERNS: List[Tuple[re.Pattern, str, str, Optional[int]]] = [
    (re.compile(r'^SSH-([\d.]+)-(\S+)',         re.I), 'ssh',     'openssh',     2),
    (re.compile(r'OpenSSH[_ ]([\d.p]+)',        re.I), 'ssh',     'openssh',     1),
    (re.compile(r'220.*?vsFTPd\s+([\d.]+)',     re.I), 'ftp',     'vsftpd',      1),
    (re.compile(r'220.*?ProFTPD\s+([\d.]+)',    re.I), 'ftp',     'proftpd',     1),
    (re.compile(r'220.*?Pure-FTPd',             re.I), 'ftp',     'pureftpd',    None),
    (re.compile(r'220.*?Microsoft FTP',         re.I), 'ftp',     'msftp',       None),
    (re.compile(r'^220.*?ESMTP\s+(\S+)',        re.I), 'smtp',    None,          None),
    (re.compile(r'\(Postfix(?:\s+([\d.]+))?\)', re.I), 'smtp',    'postfix',     1),
    (re.compile(r'Sendmail\s+([\d.]+)',         re.I), 'smtp',    'sendmail',    1),
    (re.compile(r'Microsoft ESMTP MAIL Service',re.I), 'smtp',    'exchange',    None),
    (re.compile(r'Exim\s+([\d.]+)',             re.I), 'smtp',    'exim',        1),
    (re.compile(r'mysql_native_password',       re.I), 'mysql',   'mysql',       None),
    (re.compile(r'^.\x00\x00.\x0a([\d.]+)',     re.I), 'mysql',   'mysql',       1),
    (re.compile(r'PostgreSQL\s+([\d.]+)',       re.I), 'postgres','postgres',    1),
    (re.compile(r'redis_version:([\d.]+)',      re.I), 'redis',   'redis',       1),
    (re.compile(r'\$\d\$\$VERSION\s+(\S+)',     re.I), 'memcached','memcached',  1),
    (re.compile(r'STAT version\s+([\d.]+)',     re.I), 'memcached','memcached',  1),
    (re.compile(r'\* OK\s+\[CAPABILITY.*?Dovecot',re.I),'imap',   'dovecot',     None),
    (re.compile(r'\* OK\s+(\S+) Cyrus IMAP',    re.I), 'imap',    'cyrus',       None),
    (re.compile(r'^\+OK Dovecot',               re.I), 'pop3',    'dovecot',     None),
    (re.compile(r'^RFB\s+(\d{3}\.\d{3})',       re.I), 'vnc',     'rfb',         1),
]


# ─────────────────────────────────────────────────────────────────────────────
#  HTTP TECHNOLOGY FINGERPRINTS — (label, header_regex, body_regex)
# ─────────────────────────────────────────────────────────────────────────────
HTTP_TECH_FINGERPRINTS: List[Tuple[str, Optional[str], Optional[str], str]] = [
    # (label, header_pattern, body_pattern, category)
    ('WordPress',   None, r'/wp-content/|wp-includes|wp-json',                       'CMS'),
    ('Drupal',      r'X-Generator:\s*Drupal', r'<meta name="Generator" content="Drupal', 'CMS'),
    ('Joomla',      None, r'<meta name="generator" content="Joomla',                  'CMS'),
    ('Ghost',       r'X-Powered-By:\s*Express', r'ghost-version|content/themes',      'CMS'),
    ('Shopify',     r'X-Shopify', r'cdn\.shopify\.com',                               'eCommerce'),
    ('Magento',     None, r'/skin/frontend/|Mage\.Cookies|/static/version',           'eCommerce'),
    ('Django',      r'csrftoken|sessionid', r'__admin_media_prefix__|django',         'Framework'),
    ('Flask',       r'Server:\s*Werkzeug', None,                                       'Framework'),
    ('FastAPI',     r'Server:\s*uvicorn', None,                                        'Framework'),
    ('Express',     r'X-Powered-By:\s*Express', None,                                  'Framework'),
    ('Rails',       r'X-Powered-By:\s*(Phusion Passenger|Ruby on Rails)|x-rack', None,'Framework'),
    ('Laravel',     r'XSRF-TOKEN|laravel_session', None,                               'Framework'),
    ('Spring Boot', None, r'Whitelabel Error Page|/actuator/health',                  'Framework'),
    ('ASP.NET',     r'X-AspNet-Version|X-Powered-By:\s*ASP\.NET', None,                'Framework'),
    ('Tomcat',      r'Server:\s*Apache.?Tomcat', None,                                 'AppServer'),
    ('JBoss',       r'X-Powered-By:\s*JBoss', None,                                    'AppServer'),
    ('WebLogic',    r'Server:\s*WebLogic', None,                                       'AppServer'),
    ('Apache',      r'Server:\s*Apache(?:/([\d.]+))?', None,                           'WebServer'),
    ('nginx',       r'Server:\s*nginx(?:/([\d.]+))?', None,                            'WebServer'),
    ('IIS',         r'Server:\s*Microsoft-IIS/?([\d.]+)?', None,                       'WebServer'),
    ('Caddy',       r'Server:\s*Caddy', None,                                          'WebServer'),
    ('Lighttpd',    r'Server:\s*lighttpd', None,                                       'WebServer'),
    ('Cloudflare',  r'CF-RAY|Server:\s*cloudflare', None,                              'CDN'),
    ('Akamai',      r'X-Akamai|Server:\s*AkamaiGHost', None,                           'CDN'),
    ('Fastly',      r'X-Served-By:\s*cache-.*?-fastly|Fastly-Debug', None,             'CDN'),
    ('CloudFront',  r'X-Amz-Cf-Id|Server:\s*CloudFront', None,                         'CDN'),
    ('jQuery',      None, r'jquery[.-]?\d+\.\d+|\$\.fn\.jquery',                       'JS'),
    ('React',       None, r'react(?:-dom)?[\.-]?(?:production|development)|data-reactroot|_reactRootContainer', 'JS'),
    ('Vue.js',      None, r'\bv-(?:if|for|model|bind|on)\b|\bdata-v-',                 'JS'),
    ('Angular',     None, r'ng-(?:app|controller|model|click)|angular\.min\.js',       'JS'),
    ('Next.js',     None, r'__NEXT_DATA__|/_next/static',                              'JS'),
    ('Nuxt.js',     None, r'window\.__NUXT__',                                          'JS'),
    ('Svelte',      None, r'svelte-\w+\b',                                              'JS'),
    ('GraphQL',     None, r'__schema|graphql-playground|altair-graphql',               'API'),
    ('Swagger',     None, r'swagger-ui|/swagger-ui-bundle|/v2/api-docs',               'API'),
    ('PHP',         r'X-Powered-By:\s*PHP/?([\d.]+)?', None,                           'Language'),
    ('phpMyAdmin',  None, r'phpMyAdmin|pma_username',                                  'Tool'),
    ('Jenkins',     r'X-Jenkins:\s*([\d.]+)?', None,                                   'CICD'),
    ('GitLab',      None, r'GitLab Community Edition|gitlab-static',                   'CICD'),
    ('Grafana',     r'Grafana', r'grafanaBootData',                                    'Monitoring'),
    ('Kibana',      None, r'kbn-name|kbn-version|app/kibana',                          'Monitoring'),
    ('Prometheus',  None, r'<title>Prometheus',                                        'Monitoring'),
]


# ─────────────────────────────────────────────────────────────────────────────
#  WAF FINGERPRINTS — both passive (headers) and active (response anomalies)
# ─────────────────────────────────────────────────────────────────────────────
WAF_PASSIVE_PATTERNS: List[Tuple[str, str]] = [
    ('Cloudflare',           r'cf-ray|__cfduid|server:\s*cloudflare'),
    ('Akamai',               r'akamai|x-akamai-'),
    ('Imperva Incapsula',    r'incap_ses|visid_incap|x-iinfo'),
    ('F5 BIG-IP ASM',        r'bigipserver|ts[0-9a-f]{8}'),
    ('AWS WAF',              r'awswaf|x-amz-cf-id'),
    ('Sucuri',               r'sucuri|x-sucuri-id'),
    ('ModSecurity',          r'mod_security|modsecurity'),
    ('Barracuda',            r'barra_counter_session'),
    ('Fortinet FortiWeb',    r'fortiwafsid'),
    ('Citrix NetScaler',     r'ns_af|citrix_ns_id'),
    ('Wallarm',              r'nemesida|wallarm'),
    ('Reblaze',              r'rbzid'),
]


# ─────────────────────────────────────────────────────────────────────────────
#  DATA CLASSES
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class NativeScanPort:
    port: int
    protocol: str
    state: str
    service: str
    product: Optional[str]
    version: Optional[str]
    banner: Optional[str]
    confidence: float
    rtt_ms: float


@dataclass
class HttpFingerprint:
    url: str
    status: int
    server: Optional[str]
    technologies: List[Dict[str, str]]
    waf: List[str]
    headers: Dict[str, str]
    title: Optional[str]
    length: int
    response_time_ms: float


@dataclass
class CrawlEndpoint:
    url: str
    method: str
    parameters: List[str]
    discovered_from: str
    content_type: Optional[str] = None
    status: Optional[int] = None


# ─────────────────────────────────────────────────────────────────────────────
#  TCP CONNECT SCANNER + BANNER GRABBER (no raw sockets, no root needed)
# ─────────────────────────────────────────────────────────────────────────────
class NativePortScanner:
    """TCP connect() scanner.  No raw sockets / no root required."""

    def __init__(self, timeout: float = 1.5, threads: int = 200) -> None:
        self.timeout = timeout
        self.threads = threads

    def scan(self, host: str, ports: Iterable[int]) -> List[NativeScanPort]:
        results: List[NativeScanPort] = []

        def probe(p: int) -> Optional[NativeScanPort]:
            t0 = time.perf_counter()
            try:
                s = socket.create_connection((host, p), timeout=self.timeout)
            except (socket.timeout, ConnectionRefusedError, OSError):
                return None
            rtt = (time.perf_counter() - t0) * 1000.0
            try:
                s.settimeout(self.timeout)
                # Service-specific probes when port is silent
                banner = self._grab_banner(s, p)
            finally:
                try:
                    s.close()
                except Exception:
                    pass
            service, product, version, conf = self._identify(banner, p)
            return NativeScanPort(
                port=p, protocol='tcp', state='open',
                service=service, product=product, version=version,
                banner=banner[:512] if banner else None,
                confidence=conf, rtt_ms=round(rtt, 2),
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as pool:
            for r in pool.map(probe, ports):
                if r is not None:
                    results.append(r)
        results.sort(key=lambda x: x.port)
        return results

    def _grab_banner(self, s: socket.socket, port: int) -> str:
        """Read whatever the service offers; for silent services send a probe."""
        try:
            # Many services greet immediately
            data = s.recv(2048)
            if data:
                return data.decode('latin1', 'ignore').strip()
        except socket.timeout:
            data = b''

        # Active probes for silent/HTTP-like services
        try:
            if port in (80, 8080, 8000, 8888, 3000, 5000, 9000, 9090, 8081):
                s.sendall(b'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n')
            elif port in (443, 8443, 4443):
                pass    # TLS — handled by HTTP fingerprinter separately
            elif port == 25 or port == 587:
                s.sendall(b'EHLO autopentestx.local\r\n')
            elif port == 110:
                s.sendall(b'CAPA\r\n')
            elif port == 143:
                s.sendall(b'A1 CAPABILITY\r\n')
            elif port == 6379:
                s.sendall(b'INFO\r\n')
            elif port == 11211:
                s.sendall(b'version\r\n')
            elif port == 21:
                pass    # FTP greets
            elif port == 22:
                pass    # SSH greets
            try:
                data = s.recv(2048)
                return data.decode('latin1', 'ignore').strip()
            except socket.timeout:
                return ''
        except (BrokenPipeError, ConnectionResetError, OSError):
            return ''
        return ''

    def _identify(self, banner: str, port: int) -> Tuple[str, Optional[str], Optional[str], float]:
        """Return (service, product, version, confidence)."""
        if banner:
            for pat, svc, prod, vgrp in BANNER_PATTERNS:
                m = pat.search(banner)
                if m:
                    version = m.group(vgrp).strip() if vgrp else None
                    return svc, prod, version, 0.95
            # HTTP heuristics
            if banner.startswith('HTTP/'):
                m = re.search(r'Server:\s*([^\r\n]+)', banner, re.I)
                if m:
                    return 'http', None, m.group(1).strip(), 0.85
                return 'http', None, None, 0.7
        # Fall back to port default with low confidence
        default_svc = PORT_DEFAULTS.get(port, 'unknown')
        return default_svc, None, None, 0.4 if default_svc != 'unknown' else 0.1


# ─────────────────────────────────────────────────────────────────────────────
#  HTTP FINGERPRINTER + WEB CRAWLER
# ─────────────────────────────────────────────────────────────────────────────
class NativeHttpFingerprinter:
    """Self-contained HTTP fingerprinter — no requests dependency required."""

    def __init__(self, timeout: float = 8.0, user_agent: Optional[str] = None) -> None:
        self.timeout = timeout
        self.user_agent = user_agent or (
            'Mozilla/5.0 (X11; Linux x86_64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'AutoPentestX/2.0'
        )
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    def _http_get(self, url: str, headers: Optional[Dict[str, str]] = None,
                  data: Optional[bytes] = None,
                  method: str = 'GET') -> Tuple[int, Dict[str, str], str, float]:
        h = {
            'User-Agent': self.user_agent,
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
        }
        if headers:
            h.update(headers)
        try:
            req = urllib.request.Request(url, headers=h, method=method, data=data)
            t0 = time.perf_counter()
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                raw = resp.read(2 * 1024 * 1024)
                elapsed = (time.perf_counter() - t0) * 1000.0
                hdrs = dict(resp.headers)
                body = self._decompress(raw, hdrs).decode('utf-8', errors='ignore')
                return resp.status, hdrs, body, elapsed
        except urllib.error.HTTPError as e:
            elapsed = (time.perf_counter() - t0) * 1000.0 if 't0' in locals() else 0.0
            try:
                raw = e.read(2 * 1024 * 1024)
            except Exception:
                raw = b''
            hdrs = dict(e.headers) if e.headers else {}
            body = self._decompress(raw, hdrs).decode('utf-8', errors='ignore')
            return e.code, hdrs, body, elapsed
        except Exception:
            return 0, {}, '', 0.0

    @staticmethod
    def _decompress(raw: bytes, headers: Dict[str, str]) -> bytes:
        enc = headers.get('Content-Encoding', '').lower()
        try:
            if 'gzip' in enc:
                return gzip.decompress(raw)
            if 'deflate' in enc:
                return zlib.decompress(raw)
        except Exception:
            pass
        return raw

    def fingerprint(self, url: str) -> HttpFingerprint:
        status, headers, body, elapsed = self._http_get(url)
        title_match = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
        title = html.unescape(title_match.group(1).strip()) if title_match else None
        haystack_headers = '\n'.join(f'{k}: {v}' for k, v in headers.items())

        techs: List[Dict[str, str]] = []
        for label, hdr_pat, body_pat, category in HTTP_TECH_FINGERPRINTS:
            ver = None
            hit = False
            if hdr_pat:
                m = re.search(hdr_pat, haystack_headers, re.I)
                if m:
                    hit = True
                    if m.lastindex:
                        ver = m.group(1)
            if not hit and body_pat:
                if re.search(body_pat, body, re.I):
                    hit = True
            if hit:
                entry = {'name': label, 'category': category}
                if ver:
                    entry['version'] = ver
                techs.append(entry)

        wafs: List[str] = []
        for label, pat in WAF_PASSIVE_PATTERNS:
            if re.search(pat, haystack_headers + '\n' + body[:4096], re.I):
                wafs.append(label)
        wafs = sorted(set(wafs))

        return HttpFingerprint(
            url=url, status=status, server=headers.get('Server'),
            technologies=techs, waf=wafs, headers=headers, title=title,
            length=len(body), response_time_ms=round(elapsed, 2),
        )

    # Active WAF probe — confirm what passive missed
    def probe_waf_active(self, url: str) -> List[str]:
        """Send a benign-looking attack payload and inspect the response."""
        baseline_status, baseline_headers, baseline_body, _ = self._http_get(url)
        if baseline_status == 0:
            return []
        # Payload that any modern WAF will block
        attack = url.rstrip('/') + "/?q=1' OR 1=1-- -<script>alert(1)</script>../etc/passwd"
        attack_status, attack_headers, attack_body, _ = self._http_get(attack)
        if attack_status == 0:
            return []
        wafs: List[str] = []
        # If status changed dramatically AND keywords appear, infer WAF.
        block_keywords = ('access denied', 'blocked', 'forbidden by waf',
                           'request blocked', 'security policy', 'attack detected',
                           'incident id', 'request id', 'reference #')
        if attack_status in (403, 406, 419, 429, 451, 503) and \
                attack_status != baseline_status:
            ablow = attack_body.lower()
            if any(k in ablow for k in block_keywords):
                wafs.append('Generic WAF (active probe)')
            for label, pat in WAF_PASSIVE_PATTERNS:
                merged = '\n'.join(f'{k}: {v}' for k, v in attack_headers.items())
                merged += '\n' + attack_body[:4096]
                if re.search(pat, merged, re.I):
                    wafs.append(label)
        return sorted(set(wafs))


# ─────────────────────────────────────────────────────────────────────────────
#  WEB CRAWLER + ENDPOINT EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────
class NativeWebCrawler:
    """Same-origin BFS crawler that extracts endpoints, forms, and JS API calls."""

    JS_ENDPOINT_PATTERNS: List[re.Pattern] = [
        re.compile(r'''(?:fetch|axios\.\w+|XMLHttpRequest\(\)\.open)\s*\(\s*['"`]([^'"`]+)''', re.I),
        re.compile(r'''['"]/(api|v1|v2|v3|graphql|rest)/[A-Za-z0-9_/.-]+['"]'''),
        re.compile(r'''url\s*:\s*['"`]([^'"`]+)['"`]''', re.I),
        re.compile(r'''['"](https?://[^'"\s]+)['"]'''),
    ]
    INTERESTING_FILES: Tuple[str, ...] = (
        'robots.txt', 'sitemap.xml', '.well-known/security.txt',
        '.well-known/openid-configuration',
    )

    def __init__(self, fingerprinter: NativeHttpFingerprinter,
                 max_depth: int = 2, max_pages: int = 200,
                 timeout: float = 6.0) -> None:
        self.fp = fingerprinter
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout

    def crawl(self, start_url: str) -> Dict[str, Any]:
        parsed = urllib.parse.urlsplit(start_url)
        origin = (parsed.scheme, parsed.netloc)
        visited: Set[str] = set()
        endpoints: Dict[str, CrawlEndpoint] = {}
        forms: List[Dict[str, Any]] = []
        js_files: Set[str] = set()
        external_refs: Set[str] = set()

        queue: deque = deque([(start_url.rstrip('/'), 0)])

        while queue and len(visited) < self.max_pages:
            url, depth = queue.popleft()
            if url in visited or depth > self.max_depth:
                continue
            visited.add(url)
            status, headers, body, _ = self.fp._http_get(url)
            if status == 0:
                continue
            ct = headers.get('Content-Type', '')
            ep = CrawlEndpoint(url=url, method='GET', parameters=[],
                                discovered_from='crawl',
                                content_type=ct, status=status)
            qs = urllib.parse.urlsplit(url).query
            if qs:
                ep.parameters = [k for k, _ in urllib.parse.parse_qsl(qs)]
            endpoints[url] = ep

            if 'text/html' not in ct.lower() and not body.lstrip().startswith('<'):
                # Maybe a JS file — extract fetch/axios endpoints anyway
                if 'javascript' in ct.lower() or url.endswith('.js'):
                    self._extract_js_endpoints(body, origin, endpoints, external_refs)
                continue

            self._extract_html_links(url, body, depth, origin, queue, endpoints,
                                       forms, js_files, external_refs)

        # Fetch known well-known files separately
        for path in self.INTERESTING_FILES:
            url = f'{parsed.scheme}://{parsed.netloc}/{path}'
            if url in visited:
                continue
            status, _, body, _ = self.fp._http_get(url)
            if status == 200 and body:
                endpoints[url] = CrawlEndpoint(url=url, method='GET', parameters=[],
                                                discovered_from='well-known',
                                                content_type='text/plain', status=200)
                if path == 'robots.txt':
                    for line in body.splitlines():
                        m = re.match(r'^\s*Disallow:\s*(\S+)', line, re.I)
                        if m:
                            disallowed = urllib.parse.urljoin(url, m.group(1))
                            endpoints.setdefault(disallowed, CrawlEndpoint(
                                url=disallowed, method='GET', parameters=[],
                                discovered_from='robots.txt'))
                elif path == 'sitemap.xml':
                    for loc in re.findall(r'<loc>([^<]+)</loc>', body):
                        endpoints.setdefault(loc, CrawlEndpoint(
                            url=loc, method='GET', parameters=[],
                            discovered_from='sitemap'))

        # Crawl JS files for hidden endpoints
        for js in list(js_files)[:30]:
            status, _, body, _ = self.fp._http_get(js)
            if status == 200 and body:
                self._extract_js_endpoints(body, origin, endpoints, external_refs)

        return {
            'pages_visited': len(visited),
            'endpoints': [asdict(e) for e in endpoints.values()],
            'forms': forms,
            'js_files': sorted(js_files),
            'external_refs': sorted(external_refs)[:200],
        }

    def _extract_html_links(self, url: str, body: str, depth: int,
                            origin: Tuple[str, str], queue: deque,
                            endpoints: Dict[str, CrawlEndpoint],
                            forms: List[Dict[str, Any]],
                            js_files: Set[str], external_refs: Set[str]) -> None:
        # <a href>
        for m in re.finditer(r'<a\b[^>]*?\bhref\s*=\s*["\']([^"\']+)["\']',
                              body, re.I):
            link = urllib.parse.urljoin(url, html.unescape(m.group(1)))
            self._dispatch_link(link, origin, depth, queue, endpoints,
                                 js_files, external_refs)
        # <link href>
        for m in re.finditer(r'<link\b[^>]*?\bhref\s*=\s*["\']([^"\']+)["\']',
                              body, re.I):
            link = urllib.parse.urljoin(url, html.unescape(m.group(1)))
            self._dispatch_link(link, origin, depth, queue, endpoints,
                                 js_files, external_refs)
        # <script src>
        for m in re.finditer(r'<script\b[^>]*?\bsrc\s*=\s*["\']([^"\']+)["\']',
                              body, re.I):
            link = urllib.parse.urljoin(url, html.unescape(m.group(1)))
            self._dispatch_link(link, origin, depth, queue, endpoints,
                                 js_files, external_refs)
            if link.endswith('.js'):
                js_files.add(link)
        # <form>
        for fm in re.finditer(r'<form\b([^>]*)>(.*?)</form>', body, re.I | re.S):
            attrs = fm.group(1)
            inner = fm.group(2)
            action_m = re.search(r'\baction\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
            method_m = re.search(r'\bmethod\s*=\s*["\']([^"\']+)["\']', attrs, re.I)
            action = urllib.parse.urljoin(url, html.unescape(action_m.group(1))) if action_m else url
            method = method_m.group(1).upper() if method_m else 'GET'
            params = []
            for inp in re.finditer(r'<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["\']([^"\']+)["\']',
                                     inner, re.I):
                params.append(inp.group(1))
            forms.append({'action': action, 'method': method, 'parameters': params})
            endpoints.setdefault(action, CrawlEndpoint(
                url=action, method=method, parameters=params,
                discovered_from='form'))

    def _dispatch_link(self, link: str, origin: Tuple[str, str], depth: int,
                        queue: deque, endpoints: Dict[str, CrawlEndpoint],
                        js_files: Set[str], external_refs: Set[str]) -> None:
        try:
            sp = urllib.parse.urlsplit(link)
        except Exception:
            return
        if not sp.netloc:
            return
        if (sp.scheme, sp.netloc) != origin:
            external_refs.add(link)
            return
        # Strip fragment, normalize
        clean = urllib.parse.urlunsplit((sp.scheme, sp.netloc, sp.path or '/',
                                           sp.query, ''))
        if sp.path.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
                              '.css', '.woff', '.woff2', '.ttf', '.eot',
                              '.mp4', '.mp3', '.pdf', '.zip')):
            return
        if clean not in endpoints and depth + 1 <= self.max_depth:
            queue.append((clean, depth + 1))

    def _extract_js_endpoints(self, body: str, origin: Tuple[str, str],
                                endpoints: Dict[str, CrawlEndpoint],
                                external_refs: Set[str]) -> None:
        for pat in self.JS_ENDPOINT_PATTERNS:
            for m in pat.finditer(body):
                raw = m.group(1) if m.lastindex else m.group(0)
                if raw.startswith('//') or raw.startswith('http'):
                    sp = urllib.parse.urlsplit(raw if raw.startswith('http') else 'https:' + raw)
                    if (sp.scheme, sp.netloc) != origin:
                        external_refs.add(raw)
                        continue
                    full = raw
                else:
                    if not raw.startswith('/'):
                        continue
                    full = f'{origin[0]}://{origin[1]}{raw}'
                endpoints.setdefault(full, CrawlEndpoint(
                    url=full, method='GET', parameters=[],
                    discovered_from='js'))


# ─────────────────────────────────────────────────────────────────────────────
#  ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────
class NativeAssessor:
    """Run the full native pipeline: scan → fingerprint → crawl → KB-match."""

    DEFAULT_TOP_PORTS: Tuple[int, ...] = (
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443,
        445, 465, 587, 631, 636, 873, 993, 995, 1080, 1433, 1521, 1723,
        2049, 2375, 2376, 2379, 3000, 3128, 3306, 3389, 4369, 4443, 5000,
        5432, 5601, 5672, 5900, 5984, 6379, 7001, 7474, 8000, 8008, 8080,
        8081, 8086, 8161, 8443, 8500, 8888, 9000, 9042, 9090, 9200,
        9300, 9418, 9999, 10000, 11211, 15672, 27017, 50070,
    )

    def __init__(self, target: str, ports: Optional[Iterable[int]] = None,
                 crawl_depth: int = 2, crawl_max_pages: int = 150) -> None:
        self.target = target
        self.ports = list(ports) if ports else list(self.DEFAULT_TOP_PORTS)
        self.crawl_depth = crawl_depth
        self.crawl_max_pages = crawl_max_pages
        self.scanner = NativePortScanner()
        self.fp = NativeHttpFingerprinter()
        self.crawler = NativeWebCrawler(self.fp, max_depth=crawl_depth,
                                          max_pages=crawl_max_pages)
        self.results: Dict[str, Any] = {
            'target': target, 'started_at': datetime.now().isoformat(),
            'ports': [], 'http': [], 'crawl': [], 'kb_matches': [],
        }

    def assess(self) -> Dict[str, Any]:
        print(f'[*] Native scan of {self.target} ({len(self.ports)} ports)...')
        ports = self.scanner.scan(self.target, self.ports)
        self.results['ports'] = [asdict(p) for p in ports]
        print(f'[✓] {len(ports)} open ports identified')

        # HTTP fingerprint each web port
        web_ports = [p for p in ports
                     if p.service in ('http', 'https') or
                        p.port in (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000)]
        for wp in web_ports:
            scheme = 'https' if wp.port in (443, 8443, 4443) or wp.service == 'https' else 'http'
            url = f'{scheme}://{self.target}:{wp.port}'
            print(f'[*] Fingerprinting {url}')
            fpr = self.fp.fingerprint(url)
            # Active WAF confirmation only when nothing found passively
            if not fpr.waf:
                fpr.waf = self.fp.probe_waf_active(url)
            self.results['http'].append(asdict(fpr))
            for tech in fpr.technologies:
                ver = tech.get('version', '')
                print(f'    → {tech["name"]:<14} '
                      f'{("v" + ver) if ver else "":<10} [{tech["category"]}]')
            if fpr.waf:
                print(f'    → WAF: {", ".join(fpr.waf)}')

            # Crawl
            print(f'[*] Crawling {url} (depth={self.crawl_depth})')
            crawl = self.crawler.crawl(url)
            crawl['base_url'] = url
            self.results['crawl'].append(crawl)
            print(f'    → {crawl["pages_visited"]} pages, '
                  f'{len(crawl["endpoints"])} endpoints, '
                  f'{len(crawl["forms"])} forms')

        # KB matching (lazy import to avoid circular deps)
        self.results['kb_matches'] = self._kb_match(ports)
        print(f'[✓] {len(self.results["kb_matches"])} CVE matches from native KB')

        self.results['completed_at'] = datetime.now().isoformat()
        return self.results

    def _kb_match(self, ports: List[NativeScanPort]) -> List[Dict[str, Any]]:
        try:
            from modules.vuln_scanner import (KB_VULNS, normalize_product,
                                                version_in_range)
        except Exception:
            return []
        matches: List[Dict[str, Any]] = []
        for p in ports:
            if not p.product:
                continue
            key = normalize_product(p.service, p.version or p.product)
            if not key:
                continue
            for entry in KB_VULNS.get(key, []):
                if not p.version:
                    matches.append({
                        'port': p.port, 'cve': entry.get('cve'),
                        'name': entry['name'], 'severity': entry['severity'],
                        'cvss': entry['cvss'], 'confidence': 0.30,
                        'rationale': f'{entry["rationale"]} (version unknown)',
                    })
                    continue
                if version_in_range(p.version, entry['range']):
                    matches.append({
                        'port': p.port, 'cve': entry.get('cve'),
                        'name': entry['name'], 'severity': entry['severity'],
                        'cvss': entry['cvss'], 'confidence': 0.95,
                        'rationale': entry['rationale'],
                        'observed_version': p.version,
                    })
        return matches


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print('Usage: python native_scanner.py <target>')
        sys.exit(1)
    a = NativeAssessor(sys.argv[1])
    out = a.assess()
    print(json.dumps(out, indent=2, default=str)[:4000])
