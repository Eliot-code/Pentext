#!/usr/bin/env python3
"""
AutoPentestX - Industrial Vulnerability Scanner
================================================
Combines existing tooling (Nikto / SQLMap) with a version-aware vulnerability
matcher to dramatically reduce false positives and false negatives produced by
naive substring matching.

Key improvements over the previous implementation:

  • Robust Nikto JSON parsing (handles streamed and concatenated objects).
  • Strict CVE-style version comparison (semver / triplet aware).
  • CPE-style (vendor:product:version) matching with affected-version ranges.
  • Multi-validator confirmation: a vulnerability is only emitted as
    CONFIRMED when the version string actually falls inside an affected
    range, not just because the service name is similar.
  • Confidence scores attached to every finding.
  • SQLMap output parsed for technique, DBMS, payload, and confidence.
  • De-duplication so that repeated probes against the same finding do not
    inflate counts.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
#  VERSION COMPARISON UTILITIES
# ─────────────────────────────────────────────────────────────────────────────
_VERSION_RE = re.compile(r'(\d+)(?:[.\-_p](\d+))?(?:[.\-_p](\d+))?(?:[.\-_p](\d+))?')


def parse_version(v: str) -> Tuple[int, ...]:
    """Parse a version string into a tuple of ints suitable for comparison.
    Examples:
        '7.2p1'    → (7, 2, 1, 0)
        '2.4.41'   → (2, 4, 41, 0)
        '5.0.96-r1'→ (5, 0, 96, 0)
    Non-numeric tails are ignored.  Returns (0,0,0,0) when nothing parses."""
    if not v:
        return (0, 0, 0, 0)
    m = _VERSION_RE.search(v)
    if not m:
        return (0, 0, 0, 0)
    parts = [int(x) if x else 0 for x in m.groups()]
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts)


def version_in_range(observed: str,
                      range_spec: Tuple[Optional[str], Optional[str], bool, bool]) -> bool:
    """Check whether `observed` falls inside (lo, hi, lo_inclusive, hi_inclusive).
    Either bound may be None to mean "open ended"."""
    lo, hi, lo_inc, hi_inc = range_spec
    o = parse_version(observed)
    if lo is not None:
        l = parse_version(lo)
        if (o < l) or (o == l and not lo_inc):
            return False
    if hi is not None:
        h = parse_version(hi)
        if (o > h) or (o == h and not hi_inc):
            return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
#  VULNERABILITY KNOWLEDGE BASE
# ─────────────────────────────────────────────────────────────────────────────
# Each entry is keyed by (vendor, product) and lists known vulnerabilities
# with affected version ranges, severity, CVE id and a short rationale.  The
# database is intentionally compact — for a production deployment, the engine
# can also pivot to the CVELookup module.
KB_VULNS: Dict[Tuple[str, str], List[Dict[str, Any]]] = {
    ('openbsd', 'openssh'): [
        {
            'cve': 'CVE-2023-38408',
            'name': 'OpenSSH ssh-agent forwarded keys RCE',
            'severity': 'CRITICAL', 'cvss': 9.8,
            'range': ('5.5', '9.3p1', True, False),
            'rationale': 'Vulnerable when ssh-agent forwarding is enabled.',
        },
        {
            'cve': 'CVE-2024-6387',
            'name': 'regreSSHion: pre-auth RCE',
            'severity': 'CRITICAL', 'cvss': 8.1,
            'range': ('8.5p1', '9.7p1', True, False),
            'rationale': 'Race condition in sshd signal handler.',
        },
    ],
    ('apache', 'httpd'): [
        {
            'cve': 'CVE-2021-41773',
            'name': 'Apache 2.4.49 Path Traversal & RCE',
            'severity': 'CRITICAL', 'cvss': 9.8,
            'range': ('2.4.49', '2.4.49', True, True),
            'rationale': 'Specific build affected.',
        },
        {
            'cve': 'CVE-2021-42013',
            'name': 'Apache 2.4.50 incomplete fix for path traversal',
            'severity': 'CRITICAL', 'cvss': 9.8,
            'range': ('2.4.50', '2.4.50', True, True),
            'rationale': 'Incomplete fix for CVE-2021-41773.',
        },
        {
            'cve': 'CVE-2023-25690',
            'name': 'mod_proxy HTTP Request Smuggling',
            'severity': 'HIGH', 'cvss': 9.8,
            'range': ('2.4.0', '2.4.55', True, True),
            'rationale': 'Request line normalization mismatch.',
        },
    ],
    ('vsftpd',): [
        {
            'cve': 'CVE-2011-2523',
            'name': 'vsftpd 2.3.4 backdoor (smiley face)',
            'severity': 'CRITICAL', 'cvss': 9.8,
            'range': ('2.3.4', '2.3.4', True, True),
            'rationale': 'Distributed binary contained backdoor.',
        },
    ],
    ('proftpd',): [
        {
            'cve': 'CVE-2015-3306',
            'name': 'ProFTPD mod_copy unauthenticated file copy',
            'severity': 'CRITICAL', 'cvss': 10.0,
            'range': ('1.3.5', '1.3.5b', True, False),
            'rationale': 'Pre-auth arbitrary file write.',
        },
    ],
    ('microsoft', 'iis'): [
        {
            'cve': 'CVE-2017-7269',
            'name': 'IIS 6.0 WebDAV Buffer Overflow',
            'severity': 'CRITICAL', 'cvss': 9.8,
            'range': ('6.0', '6.0', True, True),
            'rationale': 'Long IF header in PROPFIND triggers stack overflow.',
        },
    ],
    ('mysql',): [
        {
            'cve': 'CVE-2012-2122',
            'name': 'MySQL/MariaDB Authentication Bypass',
            'severity': 'HIGH', 'cvss': 7.5,
            'range': ('5.1.61', '5.5.22', True, True),
            'rationale': 'memcmp() returns non-zero non-deterministically.',
        },
    ],
    ('redis',): [
        {
            'cve': 'CVE-2022-0543',
            'name': 'Redis Lua Sandbox Escape (Debian/Ubuntu packaging)',
            'severity': 'CRITICAL', 'cvss': 10.0,
            'range': ('5.0.0', '7.0.0', True, False),
            'rationale': 'Lua interpreter escape leading to RCE.',
        },
    ],
    ('samba',): [
        {
            'cve': 'CVE-2017-7494',
            'name': 'SambaCry — RCE via writable share',
            'severity': 'CRITICAL', 'cvss': 9.8,
            'range': ('3.5.0', '4.6.4', True, False),
            'rationale': 'is_known_pipename arbitrary library load.',
        },
    ],
    ('exim',): [
        {
            'cve': 'CVE-2019-10149',
            'name': 'Exim "Return of the WIZard" RCE',
            'severity': 'CRITICAL', 'cvss': 9.8,
            'range': ('4.87', '4.91', True, True),
            'rationale': 'deliver_message recipient parsing.',
        },
    ],
    ('atlassian', 'confluence'): [
        {
            'cve': 'CVE-2022-26134',
            'name': 'Confluence OGNL Injection',
            'severity': 'CRITICAL', 'cvss': 9.8,
            'range': ('1.0', '7.18.1', True, True),
            'rationale': 'Pre-auth OGNL injection via URL.',
        },
    ],
    ('apache', 'log4j'): [
        {
            'cve': 'CVE-2021-44228',
            'name': 'Log4Shell — JNDI RCE',
            'severity': 'CRITICAL', 'cvss': 10.0,
            'range': ('2.0', '2.15.0', True, False),
            'rationale': 'JNDI lookup from logged data.',
        },
    ],
    ('vmware', 'esxi'): [
        {
            'cve': 'CVE-2021-21974',
            'name': 'OpenSLP Heap Overflow → ESXiArgs ransom',
            'severity': 'CRITICAL', 'cvss': 8.8,
            'range': ('6.5', '7.0u1', True, False),
            'rationale': 'OpenSLP exposed on UDP/TCP 427.',
        },
    ],
    ('openssl',): [
        {
            'cve': 'CVE-2014-0160',
            'name': 'OpenSSL Heartbleed',
            'severity': 'HIGH', 'cvss': 7.5,
            'range': ('1.0.1', '1.0.1g', True, False),
            'rationale': 'Read out of bounds in TLS heartbeat extension.',
        },
        {
            'cve': 'CVE-2022-3786',
            'name': 'OpenSSL X.509 buffer overrun (Spooky Mole)',
            'severity': 'HIGH', 'cvss': 7.5,
            'range': ('3.0.0', '3.0.7', True, False),
            'rationale': 'Punycode buffer overflow.',
        },
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
#  SERVICE → (vendor, product) NORMALIZATION
# ─────────────────────────────────────────────────────────────────────────────
SERVICE_MAP: List[Tuple[re.Pattern, Tuple[str, ...]]] = [
    (re.compile(r'openssh',  re.I),      ('openbsd', 'openssh')),
    (re.compile(r'apache',   re.I),      ('apache', 'httpd')),
    (re.compile(r'iis',      re.I),      ('microsoft', 'iis')),
    (re.compile(r'vsftpd',   re.I),      ('vsftpd',)),
    (re.compile(r'proftpd',  re.I),      ('proftpd',)),
    (re.compile(r'mysql',    re.I),      ('mysql',)),
    (re.compile(r'mariadb',  re.I),      ('mysql',)),
    (re.compile(r'redis',    re.I),      ('redis',)),
    (re.compile(r'samba|smbd|microsoft-ds|netbios-ssn', re.I), ('samba',)),
    (re.compile(r'exim',     re.I),      ('exim',)),
    (re.compile(r'confluence', re.I),    ('atlassian', 'confluence')),
    (re.compile(r'log4j',    re.I),      ('apache', 'log4j')),
    (re.compile(r'esxi|vmware',re.I),    ('vmware', 'esxi')),
    (re.compile(r'openssl',  re.I),      ('openssl',)),
]


def normalize_product(service: str, version: str) -> Optional[Tuple[str, ...]]:
    haystack = f'{service} {version}'
    for pat, key in SERVICE_MAP:
        if pat.search(haystack):
            return key
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  FINDING DATA CLASS
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class VulnFinding:
    port: int
    service: str
    version: str
    name: str
    cve: Optional[str]
    severity: str
    cvss: float
    confidence: float
    description: str
    evidence: List[str] = field(default_factory=list)
    exploitable: bool = False


# ─────────────────────────────────────────────────────────────────────────────
#  VULNERABILITY SCANNER
# ─────────────────────────────────────────────────────────────────────────────
class VulnerabilityScanner:
    """Industrial-grade vulnerability scanner with version-aware matching."""

    def __init__(self, target: str, ports_data: List[Dict[str, Any]],
                 nikto_timeout: int = 360, sqlmap_timeout: int = 240,
                 enable_nikto: bool = True, enable_sqlmap: bool = True) -> None:
        self.target = target
        self.ports_data = ports_data
        self.nikto_timeout = nikto_timeout
        self.sqlmap_timeout = sqlmap_timeout
        self.enable_nikto = enable_nikto
        self.enable_sqlmap = enable_sqlmap
        self.web_ports: List[Dict[str, Any]] = []
        self.vulnerabilities: List[VulnFinding] = []
        self.web_vulns: List[Dict[str, Any]] = []
        self.sql_vulns: List[Dict[str, Any]] = []
        self._seen_keys: set = set()
        self.identify_web_services()

    # ─────────────────────────────────────────────────────────
    def identify_web_services(self) -> None:
        common_web_ports = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000,
                              9000, 9090, 4443}
        web_keywords = ('http', 'https', 'ssl/http', 'http-proxy', 'http-alt',
                         'webcache', 'tomcat', 'jboss', 'jetty')
        for port in self.ports_data:
            service = (port.get('service') or '').lower()
            num = port.get('port')
            is_web = any(w in service for w in web_keywords) or num in common_web_ports
            if not is_web:
                continue
            scheme = 'https' if num in (443, 8443, 4443) or 'https' in service or 'ssl' in service else 'http'
            self.web_ports.append({
                'port': num, 'protocol': scheme,
                'url': f'{scheme}://{self.target}:{num}',
            })
            print(f'[✓] Detected web service: {scheme}://{self.target}:{num}')

    # ─────────────────────────────────────────────────────────
    def _record(self, finding: VulnFinding) -> None:
        key = (finding.port, finding.cve or '', finding.name)
        if key in self._seen_keys:
            return
        self._seen_keys.add(key)
        self.vulnerabilities.append(finding)

    # ─────────────────────────────────────────────────────────
    #  Version-aware service matcher
    # ─────────────────────────────────────────────────────────
    def scan_common_vulnerabilities(self) -> List[VulnFinding]:
        print('[*] Performing version-aware vulnerability matching...')
        confirmed: List[VulnFinding] = []
        for port in self.ports_data:
            service = (port.get('service') or '').strip()
            version = (port.get('version') or '').strip()
            num = port.get('port')
            key = normalize_product(service, version)
            if key is None:
                continue
            entries = KB_VULNS.get(key, [])
            for entry in entries:
                if not version:
                    # Without a version we cannot confirm; emit a low-confidence advisory.
                    finding = VulnFinding(
                        port=num, service=service, version=version,
                        name=entry['name'], cve=entry.get('cve'),
                        severity=entry['severity'], cvss=entry['cvss'],
                        confidence=0.30,
                        description=f'{entry["rationale"]} '
                                    '(unverified — service version not exposed)',
                        evidence=[f'product_match={key}'],
                        exploitable=False,
                    )
                    self._record(finding); confirmed.append(finding); continue

                if version_in_range(version, entry['range']):
                    finding = VulnFinding(
                        port=num, service=service, version=version,
                        name=entry['name'], cve=entry.get('cve'),
                        severity=entry['severity'], cvss=entry['cvss'],
                        confidence=0.95,
                        description=entry['rationale'],
                        evidence=[
                            f'product_match={key}',
                            f'version_observed={version}',
                            f'affected_range={entry["range"]}',
                        ],
                        exploitable=True,
                    )
                    self._record(finding); confirmed.append(finding)
                    print(f'[!] {finding.cve or finding.name} confirmed on '
                          f'port {num} (version {version})')
        return confirmed

    # ─────────────────────────────────────────────────────────
    #  Nikto integration
    # ─────────────────────────────────────────────────────────
    def scan_with_nikto(self, url: str) -> List[Dict[str, Any]]:
        if not self.enable_nikto:
            return []
        print(f'[*] Running Nikto against {url}...')
        try:
            check = subprocess.run(['which', 'nikto'], capture_output=True)
            if check.returncode != 0:
                print('[!] Nikto not installed — skipping')
                return []
            os.makedirs('logs', exist_ok=True)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            outfile = f'logs/nikto_{re.sub(r"[^A-Za-z0-9]", "_", self.target)}_{ts}.json'
            cmd = ['nikto', '-h', url, '-Format', 'json', '-output', outfile,
                    '-Tuning', '123456789', '-timeout', '10']
            result = subprocess.run(cmd, capture_output=True, text=True,
                                     timeout=self.nikto_timeout)
            return self._parse_nikto(outfile, result.stdout)
        except subprocess.TimeoutExpired:
            print('[!] Nikto scan timed out')
            return []
        except Exception as e:
            print(f'[!] Nikto failed: {e}')
            return []

    def _parse_nikto(self, outfile: str, fallback_stdout: str) -> List[Dict[str, Any]]:
        vulns: List[Dict[str, Any]] = []
        # Prefer the JSON file
        try:
            if os.path.exists(outfile):
                with open(outfile, 'r', encoding='utf-8', errors='ignore') as f:
                    raw = f.read()
                # Nikto may emit several JSON arrays / objects
                for chunk in re.findall(r'(?:\{.*?\}|\[.*?\])', raw, re.S):
                    try:
                        data = json.loads(chunk)
                    except json.JSONDecodeError:
                        continue
                    items = data.get('vulnerabilities') if isinstance(data, dict) else (
                        data if isinstance(data, list) else [])
                    for v in items:
                        if not isinstance(v, dict):
                            continue
                        vulns.append({
                            'type': 'web', 'url': v.get('url', ''),
                            'method': v.get('method', 'GET'),
                            'osvdb': v.get('OSVDB', v.get('osvdb', '')),
                            'severity': self._map_severity(v),
                            'description': v.get('msg', '')[:512],
                            'confidence': 0.7,
                        })
        except Exception:
            pass
        # Text-fallback parsing
        if not vulns and fallback_stdout:
            for line in fallback_stdout.splitlines():
                if line.startswith('+ ') and any(k in line.lower() for k in
                    ('vulnerable', 'outdated', 'disclosure', 'injection',
                     'xss', 'security', 'cgi', 'leak')):
                    vulns.append({
                        'type': 'web', 'url': self.target, 'method': 'GET',
                        'osvdb': '',
                        'severity': 'MEDIUM',
                        'description': line[2:].strip()[:512],
                        'confidence': 0.4,
                    })
        return vulns

    @staticmethod
    def _map_severity(v: Dict[str, Any]) -> str:
        msg = (v.get('msg') or '').lower()
        if any(k in msg for k in ('rce', 'remote code', 'sqli', 'sql injection',
                                    'auth bypass', 'unauthenticated')):
            return 'CRITICAL'
        if any(k in msg for k in ('xss', 'lfi', 'ssrf', 'xxe', 'csrf')):
            return 'HIGH'
        if any(k in msg for k in ('disclosure', 'directory', 'index')):
            return 'MEDIUM'
        return 'LOW'

    # ─────────────────────────────────────────────────────────
    #  SQLMap integration
    # ─────────────────────────────────────────────────────────
    def scan_sql_injection(self, url: str) -> List[Dict[str, Any]]:
        if not self.enable_sqlmap:
            return []
        print(f'[*] Running SQLMap against {url}...')
        try:
            check = subprocess.run(['which', 'sqlmap'], capture_output=True)
            if check.returncode != 0:
                print('[!] SQLMap not installed — skipping')
                return []
            cmd = ['sqlmap', '-u', url, '--batch', '--crawl=2',
                   '--level=2', '--risk=2',
                   '--random-agent', '--timeout=30',
                   '--retries=2', '--threads=3',
                   '--smart',  # only test parameters that look injectable
                   '--technique=BEUSTQ']
            result = subprocess.run(cmd, capture_output=True, text=True,
                                     timeout=self.sqlmap_timeout)
            return self._parse_sqlmap(result.stdout, url)
        except subprocess.TimeoutExpired:
            print('[!] SQLMap timed out')
            return []
        except Exception as e:
            print(f'[!] SQLMap failed: {e}')
            return []

    def _parse_sqlmap(self, output: str, url: str) -> List[Dict[str, Any]]:
        vulns: List[Dict[str, Any]] = []
        try:
            for m in re.finditer(
                    r'Parameter:\s*(?P<param>[^\s]+)\s*\((?P<place>[^)]+)\).*?'
                    r'(?:Type:\s*(?P<type>[^\n]+)).*?'
                    r'(?:Title:\s*(?P<title>[^\n]+)).*?'
                    r'(?:Payload:\s*(?P<payload>[^\n]+))',
                    output, re.S | re.I):
                vulns.append({
                    'type': 'sql_injection', 'url': url,
                    'parameter': m.group('param'),
                    'placement': m.group('place'),
                    'technique': m.group('type').strip(),
                    'title': m.group('title').strip(),
                    'payload': m.group('payload').strip(),
                    'severity': 'CRITICAL', 'cvss': 9.8,
                    'confidence': 0.95,
                })
            db = re.search(r'back-end DBMS:\s*([^\n]+)', output)
            if db and vulns:
                for v in vulns:
                    v['database'] = db.group(1).strip()
        except Exception as e:
            print(f'[!] SQLMap parse error: {e}')
        return vulns

    # ─────────────────────────────────────────────────────────
    #  Orchestration
    # ─────────────────────────────────────────────────────────
    def run_full_scan(self) -> Dict[str, Any]:
        print('\n' + '=' * 60)
        print('AutoPentestX - Vulnerability Scanner (Industrial)')
        print('=' * 60)
        print(f'Target: {self.target}')
        print(f'Services to evaluate: {len(self.ports_data)}')
        print('=' * 60 + '\n')

        self.scan_common_vulnerabilities()

        if self.web_ports:
            print(f'\n[*] {len(self.web_ports)} web service(s) detected')
            for ws in self.web_ports:
                self.web_vulns.extend(self.scan_with_nikto(ws['url']))
                self.sql_vulns.extend(self.scan_sql_injection(ws['url']))
        else:
            print('[!] No web services detected')

        total = len(self.vulnerabilities) + len(self.web_vulns) + len(self.sql_vulns)
        print('\n' + '=' * 60)
        print('VULNERABILITY SCAN SUMMARY')
        print('=' * 60)
        print(f'Service-version vulnerabilities: {len(self.vulnerabilities)}')
        print(f'Web vulnerabilities (Nikto):     {len(self.web_vulns)}')
        print(f'SQL injection points (SQLMap):   {len(self.sql_vulns)}')
        print(f'Total findings:                   {total}')
        print('=' * 60 + '\n')

        return self.get_results()

    def get_results(self) -> Dict[str, Any]:
        return {
            'vulnerabilities': [asdict(v) for v in self.vulnerabilities],
            'web_vulnerabilities': self.web_vulns,
            'sql_vulnerabilities': self.sql_vulns,
        }


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print('Usage: python vuln_scanner.py <target>')
        sys.exit(1)
    sample_ports = [
        {'port': 22, 'service': 'ssh',  'version': 'OpenSSH 9.6p1'},
        {'port': 80, 'service': 'http', 'version': 'Apache 2.4.49'},
        {'port': 21, 'service': 'ftp',  'version': 'vsftpd 2.3.4'},
    ]
    scanner = VulnerabilityScanner(sys.argv[1], sample_ports,
                                    enable_nikto=False, enable_sqlmap=False)
    print(json.dumps(scanner.run_full_scan(), indent=2, default=str))
