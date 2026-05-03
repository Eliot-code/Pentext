#!/usr/bin/env python3
"""
AutoPentestX - Threat Intelligence Module
==========================================
Real-time enrichment of vulnerabilities with multiple authoritative sources:

  • NVD (National Vulnerability Database)        — official CVE record + CVSS v3
  • CISA KEV (Known Exploited Vulnerabilities)   — actively-exploited list
  • EPSS (Exploit Prediction Scoring System)     — probability of exploitation
  • MITRE ATT&CK (technique mapping)             — TTPs per CVE / CWE
  • ExploitDB                                     — public PoC availability
  • GitHub PoC search (web scrape, optional)     — research/PoC repos

Design goals:
  • All sources are OPTIONAL.  If a feed is unreachable, the engine degrades
    gracefully instead of crashing or producing garbage.
  • Aggressive on-disk caching with TTLs to avoid hammering APIs.
  • Per-source rate limiting.
  • Resilient retry logic with exponential back-off.
  • All findings carry provenance (which source produced what).
  • CISA KEV catalog is fully cached locally on first use (~1MB).
  • EPSS score is consulted in batch where possible.

Usage:
    ti = ThreatIntelligence(cache_dir='cache/ti')
    enriched = ti.enrich_cve('CVE-2024-6387')
    enriched = ti.enrich_finding(finding_dict)
    catalog  = ti.refresh_cisa_kev()
    epss     = ti.epss_for(['CVE-2024-6387', 'CVE-2021-44228'])
"""

from __future__ import annotations

import gzip
import io
import json
import os
import re
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple


# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS — live API endpoints
# ─────────────────────────────────────────────────────────────────────────────
NVD_API_BASE       = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
CISA_KEV_URL       = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
EPSS_API           = 'https://api.first.org/data/v1/epss'
EXPLOITDB_API      = 'https://www.exploit-db.com/search'
GITHUB_SEARCH_API  = 'https://api.github.com/search/repositories'

# Rate limits (per source, in requests-per-second).  Conservative defaults.
DEFAULT_RATE_LIMITS: Dict[str, float] = {
    'nvd':       0.5,    # NVD allows 5 req/30s without API key — be polite
    'cisa':      0.5,
    'epss':      2.0,
    'github':    1.0,
    'exploitdb': 0.5,
}

# Cache TTLs (seconds)
CACHE_TTL: Dict[str, int] = {
    'nvd_cve':       7  * 86400,    # CVE records change rarely
    'cisa_kev':      24 * 3600,     # KEV updated daily-ish
    'epss':          12 * 3600,     # EPSS scored daily
    'github':        24 * 3600,
    'exploitdb':     24 * 3600,
    'attack_map':    30 * 86400,    # MITRE map static
}


# ─────────────────────────────────────────────────────────────────────────────
#  CWE → MITRE ATT&CK technique mapping (curated subset; expand as needed)
# ─────────────────────────────────────────────────────────────────────────────
CWE_TO_ATTACK: Dict[str, List[Dict[str, str]]] = {
    'CWE-79':   [{'id': 'T1059.007', 'name': 'JavaScript',                 'tactic': 'Execution'},
                 {'id': 'T1185',     'name': 'Browser Session Hijacking',  'tactic': 'Collection'}],
    'CWE-89':   [{'id': 'T1190',     'name': 'Exploit Public-Facing App',  'tactic': 'Initial Access'},
                 {'id': 'T1213.003', 'name': 'Code Repositories',          'tactic': 'Collection'}],
    'CWE-22':   [{'id': 'T1083',     'name': 'File and Directory Discovery','tactic': 'Discovery'},
                 {'id': 'T1005',     'name': 'Data from Local System',     'tactic': 'Collection'}],
    'CWE-78':   [{'id': 'T1059',     'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'},
                 {'id': 'T1190',     'name': 'Exploit Public-Facing App',  'tactic': 'Initial Access'}],
    'CWE-918':  [{'id': 'T1090',     'name': 'Proxy',                      'tactic': 'C2'},
                 {'id': 'T1005',     'name': 'Data from Local System',     'tactic': 'Collection'}],
    'CWE-94':   [{'id': 'T1059',     'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'}],
    'CWE-1336': [{'id': 'T1190',     'name': 'Exploit Public-Facing App',  'tactic': 'Initial Access'}],
    'CWE-287':  [{'id': 'T1078',     'name': 'Valid Accounts',             'tactic': 'Defense Evasion'},
                 {'id': 'T1110',     'name': 'Brute Force',                'tactic': 'Credential Access'}],
    'CWE-352':  [{'id': 'T1539',     'name': 'Steal Web Session Cookie',   'tactic': 'Credential Access'}],
    'CWE-601':  [{'id': 'T1566.002', 'name': 'Phishing: Spearphishing Link','tactic': 'Initial Access'}],
    'CWE-200':  [{'id': 'T1213',     'name': 'Data from Information Repos','tactic': 'Collection'}],
    'CWE-269':  [{'id': 'T1068',     'name': 'Exploitation for Privilege Escalation','tactic': 'Privilege Escalation'}],
    'CWE-502':  [{'id': 'T1059',     'name': 'Command and Scripting Interpreter','tactic': 'Execution'}],
    'CWE-611':  [{'id': 'T1005',     'name': 'Data from Local System',     'tactic': 'Collection'}],
    'CWE-693':  [{'id': 'T1190',     'name': 'Exploit Public-Facing App',  'tactic': 'Initial Access'}],
    'CWE-798':  [{'id': 'T1552.001', 'name': 'Credentials in Files',       'tactic': 'Credential Access'}],
    'CWE-862':  [{'id': 'T1078',     'name': 'Valid Accounts',             'tactic': 'Defense Evasion'}],
    'CWE-863':  [{'id': 'T1078',     'name': 'Valid Accounts',             'tactic': 'Defense Evasion'}],
    'CWE-444':  [{'id': 'T1090',     'name': 'Proxy',                      'tactic': 'C2'}],
    'CWE-942':  [{'id': 'T1190',     'name': 'Exploit Public-Facing App',  'tactic': 'Initial Access'}],
    'CWE-347':  [{'id': 'T1078',     'name': 'Valid Accounts',             'tactic': 'Defense Evasion'}],
    'CWE-290':  [{'id': 'T1078',     'name': 'Valid Accounts',             'tactic': 'Defense Evasion'},
                 {'id': 'T1556',     'name': 'Modify Authentication Process','tactic': 'Credential Access'}],
}

# Vulnerability TYPE → MITRE ATT&CK (for findings produced by detection_engine
# that already carry the kind, but no CWE).
VULN_TYPE_TO_ATTACK: Dict[str, List[str]] = {
    'Reflected XSS':              ['CWE-79'],
    'Stored XSS':                  ['CWE-79'],
    'SQL Injection':              ['CWE-89'],
    'Time-Blind SQL Injection':   ['CWE-89'],
    'Boolean-Blind SQL Injection':['CWE-89'],
    'Error-based SQL Injection':  ['CWE-89'],
    'OS Command Injection':       ['CWE-78'],
    'Local File Inclusion':       ['CWE-22'],
    'Path Traversal':             ['CWE-22'],
    'SSRF':                        ['CWE-918'],
    'SSTI':                        ['CWE-1336', 'CWE-94'],
    'JWT None-Algorithm Bypass':  ['CWE-347'],
    'CORS Misconfiguration':       ['CWE-942'],
    'Open Redirect':               ['CWE-601'],
    'Header Reflection':           ['CWE-444'],
    'IP Spoofing':                 ['CWE-290'],
    'Sensitive Data Exposure':    ['CWE-200'],
    'GraphQL Introspection Enabled':['CWE-200'],
    'Information Disclosure':     ['CWE-200'],
}


# ─────────────────────────────────────────────────────────────────────────────
#  RATE LIMITER
# ─────────────────────────────────────────────────────────────────────────────
class RateLimiter:
    def __init__(self, rps: float) -> None:
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.time()
            wait = self.min_interval - (now - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.time()


# ─────────────────────────────────────────────────────────────────────────────
#  CACHE
# ─────────────────────────────────────────────────────────────────────────────
class TICache:
    """SQLite-backed cache with per-key TTL.  Thread-safe."""

    SCHEMA = '''
        CREATE TABLE IF NOT EXISTS ti_cache (
            scope TEXT NOT NULL,
            key   TEXT NOT NULL,
            value BLOB NOT NULL,
            stored_at INTEGER NOT NULL,
            ttl   INTEGER NOT NULL,
            PRIMARY KEY (scope, key)
        )
    '''

    def __init__(self, path: str) -> None:
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        self._init()

    def _init(self) -> None:
        with self._lock, sqlite3.connect(self.path) as conn:
            conn.execute(self.SCHEMA)
            conn.commit()

    def get(self, scope: str, key: str) -> Optional[Any]:
        with self._lock, sqlite3.connect(self.path) as conn:
            row = conn.execute(
                'SELECT value, stored_at, ttl FROM ti_cache WHERE scope=? AND key=?',
                (scope, key)).fetchone()
        if not row:
            return None
        value, stored_at, ttl = row
        if ttl > 0 and (time.time() - stored_at) > ttl:
            return None
        try:
            return json.loads(gzip.decompress(value).decode('utf-8'))
        except Exception:
            return None

    def put(self, scope: str, key: str, value: Any, ttl: int) -> None:
        blob = gzip.compress(json.dumps(value).encode('utf-8'))
        with self._lock, sqlite3.connect(self.path) as conn:
            conn.execute(
                'INSERT OR REPLACE INTO ti_cache (scope, key, value, stored_at, ttl) '
                'VALUES (?,?,?,?,?)',
                (scope, key, blob, int(time.time()), ttl))
            conn.commit()

    def evict_scope(self, scope: str) -> int:
        with self._lock, sqlite3.connect(self.path) as conn:
            cur = conn.execute('DELETE FROM ti_cache WHERE scope=?', (scope,))
            conn.commit()
            return cur.rowcount


# ─────────────────────────────────────────────────────────────────────────────
#  HTTP CLIENT (resilient with retries + back-off)
# ─────────────────────────────────────────────────────────────────────────────
class _HttpClient:
    def __init__(self, timeout: int = 15, max_retries: int = 4,
                 user_agent: str = 'AutoPentestX-TI/1.0') -> None:
        self.timeout = timeout
        self.max_retries = max_retries
        self.user_agent = user_agent
        self._ctx = ssl.create_default_context()

    def get(self, url: str, headers: Optional[Dict[str, str]] = None,
            accept_status: Iterable[int] = (200,)) -> Tuple[int, Dict[str, str], bytes]:
        h = {'User-Agent': self.user_agent,
             'Accept': 'application/json,*/*',
             'Accept-Encoding': 'gzip, deflate'}
        if headers:
            h.update(headers)
        for attempt in range(1, self.max_retries + 1):
            try:
                req = urllib.request.Request(url, headers=h)
                with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                    raw = resp.read()
                    enc = resp.headers.get('Content-Encoding', '').lower()
                    if 'gzip' in enc:
                        try:    raw = gzip.decompress(raw)
                        except: pass
                    elif 'deflate' in enc:
                        try:    raw = zlib.decompress(raw)
                        except: pass
                    if resp.status in accept_status:
                        return resp.status, dict(resp.headers), raw
                    return resp.status, dict(resp.headers), raw
            except urllib.error.HTTPError as e:
                if e.code in (429, 503) and attempt < self.max_retries:
                    time.sleep(min(2 ** attempt, 30))
                    continue
                if e.code in accept_status:
                    return e.code, dict(e.headers) if e.headers else {}, b''
                return e.code, {}, b''
            except (urllib.error.URLError, ssl.SSLError, ConnectionError, TimeoutError):
                if attempt < self.max_retries:
                    time.sleep(min(2 ** attempt, 20))
                    continue
        return 0, {}, b''


# ─────────────────────────────────────────────────────────────────────────────
#  ENRICHED RECORD
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class CVERecord:
    cve_id: str
    description: Optional[str] = None
    published: Optional[str] = None
    last_modified: Optional[str] = None
    cvss_v3_score: Optional[float] = None
    cvss_v3_vector: Optional[str] = None
    cvss_v3_severity: Optional[str] = None
    cwes: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    cpes: List[str] = field(default_factory=list)
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    in_cisa_kev: bool = False
    cisa_due_date: Optional[str] = None
    cisa_required_action: Optional[str] = None
    exploitdb_ids: List[str] = field(default_factory=list)
    metasploit_modules: List[str] = field(default_factory=list)
    github_pocs: List[Dict[str, str]] = field(default_factory=list)
    attack_techniques: List[Dict[str, str]] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
#  THREAT INTELLIGENCE
# ─────────────────────────────────────────────────────────────────────────────
class ThreatIntelligence:
    def __init__(self, cache_dir: str = 'cache/ti',
                 nvd_api_key: Optional[str] = None,
                 enable_github: bool = False,
                 github_token: Optional[str] = None,
                 timeout: int = 15) -> None:
        os.makedirs(cache_dir, exist_ok=True)
        self.cache = TICache(os.path.join(cache_dir, 'ti.sqlite'))
        self.nvd_api_key = nvd_api_key
        self.enable_github = enable_github
        self.github_token = github_token
        self.http = _HttpClient(timeout=timeout)
        self.limiters = {k: RateLimiter(v) for k, v in DEFAULT_RATE_LIMITS.items()}
        self._kev_cache: Optional[Dict[str, Dict[str, Any]]] = None
        self._kev_lock = threading.Lock()

    # ─────────────────────────────────────────────────────────
    #  NVD
    # ─────────────────────────────────────────────────────────
    def nvd_lookup(self, cve_id: str) -> Optional[Dict[str, Any]]:
        cve_id = cve_id.upper().strip()
        if not re.match(r'^CVE-\d{4}-\d{4,7}$', cve_id):
            return None
        cached = self.cache.get('nvd_cve', cve_id)
        if cached:
            return cached
        self.limiters['nvd'].wait()
        url = f'{NVD_API_BASE}?cveId={urllib.parse.quote(cve_id)}'
        headers = {'apiKey': self.nvd_api_key} if self.nvd_api_key else {}
        status, _, body = self.http.get(url, headers=headers)
        if status != 200 or not body:
            return None
        try:
            data = json.loads(body)
            self.cache.put('nvd_cve', cve_id, data, CACHE_TTL['nvd_cve'])
            return data
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _parse_nvd_record(data: Dict[str, Any]) -> Dict[str, Any]:
        result: Dict[str, Any] = {'cwes': [], 'references': [], 'cpes': []}
        vulns = data.get('vulnerabilities', [])
        if not vulns:
            return result
        cve = vulns[0].get('cve', {})
        result['cve_id']        = cve.get('id')
        result['published']     = cve.get('published')
        result['last_modified'] = cve.get('lastModified')

        # Description (English first)
        for d in cve.get('descriptions', []):
            if d.get('lang') == 'en':
                result['description'] = d.get('value')
                break

        # CVSS v3
        metrics = cve.get('metrics', {})
        for key in ('cvssMetricV31', 'cvssMetricV30'):
            for m in metrics.get(key, []) or []:
                cvss = m.get('cvssData', {})
                result['cvss_v3_score']    = cvss.get('baseScore')
                result['cvss_v3_severity'] = cvss.get('baseSeverity')
                result['cvss_v3_vector']   = cvss.get('vectorString')
                break
            if result.get('cvss_v3_score'):
                break

        # CWE
        for w in cve.get('weaknesses', []):
            for desc in w.get('description', []):
                if desc.get('lang') == 'en' and desc.get('value', '').startswith('CWE-'):
                    result['cwes'].append(desc['value'])
        result['cwes'] = sorted(set(result['cwes']))

        # References
        for ref in cve.get('references', []):
            if ref.get('url'):
                result['references'].append(ref['url'])

        # CPE configurations
        for cfg in cve.get('configurations', []) or []:
            for node in cfg.get('nodes', []):
                for cpe in node.get('cpeMatch', []):
                    if cpe.get('vulnerable') and cpe.get('criteria'):
                        result['cpes'].append(cpe['criteria'])
        result['cpes'] = sorted(set(result['cpes']))[:30]
        return result

    # ─────────────────────────────────────────────────────────
    #  CISA KEV
    # ─────────────────────────────────────────────────────────
    def refresh_cisa_kev(self, force: bool = False) -> Dict[str, Dict[str, Any]]:
        with self._kev_lock:
            if self._kev_cache is not None and not force:
                return self._kev_cache
            cached = None if force else self.cache.get('cisa_kev', 'catalog')
            if cached is None:
                self.limiters['cisa'].wait()
                status, _, body = self.http.get(CISA_KEV_URL)
                if status != 200 or not body:
                    self._kev_cache = cached or {}
                    return self._kev_cache
                try:
                    cached = json.loads(body)
                    self.cache.put('cisa_kev', 'catalog', cached, CACHE_TTL['cisa_kev'])
                except json.JSONDecodeError:
                    self._kev_cache = {}
                    return self._kev_cache
            entries = {}
            for v in cached.get('vulnerabilities', []):
                cve_id = v.get('cveID')
                if cve_id:
                    entries[cve_id.upper()] = v
            self._kev_cache = entries
            return entries

    def is_in_cisa_kev(self, cve_id: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        kev = self.refresh_cisa_kev()
        entry = kev.get(cve_id.upper())
        return (entry is not None), entry

    # ─────────────────────────────────────────────────────────
    #  EPSS
    # ─────────────────────────────────────────────────────────
    def epss_for(self, cve_ids: Iterable[str]) -> Dict[str, Dict[str, float]]:
        ids = sorted({c.upper().strip() for c in cve_ids
                      if re.match(r'^CVE-\d{4}-\d{4,7}$', c.upper().strip())})
        if not ids:
            return {}
        result: Dict[str, Dict[str, float]] = {}
        # First check cache
        misses: List[str] = []
        for cid in ids:
            cached = self.cache.get('epss', cid)
            if cached:
                result[cid] = cached
            else:
                misses.append(cid)
        if not misses:
            return result
        # EPSS allows 100 IDs per call; chunk if needed
        for chunk_start in range(0, len(misses), 100):
            chunk = misses[chunk_start:chunk_start + 100]
            self.limiters['epss'].wait()
            url = f'{EPSS_API}?cve={",".join(chunk)}'
            status, _, body = self.http.get(url)
            if status != 200 or not body:
                continue
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                continue
            for d in data.get('data', []):
                cid = d.get('cve', '').upper()
                if not cid:
                    continue
                rec = {
                    'epss': float(d.get('epss', 0.0) or 0.0),
                    'percentile': float(d.get('percentile', 0.0) or 0.0),
                    'date': d.get('date'),
                }
                self.cache.put('epss', cid, rec, CACHE_TTL['epss'])
                result[cid] = rec
        return result

    # ─────────────────────────────────────────────────────────
    #  ExploitDB scrape (search by CVE id)
    # ─────────────────────────────────────────────────────────
    def exploitdb_for(self, cve_id: str) -> List[str]:
        cve_id = cve_id.upper().strip()
        cached = self.cache.get('exploitdb', cve_id)
        if cached is not None:
            return cached
        self.limiters['exploitdb'].wait()
        url = (f'{EXPLOITDB_API}?cve={urllib.parse.quote(cve_id.replace("CVE-", ""))}'
               f'&type=&platform=&port=')
        status, _, body = self.http.get(url, headers={'Accept': 'application/json'})
        ids: List[str] = []
        if status == 200 and body:
            try:
                data = json.loads(body)
                for entry in data.get('data', []):
                    if 'id' in entry:
                        ids.append(str(entry['id']))
            except json.JSONDecodeError:
                # fall back to HTML scrape
                ids = re.findall(r'/exploits/(\d+)', body.decode('utf-8', 'ignore'))
        ids = sorted(set(ids))[:20]
        self.cache.put('exploitdb', cve_id, ids, CACHE_TTL['exploitdb'])
        return ids

    # ─────────────────────────────────────────────────────────
    #  GitHub PoC search (optional, requires opt-in)
    # ─────────────────────────────────────────────────────────
    def github_pocs_for(self, cve_id: str) -> List[Dict[str, str]]:
        if not self.enable_github:
            return []
        cve_id = cve_id.upper().strip()
        cached = self.cache.get('github', cve_id)
        if cached is not None:
            return cached
        self.limiters['github'].wait()
        q = f'{cve_id} poc OR exploit'
        url = f'{GITHUB_SEARCH_API}?q={urllib.parse.quote(q)}&per_page=10'
        headers = {'Accept': 'application/vnd.github+json'}
        if self.github_token:
            headers['Authorization'] = f'Bearer {self.github_token}'
        status, _, body = self.http.get(url, headers=headers)
        repos: List[Dict[str, str]] = []
        if status == 200 and body:
            try:
                data = json.loads(body)
                for r in data.get('items', [])[:10]:
                    repos.append({
                        'name': r.get('full_name', ''),
                        'url':  r.get('html_url', ''),
                        'stars': str(r.get('stargazers_count', 0)),
                        'description': (r.get('description') or '')[:200],
                    })
            except json.JSONDecodeError:
                pass
        self.cache.put('github', cve_id, repos, CACHE_TTL['github'])
        return repos

    # ─────────────────────────────────────────────────────────
    #  MITRE ATT&CK mapping
    # ─────────────────────────────────────────────────────────
    @staticmethod
    def attack_for_cwes(cwes: Iterable[str]) -> List[Dict[str, str]]:
        out: List[Dict[str, str]] = []
        seen: Set[str] = set()
        for cwe in cwes:
            for entry in CWE_TO_ATTACK.get(cwe.upper(), []):
                tid = entry['id']
                if tid in seen:
                    continue
                seen.add(tid)
                out.append({**entry, 'source_cwe': cwe})
        return out

    @staticmethod
    def attack_for_vuln_type(vuln_type: str) -> List[Dict[str, str]]:
        cwes: List[str] = []
        for key, mapped in VULN_TYPE_TO_ATTACK.items():
            if key.lower() in vuln_type.lower():
                cwes.extend(mapped)
        cwes = sorted(set(cwes))
        return ThreatIntelligence.attack_for_cwes(cwes)

    # ─────────────────────────────────────────────────────────
    #  ENRICHMENT (single CVE)
    # ─────────────────────────────────────────────────────────
    def enrich_cve(self, cve_id: str) -> CVERecord:
        rec = CVERecord(cve_id=cve_id.upper())
        nvd = self.nvd_lookup(cve_id)
        if nvd:
            parsed = self._parse_nvd_record(nvd)
            for key in ('description', 'published', 'last_modified',
                         'cvss_v3_score', 'cvss_v3_severity',
                         'cvss_v3_vector'):
                if parsed.get(key) is not None:
                    setattr(rec, key, parsed[key])
            rec.cwes = parsed.get('cwes', [])
            rec.references = parsed.get('references', [])
            rec.cpes = parsed.get('cpes', [])
            rec.sources.append('NVD')

        in_kev, kev_entry = self.is_in_cisa_kev(cve_id)
        if in_kev and kev_entry:
            rec.in_cisa_kev = True
            rec.cisa_due_date = kev_entry.get('dueDate')
            rec.cisa_required_action = kev_entry.get('requiredAction')
            rec.sources.append('CISA-KEV')

        epss = self.epss_for([cve_id])
        epss_record = epss.get(cve_id.upper())
        if epss_record:
            rec.epss_score = epss_record['epss']
            rec.epss_percentile = epss_record['percentile']
            rec.sources.append('EPSS')

        exploits = self.exploitdb_for(cve_id)
        if exploits:
            rec.exploitdb_ids = exploits
            rec.sources.append('ExploitDB')

        if self.enable_github:
            pocs = self.github_pocs_for(cve_id)
            if pocs:
                rec.github_pocs = pocs
                rec.sources.append('GitHub')

        rec.attack_techniques = self.attack_for_cwes(rec.cwes)
        if rec.attack_techniques:
            rec.sources.append('MITRE-ATT&CK')

        return rec

    # ─────────────────────────────────────────────────────────
    #  ENRICHMENT (finding from detection_engine)
    # ─────────────────────────────────────────────────────────
    def enrich_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Augment a finding dict with TI data.  Mutates `finding` in place
        (and returns it for chaining)."""
        ti: Dict[str, Any] = {'sources': [], 'attack_techniques': []}

        # CWE-based mapping (preferred — most precise)
        cwe = finding.get('cwe')
        cwes = [cwe] if isinstance(cwe, str) else (cwe or [])
        if cwes:
            techs = self.attack_for_cwes(cwes)
            ti['attack_techniques'] = techs
            if techs:
                ti['sources'].append('MITRE-ATT&CK')

        # Type-based fallback
        if not ti['attack_techniques'] and finding.get('vuln_type'):
            techs = self.attack_for_vuln_type(finding['vuln_type'])
            ti['attack_techniques'] = techs
            if techs:
                ti['sources'].append('MITRE-ATT&CK')

        # If finding includes an explicit CVE, enrich fully
        cve_field = finding.get('cve') or finding.get('cve_id')
        if cve_field and re.match(r'^CVE-\d{4}-\d{4,7}$', cve_field, re.I):
            cve_rec = self.enrich_cve(cve_field)
            ti['cve_record'] = asdict(cve_rec)
            ti['sources'].extend([s for s in cve_rec.sources if s not in ti['sources']])

        finding.setdefault('threat_intel', {})
        finding['threat_intel'].update(ti)
        return finding

    # ─────────────────────────────────────────────────────────
    #  BULK ENRICHMENT for vulnerability scanner output
    # ─────────────────────────────────────────────────────────
    def enrich_vulnerability_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        cves_to_lookup = sorted({f.get('cve') for f in findings
                                  if f.get('cve') and re.match(r'^CVE-\d{4}-\d{4,7}$',
                                                                  f.get('cve', ''), re.I)})
        if not cves_to_lookup:
            for f in findings:
                self.enrich_finding(f)
            return findings

        # Batch EPSS lookup first
        epss_batch = self.epss_for(cves_to_lookup)
        kev = self.refresh_cisa_kev()
        for f in findings:
            cve = f.get('cve')
            if cve and re.match(r'^CVE-\d{4}-\d{4,7}$', cve, re.I):
                cid = cve.upper()
                ti = f.setdefault('threat_intel', {})
                if cid in epss_batch:
                    ti['epss_score'] = epss_batch[cid]['epss']
                    ti['epss_percentile'] = epss_batch[cid]['percentile']
                if cid in kev:
                    ti['in_cisa_kev'] = True
                    ti['cisa_due_date'] = kev[cid].get('dueDate')
                    ti['cisa_required_action'] = kev[cid].get('requiredAction')
                exp = self.exploitdb_for(cid)
                if exp:
                    ti['exploitdb_ids'] = exp
            self.enrich_finding(f)
        return findings

    # ─────────────────────────────────────────────────────────
    #  PRIORITY SCORING (exploit-aware)
    # ─────────────────────────────────────────────────────────
    @staticmethod
    def priority_score(finding: Dict[str, Any]) -> float:
        """Compute a single 0..10 priority score combining CVSS, EPSS and KEV.
        Designed to bubble up *actually-exploited* issues first."""
        ti = finding.get('threat_intel', {})
        cvss = float(finding.get('cvss', 0.0) or 0.0)
        epss = float(ti.get('epss_score', 0.0) or 0.0)
        kev_bonus = 2.0 if ti.get('in_cisa_kev') else 0.0
        exp_bonus = 1.0 if ti.get('exploitdb_ids') else 0.0
        # Weighting: CVSS dominates, EPSS amplifies, KEV is an authoritative bump.
        score = (cvss * 0.7) + (epss * 10 * 0.3) + kev_bonus + exp_bonus
        return round(min(score, 10.0), 2)


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description='AutoPentestX Threat Intelligence')
    p.add_argument('--cve', help='Look up a single CVE')
    p.add_argument('--refresh-kev', action='store_true', help='Refresh CISA KEV catalog')
    p.add_argument('--cache-dir', default='cache/ti')
    args = p.parse_args()

    ti = ThreatIntelligence(cache_dir=args.cache_dir)
    if args.refresh_kev:
        kev = ti.refresh_cisa_kev(force=True)
        print(f'CISA KEV catalog: {len(kev)} entries')
    if args.cve:
        rec = ti.enrich_cve(args.cve)
        print(json.dumps(asdict(rec), indent=2, default=str))
