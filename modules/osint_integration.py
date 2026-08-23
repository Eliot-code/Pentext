#!/usr/bin/env python3
"""
AutoPentestX - OSINT Integration Module
Passive enrichment of IPs/domains via Shodan, Censys, URLScan, and GreyNoise.

Environment variables:
    SHODAN_API_KEY          Shodan developer key
    CENSYS_API_ID           Censys Search API v2 App ID
    CENSYS_API_SECRET       Censys Search API v2 App Secret
    URLSCAN_API_KEY         URLScan.io API key
    GREYNOISE_API_KEY       GreyNoise key (optional — community endpoint works
                            without one, though rate-limits are tighter)
"""

from __future__ import annotations

import base64
import ipaddress
import json
import logging
import os
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

SHODAN_BASE    = 'https://api.shodan.io'
CENSYS_BASE    = 'https://search.censys.io/api/v2'
URLSCAN_BASE   = 'https://urlscan.io/api/v1'
GREYNOISE_BASE = 'https://api.greynoise.io/v3/community'

_TIMEOUT     = 15
TTL_DEFAULT  = 3600   # 1 h
TTL_URLSCAN  = 86400  # 24 h — scan results are immutable once stored


# ─────────────────────────────────────────────────────────────────────────────
#  RATE LIMITER  (matches threat_intel.py pattern)
# ─────────────────────────────────────────────────────────────────────────────
class _RateLimiter:
    def __init__(self, rps: float = 1.0) -> None:
        self._interval = 1.0 / max(rps, 1e-9)
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            gap = self._interval - (time.time() - self._last)
            if gap > 0:
                time.sleep(gap)
            self._last = time.time()


# ─────────────────────────────────────────────────────────────────────────────
#  CACHE
# ─────────────────────────────────────────────────────────────────────────────
class OSINTCache:
    """TTL-aware in-memory store keyed by (service, key).  Thread-safe."""

    def __init__(self) -> None:
        # _store[(service, key)] = (value, stored_at, ttl_s)
        self._store: Dict[Tuple[str, str], Tuple[Any, float, float]] = {}
        self._lock = threading.Lock()

    def get(self, service: str, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._store.get((service, key))
        if not entry:
            return None
        value, stored_at, ttl = entry
        if time.time() - stored_at > ttl:
            with self._lock:
                self._store.pop((service, key), None)
            return None
        return value

    def put(self, service: str, key: str, value: Any, ttl_s: float = TTL_DEFAULT) -> None:
        with self._lock:
            self._store[(service, key)] = (value, time.time(), ttl_s)


# ─────────────────────────────────────────────────────────────────────────────
#  SHODAN
# ─────────────────────────────────────────────────────────────────────────────
class ShodanClient:
    """GET https://api.shodan.io/shodan/host/{ip}?key=..."""

    def __init__(self, api_key: str, cache: OSINTCache) -> None:
        self._key, self._cache, self._rl = api_key, cache, _RateLimiter()
        self._ssl = ssl.create_default_context()

    def _get(self, path: str, params: Optional[Dict[str, str]] = None) -> Optional[Dict]:
        qs = urllib.parse.urlencode({**(params or {}), 'key': self._key})
        self._rl.wait()
        try:
            req = urllib.request.Request(f'{SHODAN_BASE}{path}?{qs}',
                                         headers={'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=_TIMEOUT, context=self._ssl) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            logger.warning('Shodan %s %s: %s', e.code, path, e.reason)
        except Exception as e:
            logger.warning('Shodan error %s: %s', path, e)
        return None

    def host_lookup(self, ip: str) -> Dict[str, Any]:
        cached = self._cache.get('shodan_host', ip)
        if cached is not None:
            return cached
        data = self._get(f'/shodan/host/{urllib.parse.quote(ip)}')
        if not data:
            return {}
        result: Dict[str, Any] = {
            'ports':        data.get('ports', []),
            'vulns':        list(data.get('vulns', {}).keys()),
            'hostnames':    data.get('hostnames', []),
            'org':          data.get('org', ''),
            'isp':          data.get('isp', ''),
            'country_name': data.get('country_name', ''),
            'tags':         data.get('tags', []),
            'services': [
                {'port': s.get('port'), 'transport': s.get('transport', 'tcp'),
                 'product': s.get('product', ''), 'version': s.get('version', ''),
                 'banner': (s.get('data') or '')[:500]}
                for s in data.get('data', [])
            ],
        }
        self._cache.put('shodan_host', ip, result)
        return result

    def search(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """GET /shodan/host/search?key=&query=&limit="""
        ck = f'{query}:{limit}'
        cached = self._cache.get('shodan_search', ck)
        if cached is not None:
            return cached
        data = self._get('/shodan/host/search', {'query': query, 'limit': str(limit)})
        if not data:
            return []
        results = [
            {'ip_str': m.get('ip_str', ''), 'port': m.get('port'),
             'transport': m.get('transport', 'tcp'), 'org': m.get('org', ''),
             'country_name': m.get('location', {}).get('country_name', ''),
             'hostnames': m.get('hostnames', []),
             'product': m.get('product', ''), 'version': m.get('version', '')}
            for m in data.get('matches', [])
        ]
        self._cache.put('shodan_search', ck, results)
        return results


# ─────────────────────────────────────────────────────────────────────────────
#  CENSYS
# ─────────────────────────────────────────────────────────────────────────────
class CensysClient:
    """https://search.censys.io/api/v2/hosts/{ip}  Basic Auth: API_ID:API_SECRET"""

    def __init__(self, api_id: str, api_secret: str, cache: OSINTCache) -> None:
        token = base64.b64encode(f'{api_id}:{api_secret}'.encode()).decode()
        self._auth = f'Basic {token}'
        self._cache, self._rl = cache, _RateLimiter()
        self._ssl = ssl.create_default_context()

    def _get(self, path: str, params: Optional[Dict[str, str]] = None) -> Optional[Dict]:
        qs = ('?' + urllib.parse.urlencode(params)) if params else ''
        self._rl.wait()
        try:
            req = urllib.request.Request(
                f'{CENSYS_BASE}{path}{qs}',
                headers={'Authorization': self._auth, 'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=_TIMEOUT, context=self._ssl) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            logger.warning('Censys %s %s: %s', e.code, path, e.reason)
        except Exception as e:
            logger.warning('Censys error %s: %s', path, e)
        return None

    def host_lookup(self, ip: str) -> Dict[str, Any]:
        cached = self._cache.get('censys_host', ip)
        if cached is not None:
            return cached
        data = self._get(f'/hosts/{urllib.parse.quote(ip)}')
        if not data:
            return {}
        raw = data.get('result', {})
        services = [
            {'port': s.get('port'), 'service_name': s.get('service_name', ''),
             'transport_protocol': s.get('transport_protocol', ''),
             'banner': (s.get('banner') or '')[:500],
             'certificate': (s.get('tls', {}).get('certificates', {})
                               .get('leaf_data', {}).get('subject_dn', ''))}
            for s in raw.get('services', [])
        ]
        loc, asn = raw.get('location', {}), raw.get('autonomous_system', {})
        result: Dict[str, Any] = {
            'ip': raw.get('ip', ip),
            'services': services,
            'location': {'country': loc.get('country', ''), 'city': loc.get('city', '')},
            'autonomous_system': {'asn': asn.get('asn'), 'name': asn.get('name', '')},
        }
        self._cache.put('censys_host', ip, result)
        return result


# ─────────────────────────────────────────────────────────────────────────────
#  URLSCAN
# ─────────────────────────────────────────────────────────────────────────────
class URLScanClient:
    """https://urlscan.io/api/v1/"""

    def __init__(self, api_key: str, cache: OSINTCache) -> None:
        self._key, self._cache, self._rl = api_key, cache, _RateLimiter()
        self._ssl = ssl.create_default_context()

    def _req(self, method: str, path: str,
             payload: Optional[Dict] = None,
             params:  Optional[Dict[str, str]] = None) -> Tuple[int, Optional[Dict]]:
        qs = ('?' + urllib.parse.urlencode(params)) if params else ''
        body = json.dumps(payload).encode() if payload else None
        hdrs: Dict[str, str] = {'API-Key': self._key, 'Accept': 'application/json'}
        if body:
            hdrs['Content-Type'] = 'application/json'
        self._rl.wait()
        try:
            req = urllib.request.Request(
                f'{URLSCAN_BASE}{path}{qs}', data=body, headers=hdrs, method=method)
            with urllib.request.urlopen(req, timeout=_TIMEOUT, context=self._ssl) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            logger.warning('URLScan %s %s: %s', e.code, path, e.reason)
            return e.code, None
        except Exception as e:
            logger.warning('URLScan error %s: %s', path, e)
            return 0, None

    def submit(self, url: str, visibility: str = 'private') -> Optional[str]:
        """POST /scan/ -> returns uuid"""
        _, data = self._req('POST', '/scan/', payload={'url': url, 'visibility': visibility})
        return str(data['uuid']) if data and data.get('uuid') else None

    def result(self, uuid: str, max_wait: int = 60) -> Dict[str, Any]:
        """GET /result/{uuid}/ polls until ready (URLScan is async — 404 until done)."""
        cached = self._cache.get('urlscan_result', uuid)
        if cached is not None:
            return cached
        deadline = time.time() + max_wait
        while time.time() < deadline:
            status, data = self._req('GET', f'/result/{uuid}/')
            if status == 200 and data:
                pg, st, ls, ov = (data.get('page', {}), data.get('stats', {}),
                                  data.get('lists', {}),
                                  data.get('verdicts', {}).get('overall', {}))
                result = {
                    'page': {'url': pg.get('url', ''), 'domain': pg.get('domain', ''),
                             'ip': pg.get('ip', ''), 'server': pg.get('server', ''),
                             'tlsIssuer': pg.get('tlsIssuer', '')},
                    'stats': {'totalLinks': st.get('totalLinks', 0),
                              'uniqIPs': st.get('uniqIPs', 0)},
                    'lists': {'ips': ls.get('ips', []), 'domains': ls.get('domains', []),
                              'urls': ls.get('urls', []),
                              'certificates': ls.get('certificates', []),
                              'hashes': ls.get('hashes', [])},
                    'verdicts': {'overall': {'score': ov.get('score', 0),
                                             'malicious': bool(ov.get('malicious', False))}},
                }
                self._cache.put('urlscan_result', uuid, result, TTL_URLSCAN)
                return result
            if status == 404:
                time.sleep(5)  # not ready yet; back off before next poll
            else:
                break
        logger.warning('URLScan result %s not ready within %ss', uuid, max_wait)
        return {}

    def search_domain(self, domain: str, limit: int = 10) -> List[Dict[str, Any]]:
        """GET /search/?q=domain:{domain}&size={limit}"""
        ck = f'{domain}:{limit}'
        cached = self._cache.get('urlscan_domain', ck)
        if cached is not None:
            return cached
        _, data = self._req('GET', '/search/', params={'q': f'domain:{domain}',
                                                        'size': str(limit)})
        if not data:
            return []
        results = [
            {'uuid': h.get('_id', ''), 'url': h.get('page', {}).get('url', ''),
             'domain': h.get('page', {}).get('domain', ''),
             'ip': h.get('page', {}).get('ip', ''), 'date': h.get('indexedAt', '')}
            for h in data.get('results', [])[:limit]
        ]
        self._cache.put('urlscan_domain', ck, results)
        return results

    def search_ip(self, ip: str, limit: int = 1) -> List[Dict[str, Any]]:
        ck = f'ip:{ip}:{limit}'
        cached = self._cache.get('urlscan_ip', ck)
        if cached is not None:
            return cached
        _, data = self._req('GET', '/search/', params={'q': f'page.ip:{ip}',
                                                        'size': str(limit)})
        if not data:
            return []
        results = [
            {'uuid': h.get('_id', ''), 'url': h.get('page', {}).get('url', ''),
             'domain': h.get('page', {}).get('domain', ''),
             'ip': h.get('page', {}).get('ip', ''), 'date': h.get('indexedAt', '')}
            for h in data.get('results', [])[:limit]
        ]
        self._cache.put('urlscan_ip', ck, results)
        return results


# ─────────────────────────────────────────────────────────────────────────────
#  GREYNOISE
# ─────────────────────────────────────────────────────────────────────────────
class GreyNoiseClient:
    """https://api.greynoise.io/v3/community/{ip}"""

    def __init__(self, api_key: str, cache: OSINTCache) -> None:
        self._key, self._cache, self._rl = api_key, cache, _RateLimiter()
        self._ssl = ssl.create_default_context()

    def lookup(self, ip: str) -> Dict[str, Any]:
        cached = self._cache.get('greynoise', ip)
        if cached is not None:
            return cached
        self._rl.wait()
        hdrs: Dict[str, str] = {'Accept': 'application/json'}
        if self._key:
            hdrs['key'] = self._key
        try:
            req = urllib.request.Request(
                f'{GREYNOISE_BASE}/{urllib.parse.quote(ip)}', headers=hdrs)
            with urllib.request.urlopen(req, timeout=_TIMEOUT, context=self._ssl) as r:
                data = json.loads(r.read())
        except urllib.error.HTTPError as e:
            raw = b''
            try:
                raw = e.read()
            except Exception:
                pass
            if e.code == 404:
                # 404 = IP has no noise record (clean/unobserved — normal)
                try:
                    data = json.loads(raw)
                except Exception:
                    data = {'ip': ip, 'noise': False, 'riot': False,
                            'message': 'IP not observed'}
            else:
                logger.warning('GreyNoise %s %s: %s', e.code, ip, e.reason)
                return {}
        except Exception as e:
            logger.warning('GreyNoise error %s: %s', ip, e)
            return {}
        result: Dict[str, Any] = {
            'ip':             data.get('ip', ip),
            'noise':          bool(data.get('noise', False)),
            'riot':           bool(data.get('riot', False)),
            'classification': data.get('classification', ''),
            'name':           data.get('name', ''),
            'link':           data.get('link', ''),
            'last_seen':      data.get('last_seen', ''),
            'message':        data.get('message', ''),
        }
        self._cache.put('greynoise', ip, result)
        return result


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _build_summary(shodan:    Optional[Dict],
                   censys:    Optional[Dict],
                   greynoise: Optional[Dict],
                   urlscan:   Optional[Dict]) -> Dict[str, Any]:
    ports: List[int] = []
    hostnames: List[str] = []
    vulns: List[str] = []
    services: List[str] = []
    country = org = ''

    if shodan:
        ports.extend(int(p) for p in shodan.get('ports', []) if p)
        hostnames.extend(shodan.get('hostnames', []))
        vulns.extend(shodan.get('vulns', []))
        for s in shodan.get('services', []):
            n = s.get('product', '')
            if n and n not in services:
                services.append(n)
        country = country or shodan.get('country_name', '')
        org     = org or shodan.get('org', '')

    if censys:
        for s in censys.get('services', []):
            p = s.get('port')
            if p and int(p) not in ports:
                ports.append(int(p))
            n = s.get('service_name', '')
            if n and n not in services:
                services.append(n)
        country = country or censys.get('location', {}).get('country', '')
        org     = org or censys.get('autonomous_system', {}).get('name', '')

    return {
        'open_ports':   sorted(set(ports)),
        'hostnames':    sorted(set(hostnames)),
        'vulns':        sorted(set(vulns)),
        'is_scanner':   bool(greynoise and greynoise.get('noise')),
        'is_malicious': bool(urlscan and
                             urlscan.get('verdicts', {}).get('overall', {})
                                    .get('malicious')),
        'services':     services,
        'country':      country,
        'org':          org,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  FACADE
# ─────────────────────────────────────────────────────────────────────────────
class OSINTIntegration:
    """Facade that runs all available OSINT services against a target."""

    def __init__(self) -> None:
        self._cache = OSINTCache()

        key = os.environ.get('SHODAN_API_KEY', '').strip()
        if key:
            self._shodan: Optional[ShodanClient] = ShodanClient(key, self._cache)
        else:
            logger.warning('SHODAN_API_KEY not set — Shodan disabled')
            self._shodan = None

        cid, csec = (os.environ.get('CENSYS_API_ID', '').strip(),
                     os.environ.get('CENSYS_API_SECRET', '').strip())
        if cid and csec:
            self._censys: Optional[CensysClient] = CensysClient(cid, csec, self._cache)
        else:
            logger.warning('CENSYS_API_ID/SECRET not set — Censys disabled')
            self._censys = None

        ukey = os.environ.get('URLSCAN_API_KEY', '').strip()
        if ukey:
            self._urlscan: Optional[URLScanClient] = URLScanClient(ukey, self._cache)
        else:
            logger.warning('URLSCAN_API_KEY not set — URLScan disabled')
            self._urlscan = None

        # Community endpoint works without a key (just lower quota)
        gkey = os.environ.get('GREYNOISE_API_KEY', '').strip()
        if not gkey:
            logger.warning('GREYNOISE_API_KEY not set — using keyless community quota')
        self._greynoise = GreyNoiseClient(gkey, self._cache)

    def enrich_target(self, target: str) -> Dict[str, Any]:
        """
        Run all available services against target (IP or domain).
        Returns merged result dict:
        {
          'target': str,
          'shodan': dict or None,
          'censys': dict or None,
          'greynoise': dict or None,
          'urlscan': dict or None,
          'summary': {
            'open_ports': List[int],   # merged from all sources
            'hostnames': List[str],
            'vulns': List[str],        # CVE IDs from Shodan
            'is_scanner': bool,        # GreyNoise noise flag
            'is_malicious': bool,      # URLScan verdict
            'services': List[str],     # unique service names
            'country': str,
            'org': str,
          },
          'timestamp': float,
        }
        """
        target = target.strip().lower()
        is_ip  = _is_ip(target)

        shodan_res: Optional[Dict] = None
        if self._shodan:
            try:
                if is_ip:
                    shodan_res = self._shodan.host_lookup(target) or None
                else:
                    hits = self._shodan.search(f'hostname:{target}', limit=1)
                    shodan_res = hits[0] if hits else None
            except Exception as e:
                logger.error('Shodan enrich: %s', e)

        censys_res: Optional[Dict] = None
        if self._censys and is_ip:
            try:
                censys_res = self._censys.host_lookup(target) or None
            except Exception as e:
                logger.error('Censys enrich: %s', e)

        gn_res: Optional[Dict] = None
        if is_ip:
            try:
                gn_res = self._greynoise.lookup(target) or None
            except Exception as e:
                logger.error('GreyNoise enrich: %s', e)

        us_res: Optional[Dict] = None
        if self._urlscan:
            try:
                hits = (self._urlscan.search_domain(target, limit=1) if not is_ip
                        else self._urlscan.search_ip(target, limit=1))
                if hits:
                    uuid = hits[0].get('uuid', '')
                    if uuid:
                        us_res = self._urlscan.result(uuid) or None
            except Exception as e:
                logger.error('URLScan enrich: %s', e)

        return {
            'target':    target,
            'shodan':    shodan_res,
            'censys':    censys_res,
            'greynoise': gn_res,
            'urlscan':   us_res,
            'summary':   _build_summary(shodan_res, censys_res, gn_res, us_res),
            'timestamp': time.time(),
        }

    def print_report(self, result: Dict[str, Any]) -> None:
        target  = result.get('target', 'unknown')
        summary = result.get('summary', {})
        dt      = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(result.get('timestamp', 0)))
        w = 62

        print('=' * w)
        print(f'  OSINT Enrichment — {target}')
        print(f'  {dt}')
        print('=' * w)
        print('\n[SUMMARY]')
        print(f"  Country  : {summary.get('country') or 'unknown'}")
        print(f"  Org/ISP  : {summary.get('org') or 'unknown'}")
        print(f"  Ports    : {', '.join(str(p) for p in summary.get('open_ports', [])) or 'none'}")
        print(f"  Services : {', '.join(summary.get('services', [])) or 'none'}")
        print(f"  Hostnames: {', '.join(summary.get('hostnames', [])) or 'none'}")
        print(f"  CVEs     : {', '.join(summary.get('vulns', [])) or 'none'}")
        print(f"  Scanner? : {'YES (GreyNoise noise)' if summary.get('is_scanner') else 'no'}")
        print(f"  Malicious: {'YES (URLScan verdict)' if summary.get('is_malicious') else 'no'}")

        _HINTS = {'shodan': 'SHODAN_API_KEY', 'censys': 'CENSYS_API_ID + CENSYS_API_SECRET',
                  'greynoise': 'GREYNOISE_API_KEY', 'urlscan': 'URLSCAN_API_KEY'}
        for label, key in [('Shodan', 'shodan'), ('Censys', 'censys'),
                            ('GreyNoise', 'greynoise'), ('URLScan', 'urlscan')]:
            data = result.get(key)
            print(f'\n[{label}]')
            if data is None:
                print(f'  skipped  (set {_HINTS[key]} to enable)')
            else:
                for line in json.dumps(data, indent=2, default=str).splitlines():
                    print(f'  {line}')
        print('=' * w)


# ─────────────────────────────────────────────────────────────────────────────
#  CLI SELF-TEST
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    import argparse

    logging.basicConfig(level=logging.INFO,
                        format='%(levelname)-8s %(name)s  %(message)s')
    p = argparse.ArgumentParser(
        description='AutoPentestX OSINT Integration — passive target enrichment')
    p.add_argument('target', nargs='?', default='8.8.8.8',
                   help='IP or domain to enrich (default: 8.8.8.8)')
    args = p.parse_args()

    osint = OSINTIntegration()
    print(f'\nRunning OSINT enrichment for: {args.target}\n')
    osint.print_report(osint.enrich_target(args.target))
