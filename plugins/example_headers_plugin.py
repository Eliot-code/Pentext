#!/usr/bin/env python3
"""Plugin: headers-audit — checks HTTP security response headers."""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from modules.plugin_loader import PluginBase, PluginMeta
from typing import Any, Dict, List, Optional
from urllib import request as _request
from urllib.error import URLError


_SCORED_HEADERS: List[Dict[str, Any]] = [
    {'name': 'Strict-Transport-Security', 'weight': 20,
     'description': 'Enforces HTTPS and prevents protocol-downgrade attacks (HSTS).',
     'check': lambda v: v is not None,
     'guidance': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'},
    {'name': 'X-Frame-Options', 'weight': 15,
     'description': 'Mitigates clickjacking by controlling framing.',
     'check': lambda v: v is not None and v.upper() in ('DENY', 'SAMEORIGIN'),
     'guidance': 'Add: X-Frame-Options: DENY  (or use CSP frame-ancestors)'},
    {'name': 'X-Content-Type-Options', 'weight': 10,
     'description': 'Prevents MIME-type sniffing (nosniff).',
     'check': lambda v: v is not None and 'nosniff' in v.lower(),
     'guidance': 'Add: X-Content-Type-Options: nosniff'},
    {'name': 'Content-Security-Policy', 'weight': 25,
     'description': 'Restricts resources the browser may load (mitigates XSS).',
     'check': lambda v: v is not None and len(v) > 10,
     'guidance': "Add a restrictive CSP, e.g.: Content-Security-Policy: default-src 'self'"},
    {'name': 'Permissions-Policy', 'weight': 10,
     'description': 'Controls browser feature access (camera, geolocation, etc.).',
     'check': lambda v: v is not None,
     'guidance': 'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()'},
    {'name': 'X-XSS-Protection', 'weight': 5,
     'description': 'Legacy XSS filter header (deprecated; CSP preferred).',
     'check': lambda v: v is not None,
     'guidance': 'Add: X-XSS-Protection: 1; mode=block  (or disable explicitly)'},
    {'name': 'Referrer-Policy', 'weight': 10,
     'description': 'Controls how much referrer information is sent.',
     'check': lambda v: v is not None,
     'guidance': 'Add: Referrer-Policy: strict-origin-when-cross-origin'},
    {'name': 'Cross-Origin-Resource-Policy', 'weight': 5,
     'description': 'Prevents other origins from reading this resource (CORP).',
     'check': lambda v: v is not None and v.lower() in ('same-origin', 'same-site', 'cross-origin'),
     'guidance': 'Add: Cross-Origin-Resource-Policy: same-origin'},
]

_TOTAL_WEIGHT = sum(h['weight'] for h in _SCORED_HEADERS)


def _grade(score: int) -> str:
    if score >= 90: return 'A'
    if score >= 75: return 'B'
    if score >= 50: return 'C'
    if score >= 25: return 'D'
    return 'F'


class Plugin(PluginBase):
    meta = PluginMeta(
        name='headers-audit',
        description=('Fetches the target URL and audits HTTP security response headers '
                     '(HSTS, CSP, X-Frame-Options, …).  Returns a score out of 100 and '
                     'a letter grade A–F.'),
        version='1.0.0',
        author='community',
        tags=['web', 'passive'],
        requires=['requests'],
    )

    TIMEOUT: int = 10

    def validate(self, target: str) -> bool:
        return target.startswith('http://') or target.startswith('https://')

    def run(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        timeout = context.get('options', {}).get('timeout', self.TIMEOUT)
        response_headers = self._fetch_headers(target, timeout)
        if response_headers is None:
            return {'missing_headers': [], 'present_headers': [], 'header_values': {},
                    'score': 0, 'grade': 'F', 'guidance': [],
                    'error': f'Could not connect to {target}'}
        lc_headers: Dict[str, str] = {k.lower(): v for k, v in response_headers.items()}
        missing: List[str] = []
        present: List[str] = []
        guidance: List[str] = []
        raw_values: Dict[str, Optional[str]] = {}
        earned_weight = 0
        for hdef in _SCORED_HEADERS:
            hname: str = hdef['name']
            value: Optional[str] = lc_headers.get(hname.lower())
            raw_values[hname] = value
            if hdef['check'](value):
                present.append(hname)
                earned_weight += hdef['weight']
            else:
                missing.append(hname)
                guidance.append(hdef['guidance'])
        score = round(earned_weight * 100 / _TOTAL_WEIGHT) if _TOTAL_WEIGHT else 0
        return {'missing_headers': missing, 'present_headers': present,
                'header_values': raw_values, 'score': score, 'grade': _grade(score),
                'guidance': guidance}

    def _fetch_headers(self, url: str, timeout: int) -> Optional[Dict[str, str]]:
        try:
            import requests
            resp = requests.head(url, timeout=timeout, allow_redirects=True, verify=False)
            return dict(resp.headers)
        except ImportError:
            pass
        except Exception:
            pass
        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = _request.Request(url, method='HEAD',
                                   headers={'User-Agent': 'AutoPentestX/1.0'})
            with _request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return dict(resp.headers)
        except Exception:
            pass
        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = _request.Request(url, headers={'User-Agent': 'AutoPentestX/1.0'})
            with _request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return dict(resp.headers)
        except Exception:
            return None


if __name__ == '__main__':
    import json
    target = sys.argv[1] if len(sys.argv) > 1 else 'https://example.com'
    plugin = Plugin()
    if not plugin.validate(target):
        print(f'[!] Invalid target: {target}')
        sys.exit(1)
    result = plugin.run(target, {})
    print(json.dumps(result, indent=2))
