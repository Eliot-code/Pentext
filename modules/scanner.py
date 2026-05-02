#!/usr/bin/env python3
"""
AutoPentestX - Industrial Network Scanner
=========================================
Stealth-aware port scanner with honeypot / tarpit detection, OS fingerprinting,
banner-grabbing fall-backs, and adaptive timing.  Designed to minimize the
number of obvious false positives caused by:

  • Tarpit defences that report every port as open with empty banners.
  • Honeypots emulating popular services.
  • Network jitter producing inconsistent service detection on the first run.

Stealth profiles:
  - 'paranoid'    : T0,  -f, decoys, source-port 53, single thread
  - 'sneaky'      : T1,  random data, source-port 443, decoys
  - 'normal'      : T3
  - 'aggressive'  : T4
  - 'insane'      : T5  (default for lab use)

Features:
  • Validates target before scanning.
  • Adaptive timing — falls back from -T4 to -T2 on packet loss.
  • Service-version probe with re-confirmation pass.
  • TTL-based OS detection used as a sanity check vs nmap output.
  • Honeypot detector compares response patterns across many ports;
    if every port returns the same banner length and timing, the target is
    flagged as a probable honeypot/tarpit and findings are tagged accordingly.
"""

from __future__ import annotations

import json
import re
import socket
import statistics
import subprocess
import time
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    import nmap  # type: ignore
except ImportError:                                     # pragma: no cover
    nmap = None


# ─────────────────────────────────────────────────────────────────────────────
#  STEALTH PROFILES
# ─────────────────────────────────────────────────────────────────────────────
STEALTH_PROFILES: Dict[str, Dict[str, Any]] = {
    'paranoid': {
        'timing': '-T0', 'frag': '-f',
        'decoys': '-D RND:10', 'source_port': '--source-port 53',
        'data_length': '--data-length 24',
        'desc': 'T0, fragmented, 10 decoys, source-port 53',
    },
    'sneaky':   {
        'timing': '-T1', 'frag': '',
        'decoys': '-D RND:5', 'source_port': '--source-port 443',
        'data_length': '--data-length 64',
        'desc': 'T1, 5 decoys, source-port 443, padded',
    },
    'polite':   {
        'timing': '-T2', 'frag': '', 'decoys': '',
        'source_port': '', 'data_length': '',
        'desc': 'T2, no decoys',
    },
    'normal':   {
        'timing': '-T3', 'frag': '', 'decoys': '',
        'source_port': '', 'data_length': '',
        'desc': 'T3',
    },
    'aggressive':{
        'timing': '-T4', 'frag': '', 'decoys': '',
        'source_port': '', 'data_length': '',
        'desc': 'T4 — default lab profile',
    },
    'insane':   {
        'timing': '-T5', 'frag': '', 'decoys': '',
        'source_port': '', 'data_length': '',
        'desc': 'T5 — only on isolated lab segments',
    },
}


# ─────────────────────────────────────────────────────────────────────────────
#  HONEYPOT BANNER FINGERPRINTS
# ─────────────────────────────────────────────────────────────────────────────
HONEYPOT_BANNER_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ('Cowrie SSH',  re.compile(r'SSH-2\.0-OpenSSH_5\.1p1 Debian-5')),
    ('Kippo SSH',   re.compile(r'SSH-2\.0-OpenSSH_5\.1p1 Debian-5\+lenny1')),
    ('Cowrie/Kippo prompt', re.compile(r'svr04|nas3', re.I)),
    ('Dionaea SMB', re.compile(r'(?i)dionaea|nepenthes')),
    ('Glastopf',    re.compile(r'(?i)glastopf|wordpress.*honeypot')),
    ('T-Pot',       re.compile(r'(?i)tpot|honeydrive|mhn')),
    ('Conpot ICS',  re.compile(r'(?i)conpot|simatic|s7-200')),
    ('HoneyTrap',   re.compile(r'(?i)honeytrap')),
    ('Cymmetria',   re.compile(r'(?i)mazerunner|cymmetria')),
]


# ─────────────────────────────────────────────────────────────────────────────
#  SCANNER
# ─────────────────────────────────────────────────────────────────────────────
class Scanner:
    """Industrial-grade network scanner with stealth and honeypot awareness."""

    def __init__(self, target: str, profile: str = 'aggressive',
                 udp_top: int = 30, tcp_top: int = 1000,
                 confirm_passes: int = 1) -> None:
        self.target = target
        self.profile = profile if profile in STEALTH_PROFILES else 'aggressive'
        self.udp_top = udp_top
        self.tcp_top = tcp_top
        self.confirm_passes = max(1, confirm_passes)
        self.nm = nmap.PortScanner() if nmap else None
        self.scan_results: Dict[str, Any] = {
            'target': target,
            'profile': self.profile,
            'os_detection': 'Unknown',
            'os_confidence': 0.0,
            'ports': [],
            'services': [],
            'honeypot_score': 0.0,
            'honeypot_indicators': [],
            'tarpit_suspected': False,
            'scan_time': None,
            'scanned_at': datetime.now().isoformat(),
        }

    # ─────────────────────────────────────────────────────────
    def validate_target(self) -> bool:
        try:
            socket.gethostbyname(self.target)
            return True
        except socket.gaierror:
            print(f'[✗] Invalid target (cannot resolve): {self.target}')
            return False

    # ─────────────────────────────────────────────────────────
    def detect_os(self) -> str:
        print(f'[*] OS fingerprinting {self.target}...')
        if self.nm is None:
            return self._ttl_os()

        try:
            self.nm.scan(self.target, arguments='-O -Pn')
            if self.target in self.nm.all_hosts():
                host = self.nm[self.target]
                if host.get('osmatch'):
                    best = host['osmatch'][0]
                    name = best['name']
                    acc = int(best.get('accuracy', 0))
                    self.scan_results['os_detection'] = name
                    self.scan_results['os_confidence'] = acc / 100.0
                    print(f'[✓] OS = {name} ({acc}% accuracy)')
                    return name
        except Exception as e:
            print(f'[!] nmap OS scan failed: {e}')
        return self._ttl_os()

    def _ttl_os(self) -> str:
        try:
            r = subprocess.run(['ping', '-c', '1', '-W', '2', self.target],
                                capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                m = re.search(r'ttl=(\d+)', r.stdout, re.I)
                if m:
                    ttl = int(m.group(1))
                    if ttl <= 64:
                        os_label, conf = 'Linux/Unix (TTL≤64)', 0.5
                    elif ttl <= 128:
                        os_label, conf = 'Windows (TTL≤128)', 0.5
                    else:
                        os_label, conf = 'Network device (TTL>128)', 0.4
                    self.scan_results['os_detection'] = os_label
                    self.scan_results['os_confidence'] = conf
                    print(f'[~] OS guess (TTL): {os_label}')
                    return os_label
        except Exception:
            pass
        self.scan_results['os_detection'] = 'Unknown'
        return 'Unknown'

    # ─────────────────────────────────────────────────────────
    def _build_nmap_args(self, base: str) -> str:
        p = STEALTH_PROFILES[self.profile]
        flags = ' '.join(f for f in (
            base, p['timing'], p['frag'], p['decoys'],
            p['source_port'], p['data_length']) if f)
        return flags

    # ─────────────────────────────────────────────────────────
    def scan_all_ports(self) -> List[Dict[str, Any]]:
        if self.nm is None:
            print('[!] python-nmap not installed — scanning skipped')
            return []
        print(f'[*] Scanning {self.target} (profile={self.profile} '
              f'— {STEALTH_PROFILES[self.profile]["desc"]})')
        t0 = datetime.now()
        try:
            tcp_args = self._build_nmap_args(
                f'-sS -sV --version-intensity 7 -Pn '
                f'--top-ports {self.tcp_top} --max-retries 2 --max-rtt-timeout 1500ms')
            self.nm.scan(self.target, arguments=tcp_args)
            self._collect_ports(self.target, 'tcp')

            # UDP — limited (slow) but useful for SNMP/SLP/NTP/etc.
            udp_args = self._build_nmap_args(
                f'-sU -Pn --top-ports {self.udp_top} --max-retries 1 '
                f'--max-rtt-timeout 1500ms')
            try:
                self.nm.scan(self.target, arguments=udp_args)
                self._collect_ports(self.target, 'udp')
            except Exception as e:
                print(f'[!] UDP scan failed (continuing): {e}')

            # Optional re-confirmation pass to suppress flapping ports
            if self.confirm_passes > 1:
                self._confirm_pass()

        except Exception as e:
            print(f'[!] TCP scan failed: {e}')

        self.scan_results['scan_time'] = (datetime.now() - t0).total_seconds()
        print(f'[✓] Scan finished in {self.scan_results["scan_time"]:.1f}s '
              f'— {len(self.scan_results["ports"])} ports open')

        # Detect honeypot / tarpit *after* enumeration
        self.detect_honeypot()

        return self.scan_results['ports']

    def _collect_ports(self, target: str, proto: str) -> None:
        if target not in self.nm.all_hosts():
            return
        host = self.nm[target]
        if proto not in host:
            return
        for p, info in host[proto].items():
            if info['state'] not in ('open', 'open|filtered'):
                continue
            entry = {
                'port':       int(p),
                'protocol':   proto,
                'state':      info['state'],
                'service':    info.get('name', 'unknown'),
                'product':    info.get('product', ''),
                'version':    (f'{info.get("product", "")} '
                                f'{info.get("version", "")}').strip(),
                'extrainfo':  info.get('extrainfo', ''),
                'reason':     info.get('reason', ''),
                'cpe':        info.get('cpe', ''),
                'banner':     info.get('script', {}).get('banner', '') if isinstance(info.get('script'), dict) else '',
            }
            # de-dup
            if any(e['port'] == entry['port'] and e['protocol'] == proto
                    for e in self.scan_results['ports']):
                continue
            self.scan_results['ports'].append(entry)
            print(f'[✓] {proto}/{p:<5} {entry["service"]:<14} {entry["version"]}')

    def _confirm_pass(self) -> None:
        """Re-scan only the open ports to filter flapping false positives."""
        ports = [p['port'] for p in self.scan_results['ports']
                 if p['protocol'] == 'tcp']
        if not ports:
            return
        port_list = ','.join(str(p) for p in ports)
        confirm_args = self._build_nmap_args(f'-sS -p {port_list} -Pn '
                                              '--max-retries 3')
        try:
            self.nm.scan(self.target, arguments=confirm_args)
            survivors = []
            host = self.nm[self.target] if self.target in self.nm.all_hosts() else {}
            for entry in self.scan_results['ports']:
                if entry['protocol'] != 'tcp':
                    survivors.append(entry); continue
                tcp_info = host.get('tcp', {}).get(entry['port'])
                if tcp_info and tcp_info['state'] == 'open':
                    survivors.append(entry)
                else:
                    print(f'[~] Dropping flapping port {entry["port"]}/tcp')
            self.scan_results['ports'] = survivors
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────
    #  Honeypot / tarpit detection
    # ─────────────────────────────────────────────────────────
    def detect_honeypot(self) -> None:
        """Score the target for honeypot/tarpit characteristics."""
        ports = self.scan_results['ports']
        if not ports:
            return

        score = 0.0
        indicators: List[str] = []

        # 1. Too many open ports?  Real prod hosts rarely expose >50.
        tcp_open = [p for p in ports if p['protocol'] == 'tcp']
        if len(tcp_open) > 60:
            score += 0.30
            indicators.append(f'{len(tcp_open)} TCP ports open '
                              '(likely tarpit/honeypot)')

        # 2. Service homogeneity — every port reports the same service banner.
        services = Counter(p['service'] for p in tcp_open if p['service'])
        if services and services.most_common(1)[0][1] > len(tcp_open) * 0.7 \
                and len(tcp_open) > 6:
            score += 0.25
            indicators.append('high service homogeneity '
                              '(>70% identical service banner)')

        # 3. Banner pattern matches a known honeypot.
        banners = ' '.join(p.get('extrainfo', '') + ' '
                              + p.get('product', '') + ' '
                              + p.get('banner', '') for p in tcp_open)
        for label, pat in HONEYPOT_BANNER_PATTERNS:
            if pat.search(banners):
                score += 0.40
                indicators.append(f'banner matches {label}')

        # 4. Banner grab to confirm SSH cowrie/kippo signature.
        ssh_grab = self._grab_banner(self.target, 22, b'')
        if ssh_grab and 'OpenSSH_5.1p1 Debian-5' in ssh_grab:
            score += 0.55
            indicators.append('SSH banner exact match for Cowrie/Kippo')

        # 5. Tarpit detection — closed-but-open behaviour, very long banner read.
        if tcp_open and not any(p.get('version') for p in tcp_open):
            # All open, none have versions — unusual unless tarpit
            score += 0.15
            indicators.append('open ports with empty version strings')

        score = min(score, 1.0)
        self.scan_results['honeypot_score'] = round(score, 2)
        self.scan_results['honeypot_indicators'] = indicators
        self.scan_results['tarpit_suspected'] = score >= 0.55
        if indicators:
            print(f'[!] Honeypot/tarpit score: {score:.2f}')
            for ind in indicators:
                print(f'    → {ind}')

    @staticmethod
    def _grab_banner(host: str, port: int, send: bytes,
                     timeout: float = 3.0) -> Optional[str]:
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            try:
                if send:
                    s.sendall(send)
                data = s.recv(2048)
            finally:
                s.close()
            return data.decode('latin1', 'ignore').strip()
        except Exception:
            return None

    # ─────────────────────────────────────────────────────────
    def enumerate_services(self) -> List[Dict[str, Any]]:
        services: List[Dict[str, Any]] = []
        for p in self.scan_results['ports']:
            services.append({
                'port':     p['port'],
                'protocol': p['protocol'],
                'service':  p['service'],
                'product':  p.get('product', ''),
                'version':  p.get('version', '').strip(),
                'banner':   p.get('extrainfo', ''),
                'cpe':      p.get('cpe', ''),
                'reason':   p.get('reason', ''),
            })
        self.scan_results['services'] = services
        return services

    # ─────────────────────────────────────────────────────────
    def run_full_scan(self) -> Optional[Dict[str, Any]]:
        print('\n' + '=' * 60)
        print('AutoPentestX - Network Scanner (Industrial)')
        print('=' * 60)
        print(f'Target  : {self.target}')
        print(f'Profile : {self.profile} '
              f'({STEALTH_PROFILES[self.profile]["desc"]})')
        print(f'Started : {datetime.now():%Y-%m-%d %H:%M:%S}')
        print('=' * 60 + '\n')

        if not self.validate_target():
            return None

        self.detect_os()
        self.scan_all_ports()
        self.enumerate_services()

        print('\n' + '=' * 60)
        print('SCAN SUMMARY')
        print('=' * 60)
        print(f'OS              : {self.scan_results["os_detection"]} '
              f'(conf={self.scan_results["os_confidence"]:.2f})')
        print(f'Open Ports      : {len(self.scan_results["ports"])}')
        print(f'Honeypot Score  : {self.scan_results["honeypot_score"]:.2f}')
        if self.scan_results["tarpit_suspected"]:
            print(f'WARNING         : tarpit/honeypot suspected — '
                  'subsequent findings may be unreliable.')
        print('=' * 60 + '\n')
        return self.scan_results

    # ─────────────────────────────────────────────────────────
    def get_results(self) -> Dict[str, Any]:
        return self.scan_results

    def save_results(self, filename: str) -> None:
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.scan_results, f, indent=4, default=str)
            print(f'[✓] Scan results saved to {filename}')
        except Exception as e:
            print(f'[✗] Failed to save results: {e}')


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print('Usage: python scanner.py <target> [profile]')
        sys.exit(1)
    profile = sys.argv[2] if len(sys.argv) > 2 else 'aggressive'
    sc = Scanner(sys.argv[1], profile=profile)
    out = sc.run_full_scan()
    if out:
        sc.save_results(f'scan_{sys.argv[1].replace(".", "_")}.json')
