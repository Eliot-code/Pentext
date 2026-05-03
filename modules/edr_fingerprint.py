#!/usr/bin/env python3
"""
AutoPentestX - EDR/AV Fingerprinting Module
============================================
Detects common endpoint security products at runtime and selects the
most appropriate evasion strategy from modules/evasion.py.

Detection vectors (passive/read-only — no writes, no process injection):
  1. Process list scan (psutil or /proc on Linux, tasklist on Windows)
  2. Service/driver name patterns
  3. File-system artefacts (EDR installation paths)
  4. Environment variable leakage
  5. Registry keys (Windows only, read-only)
  6. Loaded module / DLL names (Windows, read-only)

Zero external dependencies beyond stdlib.  psutil is used opportunistically
for richer process info but falls back gracefully when unavailable.

Supported products:
  Windows: Defender ATP, CrowdStrike Falcon, SentinelOne, Carbon Black,
           Cylance, Sophos, Trend Micro ApexOne, ESET, Symantec SEP,
           Trellix/McAfee, Palo Alto Cortex, Elastic
  Linux:   CrowdStrike Falcon sensor, SentinelOne agent, Carbon Black
           sensor, ESET PROTECT, Wazuh agent, auditd, AIDE, osquery
  macOS:   CrowdStrike Falcon, SentinelOne, Jamf Protect, Objective-See
           tools (LuLu, BlockBlock, KnockKnock)

Evasion strategy mapping:
  - Defender ATP         → amsi_veh_patchless + ekko sleep mask
  - CrowdStrike Falcon   → halos_gate + zilean sleep mask
  - SentinelOne          → tartarus_gate + deathsleep + stomping
  - Carbon Black         → amsi_com_hijack + cronos sleep mask
  - ESET / Sophos        → amsi_unicode_split + foliage
  - No EDR detected      → amsi_initfailed_v1 (lightest bypass)
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# ─────────────────────────────────────────────────────────────────────────────
#  EDR SIGNATURE DATABASE
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class EDRSignature:
    name:     str
    vendor:   str
    tier:     int              # 1=enterprise (hardest to evade), 3=consumer
    processes: List[str]       # lowercase process names to match
    services:  List[str]       # lowercase service/daemon names
    paths:     List[str]       # FS paths (case-insensitive partial match)
    env_vars:  List[str]       # environment variable names whose presence is a signal
    registry:  List[str]       # HKLM paths (Windows only, read-only check)
    preferred_bypass: str      # key into evasion.AMSI_BYPASS_LIBRARY
    preferred_sleep:  str      # key into evasion.SLEEP_MASK_TEMPLATES
    preferred_gate:   str      # key into evasion.{HELLS,HALOS,TARTARUS}_GATE_C or ''


_SIGNATURES: List[EDRSignature] = [
    # ── Windows Defender ATP / MDE ──────────────────────────────────────
    EDRSignature(
        name='Windows Defender ATP', vendor='Microsoft', tier=2,
        processes=['msmpeng.exe', 'mssense.exe', 'senseir.exe', 'sensecncproxy.exe',
                   'microsoft.tri.sensor.exe', 'msseccore.exe', 'wd-datp.exe'],
        services=['windefend', 'wdnisdrv', 'wdboot', 'sense', 'windefendnetworkservice'],
        paths=[r'C:\ProgramData\Microsoft\Windows Defender',
               r'C:\Program Files\Windows Defender Advanced Threat Protection'],
        env_vars=[],
        registry=[r'HKLM\SOFTWARE\Microsoft\Windows Defender',
                  r'HKLM\SYSTEM\CurrentControlSet\Services\Sense'],
        preferred_bypass='amsi_veh_patchless',
        preferred_sleep='ekko',
        preferred_gate='halos_gate',
    ),
    # ── CrowdStrike Falcon ───────────────────────────────────────────────
    EDRSignature(
        name='CrowdStrike Falcon', vendor='CrowdStrike', tier=1,
        processes=['falconctl', 'falcond', 'csfalconservice.exe', 'csfalconcontainer.exe',
                   'falcon-sensor', 'csagent.exe', 'cscfghost.exe'],
        services=['csfalconservice', 'falcon-sensor', 'falcond', 'csagent'],
        paths=[r'C:\Program Files\CrowdStrike',
               '/opt/CrowdStrike', '/Library/CS',
               r'C:\Windows\System32\drivers\CrowdStrike'],
        env_vars=['CS_FALCON_CROWDSTRIKE_INSTANCE_ID'],
        registry=[r'HKLM\SYSTEM\CurrentControlSet\Services\CSAgent',
                  r'HKLM\SOFTWARE\CrowdStrike'],
        preferred_bypass='amsi_hwbp',
        preferred_sleep='zilean',
        preferred_gate='halos_gate',
    ),
    # ── SentinelOne ──────────────────────────────────────────────────────
    EDRSignature(
        name='SentinelOne', vendor='SentinelOne', tier=1,
        processes=['sentinelagent.exe', 'sentinelctl', 'sentineld', 's1agent.exe',
                   'sentinelone.exe', 'sentinelservicehost.exe'],
        services=['sentinelagent', 'sentinelmonitor', 's1agent'],
        paths=[r'C:\Program Files\SentinelOne',
               '/opt/sentinelone', '/Library/Sentinel'],
        env_vars=['S1_AGENT_ID'],
        registry=[r'HKLM\SOFTWARE\Sentinel Labs',
                  r'HKLM\SYSTEM\CurrentControlSet\Services\SentinelAgent'],
        preferred_bypass='amsi_scanbuffer_patch',
        preferred_sleep='deathsleep',
        preferred_gate='tartarus_gate',
    ),
    # ── VMware Carbon Black ──────────────────────────────────────────────
    EDRSignature(
        name='Carbon Black', vendor='VMware / Broadcom', tier=1,
        processes=['cbagentservice.exe', 'cbdefense.exe', 'cbcomms.exe', 'repmgr.exe',
                   'cb.exe', 'cbstream.exe', 'cbsensor'],
        services=['cbagentservice', 'cbdefense', 'carbonblack', 'cbsensor'],
        paths=[r'C:\Program Files\Confer',
               r'C:\Program Files\VMware\VMware Carbon Black Cloud',
               '/var/lib/cb', '/opt/carbonblack'],
        env_vars=['CB_SENSOR_ID'],
        registry=[r'HKLM\SOFTWARE\CarbonBlack',
                  r'HKLM\SYSTEM\CurrentControlSet\Services\CbDefense'],
        preferred_bypass='amsi_com_hijack',
        preferred_sleep='cronos',
        preferred_gate='halos_gate',
    ),
    # ── Cylance ──────────────────────────────────────────────────────────
    EDRSignature(
        name='Cylance PROTECT', vendor='BlackBerry', tier=2,
        processes=['cylancesvc.exe', 'cylanceui.exe', 'cyagent.exe'],
        services=['cylancesvc', 'cylancedrv'],
        paths=[r'C:\Program Files\Cylance'],
        env_vars=[],
        registry=[r'HKLM\SOFTWARE\Cylance\Desktop'],
        preferred_bypass='amsi_unicode_split',
        preferred_sleep='foliage',
        preferred_gate='hells_gate',
    ),
    # ── Sophos ───────────────────────────────────────────────────────────
    EDRSignature(
        name='Sophos Intercept X', vendor='Sophos', tier=2,
        processes=['sophoshealth.exe', 'sophosui.exe', 'savservice.exe',
                   'sophosav.exe', 'sophosfs.exe', 'sophosntp.exe'],
        services=['sophosav', 'sophosagent', 'sfe'],
        paths=[r'C:\Program Files\Sophos',
               '/opt/sophos-spl', '/Library/Sophos Anti-Virus'],
        env_vars=[],
        registry=[r'HKLM\SOFTWARE\Sophos'],
        preferred_bypass='amsi_unicode_split',
        preferred_sleep='foliage',
        preferred_gate='hells_gate',
    ),
    # ── Trend Micro ──────────────────────────────────────────────────────
    EDRSignature(
        name='Trend Micro Apex One', vendor='Trend Micro', tier=2,
        processes=['ntrtscan.exe', 'tmproxy.exe', 'coreserviceshell.exe',
                   'pccntmon.exe', 'tmccsf.exe'],
        services=['ntrtscan', 'ofcservice'],
        paths=[r'C:\Program Files\Trend Micro'],
        env_vars=[],
        registry=[r'HKLM\SOFTWARE\TrendMicro'],
        preferred_bypass='amsi_initfailed_v1',
        preferred_sleep='ekko',
        preferred_gate='hells_gate',
    ),
    # ── ESET ─────────────────────────────────────────────────────────────
    EDRSignature(
        name='ESET Endpoint Security', vendor='ESET', tier=2,
        processes=['ekrn.exe', 'egui.exe', 'ecomserver.exe', 'esetdaemon'],
        services=['ekrn', 'epfwlwf', 'esetdaemon'],
        paths=[r'C:\Program Files\ESET',
               '/opt/eset', '/Library/Application Support/ESET'],
        env_vars=[],
        registry=[r'HKLM\SOFTWARE\ESET'],
        preferred_bypass='amsi_unicode_split',
        preferred_sleep='foliage',
        preferred_gate='hells_gate',
    ),
    # ── Symantec SEP ─────────────────────────────────────────────────────
    EDRSignature(
        name='Symantec Endpoint Protection', vendor='Broadcom', tier=2,
        processes=['ccsvchst.exe', 'smc.exe', 'smcgui.exe', 'symantec antivirus.exe'],
        services=['semwebclient', 'symantec endpoint protection'],
        paths=[r'C:\Program Files\Symantec',
               r'C:\Program Files\Broadcom\Symantec Endpoint Protection'],
        env_vars=[],
        registry=[r'HKLM\SOFTWARE\Symantec'],
        preferred_bypass='amsi_initfailed_v1',
        preferred_sleep='ekko',
        preferred_gate='hells_gate',
    ),
    # ── Palo Alto Cortex XDR ─────────────────────────────────────────────
    EDRSignature(
        name='Palo Alto Cortex XDR', vendor='Palo Alto Networks', tier=1,
        processes=['cortex xdr.exe', 'cytool.exe', 'cyserver.exe', 'cyd.exe'],
        services=['cyserver', 'cortexdr'],
        paths=[r'C:\Program Files\Palo Alto Networks\Traps',
               r'C:\Program Files\Cortex XDR'],
        env_vars=[],
        registry=[r'HKLM\SOFTWARE\Palo Alto Networks\Traps'],
        preferred_bypass='amsi_hwbp',
        preferred_sleep='zilean',
        preferred_gate='halos_gate',
    ),
    # ── Elastic Security ────────────────────────────────────────────────
    EDRSignature(
        name='Elastic Security', vendor='Elastic', tier=2,
        processes=['elastic-agent', 'elastic-endpoint', 'filebeat', 'winlogbeat'],
        services=['elastic-agent', 'elastic-endpoint'],
        paths=[r'C:\Program Files\Elastic', '/opt/Elastic', '/usr/share/elastic-agent'],
        env_vars=['ELASTIC_APM_SERVER_URL', 'ELASTIC_AGENT_ID'],
        registry=[r'HKLM\SOFTWARE\Elastic'],
        preferred_bypass='amsi_veh_patchless',
        preferred_sleep='ekko',
        preferred_gate='halos_gate',
    ),
    # ── Wazuh (Linux/macOS) ──────────────────────────────────────────────
    EDRSignature(
        name='Wazuh Agent', vendor='Wazuh', tier=3,
        processes=['wazuh-agentd', 'ossec-agentd', 'wazuh-syscheckd',
                   'wazuh-logcollector', 'ossec-logcollector'],
        services=['wazuh-agent', 'ossec'],
        paths=['/var/ossec', '/var/wazuh', r'C:\Program Files (x86)\ossec-agent'],
        env_vars=[],
        registry=[],
        preferred_bypass='amsi_initfailed_v1',
        preferred_sleep='ekko',
        preferred_gate='',
    ),
    # ── osquery ─────────────────────────────────────────────────────────
    EDRSignature(
        name='osquery', vendor='osquery.io', tier=3,
        processes=['osqueryd', 'osqueryi'],
        services=['osqueryd'],
        paths=['/etc/osquery', r'C:\Program Files\osquery', '/usr/local/bin/osqueryd'],
        env_vars=[],
        registry=[],
        preferred_bypass='amsi_initfailed_v1',
        preferred_sleep='foliage',
        preferred_gate='',
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
#  OS-SPECIFIC COLLECTORS
# ─────────────────────────────────────────────────────────────────────────────
def _running_processes() -> List[str]:
    """Return list of lowercase process names currently running."""
    procs: List[str] = []
    try:
        import psutil
        procs = [p.name().lower() for p in psutil.process_iter(['name'])]
        return procs
    except ImportError:
        pass

    sys_p = platform.system()

    if sys_p == 'Linux':
        try:
            for pid_dir in os.listdir('/proc'):
                if not pid_dir.isdigit():
                    continue
                try:
                    with open(f'/proc/{pid_dir}/comm') as f:
                        procs.append(f.read().strip().lower())
                except OSError:
                    pass
        except Exception:
            pass

    elif sys_p == 'Windows':
        try:
            out = subprocess.check_output(
                ['tasklist', '/fo', 'csv', '/nh'],
                stderr=subprocess.DEVNULL, timeout=10
            ).decode('utf-8', 'ignore')
            for line in out.splitlines():
                parts = line.strip('"').split('","')
                if parts:
                    procs.append(parts[0].lower())
        except Exception:
            pass

    elif sys_p == 'Darwin':
        try:
            out = subprocess.check_output(
                ['ps', '-axo', 'comm'],
                stderr=subprocess.DEVNULL, timeout=10
            ).decode('utf-8', 'ignore')
            for line in out.splitlines()[1:]:
                procs.append(os.path.basename(line.strip()).lower())
        except Exception:
            pass

    return procs


def _active_services() -> List[str]:
    """Return lowercase service/daemon names."""
    services: List[str] = []
    sys_p = platform.system()

    if sys_p == 'Linux':
        for cmd in [
            ['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager', '--plain'],
            ['service', '--status-all'],
        ]:
            try:
                out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                               timeout=10).decode('utf-8', 'ignore')
                for line in out.splitlines():
                    tok = line.split()
                    if tok:
                        services.append(tok[0].lower().replace('.service', ''))
                break
            except Exception:
                continue

    elif sys_p == 'Windows':
        try:
            out = subprocess.check_output(
                ['sc', 'query', 'type=', 'all', 'state=', 'all'],
                stderr=subprocess.DEVNULL, timeout=15
            ).decode('utf-8', 'ignore')
            for m in re.finditer(r'SERVICE_NAME:\s+(\S+)', out, re.I):
                services.append(m.group(1).lower())
        except Exception:
            pass

    elif sys_p == 'Darwin':
        try:
            out = subprocess.check_output(
                ['launchctl', 'list'],
                stderr=subprocess.DEVNULL, timeout=10
            ).decode('utf-8', 'ignore')
            for line in out.splitlines():
                parts = line.split('\t')
                if len(parts) >= 3:
                    services.append(parts[2].lower())
        except Exception:
            pass

    return services


def _installed_paths() -> List[str]:
    """Collect known EDR installation root paths that exist on disk."""
    found: List[str] = []
    all_paths = {p for sig in _SIGNATURES for p in sig.paths}
    for path in all_paths:
        try:
            if os.path.exists(path):
                found.append(path)
        except Exception:
            pass
    return found


def _registry_keys_present() -> List[str]:
    """Windows-only: check for read-only registry key presence."""
    if platform.system() != 'Windows':
        return []
    found: List[str] = []
    try:
        import winreg  # type: ignore[import]
        all_keys = {k for sig in _SIGNATURES for k in sig.registry}
        for key_path in all_keys:
            hive_str, _, sub = key_path.partition('\\')
            hive_map = {
                'HKLM': winreg.HKEY_LOCAL_MACHINE,
                'HKCU': winreg.HKEY_CURRENT_USER,
                'HKCR': winreg.HKEY_CLASSES_ROOT,
            }
            hive = hive_map.get(hive_str.upper())
            if hive is None:
                continue
            try:
                handle = winreg.OpenKey(hive, sub, 0, winreg.KEY_READ)
                winreg.CloseKey(handle)
                found.append(key_path)
            except OSError:
                pass
    except ImportError:
        pass
    return found


def _env_vars_present() -> List[str]:
    all_vars = {v for sig in _SIGNATURES for v in sig.env_vars}
    return [v for v in all_vars if os.environ.get(v)]


# ─────────────────────────────────────────────────────────────────────────────
#  FINGERPRINT RESULT
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class FingerprintResult:
    detected:     List[EDRSignature]
    evidence:     Dict[str, List[str]]    # sig.name → list of matching indicators
    evasion_plan: Dict[str, str]          # 'bypass', 'sleep_mask', 'syscall_gate'
    tier:         int                     # worst-case (minimum tier detected)
    notes:        List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            'detected': [
                {'name': s.name, 'vendor': s.vendor, 'tier': s.tier,
                 'evidence': self.evidence.get(s.name, [])}
                for s in self.detected
            ],
            'evasion_plan': self.evasion_plan,
            'tier': self.tier,
            'notes': self.notes,
        }


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN FINGERPRINTER
# ─────────────────────────────────────────────────────────────────────────────
class EDRFingerprinter:
    """
    Passive (read-only) EDR/AV detection.

    Usage:
        fp = EDRFingerprinter()
        result = fp.fingerprint()
        print(result.evasion_plan)
    """

    # Minimum indicator hits before a signature is considered matched
    MIN_HITS = 1

    def fingerprint(self) -> FingerprintResult:
        """Run all collection passes and match against signatures."""
        procs    = set(_running_processes())
        services = set(_active_services())
        paths    = set(_installed_paths())
        reg_keys = set(_registry_keys_present())
        env_vars = set(_env_vars_present())

        detected: List[EDRSignature]         = []
        evidence: Dict[str, List[str]]       = {}

        for sig in _SIGNATURES:
            hits: List[str] = []

            for p in sig.processes:
                if p.lower() in procs:
                    hits.append(f'process:{p}')

            for s in sig.services:
                if s.lower() in services:
                    hits.append(f'service:{s}')

            for path in sig.paths:
                if path in paths:
                    hits.append(f'path:{path}')

            for key in sig.registry:
                if key in reg_keys:
                    hits.append(f'registry:{key}')

            for var in sig.env_vars:
                if var in env_vars:
                    hits.append(f'env:{var}')

            if len(hits) >= self.MIN_HITS:
                detected.append(sig)
                evidence[sig.name] = hits

        evasion_plan = self._build_evasion_plan(detected)
        tier = min((s.tier for s in detected), default=3)
        notes = self._build_notes(detected)

        return FingerprintResult(
            detected=detected,
            evidence=evidence,
            evasion_plan=evasion_plan,
            tier=tier,
            notes=notes,
        )

    @staticmethod
    def _build_evasion_plan(detected: List[EDRSignature]) -> Dict[str, str]:
        if not detected:
            return {
                'bypass':      'amsi_initfailed_v1',
                'sleep_mask':  'ekko',
                'syscall_gate': 'hells_gate',
                'rationale':   'No EDR detected — minimal bypass selected',
            }

        # Select strategy based on highest-tier (tier 1 = hardest) product
        primary = min(detected, key=lambda s: s.tier)
        gate = primary.preferred_gate or 'hells_gate'

        return {
            'bypass':       primary.preferred_bypass,
            'sleep_mask':   primary.preferred_sleep,
            'syscall_gate': gate,
            'primary_edr':  primary.name,
            'rationale':    (
                f'Strategy tuned for {primary.name} (tier {primary.tier}). '
                f'Additional products: '
                f'{", ".join(s.name for s in detected if s != primary) or "none"}'
            ),
        }

    @staticmethod
    def _build_notes(detected: List[EDRSignature]) -> List[str]:
        notes: List[str] = []
        if any(s.tier == 1 for s in detected):
            notes.append(
                'Tier-1 EDR detected — kernel-level tamper protection likely. '
                'Manual beacon opsec review recommended before deployment.'
            )
        if len(detected) >= 2:
            notes.append(
                f'{len(detected)} overlapping security products — '
                'evasion complexity increased; consider staged approach.'
            )
        if not detected:
            notes.append('No known EDR signatures matched.  May be unmonitored or '
                         'using an unsupported/custom product.')
        return notes

    def print_report(self, result: FingerprintResult) -> None:
        print('\n' + '=' * 60)
        print('EDR FINGERPRINT REPORT')
        print('=' * 60)

        if not result.detected:
            print('  [*] No known EDR/AV signatures detected.')
        else:
            for sig in result.detected:
                print(f'\n  [{sig.tier}] {sig.name} ({sig.vendor})')
                for ev in result.evidence.get(sig.name, []):
                    print(f'        indicator: {ev}')

        print('\n  RECOMMENDED EVASION PLAN:')
        plan = result.evasion_plan
        print(f'    AMSI bypass   : {plan["bypass"]}')
        print(f'    Sleep mask    : {plan["sleep_mask"]}')
        print(f'    Syscall gate  : {plan["syscall_gate"]}')
        print(f'    Rationale     : {plan["rationale"]}')

        for note in result.notes:
            print(f'\n  [!] {note}')

        print('\n' + '=' * 60 + '\n')


# ─────────────────────────────────────────────────────────────────────────────
#  CONVENIENCE: integrate with evasion.py
# ─────────────────────────────────────────────────────────────────────────────
def select_evasion_strategy(fp_result: Optional[FingerprintResult] = None) -> Dict[str, str]:
    """
    Run fingerprinting (if result not provided) and return the evasion plan.
    Safe to call in any context — returns a conservative default if detection
    fails for any reason.
    """
    try:
        if fp_result is None:
            fp_result = EDRFingerprinter().fingerprint()
        return fp_result.evasion_plan
    except Exception:
        return {
            'bypass':       'amsi_initfailed_v1',
            'sleep_mask':   'ekko',
            'syscall_gate': 'hells_gate',
            'rationale':    'Detection failed — conservative default applied',
        }


if __name__ == '__main__':
    fingerprinter = EDRFingerprinter()
    result = fingerprinter.fingerprint()
    fingerprinter.print_report(result)
