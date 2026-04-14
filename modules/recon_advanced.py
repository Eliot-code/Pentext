#!/usr/bin/env python3
"""
AutoPentestX - Advanced Reconnaissance & OSINT Module
Red Team Intelligence Gathering: DNS, WHOIS, subdomain enum,
WAF detection, SSL cert analysis, ASN/CDN fingerprinting
"""

import socket
import subprocess
import re
import json
import ssl
import ipaddress
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse


# ─────────────────────────────────────────────────────────────
#  COLOUR HELPERS
# ─────────────────────────────────────────────────────────────
R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'
C = '\033[96m'; M = '\033[95m'; B = '\033[1m'; X = '\033[0m'


class AdvancedRecon:
    """
    Comprehensive passive + active OSINT and reconnaissance module.
    Performs DNS enumeration, WHOIS, subdomain brute-force, WAF detection,
    SSL/TLS audit, ASN lookup, CDN fingerprinting, and technology detection.
    """

    # ── Subdomain wordlist (top 150 common names) ───────────────
    SUBDOMAIN_WORDLIST = [
        'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
        'smtp', 'secure', 'vpn', 'mx', 'ftp', 'imap', 'pop', 'api', 'dev',
        'staging', 'test', 'portal', 'admin', 'web', 'mx1', 'mx2', 'cdn',
        'app', 'apps', 'mobile', 'static', 'media', 'images', 'img', 'files',
        'download', 'downloads', 'upload', 'uploads', 'support', 'help',
        'docs', 'documentation', 'wiki', 'kb', 'forum', 'forums', 'community',
        'news', 'blog', 'shop', 'store', 'payment', 'pay', 'checkout', 'cart',
        'auth', 'login', 'sso', 'oauth', 'api2', 'v1', 'v2', 'v3', 'beta',
        'alpha', 'old', 'new', 'backup', 'bak', 'legacy', 'archive', 'git',
        'svn', 'ci', 'jenkins', 'gitlab', 'github', 'jira', 'confluence',
        'monitor', 'monitoring', 'metrics', 'grafana', 'kibana', 'elastic',
        'search', 'db', 'database', 'mysql', 'redis', 'mongo', 'postgresql',
        'internal', 'intranet', 'corp', 'corporate', 'office', 'manage',
        'management', 'panel', 'cpanel', 'whm', 'plesk', 'webmin', 'phpmyadmin',
        'owa', 'exchange', 'autodiscover', 'autoconfig', 'calendar', 'webdav',
        'dav', 'aws', 'azure', 'gcp', 'cloud', 'proxy', 'gateway', 'firewall',
        'vpn2', 'remote2', 'access', 'connect', 'rdp', 'ssh', 'terminal',
        'pma', 'phppgadmin', 'adminer', 'sqlweb', 'sqladmin', 'pgadmin',
        'status', 'uptime', 'health', 'ping', 'stats', 'analytics', 'tracking',
        'push', 'notifications', 'ws', 'websocket', 'socket', 'stream', 'live',
        'demo', 'sandbox', 'lab', 'labs', 'research', 'secure2', 'ns3', 'ns4',
    ]

    # ── Known CDN/WAF fingerprints ────────────────────────────
    WAF_SIGNATURES = {
        'Cloudflare':    ['cf-ray', 'cloudflare', '__cfduid', 'cf-cache-status'],
        'AWS WAF':       ['awswaf', 'x-amzn-requestid', 'x-amz-cf-id'],
        'Akamai':        ['akamai', 'x-check-cacheable', 'x-akamai-transformed'],
        'Fastly':        ['fastly', 'x-fastly-request-id', 'x-served-by'],
        'Imperva/Incapsula': ['incap_ses', 'visid_incap', 'x-cdn', 'x-iinfo'],
        'F5 BIG-IP':     ['bigipserver', 'ts', 'f5', 'x-wa-info'],
        'Sucuri':        ['x-sucuri-id', 'x-sucuri-cache', 'sucuri'],
        'ModSecurity':   ['mod_security', 'modsecurity', 'x-modsecurity'],
        'Barracuda':     ['barra_counter_session', 'barracuda'],
        'Fortinet':      ['fortigate', 'fortigatefw', 'x-fortigate'],
    }

    # ── Technology fingerprints (headers/body patterns) ───────
    TECH_SIGNATURES = {
        'WordPress':    ['wp-content', 'wp-includes', 'wp-json', 'wordpress'],
        'Joomla':       ['joomla', '/components/com_', '/modules/mod_'],
        'Drupal':       ['drupal', 'sites/default', 'x-drupal-cache'],
        'PHP':          ['x-powered-by: php', '.php'],
        'ASP.NET':      ['x-aspnet-version', 'x-powered-by: asp.net', 'aspnetcore'],
        'Node.js':      ['x-powered-by: express', 'node.js'],
        'Django':       ['django', 'csrfmiddlewaretoken'],
        'Laravel':      ['laravel_session', 'x-powered-by: php', 'laravel'],
        'Ruby on Rails':['x-powered-by: phusion', 'x-request-id', '_session_id'],
        'Nginx':        ['server: nginx'],
        'Apache':       ['server: apache'],
        'IIS':          ['server: iis', 'x-powered-by: asp.net'],
        'Tomcat':       ['server: apache-coyote', 'jsessionid'],
        'Spring':       ['x-application-context', 'spring'],
        'jQuery':       ['jquery'],
        'React':        ['__react', 'react-dom', 'data-reactroot'],
        'Angular':      ['ng-version', 'angular'],
        'Vue.js':       ['__vue__', 'vue.js', 'data-v-'],
    }

    def __init__(self, target: str):
        self.target = target
        self.domain = self._extract_domain(target)
        self.ip = None
        self.results = {
            'target': target,
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'dns': {},
            'whois': {},
            'subdomains': [],
            'ssl_info': {},
            'waf_detected': [],
            'cdn_info': {},
            'technologies': [],
            'asn_info': {},
            'open_redirects': [],
            'email_security': {},
            'geolocation': {},
            'reverse_dns': {},
            'network_ranges': [],
        }

    # ─────────────────────────────────────────────────────────
    #  HELPERS
    # ─────────────────────────────────────────────────────────
    def _extract_domain(self, target: str) -> str:
        if target.startswith(('http://', 'https://')):
            return urlparse(target).hostname or target
        return target.split('/')[0]

    def _print(self, level: str, msg: str):
        icons = {'info': f'{C}[*]{X}', 'ok': f'{G}[✓]{X}',
                 'warn': f'{Y}[!]{X}', 'err': f'{R}[✗]{X}',
                 'find': f'{M}[+]{X}'}
        print(f"  {icons.get(level, '[?]')} {msg}")

    # ─────────────────────────────────────────────────────────
    #  1. DNS ENUMERATION
    # ─────────────────────────────────────────────────────────
    def enumerate_dns(self) -> dict:
        self._print('info', f'Enumerating DNS records for {B}{self.domain}{X}')
        dns_data = {'A': [], 'AAAA': [], 'MX': [], 'NS': [], 'TXT': [],
                    'CNAME': [], 'SOA': [], 'PTR': []}

        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        for rtype in record_types:
            try:
                result = subprocess.run(
                    ['dig', '+short', rtype, self.domain],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0 and result.stdout.strip():
                    records = [r.strip() for r in result.stdout.strip().split('\n') if r.strip()]
                    dns_data[rtype] = records
                    for rec in records:
                        self._print('find', f'DNS {rtype}: {Y}{rec}{X}')
            except Exception:
                pass

        # Resolve primary IP
        try:
            self.ip = socket.gethostbyname(self.domain)
            dns_data['resolved_ip'] = self.ip
            self._print('ok', f'Resolved IP: {G}{self.ip}{X}')
        except Exception:
            self._print('warn', 'Could not resolve hostname to IP')

        # Zone transfer attempt (AXFR)
        for ns in dns_data.get('NS', [])[:3]:
            ns = ns.rstrip('.')
            try:
                result = subprocess.run(
                    ['dig', 'AXFR', self.domain, f'@{ns}'],
                    capture_output=True, text=True, timeout=15
                )
                if 'Transfer failed' not in result.stdout and len(result.stdout) > 200:
                    dns_data['zone_transfer'] = {
                        'ns': ns,
                        'data': result.stdout[:2000],
                        'vulnerable': True
                    }
                    self._print('find', f'{R}ZONE TRANSFER VULNERABLE{X} via NS {ns}!')
                    break
            except Exception:
                pass

        self.results['dns'] = dns_data
        return dns_data

    # ─────────────────────────────────────────────────────────
    #  2. WHOIS LOOKUP
    # ─────────────────────────────────────────────────────────
    def whois_lookup(self) -> dict:
        self._print('info', f'WHOIS lookup for {self.domain}')
        whois_data = {}
        try:
            result = subprocess.run(
                ['whois', self.domain],
                capture_output=True, text=True, timeout=20
            )
            if result.returncode == 0:
                raw = result.stdout
                # Parse key fields
                patterns = {
                    'registrar':        r'Registrar:\s*(.+)',
                    'creation_date':    r'Creation Date:\s*(.+)',
                    'expiration_date':  r'Registry Expiry Date:\s*(.+)',
                    'updated_date':     r'Updated Date:\s*(.+)',
                    'name_servers':     r'Name Server:\s*(.+)',
                    'status':           r'Domain Status:\s*(.+)',
                    'registrant_org':   r'Registrant Organization:\s*(.+)',
                    'registrant_country': r'Registrant Country:\s*(.+)',
                    'admin_email':      r'Admin Email:\s*(.+)',
                    'tech_email':       r'Tech Email:\s*(.+)',
                }
                for field, pattern in patterns.items():
                    matches = re.findall(pattern, raw, re.IGNORECASE)
                    if matches:
                        whois_data[field] = matches[0].strip() if len(matches) == 1 else [m.strip() for m in matches[:5]]
                        self._print('find', f'WHOIS {field}: {Y}{whois_data[field]}{X}')

                whois_data['raw_truncated'] = raw[:1500]
        except Exception as e:
            self._print('warn', f'WHOIS failed: {e}')

        self.results['whois'] = whois_data
        return whois_data

    # ─────────────────────────────────────────────────────────
    #  3. SUBDOMAIN ENUMERATION (DNS brute-force)
    # ─────────────────────────────────────────────────────────
    def enumerate_subdomains(self, wordlist: list = None, threads: int = 50) -> list:
        self._print('info', f'Brute-forcing subdomains for {B}{self.domain}{X} ({len(self.SUBDOMAIN_WORDLIST)} candidates)')
        words = wordlist or self.SUBDOMAIN_WORDLIST
        found = []

        def resolve_sub(sub):
            fqdn = f'{sub}.{self.domain}'
            try:
                answers = socket.getaddrinfo(fqdn, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                ips = list({a[4][0] for a in answers})
                return {'subdomain': fqdn, 'ips': ips, 'status': 'RESOLVED'}
            except socket.gaierror:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(resolve_sub, w): w for w in words}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    self._print('find', f'Subdomain: {G}{result["subdomain"]}{X} → {result["ips"]}')

        # Also try certificate transparency via crt.sh (no API key needed)
        found += self._ct_log_subdomains()

        # Deduplicate
        seen = set()
        unique = []
        for sub in found:
            if sub['subdomain'] not in seen:
                seen.add(sub['subdomain'])
                unique.append(sub)

        self._print('ok', f'Found {G}{len(unique)}{X} unique subdomains')
        self.results['subdomains'] = unique
        return unique

    def _ct_log_subdomains(self) -> list:
        """Query crt.sh certificate transparency log."""
        self._print('info', 'Querying Certificate Transparency logs (crt.sh)...')
        found = []
        try:
            import urllib.request
            url = f'https://crt.sh/?q=%.{self.domain}&output=json'
            req = urllib.request.Request(url, headers={'User-Agent': 'AutoPentestX/2.0'})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
            names = set()
            for entry in data:
                for n in entry.get('name_value', '').split('\n'):
                    n = n.strip().lstrip('*.')
                    if n.endswith(self.domain) and n not in names:
                        names.add(n)
                        found.append({'subdomain': n, 'ips': [], 'source': 'crt.sh'})
            self._print('find', f'crt.sh returned {M}{len(found)}{X} certificate entries')
        except Exception as e:
            self._print('warn', f'crt.sh query failed: {e}')
        return found

    # ─────────────────────────────────────────────────────────
    #  4. SSL/TLS CERTIFICATE ANALYSIS
    # ─────────────────────────────────────────────────────────
    def analyze_ssl(self, port: int = 443) -> dict:
        self._print('info', f'Analyzing SSL/TLS certificate on {self.domain}:{port}')
        ssl_data = {}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with ssl.SSLSocket(
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
                _context=ctx
            ) as ssock:
                ssock.settimeout(10)
                ssock.connect((self.domain, port))
                ssock.do_handshake()

                cert = ssock.getpeercert(binary_form=False)
                cipher = ssock.cipher()
                protocol = ssock.version()

                ssl_data = {
                    'protocol':    protocol,
                    'cipher_suite': cipher[0] if cipher else 'unknown',
                    'cipher_bits':  cipher[2] if cipher else 0,
                    'subject':      dict(x[0] for x in cert.get('subject', [])) if cert else {},
                    'issuer':       dict(x[0] for x in cert.get('issuer', [])) if cert else {},
                    'valid_from':   cert.get('notBefore', '') if cert else '',
                    'valid_until':  cert.get('notAfter', '') if cert else '',
                    'san':          cert.get('subjectAltName', []) if cert else [],
                    'serial':       cert.get('serialNumber', '') if cert else '',
                }

                # Vulnerability checks
                weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
                weak_ciphers = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon']

                ssl_data['weak_protocol'] = protocol in weak_protocols
                ssl_data['weak_cipher'] = any(w in (ssl_data['cipher_suite'] or '') for w in weak_ciphers)
                ssl_data['self_signed'] = (ssl_data['subject'] == ssl_data['issuer'])

                level = R if ssl_data['weak_protocol'] or ssl_data['weak_cipher'] else G
                self._print('find', f'Protocol: {level}{protocol}{X}  Cipher: {cipher[0] if cipher else "?"} ({cipher[2] if cipher else 0} bits)')
                self._print('find', f'Issuer: {ssl_data["issuer"].get("organizationName", "?")}')

                # Extract SANs (valuable for recon)
                for san_type, san_val in ssl_data['san'][:20]:
                    self._print('find', f'SAN {san_type}: {Y}{san_val}{X}')

        except ConnectionRefusedError:
            self._print('warn', f'SSL port {port} closed')
        except Exception as e:
            self._print('warn', f'SSL analysis failed: {e}')

        self.results['ssl_info'] = ssl_data
        return ssl_data

    # ─────────────────────────────────────────────────────────
    #  5. WAF / CDN DETECTION
    # ─────────────────────────────────────────────────────────
    def detect_waf_cdn(self) -> dict:
        self._print('info', 'Detecting WAF / CDN presence...')
        detected = []
        headers_raw = ''

        try:
            import urllib.request
            urls_to_probe = [
                f'http://{self.domain}/',
                f'http://{self.domain}/?q=<script>alert(1)</script>',
                f'http://{self.domain}/?id=1+UNION+SELECT+1,2,3--',
            ]
            for url in urls_to_probe[:2]:
                try:
                    req = urllib.request.Request(url, headers={
                        'User-Agent': 'AutoPentestX/2.0 (Security Assessment)',
                        'Accept': 'text/html,application/xhtml+xml'
                    })
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        headers_raw += str(resp.headers).lower()
                except Exception:
                    pass

            for waf_name, signatures in self.WAF_SIGNATURES.items():
                if any(sig in headers_raw for sig in signatures):
                    detected.append(waf_name)
                    self._print('find', f'{R}WAF/CDN detected:{X} {M}{waf_name}{X}')

            if not detected:
                self._print('info', 'No known WAF/CDN fingerprint detected')

        except Exception as e:
            self._print('warn', f'WAF detection error: {e}')

        self.results['waf_detected'] = detected
        return {'waf_cdn': detected, 'headers_sample': headers_raw[:500]}

    # ─────────────────────────────────────────────────────────
    #  6. TECHNOLOGY FINGERPRINTING
    # ─────────────────────────────────────────────────────────
    def fingerprint_technologies(self) -> list:
        self._print('info', 'Fingerprinting web technologies...')
        found_techs = []

        try:
            import urllib.request
            req = urllib.request.Request(
                f'http://{self.domain}/',
                headers={'User-Agent': 'Mozilla/5.0 (AutoPentestX/2.0)'}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                headers_str = str(resp.headers).lower()
                body = resp.read(8192).decode('utf-8', errors='ignore').lower()

            content = headers_str + body
            for tech, patterns in self.TECH_SIGNATURES.items():
                if any(p.lower() in content for p in patterns):
                    found_techs.append(tech)
                    self._print('find', f'Technology: {G}{tech}{X}')

        except Exception as e:
            self._print('warn', f'Technology fingerprinting failed: {e}')

        self.results['technologies'] = found_techs
        return found_techs

    # ─────────────────────────────────────────────────────────
    #  7. EMAIL SECURITY (SPF / DKIM / DMARC)
    # ─────────────────────────────────────────────────────────
    def check_email_security(self) -> dict:
        self._print('info', 'Checking email security configuration (SPF/DKIM/DMARC)...')
        email_sec = {'spf': None, 'dmarc': None, 'dkim': None}

        def dig_txt(name):
            try:
                r = subprocess.run(['dig', '+short', 'TXT', name],
                                   capture_output=True, text=True, timeout=8)
                return r.stdout.strip() if r.returncode == 0 else ''
            except Exception:
                return ''

        # SPF
        spf_raw = dig_txt(self.domain)
        if 'v=spf1' in spf_raw.lower():
            email_sec['spf'] = {'record': spf_raw[:300], 'present': True,
                                'all_policy': '+all' in spf_raw.lower()}
            flag = f'{R}+all (DANGEROUS){X}' if '+all' in spf_raw.lower() else f'{G}OK{X}'
            self._print('find', f'SPF: Present  {flag}')
        else:
            email_sec['spf'] = {'present': False}
            self._print('find', f'{R}SPF: MISSING — email spoofing possible{X}')

        # DMARC
        dmarc_raw = dig_txt(f'_dmarc.{self.domain}')
        if 'v=dmarc1' in dmarc_raw.lower():
            email_sec['dmarc'] = {'record': dmarc_raw[:300], 'present': True}
            self._print('find', f'DMARC: {G}Present{X}')
        else:
            email_sec['dmarc'] = {'present': False}
            self._print('find', f'{R}DMARC: MISSING — phishing domain easily spoofable{X}')

        # DKIM (default selector)
        for selector in ['default', 'google', 'dkim', 'mail', 'k1']:
            dkim_raw = dig_txt(f'{selector}._domainkey.{self.domain}')
            if 'v=dkim1' in dkim_raw.lower():
                email_sec['dkim'] = {'selector': selector, 'present': True,
                                     'record': dkim_raw[:300]}
                self._print('find', f'DKIM: {G}Present{X} (selector: {selector})')
                break
        else:
            email_sec['dkim'] = {'present': False}
            self._print('find', f'{Y}DKIM: Not found with common selectors{X}')

        self.results['email_security'] = email_sec
        return email_sec

    # ─────────────────────────────────────────────────────────
    #  8. REVERSE DNS & ASN LOOKUP
    # ─────────────────────────────────────────────────────────
    def asn_lookup(self) -> dict:
        self._print('info', 'Querying ASN / BGP information...')
        asn_data = {}
        ip = self.ip or (socket.gethostbyname(self.domain) if self.domain else None)
        if not ip:
            return asn_data
        try:
            # Use WHOIS to CYMRU (Team Cymru IP-to-ASN)
            result = subprocess.run(
                ['whois', '-h', 'whois.cymru.com', f' -v {ip}'],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
                if len(lines) >= 2:
                    parts = [p.strip() for p in lines[-1].split('|')]
                    if len(parts) >= 5:
                        asn_data = {
                            'ip': ip,
                            'asn': parts[0],
                            'bgp_prefix': parts[2],
                            'country': parts[3],
                            'organization': parts[4],
                        }
                        self._print('find', f'ASN: {Y}{asn_data.get("asn")}{X}  Org: {asn_data.get("organization")}')
                        self._print('find', f'BGP Prefix: {Y}{asn_data.get("bgp_prefix")}{X}  Country: {asn_data.get("country")}')
        except Exception as e:
            self._print('warn', f'ASN lookup failed: {e}')

        # Reverse DNS
        try:
            rdns = socket.gethostbyaddr(ip)
            self.results['reverse_dns'] = {'ip': ip, 'hostname': rdns[0]}
            self._print('find', f'Reverse DNS: {G}{ip}{X} → {rdns[0]}')
        except Exception:
            pass

        self.results['asn_info'] = asn_data
        return asn_data

    # ─────────────────────────────────────────────────────────
    #  9. GOOGLE DORK TEMPLATES (passive recon aids)
    # ─────────────────────────────────────────────────────────
    def generate_dork_queries(self) -> list:
        d = self.domain
        dorks = [
            f'site:{d}',
            f'site:{d} filetype:pdf',
            f'site:{d} filetype:xls OR filetype:xlsx OR filetype:csv',
            f'site:{d} filetype:doc OR filetype:docx',
            f'site:{d} inurl:admin OR inurl:login OR inurl:panel',
            f'site:{d} inurl:config OR inurl:conf OR inurl:setup',
            f'site:{d} intext:"internal use only" OR intext:"confidential"',
            f'site:{d} inurl:api OR inurl:swagger OR inurl:graphql',
            f'site:{d} inurl:.git OR inurl:.env OR inurl:.bak',
            f'site:{d} inurl:phpinfo OR inurl:server-status OR inurl:server-info',
            f'site:{d} ext:sql OR ext:db OR ext:dump',
            f'"{d}" password OR passwd OR credentials filetype:txt',
            f'"{d}" site:pastebin.com OR site:paste.ee OR site:ghostbin.com',
            f'"{d}" site:github.com OR site:gitlab.com',
            f'intitle:"index of" site:{d}',
            f'site:{d} "error" OR "exception" OR "stack trace"',
            f'site:{d} -www',
        ]
        self._print('info', f'Generated {len(dorks)} Google dork queries')
        for dork in dorks:
            self._print('find', f'{C}{dork}{X}')
        self.results['google_dorks'] = dorks
        return dorks

    # ─────────────────────────────────────────────────────────
    #  MAIN ORCHESTRATION
    # ─────────────────────────────────────────────────────────
    def run_full_recon(self, subdomain_enum: bool = True) -> dict:
        print(f'\n{C}╔══════════════════════════════════════════════════════════╗{X}')
        print(f'{C}║{X} {B}{M}[ADVANCED RECON]{X} Target: {Y}{self.target}{X}')
        print(f'{C}╚══════════════════════════════════════════════════════════╝{X}\n')

        self.enumerate_dns()
        self.whois_lookup()

        if subdomain_enum:
            self.enumerate_subdomains()

        self.analyze_ssl()
        self.detect_waf_cdn()
        self.fingerprint_technologies()
        self.check_email_security()
        self.asn_lookup()
        self.generate_dork_queries()

        self.results['recon_complete'] = True
        self.results['completed_at'] = datetime.now().isoformat()

        total_subdomains = len(self.results.get('subdomains', []))
        print(f'\n{G}[✓]{X} Advanced recon complete — '
              f'{total_subdomains} subdomains | '
              f'{len(self.results.get("technologies", []))} technologies | '
              f'{len(self.results.get("waf_detected", []))} WAF/CDN fingerprints')

        return self.results
