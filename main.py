#!/usr/bin/env python3
"""
AutoPentestX v2.0 - Main Application
Advanced Red Team & Penetration Testing Toolkit
Complete orchestration of all modules including:
  • Advanced OSINT & Reconnaissance
  • Web Application Attack Framework
  • Active Directory Attack Suite
  • Post-Exploitation Framework
  • Payload Generator with Evasion
"""

import sys
import os
import argparse
import time
from datetime import datetime
import json

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.database import Database
from modules.scanner import Scanner
from modules.vuln_scanner import VulnerabilityScanner
from modules.cve_lookup import CVELookup
from modules.risk_engine import RiskEngine
from modules.exploit_engine import ExploitEngine
from modules.pdf_report import PDFReportGenerator

from modules.recon_advanced import AdvancedRecon
from modules.web_attacks import WebAttackFramework
from modules.payload_gen import PayloadGenerator
from modules.ad_attacks import ADAttackSuite
from modules.post_exploit import PostExploitFramework
from modules.evasion import EvasionEngine

from modules.native_scanner import NativeAssessor
from modules.polymorphic_engine import PolymorphicEngine
from modules.threat_intel import ThreatIntelligence
from modules.heuristic_engine import HeuristicEngine
from modules.edr_fingerprint import EDRFingerprinter, select_evasion_strategy


class AutoPentestX:
    """Main AutoPentestX v2.0 — Advanced Red Team Framework"""

    def __init__(self, target, tester_name="AutoPentestX Team", safe_mode=True,
                 skip_web=False, skip_exploit=False,
                 lhost=None, lport=4444,
                 domain=None, dc_ip=None,
                 ad_user=None, ad_pass=None,
                 skip_recon=False, skip_ad=False,
                 skip_payload=False, skip_post=False, skip_evasion=False,
                 native_scan=False, threat_intel=False, poly_payloads=False,
                 edr_fp=False, webshell_password=None,
                 osint=False, plugins=False, plugin_dir='plugins'):
        self.target = target
        self.tester_name = tester_name
        self.safe_mode = safe_mode
        self.skip_web = skip_web
        self.skip_exploit = skip_exploit
        self.lhost = lhost or self._get_local_ip()
        self.lport = lport
        self.domain = domain
        self.dc_ip = dc_ip or target
        self.ad_user = ad_user
        self.ad_pass = ad_pass
        self.skip_recon = skip_recon
        self.skip_ad = skip_ad
        self.skip_payload = skip_payload
        self.skip_post = skip_post
        self.skip_evasion = skip_evasion
        self.native_scan = native_scan
        self.threat_intel = threat_intel
        self.poly_payloads = poly_payloads
        self.edr_fp = edr_fp
        self.webshell_password = webshell_password
        self.osint = osint
        self.plugins = plugins
        self.plugin_dir = plugin_dir
        self.scan_id = None
        self.start_time = None
        self.end_time = None
        self.scan_results = None
        self.vuln_results = None
        self.cve_results = None
        self.risk_results = None
        self.exploit_results = None
        self.recon_results = None
        self.web_attack_results = None
        self.ad_results = None
        self.post_exploit_results = None
        self.payload_results = None
        self.evasion_results = None
        self.native_scan_results = None
        self.threat_intel_results = None
        self.poly_results = None
        self.edr_fp_results = None
        self.heuristic_results = None
        self.osint_results = None
        self.plugin_results = None
        self.db = Database()

    def _get_local_ip(self) -> str:
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '0.0.0.0'

    def display_banner(self):
        RED = '\033[91m'
        GREEN = '\033[92m'
        CYAN = '\033[96m'
        YELLOW = '\033[93m'
        MAGENTA = '\033[95m'
        BOLD = '\033[1m'
        RESET = '\033[0m'

        art_lines = [
            "█████╗ ██╗   ██╗███████╗██████╗ ██████╗ ██████╗ ██████╗ ███╗   ██╗",
            "██╔══██╗██║   ██║╔══██╔══╝██╔══██╗██╔═══██╗██╔══██╗████╗  ██║",
            "███████║██║   ██║   ██║   ██║   ██║██████╔╝██████╔╝██╔██╗ ██║",
            "██╔══██║██║   ██║   ██║   ██║   ██║██╔═══╝ ██╔══██╗██║╚██╗██║",
            "██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║     ███████║██║ ╚████║",
            "╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝",
        ]

        subtitle_lines = [
            "PENETRATION TESTING FRAMEWORK",
            "[CODENAME: D A R K S E I D]",
            "Author: Eliot-code",
        ]

        content_lines = art_lines + subtitle_lines
        inner_width = max(len(line) for line in content_lines) + 4

        top = f"{RED}{BOLD}╔" + "═" * inner_width + f"╗{RESET}"
        bot = f"{RED}{BOLD}╚" + "═" * inner_width + f"╝{RESET}"

        print(top)
        print(f"{RED}{BOLD}║{RESET}" + " " * (inner_width) + f"{RED}{BOLD}║{RESET}")

        for l in art_lines:
            print(f"{RED}{BOLD}║{RESET}  {l.center(inner_width-4)}  {RED}{BOLD}║{RESET}")

        print(f"{RED}{BOLD}║{RESET}" + " " * (inner_width) + f"{RED}{BOLD}║{RESET}")

        for l in subtitle_lines:
            color = GREEN if 'PENETRATION' in l else YELLOW if 'CODENAME' in l else MAGENTA
            print(f"{RED}{BOLD}║{RESET}  {color}{l.center(inner_width-4)}{RESET}  {RED}{BOLD}║{RESET}")

        print(f"{RED}{BOLD}║{RESET}" + " " * (inner_width) + f"{RED}{BOLD}║{RESET}")
        print(f"{RED}{BOLD}║{RESET}  {YELLOW}⚠️  [CLASSIFIED] FOR AUTHORIZED OPS & TRAINING ONLY ⚠️{RESET}" + " " * max(0, inner_width - 56) + f"{RED}{BOLD}║{RESET}")
        print(bot)

        status_width = inner_width
        print(f"{CYAN}┌" + "─" * status_width + f"┐{RESET}")
        print(f"{CYAN}│{RESET} {BOLD}[SYSTEM STATUS]{RESET}" + " " * (status_width - 14) + f"{CYAN}│{RESET}")
        print(f"{CYAN}│{RESET} ├─ Exploit Engine  : {GREEN}ONLINE{RESET}" + " " * (status_width - 36) + f"{CYAN}│{RESET}")
        print(f"{CYAN}│{RESET} ├─ Scanner Array   : {GREEN}ONLINE{RESET}" + " " * (status_width - 36) + f"{CYAN}│{RESET}")
        print(f"{CYAN}│{RESET} ├─ Threat Intel    : {GREEN}LIVE{RESET}" + " " * (status_width - 36) + f"{CYAN}│{RESET}")
        print(f"{CYAN}│{RESET} ├─ Polymorphic Eng : {GREEN}ACTIVE{RESET}" + " " * (status_width - 36) + f"{CYAN}│{RESET}")
        print(f"{CYAN}│{RESET} └─ Heuristic Engine: {GREEN}FUSED [Bayesian+Anomaly]{RESET}" + " " * (status_width - 51) + f"{CYAN}│{RESET}")
        print(f"{CYAN}└" + "─" * status_width + f"┘{RESET}")

    def run_full_assessment(self):
        self.start_time = time.time()

        try:
            self.display_banner()

            CYAN = '\033[96m'
            GREEN = '\033[92m'
            RED = '\033[91m'
            YELLOW = '\033[93m'
            BOLD = '\033[1m'
            RESET = '\033[0m'

            print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
            print(f"{CYAN}║{RESET} {BOLD}{YELLOW}[PHASE 1]{RESET} {GREEN}►{RESET} Initializing attack sequence...                    {CYAN}║{RESET}")
            print(f"{CYAN}╚{'═'*66}╝{RESET}")
            self.scan_id = self.db.insert_scan(self.target)
            if not self.scan_id:
                print(f"{RED}[✗] CRITICAL ERROR: Database initialization failed{RESET}")
                return False
            print(f"{GREEN}[✓]{RESET} Mission ID: {YELLOW}{self.scan_id}{RESET} | Status: {GREEN}ACTIVE{RESET}")

            print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
            print(f"{CYAN}║{RESET} {BOLD}{YELLOW}[PHASE 2]{RESET} {GREEN}►{RESET} Network reconnaissance in progress...             {CYAN}║{RESET}")
            print(f"{CYAN}╚{'═'*66}╝{RESET}")
            scanner = Scanner(self.target)
            self.scan_results = scanner.run_full_scan()
            if not self.scan_results:
                print(f"{RED}[✗] ABORT: Network reconnaissance failed{RESET}")
                return False
            print(f"{GREEN}[✓]{RESET} Phase 2 complete - {GREEN}{len(self.scan_results.get('ports', []))}{RESET} ports discovered")
            self.db.update_scan(self.scan_id,
                              os_detection=self.scan_results.get('os_detection', 'Unknown'))
            for port in self.scan_results.get('ports', []):
                self.db.insert_port(self.scan_id, port)

            # PHASE 2.4: Native Scanner
            if self.native_scan:
                print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
                print(f"{CYAN}║{RESET} {BOLD}{YELLOW}[PHASE 2.4]{RESET} {GREEN}►{RESET} Native Port/Service Scanner (no-root)...  {CYAN}║{RESET}")
                print(f"{CYAN}╚{'═'*66}╝{RESET}")
                native = NativeAssessor(self.target)
                self.native_scan_results = native.assess()
                ns_ports = len(self.native_scan_results.get('open_ports', []))
                ns_vulns = len(self.native_scan_results.get('kb_matches', []))
                print(f"{GREEN}[✓]{RESET} Native scan: {GREEN}{ns_ports}{RESET} ports | {RED}{ns_vulns}{RESET} KB vulnerability matches")

            # PHASE 2.5: Advanced Recon
            if not self.skip_recon:
                print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
                print(f"{CYAN}║{RESET} {BOLD}{YELLOW}[PHASE 2.5]{RESET} {GREEN}►{RESET} Advanced OSINT & Reconnaissance...         {CYAN}║{RESET}")
                print(f"{CYAN}╚{'═'*66}╝{RESET}")
                recon = AdvancedRecon(self.target)
                self.recon_results = recon.run_full_recon(subdomain_enum=True)
                sub_count = len(self.recon_results.get('subdomains', []))
                tech_count = len(self.recon_results.get('technologies', []))
                print(f"{GREEN}[✓]{RESET} Recon complete — {GREEN}{sub_count}{RESET} subdomains | {GREEN}{tech_count}{RESET} technologies")
            else:
                print(f"\n{YELLOW}[PHASE 2.5]{RESET} Advanced Recon... {YELLOW}[SKIPPED]{RESET}")
                self.recon_results = {}

            # PHASE 2.6: OSINT Enrichment
            if self.osint:
                print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
                print(f"{CYAN}║{RESET} {BOLD}{YELLOW}[PHASE 2.6]{RESET} {GREEN}►{RESET} OSINT Enrichment (Shodan/Censys/URLScan)...{CYAN}║{RESET}")
                print(f"{CYAN}╚{'═'*66}╝{RESET}")
                try:
                    from modules.osint_integration import OSINTIntegration
                    osint = OSINTIntegration()
                    self.osint_results = osint.enrich_target(self.target)
                    osint.print_report(self.osint_results)
                    ports_found = len(self.osint_results.get('summary', {}).get('open_ports', []))
                    print(f"{GREEN}[✓]{RESET} OSINT: {YELLOW}{ports_found}{RESET} exposed ports | "
                          f"scanner={self.osint_results.get('summary',{}).get('is_scanner',False)}")
                except ImportError:
                    print(f"{YELLOW}[!]{RESET} osint_integration module not found — skipping")
                    self.osint_results = {}

            # PHASE 3: Vulnerability Scanning
            if not self.skip_web:
                print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
                print(f"{CYAN}║{RESET} {BOLD}{YELLOW}[PHASE 3]{RESET} {GREEN}►{RESET} Vulnerability analysis initiated...                {CYAN}║{RESET}")
                print(f"{CYAN}╚{'═'*66}╝{RESET}")
                vuln_scanner = VulnerabilityScanner(
                    self.target, self.scan_results.get('ports', []))
                self.vuln_results = vuln_scanner.run_full_scan()
                for vuln in self.vuln_results.get('vulnerabilities', []):
                    self.db.insert_vulnerability(self.scan_id, vuln)
                for web_vuln in self.vuln_results.get('web_vulnerabilities', []):
                    self.db.insert_web_vulnerability(self.scan_id, web_vuln)
            else:
                print(f"\n{YELLOW}[PHASE 3]{RESET} Vulnerability analysis... {YELLOW}[SKIPPED]{RESET}")
                self.vuln_results = {'vulnerabilities': [], 'web_vulnerabilities': [], 'sql_vulnerabilities': []}

            # PHASE 4: CVE Lookup
            print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
            print(f"{CYAN}║{RESET} {BOLD}{YELLOW}[PHASE 4]{RESET} {GREEN}►{RESET} Accessing CVE intelligence database...           {CYAN}║{RESET}")
            print(f"{CYAN}╚{'═'*66}╝{RESET}")
            cve_lookup = CVELookup()
            services = self.scan_results.get('services', [])
            self.cve_results = cve_lookup.lookup_services(services)
            for cve in self.cve_results:
                vuln_data = {
                    'port': cve.get('port'), 'service': cve.get('service'),
                    'name': cve.get('cve_id'), 'description': cve.get('description'),
                    'cve_id': cve.get('cve_id'), 'cvss_score': cve.get('cvss_score'),
                    'risk_level': cve.get('risk_level'), 'exploitable': cve.get('exploitable', False)
                }
                self.db.insert_vulnerability(self.scan_id, vuln_data)

            # PHASE 4.5: Threat Intelligence
            if self.threat_intel:
                print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
                print(f"{CYAN}║{RESET} {BOLD}{YELLOW}[PHASE 4.5]{RESET} {GREEN}►{RESET} Threat Intelligence (NVD/KEV/EPSS/ATT&CK)... {CYAN}║{RESET}")
                print(f"{CYAN}╚{'═'*66}╝{RESET}")
                ti = ThreatIntelligence()
                ti_lookup: dict = {}
                for cve_entry in (self.cve_results or []):
                    cve_id = cve_entry.get('cve_id', '')
                    if cve_id and cve_id != 'Unknown':
                        try:
                            record = ti.enrich_cve(cve_id)
                            ti_lookup[cve_id] = {
                                'cvss': record.cvss_score,
                                'epss_probability': record.epss_probability,
                                'in_kev': record.in_kev,
                                'exploit_available': bool(record.exploit_db_ids),
                                'attack_techniques': record.attack_techniques,
                            }
                        except Exception:
                            pass
                self.threat_intel_results = ti_lookup
                kev_count = sum(1 for v in ti_lookup.values() if v.get('in_kev'))
                print(f"{GREEN}[✓]{RESET} TI enrichment: {YELLOW}{len(ti_lookup)}{RESET} CVEs | {RED}{kev_count}{RESET} in CISA KEV")

            # PHASE 5: Risk Assessment
            print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
            print(f"{CYAN}║{RESET} {BOLD}{YELLOW}[PHASE 5]{RESET} {GREEN}►{RESET} Computing threat matrix...                        {CYAN}║{RESET}")
            print(f"{CYAN}╚{'═'*66}╝{RESET}")
            risk_engine = RiskEngine()
            self.risk_results = risk_engine.calculate_overall_risk(
                self.scan_results,
                self.vuln_results.get('vulnerabilities', []),
                self.cve_results,
                self.vuln_results.get('web_vulnerabilities', []),
                self.vuln_results.get('sql_vulnerabilities', [])
            )
            self.db.update_scan(
                self.scan_id,
                total_ports=len(self.scan_results.get('ports', [])),
                open_ports=len(self.scan_results.get('ports', [])),
                vulnerabilities_found=self.risk_results.get('total_vulnerabilities', 0),
                risk_score=self.risk_results.get('overall_risk_level', 'UNKNOWN'),
                status='completed'
            )

            # PHASE 6: Exploitation
            if not self.skip_exploit:
                print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
                print(f"{CYAN}║{RESET} {BOLD}{YELLOW}[PHASE 6]{RESET} {GREEN}►{RESET} Exploit simulation {YELLOW}[SAFE MODE]{RESET}...                    {CYAN}║{RESET}")
                print(f"{CYAN}╚{'═'*66}╝{RESET}")
                exploit_engine = ExploitEngine(safe_mode=self.safe_mode)
                matched_exploits = exploit_engine.match_exploits(
                    self.vuln_results.get('vulnerabilities', []), self.cve_results)
                if matched_exploits:
                    self.exploit_results = exploit_engine.simulate_exploitation(
                        matched_exploits, self.target)
                    for exploit in self.exploit_results:
                        exploit_data = {'name': exploit.get('exploit_name'),
                                        'status': exploit.get('status'),
                                        'result': json.dumps(exploit)}
                        self.db.insert_exploit(self.scan_id, None, exploit_data)
                else:
                    print(f"{YELLOW}[*]{RESET} No exploits matched vulnerability profile")
                    self.exploit_results = []
            else:
                print(f"\n{YELLOW}[PHASE 6]{RESET} Exploitation assessment... {YELLOW}[SKIPPED]{RESET}")
                self.exploit_results = []

            # PHASE 6.2: Web Attack Framework
            if not self.skip_web:
                print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
                print(f"{CYAN}║{RESET} {BOLD}{YELLOW}[PHASE 6.2]{RESET} {GREEN}►{RESET} Web Application Attack Framework...       {CYAN}║{RESET}")
                print(f"{CYAN}╚{'═'*66}╝{RESET}")
                web_fw = WebAttackFramework(
                    self.target, ports=self.scan_results.get('ports', []),
                    safe_mode=self.safe_mode)
                self.web_attack_results = web_fw.run_full_web_attack()
                wa_vulns = sum(len(v) for k, v in self.web_attack_results.items()
                               if isinstance(v, list) and k not in ('open_dirs', 'api_endpoints'))
                print(f"{GREEN}[✓]{RESET} Web attacks complete — {RED}{wa_vulns}{RESET} vulnerabilities identified")
            else:
                self.web_attack_results = {}

            # PHASE 6.3: AD Attack Suite
            if not self.skip_ad:
                print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
                print(f"{CYAN}║{RESET} {BOLD}{YELLOW}[PHASE 6.3]{RESET} {GREEN}►{RESET} Active Directory Attack Suite...           {CYAN}║{RESET}")
                print(f"{CYAN}╚{'═'*66}╝{RESET}")
                ad_suite = ADAttackSuite(
                    target=self.target, domain=self.domain, dc_ip=self.dc_ip,
                    username=self.ad_user, password=self.ad_pass, safe_mode=self.safe_mode)
                self.ad_results = ad_suite.run_full_ad_attack()
                kerb_count = len(self.ad_results.get('kerberoastable', []))
                print(f"{GREEN}[✓]{RESET} AD attack complete — {RED}{kerb_count}{RESET} Kerberoastable accounts")
            else:
                print(f"\n{YELLOW}[PHASE 6.3]{RESET} AD Attack Suite... {YELLOW}[SKIPPED]{RESET}")
                self.ad_results = {}

            # PHASE 6.4: Payload Generator
            if not self.skip_payload:
                print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
                print(f"{CYAN}║{RESET} {BOLD}{YELLOW}[PHASE 6.4]{RESET} {GREEN}►{RESET} Payload Generator [LHOST={self.lhost}:{self.lport}]... {CYAN}║{RESET}")
                print(f"{CYAN}╚{'═'*66}╝{RESET}")
                os.makedirs('payloads', exist_ok=True)
                payload_gen = PayloadGenerator(
                    lhost=self.lhost, lport=self.lport, out_dir='payloads')
                self.payload_results = payload_gen.run_full_generation(include_msf=True)
                print(f"{GREEN}[✓]{RESET} Payload generation complete — cheatsheet: {YELLOW}{self.payload_results.get('cheatsheet', 'N/A')}{RESET}")
            else:
                print(f"\n{YELLOW}[PHASE 6.4]{RESET} Payload Generator... {YELLOW}[SKIPPED]{RESET}")
                self.payload_results = {}

            # PHASE 6.4.5: Polymorphic Payload Engine
            if self.poly_payloads:
                print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
                print(f"{CYAN}║{RESET} {BOLD}{YELLOW}[PHASE 6.4.5]{RESET} {GREEN}►{RESET} Polymorphic Payload Engine...          {CYAN}║{RESET}")
                print(f"{CYAN}╚{'═'*66}╝{RESET}")
                os.makedirs('payloads/poly', exist_ok=True)
                poly = PolymorphicEngine()
                self.poly_results = poly.run_full_generation(
                    lhost=self.lhost, lport=self.lport,
                    shellcode=b'\x90' * 16,
                    webshell_password=self.webshell_password or 'changeme',
                )
                poly_count = len(self.poly_results.get('artifacts', []))
                print(f"{GREEN}[✓]{RESET} Polymorphic engine: {YELLOW}{poly_count}{RESET} unique artifacts generated")
            else:
                self.poly_results = {}

            # PHASE 6.5: Post-Exploitation
            if not self.skip_post:
                print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
                print(f"{CYAN}║{RESET} {BOLD}{YELLOW}[PHASE 6.5]{RESET} {GREEN}►{RESET} Post-Exploitation Framework...             {CYAN}║{RESET}")
                print(f"{CYAN}╚{'═'*66}╝{RESET}")
                post_fw = PostExploitFramework(
                    target=self.target, is_local=False, safe_mode=self.safe_mode)
                self.post_exploit_results = post_fw.run_full_post_exploit(
                    lhost=self.lhost, lport=self.lport)
                persist_count = len(self.post_exploit_results.get('persistence_mechanisms', []))
                print(f"{GREEN}[✓]{RESET} Post-exploitation complete — {YELLOW}{persist_count}{RESET} persistence techniques generated")
            else:
                print(f"\n{YELLOW}[PHASE 6.5]{RESET} Post-Exploitation... {YELLOW}[SKIPPED]{RESET}")
                self.post_exploit_results = {}

            # PHASE 6.55: EDR Fingerprinting
            if self.edr_fp:
                print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
                print(f"{CYAN}║{RESET} {BOLD}{YELLOW}[PHASE 6.55]{RESET} {GREEN}►{RESET} EDR/AV Fingerprinting...               {CYAN}║{RESET}")
                print(f"{CYAN}╚{'═'*66}╝{RESET}")
                edr_fp = EDRFingerprinter()
                self.edr_fp_results = edr_fp.fingerprint()
                edr_fp.print_report(self.edr_fp_results)
                detected_count = len(self.edr_fp_results.detected)
                plan = self.edr_fp_results.evasion_plan
                print(f"{GREEN}[✓]{RESET} EDR detected: {RED}{detected_count}{RESET} product(s) | "
                      f"Strategy: bypass={YELLOW}{plan['bypass']}{RESET} "
                      f"gate={YELLOW}{plan['syscall_gate']}{RESET}")

            # PHASE 6.6: Evasion Engine
            if not self.skip_evasion:
                print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
                print(f"{CYAN}║{RESET} {BOLD}{YELLOW}[PHASE 6.6]{RESET} {GREEN}►{RESET} Evasion & Obfuscation Engine...            {CYAN}║{RESET}")
                print(f"{CYAN}╚{'═'*66}╝{RESET}")
                os.makedirs('payloads/evasion', exist_ok=True)
                evasion_eng = EvasionEngine(out_dir='payloads/evasion')
                self.evasion_results = evasion_eng.run_full_evasion_suite()
                enc_count = len(self.evasion_results.get('encoded_payloads', []))
                print(f"{GREEN}[✓]{RESET} Evasion suite complete — {YELLOW}{enc_count}{RESET} encoded payload variants")
            else:
                print(f"\n{YELLOW}[PHASE 6.6]{RESET} Evasion Engine... {YELLOW}[SKIPPED]{RESET}")
                self.evasion_results = {}

            # PHASE 6.8: Heuristic / Bayesian Fusion Engine
            print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
            print(f"{CYAN}║{RESET} {BOLD}{YELLOW}[PHASE 6.8]{RESET} {GREEN}►{RESET} Heuristic Fusion Engine...                 {CYAN}║{RESET}")
            print(f"{CYAN}╚{'═'*66}╝{RESET}")
            raw_findings: list = []
            for key, items in (self.web_attack_results or {}).items():
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict):
                            item.setdefault('vuln_type', key)
                            raw_findings.append(item)
            for v in (self.vuln_results or {}).get('vulnerabilities', []):
                if isinstance(v, dict):
                    raw_findings.append(v)
            heuristic = HeuristicEngine()
            self.heuristic_results = heuristic.analyze(raw_findings, self.threat_intel_results)
            heuristic.print_summary(self.heuristic_results)
            confirmed = sum(1 for r in self.heuristic_results if r.grade == 'CONFIRMED')
            probable  = sum(1 for r in self.heuristic_results if r.grade == 'PROBABLE')
            print(f"{GREEN}[✓]{RESET} Heuristic analysis: {RED}{confirmed}{RESET} CONFIRMED | {YELLOW}{probable}{RESET} PROBABLE")

            # PHASE 6.9: Community Plugins
            if self.plugins:
                print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
                print(f"{CYAN}║{RESET} {BOLD}{YELLOW}[PHASE 6.9]{RESET} {GREEN}►{RESET} Community Plugin Runner...                 {CYAN}║{RESET}")
                print(f"{CYAN}╚{'═'*66}╝{RESET}")
                try:
                    from modules.plugin_loader import PluginLoader
                    loader = PluginLoader(self.plugin_dir)
                    loader.list_plugins()
                    context = {
                        'scan_results':    self.scan_results,
                        'vuln_results':    self.vuln_results,
                        'web_attack_results': self.web_attack_results,
                        'heuristic_results': [r.as_dict() for r in (self.heuristic_results or [])],
                    }
                    self.plugin_results = loader.run_all(self.target, context)
                    n_plugins = len(self.plugin_results)
                    print(f"{GREEN}[✓]{RESET} Plugins executed: {YELLOW}{n_plugins}{RESET}")
                except ImportError:
                    print(f"{YELLOW}[!]{RESET} plugin_loader module not found — skipping")
                    self.plugin_results = {}

            # PHASE 7: PDF Report
            print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
            print(f"{CYAN}║{RESET} {BOLD}{YELLOW}[PHASE 7]{RESET} {GREEN}►{RESET} Compiling classified intelligence report...      {CYAN}║{RESET}")
            print(f"{CYAN}╚{'═'*66}╝{RESET}")
            pdf_generator = PDFReportGenerator(self.target, self.scan_id)
            report_file = pdf_generator.generate_report(
                self.scan_results,
                self.vuln_results.get('vulnerabilities', []),
                self.cve_results,
                self.vuln_results.get('web_vulnerabilities', []),
                self.vuln_results.get('sql_vulnerabilities', []),
                self.risk_results,
                self.exploit_results,
                self.tester_name
            )
            if not report_file:
                print(f"{YELLOW}[!]{RESET} Report generation failed, but mission data captured successfully")

            self.end_time = time.time()
            duration = self.end_time - self.start_time
            self.db.update_scan(self.scan_id, scan_duration=duration)
            self.display_final_summary(duration, report_file)
            return True

        except KeyboardInterrupt:
            RED = '\033[91m'
            YELLOW = '\033[93m'
            RESET = '\033[0m'
            print(f"\n\n{RED}[!] MISSION ABORT - Operator initiated shutdown{RESET}")
            if self.scan_id:
                self.db.update_scan(self.scan_id, status='interrupted')
            return False

        except Exception as e:
            RED = '\033[91m'
            RESET = '\033[0m'
            print(f"\n{RED}[✗] CRITICAL SYSTEM ERROR: {e}{RESET}")
            import traceback
            traceback.print_exc()
            if self.scan_id:
                self.db.update_scan(self.scan_id, status='failed')
            return False

        finally:
            self.db.close()

    def display_final_summary(self, duration, report_file):
        RED = '\033[91m'
        GREEN = '\033[92m'
        CYAN = '\033[96m'
        YELLOW = '\033[93m'
        MAGENTA = '\033[95m'
        BOLD = '\033[1m'
        RESET = '\033[0m'

        print(f"\n\n{GREEN}{'▓'*70}{RESET}")
        print(f"{BOLD}{GREEN}{'█' * 18}{RESET} {YELLOW}MISSION COMPLETE{RESET} {GREEN}{'█' * 18}{RESET}")
        print(f"{GREEN}{'▓'*70}{RESET}")

        print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
        print(f"{CYAN}║{RESET} {BOLD}[OPERATION SUMMARY]{RESET}" + " " * 46 + f"{CYAN}║{RESET}")
        print(f"{CYAN}╠{'═'*66}╣{RESET}")
        print(f"{CYAN}║{RESET} {GREEN}►{RESET} Target: {YELLOW}{self.target}{RESET}")
        print(f"{CYAN}║{RESET} {GREEN}►{RESET} Mission ID: {YELLOW}{self.scan_id}{RESET}")
        print(f"{CYAN}║{RESET} {GREEN}►{RESET} Duration: {YELLOW}{duration:.2f}s{RESET} ({YELLOW}{duration/60:.2f} min{RESET})")
        print(f"{CYAN}║{RESET} {GREEN}►{RESET} Timestamp: {YELLOW}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
        print(f"{CYAN}╚{'═'*66}╝{RESET}")

        if self.risk_results:
            vuln_count = self.risk_results.get('total_vulnerabilities', 0)
            risk_level = self.risk_results.get('overall_risk_level', 'UNKNOWN')
            risk_color = RED if risk_level in ['CRITICAL', 'HIGH'] else YELLOW if risk_level == 'MEDIUM' else GREEN
            print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
            print(f"{CYAN}║{RESET} {BOLD}[INTELLIGENCE GATHERED]{RESET}" + " " * 43 + f"{CYAN}║{RESET}")
            print(f"{CYAN}╠{'═'*66}╣{RESET}")
            if self.scan_results:
                print(f"{CYAN}║{RESET} {GREEN}►{RESET} Open Ports: {YELLOW}{len(self.scan_results.get('ports', []))}{RESET}")
            print(f"{CYAN}║{RESET} {GREEN}►{RESET} Total Vulnerabilities: {RED if vuln_count > 0 else GREEN}{vuln_count}{RESET}")
            print(f"{CYAN}║{RESET} {GREEN}►{RESET} CVEs Identified: {YELLOW}{len(self.cve_results) if self.cve_results else 0}{RESET}")
            print(f"{CYAN}║{RESET} {GREEN}►{RESET} Overall Risk Level: {BOLD}{risk_color}{risk_level}{RESET}")
            print(f"{CYAN}╚{'═'*66}╝{RESET}")

        print(f"\n{CYAN}╔{'═'*66}╗{RESET}")
        print(f"{CYAN}║{RESET} {BOLD}[CLASSIFIED DATA STORAGE]{RESET}" + " " * 40 + f"{CYAN}║{RESET}")
        print(f"{CYAN}╠{'═'*66}╣{RESET}")
        if report_file and os.path.exists(report_file):
            print(f"{CYAN}║{RESET} {GREEN}►{RESET} PDF Report: {YELLOW}{report_file}{RESET}")
        print(f"{CYAN}║{RESET} {GREEN}►{RESET} Database: {YELLOW}database/autopentestx.db{RESET}")
        print(f"{CYAN}║{RESET} {GREEN}►{RESET} Payloads: {YELLOW}payloads/{RESET}")
        print(f"{CYAN}╚{'═'*66}╝{RESET}")

        print(f"\n{GREEN}{'▓'*70}{RESET}")
        print(f"\n{CYAN}[i]{RESET} {GREEN}Mission accomplished. Thank you for using AutoPentestX!{RESET}")
        print(f"{CYAN}[i]{RESET} {YELLOW}Remember: Hack ethically. Hack legally. Hack responsibly.{RESET}")
        print(f"{RED}[!]{RESET} {RED}Unauthorized access to systems = Federal prosecution{RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description='AutoPentestX v3.0 - Advanced Red Team & Offensive Security Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -t 192.168.1.100
  python main.py -t example.com -n "John Doe" --lhost 10.10.14.5 --lport 9001
  python main.py -t 10.0.0.1 --domain corp.local --dc-ip 10.0.0.5
  python main.py -t 192.168.1.100 --osint --threat-intel --edr-fp
  python main.py -t 192.168.1.100 --c2
  python main.py -t 192.168.1.100 --dashboard

WARNING: FOR AUTHORIZED PENETRATION TESTING AND EDUCATIONAL PURPOSES ONLY.
        """
    )

    parser.add_argument('-t', '--target', required=True,
                        help='Target IP address or domain name')
    parser.add_argument('-n', '--tester-name', default='AutoPentestX Team')
    parser.add_argument('--no-safe-mode', action='store_true')
    parser.add_argument('--skip-web', action='store_true')
    parser.add_argument('--skip-exploit', action='store_true')
    parser.add_argument('--lhost', default=None)
    parser.add_argument('--lport', type=int, default=4444)
    parser.add_argument('--domain', default=None)
    parser.add_argument('--dc-ip', default=None)
    parser.add_argument('--ad-user', default=None)
    parser.add_argument('--ad-pass', default=None)
    parser.add_argument('--skip-recon', action='store_true')
    parser.add_argument('--skip-ad', action='store_true')
    parser.add_argument('--skip-payload', action='store_true')
    parser.add_argument('--skip-post', action='store_true')
    parser.add_argument('--skip-evasion', action='store_true')
    parser.add_argument('--native-scan', action='store_true')
    parser.add_argument('--threat-intel', action='store_true')
    parser.add_argument('--poly-payloads', action='store_true')
    parser.add_argument('--webshell-password', default=None)
    parser.add_argument('--edr-fp', action='store_true')
    parser.add_argument('--c2', action='store_true')
    parser.add_argument('--c2-port', type=int, default=8443)
    parser.add_argument('--c2-psk', default=None)
    parser.add_argument('--c2-cert', default=None)
    parser.add_argument('--c2-key', default=None)
    parser.add_argument('--gen-implant', metavar='CALLBACK_URL')
    parser.add_argument('--dashboard', action='store_true')
    parser.add_argument('--dashboard-host', default='127.0.0.1')
    parser.add_argument('--dashboard-port', type=int, default=5000)
    parser.add_argument('--osint', action='store_true')
    parser.add_argument('--plugins', action='store_true')
    parser.add_argument('--plugin-dir', default='plugins')
    parser.add_argument('--version', action='version',
                        version='AutoPentestX v3.0 [DARKSEID]')

    args = parser.parse_args()

    # C2 / implant generator mode
    if args.gen_implant:
        from modules.c2_server import generate_implant
        psk = args.c2_psk or __import__('secrets').token_urlsafe(24)
        code = generate_implant(args.gen_implant, psk, '-')
        print(code)
        sys.exit(0)

    if args.c2:
        from modules.c2_server import C2Server, OperatorCLI
        srv = C2Server(host='0.0.0.0', port=args.c2_port, psk=args.c2_psk,
                       cert=args.c2_cert, key=args.c2_key)
        srv.start()
        cli = OperatorCLI(srv)
        cli.run()
        srv.stop()
        sys.exit(0)

    if args.dashboard:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        os.environ.setdefault('APX_DB', 'database/autopentestx.db')
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            'dashboard', os.path.join(os.path.dirname(__file__), 'dashboard', 'app.py'))
        dash = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dash)
        dash.DB_PATH = 'database/autopentestx.db'
        dash._write_templates()
        print(f'[+] Dashboard → http://{args.dashboard_host}:{args.dashboard_port}')
        dash.app.run(host=args.dashboard_host, port=args.dashboard_port, threaded=True)
        sys.exit(0)

    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    print(f"\n{RED}{'▓'*70}{RESET}")
    print(f"{BOLD}{RED}⚠️  [LEGAL WARNING] - AUTHORIZATION REQUIRED ⚠️{RESET}")
    print(f"{RED}{'▓'*70}{RESET}")
    print(f"\n{YELLOW}╔{'═'*66}╗{RESET}")
    print(f"{YELLOW}║{RESET} You are about to deploy an automated penetration testing tool. {YELLOW}║{RESET}")
    print(f"{YELLOW}║{RESET} This tool should ONLY be used on:                              {YELLOW}║{RESET}")
    print(f"{YELLOW}║{RESET}   • Systems you own                                            {YELLOW}║{RESET}")
    print(f"{YELLOW}║{RESET}   • Systems with explicit written authorization                {YELLOW}║{RESET}")
    print(f"{YELLOW}║{RESET} {RED}Unauthorized system access = FEDERAL CRIME{RESET}                      {YELLOW}║{RESET}")
    print(f"{YELLOW}╚{'═'*66}╝{RESET}")

    confirmation = input(f"\n{CYAN}>{RESET} {BOLD}Do you have authorization to test this target?{RESET} {YELLOW}(yes/no):{RESET} ")
    if confirmation.lower() not in ['yes', 'y']:
        print(f"\n{RED}[!] MISSION ABORT - Authorization not confirmed.{RESET}")
        sys.exit(0)

    print(f"{CYAN}[*] Authorization confirmed. Proceeding with operation...{RESET}")

    safe_mode = not args.no_safe_mode
    autopentestx = AutoPentestX(
        target=args.target,
        tester_name=args.tester_name,
        safe_mode=safe_mode,
        skip_web=args.skip_web,
        skip_exploit=args.skip_exploit,
        lhost=args.lhost,
        lport=args.lport,
        domain=args.domain,
        dc_ip=args.dc_ip,
        ad_user=args.ad_user,
        ad_pass=args.ad_pass,
        skip_recon=args.skip_recon,
        skip_ad=args.skip_ad,
        skip_payload=args.skip_payload,
        skip_post=args.skip_post,
        skip_evasion=args.skip_evasion,
        native_scan=args.native_scan,
        threat_intel=args.threat_intel,
        poly_payloads=args.poly_payloads,
        edr_fp=args.edr_fp,
        webshell_password=args.webshell_password,
        osint=args.osint,
        plugins=args.plugins,
        plugin_dir=args.plugin_dir,
    )
    success = autopentestx.run_full_assessment()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
