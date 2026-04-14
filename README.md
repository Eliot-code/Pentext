# AutoPentestX v2.0 — [DARKSEID]

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Kali-lightgrey.svg)](https://www.kali.org/)
[![Version](https://img.shields.io/badge/version-2.0.0-red.svg)]()
[![RedTeam](https://img.shields.io/badge/category-Red%20Team-critical.svg)]()

<img width="1159" height="651" alt="image" src="https://github.com/user-attachments/assets/0187dccf-3391-4315-9835-de494c072d7e" />

##

<img width="1137" height="432" alt="image" src="https://github.com/user-attachments/assets/22ff45c5-0a62-4a44-a9ce-cd84e53ed618" />

---

> **⚠️ AVISO LEGAL:** Esta herramienta es exclusivamente para pruebas de penetración **autorizadas**, entornos de laboratorio, CTFs y formación en ciberseguridad. El uso no autorizado contra sistemas ajenos es **ilegal**. El autor no se responsabiliza del mal uso.

---

## ¿Qué es AutoPentestX?

**AutoPentestX v2.0 [DARKSEID]** es un framework avanzado de Red Team y seguridad ofensiva que automatiza las fases completas de un pentest profesional: desde reconocimiento OSINT hasta post-explotación, evasión y generación de payloads.

Combina herramientas del ecosistema de seguridad (Nmap, Nikto, SQLMap, Metasploit, Impacket) con módulos propios altamente sofisticados para ofrecer una plataforma todo-en-uno para operadores de Red Team.

---

## Características principales

### 🔍 Reconocimiento Avanzado (OSINT)
- Enumeración DNS completa + intento de transferencia de zona (AXFR)
- Fuerza bruta de subdominios (150 palabras clave + consulta a crt.sh)
- Análisis SSL/TLS: protocolos débiles, cifrados inseguros, SANs
- Detección de WAF/CDN (Cloudflare, Akamai, Imperva, F5, Sucuri, Barracuda…)
- Fingerprinting de tecnologías (WordPress, Drupal, Django, React, Angular…)
- Auditoría de seguridad de email (SPF, DKIM, DMARC)
- Lookup ASN/BGP vía Team Cymru
- Generación automática de 17 consultas Google Dork

### 🌐 Ataques Web (OWASP Top 10+)
- Auditoría de cabeceras de seguridad HTTP
- Fuzzing de directorios y archivos (80+ rutas)
- XSS reflejado (13 payloads × 10 parámetros)
- SQL Injection error-based y time-based
- LFI/Path Traversal con confirmación en `/etc/passwd`
- SSRF (metadatos AWS/GCP/Alibaba, Redis, Gopher)
- CORS mal configurado con detección de exposición de credenciales
- JWT bypass por algoritmo `none`
- Descubrimiento de endpoints API (30+ rutas)
- Inyección de cabeceras HTTP / spoofing de IP

### 💣 Generador de Payloads
- **25 variantes de reverse shell**: bash, python, perl, ruby, php, golang, node.js, PowerShell (base64), socat, awk, xterm, telnet, curl, wget
- **8 web shells**: PHP minimal/exec/passthru/full, ASPX, JSP, Python Flask (con ofuscación base64)
- **13 comandos MSFVenom**: Windows x64 EXE/DLL/PS1/VBA/HTA, Linux x64/x86, macOS, Android APK, Java JAR, PHP, Python
- Macro VBA para phishing en Office
- Templates de listeners (nc, socat, msfconsole, rlwrap)
- Exportación automática de cheatsheet en Markdown

### 🏢 Active Directory Attack Suite
- Detección de servicios AD (Kerberos, LDAP, SMB, WinRM, GC)
- Enumeración SMB: enum4linux-ng, smbclient, rpcclient (sesión nula)
- Enumeración LDAP anónima y autenticada
- **Kerberoasting**: Impacket GetUserSPNs + Rubeus
- **AS-REP Roasting**: GetNPUsers + Rubeus + Hashcat
- **Password Spray** con límite inteligente anti-lockout
- Vectores **DCSync** (secretsdump + Mimikatz)
- **Golden Ticket** generation commands
- Comandos de recolección BloodHound (Python + SharpHound)
- Movimiento lateral: WinRM, SMBexec, WMIexec, PSexec, RDP, Pass-the-Hash, Pass-the-Ticket

### 🎯 Post-Explotación
- Enumeración de sistema (local y remota)
- Detección de vectores privesc: SUID GTFOBins, sudo NOPASSWD, `/etc/passwd` escribible, cron wildcards, kernel antiguo
- Recolección de credenciales: archivos de config, historial de shell, credenciales AWS
- **6 mecanismos de persistencia Linux**: cron, SSH authorized_keys, bashrc, systemd service, SUID backdoor, sudoers
- **4 mecanismos de persistencia Windows**: registro Run, tarea programada, WMI subscription, DLL hijacking
- Reconocimiento de red interna + comandos de pivoting (SSH tunnels, Chisel, Ligolo, Meterpreter)
- 9 técnicas de exfiltración: DNS, HTTP POST, ICMP, SCP, Netcat, base64, SMTP, FTP, Python HTTPS

### 🛡️ Motor de Evasión
- Cadenas de codificación: base64 → hex → XOR → URL
- 6 técnicas de ofuscación PowerShell (base64, IEX, char array, reversal, concat split, AMSI bypass)
- 6 técnicas de ofuscación Bash (base64 exec, hex exec, var split, IFS, keyword split, subshell)
- Encoder XOR de shellcode con stubs de decoder en C y Python
- 5 snippets de bypass AMSI + bypass ETW + bypass de ExecutionPolicy
- Loaders C#: PInvoke VirtualAlloc + inyección de proceso remoto
- 11 técnicas de evasión IDS/IPS + comandos Nmap evasivos
- Patrones de camuflaje de tráfico (Google Analytics, CDN assets, OCSP, Slack webhook, DNS-over-HTTPS)

---

## Flujo de trabajo — 11 fases

```
FASE 1   → Inicialización de base de datos
FASE 2   → Reconocimiento de red (Nmap TCP/UDP + OS detection)
FASE 2.5 → OSINT avanzado (DNS, subdominios, WAF, SSL, tecnologías)
FASE 3   → Análisis de vulnerabilidades (Nikto + SQLMap)
FASE 4   → Inteligencia CVE (CIRCL + NVD APIs)
FASE 5   → Motor de riesgo (CVSS scoring)
FASE 6   → Simulación de exploits (Metasploit RC scripts)
FASE 6.2 → Web Attack Framework (XSS, SQLi, LFI, SSRF, CORS, JWT…)
FASE 6.3 → Active Directory Attack Suite (Kerberoasting, AS-REP…)
FASE 6.4 → Generador de payloads (shells, web shells, MSFVenom)
FASE 6.5 → Post-explotación (privesc, persistencia, exfiltración)
FASE 6.6 → Motor de evasión (AMSI bypass, ofuscación, loaders C#)
FASE 7   → Generación de reporte PDF profesional
```

---

## Instalación

### Requisitos
- Python 3.8+
- Kali Linux / Ubuntu 20.04+ (recomendado)
- Herramientas del sistema: `nmap`, `nikto`, `sqlmap`, `dig`, `whois`, `smbclient`, `ldapsearch`

### Instalación rápida

```bash
git clone https://github.com/eliot-code/pentext.git
cd pentext
chmod +x install.sh
./install.sh
```

### Instalación manual

```bash
# Instalar dependencias del sistema
sudo apt update && sudo apt install -y nmap nikto sqlmap metasploit-framework \
    dnsutils whois smbclient ldap-utils enum4linux smbmap

# Entorno virtual Python
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Uso

### Evaluación completa Red Team

```bash
python main.py -t 10.10.10.10 --lhost 10.10.14.5 --lport 443
```

### Con credenciales de Active Directory

```bash
python main.py -t 10.0.0.5 \
               --domain corp.local \
               --dc-ip 10.0.0.5 \
               --ad-user jdoe \
               --ad-pass 'Password123' \
               --lhost 10.10.14.5 \
               --lport 9001
```

### Solo reconocimiento + web (rápido)

```bash
python main.py -t ejemplo.com --skip-ad --skip-payload --skip-post --skip-evasion
```

### Modo ofensivo sin safe mode (requiere autorización explícita)

```bash
python main.py -t 192.168.1.100 --no-safe-mode --lhost 192.168.1.50 --lport 4444
```

### Saltar fases específicas

```bash
python main.py -t 10.10.10.10 \
               --skip-web        # Salta Nikto/SQLMap/WebAttacks
               --skip-exploit    # Salta Metasploit simulation
               --skip-recon      # Salta OSINT avanzado
               --skip-ad         # Salta Active Directory
               --skip-payload    # Salta generación de payloads
               --skip-post       # Salta post-explotación
               --skip-evasion    # Salta motor de evasión
```

---

## Argumentos CLI completos

| Argumento | Descripción | Valor por defecto |
|---|---|---|
| `-t`, `--target` | IP o dominio objetivo (**requerido**) | — |
| `-n`, `--tester-name` | Nombre del operador | `AutoPentestX Team` |
| `--lhost` | IP del listener para payloads | Auto-detectada |
| `--lport` | Puerto del listener | `4444` |
| `--domain` | Dominio AD (ej. `corp.local`) | — |
| `--dc-ip` | IP del Domain Controller | igual que target |
| `--ad-user` | Usuario AD para enumeración autenticada | — |
| `--ad-pass` | Contraseña AD | — |
| `--no-safe-mode` | Desactiva el modo seguro | — |
| `--skip-web` | Salta análisis web | — |
| `--skip-exploit` | Salta simulación de exploits | — |
| `--skip-recon` | Salta reconocimiento OSINT | — |
| `--skip-ad` | Salta Active Directory | — |
| `--skip-payload` | Salta generador de payloads | — |
| `--skip-post` | Salta post-explotación | — |
| `--skip-evasion` | Salta motor de evasión | — |
| `--version` | Muestra versión | — |

---

## Estructura del proyecto

```
AutoPentestX/
├── main.py                    # Orquestador principal v2.0
├── autopentestx.sh            # Launcher CLI
├── install.sh                 # Instalador automático
├── config.json                # Configuración global
├── requirements.txt           # Dependencias Python
│
├── modules/
│   ├── scanner.py             # Nmap: TCP/UDP/OS detection
│   ├── vuln_scanner.py        # Nikto + SQLMap wrapper
│   ├── cve_lookup.py          # CIRCL + NVD API
│   ├── risk_engine.py         # CVSS scoring
│   ├── exploit_engine.py      # Metasploit RC scripts
│   ├── database.py            # SQLite persistence
│   ├── pdf_report.py          # Reporte PDF profesional
│   │
│   ├── recon_advanced.py      # [v2.0] OSINT & Reconocimiento
│   ├── web_attacks.py         # [v2.0] Web Attack Framework
│   ├── payload_gen.py         # [v2.0] Generador de Payloads
│   ├── ad_attacks.py          # [v2.0] Active Directory Suite
│   ├── post_exploit.py        # [v2.0] Post-Explotación
│   └── evasion.py             # [v2.0] Evasión & Ofuscación
│
├── reports/                   # Reportes PDF generados
├── payloads/                  # Payloads generados
│   └── evasion/               # Artefactos de evasión (loaders C#)
├── exploits/                  # Scripts RC de Metasploit
├── database/                  # Base de datos SQLite
└── logs/                      # Logs de ejecución
```

---

## Artefactos generados

| Artefacto | Ubicación | Descripción |
|---|---|---|
| Reporte PDF | `reports/AutoPentestX_Report_*.pdf` | Reporte ejecutivo completo |
| Base de datos | `database/autopentestx.db` | Histórico de escaneos (SQLite) |
| Cheatsheet | `payloads/cheatsheet_*.md` | Todos los payloads generados |
| Web shells | `payloads/webshell_*.php/aspx/jsp` | Web shells listos para subir |
| Loaders C# | `payloads/evasion/loader_*.cs` | Shellcode loaders compilables |
| Scripts MSF | `exploits/exploit_*.rc` | Resource scripts de Metasploit |
| Logs | `logs/autopentestx_*.log` | Log completo de la operación |

---

## Dependencias Python

```
python-nmap>=0.7.1
requests>=2.31.0
reportlab>=4.0.4
sqlparse>=0.4.4
```

---

## Herramientas del sistema utilizadas

| Herramienta | Uso |
|---|---|
| `nmap` | Escaneo de puertos, OS detection, versiones |
| `nikto` | Escaneo de vulnerabilidades web |
| `sqlmap` | Detección de SQL injection |
| `dig` | Enumeración DNS, consultas AXFR |
| `whois` | Información de registro de dominio |
| `smbclient` | Enumeración de shares SMB |
| `rpcclient` | Enumeración de usuarios/grupos via RPC |
| `ldapsearch` | Enumeración LDAP de Active Directory |
| `enum4linux-ng` | Enumeración completa de hosts Windows/Samba |
| `msfconsole` | Framework de explotación Metasploit |
| `msfvenom` | Generación de payloads |

---

## Módulos v2.0 — Uso independiente

Cada módulo puede usarse de forma independiente:

```python
# Reconocimiento OSINT
from modules.recon_advanced import AdvancedRecon
recon = AdvancedRecon("ejemplo.com")
results = recon.run_full_recon()

# Ataques web
from modules.web_attacks import WebAttackFramework
wa = WebAttackFramework("10.10.10.10", ports=[{'port':80}])
results = wa.run_full_web_attack()

# Generador de payloads
from modules.payload_gen import PayloadGenerator
pg = PayloadGenerator(lhost="10.10.14.5", lport=4444)
pg.run_full_generation()

# Active Directory
from modules.ad_attacks import ADAttackSuite
ad = ADAttackSuite("10.0.0.5", domain="corp.local")
results = ad.run_full_ad_attack()

# Post-explotación
from modules.post_exploit import PostExploitFramework
pe = PostExploitFramework("10.10.10.10")
results = pe.run_full_post_exploit(lhost="10.10.14.5")

# Evasión
from modules.evasion import EvasionEngine
ev = EvasionEngine()
results = ev.run_full_evasion_suite()
```

---

## Changelog

### v2.0.0 — DARKSEID
- Nuevo módulo: `recon_advanced.py` — OSINT avanzado completo
- Nuevo módulo: `web_attacks.py` — Framework de ataques web (OWASP Top 10+)
- Nuevo módulo: `payload_gen.py` — Generador de payloads multi-plataforma
- Nuevo módulo: `ad_attacks.py` — Suite de ataques a Active Directory
- Nuevo módulo: `post_exploit.py` — Framework de post-explotación
- Nuevo módulo: `evasion.py` — Motor de evasión y ofuscación
- `main.py`: 11 fases de ataque, 11 nuevos argumentos CLI
- `config.json`: Configuración completa para todos los módulos

### v1.0.0
- Escaneo de puertos TCP/UDP con Nmap
- Detección de vulnerabilidades con Nikto y SQLMap
- Lookup de CVEs (CIRCL + NVD)
- Motor de riesgo CVSS
- Simulación de exploits con Metasploit
- Reporte PDF profesional
- Base de datos SQLite

---

## Aviso legal

```
Este software se proporciona únicamente para:
  • Pruebas de penetración con autorización escrita explícita
  • Entornos de laboratorio controlados (VMs, HTB, THM, VulnHub)
  • Competencias CTF (Capture The Flag)
  • Formación y educación en ciberseguridad

El uso contra sistemas sin autorización es un DELITO FEDERAL
en la mayoría de jurisdicciones. El autor no asume ninguna
responsabilidad por el uso indebido de esta herramienta.

Hack ético. Hack legal. Hack responsable.
```

---

## Licencia

MIT License — consulta el archivo [LICENSE](LICENSE) para más detalles.

---

*AutoPentestX v2.0 [DARKSEID] — Advanced Red Team Framework*

---

**Autor:** [Eliot-code](https://github.com/Eliot-code)
