from __future__ import annotations

from dataclasses import dataclass

from validation import kat_3des, kat_aes, kat_chacha20, kat_des, kat_gcm, kat_modes


class _BadBlockCipher:
    def __init__(self, _key: bytes):
        pass

    def encrypt_block(self, _block: bytes) -> bytes:
        return b"\x00" * 16

    def decrypt_block(self, _block: bytes) -> bytes:
        return b"\x00" * 16


def test_kat_aes_failure_paths(monkeypatch):
    monkeypatch.setattr(kat_aes, "AES", _BadBlockCipher)
    assert kat_aes.run(verbose=True) > 0


def test_kat_des_failure_paths(monkeypatch):
    monkeypatch.setattr(kat_des, "DES", _BadBlockCipher)
    assert kat_des.run(verbose=True) > 0


def test_kat_3des_failure_paths(monkeypatch):
    monkeypatch.setattr(kat_3des, "TripleDES", _BadBlockCipher)
    assert kat_3des.run(verbose=True) > 0


class _BadECB:
    def __init__(self, _aes):
        pass

    def encrypt(self, plaintext: bytes) -> bytes:
        return b"\x00" * (len(plaintext) + 16)

    def decrypt(self, _ciphertext: bytes) -> bytes:
        return b"\x00" * 64


class _BadCBC:
    def __init__(self, _aes):
        pass

    def encrypt(self, plaintext: bytes, iv: bytes | None = None) -> bytes:
        _ = iv
        return b"\x00" * (16 + len(plaintext) + 16)

    def decrypt(self, _ciphertext: bytes) -> bytes:
        return b"\x00" * 64


class _BadCTR:
    def __init__(self, _aes):
        pass

    def encrypt(self, plaintext: bytes, nonce: bytes | None = None) -> bytes:
        _ = nonce
        return b"\x00" * (8 + len(plaintext))

    def decrypt(self, _ciphertext: bytes) -> bytes:
        return b"\x00" * 64


def test_kat_modes_failure_paths(monkeypatch):
    monkeypatch.setattr(kat_modes, "ECB", _BadECB)
    monkeypatch.setattr(kat_modes, "CBC", _BadCBC)
    monkeypatch.setattr(kat_modes, "CTR", _BadCTR)
    assert kat_modes.run(verbose=True) > 0


class _BadGCM:
    def __init__(self, _aes):
        self._count = 0

    def encrypt(self, plain: bytes, nonce: bytes | None = None, aad: bytes = b"") -> bytes:
        _ = aad
        # Return a valid framing nonce||cipher||tag, but with wrong values.
        n = nonce if nonce is not None else (b"\x00" * 12)
        return n + (b"\x00" * len(plain)) + (b"\x00" * 16)

    def decrypt(self, payload: bytes, nonce: bytes | None = None, aad: bytes = b"") -> bytes:
        _ = (payload, nonce, aad)
        self._count += 1
        # First decrypt path returns wrong plaintext, tamper path also returns bytes.
        return b"\x00" * 64


class _RaiseOnDecryptGCM(_BadGCM):
    def decrypt(self, payload: bytes, nonce: bytes | None = None, aad: bytes = b"") -> bytes:
        _ = (payload, nonce, aad)
        raise ValueError("bad tag")


def test_kat_gcm_failure_paths(monkeypatch):
    monkeypatch.setattr(kat_gcm, "GCM", _BadGCM)
    assert kat_gcm.run(verbose=True) > 0


def test_kat_gcm_exception_decrypt_path(monkeypatch):
    monkeypatch.setattr(kat_gcm, "GCM", _RaiseOnDecryptGCM)
    assert kat_gcm.run(verbose=True) > 0


@dataclass
class _FakeRawCipher:
    def seek(self, _offset: int) -> None:
        return None

    def encrypt(self, plain: bytes) -> bytes:
        return b"\x00" * len(plain)


class _FakeRawFactory:
    @staticmethod
    def new(*, key: bytes, nonce: bytes):
        _ = (key, nonce)
        return _FakeRawCipher()


class _FakeChaCha20:
    def __init__(self, key: bytes):
        self._last_plain = b""
        self._key = key

    def encrypt_block(self, plain: bytes) -> bytes:
        self._last_plain = plain
        return b"\x00" * 12 + plain

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        _ = ciphertext
        return self._last_plain


def test_kat_chacha20_failure_paths(monkeypatch):
    monkeypatch.setattr(kat_chacha20, "_PyCryptoChaCha20", _FakeRawFactory)
    monkeypatch.setattr(kat_chacha20, "ChaCha20", _FakeChaCha20)
    assert kat_chacha20.run(verbose=True) > 0


class _FakeChaCha20BadRoundTrip:
    def __init__(self, key: bytes):
        if len(key) == 16:
            raise ValueError("invalid key length")

    def encrypt_block(self, plain: bytes) -> bytes:
        return b"\x00" * 12 + plain

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        _ = ciphertext
        return b"\x00" * 8


def test_kat_chacha20_roundtrip_else_branch(monkeypatch):
    monkeypatch.setattr(kat_chacha20, "_PyCryptoChaCha20", _FakeRawFactory)
    monkeypatch.setattr(kat_chacha20, "ChaCha20", _FakeChaCha20BadRoundTrip)
    assert kat_chacha20.run(verbose=True) > 0


def test_kat_chacha20_helper_silent_branches():
    assert kat_chacha20._pass("ok", verbose=False) == 0
    assert kat_chacha20._fail("ko", b"a", b"b", verbose=False) == 1
