import sys
import types
import importlib

import pytest

from domain import AES, CBC, CTR, DES, ECB, GCM, TripleDES, Twofish
from domain.cipher.ChaCha20 import ChaCha20
from domain.mode.StreamMode import StreamMode


def test_domain_public_imports():
    import domain

    assert domain.AES is AES
    assert domain.CBC is CBC


def test_aes_roundtrip_and_validation():
    with pytest.raises(ValueError):
        AES(b"short")

    aes = AES(bytes(range(16)))
    assert aes.block_size == 16
    assert aes.key_size == 16
    block = bytes(range(16))
    encrypted = aes.encrypt_block(block)
    assert aes.decrypt_block(encrypted) == block
    assert aes.decrypt_blocks(aes.encrypt_blocks(block * 2)) == block * 2

    with pytest.raises(ValueError):
        aes.encrypt_block(b"tiny")
    with pytest.raises(ValueError):
        aes.decrypt_block(b"tiny")


def test_des_roundtrip_and_validation():
    with pytest.raises(ValueError):
        DES(b"tiny")

    des = DES(b"12345678")
    assert des.block_size == 8
    assert des.key_size == 8
    block = b"ABCDEFGH"
    encrypted = des.encrypt_block(block)
    assert des.decrypt_block(encrypted) == block
    assert des.decrypt_blocks(des.encrypt_blocks(block * 2)) == block * 2

    with pytest.raises(ValueError):
        des.encrypt_block(b"bad")
    with pytest.raises(ValueError):
        des.decrypt_block(b"bad")


def test_3des_roundtrip_and_validation():
    with pytest.raises(ValueError):
        TripleDES(b"short")

    key_16 = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    tdes = TripleDES(key_16)
    assert tdes.block_size == 8
    assert tdes.key_size in (16, 24)
    block = b"ABCDEFGH"
    encrypted = tdes.encrypt_block(block)
    assert tdes.decrypt_block(encrypted) == block
    assert tdes.decrypt_blocks(tdes.encrypt_blocks(block * 2)) == block * 2

    with pytest.raises(ValueError):
        tdes.encrypt_block(b"x")
    with pytest.raises(ValueError):
        tdes.decrypt_block(b"x")


def test_twofish_roundtrip_and_validation(monkeypatch):
    with pytest.raises(ValueError):
        Twofish(b"short")

    fake_module = types.ModuleType("twofish")

    class FakeTwofish:
        def __init__(self, key: bytes):
            self.key = key

        def encrypt(self, block: bytes) -> bytes:
            return bytes((b ^ 0xAA) for b in block)

        def decrypt(self, block: bytes) -> bytes:
            return bytes((b ^ 0xAA) for b in block)

    fake_module.Twofish = FakeTwofish
    monkeypatch.setitem(sys.modules, "twofish", fake_module)

    tf = Twofish(bytes(range(16)))
    assert tf.block_size == 16
    assert tf.key_size == 16
    block = bytes(reversed(range(16)))
    encrypted = tf.encrypt_block(block)
    assert tf.decrypt_block(encrypted) == block

    with pytest.raises(ValueError):
        tf.encrypt_block(b"x")
    with pytest.raises(ValueError):
        tf.decrypt_block(b"x")


def test_twofish_import_error_path(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_builtin_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "twofish":
            raise ImportError("forced")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_builtin_import)
    with pytest.raises(ImportError):
        Twofish(bytes(range(16)))


def test_twofish_import_error_missing_package(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_builtin_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "twofish":
            raise ImportError("No module named twofish", name="twofish")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_builtin_import)
    with pytest.raises(ImportError, match="required for Twofish support"):
        Twofish(bytes(range(16)))


def test_twofish_imp_compat_injected_when_missing(monkeypatch):
    import builtins

    twofish_module = importlib.import_module("domain.cipher.Twofish")
    original_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "imp":
            raise ModuleNotFoundError("No module named imp")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.delitem(sys.modules, "imp", raising=False)
    monkeypatch.setattr(builtins, "__import__", fake_import)

    twofish_module._ensure_imp_compat_module()

    imp_mod = sys.modules.get("imp")
    assert imp_mod is not None
    assert hasattr(imp_mod, "find_module")
    assert hasattr(imp_mod, "get_suffixes")
    assert hasattr(imp_mod, "load_module")
    assert imp_mod.load_module("sys") is sys
    # Exercise legacy load path when target is not already in sys.modules.
    sentinel = object()
    monkeypatch.setattr(importlib, "import_module", lambda name: sentinel)
    assert imp_mod.load_module("_module_not_in_sys_modules") is sentinel
    assert imp_mod.get_suffixes()

    with pytest.raises(ImportError):
        imp_mod.find_module("definitely_missing_module_for_twofish_tests")


def test_twofish_imp_compat_uses_existing_module(monkeypatch):
    twofish_module = importlib.import_module("domain.cipher.Twofish")
    fake_imp = types.ModuleType("imp")
    monkeypatch.setitem(sys.modules, "imp", fake_imp)

    twofish_module._ensure_imp_compat_module()
    assert sys.modules["imp"] is fake_imp


def test_twofish_imp_find_module_descriptor_branches(monkeypatch):
    twofish_module = importlib.import_module("domain.cipher.Twofish")
    monkeypatch.delitem(sys.modules, "imp", raising=False)
    twofish_module._ensure_imp_compat_module()
    imp_mod = sys.modules["imp"]

    class _Spec:
        def __init__(self, origin: str, pkg=None):
            self.origin = origin
            self.submodule_search_locations = pkg

    def fake_find_spec(name, path=None):
        mapping = {
            "builtin_case": _Spec("built-in"),
            "frozen_case": _Spec("frozen"),
            "pkg_case": _Spec("pkg/__init__.py", pkg=[]),
            "ext_case": _Spec("module" + importlib.machinery.EXTENSION_SUFFIXES[0]),
            "pyc_case": _Spec("module.pyc"),
            "py_case": _Spec("module.py"),
            "none_case": _Spec(None),
        }
        return mapping.get(name)

    monkeypatch.setattr(importlib.machinery.PathFinder, "find_spec", staticmethod(fake_find_spec))

    assert imp_mod.find_module("builtin_case")[2][2] == imp_mod.C_BUILTIN
    assert imp_mod.find_module("frozen_case")[2][2] == imp_mod.PY_FROZEN
    assert imp_mod.find_module("pkg_case")[2][2] == imp_mod.PKG_DIRECTORY
    assert imp_mod.find_module("ext_case")[2][2] == imp_mod.C_EXTENSION
    assert imp_mod.find_module("pyc_case")[2][2] == imp_mod.PY_COMPILED
    assert imp_mod.find_module("py_case")[2][2] == imp_mod.PY_SOURCE

    with pytest.raises(ImportError):
        imp_mod.find_module("none_case")


def test_chacha20_roundtrip_and_validation():
    with pytest.raises(ValueError):
        ChaCha20(b"short")

    chacha = ChaCha20(bytes(range(32)))
    assert chacha.block_size == 64
    assert chacha.key_size == 32
    plaintext = b"hello stream cipher"
    ciphertext = chacha.encrypt_block(plaintext)
    assert chacha.decrypt_block(ciphertext) == plaintext
    assert chacha.decrypt_blocks(chacha.encrypt_blocks(plaintext)) == plaintext

    with pytest.raises(ValueError):
        chacha.decrypt_block(b"tiny")


def test_ecb_mode_positive_and_negative():
    aes = AES(bytes(range(16)))
    ecb = ECB(aes)

    plaintext = b"message for ecb mode"
    encrypted = ecb.encrypt(plaintext)
    assert ecb.decrypt(encrypted) == plaintext

    with pytest.raises(ValueError):
        ecb.decrypt(b"not-multiple")


def test_cbc_mode_positive_and_negative():
    aes = AES(bytes(range(16)))
    cbc = CBC(aes)

    iv = bytes([1] * 16)
    plaintext = b"cbc plaintext"
    encrypted = cbc.encrypt(plaintext, iv=iv)
    assert cbc.decrypt(encrypted) == plaintext

    auto_iv_encrypted = cbc.encrypt(plaintext)
    assert cbc.decrypt(auto_iv_encrypted) == plaintext

    with pytest.raises(ValueError):
        cbc.encrypt(plaintext, iv=b"short")
    with pytest.raises(ValueError):
        cbc.decrypt(encrypted, iv=b"short")
    with pytest.raises(ValueError):
        cbc.decrypt(iv + b"bad")


def test_ctr_mode_positive_and_negative():
    aes = AES(bytes(range(16)))
    ctr = CTR(aes)

    nonce = bytes([2] * 8)
    plaintext = b"ctr plaintext that can be any length"

    encrypted = ctr.encrypt(plaintext, nonce=nonce)
    assert ctr.decrypt(encrypted) == plaintext

    auto_nonce_encrypted = ctr.encrypt(plaintext)
    assert ctr.decrypt(auto_nonce_encrypted) == plaintext

    with pytest.raises(ValueError):
        ctr.encrypt(plaintext, nonce=b"short")
    with pytest.raises(ValueError):
        ctr.decrypt(encrypted, nonce=b"short")


def test_gcm_mode_positive_and_negative():
    aes = AES(bytes(range(16)))

    gcm = GCM(aes)
    nonce = bytes([3] * 12)
    aad = b"metadata"
    plaintext = b"gcm payload"

    encrypted = gcm.encrypt(plaintext, nonce=nonce, aad=aad)
    assert gcm.decrypt(encrypted, aad=aad) == plaintext

    encrypted_auto_nonce = gcm.encrypt(plaintext, aad=aad)
    assert gcm.decrypt(encrypted_auto_nonce, aad=aad) == plaintext

    tampered = bytearray(encrypted)
    tampered[-1] ^= 0x01
    with pytest.raises(ValueError):
        gcm.decrypt(bytes(tampered), aad=aad)

    with pytest.raises(ValueError):
        gcm.encrypt(plaintext, nonce=b"short")
    with pytest.raises(ValueError):
        gcm.decrypt(encrypted, nonce=b"short")

    with pytest.raises(TypeError):
        GCM(DES(b"12345678"))


def test_stream_mode_passthrough():
    chacha = ChaCha20(bytes(range(32)))
    mode = StreamMode(chacha)

    plaintext = b"stream mode delegates to primitive"
    encrypted = mode.encrypt(plaintext)
    assert mode.decrypt(encrypted) == plaintext
