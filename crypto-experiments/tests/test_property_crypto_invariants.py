from __future__ import annotations

import pytest
from hypothesis import given, settings, strategies as st

from domain.cipher import AES, DES, TripleDES, Twofish
from domain.mode import ECB, CBC, CTR, GCM
from domain.mode.StreamMode import StreamMode
from domain.cipher.ChaCha20 import ChaCha20


@settings(max_examples=40, deadline=None)
@given(st.binary(min_size=16, max_size=16))
def test_aes_block_roundtrip_property(block: bytes):
    key = b"A" * 16
    cipher = AES(key)
    assert cipher.decrypt_block(cipher.encrypt_block(block)) == block


@settings(max_examples=40, deadline=None)
@given(st.binary(min_size=8, max_size=8))
def test_des_block_roundtrip_property(block: bytes):
    key = b"D" * 8
    cipher = DES(key)
    assert cipher.decrypt_block(cipher.encrypt_block(block)) == block


@settings(max_examples=40, deadline=None)
@given(st.binary(min_size=8, max_size=8))
def test_3des_block_roundtrip_property(block: bytes):
    key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    cipher = TripleDES(key)
    assert cipher.decrypt_block(cipher.encrypt_block(block)) == block


@settings(max_examples=40, deadline=None)
@given(st.binary(min_size=16, max_size=16))
def test_twofish_block_roundtrip_property(block: bytes):
    key = bytes.fromhex("9F589F5CF6122C32B6BFEC2F2AE8C35A")
    cipher = Twofish(key)
    assert cipher.decrypt_block(cipher.encrypt_block(block)) == block


@settings(max_examples=40, deadline=None)
@given(st.binary(min_size=0, max_size=512))
def test_ecb_roundtrip_property(data: bytes):
    mode = ECB(AES(b"K" * 16))
    assert mode.decrypt(mode.encrypt(data)) == data


@settings(max_examples=40, deadline=None)
@given(st.binary(min_size=0, max_size=512))
def test_cbc_roundtrip_property(data: bytes):
    mode = CBC(AES(b"K" * 16))
    iv = b"I" * 16
    assert mode.decrypt(mode.encrypt(data, iv=iv)) == data


@settings(max_examples=40, deadline=None)
@given(st.binary(min_size=0, max_size=512))
def test_ctr_roundtrip_property(data: bytes):
    mode = CTR(AES(b"K" * 16))
    nonce = b"N" * 8
    assert mode.decrypt(mode.encrypt(data, nonce=nonce)) == data


@settings(max_examples=40, deadline=None)
@given(st.binary(min_size=0, max_size=512), st.binary(min_size=0, max_size=64))
def test_gcm_roundtrip_property(data: bytes, aad: bytes):
    mode = GCM(AES(b"K" * 16))
    nonce = b"G" * 12
    encrypted = mode.encrypt(data, nonce=nonce, aad=aad)
    assert mode.decrypt(encrypted, nonce=None, aad=aad) == data


@settings(max_examples=20, deadline=None)
@given(st.binary(min_size=1, max_size=256))
def test_gcm_tamper_detected_property(data: bytes):
    mode = GCM(AES(b"K" * 16))
    encrypted = bytearray(mode.encrypt(data, nonce=b"G" * 12, aad=b"aad"))
    encrypted[-1] ^= 0x01
    with pytest.raises(ValueError):
        mode.decrypt(bytes(encrypted), nonce=None, aad=b"aad")


@settings(max_examples=40, deadline=None)
@given(st.binary(min_size=0, max_size=512))
def test_chacha20_streammode_roundtrip_property(data: bytes):
    primitive = ChaCha20(b"C" * 32)
    mode = StreamMode(primitive)
    assert mode.decrypt(mode.encrypt(data)) == data
