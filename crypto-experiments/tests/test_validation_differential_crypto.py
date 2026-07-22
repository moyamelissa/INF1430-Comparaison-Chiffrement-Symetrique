from __future__ import annotations

from unittest.mock import patch

from hypothesis import given, settings, strategies as st
from Crypto.Cipher import AES as RefAES
from Crypto.Cipher import DES as RefDES
from Crypto.Cipher import DES3 as RefDES3
from Crypto.Cipher import ChaCha20 as RefChaCha20

from domain.cipher import AES, DES, TripleDES
from domain.cipher.ChaCha20 import ChaCha20
from domain.mode import GCM


@settings(max_examples=30, deadline=None)
@given(
    key=st.binary(min_size=16, max_size=16),
    block=st.binary(min_size=16, max_size=16),
)
def test_aes_block_matches_reference(key: bytes, block: bytes):
    ours = AES(key).encrypt_block(block)
    ref = RefAES.new(key, RefAES.MODE_ECB).encrypt(block)
    assert ours == ref


@settings(max_examples=30, deadline=None)
@given(
    key=st.binary(min_size=8, max_size=8),
    block=st.binary(min_size=8, max_size=8),
)
def test_des_block_matches_reference(key: bytes, block: bytes):
    ours = DES(key).encrypt_block(block)
    ref = RefDES.new(key, RefDES.MODE_ECB).encrypt(block)
    assert ours == ref


@settings(max_examples=30, deadline=None)
@given(
    key=st.binary(min_size=24, max_size=24),
    block=st.binary(min_size=8, max_size=8),
)
def test_3des_block_matches_reference(key: bytes, block: bytes):
    # Skip keys rejected by reference provider as weak/degenerate.
    try:
        ref_key = RefDES3.adjust_key_parity(key)
        ref = RefDES3.new(ref_key, RefDES3.MODE_ECB).encrypt(block)
    except ValueError:
        return

    ours = TripleDES(key).encrypt_block(block)
    assert ours == ref


@settings(max_examples=20, deadline=None)
@given(
    key=st.binary(min_size=32, max_size=32),
    nonce=st.binary(min_size=12, max_size=12),
    data=st.binary(min_size=0, max_size=128),
)
def test_chacha20_matches_reference_when_nonce_is_fixed(
    key: bytes,
    nonce: bytes,
    data: bytes,
):
    with patch("domain.cipher.ChaCha20.os.urandom", return_value=nonce):
        ours_packet = ChaCha20(key).encrypt_block(data)
    ours_nonce, ours_cipher = ours_packet[:12], ours_packet[12:]

    ref_cipher = RefChaCha20.new(key=key, nonce=nonce).encrypt(data)
    assert ours_nonce == nonce
    assert ours_cipher == ref_cipher


@settings(max_examples=20, deadline=None)
@given(
    key=st.binary(min_size=16, max_size=16),
    nonce=st.binary(min_size=12, max_size=12),
    aad=st.binary(min_size=0, max_size=64),
    data=st.binary(min_size=0, max_size=128),
)
def test_gcm_packet_matches_reference(
    key: bytes,
    nonce: bytes,
    aad: bytes,
    data: bytes,
):
    ours_packet = GCM(AES(key)).encrypt(data, nonce=nonce, aad=aad)
    ours_nonce, ours_cipher, ours_tag = ours_packet[:12], ours_packet[12:-16], ours_packet[-16:]

    ref = RefAES.new(key, RefAES.MODE_GCM, nonce=nonce)
    if aad:
        ref.update(aad)
    ref_cipher, ref_tag = ref.encrypt_and_digest(data)

    assert ours_nonce == nonce
    assert ours_cipher == ref_cipher
    assert ours_tag == ref_tag
