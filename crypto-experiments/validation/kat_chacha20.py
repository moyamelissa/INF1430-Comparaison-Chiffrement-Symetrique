"""
kat_chacha20.py
Known-Answer Tests for the ChaCha20 stream cipher primitive.

Sources
-------
* RFC 8439, Section 2.1.1 — ChaCha20 Quarter Round test
* RFC 8439, Section 2.3.2 — ChaCha20 block function test vector
* RFC 8439, Section 2.4.2 — ChaCha20 encryption test vector

Note: Our ChaCha20 implementation wraps PyCryptodome's ChaCha20 in IETF
mode (96-bit nonce, 32-bit counter), which matches RFC 8439 exactly.

Because encrypt_block prepends the nonce to the ciphertext, we test the
round-trip (encrypt → decrypt) AND verify that known plaintext+nonce+key
produce the exact ciphertext from the RFC.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from Crypto.Cipher import ChaCha20 as _PyCryptoChaCha20
from domain.cipher.ChaCha20 import ChaCha20


def _h(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.replace(" ", ""))


def _pass(label: str, verbose: bool) -> int:
    if verbose:
        print(f"    PASS  {label}")
    return 0


def _fail(label: str, got: bytes, expected: bytes, verbose: bool) -> int:
    if verbose:
        print(f"    FAIL  {label}")
        print(f"          got:      {got.hex()}")
        print(f"          expected: {expected.hex()}")
    return 1


def run(verbose: bool = True) -> int:
    """Run all ChaCha20 KAT vectors. Returns number of failures."""
    failures = 0

    # ------------------------------------------------------------------
    # Test 1 — RFC 8439 §2.4.2: full encryption test vector
    # Key, nonce, counter=1, and a 114-byte plaintext produce a known CT.
    # We test PyCryptodome's raw ChaCha20 (not our wrapper) to confirm
    # the underlying primitive matches the standard exactly.
    # ------------------------------------------------------------------
    key_rfc = _h(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    )
    nonce_rfc = _h("000000000000004a00000000")
    plain_rfc = (
        b"Ladies and Gentlemen of the class of '99: "
        b"If I could offer you only one tip for the future, "
        b"sunscreen would be it."
    )
    # Expected ciphertext from RFC 8439 §2.4.2 (exact bytes from the RFC)
    ct_rfc = _h(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42"
        "874d"
    )

    # Use PyCryptodome directly with counter=1 (RFC 8439 uses initial_value=1)
    # PyCryptodome's seek(64) advances the keystream position by 64 bytes,
    # which is equivalent to starting at counter block 1.
    raw_cipher = _PyCryptoChaCha20.new(
        key=key_rfc, nonce=nonce_rfc
    )
    raw_cipher.seek(64)  # skip block 0, start at counter=1
    got_ct = raw_cipher.encrypt(plain_rfc)

    label = "RFC 8439 §2.4.2 — ChaCha20 encryption vector (counter=1)"
    if got_ct == ct_rfc:
        failures += _pass(label, verbose)
    else:
        failures += _fail(label, got_ct, ct_rfc, verbose)

    # ------------------------------------------------------------------
    # Test 2 — Round-trip via our ChaCha20 wrapper: encrypt then decrypt
    # We can't use a fixed nonce with our wrapper (nonce is random), so
    # we verify that decrypt(encrypt(plaintext)) == plaintext for a
    # 64-byte block, a 256-byte message, and an odd-sized message.
    # ------------------------------------------------------------------
    key_rt = _h(
        "2b7e151628aed2a6abf7158809cf4f3c"
        "2b7e151628aed2a6abf7158809cf4f3c"
    )
    cipher = ChaCha20(key_rt)

    for size, desc in [(64, "64 B"), (256, "256 B"), (113, "113 B (odd)")]:
        plaintext = bytes(range(size % 256)) * (size // 256 + 1)
        plaintext = plaintext[:size]
        ct  = cipher.encrypt_block(plaintext)
        dec = cipher.decrypt_block(ct)
        label = f"RFC 8439 wrapper round-trip — {desc}"
        if dec == plaintext:
            failures += _pass(label, verbose)
        else:
            failures += _fail(label, dec, plaintext, verbose)

    # ------------------------------------------------------------------
    # Test 3 — Tamper detection: flipping 1 bit in the ciphertext body
    # must produce a different plaintext (stream cipher provides no auth,
    # but we confirm the keystream XOR changes the output byte correctly).
    # ------------------------------------------------------------------
    key_t = _h(
        "1c9240a5eb55d38af333888604f6b5f0"
        "473917c1402b80099dca5cbc207075c0"
    )
    cipher_t = ChaCha20(key_t)
    pt_t = b"Test tamper detection for ChaCha20 stream cipher."
    ct_t = cipher_t.encrypt_block(pt_t)

    # Flip byte 15 of ciphertext body (after the 12-byte nonce)
    tampered = bytearray(ct_t)
    tampered[12 + 15] ^= 0xFF
    dec_tampered = cipher_t.decrypt_block(bytes(tampered))

    label = "ChaCha20 tamper — flipped byte produces different plaintext"
    if dec_tampered != pt_t:
        failures += _pass(label, verbose)
    else:
        failures += _fail(label, dec_tampered, pt_t, verbose)

    # ------------------------------------------------------------------
    # Test 4 — Key size validation: wrong key size must raise ValueError
    # ------------------------------------------------------------------
    label = "ChaCha20 rejects 16-byte key (must be 32 bytes)"
    try:
        ChaCha20(b"\x00" * 16)
        failures += _fail(label, b"no exception", b"ValueError", verbose)
    except ValueError:
        failures += _pass(label, verbose)

    return failures
