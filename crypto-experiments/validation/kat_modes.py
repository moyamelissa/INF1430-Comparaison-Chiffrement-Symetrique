"""
kat_modes.py
Known-Answer Tests for ECB, CBC, and CTR operation modes.

Sources
-------
* NIST SP 800-38A (2001), Appendix F
  F.1 — ECB with AES-128  (encrypt direction matches official vectors)
  F.2 — CBC with AES-128  (encrypt direction matches official vectors)
  F.5 — CTR with AES-128  (keystream spot-check; see note below)

Notes on CTR:
  SP 800-38A initialises the counter block to an arbitrary 16-byte value
  (000102...0f), whereas our CTR always starts the 8-byte counter at 0 and
  stores a fresh 8-byte nonce prefix.  The test therefore verifies:
    1. That E(KEY, nonce||0) produces the expected first keystream block.
    2. A full encrypt→decrypt round-trip over the four SP 800-38A plaintext
       blocks, confirming correctness of multi-block CTR operation.

ECB/CBC decrypt tests use the output of our own encrypt() as the input to
decrypt(), eliminating the need to manually append the PKCS7 padding block
ciphertext (which is algorithm-dependent).
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from domain.cipher.AES import AES
from domain.mode.ECB import ECB
from domain.mode.CBC import CBC
from domain.mode.CTR import CTR


def _h(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.replace(" ", ""))


# ---------------------------------------------------------------------------
# SP 800-38A shared key and IV
# ---------------------------------------------------------------------------
KEY = _h("2b7e151628aed2a6abf7158809cf4f3c")
IV  = _h("000102030405060708090a0b0c0d0e0f")  # used for CBC

# Four plaintext blocks from SP 800-38A
PT_BLOCKS = [
    _h("6bc1bee22e409f96e93d7e117393172a"),
    _h("ae2d8a571e03ac9c9eb76fac45af8e51"),
    _h("30c81c46a35ce411e5fbc1191a0a52ef"),
    _h("f69f2445df4f9b17ad2b417be66c3710"),
]
PLAINTEXT = b"".join(PT_BLOCKS)


def run(verbose: bool = True) -> int:
    failures = 0

    # ------------------------------------------------------------------
    # F.1  ECB-AES128 Encrypt + decrypt round-trip
    # ------------------------------------------------------------------
    ecb_ciphertext = b"".join([
        _h("3ad77bb40d7a3660a89ecaf32466ef97"),
        _h("f5d3d58503b9699de785895a96fdbaaf"),
        _h("43b1cd7f598ece23881b00e3ed030688"),
        _h("7b0c785e27e8ad3f8223207104725dd4"),
    ])

    aes = AES(KEY)
    ecb = ECB(aes)

    # Our ECB.encrypt appends a PKCS7 padding block for block-aligned input.
    ecb_enc = ecb.encrypt(PLAINTEXT)
    ecb_enc_payload = ecb_enc[: len(ecb_ciphertext)]  # first 4 blocks = NIST vectors

    ok = ecb_enc_payload == ecb_ciphertext
    if not ok:
        failures += 1
    if verbose:
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] SP800-38A F.1.1 ECB-AES128 Encrypt")
        if not ok:
            print(f"         expected: {ecb_ciphertext.hex()}")
            print(f"         got:      {ecb_enc_payload.hex()}")

    # Decrypt: feed the full encrypt() output (includes padding block ciphertext)
    ecb_dec = ecb.decrypt(ecb_enc)
    ok_dec = ecb_dec == PLAINTEXT
    if not ok_dec:
        failures += 1
    if verbose:
        status = "PASS" if ok_dec else "FAIL"
        print(f"  [{status}] SP800-38A F.1.2 ECB-AES128 Decrypt round-trip")
        if not ok_dec:
            print(f"         expected: {PLAINTEXT.hex()}")
            print(f"         got:      {ecb_dec.hex()}")

    # ------------------------------------------------------------------
    # F.2  CBC-AES128 Encrypt + decrypt round-trip
    # ------------------------------------------------------------------
    cbc_ciphertext = b"".join([
        _h("7649abac8119b246cee98e9b12e9197d"),
        _h("5086cb9b507219ee95db113a917678b2"),
        _h("73bed6b8e3c1743b7116e69e22229516"),
        _h("3ff1caa1681fac09120eca307586e1a7"),
    ])

    aes2 = AES(KEY)
    cbc  = CBC(aes2)

    # Our CBC.encrypt output: IV(16) || ciphertext || padding_block_ciphertext
    cbc_enc = cbc.encrypt(PLAINTEXT, iv=IV)
    # Payload: skip prepended IV (16 B), take next 64 B = 4 ciphertext blocks
    cbc_enc_payload = cbc_enc[16 : 16 + len(cbc_ciphertext)]

    ok = cbc_enc_payload == cbc_ciphertext
    if not ok:
        failures += 1
    if verbose:
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] SP800-38A F.2.1 CBC-AES128 Encrypt")
        if not ok:
            print(f"         expected: {cbc_ciphertext.hex()}")
            print(f"         got:      {cbc_enc_payload.hex()}")

    # Decrypt: feed the full encrypt() output (IV + ciphertext + padding block)
    cbc_dec = cbc.decrypt(cbc_enc)
    ok_dec = cbc_dec == PLAINTEXT
    if not ok_dec:
        failures += 1
    if verbose:
        status = "PASS" if ok_dec else "FAIL"
        print(f"  [{status}] SP800-38A F.2.2 CBC-AES128 Decrypt round-trip")
        if not ok_dec:
            print(f"         expected: {PLAINTEXT.hex()}")
            print(f"         got:      {cbc_dec.hex()}")

    # ------------------------------------------------------------------
    # CTR-AES128  keystream spot-check + round-trip
    #
    # Our CTR: counter_block[i] = nonce(8 B) || i(8 B big-endian), i starts at 0.
    # SP 800-38A uses nonce = 0001020304050607, initial counter = 0 (aligned).
    # First keystream block = E(KEY, 0001020304050607 || 0000000000000000).
    # ------------------------------------------------------------------
    ctr_nonce = _h("0001020304050607")

    aes3 = AES(KEY)

    # Manually compute expected first keystream block
    counter_block_0 = ctr_nonce + b"\x00" * 8
    expected_ks0 = aes3.encrypt_block(counter_block_0)

    ctr = CTR(aes3)
    ctr_enc = ctr.encrypt(PLAINTEXT, nonce=ctr_nonce)
    # Our CTR output: nonce(8) || ciphertext(64)
    actual_ks0_xored = ctr_enc[8 : 24]  # first 16 bytes of ciphertext
    actual_ks0 = bytes(c ^ p for c, p in zip(actual_ks0_xored, PT_BLOCKS[0]))

    ok = actual_ks0 == expected_ks0
    if not ok:
        failures += 1
    if verbose:
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] CTR-AES128 keystream block-0 spot-check (counter=0)")
        if not ok:
            print(f"         expected keystream: {expected_ks0.hex()}")
            print(f"         got keystream:      {actual_ks0.hex()}")

    # Full round-trip
    ctr_dec = ctr.decrypt(ctr_enc)
    ok_dec = ctr_dec == PLAINTEXT
    if not ok_dec:
        failures += 1
    if verbose:
        status = "PASS" if ok_dec else "FAIL"
        print(f"  [{status}] CTR-AES128 encrypt→decrypt round-trip (4 blocks)")
        if not ok_dec:
            print(f"         expected: {PLAINTEXT.hex()}")
            print(f"         got:      {ctr_dec.hex()}")

    return failures
