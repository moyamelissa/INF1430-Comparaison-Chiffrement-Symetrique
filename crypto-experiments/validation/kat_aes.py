"""
kat_aes.py
Known-Answer Tests for the AES primitive.

Sources
-------
* FIPS 197, Appendix B  — AES-128 encrypt/decrypt
* NIST FIPS 197, Appendix C.1 — AES-128 (already same as B but cross-checked)
* NIST Key Expansion Appendix A.1/A.2/A.3 — AES-128/192/256

The vectors below are taken directly from the official NIST publications.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from domain.cipher.AES import AES

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _h(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.replace(" ", ""))


def run(verbose: bool = True) -> int:
    """Run all AES KAT vectors.  Returns number of failures."""
    failures = 0

    # ------------------------------------------------------------------
    # AES-128  FIPS 197 Appendix B
    # ------------------------------------------------------------------
    vectors_128 = [
        {
            "label": "FIPS197 App-B AES-128 encrypt",
            "key":   "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c",
            "plain": "32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34",
            "cipher":"39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32",
        },
        # NIST AES-128 ECB Monte-Carlo first step (FIPS 197 Appendix A.1)
        {
            "label": "FIPS197 App-A.1 AES-128 zero-key zero-plain",
            "key":   "00000000000000000000000000000000",
            "plain": "00000000000000000000000000000000",
            "cipher":"66e94bd4ef8a2c3b884cfa59ca342b2e",
        },
    ]

    # ------------------------------------------------------------------
    # AES-192  FIPS 197 Appendix C.2
    # ------------------------------------------------------------------
    vectors_192 = [
        {
            "label": "FIPS197 App-C.2 AES-192 encrypt",
            "key":   "000102030405060708090a0b0c0d0e0f1011121314151617",
            "plain": "00112233445566778899aabbccddeeff",
            "cipher":"dda97ca4864cdfe06eaf70a0ec0d7191",
        },
    ]

    # ------------------------------------------------------------------
    # AES-256  FIPS 197 Appendix C.3
    # ------------------------------------------------------------------
    vectors_256 = [
        {
            "label": "FIPS197 App-C.3 AES-256 encrypt",
            "key":   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "plain": "00112233445566778899aabbccddeeff",
            "cipher":"8ea2b7ca516745bfeafc49904b496089",
        },
    ]

    all_vectors = (
        [(v, 16) for v in vectors_128]
        + [(v, 24) for v in vectors_192]
        + [(v, 32) for v in vectors_256]
    )

    for vec, _key_len in all_vectors:
        key    = _h(vec["key"])
        plain  = _h(vec["plain"])
        cipher = _h(vec["cipher"])
        label  = vec["label"]

        aes = AES(key)

        # Encrypt
        result = aes.encrypt_block(plain)
        ok = result == cipher
        if not ok:
            failures += 1
        if verbose:
            status = "PASS" if ok else "FAIL"
            print(f"  [{status}] {label}")
            if not ok:
                print(f"         expected: {cipher.hex()}")
                print(f"         got:      {result.hex()}")

        # Decrypt (round-trip)
        result_dec = aes.decrypt_block(cipher)
        ok_dec = result_dec == plain
        if not ok_dec:
            failures += 1
        if verbose:
            status = "PASS" if ok_dec else "FAIL"
            print(f"  [{status}] {label} (decrypt round-trip)")
            if not ok_dec:
                print(f"         expected: {plain.hex()}")
                print(f"         got:      {result_dec.hex()}")

    return failures
