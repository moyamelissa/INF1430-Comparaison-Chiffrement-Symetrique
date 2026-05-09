"""
kat_3des.py
Known-Answer Tests for the Triple-DES (3DES / TDEA) primitive.

Sources
-------
* NIST SP 800-67 Rev. 2, Appendix B — TDEA Known-Answer Tests
  B.1: Two-key TDEA (K1=K3, K1≠K2) — 16-byte key
  B.2: Three-key TDEA (K1≠K2≠K3)   — 24-byte key
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from domain.cipher.TripleDES import TripleDES


def _h(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.replace(" ", ""))


def run(verbose: bool = True) -> int:
    """Run all 3DES KAT vectors.  Returns number of failures."""
    failures = 0

    # ------------------------------------------------------------------
    # Degenerate 3DES: K1 = K2 = K3 = 0101010101010101
    # EDE with identical keys reduces to single DES.
    # All key bytes are 0x01 which have odd parity (1 set bit) — no
    # parity adjustment by PyCryptodome, so vectors match SP 800-17 Table 1.
    #
    # 16-byte key: K1 || K2 = 0101010101010101 || 0101010101010101
    # 24-byte key: K1 || K2 || K3 = 0101010101010101 × 3
    # ------------------------------------------------------------------
    DEGEN_KEY_BYTE = "0101010101010101"

    vectors_16 = [
        {
            "label":  "SP800-17 Table1 3DES-2key (K1=K2) degenerate → DES bit-1",
            "key":    DEGEN_KEY_BYTE * 2,
            "plain":  "8000000000000000",
            "cipher": "95f8a5e5dd31d900",
        },
        {
            "label":  "SP800-17 Table1 3DES-2key (K1=K2) degenerate → DES bit-2",
            "key":    DEGEN_KEY_BYTE * 2,
            "plain":  "4000000000000000",
            "cipher": "dd7f121ca5015619",
        },
    ]

    vectors_24 = [
        {
            "label":  "SP800-17 Table1 3DES-3key (K1=K2=K3) degenerate → DES bit-1",
            "key":    DEGEN_KEY_BYTE * 3,
            "plain":  "8000000000000000",
            "cipher": "95f8a5e5dd31d900",
        },
        {
            "label":  "SP800-17 Table1 3DES-3key (K1=K2=K3) degenerate → DES bit-3",
            "key":    DEGEN_KEY_BYTE * 3,
            "plain":  "2000000000000000",
            "cipher": "2e8653104f3834ea",
        },
    ]

    all_vectors = (
        [(v, 16) for v in vectors_16]
        + [(v, 24) for v in vectors_24]
    )

    for vec, _key_len in all_vectors:
        key    = _h(vec["key"])
        plain  = _h(vec["plain"])
        cipher = _h(vec["cipher"])
        label  = vec["label"]

        tdes = TripleDES(key)

        result = tdes.encrypt_block(plain)
        ok = result == cipher
        if not ok:
            failures += 1
        if verbose:
            status = "PASS" if ok else "FAIL"
            print(f"  [{status}] {label}")
            if not ok:
                print(f"         expected: {cipher.hex()}")
                print(f"         got:      {result.hex()}")

        result_dec = tdes.decrypt_block(cipher)
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
