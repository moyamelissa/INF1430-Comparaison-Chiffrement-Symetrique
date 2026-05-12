"""
kat_3des.py
Known-Answer Tests for the Triple-DES (3DES / TDEA) primitive.

Sources
-------
All key bytes in the vectors below have odd DES parity (verified), so
PyCryptodome's adjust_key_parity() is a no-op and expected values match.
Expected ciphertexts were computed with PyCryptodome DES3 (reference
implementation) and cross-checked against the EDE specification in
NIST SP 800-67 Rev. 2.

  Vector A: 16-byte 2-key TDEA
    K1 = 0123456789ABCDEF, K2 = FEDCBA9876543210  (K1 ≠ K2 — valid)
  Vector B: 24-byte 3-key TDEA
    K1 = 0123456789ABCDEF, K2 = FEDCBA9876543210, K3 = 89ABCDEF01234567
    (K1 ≠ K2 ≠ K3 ≠ K1 — valid three-key TDEA)
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
    # All key bytes have been verified to have odd DES parity.
    # Expected ciphertexts computed via PyCryptodome DES3 reference.
    # ------------------------------------------------------------------
    vectors_16 = [
        {
            "label":  "3DES-2key TDEA K1≠K2 plain=0x00..00",
            "key":    "0123456789ABCDEFFEDCBA9876543210",
            "plain":  "0000000000000000",
            "cipher": "08d7b4fb629d0885",
        },
    ]

    vectors_24 = [
        {
            "label":  "3DES-3key TDEA K1≠K2≠K3 plain=0x00..00",
            "key":    "0123456789ABCDEFFEDCBA987654321089ABCDEF01234567",
            "plain":  "0000000000000000",
            "cipher": "3fd539e3abeb8b5b",
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
