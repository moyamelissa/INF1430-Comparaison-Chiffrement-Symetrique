"""
kat_des.py
Known-Answer Tests for the DES primitive.

Sources
-------
* NIST SP 800-17, Table 1 (Variable plaintext known-answer test, key=01..01)
* Widely used DES KAT vectors from NIST validation suite
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from domain.cipher.DES import DES


def _h(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.replace(" ", ""))


def run(verbose: bool = True) -> int:
    """Run all DES KAT vectors.  Returns number of failures."""
    failures = 0

    # ------------------------------------------------------------------
    # NIST SP 800-17 Table 1 — Variable Plaintext KAT
    # key = 0101010101010101 (all parity bits set, effective key = 0)
    # A subset of the 64 vectors; these cover the first 8 and last entry.
    # ------------------------------------------------------------------
    vectors = [
        # (plaintext_hex, ciphertext_hex)
        ("8000000000000000", "95f8a5e5dd31d900"),
        ("4000000000000000", "dd7f121ca5015619"),
        ("2000000000000000", "2e8653104f3834ea"),
        ("1000000000000000", "4bd388ff6cd81d4f"),
        ("0800000000000000", "20b9e767b2fb1456"),
        ("0400000000000000", "55579380d77138ef"),
        ("0200000000000000", "6cc5defaaf04512f"),
        ("0100000000000000", "0d9f279ba5d87260"),
        # Last entry in Table 1 (bit 64 set)
        ("0000000000000001", "166b40b44aba4bd6"),
    ]

    des_key = _h("0101010101010101")

    for plain_hex, cipher_hex in vectors:
        label  = f"SP800-17 Table1 P={plain_hex}"
        plain  = _h(plain_hex)
        cipher = _h(cipher_hex)

        des = DES(des_key)

        result = des.encrypt_block(plain)
        ok = result == cipher
        if not ok:
            failures += 1
        if verbose:
            status = "PASS" if ok else "FAIL"
            print(f"  [{status}] {label}")
            if not ok:
                print(f"         expected: {cipher.hex()}")
                print(f"         got:      {result.hex()}")

        result_dec = des.decrypt_block(cipher)
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
