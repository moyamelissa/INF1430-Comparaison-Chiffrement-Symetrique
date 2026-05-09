"""
kat_gcm.py
Known-Answer Tests for AES-GCM (authenticated encryption).

Sources
-------
* NIST SP 800-38D, Appendix B — GCM Test Vectors
  Test Case 1:  AES-128, empty plaintext, empty AAD
  Test Case 2:  AES-128, empty plaintext, empty AAD, different IV
  Test Case 3:  AES-128, 16-byte plaintext, empty AAD
  Test Case 4:  AES-128, 16-byte plaintext, 20-byte AAD

Only cases that exercise our code paths are included (non-empty plaintext).
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from domain.cipher.AES import AES
from domain.mode.GCM import GCM


def _h(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.replace(" ", ""))


def run(verbose: bool = True) -> int:
    """Run all AES-GCM KAT vectors.  Returns number of failures."""
    failures = 0

    # ------------------------------------------------------------------
    # NIST SP 800-38D Appendix B, Test Case 3
    # AES-128, 16-byte plaintext, 12-byte IV (nonce), no AAD
    # ------------------------------------------------------------------
    tc3 = {
        "label":  "SP800-38D TC3 AES-128-GCM",
        "key":    "feffe9928665731c6d6a8f9467308308",
        "nonce":  "cafebabefacedbaddecaf888",
        "plain":  "d9313225f88406e5a55909c5aff5269a"
                  "86a7a9531534f7da2e4c303d8a318a72"
                  "1c3c0c95956809532fcf0e2449a6b525"
                  "b16aedf5aa0de657ba637b391aafd255",
        "cipher": "42831ec2217774244b7221b784d0d49c"
                  "e3aa212f2c02a4e035c17e2329aca12e"
                  "21d514b25466931c7d8f6a5aac84aa05"
                  "1ba30b396a0aac973d58e091473f5985",
        "tag":    "4d5c2af327cd64a62cf35abd2ba6fab4",
    }

    # ------------------------------------------------------------------
    # NIST SP 800-38D Appendix B, Test Case 4
    # AES-128, 60-byte plaintext, 12-byte IV, 20-byte AAD
    # ------------------------------------------------------------------
    tc4 = {
        "label":  "SP800-38D TC4 AES-128-GCM with AAD",
        "key":    "feffe9928665731c6d6a8f9467308308",
        "nonce":  "cafebabefacedbaddecaf888",
        "aad":    "feedfacedeadbeeffeedfacedeadbeef"
                  "abaddad2",
        "plain":  "d9313225f88406e5a55909c5aff5269a"
                  "86a7a9531534f7da2e4c303d8a318a72"
                  "1c3c0c95956809532fcf0e2449a6b525"
                  "b16aedf5aa0de657ba637b39",
        "cipher": "42831ec2217774244b7221b784d0d49c"
                  "e3aa212f2c02a4e035c17e2329aca12e"
                  "21d514b25466931c7d8f6a5aac84aa05"
                  "1ba30b396a0aac973d58e091",
        "tag":    "5bc94fbc3221a5db94fae95ae7121a47",
    }

    for vec in (tc3, tc4):
        key    = _h(vec["key"])
        nonce  = _h(vec["nonce"])
        plain  = _h(vec["plain"])
        cipher = _h(vec["cipher"])
        tag    = _h(vec["tag"])
        aad    = _h(vec.get("aad", ""))
        label  = vec["label"]

        aes = AES(key)
        gcm = GCM(aes)

        # Encrypt — output is nonce(12) || ciphertext || tag(16)
        enc_out = gcm.encrypt(plain, nonce=nonce, aad=aad)
        enc_nonce     = enc_out[:12]
        enc_ciphertext = enc_out[12:-16]
        enc_tag       = enc_out[-16:]

        ok_cipher = enc_ciphertext == cipher
        ok_tag    = enc_tag == tag
        ok        = ok_cipher and ok_tag
        if not ok:
            failures += 1
        if verbose:
            status = "PASS" if ok else "FAIL"
            print(f"  [{status}] {label} encrypt")
            if not ok_cipher:
                print(f"         ciphertext expected: {cipher.hex()}")
                print(f"         ciphertext got:      {enc_ciphertext.hex()}")
            if not ok_tag:
                print(f"         tag expected: {tag.hex()}")
                print(f"         tag got:      {enc_tag.hex()}")

        # Decrypt — feed nonce || ciphertext || tag
        try:
            dec_out = gcm.decrypt(nonce + cipher + tag, nonce=None, aad=aad)
            ok_dec = dec_out == plain
        except ValueError:
            ok_dec = False

        if not ok_dec:
            failures += 1
        if verbose:
            status = "PASS" if ok_dec else "FAIL"
            print(f"  [{status}] {label} decrypt/verify round-trip")
            if not ok_dec:
                print(f"         expected: {plain.hex()}")
                if ok_dec is False and 'dec_out' in dir():
                    print(f"         got:      {dec_out.hex()}")

        # Tamper test — modified tag must raise ValueError
        tampered = nonce + cipher + bytes([tag[0] ^ 0xFF]) + tag[1:]
        tamper_caught = False
        try:
            gcm.decrypt(tampered, nonce=None, aad=aad)
        except ValueError:
            tamper_caught = True

        if not tamper_caught:
            failures += 1
        if verbose:
            status = "PASS" if tamper_caught else "FAIL"
            print(f"  [{status}] {label} tamper detection")

    return failures
