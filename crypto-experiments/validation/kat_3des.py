"""
kat_3des.py
Tests à réponse connue (KAT) pour la primitive Triple-DES (3DES / TDEA).

Sources
-------
Tous les octets de clé dans les vecteurs ci-dessous possèdent une parité DES
impaire (vérifiée), donc adjust_key_parity() de PyCryptodome est sans effet
et les valeurs attendues correspondent.
Les textes chiffrés attendus ont été calculés avec PyCryptodome DES3
(implémentation de référence) et vérifiés par rapport à la spécification
EDE dans NIST SP 800-67 Rev. 2.

  Vecteur A : TDEA à 2 clés (16 octets)
    K1 = 0123456789ABCDEF, K2 = FEDCBA9876543210  (K1 ≠ K2 — valide)
  Vecteur B : TDEA à 3 clés (24 octets)
    K1 = 0123456789ABCDEF, K2 = FEDCBA9876543210, K3 = 89ABCDEF01234567
    (K1 ≠ K2 ≠ K3 ≠ K1 — TDEA à trois clés valide)
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from domain.cipher.TripleDES import TripleDES


def _h(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.replace(" ", ""))


def run(verbose: bool = True) -> int:
    """Exécute tous les vecteurs KAT 3DES. Retourne le nombre d'échecs."""
    failures = 0

    # ------------------------------------------------------------------
    # Tous les octets de clé ont une parité DES impaire vérifiée.
    # Textes chiffrés attendus calculés via PyCryptodome DES3 (référence).
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
