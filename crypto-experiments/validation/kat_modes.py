"""
kat_modes.py
Tests à réponse connue (KAT) pour les modes opératoires ECB, CBC et CTR.

Sources
-------
* NIST SP 800-38A (2001), Annexe F
  F.1 — ECB avec AES-128  (la direction chiffrement correspond aux vecteurs officiels)
  F.2 — CBC avec AES-128  (la direction chiffrement correspond aux vecteurs officiels)
  F.5 — CTR avec AES-128  (vérification ponctuelle du train de clés ; voir note ci-dessous)

Notes sur CTR :
  SP 800-38A initialise le bloc compteur à une valeur arbitraire de 16 octets
  (000102...0f), tandis que notre CTR commence toujours le compteur 8 octets à 0 et
  stocke un préfixe de nonce frais de 8 octets. Le test vérifie donc :
    1. Que E(CLÉ, nonce||0) produit le premier bloc de train de clés attendu.
    2. Un aller-retour complet chiffrement→déchiffrement sur les quatre blocs de
       texte clair SP 800-38A, confirmant la correction du CTR multi-blocs.

Les tests de déchiffrement ECB/CBC utilisent la sortie de notre propre encrypt()
comme entrée de decrypt(), éliminant le besoin d'ajouter manuellement le bloc
de rembourrage PKCS7 chiffré (qui dépend de l'algorithme).
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
# Clé et IV partagés SP 800-38A
# ---------------------------------------------------------------------------
KEY = _h("2b7e151628aed2a6abf7158809cf4f3c")
IV  = _h("000102030405060708090a0b0c0d0e0f")  # utilisé pour CBC

# Quatre blocs de texte clair extraits de SP 800-38A
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
    # F.1  ECB-AES128 Chiffrement + aller-retour déchiffrement
    # ------------------------------------------------------------------
    ecb_ciphertext = b"".join([
        _h("3ad77bb40d7a3660a89ecaf32466ef97"),
        _h("f5d3d58503b9699de785895a96fdbaaf"),
        _h("43b1cd7f598ece23881b00e3ed030688"),
        _h("7b0c785e27e8ad3f8223207104725dd4"),
    ])

    aes = AES(KEY)
    ecb = ECB(aes)

    # Notre ECB.encrypt ajoute un bloc de rembourrage PKCS7 pour une entrée alignée sur les blocs.
    ecb_enc = ecb.encrypt(PLAINTEXT)
    ecb_enc_payload = ecb_enc[: len(ecb_ciphertext)]  # les 4 premiers blocs = vecteurs NIST

    ok = ecb_enc_payload == ecb_ciphertext
    if not ok:
        failures += 1
    if verbose:
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] SP800-38A F.1.1 ECB-AES128 Encrypt")
        if not ok:
            print(f"         expected: {ecb_ciphertext.hex()}")
            print(f"         got:      {ecb_enc_payload.hex()}")

    # Déchiffrement : fournit la sortie complète de encrypt() (inclut le bloc de rembourrage chiffré)
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
    # F.2  CBC-AES128 Chiffrement + aller-retour déchiffrement
    # ------------------------------------------------------------------
    cbc_ciphertext = b"".join([
        _h("7649abac8119b246cee98e9b12e9197d"),
        _h("5086cb9b507219ee95db113a917678b2"),
        _h("73bed6b8e3c1743b7116e69e22229516"),
        _h("3ff1caa1681fac09120eca307586e1a7"),
    ])

    aes2 = AES(KEY)
    cbc  = CBC(aes2)

    # Sortie de notre CBC.encrypt : IV(16) || texte chiffré || bloc_rembourrage_chiffré
    cbc_enc = cbc.encrypt(PLAINTEXT, iv=IV)
    # Charge utile : ignorer l'IV préfixé (16 o), prendre les 64 o suivants = 4 blocs chiffrés
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

    # Déchiffrement : fournit la sortie complète de encrypt() (IV + texte chiffré + bloc rembourrage)
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
    # CTR-AES128  vérification ponctuelle du train de clés + aller-retour
    #
    # Notre CTR : counter_block[i] = nonce(8 o) || i(8 o big-endian), i commence à 0.
    # SP 800-38A utilise nonce = 0001020304050607, compteur initial = 0 (aligné).
    # Premier bloc de train de clés = E(CLÉ, 0001020304050607 || 0000000000000000).
    # ------------------------------------------------------------------
    ctr_nonce = _h("0001020304050607")

    aes3 = AES(KEY)

    # Calcul manuel du premier bloc de train de clés attendu
    counter_block_0 = ctr_nonce + b"\x00" * 8
    expected_ks0 = aes3.encrypt_block(counter_block_0)

    ctr = CTR(aes3)
    ctr_enc = ctr.encrypt(PLAINTEXT, nonce=ctr_nonce)
    # Sortie de notre CTR : nonce(8) || texte chiffré(64)
    actual_ks0_xored = ctr_enc[8 : 24]  # les 16 premiers octets du texte chiffré
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

    # Aller-retour complet
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
