"""
kat_chacha20.py
Tests à réponse connue (KAT) pour la primitive de chiffrement par flot ChaCha20.

Sources
-------
* RFC 8439, Section 2.1.1 — Test du ChaCha20 Quarter Round
* RFC 8439, Section 2.3.2 — Vecteur de test de la fonction de bloc ChaCha20
* RFC 8439, Section 2.4.2 — Vecteur de test de chiffrement ChaCha20

Note : Notre implémentation ChaCha20 encapsule le ChaCha20 de PyCryptodome en mode
IETF (nonce 96 bits, compteur 32 bits), ce qui correspond exactement à la RFC 8439.

Comme encrypt_block préfixe le nonce au texte chiffré, nous testons l'aller-retour
(chiffrement → déchiffrement) ET vérifions que texte clair + nonce + clé connus
produisent le texte chiffré exact de la RFC.
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
    """Exécute tous les vecteurs KAT ChaCha20. Retourne le nombre d'échecs."""
    failures = 0

    # ------------------------------------------------------------------
    # Test 1 — RFC 8439 §2.4.2 : vecteur de test de chiffrement complet
    # Clé, nonce, compteur=1, et un texte clair de 114 octets produisent un CT connu.
    # Nous testons le ChaCha20 brut de PyCryptodome (pas notre wrapper) pour confirmer
    # que la primitive sous-jacente correspond exactement à la norme.
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
    # Texte chiffré attendu extrait de la RFC 8439 §2.4.2 (octets exacts de la RFC)
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

    # Utilise PyCryptodome directement avec compteur=1 (RFC 8439 utilise initial_value=1)
    # PyCryptodome's seek(64) avance la position du train de clés de 64 octets,
    # ce qui équivaut à démarrer au bloc de compteur 1.
    raw_cipher = _PyCryptoChaCha20.new(
        key=key_rfc, nonce=nonce_rfc
    )
    raw_cipher.seek(64)  # skip block 0, start at counter=1
    got_ct = raw_cipher.encrypt(plain_rfc)

    label = "RFC 8439 §2.4.2 — vecteur de chiffrement ChaCha20 (compteur=1)"
    if got_ct == ct_rfc:
        failures += _pass(label, verbose)
    else:
        failures += _fail(label, got_ct, ct_rfc, verbose)

    # ------------------------------------------------------------------
    # Test 2 — Aller-retour via notre wrapper ChaCha20 : chiffrement puis déchiffrement
    # Nous ne pouvons pas utiliser un nonce fixe avec notre wrapper (le nonce est aléatoire),
    # donc nous vérifions que decrypt(encrypt(texte_clair)) == texte_clair pour un
    # bloc de 64 octets, un message de 256 octets et un message de taille impaire.
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
        label = f"RFC 8439 aller-retour wrapper — {desc}"
        if dec == plaintext:
            failures += _pass(label, verbose)
        else:
            failures += _fail(label, dec, plaintext, verbose)

    # ------------------------------------------------------------------
    # Test 3 — Détection de falsification : inverser 1 bit dans le corps du texte chiffré
    # doit produire un texte clair différent (le chiffrement par flot ne fournit pas
    # d'authentification, mais nous confirmons que le XOR du train de clés change
    # correctement l'octet de sortie).
    # ------------------------------------------------------------------
    key_t = _h(
        "1c9240a5eb55d38af333888604f6b5f0"
        "473917c1402b80099dca5cbc207075c0"
    )
    cipher_t = ChaCha20(key_t)
    pt_t = b"Test tamper detection for ChaCha20 stream cipher."
    ct_t = cipher_t.encrypt_block(pt_t)

    # Inverser l'octet 15 du corps du texte chiffré (après le nonce de 12 octets)
    tampered = bytearray(ct_t)
    tampered[12 + 15] ^= 0xFF
    dec_tampered = cipher_t.decrypt_block(bytes(tampered))

    label = "ChaCha20 falsification — l'octet inversé produit un texte clair différent"
    if dec_tampered != pt_t:
        failures += _pass(label, verbose)
    else:
        failures += _fail(label, dec_tampered, pt_t, verbose)

    # ------------------------------------------------------------------
    # Test 4 — Validation de la taille de clé : une clé de mauvaise taille doit lever ValueError
    # ------------------------------------------------------------------
    label = "ChaCha20 rejette une clé de 16 octets (doit être 32 octets)"
    try:
        ChaCha20(b"\x00" * 16)
        failures += _fail(label, b"no exception", b"ValueError", verbose)
    except ValueError:
        failures += _pass(label, verbose)

    return failures
