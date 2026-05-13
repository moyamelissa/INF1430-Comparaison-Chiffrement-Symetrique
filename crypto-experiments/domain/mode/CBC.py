"""
CBC.py
Mode d'opération CBC (Cipher Block Chaining) — NIST SP 800-38A.

Chaque bloc de texte en clair est XORé avec le bloc de texte chiffré précédent
avant le chiffrement. Un vecteur d'initialisation (IV) est XORé avec le premier
bloc, garantissant que des textes en clair identiques chiffrés avec des IV
différents produisent des textes chiffrés différents.

Rembourrage : PKCS#7 est appliqué pour accepter des messages de toute longueur.
IV : doit faire exactement ``primitive.block_size`` octets.
"""

import os

from domain.cipher.CipherPrimitive import CipherPrimitive
from .OperationMode import OperationMode


def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

class CBC(OperationMode):
    """
    Mode CBC (Cipher Block Chaining) — NIST SP 800-38A, section 6.2.

    Nécessite un IV de ``primitive.block_size`` octets. Si aucun IV n'est fourni
    lors du chiffrement, un IV aléatoire est généré ; il doit être passé
    explicitement lors du déchiffrement.
    """

    def __init__(self, primitive: CipherPrimitive) -> None:
        super().__init__(primitive)

    def encrypt(self, plaintext: bytes, iv: bytes | None = None, **kwargs) -> bytes:
        """
        Chiffre ``plaintext`` en mode CBC.

        Paramètres
        ----------
        plaintext : bytes
            Texte en clair de longueur arbitraire.
        iv : bytes, optionnel
            Vecteur d'initialisation de ``block_size`` octets.
            Un IV aléatoire est généré automatiquement si omis.

        Retourne
        --------
        bytes
            IV préfixé au texte chiffré (IV || texte chiffré).
        """
        bs = self._primitive.block_size
        if iv is None:
            iv = os.urandom(bs)
        if len(iv) != bs:
            raise ValueError(f"IV must be exactly {bs} bytes; got {len(iv)}.")

        padded = _pkcs7_pad(plaintext, bs)
        ciphertext = bytearray()
        prev = iv
        for i in range(0, len(padded), bs):
            block = _xor(padded[i : i + bs], prev)
            encrypted = self._primitive.encrypt_block(block)
            ciphertext += encrypted
            prev = encrypted

        # IV préfixé pour que decrypt() puisse le récupérer
        return iv + bytes(ciphertext)

    def decrypt(self, ciphertext: bytes, iv: bytes | None = None, **kwargs) -> bytes:
        """
        Déchiffre ``ciphertext`` produit par CBC.encrypt().

        Paramètres
        ----------
        ciphertext : bytes
            IV || texte chiffré (tel que retourné par encrypt) si ``iv`` est None,
            ou texte chiffré brut si ``iv`` est fourni explicitement.
        iv : bytes, optionnel
            IV explicite. Si None, l'IV est lu dans les premiers
            ``block_size`` octets de ``ciphertext``.

        Retourne
        --------
        bytes
            Texte en clair avec le rembourrage PKCS#7 retiré.
        """
        bs = self._primitive.block_size
        if iv is None:
            iv, ciphertext = ciphertext[:bs], ciphertext[bs:]
        if len(iv) != bs:
            raise ValueError(f"IV must be exactly {bs} bytes; got {len(iv)}.")
        if len(ciphertext) % bs != 0:
            raise ValueError(
                f"Ciphertext length must be a multiple of {bs} bytes."
            )

        # Déchiffrement de tous les blocs en un appel groupé, puis XOR avec les blocs
        # décalés (IV préposé) — le déchiffrement CBC est parallélisable.
        raw = self._primitive.decrypt_blocks(ciphertext)
        prev_blocks = iv + ciphertext[:-bs]   # IV || C[0] || C[1] || ... || C[n-2]
        plaintext = _xor(raw, prev_blocks)

        return _pkcs7_unpad(plaintext)
