"""
ECB.py
Mode d'opération ECB (Electronic Codebook).

ATTENTION : ECB est cryptographiquement faible — des blocs de texte en clair
identiques produisent des blocs de texte chiffré identiques, révélant ainsi
les motifs des données. Il est inclus ici uniquement à des fins de benchmarking
et de comparaison académique.

Rembourrage : PKCS#7 est appliqué pour accepter des messages de toute longueur.
"""

from domain.cipher.CipherPrimitive import CipherPrimitive
from .OperationMode import OperationMode


def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


class ECB(OperationMode):
    """
    Mode ECB (Electronic Codebook).

    Chaque bloc est chiffré indépendamment — aucun IV requis.
    """

    def __init__(self, primitive: CipherPrimitive) -> None:
        super().__init__(primitive)

    def encrypt(self, plaintext: bytes, **kwargs) -> bytes:
        """
        Chiffre ``plaintext`` bloc par bloc (sans chaînage).

        Paramètres
        ----------
        plaintext : bytes
            Texte en clair de longueur arbitraire.

        Retourne
        --------
        bytes
            Texte chiffré (même longueur que le texte rembourré).
        """
        bs = self._primitive.block_size
        padded = _pkcs7_pad(plaintext, bs)
        return self._primitive.encrypt_blocks(padded)

    def decrypt(self, ciphertext: bytes, **kwargs) -> bytes:
        """
        Déchiffre ``ciphertext`` bloc par bloc.

        Paramètres
        ----------
        ciphertext : bytes
            Doit être un multiple de la taille de bloc de la primitive.

        Retourne
        --------
        bytes
            Texte en clair avec le rembourrage PKCS#7 retiré.
        """
        bs = self._primitive.block_size
        if len(ciphertext) % bs != 0:
            raise ValueError(
                f"Ciphertext length must be a multiple of {bs} bytes."
            )
        return _pkcs7_unpad(self._primitive.decrypt_blocks(ciphertext))
