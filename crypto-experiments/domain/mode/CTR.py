"""
CTR.py
Mode d'opération CTR (Counter) — NIST SP 800-38A.

Le mode CTR transforme un chiffre par blocs en chiffre de flux en chiffrant
des valeurs de compteur successives et en XOR-ant le flux de clés avec le
texte en clair. Aucun rembourrage n'est nécessaire et chiffrement/déchiffrement
sont des opérations identiques. Les blocs peuvent être traités en parallèle
(important pour le benchmarking du parallélisme).

Nonce : ``block_size - 8`` octets préfixés à un compteur de 8 octets big-endian.
Le bloc de compteur complet fait donc ``block_size`` octets.
"""

import os
import struct

from domain.cipher.CipherPrimitive import CipherPrimitive
from .OperationMode import OperationMode

_COUNTER_BYTES = 8  # compteur 64 bits


class CTR(OperationMode):
    """
    Mode CTR (Counter) — NIST SP 800-38A, section 6.5.

    Le bloc de compteur est construit comme : nonce (block_size - 8 octets) || compteur (8 octets).
    Un nonce aléatoire est généré à chaque appel d'encrypt() si aucun n'est fourni ;
    le nonce est préfixé à la sortie et relu dans decrypt().
    """

    def __init__(self, primitive: CipherPrimitive) -> None:
        super().__init__(primitive)
        self._nonce_size = primitive.block_size - _COUNTER_BYTES

    def _counter_block(self, nonce: bytes, count: int) -> bytes:
        return nonce + struct.pack(">Q", count)

    def encrypt(self, plaintext: bytes, nonce: bytes | None = None, **kwargs) -> bytes:
        """
        Chiffre ``plaintext`` en mode CTR.

        Paramètres
        ----------
        plaintext : bytes
            Texte en clair de longueur arbitraire (aucun rembourrage requis).
        nonce : bytes, optionnel
            ``block_size - 8`` octets aléatoires. Généré automatiquement si None.

        Retourne
        --------
        bytes
            nonce || texte chiffré.
        """
        if nonce is None:
            nonce = os.urandom(self._nonce_size)
        if len(nonce) != self._nonce_size:
            raise ValueError(
                f"Nonce must be {self._nonce_size} bytes; got {len(nonce)}."
            )

        bs = self._primitive.block_size
        num_blocks = (len(plaintext) + bs - 1) // bs

        # Construction de tous les blocs de compteur et chiffrement en un appel groupé
        all_counters = b"".join(
            self._counter_block(nonce, i) for i in range(num_blocks)
        )
        keystream = self._primitive.encrypt_blocks(all_counters)

        ciphertext = bytes(
            p ^ k for p, k in zip(plaintext, keystream)
        )
        return nonce + ciphertext

    def decrypt(self, ciphertext: bytes, nonce: bytes | None = None, **kwargs) -> bytes:
        """
        Déchiffre ``ciphertext`` produit par CTR.encrypt().

        Le déchiffrement CTR est identique au chiffrement CTR (XOR est sa propre inverse).

        Paramètres
        ----------
        ciphertext : bytes
            nonce || texte chiffré (tel que retourné par encrypt) si ``nonce`` est None,
            ou texte chiffré brut si ``nonce`` est fourni explicitement.
        nonce : bytes, optionnel
            Nonce explicite. Si None, lu dans les premiers
            ``block_size - 8`` octets de ``ciphertext``.

        Retourne
        --------
        bytes
            Texte en clair.
        """
        if nonce is None:
            nonce, ciphertext = ciphertext[: self._nonce_size], ciphertext[self._nonce_size :]
        if len(nonce) != self._nonce_size:
            raise ValueError(
                f"Nonce must be {self._nonce_size} bytes; got {len(nonce)}."
            )

        bs = self._primitive.block_size
        num_blocks = (len(ciphertext) + bs - 1) // bs

        all_counters = b"".join(
            self._counter_block(nonce, i) for i in range(num_blocks)
        )
        keystream = self._primitive.encrypt_blocks(all_counters)

        return bytes(c ^ k for c, k in zip(ciphertext, keystream))
