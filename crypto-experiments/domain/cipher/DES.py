"""
DES.py
Implémentation concrète de la primitive de chiffrement DES.

Taille de clé  : 64 bits (8 octets, dont 56 bits effectifs).
Taille de bloc : 64 bits (8 octets).

Utilise PyCryptodome en mode ECB brut afin de chiffrer/déchiffrer un seul bloc.
Toute la logique de chaînage est gérée par la couche mode d'opération.

Note : DES est considéré cryptographiquement compromis et n'est inclus ici qu'à
des fins de comparaison académique.
"""

from Crypto.Cipher import DES as _DES

from .CipherPrimitive import CipherPrimitive

_KEY_SIZE = 8   # clé 64 bits (56 bits effectifs)


class DES(CipherPrimitive):
    """Chiffre par blocs DES (hérité — usage académique uniquement)."""

    BLOCK_SIZE = 8  # octets

    def __init__(self, key: bytes) -> None:
        """
        Paramètres
        ----------
        key : bytes
            Exactement 8 octets (clé 64 bits, 56 bits effectifs).

        Lève
        ----
        ValueError
            Si la longueur de la clé n'est pas 8 octets.
        """
        if len(key) != _KEY_SIZE:
            raise ValueError(
                f"DES key must be exactly 8 bytes; got {len(key)}."
            )
        self._key = key

    # ------------------------------------------------------------------ #
    #  Interface CipherPrimitive                                           #
    # ------------------------------------------------------------------ #

    @property
    def block_size(self) -> int:
        return self.BLOCK_SIZE

    @property
    def key_size(self) -> int:
        return len(self._key)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.BLOCK_SIZE:
            raise ValueError(
                f"Block must be exactly {self.BLOCK_SIZE} bytes; got {len(block)}."
            )
        cipher = _DES.new(self._key, _DES.MODE_ECB)
        return cipher.encrypt(block)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.BLOCK_SIZE:
            raise ValueError(
                f"Block must be exactly {self.BLOCK_SIZE} bytes; got {len(block)}."
            )
        cipher = _DES.new(self._key, _DES.MODE_ECB)
        return cipher.decrypt(block)

    def encrypt_blocks(self, data: bytes) -> bytes:
        """Chiffre plusieurs blocs en un seul appel PyCryptodome (chemin rapide)."""
        return _DES.new(self._key, _DES.MODE_ECB).encrypt(data)

    def decrypt_blocks(self, data: bytes) -> bytes:
        """Déchiffre plusieurs blocs en un seul appel PyCryptodome (chemin rapide)."""
        return _DES.new(self._key, _DES.MODE_ECB).decrypt(data)
