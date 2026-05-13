"""
AES.py
Implémentation concrète de la primitive de chiffrement AES (FIPS 197).

Tailles de clé supportées : 128, 192 ou 256 bits (16, 24, 32 octets).
Taille de bloc : 128 bits (16 octets).

Utilise PyCryptodome en mode ECB brut afin de chiffrer/déchiffrer un seul bloc.
Toute la logique de chaînage est gérée par la couche mode d'opération.
"""

from Crypto.Cipher import AES as _AES

from .CipherPrimitive import CipherPrimitive

_VALID_KEY_SIZES = {16, 24, 32}  # 128 / 192 / 256 bits (tailles de clé valides)


class AES(CipherPrimitive):
    """Chiffre par blocs AES — FIPS 197."""

    BLOCK_SIZE = 16  # octets

    def __init__(self, key: bytes) -> None:
        """
        Paramètres
        ----------
        key : bytes
            16, 24 ou 32 octets (clé de 128 / 192 / 256 bits).

        Lève
        ----
        ValueError
            Si la longueur de la clé n'est pas une taille supportée.
        """
        if len(key) not in _VALID_KEY_SIZES:
            raise ValueError(
                f"AES key must be 16, 24 or 32 bytes; got {len(key)}."
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
        cipher = _AES.new(self._key, _AES.MODE_ECB)
        return cipher.encrypt(block)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.BLOCK_SIZE:
            raise ValueError(
                f"Block must be exactly {self.BLOCK_SIZE} bytes; got {len(block)}."
            )
        cipher = _AES.new(self._key, _AES.MODE_ECB)
        return cipher.decrypt(block)

    def encrypt_blocks(self, data: bytes) -> bytes:
        """Chiffre plusieurs blocs en un seul appel PyCryptodome (chemin rapide)."""
        return _AES.new(self._key, _AES.MODE_ECB).encrypt(data)

    def decrypt_blocks(self, data: bytes) -> bytes:
        """Déchiffre plusieurs blocs en un seul appel PyCryptodome (chemin rapide)."""
        return _AES.new(self._key, _AES.MODE_ECB).decrypt(data)
