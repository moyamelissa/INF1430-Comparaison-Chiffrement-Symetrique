"""
Twofish.py
Implémentation concrète de la primitive de chiffrement Twofish.

Tailles de clé supportées : 128, 192 ou 256 bits (16, 24, 32 octets).
Taille de bloc : 128 bits (16 octets).

PyCryptodome ne fournit pas Twofish nativement. Ce module encapsule le paquet
Python pur `twofish` (pip install twofish). L'interface est identique à celle
de toutes les autres sous-classes de CipherPrimitive, de sorte que le reste
du système ignore la différence d'implémentation.
"""

from .CipherPrimitive import CipherPrimitive

_VALID_KEY_SIZES = {16, 24, 32}  # 128 / 192 / 256 bits (tailles de clé valides)


class Twofish(CipherPrimitive):
    """Chiffre par blocs Twofish."""

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
        ImportError
            Si le paquet `twofish` n'est pas installé.
        """
        if len(key) not in _VALID_KEY_SIZES:
            raise ValueError(
                f"Twofish key must be 16, 24 or 32 bytes; got {len(key)}."
            )
        try:
            from twofish import Twofish as _Twofish  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "The 'twofish' package is required for Twofish support. "
                "Install it with: pip install twofish"
            ) from exc

        self._key = key
        self._cipher = _Twofish(key)

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
        return bytes(self._cipher.encrypt(block))

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.BLOCK_SIZE:
            raise ValueError(
                f"Block must be exactly {self.BLOCK_SIZE} bytes; got {len(block)}."
            )
        return bytes(self._cipher.decrypt(block))
