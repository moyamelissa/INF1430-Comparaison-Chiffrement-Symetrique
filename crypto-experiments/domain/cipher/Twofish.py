"""
Twofish.py
Concrete implementation of the Twofish cipher primitive.

Key sizes supported: 128, 192 or 256 bits (16, 24, 32 bytes).
Block size: 128 bits (16 bytes).

PyCryptodome does not ship Twofish natively.  This module wraps the
`twofish` pure-Python package (pip install twofish).  The interface is kept
identical to all other CipherPrimitive subclasses so the rest of the system
is unaware of the implementation difference.
"""

from .CipherPrimitive import CipherPrimitive

_VALID_KEY_SIZES = {16, 24, 32}  # 128 / 192 / 256 bits


class Twofish(CipherPrimitive):
    """Twofish block cipher."""

    BLOCK_SIZE = 16  # bytes

    def __init__(self, key: bytes) -> None:
        """
        Parameters
        ----------
        key : bytes
            16, 24 or 32 bytes (128 / 192 / 256-bit key).

        Raises
        ------
        ValueError
            If the key length is not one of the supported sizes.
        ImportError
            If the `twofish` package is not installed.
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
    #  CipherPrimitive interface                                           #
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
