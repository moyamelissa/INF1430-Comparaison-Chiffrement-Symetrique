"""
AES.py
Concrete implementation of the AES cipher primitive (FIPS 197).

Key sizes supported: 128, 192 or 256 bits (16, 24, 32 bytes).
Block size: 128 bits (16 bytes).

Uses PyCryptodome in raw ECB mode internally so that a single block can be
encrypted/decrypted.  All chaining logic lives in the mode layer.
"""

from Crypto.Cipher import AES as _AES

from .CipherPrimitive import CipherPrimitive

_VALID_KEY_SIZES = {16, 24, 32}  # 128 / 192 / 256 bits


class AES(CipherPrimitive):
    """AES block cipher — FIPS 197."""

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
        """
        if len(key) not in _VALID_KEY_SIZES:
            raise ValueError(
                f"AES key must be 16, 24 or 32 bytes; got {len(key)}."
            )
        self._key = key

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
        """Encrypt multiple blocks in a single PyCryptodome call (fast path)."""
        return _AES.new(self._key, _AES.MODE_ECB).encrypt(data)

    def decrypt_blocks(self, data: bytes) -> bytes:
        """Decrypt multiple blocks in a single PyCryptodome call (fast path)."""
        return _AES.new(self._key, _AES.MODE_ECB).decrypt(data)
