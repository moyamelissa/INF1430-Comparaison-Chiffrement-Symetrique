"""
DES.py
Concrete implementation of the DES cipher primitive.

Key size : 64 bits (8 bytes, of which 56 are effective).
Block size: 64 bits (8 bytes).

Uses PyCryptodome in raw ECB mode internally so a single block can be
encrypted/decrypted.  All chaining logic lives in the mode layer.

Note: DES is considered cryptographically broken and is included here solely
for academic comparison purposes.
"""

from Crypto.Cipher import DES as _DES

from .CipherPrimitive import CipherPrimitive

_KEY_SIZE = 8   # 64-bit key (56 effective bits)


class DES(CipherPrimitive):
    """DES block cipher (legacy — academic use only)."""

    BLOCK_SIZE = 8  # bytes

    def __init__(self, key: bytes) -> None:
        """
        Parameters
        ----------
        key : bytes
            Exactly 8 bytes (64-bit key, 56 effective bits).

        Raises
        ------
        ValueError
            If the key length is not 8 bytes.
        """
        if len(key) != _KEY_SIZE:
            raise ValueError(
                f"DES key must be exactly 8 bytes; got {len(key)}."
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
        """Encrypt multiple blocks in a single PyCryptodome call (fast path)."""
        return _DES.new(self._key, _DES.MODE_ECB).encrypt(data)

    def decrypt_blocks(self, data: bytes) -> bytes:
        """Decrypt multiple blocks in a single PyCryptodome call (fast path)."""
        return _DES.new(self._key, _DES.MODE_ECB).decrypt(data)
