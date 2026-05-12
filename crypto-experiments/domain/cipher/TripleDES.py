"""
TripleDES.py
Concrete implementation of the 3DES (Triple DES) cipher primitive.

Key sizes supported:
  - 16 bytes (112-bit security) — two-key 3DES: K1 || K2, K3 = K1
  - 24 bytes (168-bit security) — three-key 3DES: K1 || K2 || K3

Block size: 64 bits (8 bytes).

The three-step encrypt-decrypt-encrypt (EDE) sequence is handled by
PyCryptodome so each call to encrypt_block / decrypt_block applies the full
K1-encrypt → K2-decrypt → K3-encrypt pipeline, not a single DES pass.

Uses PyCryptodome in raw ECB mode internally so a single block can be
encrypted/decrypted.  All chaining logic lives in the mode layer.
"""

from Crypto.Cipher import DES3 as _DES3

from .CipherPrimitive import CipherPrimitive

_VALID_KEY_SIZES = {16, 24}  # 112 or 168 effective bits


class TripleDES(CipherPrimitive):
    """3DES (Triple DES / TDEA) block cipher."""

    BLOCK_SIZE = 8  # bytes

    def __init__(self, key: bytes) -> None:
        """
        Parameters
        ----------
        key : bytes
            16 bytes (two-key) or 24 bytes (three-key).

        Raises
        ------
        ValueError
            If the key length is not 16 or 24 bytes.
        """
        if len(key) not in _VALID_KEY_SIZES:
            raise ValueError(
                f"3DES key must be 16 or 24 bytes; got {len(key)}."
            )
        # PyCryptodome rejects keys where K1 == K3 (weak key guard).
        # Adjust if the caller passes a 24-byte key with K1 == K3.
        self._key = _DES3.adjust_key_parity(key)
        # Cache stateless ECB cipher objects so encrypt_block / decrypt_block
        # do not pay the cost of adjust_key_parity on every single block call.
        self._enc = _DES3.new(self._key, _DES3.MODE_ECB)
        self._dec = _DES3.new(self._key, _DES3.MODE_ECB)

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
        """Apply full EDE (Encrypt-Decrypt-Encrypt) pipeline to one block."""
        if len(block) != self.BLOCK_SIZE:
            raise ValueError(
                f"Block must be exactly {self.BLOCK_SIZE} bytes; got {len(block)}."
            )
        return self._enc.encrypt(block)

    def decrypt_block(self, block: bytes) -> bytes:
        """Apply full DED (Decrypt-Encrypt-Decrypt) pipeline to one block."""
        if len(block) != self.BLOCK_SIZE:
            raise ValueError(
                f"Block must be exactly {self.BLOCK_SIZE} bytes; got {len(block)}."
            )
        return self._dec.decrypt(block)

    def encrypt_blocks(self, data: bytes) -> bytes:
        """Apply full EDE pipeline to multiple blocks in one PyCryptodome call."""
        return _DES3.new(self._key, _DES3.MODE_ECB).encrypt(data)

    def decrypt_blocks(self, data: bytes) -> bytes:
        """Apply full DED pipeline to multiple blocks in one PyCryptodome call."""
        return _DES3.new(self._key, _DES3.MODE_ECB).decrypt(data)
