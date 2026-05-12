"""
ChaCha20.py
Concrete implementation of ChaCha20 as a stream cipher primitive.

ChaCha20 is a stream cipher designed by Daniel J. Bernstein (2008).
Unlike block ciphers (AES, DES), it generates a keystream and XORs it
with the plaintext — there is no concept of a "block" in the same sense.

For benchmarking purposes we set block_size = 64 bytes (the ChaCha20
keystream block size, matching one call to the quarter-round function).

Key size : 256 bits (32 bytes) only.
Nonce    : 96 bits (12 bytes), randomly generated per call.

Note: ChaCha20 is used in TLS 1.3, WireGuard, and SSH as a modern
alternative to AES when hardware AES acceleration is unavailable.
"""

import os

from Crypto.Cipher import ChaCha20 as _ChaCha20

from .CipherPrimitive import CipherPrimitive

_KEY_SIZE   = 32   # 256-bit key
_NONCE_SIZE = 12   # 96-bit nonce (IETF variant)
_BLOCK_SIZE = 64   # ChaCha20 keystream block (for benchmarking block_size property)


class ChaCha20(CipherPrimitive):
    """
    ChaCha20 stream cipher.

    Because ChaCha20 is a stream cipher, encrypt_block / decrypt_block
    operate on arbitrary-length data (not just 64-byte chunks).  The
    block_size = 64 property is used only for avalanche measurement
    (where a single keystream block is the natural unit).

    The nonce is prepended to the ciphertext (12 bytes) so that
    decrypt_block can recover it.  This mirrors the convention used
    by CBC (IV) and GCM (nonce).
    """

    BLOCK_SIZE = 64  # bytes (keystream block size)

    def __init__(self, key: bytes) -> None:
        """
        Parameters
        ----------
        key : bytes
            Exactly 32 bytes (256-bit key).

        Raises
        ------
        ValueError
            If the key length is not 32 bytes.
        """
        if len(key) != _KEY_SIZE:
            raise ValueError(
                f"ChaCha20 key must be exactly 32 bytes; got {len(key)}."
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

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """
        Encrypt arbitrary-length data.

        Output format: nonce (12 bytes) || ciphertext
        """
        nonce = os.urandom(_NONCE_SIZE)
        cipher = _ChaCha20.new(key=self._key, nonce=nonce)
        return nonce + cipher.encrypt(plaintext)

    def decrypt_block(self, data: bytes) -> bytes:
        """
        Decrypt data produced by encrypt_block.

        Input format: nonce (12 bytes) || ciphertext
        """
        if len(data) < _NONCE_SIZE:
            raise ValueError("ChaCha20 ciphertext too short to contain nonce.")
        nonce, ciphertext = data[:_NONCE_SIZE], data[_NONCE_SIZE:]
        cipher = _ChaCha20.new(key=self._key, nonce=nonce)
        return cipher.decrypt(ciphertext)

    def encrypt_blocks(self, plaintext: bytes) -> bytes:
        """Bulk encrypt — single call (stream cipher is naturally bulk)."""
        return self.encrypt_block(plaintext)

    def decrypt_blocks(self, data: bytes) -> bytes:
        """Bulk decrypt — single call."""
        return self.decrypt_block(data)
