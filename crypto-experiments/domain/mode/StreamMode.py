"""
StreamMode.py
Thin pass-through mode for stream ciphers (e.g. ChaCha20).

Stream ciphers have no concept of "block chaining" — the primitive itself
handles nonce generation and keystream XOR internally.  StreamMode simply
delegates encrypt/decrypt directly to the primitive's encrypt_blocks /
decrypt_blocks methods so that the EncryptionEngine interface is satisfied
without forcing a stream cipher through block-mode logic (padding, IV, etc.).

This mode is only valid when paired with a stream cipher primitive such as
ChaCha20.  Using it with a block cipher (AES, DES, etc.) would be incorrect.
"""

from domain.mode.OperationMode import OperationMode


class StreamMode(OperationMode):
    """Pass-through mode for stream ciphers."""

    def encrypt(self, plaintext: bytes, **kwargs) -> bytes:
        """Delegate directly to the primitive (nonce embedded in output)."""
        return self._primitive.encrypt_blocks(plaintext)

    def decrypt(self, ciphertext: bytes, **kwargs) -> bytes:
        """Delegate directly to the primitive (nonce extracted from input)."""
        return self._primitive.decrypt_blocks(ciphertext)
