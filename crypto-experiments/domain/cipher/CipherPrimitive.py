"""
CipherPrimitive.py
Abstract base class for all symmetric block cipher primitives.

Every concrete cipher (AES, DES, TripleDES, Twofish) must inherit from this
class and implement encrypt_block / decrypt_block on a single block of bytes.
The mode-of-operation layer is kept strictly separate: primitives know nothing
about chaining, IVs or nonces.
"""

from abc import ABC, abstractmethod


class CipherPrimitive(ABC):
    """Common interface for symmetric block-cipher primitives."""

    @property
    @abstractmethod
    def block_size(self) -> int:
        """Block size in bytes (e.g. 16 for AES, 8 for DES/3DES)."""

    @property
    @abstractmethod
    def key_size(self) -> int:
        """Key size in bytes used by this instance."""

    @abstractmethod
    def encrypt_block(self, block: bytes) -> bytes:
        """
        Encrypt exactly one block of plaintext.

        Parameters
        ----------
        block : bytes
            Plaintext block of exactly ``block_size`` bytes.

        Returns
        -------
        bytes
            Ciphertext block of exactly ``block_size`` bytes.
        """

    @abstractmethod
    def decrypt_block(self, block: bytes) -> bytes:
        """
        Decrypt exactly one block of ciphertext.

        Parameters
        ----------
        block : bytes
            Ciphertext block of exactly ``block_size`` bytes.

        Returns
        -------
        bytes
            Plaintext block of exactly ``block_size`` bytes.
        """

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"block_size={self.block_size}, key_size={self.key_size})"
        )
