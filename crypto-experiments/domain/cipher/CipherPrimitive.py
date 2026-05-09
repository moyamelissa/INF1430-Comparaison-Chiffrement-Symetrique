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

    def encrypt_blocks(self, data: bytes) -> bytes:
        """
        Encrypt ``data`` (must be a multiple of block_size) as raw ECB blocks.

        Subclasses should override this with a single bulk call to their
        underlying library so the loop overhead is paid only once per message
        instead of once per block.  The default falls back to the block loop.
        """
        bs = self.block_size
        if len(data) % bs != 0:
            raise ValueError(
                f"data length must be a multiple of {bs}; got {len(data)}."
            )
        result = bytearray()
        for i in range(0, len(data), bs):
            result += self.encrypt_block(data[i : i + bs])
        return bytes(result)

    def decrypt_blocks(self, data: bytes) -> bytes:
        """
        Decrypt ``data`` (must be a multiple of block_size) as raw ECB blocks.

        Same bulk-optimisation contract as ``encrypt_blocks``.
        """
        bs = self.block_size
        if len(data) % bs != 0:
            raise ValueError(
                f"data length must be a multiple of {bs}; got {len(data)}."
            )
        result = bytearray()
        for i in range(0, len(data), bs):
            result += self.decrypt_block(data[i : i + bs])
        return bytes(result)

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"block_size={self.block_size}, key_size={self.key_size})"
        )
