"""
OperationMode.py
Abstract base class for all block-cipher modes of operation.

A mode receives a CipherPrimitive and applies a chaining/padding strategy to
encrypt or decrypt arbitrarily-sized messages.  The mode layer knows nothing
about which primitive it wraps — it only calls encrypt_block / decrypt_block.
"""

from abc import ABC, abstractmethod

from domain.cipher.CipherPrimitive import CipherPrimitive


class OperationMode(ABC):
    """Common interface for block-cipher modes of operation."""

    def __init__(self, primitive: CipherPrimitive) -> None:
        """
        Parameters
        ----------
        primitive : CipherPrimitive
            The block-cipher primitive this mode will wrap.
        """
        self._primitive = primitive

    @property
    def primitive(self) -> CipherPrimitive:
        return self._primitive

    @abstractmethod
    def encrypt(self, plaintext: bytes, **kwargs) -> bytes:
        """
        Encrypt an arbitrary-length plaintext.

        Parameters
        ----------
        plaintext : bytes
            Data to encrypt.  Padding (if required) is handled internally.
        **kwargs
            Mode-specific parameters (e.g. ``iv``, ``nonce``).

        Returns
        -------
        bytes
            Ciphertext.
        """

    @abstractmethod
    def decrypt(self, ciphertext: bytes, **kwargs) -> bytes:
        """
        Decrypt an arbitrary-length ciphertext.

        Parameters
        ----------
        ciphertext : bytes
            Data to decrypt.
        **kwargs
            Mode-specific parameters (e.g. ``iv``, ``nonce``).

        Returns
        -------
        bytes
            Plaintext (padding stripped where applicable).
        """

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(primitive={self._primitive!r})"
