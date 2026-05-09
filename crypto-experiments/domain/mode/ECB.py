"""
ECB.py
Electronic Codebook (ECB) mode of operation.

WARNING: ECB is cryptographically weak — identical plaintext blocks produce
identical ciphertext blocks, revealing data patterns.  It is included here
solely for academic benchmarking and comparison purposes.

Padding: PKCS#7 is applied so messages of any length are accepted.
"""

from domain.cipher.CipherPrimitive import CipherPrimitive
from .OperationMode import OperationMode


def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


class ECB(OperationMode):
    """
    Electronic Codebook mode.

    Each block is encrypted independently — no IV required.
    """

    def __init__(self, primitive: CipherPrimitive) -> None:
        super().__init__(primitive)

    def encrypt(self, plaintext: bytes, **kwargs) -> bytes:
        """
        Encrypt ``plaintext`` block by block (no chaining).

        Parameters
        ----------
        plaintext : bytes
            Arbitrary-length plaintext.

        Returns
        -------
        bytes
            Ciphertext (same length as padded plaintext).
        """
        bs = self._primitive.block_size
        padded = _pkcs7_pad(plaintext, bs)
        return self._primitive.encrypt_blocks(padded)

    def decrypt(self, ciphertext: bytes, **kwargs) -> bytes:
        """
        Decrypt ``ciphertext`` block by block.

        Parameters
        ----------
        ciphertext : bytes
            Must be a multiple of the primitive's block size.

        Returns
        -------
        bytes
            Plaintext with PKCS#7 padding removed.
        """
        bs = self._primitive.block_size
        if len(ciphertext) % bs != 0:
            raise ValueError(
                f"Ciphertext length must be a multiple of {bs} bytes."
            )
        return _pkcs7_unpad(self._primitive.decrypt_blocks(ciphertext))
