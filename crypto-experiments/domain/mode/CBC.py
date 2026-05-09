"""
CBC.py
Cipher Block Chaining (CBC) mode of operation (NIST SP 800-38A).

Each plaintext block is XOR-ed with the previous ciphertext block before
encryption.  An Initialization Vector (IV) is XOR-ed with the first block,
ensuring that identical plaintexts encrypted with different IVs produce
different ciphertexts.

Padding: PKCS#7 is applied so messages of any length are accepted.
IV: must be exactly ``primitive.block_size`` bytes.
"""

import os

from domain.cipher.CipherPrimitive import CipherPrimitive
from .OperationMode import OperationMode


def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

class CBC(OperationMode):
    """
    Cipher Block Chaining mode (NIST SP 800-38A, Section 6.2).

    Requires an IV of ``primitive.block_size`` bytes.  If no IV is supplied
    at encrypt/decrypt time, a random one is generated for encryption (and
    must be passed explicitly for decryption).
    """

    def __init__(self, primitive: CipherPrimitive) -> None:
        super().__init__(primitive)

    def encrypt(self, plaintext: bytes, iv: bytes | None = None, **kwargs) -> bytes:
        """
        Encrypt ``plaintext`` in CBC mode.

        Parameters
        ----------
        plaintext : bytes
            Arbitrary-length plaintext.
        iv : bytes, optional
            Initialization vector of ``block_size`` bytes.  A fresh random IV
            is generated when omitted.

        Returns
        -------
        bytes
            IV prepended to the ciphertext (IV || ciphertext).
        """
        bs = self._primitive.block_size
        if iv is None:
            iv = os.urandom(bs)
        if len(iv) != bs:
            raise ValueError(f"IV must be exactly {bs} bytes; got {len(iv)}.")

        padded = _pkcs7_pad(plaintext, bs)
        ciphertext = bytearray()
        prev = iv
        for i in range(0, len(padded), bs):
            block = _xor(padded[i : i + bs], prev)
            encrypted = self._primitive.encrypt_block(block)
            ciphertext += encrypted
            prev = encrypted

        # Prepend IV so decrypt() can recover it
        return iv + bytes(ciphertext)

    def decrypt(self, ciphertext: bytes, iv: bytes | None = None, **kwargs) -> bytes:
        """
        Decrypt ``ciphertext`` produced by CBC.encrypt().

        Parameters
        ----------
        ciphertext : bytes
            IV || ciphertext (as returned by encrypt) when ``iv`` is None,
            or raw ciphertext when ``iv`` is provided explicitly.
        iv : bytes, optional
            Explicit IV.  When None, the IV is read from the first
            ``block_size`` bytes of ``ciphertext``.

        Returns
        -------
        bytes
            Plaintext with PKCS#7 padding removed.
        """
        bs = self._primitive.block_size
        if iv is None:
            iv, ciphertext = ciphertext[:bs], ciphertext[bs:]
        if len(iv) != bs:
            raise ValueError(f"IV must be exactly {bs} bytes; got {len(iv)}.")
        if len(ciphertext) % bs != 0:
            raise ValueError(
                f"Ciphertext length must be a multiple of {bs} bytes."
            )

        # Decrypt all blocks in one bulk call, then XOR with the shifted
        # ciphertext (IV prepended) — CBC decryption is parallelisable.
        raw = self._primitive.decrypt_blocks(ciphertext)
        prev_blocks = iv + ciphertext[:-bs]   # IV || C[0] || C[1] || ... || C[n-2]
        plaintext = _xor(raw, prev_blocks)

        return _pkcs7_unpad(plaintext)
