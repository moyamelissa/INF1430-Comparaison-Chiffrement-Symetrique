"""
CTR.py
Counter (CTR) mode of operation (NIST SP 800-38A).

CTR turns a block cipher into a stream cipher by encrypting successive counter
values and XOR-ing the keystream with the plaintext.  No padding is needed and
encryption/decryption are identical operations.  Blocks can be processed in
parallel (important for benchmarking parallelism).

Nonce: ``block_size - 8`` bytes prepended to an 8-byte big-endian counter.
The full counter block is therefore ``block_size`` bytes.
"""

import os
import struct

from domain.cipher.CipherPrimitive import CipherPrimitive
from .OperationMode import OperationMode

_COUNTER_BYTES = 8  # 64-bit counter


class CTR(OperationMode):
    """
    Counter mode (NIST SP 800-38A, Section 6.5).

    The counter block is built as: nonce (block_size - 8 bytes) || counter (8 bytes).
    A fresh random nonce is generated for each encrypt() call when none is
    supplied; the nonce is prepended to the output and read back in decrypt().
    """

    def __init__(self, primitive: CipherPrimitive) -> None:
        super().__init__(primitive)
        self._nonce_size = primitive.block_size - _COUNTER_BYTES

    def _counter_block(self, nonce: bytes, count: int) -> bytes:
        return nonce + struct.pack(">Q", count)

    def encrypt(self, plaintext: bytes, nonce: bytes | None = None, **kwargs) -> bytes:
        """
        Encrypt ``plaintext`` in CTR mode.

        Parameters
        ----------
        plaintext : bytes
            Arbitrary-length plaintext (no padding required).
        nonce : bytes, optional
            ``block_size - 8`` random bytes.  Generated automatically when None.

        Returns
        -------
        bytes
            nonce || ciphertext.
        """
        if nonce is None:
            nonce = os.urandom(self._nonce_size)
        if len(nonce) != self._nonce_size:
            raise ValueError(
                f"Nonce must be {self._nonce_size} bytes; got {len(nonce)}."
            )

        bs = self._primitive.block_size
        num_blocks = (len(plaintext) + bs - 1) // bs

        # Build all counter blocks and encrypt in one bulk call
        all_counters = b"".join(
            self._counter_block(nonce, i) for i in range(num_blocks)
        )
        keystream = self._primitive.encrypt_blocks(all_counters)

        ciphertext = bytes(
            p ^ k for p, k in zip(plaintext, keystream)
        )
        return nonce + ciphertext

    def decrypt(self, ciphertext: bytes, nonce: bytes | None = None, **kwargs) -> bytes:
        """
        Decrypt ``ciphertext`` produced by CTR.encrypt().

        CTR decrypt is identical to CTR encrypt (XOR is its own inverse).

        Parameters
        ----------
        ciphertext : bytes
            nonce || ciphertext (as returned by encrypt) when ``nonce`` is None,
            or raw ciphertext when ``nonce`` is supplied explicitly.
        nonce : bytes, optional
            Explicit nonce.  When None it is read from the first
            ``block_size - 8`` bytes of ``ciphertext``.

        Returns
        -------
        bytes
            Plaintext.
        """
        if nonce is None:
            nonce, ciphertext = ciphertext[: self._nonce_size], ciphertext[self._nonce_size :]
        if len(nonce) != self._nonce_size:
            raise ValueError(
                f"Nonce must be {self._nonce_size} bytes; got {len(nonce)}."
            )

        bs = self._primitive.block_size
        num_blocks = (len(ciphertext) + bs - 1) // bs

        all_counters = b"".join(
            self._counter_block(nonce, i) for i in range(num_blocks)
        )
        keystream = self._primitive.encrypt_blocks(all_counters)

        return bytes(c ^ k for c, k in zip(ciphertext, keystream))
