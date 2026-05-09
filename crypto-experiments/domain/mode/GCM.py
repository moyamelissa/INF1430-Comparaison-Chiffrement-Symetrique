"""
GCM.py
Galois/Counter Mode (GCM) mode of operation (NIST SP 800-38D).

GCM is an authenticated encryption with associated data (AEAD) mode built on
top of CTR mode plus a GHASH authentication tag.  It guarantees both
confidentiality and integrity.

This implementation delegates the full GCM logic to PyCryptodome's AES-GCM,
which is the only primitive GCM is standardised for.  For other primitives
(DES, 3DES, Twofish) the mode is not available and a clear error is raised,
keeping the domain model honest.

Tag size: 16 bytes (128-bit authentication tag).
Nonce: 12 bytes (96-bit, recommended by NIST).
"""

import os

from Crypto.Cipher import AES as _AES

from domain.cipher.AES import AES as AESPrimitive
from domain.cipher.CipherPrimitive import CipherPrimitive
from .OperationMode import OperationMode

_TAG_SIZE = 16   # bytes
_NONCE_SIZE = 12  # bytes (96-bit nonce recommended by NIST SP 800-38D)


class GCM(OperationMode):
    """
    Galois/Counter Mode (NIST SP 800-38D).

    Only compatible with the AES primitive.  Provides authenticated
    encryption: encrypt() appends a 16-byte authentication tag and
    decrypt() verifies it before returning plaintext.
    """

    def __init__(self, primitive: CipherPrimitive) -> None:
        if not isinstance(primitive, AESPrimitive):
            raise TypeError(
                "GCM is only defined for AES; "
                f"got {type(primitive).__name__}."
            )
        super().__init__(primitive)

    def encrypt(
        self,
        plaintext: bytes,
        nonce: bytes | None = None,
        aad: bytes = b"",
        **kwargs,
    ) -> bytes:
        """
        Encrypt and authenticate ``plaintext``.

        Parameters
        ----------
        plaintext : bytes
            Arbitrary-length plaintext.
        nonce : bytes, optional
            12-byte nonce.  A fresh random nonce is generated when None.
        aad : bytes, optional
            Additional Authenticated Data (not encrypted, but authenticated).

        Returns
        -------
        bytes
            nonce (12 B) || ciphertext || tag (16 B).
        """
        if nonce is None:
            nonce = os.urandom(_NONCE_SIZE)
        if len(nonce) != _NONCE_SIZE:
            raise ValueError(
                f"GCM nonce must be {_NONCE_SIZE} bytes; got {len(nonce)}."
            )

        cipher = _AES.new(self._primitive._key, _AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + ciphertext + tag

    def decrypt(
        self,
        ciphertext: bytes,
        nonce: bytes | None = None,
        aad: bytes = b"",
        **kwargs,
    ) -> bytes:
        """
        Verify and decrypt ``ciphertext`` produced by GCM.encrypt().

        Parameters
        ----------
        ciphertext : bytes
            nonce || ciphertext || tag (as returned by encrypt) when
            ``nonce`` is None, otherwise raw ciphertext || tag.
        nonce : bytes, optional
            Explicit 12-byte nonce.  When None it is read from the first
            12 bytes of ``ciphertext``.
        aad : bytes, optional
            Must match the AAD used during encryption.

        Returns
        -------
        bytes
            Plaintext.

        Raises
        ------
        ValueError
            If the authentication tag does not match (data tampered).
        """
        if nonce is None:
            nonce, ciphertext = ciphertext[:_NONCE_SIZE], ciphertext[_NONCE_SIZE:]
        if len(nonce) != _NONCE_SIZE:
            raise ValueError(
                f"GCM nonce must be {_NONCE_SIZE} bytes; got {len(nonce)}."
            )

        tag = ciphertext[-_TAG_SIZE:]
        ciphertext = ciphertext[:-_TAG_SIZE]

        cipher = _AES.new(self._primitive._key, _AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)
        try:
            return cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as exc:
            raise ValueError(
                "GCM authentication tag mismatch — data may have been tampered with."
            ) from exc
