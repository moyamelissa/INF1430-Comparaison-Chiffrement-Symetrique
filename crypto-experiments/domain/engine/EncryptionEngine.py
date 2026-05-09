"""
EncryptionEngine.py
Composes a CipherPrimitive with an OperationMode into a complete encryption
service.

This is the central domain object: it is what the application layer
(ExperimentController) works with.  It knows nothing about timing, CSV files
or experiment configuration — those concerns belong to upper layers.
"""

from domain.cipher.CipherPrimitive import CipherPrimitive
from domain.mode.OperationMode import OperationMode


class EncryptionEngine:
    """
    Combines a cipher primitive and a mode of operation.

    Parameters
    ----------
    primitive : CipherPrimitive
        A concrete cipher (AES, DES, TripleDES, Twofish …).
    mode : OperationMode
        A concrete mode (ECB, CBC, CTR, GCM …) already initialised with
        the same primitive.
    """

    def __init__(self, primitive: CipherPrimitive, mode: OperationMode) -> None:
        if mode.primitive is not primitive:
            raise ValueError(
                "The mode's primitive must be the same object as the engine's "
                "primitive.  Build the mode with the primitive first, then pass "
                "both to EncryptionEngine."
            )
        self._primitive = primitive
        self._mode = mode

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    @property
    def primitive(self) -> CipherPrimitive:
        return self._primitive

    @property
    def mode(self) -> OperationMode:
        return self._mode

    def encrypt(self, plaintext: bytes, **kwargs) -> bytes:
        """
        Encrypt ``plaintext`` using the configured primitive and mode.

        All keyword arguments are forwarded to the mode (e.g. ``iv``,
        ``nonce``, ``aad``).
        """
        return self._mode.encrypt(plaintext, **kwargs)

    def decrypt(self, ciphertext: bytes, **kwargs) -> bytes:
        """
        Decrypt ``ciphertext`` using the configured primitive and mode.

        All keyword arguments are forwarded to the mode.
        """
        return self._mode.decrypt(ciphertext, **kwargs)

    def __repr__(self) -> str:
        return (
            f"EncryptionEngine("
            f"primitive={self._primitive.__class__.__name__}, "
            f"mode={self._mode.__class__.__name__})"
        )
