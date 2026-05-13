"""
EncryptionEngine.py
Compose une CipherPrimitive avec un OperationMode pour former un service
de chiffrement complet.

C'est l'objet central du domaine : c'est avec lui que travaille la couche
application (ExperimentController). Il ne sait rien du chronométrage, des
fichiers CSV ni de la configuration des expériences — ces préoccupations
appartiennent aux couches supérieures.
"""

from domain.cipher.CipherPrimitive import CipherPrimitive
from domain.mode.OperationMode import OperationMode


class EncryptionEngine:
    """
    Combine une primitive de chiffrement et un mode d'opération.

    Paramètres
    ----------
    primitive : CipherPrimitive
        Un chiffre concret (AES, DES, TripleDES, Twofish …).
    mode : OperationMode
        Un mode concret (ECB, CBC, CTR, GCM …) déjà initialisé avec
        la même primitive.
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
    #  API publique                                                        #
    # ------------------------------------------------------------------ #

    @property
    def primitive(self) -> CipherPrimitive:
        return self._primitive

    @property
    def mode(self) -> OperationMode:
        return self._mode

    def encrypt(self, plaintext: bytes, **kwargs) -> bytes:
        """
        Chiffre ``plaintext`` avec la primitive et le mode configurés.

        Tous les arguments nommés sont transmis au mode (ex. ``iv``,
        ``nonce``, ``aad``).
        """
        return self._mode.encrypt(plaintext, **kwargs)

    def decrypt(self, ciphertext: bytes, **kwargs) -> bytes:
        """
        Déchiffre ``ciphertext`` avec la primitive et le mode configurés.

        Tous les arguments nommés sont transmis au mode.
        """
        return self._mode.decrypt(ciphertext, **kwargs)

    def __repr__(self) -> str:
        return (
            f"EncryptionEngine("
            f"primitive={self._primitive.__class__.__name__}, "
            f"mode={self._mode.__class__.__name__})"
        )
