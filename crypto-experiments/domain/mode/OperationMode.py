"""
OperationMode.py
Classe abstraite de base pour tous les modes d'opération de chiffrement par blocs.

Un mode reçoit une CipherPrimitive et applique une stratégie de chaînage/rembourrage
pour chiffrer ou déchiffrer des messages de longueur arbitraire. La couche mode
ne sait rien de la primitive qu'elle encapsule — elle appelle uniquement
encrypt_block / decrypt_block.
"""

from abc import ABC, abstractmethod

from domain.cipher.CipherPrimitive import CipherPrimitive


class OperationMode(ABC):
    """Interface commune pour les modes d'opération de chiffrement par blocs."""

    def __init__(self, primitive: CipherPrimitive) -> None:
        """
        Paramètres
        ----------
        primitive : CipherPrimitive
            La primitive de chiffrement par blocs que ce mode va encapsuler.
        """
        self._primitive = primitive

    @property
    def primitive(self) -> CipherPrimitive:
        return self._primitive

    @abstractmethod
    def encrypt(self, plaintext: bytes, **kwargs) -> bytes:
        """
        Chiffre un texte en clair de longueur arbitraire.

        Paramètres
        ----------
        plaintext : bytes
            Données à chiffrer. Le rembourrage (si nécessaire) est géré en interne.
        **kwargs
            Paramètres spécifiques au mode (ex. ``iv``, ``nonce``).

        Retourne
        --------
        bytes
            Texte chiffré.
        """

    @abstractmethod
    def decrypt(self, ciphertext: bytes, **kwargs) -> bytes:
        """
        Déchiffre un texte chiffré de longueur arbitraire.

        Paramètres
        ----------
        ciphertext : bytes
            Données à déchiffrer.
        **kwargs
            Paramètres spécifiques au mode (ex. ``iv``, ``nonce``).

        Retourne
        --------
        bytes
            Texte en clair (rembourrage retiré le cas échéant).
        """

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(primitive={self._primitive!r})"
