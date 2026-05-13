"""
CipherPrimitive.py
Classe abstraite de base pour toutes les primitives de chiffrement symétrique par blocs.

Chaque chiffre concret (AES, DES, TripleDES, Twofish) doit hériter de cette
classe et implémenter encrypt_block / decrypt_block sur un seul bloc d'octets.
La couche mode d'opération est strictement séparée : les primitives ne savent
rien du chaînage, des IV ou des nonces.
"""

from abc import ABC, abstractmethod


class CipherPrimitive(ABC):
    """Interface commune pour les primitives de chiffrement symétrique par blocs."""

    @property
    @abstractmethod
    def block_size(self) -> int:
        """Taille du bloc en octets (ex. 16 pour AES, 8 pour DES/3DES)."""

    @property
    @abstractmethod
    def key_size(self) -> int:
        """Taille de la clé en octets utilisée par cette instance."""

    @abstractmethod
    def encrypt_block(self, block: bytes) -> bytes:
        """
        Chiffre exactement un bloc de texte en clair.

        Paramètres
        ----------
        block : bytes
            Bloc de texte en clair de exactement ``block_size`` octets.

        Retourne
        --------
        bytes
            Bloc de texte chiffré de exactement ``block_size`` octets.
        """

    @abstractmethod
    def decrypt_block(self, block: bytes) -> bytes:
        """
        Déchiffre exactement un bloc de texte chiffré.

        Paramètres
        ----------
        block : bytes
            Bloc de texte chiffré de exactement ``block_size`` octets.

        Retourne
        --------
        bytes
            Bloc de texte en clair de exactement ``block_size`` octets.
        """

    def encrypt_blocks(self, data: bytes) -> bytes:
        """
        Chiffre ``data`` (doit être un multiple de block_size) en blocs ECB bruts.

        Les sous-classes devraient surcharger cette méthode avec un appel groupé
        à leur bibliothèque sous-jacente, afin de ne payer le surcoût de boucle
        qu'une seule fois par message plutôt qu'une fois par bloc.
        Le comportement par défaut se rabat sur la boucle bloc par bloc.
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
        Déchiffre ``data`` (doit être un multiple de block_size) en blocs ECB bruts.

        Même contrat d'optimisation groupée que ``encrypt_blocks``.
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
