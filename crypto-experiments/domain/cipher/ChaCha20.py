"""
ChaCha20.py
Implémentation concrète de ChaCha20 en tant que chiffre de flux.

ChaCha20 est un chiffre de flux conçu par Daniel J. Bernstein (2008).
Contrairement aux chiffres par blocs (AES, DES), il génère un flux de clés
et effectue un XOR avec le texte en clair — il n'existe pas de notion de
« bloc » au même sens.

Pour les besoins du benchmarking, block_size est fixé à 64 octets
(la taille d'un bloc de flux ChaCha20, correspondant à un appel de la
fonction quart-de-tour).

Taille de clé : 256 bits (32 octets) uniquement.
Nonce        : 96 bits (12 octets), généré aléatoirement par appel.

Note : ChaCha20 est utilisé dans TLS 1.3, WireGuard et SSH comme alternative
moderne à AES lorsque l'accélération matérielle AES est indisponible.
"""

import os

from Crypto.Cipher import ChaCha20 as _ChaCha20

from .CipherPrimitive import CipherPrimitive

_KEY_SIZE   = 32   # clé 256 bits
_NONCE_SIZE = 12   # nonce 96 bits (variante IETF)
_BLOCK_SIZE = 64   # bloc de flux ChaCha20 (pour la propriété block_size en benchmarking)


class ChaCha20(CipherPrimitive):
    """
    Chiffre de flux ChaCha20.

    ChaCha20 étant un chiffre de flux, encrypt_block / decrypt_block
    opèrent sur des données de longueur arbitraire (pas seulement 64 octets).
    La propriété block_size = 64 est utilisée uniquement pour la mesure
    d'avalanche (un bloc de flux est l'unité naturelle).

    Le nonce est préfixé au texte chiffré (12 octets) pour que decrypt_block
    puisse le récupérer. Cette convention est identique à celle utilisée
    par CBC (IV) et GCM (nonce).
    """

    BLOCK_SIZE = 64  # octets (taille du bloc de flux)

    def __init__(self, key: bytes) -> None:
        """
        Paramètres
        ----------
        key : bytes
            Exactement 32 octets (clé 256 bits).

        Lève
        ----
        ValueError
            Si la longueur de la clé n'est pas 32 octets.
        """
        if len(key) != _KEY_SIZE:
            raise ValueError(
                f"ChaCha20 key must be exactly 32 bytes; got {len(key)}."
            )
        self._key = key

    # ------------------------------------------------------------------ #
    #  Interface CipherPrimitive                                           #
    # ------------------------------------------------------------------ #

    @property
    def block_size(self) -> int:
        return self.BLOCK_SIZE

    @property
    def key_size(self) -> int:
        return len(self._key)

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """
        Chiffre des données de longueur arbitraire.

        Format de sortie : nonce (12 octets) || texte chiffré
        """
        nonce = os.urandom(_NONCE_SIZE)
        cipher = _ChaCha20.new(key=self._key, nonce=nonce)
        return nonce + cipher.encrypt(plaintext)

    def decrypt_block(self, data: bytes) -> bytes:
        """
        Déchiffre les données produites par encrypt_block.

        Format d'entrée : nonce (12 octets) || texte chiffré
        """
        if len(data) < _NONCE_SIZE:
            raise ValueError("ChaCha20 ciphertext too short to contain nonce.")
        nonce, ciphertext = data[:_NONCE_SIZE], data[_NONCE_SIZE:]
        cipher = _ChaCha20.new(key=self._key, nonce=nonce)
        return cipher.decrypt(ciphertext)

    def encrypt_blocks(self, plaintext: bytes) -> bytes:
        """Chiffrement groupé — appel unique (le chiffre de flux est naturellement groupé)."""
        return self.encrypt_block(plaintext)

    def decrypt_blocks(self, data: bytes) -> bytes:
        """Déchiffrement groupé — appel unique."""
        return self.decrypt_block(data)
