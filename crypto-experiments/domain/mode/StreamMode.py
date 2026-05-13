"""
StreamMode.py
Mode passthrough pour les chiffres de flux (ex. ChaCha20).

Les chiffres de flux n'ont pas de notion de chaînage par blocs — la primitive
gère elle-même la génération du nonce et le XOR du flux de clés. StreamMode
délègue simplement encrypt/decrypt directement aux méthodes encrypt_blocks /
decrypt_blocks de la primitive, de sorte que l'interface EncryptionEngine soit
satisfaite sans forcer un chiffre de flux à traverser la logique de mode par
blocs (rembourrage, IV, etc.).

Ce mode n'est valide que lorsqu'il est associé à une primitive de type chiffre
de flux comme ChaCha20. L'utiliser avec un chiffre par blocs (AES, DES, etc.)
serait incorrect.
"""

from domain.mode.OperationMode import OperationMode


class StreamMode(OperationMode):
    """Mode passthrough pour les chiffres de flux."""

    def encrypt(self, plaintext: bytes, **kwargs) -> bytes:
        """Délègue directement à la primitive (nonce inclus dans la sortie)."""
        return self._primitive.encrypt_blocks(plaintext)

    def decrypt(self, ciphertext: bytes, **kwargs) -> bytes:
        """Délègue directement à la primitive (nonce extrait de l'entrée)."""
        return self._primitive.decrypt_blocks(ciphertext)
