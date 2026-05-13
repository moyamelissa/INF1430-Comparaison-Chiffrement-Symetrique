"""
GCM.py
Mode d'opération GCM (Galois/Counter Mode) — NIST SP 800-38D.

GCM est un mode AEAD (Authenticated Encryption with Associated Data) construit
sur le mode CTR augmenté d'un tag d'authentification GHASH. Il garantit à la
fois la confidentialité et l'intégrité.

Cette implémentation délègue la logique GCM complète à l'AES-GCM de PyCryptodome,
qui est la seule primitive pour laquelle GCM est standardisé. Pour les autres
primitives (DES, 3DES, Twofish), le mode n'est pas disponible et une erreur
explicite est levée, pour maintenir l'honnêteté du modèle de domaine.

Taille du tag : 16 octets (tag d'authentification 128 bits).
Nonce : 12 octets (96 bits, recommandé par NIST).
"""

import os

from Crypto.Cipher import AES as _AES

from domain.cipher.AES import AES as AESPrimitive
from domain.cipher.CipherPrimitive import CipherPrimitive
from .OperationMode import OperationMode

_TAG_SIZE = 16   # octets
_NONCE_SIZE = 12  # octets (nonce 96 bits recommandé par NIST SP 800-38D)


class GCM(OperationMode):
    """
    Mode GCM (Galois/Counter Mode) — NIST SP 800-38D.

    Compatible uniquement avec la primitive AES. Fournit un chiffrement
    authentifié : encrypt() ajoute un tag d'authentification de 16 octets et
    decrypt() le vérifie avant de retourner le texte en clair.
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
        Chiffre et authentifie ``plaintext``.

        Paramètres
        ----------
        plaintext : bytes
            Texte en clair de longueur arbitraire.
        nonce : bytes, optionnel
            Nonce de 12 octets. Un nonce aléatoire est généré si None.
        aad : bytes, optionnel
            Données authentifiées additionnelles (non chiffrées, mais authentifiées).

        Retourne
        --------
        bytes
            nonce (12 o) || texte chiffré || tag (16 o).
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
        Vérifie et déchiffre ``ciphertext`` produit par GCM.encrypt().

        Paramètres
        ----------
        ciphertext : bytes
            nonce || texte chiffré || tag (tel que retourné par encrypt) si
            ``nonce`` est None, sinon texte chiffré brut || tag.
        nonce : bytes, optionnel
            Nonce explicite de 12 octets. Si None, lu dans les 12 premiers
            octets de ``ciphertext``.
        aad : bytes, optionnel
            Doit correspondre aux AAD utilisées lors du chiffrement.

        Retourne
        --------
        bytes
            Texte en clair.

        Lève
        ----
        ValueError
            Si le tag d'authentification ne correspond pas (données altérées).
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
