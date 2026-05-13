"""
TripleDES.py
Implémentation concrète de la primitive de chiffrement 3DES (Triple DES).

Tailles de clé supportées :
  - 16 octets (sécurité 112 bits) — 3DES à deux clés : K1 || K2, K3 = K1
  - 24 octets (sécurité 168 bits) — 3DES à trois clés : K1 || K2 || K3

Taille de bloc : 64 bits (8 octets).

La séquence EDE (Chiffrer-Déchiffrer-Chiffrer) est gérée par PyCryptodome,
de sorte que chaque appel à encrypt_block / decrypt_block applique le pipeline
complet K1‑chiffre → K2‑déchiffre → K3‑chiffre, et non un seul passage DES.

Utilise PyCryptodome en mode ECB brut afin de chiffrer/déchiffrer un seul bloc.
Toute la logique de chaînage est gérée par la couche mode d'opération.
"""

from Crypto.Cipher import DES3 as _DES3

from .CipherPrimitive import CipherPrimitive

_VALID_KEY_SIZES = {16, 24}  # 112 ou 168 bits effectifs


class TripleDES(CipherPrimitive):
    """Chiffre par blocs 3DES (Triple DES / TDEA)."""

    BLOCK_SIZE = 8  # octets

    def __init__(self, key: bytes) -> None:
        """
        Paramètres
        ----------
        key : bytes
            16 octets (deux clés) ou 24 octets (trois clés).

        Lève
        ----
        ValueError
            Si la longueur de la clé n'est pas 16 ou 24 octets.
        """
        if len(key) not in _VALID_KEY_SIZES:
            raise ValueError(
                f"3DES key must be 16 or 24 bytes; got {len(key)}."
            )
        # PyCryptodome rejette les clés où K1 == K3 (protection clé faible).
        # Ajustement si l'appelant passe une clé de 24 octets avec K1 == K3.
        self._key = _DES3.adjust_key_parity(key)
        # Mémorisation des objets ECB sans état pour éviter de payer le coût
        # d'adjust_key_parity à chaque appel block par block.
        self._enc = _DES3.new(self._key, _DES3.MODE_ECB)
        self._dec = _DES3.new(self._key, _DES3.MODE_ECB)

    # ------------------------------------------------------------------ #
    #  Interface CipherPrimitive                                           #
    # ------------------------------------------------------------------ #

    @property
    def block_size(self) -> int:
        return self.BLOCK_SIZE

    @property
    def key_size(self) -> int:
        return len(self._key)

    def encrypt_block(self, block: bytes) -> bytes:
        """Applique le pipeline EDE (Chiffrer-Déchiffrer-Chiffrer) à un bloc."""
        if len(block) != self.BLOCK_SIZE:
            raise ValueError(
                f"Block must be exactly {self.BLOCK_SIZE} bytes; got {len(block)}."
            )
        return self._enc.encrypt(block)

    def decrypt_block(self, block: bytes) -> bytes:
        """Applique le pipeline DED (Déchiffrer-Chiffrer-Déchiffrer) à un bloc."""
        if len(block) != self.BLOCK_SIZE:
            raise ValueError(
                f"Block must be exactly {self.BLOCK_SIZE} bytes; got {len(block)}."
            )
        return self._dec.decrypt(block)

    def encrypt_blocks(self, data: bytes) -> bytes:
        """Applique le pipeline EDE à plusieurs blocs en un seul appel PyCryptodome."""
        return _DES3.new(self._key, _DES3.MODE_ECB).encrypt(data)

    def decrypt_blocks(self, data: bytes) -> bytes:
        """Applique le pipeline DED à plusieurs blocs en un seul appel PyCryptodome."""
        return _DES3.new(self._key, _DES3.MODE_ECB).decrypt(data)
