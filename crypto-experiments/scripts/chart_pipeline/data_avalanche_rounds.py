"""Prépare les données pour l'analyse d'avalanche DES à nombre de tours réduit.

Ce module contient la partie calculatoire uniquement: constantes DES,
chiffrement réduit à ``n`` tours, puis mesure du score d'avalanche moyen.
La construction du graphique se fait dans ``build_avalanche_rounds.py``.
"""

from __future__ import annotations

import os
import secrets


# ---------------------------------------------------------------------------
# Constantes DES standard
# ---------------------------------------------------------------------------
# Ces tables sont les permutations et S-boxes nécessaires pour reproduire
# la structure Feistel de DES au niveau bit à bit.
_IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
]
_IP_INV = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
]
_E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23,
    24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
]
_P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
]
_S = [
    [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
]
_PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
_PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
_SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
TRIALS = 500


def _bytes_to_bits(b: bytes) -> list[int]:
    """Convertit une séquence d'octets en liste de bits (MSB vers LSB)."""
    return [((byte >> i) & 1) for byte in b for i in range(7, -1, -1)]


def _bits_to_bytes(bits: list[int]) -> bytes:
    """Reconstruit des octets à partir d'une liste de bits."""
    out = bytearray()
    for index in range(0, len(bits), 8):
        byte = 0
        for bit in bits[index:index + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)


def _permute(bits: list[int], table: list[int]) -> list[int]:
    """Applique une table de permutation DES standard."""
    return [bits[t - 1] for t in table]


def _xor(left: list[int], right: list[int]) -> list[int]:
    """Effectue un XOR bit à bit entre deux listes de même longueur."""
    return [x ^ y for x, y in zip(left, right)]


def _lrot(bits: list[int], n: int) -> list[int]:
    """Applique une rotation circulaire à gauche."""
    return bits[n:] + bits[:n]


def _generate_subkeys(key: bytes) -> list[list[int]]:
    """Génère les 16 sous-clés DES à partir de la clé de 64 bits."""

    # DES utilise PC-1, des rotations successives, puis PC-2 pour produire
    # les sous-clés de chaque tour.
    key_bits = _bytes_to_bits(key)
    key_56 = _permute(key_bits, _PC1)
    c_bits, d_bits = key_56[:28], key_56[28:]
    subkeys = []
    for shift in _SHIFTS:
        c_bits = _lrot(c_bits, shift)
        d_bits = _lrot(d_bits, shift)
        subkeys.append(_permute(c_bits + d_bits, _PC2))
    return subkeys


def _f(r_bits: list[int], subkey: list[int]) -> list[int]:
    """Implémente la fonction F de DES pour un demi-bloc et une sous-clé."""

    # Étapes standard : expansion E, XOR avec la sous-clé, substitution par
    # S-boxes, puis permutation P.
    expanded = _permute(r_bits, _E)
    xored = _xor(expanded, subkey)
    sbox_out: list[int] = []
    for index in range(8):
        chunk = xored[index * 6:(index + 1) * 6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        value = _S[index][row * 16 + col]
        sbox_out.extend((value >> (3 - offset)) & 1 for offset in range(4))
    return _permute(sbox_out, _P)


def des_encrypt_n_rounds(plaintext: bytes, key: bytes, n_rounds: int) -> bytes:
    """Chiffre un bloc DES en s'arrêtant après ``n_rounds`` tours.

    C'est la fonction centrale de la mesure: elle permet d'observer comment la
    diffusion converge vers un comportement d'avalanche idéal au fil des tours.
    """
    subkeys = _generate_subkeys(key)[:n_rounds]
    bits = _bytes_to_bits(plaintext)
    perm = _permute(bits, _IP)
    left, right = perm[:32], perm[32:]
    for subkey in subkeys:
        left, right = right, _xor(left, _f(right, subkey))
    return _bits_to_bytes(_permute(right + left, _IP_INV))


def measure_avalanche_at_rounds(n_rounds: int, trials: int = TRIALS) -> float:
    """Mesure le score d'avalanche moyen pour un nombre de tours donné.

    À chaque essai, un seul bit du texte clair est modifié, puis on compare le
    nombre de bits changés dans les deux textes chiffrés obtenus.
    """
    key = os.urandom(8)
    scores: list[float] = []
    for _ in range(trials):
        block = os.urandom(8)
        reference = des_encrypt_n_rounds(block, key, n_rounds)
        flip_byte = secrets.randbelow(8)
        flip_bit = secrets.randbelow(8)
        modified = bytearray(block)
        modified[flip_byte] ^= 1 << flip_bit
        changed = des_encrypt_n_rounds(bytes(modified), key, n_rounds)
        # Le score est ramené sur 64 bits pour obtenir une proportion entre 0 et 1.
        diff_bits = sum(bin(a ^ b).count("1") for a, b in zip(reference, changed))
        scores.append(diff_bits / 64.0)
    return sum(scores) / len(scores)


def measure_rounds_series(trials: int = TRIALS) -> list[dict[str, float]]:
    """Construit la série complète utilisée par le graphique rounds vs avalanche.

    La sortie est déjà prête pour l'affichage console et pour le rendu du
    graphique final.
    """
    series = []
    for n_rounds in range(1, 17):
        score = measure_avalanche_at_rounds(n_rounds, trials=trials)
        series.append({
            "rounds": n_rounds,
            "score": score,
            # Le rendu affiche le résultat en pourcentage pour rester cohérent
            # avec les autres graphiques d'effet d'avalanche.
            "score_pct": score * 100.0,
            "delta_from_ideal_pp": abs(score * 100.0 - 50.0),
        })
    return series

