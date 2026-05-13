"""
analyse_rounds_avalanche.py
Analyse de l'avalanche DES à nombre de tours réduit.

Inspiré du retour du professeur (TN1, Retour 11) :
  « Une chose que vous pouvez observer est le nombre de tours (rounds) optimal
   qui donne un score d'avalanche maximal. »

Ce script mesure le score d'avalanche du chiffrement Feistel DES à chaque
nombre de tours de 1 à 16, montrant à quel tour la propriété de diffusion
converge vers la valeur idéale de 0,50.

Il réimplémente la structure Feistel DES au niveau des bits en utilisant les
S-boxes, la P-box, et les permutations IP et IP-1 standard DES, afin de pouvoir
s'arrêter après un nombre quelconque de tours. Le calendrier de clés reste
complet (les 16 sous-clés sont dérivées), mais seules les N premières
sous-clés sont appliquées.

Usage
-----
    py scripts/analyse_rounds_avalanche.py

Sortie : data/charts/fig7_rounds_avalanche.png + tableau console
"""

import os
import sys
import secrets

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ---------------------------------------------------------------------------
# Constantes DES (tables FIPS 46-3 standard)
# ---------------------------------------------------------------------------

# Permutation initiale (IP)
_IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

# Permutation initiale inverse (IP-1)
_IP_INV = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25,
]

# Permutation d'expansion (E)
_E = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
]

# Permutation P-box
_P = [
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25,
]

# S-boxes (8 boîtes × 4 lignes × 16 colonnes)
_S = [
    # S1
    [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
      0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
      4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
     15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    # S2
    [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
      3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
      0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
     13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    # S3
    [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
     13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
     13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
      1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    # S4
    [ 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
     13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
     10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
      3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    # S5
    [ 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
     14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
      4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
     11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    # S6
    [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
     10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
      9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
      4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    # S7
    [ 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
     13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
      1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
      6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    # S8
    [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
      1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
      7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
      2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
]

# Choix permuté 1 (PC-1) pour le calendrier de clés
_PC1 = [
    57,49,41,33,25,17, 9,
     1,58,50,42,34,26,18,
    10, 2,59,51,43,35,27,
    19,11, 3,60,52,44,36,
    63,55,47,39,31,23,15,
     7,62,54,46,38,30,22,
    14, 6,61,53,45,37,29,
    21,13, 5,28,20,12, 4,
]

# Choix permuté 2 (PC-2) pour le calendrier de clés
_PC2 = [
    14,17,11,24, 1, 5, 3,28,
    15, 6,21,10,23,19,12, 4,
    26, 8,16, 7,27,20,13, 2,
    41,52,31,37,47,55,30,40,
    51,45,33,48,44,49,39,56,
    34,53,46,42,50,36,29,32,
]

# Planning des décalages gauches pour le calendrier de clés
_SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

# ---------------------------------------------------------------------------
# Fonctions utilitaires au niveau des bits
# ---------------------------------------------------------------------------

def _bytes_to_bits(b: bytes) -> list:
    bits = []
    for byte in b:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def _bits_to_bytes(bits: list) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)

def _permute(bits: list, table: list) -> list:
    return [bits[t - 1] for t in table]

def _xor(a: list, b: list) -> list:
    return [x ^ y for x, y in zip(a, b)]

def _lrot(bits: list, n: int) -> list:
    return bits[n:] + bits[:n]

# ---------------------------------------------------------------------------
# Calendrier de clés
# ---------------------------------------------------------------------------

def _generate_subkeys(key: bytes) -> list:
    """Retourne les 16 sous-clés DES (chacune de 48 bits sous forme de liste)."""
    key_bits = _bytes_to_bits(key)
    key_56   = _permute(key_bits, _PC1)
    C, D     = key_56[:28], key_56[28:]
    subkeys  = []
    for shift in _SHIFTS:
        C = _lrot(C, shift)
        D = _lrot(D, shift)
        subkeys.append(_permute(C + D, _PC2))
    return subkeys

# ---------------------------------------------------------------------------
# Fonction F de DES
# ---------------------------------------------------------------------------

def _f(R: list, subkey: list) -> list:
    expanded = _permute(R, _E)          # 32 → 48 bits
    xored    = _xor(expanded, subkey)   # XOR avec la sous-clé
    # Substitution par S-boxes
    sbox_out = []
    for i in range(8):
        chunk = xored[i*6:(i+1)*6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        val = _S[i][row * 16 + col]
        sbox_out += [(val >> (3 - j)) & 1 for j in range(4)]
    return _permute(sbox_out, _P)       # permutation P → 32 bits

# ---------------------------------------------------------------------------
# Chiffrement DES à nombre de tours réduit
# ---------------------------------------------------------------------------

def des_encrypt_n_rounds(plaintext: bytes, key: bytes, n_rounds: int) -> bytes:
    """
    Chiffre un bloc de 8 octets avec DES en n'appliquant que n_rounds (1–16).

    Paramètres
    ----------
    plaintext : bytes
        Exactement 8 octets.
    key : bytes
        Exactement 8 octets.
    n_rounds : int
        Nombre de tours Feistel à appliquer (1 à 16).

    Retourne
    --------
    bytes
        Texte chiffré de 8 octets.
    """
    subkeys = _generate_subkeys(key)[:n_rounds]
    bits    = _bytes_to_bits(plaintext)
    perm    = _permute(bits, _IP)
    L, R    = perm[:32], perm[32:]

    for sk in subkeys:
        L, R = R, _xor(L, _f(R, sk))

    # Échange final + permutation inverse
    combined = _permute(R + L, _IP_INV)
    return _bits_to_bytes(combined)

# ---------------------------------------------------------------------------
# Mesure de l'avalanche (flip d'un bit en texte clair)
# ---------------------------------------------------------------------------

TRIALS = 500

def measure_avalanche_at_rounds(n_rounds: int) -> float:
    key        = os.urandom(8)
    total_bits = 64
    scores     = []

    for _ in range(TRIALS):
        block    = os.urandom(8)
        ref_ct   = des_encrypt_n_rounds(block, key, n_rounds)

        flip_byte = secrets.randbelow(8)
        flip_bit  = secrets.randbelow(8)
        modified  = bytearray(block)
        modified[flip_byte] ^= (1 << flip_bit)
        mod_ct   = des_encrypt_n_rounds(bytes(modified), key, n_rounds)

        diff_bits = sum(bin(a ^ b).count("1") for a, b in zip(ref_ct, mod_ct))
        scores.append(diff_bits / total_bits)

    return sum(scores) / len(scores)

# ---------------------------------------------------------------------------
# Programme principal
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"Mesure du score d'avalanche DES pour les tours 1–16 ({TRIALS} essais chacun)…\n")
    print(f"{'Rounds':>8}  {'Avalanche Score':>16}  {'Δ from ideal':>14}")
    print("-" * 44)

    rounds_list = list(range(1, 17))
    scores      = []

    for n in rounds_list:
        score = measure_avalanche_at_rounds(n)
        scores.append(score)
        delta = abs(score - 0.5)
        print(f"{n:>8}  {score:>16.4f}  {delta:>+14.4f}")

    # Save chart
    CHARTS_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "charts")
    os.makedirs(CHARTS_DIR, exist_ok=True)

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.plot(rounds_list, scores, marker="o", linewidth=2,
            color="#1565C0", label="Score d'avalanche (DES)")
    ax.axhline(0.5, color="black", linestyle="--", linewidth=1.2,
               label="Valeur idéale (0,50)")
    ax.fill_between(rounds_list, [0.48]*16, [0.52]*16,
                    alpha=0.1, color="green", label="Plage ±2 % autour de l'idéal")

    ax.set_xlabel("Nombre de tours (rounds)", fontsize=11)
    ax.set_ylabel("Score d'effet d'avalanche", fontsize=11)
    ax.set_title(
        "Figure 7 — Convergence de l'effet d'avalanche selon le nombre de tours DES\n"
        f"({TRIALS} essais par configuration, flip d'un bit en entrée)",
        fontsize=11,
    )
    ax.set_xticks(rounds_list)
    ax.set_ylim(0, 1)
    ax.legend(fontsize=9)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)
    plt.tight_layout()

    out = os.path.join(CHARTS_DIR, "fig7_rounds_avalanche.png")
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"\nChart saved: {out}")
