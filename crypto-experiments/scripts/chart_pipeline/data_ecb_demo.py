"""Prépare les données de la démonstration visuelle ECB vs CBC.

Ce module génère l'image synthétique source, applique les chiffrement ECB et
CBC, puis expose les utilitaires BMP nécessaires au rendu final.
"""

from __future__ import annotations

import struct
from pathlib import Path

from Crypto.Cipher import AES as _AES
from Crypto.Util.Padding import pad


# ---------------------------------------------------------------------------
# Paramètres de la démonstration
# ---------------------------------------------------------------------------
# Une petite image carrée suffit pour montrer les motifs répétitifs sans
# alourdir inutilement les fichiers générés.
WIDTH = 128
HEIGHT = 128
# Clé fixe: l'objectif est une démonstration visuelle reproductible, pas une
# simulation de bonnes pratiques opérationnelles de gestion de clés.
KEY = bytes.fromhex("00112233445566778899aabbccddeeff")


def make_image() -> bytes:
    """Construit une image synthétique avec de grandes zones uniformes.

    Ce type d'image rend immédiatement visibles les motifs que le mode ECB
    laisse apparaître dans le texte chiffré.
    """
    img = bytearray(WIDTH * HEIGHT)
    for index in range(len(img)):
        img[index] = 200
    for row in range(10, 60):
        for col in range(10, 118):
            img[row * WIDTH + col] = 40
    for row in range(70, 118):
        for col in range(10, 60):
            img[row * WIDTH + col] = 100
    for row in range(70, 118):
        for col in range(68, 118):
            img[row * WIDTH + col] = 255
    return bytes(img)


def write_bmp(path: Path, pixels_grey: bytes) -> None:
    """Écrit un BMP 24 bits à partir d'octets de niveaux de gris.

    Le format BMP est choisi ici car il est simple à générer sans dépendance
    externe, tout en restant facile à relire pour la démo.
    """
    row_size = (WIDTH * 3 + 3) & ~3
    pixel_data_size = row_size * HEIGHT
    file_size = 54 + pixel_data_size
    header = struct.pack("<2sIHHI", b"BM", file_size, 0, 0, 54)
    dib = struct.pack("<IiiHHIIiiII", 40, WIDTH, HEIGHT, 1, 24, 0, pixel_data_size, 2835, 2835, 0, 0)
    rows = []
    for row in range(HEIGHT - 1, -1, -1):
        row_bytes = bytearray()
        for col in range(WIDTH):
            grey = pixels_grey[row * WIDTH + col]
            row_bytes += bytes([grey, grey, grey])
        row_bytes += b"\x00" * (row_size - WIDTH * 3)
        rows.append(bytes(row_bytes))
    path.write_bytes(header + dib + b"".join(rows))


def read_bmp_as_array(path: Path) -> list[list[int]]:
    """Relit un BMP en matrice 2D utilisable par matplotlib."""

    # On reconstruit une matrice de gris ligne par ligne pour pouvoir afficher
    # directement l'image avec imshow().
    data = path.read_bytes()
    offset = struct.unpack_from("<I", data, 10)[0]
    width = struct.unpack_from("<i", data, 18)[0]
    height = struct.unpack_from("<i", data, 22)[0]
    row_size = (width * 3 + 3) & ~3
    img = []
    for row in range(abs(height) - 1, -1, -1):
        row_start = offset + row * row_size
        grey_row = []
        for col in range(width):
            grey_row.append(data[row_start + col * 3])
        img.append(grey_row)
    return img


def ecb_encrypt_raw(pixels: bytes) -> bytes:
    """Chiffre les pixels avec AES-128 en mode ECB."""
    cipher = _AES.new(KEY, _AES.MODE_ECB)
    return cipher.encrypt(pad(pixels, 16))


def cbc_encrypt_raw(pixels: bytes) -> bytes:
    """Chiffre les pixels avec AES-128 en mode CBC.

    L'IV nul est acceptable ici car on cherche uniquement une comparaison
    visuelle reproductible entre ECB et CBC dans une démo pédagogique.
    """
    cipher = _AES.new(KEY, _AES.MODE_CBC, iv=bytes(16))
    return cipher.encrypt(pad(pixels, 16))


def build_demo_images() -> dict[str, bytes]:
    """Prépare les trois images utiles au rendu final.

    Les versions chiffrées sont tronquées à la taille originale de l'image afin
    de rester affichables comme matrice de pixels 128x128.
    """
    original_pixels = make_image()
    # La fonction de rendu n'a besoin que de ces trois versions déjà prêtes.
    return {
        "original": original_pixels,
        "ecb": ecb_encrypt_raw(original_pixels)[:WIDTH * HEIGHT],
        "cbc": cbc_encrypt_raw(original_pixels)[:WIDTH * HEIGHT],
    }
