"""Construit le graphique de vulnérabilité visuelle du mode ECB.

Structure
---------
1. charts.data_ecb_demo prépare les pixels et les BMP intermédiaires.
2. Ce module construit la figure finale.
"""

from __future__ import annotations

import os
import sys


SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
SCRIPTS_DIR = os.path.dirname(SCRIPT_DIR)
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

import matplotlib.pyplot as plt

from charts.style_charts import BG_COLOR, PANEL_COLOR, TEXT_COLOR, setup_matplotlib
from charts.data_ecb_demo import build_demo_images, read_bmp_as_array, write_bmp
from charts.shared_paths import CHARTS_DIR, ensure_chart_dir


setup_matplotlib(title_pad=8)


def generate_ecb_demo_chart():
    print("Génération de la démonstration de vulnérabilité ECB…")
    images = build_demo_images()

    ecb_demo_dir = ensure_chart_dir("03-encryption-modes/demo-ecb")
    orig_path = ecb_demo_dir / "image-original.bmp"
    ecb_path = ecb_demo_dir / "image-encrypted-ecb.bmp"
    cbc_path = ecb_demo_dir / "image-encrypted-cbc.bmp"

    write_bmp(orig_path, images["original"])
    write_bmp(ecb_path, images["ecb"])
    write_bmp(cbc_path, images["cbc"])

    print(f"  Enregistré: {orig_path}")
    print(f"  Enregistré: {ecb_path}")
    print(f"  Enregistré: {cbc_path}")

    orig_arr = read_bmp_as_array(orig_path)
    ecb_arr = read_bmp_as_array(ecb_path)
    cbc_arr = read_bmp_as_array(cbc_path)

    fig, axes = plt.subplots(1, 3, figsize=(12, 4.5))
    fig.patch.set_facecolor(BG_COLOR)
    for ax in axes:
        ax.set_facecolor(PANEL_COLOR)

    axes[0].imshow(orig_arr, cmap="gray", vmin=0, vmax=255)
    axes[0].set_title("Image A: originale", fontsize=10, color=TEXT_COLOR, pad=8)
    axes[0].axis("off")

    axes[1].imshow(ecb_arr, cmap="gray", vmin=0, vmax=255)
    axes[1].set_title("Image B: chiffree en mode ECB", fontsize=10, color=TEXT_COLOR, pad=8)
    axes[1].axis("off")

    axes[2].imshow(cbc_arr, cmap="gray", vmin=0, vmax=255)
    axes[2].set_title("Image C: chiffree en mode CBC", fontsize=10, color=TEXT_COLOR, pad=8)
    axes[2].axis("off")
    plt.tight_layout()

    mode_dir = ensure_chart_dir("03-encryption-modes")
    out = mode_dir / "graph-08-ecb-visual-pattern-leakage-demo.png"
    fig.savefig(out, dpi=180, bbox_inches="tight", facecolor=BG_COLOR)
    plt.close(fig)
    print(f"  Enregistré: {out}")
    print("\nTerminé.")


if __name__ == "__main__":
    generate_ecb_demo_chart()



