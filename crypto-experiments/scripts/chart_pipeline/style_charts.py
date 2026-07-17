"""Style partagé des graphiques, palette et helpers de sauvegarde."""

from __future__ import annotations

from pathlib import Path

import matplotlib
import matplotlib.pyplot as plt


BG_COLOR = "#FFFFFF"
PANEL_COLOR = "#FFFFFF"
GRID_COLOR = "#F0F0F0"
TEXT_COLOR = "#555555"
DPI = 180
FIG_W = 11

ALGO_COLORS = {
    "AES": "#0A0A0A",
    "DES": "#B03A2E",
    "3DES": "#D4783A",
    "Twofish": "#C9A84C",
    "ChaCha20": "#1A5E8A",
}

MODE_COLORS = {
    "ECB": "#B03A2E",
    "CBC": "#1A5E8A",
    "CTR": "#3A7A3A",
    "GCM": "#C9A84C",
}

MODE_HATCH = {"ECB": "", "CBC": "/", "CTR": "x", "GCM": "."}

PLATFORM_STYLE = {
    "x86": {"hatch": "", "alpha": 0.82, "label": "Laptop x86 (Windows)"},
    "pi": {"hatch": "//", "alpha": 0.45, "label": "Raspberry Pi (ARM)"},
}


def setup_matplotlib(title_pad: int = 12, hatch_linewidth: float | None = None) -> None:
    matplotlib.use("Agg")
    plt.rcParams.update({
        "figure.facecolor": BG_COLOR,
        "axes.facecolor": PANEL_COLOR,
        "axes.edgecolor": GRID_COLOR,
        "axes.labelcolor": TEXT_COLOR,
        "axes.titlecolor": "#0A0A0A",
        "xtick.color": "#888888",
        "ytick.color": "#888888",
        "text.color": TEXT_COLOR,
        "grid.color": GRID_COLOR,
        "grid.linestyle": "--",
        "grid.alpha": 0.8,
        "legend.facecolor": "#FFFFFF",
        "legend.edgecolor": "#C0C0C0",
        "legend.labelcolor": TEXT_COLOR,
        "font.family": "DejaVu Sans",
        "axes.titlepad": title_pad,
    })
    if hatch_linewidth is not None:
        plt.rcParams["hatch.linewidth"] = hatch_linewidth
        matplotlib.rcParams["hatch.color"] = (0.0, 0.0, 0.0, 0.25)


def style_ax(ax) -> None:
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_edgecolor("#C0C0C0")
    ax.spines["bottom"].set_edgecolor("#C0C0C0")
    ax.set_axisbelow(True)
    ax.yaxis.grid(True)


def save_figure(fig, output_root: Path, relative_path: str, facecolor: str = BG_COLOR, dpi: int = DPI) -> Path:
    path = output_root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=dpi, bbox_inches="tight", facecolor=facecolor)
    plt.close(fig)
    print(f"  Enregistré: {path}")
    return path
