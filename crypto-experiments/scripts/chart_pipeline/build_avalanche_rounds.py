"""Construit le graphique d'avalanche DES à nombre de tours réduit.

Structure
---------
1. chart_pipeline.data_avalanche_rounds prépare les mesures.
2. Ce module construit le graphique final et l'affichage console.
"""

from __future__ import annotations

import os
import sys


SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
SCRIPTS_DIR = os.path.dirname(SCRIPT_DIR)
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

import matplotlib.pyplot as plt

from chart_pipeline.data_avalanche_rounds import TRIALS, measure_rounds_series
from chart_pipeline.style_charts import BG_COLOR, TEXT_COLOR, setup_matplotlib
from chart_pipeline.shared_paths import CHARTS_DIR, ensure_chart_dir


setup_matplotlib(title_pad=12)


def generate_rounds_avalanche_chart():
    print(f"Mesure du score d'avalanche DES pour les tours 1–16 ({TRIALS} essais chacun)…\n")
    print(f"{'Tours':>8}  {'Avalanche (%)':>16}  {'Δ à 50% (pp)':>14}")
    print("-" * 44)

    series = measure_rounds_series(trials=TRIALS)
    for item in series:
        print(
            f"{item['rounds']:>8}  {item['score_pct']:>16.2f}  {item['delta_from_ideal_pp']:>+14.2f}"
        )

    rounds_list = [item["rounds"] for item in series]
    scores_pct = [item["score_pct"] for item in series]

    fig, ax = plt.subplots(figsize=(9, 5))
    fig.patch.set_facecolor(BG_COLOR)
    ax.set_facecolor(BG_COLOR)
    ax.plot(rounds_list, scores_pct, marker="o", linewidth=2, color="#B03A2E", label="Score d'avalanche (DES)")
    ax.axhline(50.0, color="#0A0A0A", linestyle="--", linewidth=1.2, label="Valeur idéale (50 %)")
    ax.fill_between(rounds_list, [49.0] * 16, [51.0] * 16, alpha=0.10, color="#3A7A3A", label="Plage ±1 % autour de l'idéal")
    ax.set_xlabel("Nombre de tours (rounds)", fontsize=11)
    ax.set_ylabel("Pourcentage de bits modifiés dans le texte chiffré (%)", fontsize=11)
    ax.set_title("Score d'avalanche en fonction du nombre de tours DES", fontsize=11)
    ax.set_xticks(rounds_list)
    ax.set_ylim(40, 60)
    ax.legend(fontsize=9)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    ax.tick_params(colors=TEXT_COLOR)
    ax.set_axisbelow(True)
    plt.tight_layout()

    aval_dir = ensure_chart_dir("02-avalanche-effect")
    out = aval_dir / "avalanche-convergence-des-rounds.png"
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor=BG_COLOR)
    plt.close(fig)
    print(f"\nGraphique enregistré: {out}")


if __name__ == "__main__":
    generate_rounds_avalanche_chart()

