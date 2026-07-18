"""Construit les graphiques de comparaison x86/ARM à partir des CSV de benchmark.

Chaîne de traitement
-------------------
1. scripts/experiment.py produit un CSV sur chaque machine.
2. Les CSV x86 et Raspberry Pi sont copiés dans data/results/.
3. scripts/run_charts.py orchestre la génération.
4. Ce module lit les deux CSV et génère les graphiques de comparaison.

Structure du fichier
-------------------
- Recherche et chargement des CSV x86 / ARM
- Style réutilisable commun à tous les graphiques
- Graphique 1, Graphique 2, ... : une fonction par graphique
- CHART_GROUPS / GRAPH_OUTPUTS : correspondance dossier -> fonctions -> PNG

Utilisation
-----------
    py scripts/run_charts.py 01
    py scripts/run_charts.py 02
    py scripts/run_charts.py 04
"""

import os
import sys
from collections import defaultdict

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
SCRIPTS_DIR = os.path.dirname(SCRIPT_DIR)
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from chart_pipeline.style_charts import (
    ALGO_COLORS,
    BG_COLOR,
    FIG_W,
    GRID_COLOR,
    PANEL_COLOR,
    PLATFORM_STYLE,
    TEXT_COLOR,
    save_figure,
    setup_matplotlib,
)
from chart_pipeline.data_platform import load_platform_rows
from chart_pipeline.shared_paths import CHARTS_DIR as OUT_DIR, ensure_chart_dir


setup_matplotlib(title_pad=14)
for subdir in ["01-debit", "02-effet-avalanche", "04-synthese"]:
    ensure_chart_dir(subdir)

# Mode de référence par algorithme pour la comparaison inter-plateformes.
# ChaCha20 ne possède pas de mode ECB: on utilise Stream.
BEST_MODE = {
    "AES":      "ECB",
    "DES":      "ECB",
    "3DES":     "ECB",
    "Twofish":  "ECB",
    "ChaCha20": "Stream",
}

try:
    x86_paths, pi_paths, x86_rows, pi_rows = load_platform_rows()
except FileNotFoundError as exc:
    message = str(exc)
    if "Raspberry Pi" in message:
        print("\n⚠  Aucun CSV Raspberry Pi trouvé dans data/results/")
        print("   Fichier attendu: raspberry-pi_experience*.csv")
        print("   Exécute experiment.py sur le Pi, copie le CSV ici, puis relance le script.")
        sys.exit(0)
    print(f"ERREUR: {message}")
    sys.exit(1)

print(f"Sources Raspberry Pi ({len(pi_paths)}) : {', '.join(p.name for p in pi_paths)}")


def _lookup(rows, algo, mode, key_bits, msg_size):
    for r in rows:
        if (r["algorithm"] == algo and r["mode"] == mode
                and r["key_size_bits"] == key_bits
                and r["message_size_bytes"] == msg_size):
            return r
    return None


def savefig(name: str):
    save_figure(plt.gcf(), OUT_DIR, name, facecolor=BG_COLOR)


# ===========================================================================
# Dossier 01 — debit
# ===========================================================================


# ===========================================================================
# Graphique 1 — 01-debit/throughput-by-algo-x86-vs-arm-4kb.png
# Barres de débit côte-à-côte (ECB, 4096 o, meilleure clé par algo)
# ===========================================================================
def cmp1_throughput_all():
    target_size = 4096
    best_key = {"AES": 256, "DES": 64, "3DES": 192, "Twofish": 256, "ChaCha20": 256}
    algo_order = list(best_key.keys())

    x = np.arange(len(algo_order))
    w = 0.32
    fig, ax = plt.subplots(figsize=(FIG_W, 5.5))
    fig.patch.set_facecolor(BG_COLOR)

    x86_vals, pi_vals, colors = [], [], []
    for algo in algo_order:
        kb   = best_key[algo]
        mode = BEST_MODE[algo]
        r86 = _lookup(x86_rows, algo, mode, kb, target_size)
        rpi = _lookup(pi_rows,  algo, mode, kb, target_size)
        x86_vals.append(r86["throughput_enc"] if r86 else 0)
        pi_vals.append( rpi["throughput_enc"] if rpi else 0)
        colors.append(ALGO_COLORS.get(algo, "#888"))

    bars_x86 = ax.bar(x - w/2, x86_vals, w, label="Laptop x86 (Windows)",
                      color=colors, edgecolor=BG_COLOR, linewidth=0.8,
                      alpha=PLATFORM_STYLE["x86"]["alpha"])
    ax.bar(x + w/2, pi_vals, w, label="Raspberry Pi (ARM)",
           color=colors, edgecolor=BG_COLOR, linewidth=0.8,
           alpha=PLATFORM_STYLE["pi"]["alpha"], hatch="//")

    for bar, val in zip(bars_x86, x86_vals):
        if val > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, val + max(x86_vals) * 0.01,
                    f"{val:.0f}", ha="center", va="bottom",
                    fontsize=8, color=TEXT_COLOR, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(algo_order, fontsize=11)
    ax.set_ylabel("Débit de chiffrement (MB/s)", fontsize=11)
    ax.set_title(
        "Débit de chiffrement en fonction de l'algorithme",
        fontsize=11,
    )
    ax.legend(fontsize=9)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_edgecolor(GRID_COLOR)
    ax.spines["bottom"].set_edgecolor(GRID_COLOR)
    plt.tight_layout()
    savefig("01-debit/throughput-by-algo-x86-vs-arm-4kb.png")


# ===========================================================================
# Graphique 1b — 01-debit/throughput-by-algo-mode-arm-4kb.png
# Comparaison du débit à 4 096 octets (Raspberry Pi uniquement)
# Une barre par combinaison algorithme+mode, regroupées par algorithme.
# ===========================================================================
def cmp1b_throughput_4096_pi():
    target_size = 4096
    data = [r for r in pi_rows if r["message_size_bytes"] == target_size]

    groups = defaultdict(list)
    for r in data:
        label = f"{r['mode']}\n{r['key_size_bits']}b"
        groups[r["algorithm"]].append((label, r["throughput_enc"]))

    algo_order = ["AES", "DES", "3DES", "Twofish", "ChaCha20"]
    fig, ax = plt.subplots(figsize=(FIG_W, 5.5))
    fig.patch.set_facecolor(BG_COLOR)

    x_pos = 0
    tick_positions, tick_labels = [], []
    group_centers = {}

    for algo in algo_order:
        if algo not in groups:
            continue
        items = groups[algo]
        start = x_pos
        for label, mbps in items:
            ax.bar(
                x_pos,
                mbps,
                color=ALGO_COLORS.get(algo, "#888"),
                edgecolor=BG_COLOR,
                linewidth=0.8,
                width=0.7,
                alpha=PLATFORM_STYLE["pi"]["alpha"],
                hatch=PLATFORM_STYLE["pi"]["hatch"],
            )
            tick_positions.append(x_pos)
            tick_labels.append(label)
            x_pos += 1
        group_centers[algo] = (start + x_pos - 1) / 2
        x_pos += 0.8

    ax.set_xticks(tick_positions)
    ax.set_xticklabels(tick_labels, fontsize=7)
    ax.set_ylabel("Débit de chiffrement (MB/s)", fontsize=11)
    ax.set_title("Débit de chiffrement en fonction de l'algorithme et du mode", fontsize=11, pad=20)
    ax.text(
        0.5,
        1.01,
        "Données Raspberry Pi uniquement",
        transform=ax.transAxes,
        ha="center",
        va="bottom",
        fontsize=9,
        fontstyle="italic",
        color=TEXT_COLOR,
    )

    for algo, cx in group_centers.items():
        ax.text(
            cx,
            -ax.get_ylim()[1] * 0.12,
            algo,
            ha="center",
            fontsize=9,
            fontweight="bold",
            color=ALGO_COLORS.get(algo, "#888"),
        )

    legend_patches = [
        mpatches.Patch(color=ALGO_COLORS.get(a, "#888"), label=a)
        for a in algo_order
        if a in groups
    ]
    ax.legend(handles=legend_patches, loc="upper right", fontsize=9)
    ax.set_ylim(bottom=0)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_edgecolor(GRID_COLOR)
    ax.spines["bottom"].set_edgecolor(GRID_COLOR)
    plt.tight_layout()
    savefig("01-debit/throughput-by-algo-mode-arm-4kb.png")


# ===========================================================================
# Graphique 2 — 01-debit/speedup-ratio-x86-over-arm-by-algo.png
# Rapport d'accélération x86/Pi par algorithme (ECB, 4096 o)
# Montre dans quelle mesure x86 est plus rapide que le Pi pour chaque algorithme.
# ===========================================================================
def cmp2_speedup_ratio():
    target_size = 4096
    best_key = {"AES": 256, "DES": 64, "3DES": 192, "Twofish": 256, "ChaCha20": 256}
    algo_order = list(best_key.keys())

    ratios, algos, colors = [], [], []
    for algo in algo_order:
        kb   = best_key[algo]
        mode = BEST_MODE[algo]
        r86 = _lookup(x86_rows, algo, mode, kb, target_size)
        rpi = _lookup(pi_rows,  algo, mode, kb, target_size)
        if r86 and rpi and rpi["throughput_enc"] > 0:
            ratios.append(r86["throughput_enc"] / rpi["throughput_enc"])
            algos.append(algo)
            colors.append(ALGO_COLORS.get(algo, "#888"))

    fig, ax = plt.subplots(figsize=(9, 5))
    fig.patch.set_facecolor(BG_COLOR)
    bars = ax.bar(algos, ratios, color=colors, edgecolor=BG_COLOR,
                  linewidth=0.8, width=0.5,
                  alpha=PLATFORM_STYLE["x86"]["alpha"])
    ax.axhline(1.0, color="#475569", linestyle="--", linewidth=1.4,
               label="Ratio = 1 (performances égales)")

    for bar, r, c in zip(bars, ratios, colors):
        ax.text(bar.get_x() + bar.get_width() / 2, r + 0.06,
                f"{r:.2f}×", ha="center", va="bottom",
                fontsize=10, fontweight="bold", color=c)

    ax.set_ylabel("Rapport de débit x86 / Pi (×)", fontsize=11)
    ax.set_title(
        "Ratio de performance en fonction de l'algorithme",
        fontsize=11,
    )
    ax.legend(fontsize=9)
    ax.set_ylim(bottom=0)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_edgecolor(GRID_COLOR)
    ax.spines["bottom"].set_edgecolor(GRID_COLOR)
    plt.tight_layout()
    savefig("01-debit/speedup-ratio-x86-over-arm-by-algo.png")


# ===========================================================================
# Graphique 3 — 01-debit/throughput-vs-message-size-x86-vs-arm-ecb.png
# Débit selon la taille du message : les deux plateformes, ECB, meilleure clé par algo
# ===========================================================================
def cmp3_throughput_vs_size():
    best_key = {"AES": 256, "DES": 64, "3DES": 192, "Twofish": 256, "ChaCha20": 256}
    msg_sizes = sorted({r["message_size_bytes"] for r in x86_rows if r["mode"] == "ECB"})

    fig, ax = plt.subplots(figsize=(FIG_W, 5.5))
    fig.patch.set_facecolor(BG_COLOR)
    for algo, kb in best_key.items():
        color = ALGO_COLORS.get(algo, "#888")
        # x86 — trait plein
        x86_pts = sorted(
            [r for r in x86_rows if r["algorithm"] == algo and r["mode"] == "ECB"
             and r["key_size_bits"] == kb],
            key=lambda r: r["message_size_bytes"]
        )
        if x86_pts:
            ax.plot([r["message_size_bytes"] for r in x86_pts],
                    [r["throughput_enc"] for r in x86_pts],
                    marker="o", color=color, linewidth=2.2,
                    label=f"{algo} x86", linestyle="-",
                    alpha=0.95, markersize=5)
        # Pi — trait pointillé
        pi_pts = sorted(
            [r for r in pi_rows if r["algorithm"] == algo and r["mode"] == "ECB"
             and r["key_size_bits"] == kb],
            key=lambda r: r["message_size_bytes"]
        )
        if pi_pts:
            ax.plot([r["message_size_bytes"] for r in pi_pts],
                    [r["throughput_enc"] for r in pi_pts],
                    marker="s", color=color, linewidth=2.2,
                    label=f"{algo} Pi", linestyle="--",
                    alpha=0.50, markersize=5)

    ax.set_xscale("log", base=2)
    ax.set_xticks(msg_sizes)
    ax.set_xticklabels([f"{s:,}" for s in msg_sizes])
    ax.set_xlabel("Taille du message (octets)", fontsize=11)
    ax.set_ylabel("Débit de chiffrement (MB/s)", fontsize=11)
    ax.set_title("Débit en fonction de la taille du message", fontsize=11, pad=20)
    ax.text(
        0.5,
        1.01,
        "ECB forcé pour les algorithmes comparés",
        transform=ax.transAxes,
        ha="center",
        va="bottom",
        fontsize=9,
        fontstyle="italic",
        color=TEXT_COLOR,
    )
    ax.legend(fontsize=7, ncol=2)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_edgecolor(GRID_COLOR)
    ax.spines["bottom"].set_edgecolor(GRID_COLOR)
    plt.tight_layout()
    savefig("01-debit/throughput-vs-message-size-x86-vs-arm-ecb.png")


# ===========================================================================
# Graphique 4 — 01-debit/throughput-vs-message-size-chacha20-x86-vs-arm.png
# Performance ChaCha20 : x86 vs Pi sur toutes les tailles de message
# Intéressant car le Pi ne dispose pas d'AES-NI mais ChaCha20 n'a pas d'accélération
# matérielle sur aucune des deux plateformes — l'écart devrait être plus faible qu'avec AES.
# ===========================================================================
def cmp5_chacha20():
    msg_sizes = sorted({r["message_size_bytes"] for r in x86_rows
                        if r["algorithm"] == "ChaCha20"})
    if not msg_sizes:
        print("  (cmp5 ignoré — aucune donnée ChaCha20)")
        return

    cc_color = ALGO_COLORS["ChaCha20"]
    fig, ax = plt.subplots(figsize=(9, 5))
    fig.patch.set_facecolor(BG_COLOR)
    for data_rows, label, ls, marker, alpha in [
        (x86_rows, "ChaCha20 — Laptop x86", "-",  "o", 0.95),
        (pi_rows,  "ChaCha20 — Raspberry Pi", "--", "s", 0.50),
    ]:
        pts = sorted(
            [r for r in data_rows if r["algorithm"] == "ChaCha20"],
            key=lambda r: r["message_size_bytes"]
        )
        if pts:
            ax.plot([r["message_size_bytes"] for r in pts],
                    [r["throughput_enc"] for r in pts],
                    marker=marker, linewidth=2.2, linestyle=ls,
                    color=cc_color, label=label, alpha=alpha, markersize=6)

    ax.set_xscale("log", base=2)
    ax.set_xticks(msg_sizes)
    ax.set_xticklabels([f"{s:,}" for s in msg_sizes])
    ax.set_xlabel("Taille du message (octets)", fontsize=11)
    ax.set_ylabel("Débit de chiffrement (MB/s)", fontsize=11)
    ax.set_title(
        "Débit de ChaCha20 en fonction de la taille du message",
        fontsize=11,
    )
    ax.legend(fontsize=9)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_edgecolor(GRID_COLOR)
    ax.spines["bottom"].set_edgecolor(GRID_COLOR)
    plt.tight_layout()
    savefig("01-debit/throughput-vs-message-size-chacha20-x86-vs-arm.png")


# ===========================================================================
# Graphique 5 — 01-debit/ci95-throughput-stability-x86-vs-arm-4kb.png
# Stabilité des mesures : CI95 x86 vs Pi (ECB, 4096 o, meilleure clé)
# Montre lequel des deux environnements est le plus déterministe.
# ===========================================================================
def cmp6_ci95_stability():
    target_size = 4096
    best_key = {"AES": 256, "DES": 64, "3DES": 192, "Twofish": 256, "ChaCha20": 256}
    algo_order = [a for a in best_key if any(r["algorithm"] == a for r in x86_rows)]

    x = np.arange(len(algo_order))
    w = 0.32
    fig, ax = plt.subplots(figsize=(FIG_W, 5.5))
    fig.patch.set_facecolor(BG_COLOR)

    x86_ci, pi_ci, colors = [], [], []
    for algo in algo_order:
        mode = BEST_MODE[algo]
        kb   = best_key[algo]
        r86  = _lookup(x86_rows, algo, mode, kb, target_size)
        rpi  = _lookup(pi_rows,  algo, mode, kb, target_size)
        x86_ci.append(r86["ci95_enc"] if r86 else 0)
        pi_ci.append( rpi["ci95_enc"] if rpi else 0)
        colors.append(ALGO_COLORS.get(algo, "#888"))

    bars_x86 = ax.bar(x - w/2, x86_ci, w,
                      label="Laptop x86 (Windows)",
                      color=colors, edgecolor=BG_COLOR, linewidth=0.8,
                      alpha=PLATFORM_STYLE["x86"]["alpha"])
    ax.bar(x + w/2, pi_ci, w,
           label="Raspberry Pi (ARM)",
           color=colors, edgecolor=BG_COLOR, linewidth=0.8,
           alpha=PLATFORM_STYLE["pi"]["alpha"], hatch="//")

    # Étiquettes de valeur sur les barres x86.
    for bar, val in zip(bars_x86, x86_ci):
        if val > 0:
            ax.text(bar.get_x() + bar.get_width() / 2,
                    val + max(x86_ci) * 0.012,
                    f"{val:.2f}", ha="center", va="bottom",
                    fontsize=8, color=TEXT_COLOR, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(algo_order, fontsize=11)
    ax.set_ylabel("Largeur de l'IC95 du débit de chiffrement (MB/s)", fontsize=11)
    ax.set_title(
        "Stabilité des mesures en fonction de la plateforme (IC95, n=100 répétitions)",
        fontsize=11,
    )
    ax.legend(fontsize=9)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_edgecolor(GRID_COLOR)
    ax.spines["bottom"].set_edgecolor(GRID_COLOR)
    plt.tight_layout()
    savefig("01-debit/ci95-throughput-stability-x86-vs-arm-4kb.png")


# ===========================================================================
# Graphique 6 — 01-debit/throughput-vs-message-size-x86-vs-arm-all-algos.png
# Scalabilité tous algos : x86 (—) et Pi (- -) sur les mêmes axes
# ===========================================================================
def cmp8_scalability_all_algos():
    best_key  = {"AES": 256, "DES": 64, "3DES": 192, "Twofish": 256, "ChaCha20": 256}
    algo_order = ["AES", "ChaCha20", "DES", "3DES", "Twofish"]
    msg_sizes = sorted({r["message_size_bytes"] for r in x86_rows})

    fig, ax = plt.subplots(figsize=(FIG_W, 5.5))
    fig.patch.set_facecolor(BG_COLOR)

    for algo in algo_order:
        mode  = BEST_MODE[algo]
        kb    = best_key[algo]
        color = ALGO_COLORS.get(algo, "#888")

        pts_x86 = sorted(
            [r for r in x86_rows if r["algorithm"] == algo and r["mode"] == mode and r["key_size_bits"] == kb],
            key=lambda r: r["message_size_bytes"])
        if pts_x86:
            ax.plot([r["message_size_bytes"] for r in pts_x86],
                    [r["throughput_enc"] for r in pts_x86],
                    marker="o", linewidth=2, linestyle="-", color=color,
                    label=f"{algo} x86", alpha=0.9, markersize=4)

        pts_pi = sorted(
            [r for r in pi_rows if r["algorithm"] == algo and r["mode"] == mode and r["key_size_bits"] == kb],
            key=lambda r: r["message_size_bytes"])
        if pts_pi:
            ax.plot([r["message_size_bytes"] for r in pts_pi],
                    [r["throughput_enc"] for r in pts_pi],
                    marker="s", linewidth=2, linestyle="--", color=color,
                    label=f"{algo} Pi", alpha=0.45, markersize=4)

    ax.set_xscale("log", base=2)
    ax.set_xticks(msg_sizes)
    ax.set_xticklabels([f"{s:,}" for s in msg_sizes])
    ax.set_xlabel("Taille du message (octets)", fontsize=11)
    ax.set_ylabel("Débit de chiffrement (MB/s)", fontsize=11)
    ax.set_title("Débit en fonction de la taille du message — tous algorithmes", fontsize=11, pad=20)
    ax.text(
        0.5,
        1.01,
        "ECB pour AES/DES/3DES/Twofish, Stream pour ChaCha20",
        transform=ax.transAxes,
        ha="center",
        va="bottom",
        fontsize=9,
        fontstyle="italic",
        color=TEXT_COLOR,
    )
    ax.legend(fontsize=7, ncol=5)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_edgecolor(GRID_COLOR)
    ax.spines["bottom"].set_edgecolor(GRID_COLOR)
    plt.tight_layout()
    savefig("01-debit/throughput-vs-message-size-x86-vs-arm-all-algos.png")


# ===========================================================================
# Dossier 02 — effet-avalanche
# ===========================================================================


# ===========================================================================
# Graphique 7 — 02-effet-avalanche/avalanche-score-x86-vs-arm.png
# Scores d'avalanche : les deux plateformes (doivent être identiques — aucun effet matériel)
# ===========================================================================
def cmp4_avalanche():
    algo_order = ["AES", "DES", "3DES", "Twofish", "ChaCha20"]

    x86_means = {a: np.mean([r["avalanche"] for r in x86_rows if r["algorithm"] == a])
                 for a in algo_order if any(r["algorithm"] == a for r in x86_rows)}
    pi_means  = {a: np.mean([r["avalanche"] for r in pi_rows  if r["algorithm"] == a])
                 for a in algo_order if any(r["algorithm"] == a for r in pi_rows)}

    algos  = [a for a in algo_order if a in x86_means and a in pi_means]
    x      = np.arange(len(algos))
    w      = 0.35
    colors = [ALGO_COLORS.get(a, "#888") for a in algos]
    x86_vals_pct = [x86_means[a] * 100.0 for a in algos]
    pi_vals_pct  = [pi_means[a]  * 100.0 for a in algos]

    fig, ax = plt.subplots(figsize=(9, 5))
    fig.patch.set_facecolor(BG_COLOR)
    ax.bar(x - w/2, x86_vals_pct, w,
           label="x86", color=colors, edgecolor=BG_COLOR,
           linewidth=0.8, alpha=PLATFORM_STYLE["x86"]["alpha"])
    ax.bar(x + w/2, pi_vals_pct, w,
           label="Pi",  color=colors, edgecolor=BG_COLOR,
           linewidth=0.8, alpha=PLATFORM_STYLE["pi"]["alpha"], hatch="//")
    ax.axhline(50.0, color="#64748B", linestyle="--", linewidth=1.4,
               label="Valeur idéale (50 %)")
    ax.set_xticks(x)
    ax.set_xticklabels(algos, fontsize=11)
    ax.set_ylim(42.0, 64.0)
    ax.set_ylabel("Pourcentage de bits modifiés dans le texte chiffré (%)", fontsize=11)
    ax.set_title(
        "Score d'avalanche en fonction de l'algorithme",
        fontsize=11,
    )
    ax.legend(fontsize=9)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_edgecolor(GRID_COLOR)
    ax.spines["bottom"].set_edgecolor(GRID_COLOR)
    plt.tight_layout()
    savefig("02-effet-avalanche/avalanche-score-x86-vs-arm.png")


# ===========================================================================
# Dossier 04 — synthese
# ===========================================================================


# ===========================================================================
# Graphique 8 — 04-synthese/algorithm-profile-radar-chart.png
# Radar synthèse : tous algos sur 4 axes normalisés
# Débit x86 · Débit Pi · Avalanche · Portabilité (ratio Pi/x86)
# ===========================================================================
def cmp7_radar():
    algo_order = ["AES", "ChaCha20", "DES", "3DES", "Twofish"]
    best_key  = {"AES": 256, "DES": 64, "3DES": 192, "Twofish": 256, "ChaCha20": 256}
    target    = 16384  # plus grande taille de message pour le débit maximal

    x86_thr, pi_thr, aval_scores = {}, {}, {}
    for algo in algo_order:
        mode = BEST_MODE[algo]
        kb   = best_key[algo]
        r86  = _lookup(x86_rows, algo, mode, kb, target)
        rpi  = _lookup(pi_rows,  algo, mode, kb, target)
        x86_thr[algo] = r86["throughput_enc"] if r86 else 0
        pi_thr[algo]  = rpi["throughput_enc"] if rpi else 0
        avals = [r["avalanche"] for r in x86_rows if r["algorithm"] == algo]
        aval_scores[algo] = np.mean(avals) if avals else 0.5

    portability = {a: (pi_thr[a] / x86_thr[a]) if x86_thr[a] > 0 else 0 for a in algo_order}

    def norm(d):
        mx = max(d.values()) or 1
        return {k: v / mx for k, v in d.items()}

    n_x86  = norm(x86_thr)
    n_pi   = norm(pi_thr)
    n_aval = {a: 1 - abs(aval_scores[a] - 0.5) * 10 for a in algo_order}
    n_port = norm(portability)

    categories = ["Débit\nx86", "Débit\nPi (ARM)", "Avalanche\nqualité", "Portabilité\nPi/x86"]
    N      = len(categories)
    angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(9, 8), subplot_kw=dict(polar=True))
    fig.patch.set_facecolor(BG_COLOR)
    ax.set_facecolor(PANEL_COLOR)
    ax.spines["polar"].set_color(GRID_COLOR)
    ax.grid(color=GRID_COLOR, linestyle="--", alpha=0.5)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, size=10, color=TEXT_COLOR)
    ax.tick_params(axis="x", pad=12)
    ax.set_ylim(0, 1)
    ax.set_yticks([0.25, 0.5, 0.75, 1.0])
    ax.set_yticklabels(["", "50%", "", "100%"], size=8, color=TEXT_COLOR)
    ax.set_rlabel_position(22)
    ax.tick_params(colors=TEXT_COLOR)

    for algo in algo_order:
        vals = [n_x86[algo], n_pi[algo], n_aval[algo], n_port[algo]]
        vals += vals[:1]
        color = ALGO_COLORS.get(algo, "#888")
        ax.plot(angles, vals, linewidth=2, color=color, label=algo, alpha=0.9)
        ax.fill(angles, vals, alpha=0.08, color=color)

    ax.set_title(
        "Score global en fonction de l'algorithme (synthèse normalisée)",
        fontsize=11, color=TEXT_COLOR, pad=25,
    )
    ax.legend(loc="upper right", bbox_to_anchor=(1.28, 1.12), fontsize=9)
    plt.tight_layout()
    savefig("04-synthese/algorithm-profile-radar-chart.png")


CHART_GROUPS = {
    "01-debit": [
        cmp1_throughput_all,
        cmp1b_throughput_4096_pi,
        cmp2_speedup_ratio,
        cmp3_throughput_vs_size,
        cmp5_chacha20,
        cmp6_ci95_stability,
        cmp8_scalability_all_algos,
    ],
    "02-effet-avalanche": [
        cmp4_avalanche,
    ],
    "04-synthese": [
        cmp7_radar,
    ],
}

# Correspondance explicite: fonction de tracé -> fichier PNG de sortie.
# Utile pour vérifier rapidement comment chaque graphique est produit.
GRAPH_OUTPUTS = {
    cmp1_throughput_all: "01-debit/throughput-by-algo-x86-vs-arm-4kb.png",
    cmp1b_throughput_4096_pi: "01-debit/throughput-by-algo-mode-arm-4kb.png",
    cmp2_speedup_ratio: "01-debit/speedup-ratio-x86-over-arm-by-algo.png",
    cmp3_throughput_vs_size: "01-debit/throughput-vs-message-size-x86-vs-arm-ecb.png",
    cmp4_avalanche: "02-effet-avalanche/avalanche-score-x86-vs-arm.png",
    cmp5_chacha20: "01-debit/throughput-vs-message-size-chacha20-x86-vs-arm.png",
    cmp6_ci95_stability: "01-debit/ci95-throughput-stability-x86-vs-arm-4kb.png",
    cmp7_radar: "04-synthese/algorithm-profile-radar-chart.png",
    cmp8_scalability_all_algos: "01-debit/throughput-vs-message-size-x86-vs-arm-all-algos.png",
}


def describe_generation():
    """Affiche une correspondance concise dossiers -> fonctions -> fichiers."""
    for group, funcs in CHART_GROUPS.items():
        print(f"[{group}]")
        for func in funcs:
            out = GRAPH_OUTPUTS.get(func, "<sortie inconnue>")
            print(f"  - {func.__name__} -> {out}")


def generate_groups(groups=None):
    """Génère des groupes de graphiques selon le nom du dossier de sortie.

    Paramètres:
        groups: liste de dossiers, ex. ["01-debit", "04-synthese"].
                Si None, tous les groupes sont générés.

    Voir GRAPH_OUTPUTS pour la correspondance fonction -> PNG.
    """
    selected = groups or list(CHART_GROUPS.keys())
    unknown = [g for g in selected if g not in CHART_GROUPS]
    if unknown:
        raise ValueError(f"Groupes de graphiques inconnus: {unknown}")

    for group in selected:
        os.makedirs(os.path.join(OUT_DIR, group), exist_ok=True)
        for func in CHART_GROUPS[group]:
            func()


# ===========================================================================
# Exécution de toutes les figures
# ===========================================================================
if __name__ == "__main__":
    print("\nGénération des graphiques de comparaison...")
    generate_groups()
    print(f"\nTerminé. Graphiques enregistrés dans: {os.path.abspath(OUT_DIR)}")



