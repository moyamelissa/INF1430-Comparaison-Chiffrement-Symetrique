"""
compare_platforms.py
Génère les graphiques de comparaison inter-plateformes (laptop x86 vs Raspberry Pi).

Usage
-----
    py scripts/compare_platforms.py

Le script trouve automatiquement les fichiers CSV correspondant à la convention
de nommage :
    laptop-windows-x86_experience*.csv   → plateforme x86
    raspberry-pi_experience*.csv         → ARM / Raspberry Pi

Si aucun CSV Pi n'est trouvé, le script affiche un message explicite et se
termine proprement.
Tous les graphiques sont enregistrés dans data/charts/comparison/.

Figures produites
-----------------
    cmp1_throughput_all.png     — Barres de débit côte-à-côte (4096 o, ECB)
    cmp2_speedup_ratio.png      — Ratio d'accélération x86/Pi par algorithme
    cmp3_throughput_vs_size.png — Courbe : les deux plateformes, ECB meilleure clé
    cmp4_avalanche.png          — Scores d'avalanche : les deux plateformes (doivent correspondre)
    cmp5_chacha20.png           — Performance ChaCha20 : x86 vs Pi
    cmp6_ci95_stability.png     — Stabilité des mesures : CI95 x86 vs Pi
"""

import os
import sys
import csv
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "results")
OUT_DIR     = os.path.join(os.path.dirname(__file__), "..", "data", "charts")
os.makedirs(OUT_DIR, exist_ok=True)
# Create subdirectories for organized output
for subdir in ["01-debit", "02-effet-avalanche", "05-comparaison-algorithmes", "07-synthese"]:
    os.makedirs(os.path.join(OUT_DIR, subdir), exist_ok=True)

DPI   = 180
FIG_W = 11

# ---------------------------------------------------------------------------
# Palette officielle INF1430 TN3
# ---------------------------------------------------------------------------
BG_COLOR    = "#FFFFFF"   # blanc pur
PANEL_COLOR = "#FFFFFF"   # fond panel
GRID_COLOR  = "#F0F0F0"   # grille subtile
TEXT_COLOR  = "#555555"   # gris texte (officiel)

plt.rcParams.update({
    "figure.facecolor":  BG_COLOR,
    "axes.facecolor":    PANEL_COLOR,
    "axes.edgecolor":    GRID_COLOR,
    "axes.labelcolor":   TEXT_COLOR,
    "axes.titlecolor":   "#0A0A0A",
    "xtick.color":       "#888888",
    "ytick.color":       "#888888",
    "text.color":        TEXT_COLOR,
    "grid.color":        GRID_COLOR,
    "grid.linestyle":    "--",
    "grid.alpha":        0.8,
    "legend.facecolor":  "#FFFFFF",
    "legend.edgecolor":  "#C0C0C0",
    "legend.labelcolor": TEXT_COLOR,
    "font.family":       "Arial",
    "axes.titlepad":     14,
})

ALGO_COLORS = {
    "AES":      "#0A0A0A",   # noir principal (officiel) — standard dominant
    "DES":      "#B03A2E",   # rouge danger — déprécié, cassé
    "3DES":     "#D4783A",   # orange héritage — legacy, intermédiaire
    "Twofish":  "#C9A84C",   # or accent (officiel) — finaliste AES
    "ChaCha20": "#1A5E8A",   # bleu marine — stream cipher, catégorie unique
}

PLATFORM_STYLE = {
    "x86":  {"hatch": "",   "alpha": 0.82, "label": "Laptop x86 (Windows)"},
    "pi":   {"hatch": "//", "alpha": 0.45, "label": "Raspberry Pi (ARM)"},
}

# Best mode per algo for cross-platform comparison
# ChaCha20 has no ECB — use Stream instead
BEST_MODE = {
    "AES":      "ECB",
    "DES":      "ECB",
    "3DES":     "ECB",
    "Twofish":  "ECB",
    "ChaCha20": "Stream",
}

# ---------------------------------------------------------------------------
# Recherche des fichiers CSV
# ---------------------------------------------------------------------------
all_csvs = [f for f in os.listdir(RESULTS_DIR) if f.endswith(".csv")]

x86_csvs = sorted([f for f in all_csvs if "x86" in f or "laptop-windows" in f])
pi_csvs  = sorted([f for f in all_csvs if "raspberry" in f or "raspberry-pi" in f])

if not x86_csvs:
    print("ERROR: No x86 CSV found in data/results/")
    sys.exit(1)

x86_path = os.path.join(RESULTS_DIR, x86_csvs[-1])
print(f"x86 data : {x86_csvs[-1]}")

if not pi_csvs:
    print("\n⚠  No Raspberry Pi CSV found in data/results/")
    print("   Expected a file matching: raspberry-pi_experience*.csv")
    print("   Run experiment.py on the Pi, copy the CSV here, then re-run this script.")
    sys.exit(0)

pi_path = os.path.join(RESULTS_DIR, pi_csvs[-1])
print(f"Pi data  : {pi_csvs[-1]}")

# ---------------------------------------------------------------------------
# Chargement des données
# ---------------------------------------------------------------------------

def _load(path: str) -> list:
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows.append({
                "algorithm":          row["algorithm"],
                "mode":               row["mode"],
                "key_size_bits":      int(row["key_size_bytes"]) * 8,
                "message_size_bytes": int(row["message_size_bytes"]),
                "throughput_enc":     float(row["throughput_encrypt_mbps"]),
                "throughput_dec":     float(row["throughput_decrypt_mbps"]),
                "avalanche":          float(row["avalanche_score"]),
                "key_avalanche":      float(row.get("key_avalanche_score", row["avalanche_score"])),
                "ci95_enc":           float(row.get("ci95_encrypt_mbps", 0)),
            })
    return rows


x86_rows = _load(x86_path)
pi_rows  = _load(pi_path)


def _lookup(rows, algo, mode, key_bits, msg_size):
    for r in rows:
        if (r["algorithm"] == algo and r["mode"] == mode
                and r["key_size_bits"] == key_bits
                and r["message_size_bytes"] == msg_size):
            return r
    return None


def savefig(name: str):
    path = os.path.join(OUT_DIR, name)
    plt.savefig(path, dpi=DPI, bbox_inches="tight", facecolor=BG_COLOR)
    plt.close()
    print(f"  Saved: {path}")


# ===========================================================================
# cmp1 — Barres de débit côte-à-côte (ECB, 4096 o, meilleure clé par algo)
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
        "Débit de chiffrement en fonction de l'algorithme (x86 et ARM)",
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
    savefig("01-debit/comparaison-debit-global.png")


# ===========================================================================
# cmp2 — Rapport d'accélération x86/Pi par algorithme (ECB, 4096 o)
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
        "Ratio de performance en fonction de l'algorithme (x86/ARM)",
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
    savefig("01-debit/comparaison-ratio-acceleration.png")


# ===========================================================================
# cmp3 — Débit selon la taille du message : les deux plateformes, ECB, meilleure clé par algo
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
    ax.set_title(
        "Débit en fonction de la taille du message (x86 et ARM)",
        fontsize=11,
    )
    ax.legend(fontsize=7, ncol=2)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_edgecolor(GRID_COLOR)
    ax.spines["bottom"].set_edgecolor(GRID_COLOR)
    plt.tight_layout()
    savefig("01-debit/comparaison-debit-vs-taille-message.png")


# ===========================================================================
# cmp4 — Scores d'avalanche : les deux plateformes (doivent être identiques — aucun effet matériel)
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

    fig, ax = plt.subplots(figsize=(9, 5))
    fig.patch.set_facecolor(BG_COLOR)
    ax.bar(x - w/2, [x86_means[a] for a in algos], w,
           label="x86", color=colors, edgecolor=BG_COLOR,
           linewidth=0.8, alpha=PLATFORM_STYLE["x86"]["alpha"])
    ax.bar(x + w/2, [pi_means[a]  for a in algos], w,
           label="Pi",  color=colors, edgecolor=BG_COLOR,
           linewidth=0.8, alpha=PLATFORM_STYLE["pi"]["alpha"], hatch="//")
    ax.axhline(0.5, color="#64748B", linestyle="--", linewidth=1.4,
               label="Valeur idéale (0,50)")
    ax.set_xticks(x)
    ax.set_xticklabels(algos, fontsize=11)
    ax.set_ylim(0.42, 0.64)
    ax.set_ylabel("Score d'avalanche", fontsize=11)
    ax.set_title(
        "Score d'avalanche en fonction de l'algorithme (x86 et ARM)",
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
    savefig("02-effet-avalanche/comparaison-avalanche.png")


# ===========================================================================
# cmp5 — Performance ChaCha20 : x86 vs Pi sur toutes les tailles de message
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
        "Débit de ChaCha20 en fonction de la taille du message (x86 et ARM)",
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
    savefig("05-comparaison-algorithmes/chacha20-comparaison-plateformes.png")


# ===========================================================================
# cmp6 — Stabilité des mesures : CI95 x86 vs Pi (ECB, 4096 o, meilleure clé)
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

    # Value labels on x86 bars
    for bar, val in zip(bars_x86, x86_ci):
        if val > 0:
            ax.text(bar.get_x() + bar.get_width() / 2,
                    val + max(x86_ci) * 0.012,
                    f"{val:.2f}", ha="center", va="bottom",
                    fontsize=8, color=TEXT_COLOR, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(algo_order, fontsize=11)
    ax.set_ylabel("IC à 95 % du débit de chiffrement (MB/s)", fontsize=11)
    ax.set_title(
        "Stabilité des mesures en fonction de la plateforme (IC95)",
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
    savefig("05-comparaison-algorithmes/stabilite-ic95.png")


# ===========================================================================
# cmp7 — Radar synthèse : tous algos sur 4 axes normalisés
# Débit x86 · Débit Pi · Avalanche · Portabilité (ratio Pi/x86)
# ===========================================================================
def cmp7_radar():
    algo_order = ["AES", "ChaCha20", "DES", "3DES", "Twofish"]
    best_key  = {"AES": 256, "DES": 64, "3DES": 192, "Twofish": 256, "ChaCha20": 256}
    target    = 16384  # largest message for peak throughput

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

    # Portability: Pi/x86 ratio (higher = more portable)
    portability = {a: (pi_thr[a] / x86_thr[a]) if x86_thr[a] > 0 else 0 for a in algo_order}

    # Normalize each axis 0→1
    def norm(d):
        mx = max(d.values()) or 1
        return {k: v / mx for k, v in d.items()}

    n_x86  = norm(x86_thr)
    n_pi   = norm(pi_thr)
    n_aval = {a: 1 - abs(aval_scores[a] - 0.5) * 10 for a in algo_order}
    n_port = norm(portability)

    categories = ["Débit x86", "Débit Pi (ARM)", "Avalanche\n(qualité)", "Portabilité\n(Pi/x86)"]
    N      = len(categories)
    angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))
    fig.patch.set_facecolor(BG_COLOR)
    ax.set_facecolor(PANEL_COLOR)
    ax.spines["polar"].set_color(GRID_COLOR)
    ax.grid(color=GRID_COLOR, linestyle="--", alpha=0.5)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, size=10, color=TEXT_COLOR)
    ax.set_ylim(0, 1)
    ax.set_yticks([0.25, 0.5, 0.75, 1.0])
    ax.set_yticklabels(["25%", "50%", "75%", "100%"], size=7, color=TEXT_COLOR)
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
    ax.legend(loc="upper right", bbox_to_anchor=(1.35, 1.15), fontsize=9)
    plt.tight_layout()
    savefig("07-synthese/radar-synthese.png")


# ===========================================================================
# cmp8 — Scalabilité tous algos : x86 (—) et Pi (- -) sur les mêmes axes
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
    ax.set_title(
        "Débit en fonction de la taille du message (tous algorithmes)",
        fontsize=11,
    )
    ax.legend(fontsize=7, ncol=5)
    ax.yaxis.grid(True)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_edgecolor(GRID_COLOR)
    ax.spines["bottom"].set_edgecolor(GRID_COLOR)
    plt.tight_layout()
    savefig("01-debit/scalabilite-tous-algorithmes.png")


# ===========================================================================
# Exécution de toutes les figures
# ===========================================================================
if __name__ == "__main__":
    print("\nGénération des graphiques de comparaison...")
    for subdir in ["01-debit", "02-effet-avalanche", "05-comparaison-algorithmes", "07-synthese"]:
        os.makedirs(os.path.join(OUT_DIR, subdir), exist_ok=True)
    cmp1_throughput_all()
    cmp2_speedup_ratio()
    cmp3_throughput_vs_size()
    cmp4_avalanche()
    cmp5_chacha20()
    cmp6_ci95_stability()
    cmp7_radar()
    print(f"\nDone. Charts saved to: {os.path.abspath(OUT_DIR)}")
