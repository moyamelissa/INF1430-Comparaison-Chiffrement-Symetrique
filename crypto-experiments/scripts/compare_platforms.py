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
OUT_DIR     = os.path.join(os.path.dirname(__file__), "..", "data", "charts", "comparison")
os.makedirs(OUT_DIR, exist_ok=True)

DPI   = 150
FIG_W = 10

ALGO_COLORS = {
    "AES":      "#2196F3",
    "DES":      "#F44336",
    "3DES":     "#FF9800",
    "Twofish":  "#4CAF50",
    "ChaCha20": "#9C27B0",
}

PLATFORM_STYLE = {
    "x86":  {"hatch": "",   "alpha": 1.0, "label": "Laptop x86 (Windows)"},
    "pi":   {"hatch": "//", "alpha": 0.8, "label": "Raspberry Pi (ARM)"},
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
    plt.savefig(path, dpi=DPI, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {path}")


# ===========================================================================
# cmp1 — Barres de débit côte-à-côte (ECB, 4096 o, meilleure clé par algo)
# ===========================================================================
def cmp1_throughput_all():
    target_size = 4096
    target_mode = "ECB"
    best_key = {"AES": 256, "DES": 64, "3DES": 192, "Twofish": 256, "ChaCha20": 256}
    algo_order = [a for a in best_key if any(
        r["algorithm"] == a and r["mode"] == target_mode for r in x86_rows
    )]

    x = np.arange(len(algo_order))
    w = 0.35
    fig, ax = plt.subplots(figsize=(FIG_W, 5))

    x86_vals, pi_vals, colors = [], [], []
    for algo in algo_order:
        kb  = best_key[algo]
        r86 = _lookup(x86_rows, algo, target_mode, kb, target_size)
        rpi = _lookup(pi_rows,  algo, target_mode, kb, target_size)
        x86_vals.append(r86["throughput_enc"] if r86 else 0)
        pi_vals.append( rpi["throughput_enc"] if rpi else 0)
        colors.append(ALGO_COLORS.get(algo, "#888"))

    ax.bar(x - w/2, x86_vals, w, label="Laptop x86 (Windows)", color=colors,
           edgecolor="white", alpha=1.0)
    ax.bar(x + w/2, pi_vals,  w, label="Raspberry Pi (ARM)",   color=colors,
           edgecolor="white", alpha=0.6, hatch="//")

    ax.set_xticks(x)
    ax.set_xticklabels(algo_order)
    ax.set_ylabel("Débit de chiffrement (MB/s)", fontsize=11)
    ax.set_title(
        "Comparaison 1 — Débit de chiffrement : laptop x86 vs Raspberry Pi\n"
        f"(mode ECB, {target_size} octets, meilleure clé par algorithme)",
        fontsize=11,
    )
    ax.legend(fontsize=9)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)
    plt.tight_layout()
    savefig("cmp1_throughput_all.png")


# ===========================================================================
# cmp2 — Rapport d'accélération x86/Pi par algorithme (ECB, 4096 o)
# Montre dans quelle mesure x86 est plus rapide que le Pi pour chaque algorithme.
# ===========================================================================
def cmp2_speedup_ratio():
    target_size = 4096
    target_mode = "ECB"
    best_key = {"AES": 256, "DES": 64, "3DES": 192, "Twofish": 256, "ChaCha20": 256}
    algo_order = [a for a in best_key if any(r["algorithm"] == a for r in x86_rows)]

    ratios, algos, colors = [], [], []
    for algo in algo_order:
        kb  = best_key[algo]
        r86 = _lookup(x86_rows, algo, target_mode, kb, target_size)
        rpi = _lookup(pi_rows,  algo, target_mode, kb, target_size)
        if r86 and rpi and rpi["throughput_enc"] > 0:
            ratios.append(r86["throughput_enc"] / rpi["throughput_enc"])
            algos.append(algo)
            colors.append(ALGO_COLORS.get(algo, "#888"))

    fig, ax = plt.subplots(figsize=(8, 4.5))
    bars = ax.bar(algos, ratios, color=colors, edgecolor="white", width=0.5)
    ax.axhline(1.0, color="black", linestyle="--", linewidth=1.2,
               label="Ratio = 1 (performances égales)")

    for bar, r in zip(bars, ratios):
        ax.text(bar.get_x() + bar.get_width() / 2, r + 0.05,
                f"{r:.1f}×", ha="center", va="bottom", fontsize=10, fontweight="bold")

    ax.set_ylabel("Rapport de débit x86 / Pi (×)", fontsize=11)
    ax.set_title(
        "Comparaison 2 — Rapport de performance x86 vs Raspberry Pi\n"
        "(mode ECB, 4 096 octets — valeur > 1 signifie x86 plus rapide)",
        fontsize=11,
    )
    ax.legend(fontsize=9)
    ax.set_ylim(bottom=0)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)
    plt.tight_layout()
    savefig("cmp2_speedup_ratio.png")


# ===========================================================================
# cmp3 — Débit selon la taille du message : les deux plateformes, ECB, meilleure clé par algo
# ===========================================================================
def cmp3_throughput_vs_size():
    best_key = {"AES": 256, "DES": 64, "3DES": 192, "Twofish": 256, "ChaCha20": 256}
    msg_sizes = sorted({r["message_size_bytes"] for r in x86_rows if r["mode"] == "ECB"})

    fig, ax = plt.subplots(figsize=(FIG_W, 5))
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
                    marker="o", color=color, linewidth=2,
                    label=f"{algo} x86", linestyle="-")
        # Pi — trait pointillé
        pi_pts = sorted(
            [r for r in pi_rows if r["algorithm"] == algo and r["mode"] == "ECB"
             and r["key_size_bits"] == kb],
            key=lambda r: r["message_size_bytes"]
        )
        if pi_pts:
            ax.plot([r["message_size_bytes"] for r in pi_pts],
                    [r["throughput_enc"] for r in pi_pts],
                    marker="s", color=color, linewidth=2,
                    label=f"{algo} Pi", linestyle="--")

    ax.set_xscale("log", base=2)
    ax.set_xticks(msg_sizes)
    ax.set_xticklabels([f"{s:,}" for s in msg_sizes])
    ax.set_xlabel("Taille du message (octets)", fontsize=11)
    ax.set_ylabel("Débit de chiffrement (MB/s)", fontsize=11)
    ax.set_title(
        "Comparaison 3 — Débit selon la taille du message (mode ECB)\n"
        "Trait plein = x86 · Trait pointillé = Raspberry Pi",
        fontsize=11,
    )
    ax.legend(fontsize=7, ncol=2)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)
    plt.tight_layout()
    savefig("cmp3_throughput_vs_size.png")


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

    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.bar(x - w/2, [x86_means[a] for a in algos], w,
           label="x86", color=colors, edgecolor="white", alpha=1.0)
    ax.bar(x + w/2, [pi_means[a]  for a in algos], w,
           label="Pi",  color=colors, edgecolor="white", alpha=0.6, hatch="//")
    ax.axhline(0.5, color="black", linestyle="--", linewidth=1.2,
               label="Valeur idéale (0,50)")
    ax.set_xticks(x)
    ax.set_xticklabels(algos)
    ax.set_ylim(0.44, 0.56)
    ax.set_ylabel("Score d'avalanche", fontsize=11)
    ax.set_title(
        "Comparaison 4 — Effet d'avalanche : x86 vs Raspberry Pi\n"
        "(les scores doivent être identiques — l'avalanche est une propriété mathématique)",
        fontsize=11,
    )
    ax.legend(fontsize=9)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)
    plt.tight_layout()
    savefig("cmp4_avalanche.png")


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

    fig, ax = plt.subplots(figsize=(8, 4.5))
    for rows, label, ls, marker in [
        (x86_rows, "ChaCha20 — x86", "-",  "o"),
        (pi_rows,  "ChaCha20 — Pi",  "--", "s"),
    ]:
        pts = sorted(
            [r for r in rows if r["algorithm"] == "ChaCha20"],
            key=lambda r: r["message_size_bytes"]
        )
        if pts:
            ax.plot([r["message_size_bytes"] for r in pts],
                    [r["throughput_enc"] for r in pts],
                    marker=marker, linewidth=2, linestyle=ls,
                    color="#9C27B0", label=label)

    ax.set_xscale("log", base=2)
    ax.set_xticks(msg_sizes)
    ax.set_xticklabels([f"{s:,}" for s in msg_sizes])
    ax.set_xlabel("Taille du message (octets)", fontsize=11)
    ax.set_ylabel("Débit de chiffrement (MB/s)", fontsize=11)
    ax.set_title(
        "Comparaison 5 — ChaCha20 : x86 vs Raspberry Pi\n"
        "(aucune accélération matérielle sur les deux plateformes)",
        fontsize=11,
    )
    ax.legend(fontsize=9)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)
    plt.tight_layout()
    savefig("cmp5_chacha20.png")


# ===========================================================================
# Exécution de toutes les figures
# ===========================================================================
if __name__ == "__main__":
    print("\nGénération des graphiques de comparaison...")
    cmp1_throughput_all()
    cmp2_speedup_ratio()
    cmp3_throughput_vs_size()
    cmp4_avalanche()
    cmp5_chacha20()
    print(f"\nDone. Charts saved to: {os.path.abspath(OUT_DIR)}")
