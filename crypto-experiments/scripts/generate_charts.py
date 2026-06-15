"""
generate_charts.py
Génère toutes les figures d'analyse à partir des données CSV de benchmarking.

Usage
-----
    py scripts/generate_charts.py

Sortie : data/charts/  (fichiers PNG à 150 dpi, adaptés à l'insertion dans Word)
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
CHARTS_DIR  = os.path.join(os.path.dirname(__file__), "..", "data", "charts")
os.makedirs(CHARTS_DIR, exist_ok=True)

# Utilise le premier fichier CSV trouvé (le plus récent si trié)
csv_files = sorted(
    [f for f in os.listdir(RESULTS_DIR) if f.endswith(".csv") and f != ".gitkeep"]
)
if not csv_files:
    print("No CSV file found in data/results/")
    sys.exit(1)

CSV_PATH = os.path.join(RESULTS_DIR, csv_files[-1])
print(f"Reading: {CSV_PATH}")

# ---------------------------------------------------------------------------
# Chargement des données
# ---------------------------------------------------------------------------
rows = []
with open(CSV_PATH, newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        rows.append({
            "algorithm":            row["algorithm"],
            "mode":                 row["mode"],
            "key_size_bytes":       int(row["key_size_bytes"]),
            "key_size_bits":        int(row["key_size_bytes"]) * 8,
            "message_size_bytes":   int(row["message_size_bytes"]),
            "avg_encrypt_time_s":   float(row["avg_encrypt_time_s"]),
            "avg_decrypt_time_s":   float(row["avg_decrypt_time_s"]),
            "throughput_enc_mbps":  float(row["throughput_encrypt_mbps"]),
            "throughput_dec_mbps":    float(row["throughput_decrypt_mbps"]),
            "avalanche_score":        float(row["avalanche_score"]),
            "key_avalanche_score":    float(row.get("key_avalanche_score", row["avalanche_score"])),
        })

# ---------------------------------------------------------------------------
# Palette — couleurs cohérentes par algorithme
# ---------------------------------------------------------------------------
BG_COLOR    = "#0A0E1A"
PANEL_COLOR = "#0F1524"
GRID_COLOR  = "#1C2438"
TEXT_COLOR  = "#C9D4F0"

plt.rcParams.update({
    "figure.facecolor":  BG_COLOR,
    "axes.facecolor":    PANEL_COLOR,
    "axes.edgecolor":    GRID_COLOR,
    "axes.labelcolor":   TEXT_COLOR,
    "axes.titlecolor":   TEXT_COLOR,
    "xtick.color":       TEXT_COLOR,
    "ytick.color":       TEXT_COLOR,
    "text.color":        TEXT_COLOR,
    "grid.color":        GRID_COLOR,
    "grid.linestyle":    "--",
    "grid.alpha":        0.8,
    "legend.facecolor":  "#111827",
    "legend.edgecolor":  "#1C2438",
    "legend.labelcolor": TEXT_COLOR,
    "font.family":       "DejaVu Sans",
    "axes.titlepad":     12,
})

ALGO_COLORS = {
    "AES":      "#3B82F6",   # vivid blue
    "DES":      "#EC4899",   # hot pink
    "3DES":     "#A855F7",   # purple
    "Twofish":  "#10B981",   # emerald green
    "ChaCha20": "#06B6D4",   # cyan
}
MODE_COLORS = {
    "ECB": "#3B82F6",   # blue
    "CBC": "#EC4899",   # pink
    "CTR": "#10B981",   # green
    "GCM": "#F59E0B",   # amber
}
MODE_HATCH = {"ECB": "", "CBC": "//", "CTR": "xx", "GCM": ".."}

DPI   = 180
FIG_W = 11

def _style_ax(ax):
    """Apply consistent dark style to an axes."""
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_edgecolor(GRID_COLOR)
    ax.spines["bottom"].set_edgecolor(GRID_COLOR)
    ax.set_axisbelow(True)
    ax.yaxis.grid(True)

def savefig(name: str):
    path = os.path.join(CHARTS_DIR, name)
    plt.savefig(path, dpi=DPI, bbox_inches="tight", facecolor=BG_COLOR)
    plt.close()
    print(f"  Saved: {path}")


# ===========================================================================
# Figure 1 — Comparaison du débit à 4 096 octets (point médian représentatif)
# Une barre par combinaison algorithme+mode, regroupées par algorithme.
# ===========================================================================
def fig1_throughput_4096():
    target_size = 4096
    data = [r for r in rows if r["message_size_bytes"] == target_size]

    # Groupe : algo → liste de (mode, bits_clé, enc_mbps)
    groups = defaultdict(list)
    for r in data:
        label = f"{r['mode']}\n{r['key_size_bits']}b"
        groups[r["algorithm"]].append((label, r["throughput_enc_mbps"]))

    algo_order = ["AES", "DES", "3DES", "Twofish"]
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
            ax.bar(x_pos, mbps, color=ALGO_COLORS[algo],
                   edgecolor=BG_COLOR, linewidth=0.8, width=0.7,
                   alpha=0.82)
            tick_positions.append(x_pos)
            tick_labels.append(label)
            x_pos += 1
        group_centers[algo] = (start + x_pos - 1) / 2
        x_pos += 0.8

    ax.set_xticks(tick_positions)
    ax.set_xticklabels(tick_labels, fontsize=7)
    ax.set_ylabel("Débit de chiffrement (MB/s)", fontsize=11)
    ax.set_title(
        "Figure 1 — Débit de chiffrement par algorithme et mode\n"
        f"(message de {target_size} octets, plateforme : laptop Windows x86)",
        fontsize=11,
    )

    for algo, cx in group_centers.items():
        ax.text(cx, -ax.get_ylim()[1] * 0.12, algo,
                ha="center", fontsize=9, fontweight="bold", color=ALGO_COLORS[algo])

    legend_patches = [
        mpatches.Patch(color=ALGO_COLORS[a], label=a) for a in algo_order if a in groups
    ]
    ax.legend(handles=legend_patches, loc="upper right", fontsize=9)
    ax.set_ylim(bottom=0)
    _style_ax(ax)
    plt.tight_layout()
    savefig("01-throughput/throughput-4096B.png")


# ===========================================================================
# Figure 2 — Débit en fonction de la taille du message (courbe, mode ECB uniquement)
# Montre la scalabilité de chaque algorithme selon la taille des données.
# ===========================================================================
def fig2_throughput_vs_size():
    # Pick ECB (or CTR for DES/3DES which also have ECB; use ECB for all)
    ecb_data = [r for r in rows if r["mode"] == "ECB"]

    # Meilleure taille de clé par algo pour la clarté (la plus grande = recommandation courante)
    best_key = {"AES": 256, "DES": 64, "3DES": 192, "Twofish": 256, "ChaCha20": 256}

    msg_sizes = sorted({r["message_size_bytes"] for r in ecb_data})
    fig, ax = plt.subplots(figsize=(FIG_W, 5.5))
    fig.patch.set_facecolor(BG_COLOR)

    for algo, key_bits in best_key.items():
        subset = sorted(
            [r for r in ecb_data
             if r["algorithm"] == algo and r["key_size_bits"] == key_bits],
            key=lambda r: r["message_size_bytes"],
        )
        if not subset:
            continue
        sizes = [r["message_size_bytes"] for r in subset]
        mbps  = [r["throughput_enc_mbps"] for r in subset]
        ax.plot(sizes, mbps, marker="o", label=f"{algo}-{key_bits}b",
                color=ALGO_COLORS[algo], linewidth=2.2, markersize=5, alpha=0.92)

    ax.set_xscale("log", base=2)
    ax.set_xticks(msg_sizes)
    ax.set_xticklabels([f"{s:,}" for s in msg_sizes])
    ax.set_xlabel("Taille du message (octets)", fontsize=11)
    ax.set_ylabel("Débit de chiffrement (MB/s)", fontsize=11)
    ax.set_title(
        "Figure 2 — Débit de chiffrement selon la taille du message (mode ECB)\n"
        "(plateforme : laptop Windows x86)",
        fontsize=11,
    )
    ax.legend(fontsize=9)
    _style_ax(ax)
    plt.tight_layout()
    savefig("01-throughput/throughput-vs-msgsize.png")


# ===========================================================================
# Figure 3 — Comparaison des modes pour AES-128 sur toutes les tailles de message
# Débit de chiffrement : ECB / CBC / CTR / GCM
# ===========================================================================
def fig3_aes_mode_comparison():
    aes128 = [r for r in rows if r["algorithm"] == "AES" and r["key_size_bits"] == 128]
    modes  = ["ECB", "CBC", "CTR", "GCM"]
    msg_sizes = sorted({r["message_size_bytes"] for r in aes128})

    fig, ax = plt.subplots(figsize=(FIG_W, 5.5))
    fig.patch.set_facecolor(BG_COLOR)
    for mode in modes:
        subset = sorted(
            [r for r in aes128 if r["mode"] == mode],
            key=lambda r: r["message_size_bytes"],
        )
        if not subset:
            continue
        sizes = [r["message_size_bytes"] for r in subset]
        mbps  = [r["throughput_enc_mbps"] for r in subset]
        ax.plot(sizes, mbps, marker="o", label=mode,
                color=MODE_COLORS[mode], linewidth=2.2, markersize=5, alpha=0.92)

    ax.set_xscale("log", base=2)
    ax.set_xticks(msg_sizes)
    ax.set_xticklabels([f"{s:,}" for s in msg_sizes])
    ax.set_xlabel("Taille du message (octets)", fontsize=11)
    ax.set_ylabel("Débit de chiffrement (MB/s)", fontsize=11)
    ax.set_title(
        "Figure 3 — Comparaison des modes d'opération (AES-128)\n"
        "(plateforme : laptop Windows x86)",
        fontsize=11,
    )
    ax.legend(title="Mode", fontsize=9)
    _style_ax(ax)
    plt.tight_layout()
    savefig("03-encryption-modes/aes-mode-comparison.png")


# ===========================================================================
# Figure 4 — Score d'avalanche par algorithme (barres, moyenne de tous les modes)
# Valeur attendue ≈ 0,50 (diffusion idéale)
# ===========================================================================
def fig4_avalanche():
    algo_scores = defaultdict(list)
    for r in rows:
        algo_scores[r["algorithm"]].append(r["avalanche_score"])

    algo_order = ["AES", "DES", "3DES", "Twofish"]
    means  = [np.mean(algo_scores[a]) for a in algo_order if a in algo_scores]
    stdevs = [np.std(algo_scores[a])  for a in algo_order if a in algo_scores]
    algos  = [a for a in algo_order if a in algo_scores]
    colors = [ALGO_COLORS[a] for a in algos]

    fig, ax = plt.subplots(figsize=(8, 5))
    fig.patch.set_facecolor(BG_COLOR)
    bars = ax.bar(algos, means, yerr=stdevs, color=colors, capsize=6,
                  edgecolor=BG_COLOR, linewidth=0.8, width=0.5,
                  alpha=0.82,
                  error_kw={"linewidth": 1.5, "ecolor": TEXT_COLOR})
    ax.axhline(0.5, color="#475569", linestyle="--", linewidth=1.4,
               label="Valeur idéale (0,50)")
    ax.set_ylim(0.45, 0.565)
    ax.set_ylabel("Score d'effet d'avalanche (proportion de bits modifiés)", fontsize=10)
    ax.set_title(
        "Figure 4 — Effet d'avalanche par algorithme\n"
        "(moyenne ± écart-type, tous modes et tailles confondus)",
        fontsize=11,
    )
    ax.legend(fontsize=9)

    for bar, mean, std, color in zip(bars, means, stdevs, colors):
        ax.text(bar.get_x() + bar.get_width() / 2, mean + std + 0.003,
                f"{mean:.4f}", ha="center", va="bottom", fontsize=9, color=color)

    _style_ax(ax)
    plt.tight_layout()
    savefig("fig4_avalanche.png")


# ===========================================================================
# Figure 4b — Comparaison avalanche texte clair vs avalanche clé
# Montre que tous les algorithmes répondent de façon égale aux deux types de flip.
# ===========================================================================
def fig4b_key_avalanche():
    algo_scores_pt  = defaultdict(list)
    algo_scores_key = defaultdict(list)
    for r in rows:
        algo_scores_pt[r["algorithm"]].append(r["avalanche_score"])
        algo_scores_key[r["algorithm"]].append(r["key_avalanche_score"])

    algo_order = [a for a in ["AES", "DES", "3DES", "Twofish", "ChaCha20"]
                  if a in algo_scores_pt]
    means_pt  = [np.mean(algo_scores_pt[a])  for a in algo_order]
    means_key = [np.mean(algo_scores_key[a]) for a in algo_order]

    x = np.arange(len(algo_order))
    w = 0.32
    fig, ax = plt.subplots(figsize=(9, 5))
    fig.patch.set_facecolor(BG_COLOR)
    bars_pt  = ax.bar(x - w/2, means_pt,  w, label="Avalanche (texte clair)",
                      color=[ALGO_COLORS[a] for a in algo_order],
                      edgecolor=BG_COLOR, linewidth=0.8, alpha=0.50)
    bars_key = ax.bar(x + w/2, means_key, w, label="Avalanche (clé)",
                      color=[ALGO_COLORS[a] for a in algo_order],
                      edgecolor=BG_COLOR, linewidth=0.8, alpha=0.88)
    ax.axhline(0.5, color="#475569", linestyle="--", linewidth=1.4,
               label="Valeur idéale (0,50)")
    ax.set_xticks(x)
    ax.set_xticklabels(algo_order, fontsize=11)
    ax.set_ylim(0.40, 0.65)
    ax.set_ylabel("Score d'avalanche", fontsize=11)
    ax.set_title(
        "Figure 4b — Comparaison de l'effet d'avalanche : flip texte clair vs flip clé\n"
        "(tous modes et tailles confondus)",
        fontsize=11,
    )
    ax.legend(fontsize=9)
    for bar, m, c in zip(bars_pt, means_pt, [ALGO_COLORS[a] for a in algo_order]):
        ax.text(bar.get_x() + bar.get_width()/2, m + 0.001,
                f"{m:.3f}", ha="center", va="bottom", fontsize=8, color=c)
    for bar, m, c in zip(bars_key, means_key, [ALGO_COLORS[a] for a in algo_order]):
        ax.text(bar.get_x() + bar.get_width()/2, m + 0.001,
                f"{m:.3f}", ha="center", va="bottom", fontsize=8, color=c)
    _style_ax(ax)
    plt.tight_layout()
    savefig("fig4b_key_avalanche.png")


# ===========================================================================
# Figure 5 — Débit chiffrement vs déchiffrement (barres pairées, 4096 o, mode ECB)
# ===========================================================================
def fig5_enc_vs_dec():
    target_size = 4096
    target_mode = "ECB"
    data = [r for r in rows
            if r["message_size_bytes"] == target_size and r["mode"] == target_mode]

    # Une entrée par combinaison algo+clé
    labels, enc_vals, dec_vals, colors = [], [], [], []
    for r in sorted(data, key=lambda r: (r["algorithm"], r["key_size_bits"])):
        labels.append(f"{r['algorithm']}\n{r['key_size_bits']}b")
        enc_vals.append(r["throughput_enc_mbps"])
        dec_vals.append(r["throughput_dec_mbps"])
        colors.append(ALGO_COLORS[r["algorithm"]])

    x = np.arange(len(labels))
    w = 0.32
    fig, ax = plt.subplots(figsize=(FIG_W, 5.5))
    fig.patch.set_facecolor(BG_COLOR)
    ax.bar(x - w/2, enc_vals, w, label="Chiffrement",
           color=colors, edgecolor=BG_COLOR, linewidth=0.8, alpha=0.50)
    ax.bar(x + w/2, dec_vals, w, label="Déchiffrement",
           color=colors, edgecolor=BG_COLOR, linewidth=0.8, alpha=0.88)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylabel("Débit (MB/s)", fontsize=11)
    ax.set_title(
        f"Figure 5 — Débit de chiffrement vs déchiffrement (mode ECB, {target_size} octets)\n"
        "(plateforme : laptop Windows x86)",
        fontsize=11,
    )
    ax.legend(fontsize=9)
    _style_ax(ax)
    plt.tight_layout()
    savefig("fig5_enc_vs_dec_ecb.png")


# ===========================================================================
# Figure 6 — Impact de la taille de clé sur le débit AES (ECB, 4096 o)
# ===========================================================================
def fig6_key_size_impact():
    data = [r for r in rows
            if r["algorithm"] == "AES" and r["message_size_bytes"] == 4096]
    modes = sorted({r["mode"] for r in data})
    key_bits = sorted({r["key_size_bits"] for r in data})

    mode_colors = {"ECB": "#1565C0", "CBC": "#42A5F5", "CTR": "#66BB6A", "GCM": "#FFA726"}
    x = np.arange(len(key_bits))
    w = 0.18
    offsets = np.linspace(-(len(modes)-1)/2 * w, (len(modes)-1)/2 * w, len(modes))

    fig, ax = plt.subplots(figsize=(9, 5.5))
    fig.patch.set_facecolor(BG_COLOR)
    for offset, mode in zip(offsets, modes):
        vals = []
        for kb in key_bits:
            match = [r for r in data if r["mode"] == mode and r["key_size_bits"] == kb]
            vals.append(match[0]["throughput_enc_mbps"] if match else 0)
        ax.bar(x + offset, vals, w, label=mode,
               color=MODE_COLORS.get(mode, "#888"),
               edgecolor=BG_COLOR, linewidth=0.8, alpha=0.82)

    ax.set_xticks(x)
    ax.set_xticklabels([f"{k} bits" for k in key_bits])
    ax.set_xlabel("Taille de clé AES", fontsize=11)
    ax.set_ylabel("Débit de chiffrement (MB/s)", fontsize=11)
    ax.set_title(
        "Figure 6 — Impact de la taille de clé sur le débit AES\n"
        "(message de 4 096 octets, plateforme : laptop Windows x86)",
        fontsize=11,
    )
    ax.legend(title="Mode", fontsize=9)
    _style_ax(ax)
    plt.tight_layout()
    savefig("fig6_aes_key_size.png")


# ===========================================================================
# Profils par algorithme — Vue synthétique de chaque algo
# Affiche débit et effet d'avalanche sur 2 lignes
# ===========================================================================
def algo_profile(algo_name):
    """Crée une vue synthétique d'un algorithme : débit vs modes + avalanche."""
    algo_data = [r for r in rows if r["algorithm"] == algo_name]
    if not algo_data:
        return
    
    # Filtre : message de 4096 octets
    data_4096 = [r for r in algo_data if r["message_size_bytes"] == 4096]
    if not data_4096:
        return
    
    modes_available = sorted({r["mode"] for r in data_4096})
    key_bits_list = sorted({r["key_size_bits"] for r in data_4096})
    
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))
    fig.patch.set_facecolor(BG_COLOR)
    
    # ===== Ligne 1 : Débit (MB/s) par mode et taille de clé
    x = np.arange(len(key_bits_list))
    w = 0.18
    offsets = np.linspace(-(len(modes_available)-1)/2 * w, 
                          (len(modes_available)-1)/2 * w, len(modes_available))
    
    for offset, mode in zip(offsets, modes_available):
        vals = []
        for kb in key_bits_list:
            match = [r for r in data_4096 if r["mode"] == mode and r["key_size_bits"] == kb]
            vals.append(match[0]["throughput_enc_mbps"] if match else 0)
        ax1.bar(x + offset, vals, w, label=mode,
               color=MODE_COLORS.get(mode, "#888"),
               edgecolor=BG_COLOR, linewidth=0.8, alpha=0.82)
    
    ax1.set_xticks(x)
    ax1.set_xticklabels([f"{k} bits" for k in key_bits_list])
    ax1.set_ylabel("Débit de chiffrement (MB/s)", fontsize=10)
    ax1.set_title(f"Profil {algo_name} — Débit par mode et taille de clé (4 096 octets)",
                  fontsize=11, fontweight="bold")
    ax1.legend(title="Mode", fontsize=8, ncol=4)
    _style_ax(ax1)
    
    # ===== Ligne 2 : Score d'avalanche par mode et taille de clé
    for offset, mode in zip(offsets, modes_available):
        vals = []
        for kb in key_bits_list:
            match = [r for r in data_4096 if r["mode"] == mode and r["key_size_bits"] == kb]
            vals.append(match[0]["avalanche_score"] if match else 0)
        ax2.bar(x + offset, vals, w, label=mode,
               color=MODE_COLORS.get(mode, "#888"),
               edgecolor=BG_COLOR, linewidth=0.8, alpha=0.82)
    
    ax2.axhline(0.5, color="#475569", linestyle="--", linewidth=1.2, alpha=0.7)
    ax2.set_xticks(x)
    ax2.set_xticklabels([f"{k} bits" for k in key_bits_list])
    ax2.set_xlabel("Taille de clé", fontsize=10)
    ax2.set_ylabel("Score d'avalanche", fontsize=10)
    ax2.set_ylim(0.45, 0.55)
    ax2.set_title("Score d'effet d'avalanche par mode et taille de clé", fontsize=10)
    _style_ax(ax2)
    
    plt.tight_layout()
    filename = f"06-algorithm-profiles/{algo_name.lower()}-profile.png"
    savefig(filename)


# ===========================================================================
# Exécution de toutes les figures
# ===========================================================================
if __name__ == "__main__":
    print("Generating charts...")
    # Create subdirectories if they don't exist
    for subdir in ["01-throughput", "02-avalanche-effect", "03-encryption-modes", "06-algorithm-profiles"]:
        os.makedirs(os.path.join(CHARTS_DIR, subdir), exist_ok=True)
    
    fig1_throughput_4096()
    fig2_throughput_vs_size()
    fig3_aes_mode_comparison()
    fig4_avalanche()
    fig4b_key_avalanche()
    fig5_enc_vs_dec()
    fig6_key_size_impact()
    
    # Generate per-algorithm profile charts
    algorithms = ["AES", "DES", "3DES", "Twofish", "ChaCha20"]
    for algo in algorithms:
        algo_profile(algo)
    
    print(f"\nDone. Charts saved to: {os.path.abspath(CHARTS_DIR)}")
