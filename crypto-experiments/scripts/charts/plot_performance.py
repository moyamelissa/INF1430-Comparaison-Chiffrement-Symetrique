"""
generate_charts.py
Génère toutes les figures d'analyse à partir des données CSV de benchmarking.

Usage
-----
    py scripts/charts/plot_performance.py

Sortie : data/charts/  (fichiers PNG à 150 dpi, adaptés à l'insertion dans Word)
"""
import os
import sys
import csv
from collections import defaultdict

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

sys.path.insert(0, BASE_DIR)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
RESULTS_DIR = os.path.join(BASE_DIR, "data", "results")
CHARTS_DIR  = os.path.join(BASE_DIR, "data", "charts")
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
BG_COLOR    = "#FFFFFF"
PANEL_COLOR = "#FFFFFF"
GRID_COLOR  = "#F0F0F0"
TEXT_COLOR  = "#555555"

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
    "axes.titlepad":     12,
    "hatch.linewidth":   1.0,
})
matplotlib.rcParams["hatch.color"] = (0.0, 0.0, 0.0, 0.25)

# ---------------------------------------------------------------------------
# Palette officielle INF1430 TN3
#   Noir principal  : #0A0A0A
#   Or accent       : #C9A84C   (couleur signature)
#   Gris texte      : #555555
#   Gris léger      : #888888
#   Gris très léger : #C0C0C0
#   Vert validé     : #3A7A3A   (KAT / recommandé uniquement)
#
# Compléments harmonieux pour différenciation graphique :
#   Rouge danger    : #B03A2E   (déprécié / non sécurisé)
#   Orange héritage : #D4783A   (legacy, intermédiaire)
#   Bleu marine     : #1A5E8A   (moderne / stream / standard)
# ---------------------------------------------------------------------------
ALGO_COLORS = {
    "AES":      "#0A0A0A",   # noir principal (officiel) — standard dominant
    "DES":      "#B03A2E",   # rouge danger — déprécié, cassé
    "3DES":     "#D4783A",   # orange héritage — legacy, intermédiaire
    "Twofish":  "#C9A84C",   # or accent (officiel) — finaliste AES, premium
    "ChaCha20": "#1A5E8A",   # bleu marine — stream cipher, catégorie unique
}
MODE_COLORS = {
    "ECB": "#B03A2E",        # rouge danger — non sécurisé (patterns visibles)
    "CBC": "#1A5E8A",        # bleu marine — standard sécurisé
    "CTR": "#3A7A3A",        # vert validé (officiel) — moderne, approuvé
    "GCM": "#C9A84C",        # or accent (officiel) — authentifié, premium
}
MODE_HATCH = {"ECB": "", "CBC": "/", "CTR": "x", "GCM": "."}

DPI   = 180
FIG_W = 11

def _style_ax(ax):
    """Apply consistent light style to an axes."""
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_edgecolor("#C0C0C0")
    ax.spines["bottom"].set_edgecolor("#C0C0C0")
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
        "Débit de chiffrement en fonction de l'algorithme et du mode",
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
    savefig("01-debit/debit-4096o.png")


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
        "Débit de chiffrement en fonction de la taille du message",
        fontsize=11,
    )
    ax.legend(fontsize=9)
    _style_ax(ax)
    plt.tight_layout()
    savefig("01-debit/debit-vs-taille-message.png")


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
        "Débit AES-128 en fonction du mode d'opération",
        fontsize=11,
    )
    ax.legend(title="Mode", fontsize=9)
    _style_ax(ax)
    plt.tight_layout()
    savefig("03-modes-chiffrement/aes-comparaison-modes.png")


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
    means_pct  = [m * 100.0 for m in means]
    stdevs_pct = [s * 100.0 for s in stdevs]
    algos  = [a for a in algo_order if a in algo_scores]
    colors = [ALGO_COLORS[a] for a in algos]

    fig, ax = plt.subplots(figsize=(8, 5))
    fig.patch.set_facecolor(BG_COLOR)
    bars = ax.bar(algos, means_pct, yerr=stdevs_pct, color=colors, capsize=6,
                  edgecolor=BG_COLOR, linewidth=0.8, width=0.5,
                  alpha=0.82,
                  error_kw={"linewidth": 1.5, "ecolor": TEXT_COLOR})
    ax.axhline(50.0, color="#475569", linestyle="--", linewidth=1.4,
               label="Valeur idéale (50 %) ")
    ax.set_ylim(45.0, 56.5)
    ax.set_ylabel("Pourcentage de bits modifiés dans le texte chiffré (%)", fontsize=10)
    ax.set_title(
        "Score d'avalanche en fonction de l'algorithme",
        fontsize=11,
    )
    ax.legend(fontsize=9)

    for bar, mean_pct, std_pct, color in zip(bars, means_pct, stdevs_pct, colors):
        ax.text(bar.get_x() + bar.get_width() / 2, mean_pct + std_pct + 0.3,
                f"{mean_pct:.2f}%", ha="center", va="bottom", fontsize=9, color=color)

    _style_ax(ax)
    plt.tight_layout()
    savefig("02-effet-avalanche/avalanche-par-algorithme.png")


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
    means_pt_pct  = [m * 100.0 for m in means_pt]
    means_key_pct = [m * 100.0 for m in means_key]

    x = np.arange(len(algo_order))
    w = 0.32
    fig, ax = plt.subplots(figsize=(9, 5))
    fig.patch.set_facecolor(BG_COLOR)
    bars_pt  = ax.bar(x - w/2, means_pt_pct,  w, label="Avalanche (texte clair)",
                      color=[ALGO_COLORS[a] for a in algo_order],
                      edgecolor=BG_COLOR, linewidth=0.8, alpha=0.50)
    bars_key = ax.bar(x + w/2, means_key_pct, w, label="Avalanche (clé)",
                      color=[ALGO_COLORS[a] for a in algo_order],
                      edgecolor=BG_COLOR, linewidth=0.8, alpha=0.88)
    ax.axhline(50.0, color="#475569", linestyle="--", linewidth=1.4,
               label="Valeur idéale (50 %) ")
    ax.set_xticks(x)
    ax.set_xticklabels(algo_order, fontsize=11)
    ax.set_ylim(40.0, 65.0)
    ax.set_ylabel("Pourcentage de bits modifiés dans le texte chiffré (%)", fontsize=11)
    ax.set_title(
        "Score d'avalanche en fonction du type de perturbation",
        fontsize=11,
    )
    ax.legend(fontsize=9)
    for bar, m_pct, c in zip(bars_pt, means_pt_pct, [ALGO_COLORS[a] for a in algo_order]):
        ax.text(bar.get_x() + bar.get_width()/2, m_pct + 0.1,
                f"{m_pct:.1f}%", ha="center", va="bottom", fontsize=8, color=c)
    for bar, m_pct, c in zip(bars_key, means_key_pct, [ALGO_COLORS[a] for a in algo_order]):
        ax.text(bar.get_x() + bar.get_width()/2, m_pct + 0.1,
                f"{m_pct:.1f}%", ha="center", va="bottom", fontsize=8, color=c)
    _style_ax(ax)
    plt.tight_layout()
    savefig("02-effet-avalanche/avalanche-texte-vs-cle.png")


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
        "Débit de chiffrement en fonction de l'opération (ECB)",
        fontsize=11,
    )
    ax.legend(fontsize=9)
    _style_ax(ax)
    plt.tight_layout()
    savefig("03-modes-chiffrement/chiffrement-vs-dechiffrement-ecb.png")


# ===========================================================================
# Figure 6 — Impact de la taille de clé sur le débit AES (ECB, 4096 o)
# ===========================================================================
def fig6_key_size_impact():
    data = [r for r in rows
            if r["algorithm"] == "AES" and r["message_size_bytes"] == 4096]
    modes = sorted({r["mode"] for r in data})
    key_bits = sorted({r["key_size_bits"] for r in data})

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
        "Débit AES en fonction de la taille de clé",
        fontsize=11,
    )
    ax.legend(title="Mode", fontsize=9)
    _style_ax(ax)
    plt.tight_layout()
    savefig("03-modes-chiffrement/aes-impact-taille-cle.png")


# ===========================================================================
# Profils par algorithme — Vue synthétique de chaque algo
# Affiche débit et effet d'avalanche sur 2 lignes
# ===========================================================================
def algo_profile(algo_name):
    """Crée une vue synthétique d'un algorithme : débit vs modes + avalanche."""
    algo_data = [r for r in rows if r["algorithm"] == algo_name]
    if not algo_data:
        return

    algo_color = ALGO_COLORS.get(algo_name, "#888")

    # --- Stream ciphers (ChaCha20) : pas de modes bloc, afficher débit vs taille ---
    modes_in_data = {r["mode"] for r in algo_data}
    if modes_in_data == {"Stream"} or len(modes_in_data) == 1 and "Stream" in modes_in_data:
        msg_sizes = sorted({r["message_size_bytes"] for r in algo_data})
        enc_vals = []
        dec_vals = []
        for s in msg_sizes:
            match = [r for r in algo_data if r["message_size_bytes"] == s]
            enc_vals.append(np.mean([r["throughput_enc_mbps"] for r in match]))
            dec_vals.append(np.mean([r["throughput_dec_mbps"] for r in match]))

        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))
        fig.patch.set_facecolor(BG_COLOR)

        x = np.arange(len(msg_sizes))
        w = 0.35
        ax1.bar(x - w/2, enc_vals, w, label="Chiffrement", color=algo_color, alpha=0.85, edgecolor=BG_COLOR)
        ax1.bar(x + w/2, dec_vals, w, label="Déchiffrement", color=algo_color, alpha=0.50, edgecolor=BG_COLOR)
        ax1.set_xticks(x)
        ax1.set_xticklabels([f"{s:,}" for s in msg_sizes])
        ax1.set_xlabel("Taille du message (octets)", fontsize=10)
        ax1.set_ylabel("Débit (MB/s)", fontsize=10)
        ax1.set_title(f"Profil {algo_name} — Débit en fonction de la taille du message",
                      fontsize=11, fontweight="bold")
        ax1.legend(fontsize=9)
        _style_ax(ax1)

        # Avalanche scores by message size
        aval_vals = [np.mean([r["avalanche_score"] for r in algo_data if r["message_size_bytes"] == s])
                     for s in msg_sizes]
        ax2.bar(x, aval_vals, 0.5, color=algo_color, alpha=0.75, edgecolor=BG_COLOR)
        ax2.axhline(0.5, color="#475569", linestyle="--", linewidth=1.2, alpha=0.7)
        ax2.set_xticks(x)
        ax2.set_xticklabels([f"{s:,}" for s in msg_sizes])
        ax2.set_xlabel("Taille du message (octets)", fontsize=10)
        ax2.set_ylabel("Score d'avalanche", fontsize=10)
        ax2.set_ylim(0.45, 0.65)
        ax2.set_title(f"Profil {algo_name} — Avalanche en fonction de la taille du message", fontsize=10)
        _style_ax(ax2)

        plt.tight_layout()
        savefig(f"06-algorithm-profiles/{algo_name.lower()}-profile.png")
        return

    # --- Block ciphers : débit et avalanche par mode et taille de clé (4096 o) ---
    data_4096 = [r for r in algo_data if r["message_size_bytes"] == 4096]
    if not data_4096:
        return

    modes_available = sorted({r["mode"] for r in data_4096})
    key_bits_list = sorted({r["key_size_bits"] for r in data_4096})

    import matplotlib.colors as mcolors
    base_rgb = mcolors.to_rgb(algo_color)
    n = len(modes_available)
    alphas = np.linspace(0.35, 0.95, n)
    shade_colors = [(*base_rgb, a) for a in alphas]
    mode_shade = {mode: shade_colors[i] for i, mode in enumerate(modes_available)}

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))
    fig.patch.set_facecolor(BG_COLOR)

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
               color=mode_shade[mode],
               edgecolor="none", linewidth=0,
               hatch=MODE_HATCH.get(mode, ""))

    ax1.set_xticks(x)
    ax1.set_xticklabels([f"{k} bits" for k in key_bits_list])
    ax1.set_ylabel("Débit de chiffrement (MB/s)", fontsize=10)
    ax1.set_title(f"Profil {algo_name} — Débit en fonction du mode et de la taille de clé",
                  fontsize=11, fontweight="bold")
    ax1.legend(title="Mode", fontsize=8, ncol=4)
    _style_ax(ax1)

    for offset, mode in zip(offsets, modes_available):
        vals = []
        for kb in key_bits_list:
            match = [r for r in data_4096 if r["mode"] == mode and r["key_size_bits"] == kb]
            vals.append(match[0]["avalanche_score"] if match else 0)
        ax2.bar(x + offset, vals, w, label=mode,
               color=mode_shade[mode],
               edgecolor="none", linewidth=0,
               hatch=MODE_HATCH.get(mode, ""))

    ax2.axhline(0.5, color="#475569", linestyle="--", linewidth=1.2, alpha=0.7)
    ax2.set_xticks(x)
    ax2.set_xticklabels([f"{k} bits" for k in key_bits_list])
    ax2.set_xlabel("Taille de clé", fontsize=10)
    ax2.set_ylabel("Score d'avalanche", fontsize=10)
    ax2.set_ylim(0.45, 0.55)
    ax2.set_title(f"Profil {algo_name} — Avalanche en fonction du mode et de la taille de clé", fontsize=10)
    _style_ax(ax2)

    plt.tight_layout()
    savefig(f"06-algorithm-profiles/{algo_name.lower()}-profile.png")


# ===========================================================================
# Figure 7 — AES : sécurité vs performance — ECB / GCM / CTR
# ===========================================================================
def fig7_ecb_vs_gcm():
    aes128 = [r for r in rows if r["algorithm"] == "AES" and r["key_size_bits"] == 128]
    msg_sizes = sorted({r["message_size_bytes"] for r in aes128})

    fig, ax = plt.subplots(figsize=(FIG_W, 5.5))
    fig.patch.set_facecolor(BG_COLOR)
    for mode, color, ls, lbl in [
        ("ECB", "#B03A2E", "-",  "ECB — [!] Non sécurisé (détecte les patterns)"),
        ("GCM", "#3A7A3A", "--", "GCM — [OK] Recommandé (authentifié)"),
        ("CTR", "#888888", ":",  "CTR — Authentification externe requise"),
        ("CBC", "#1A5E8A", "-.", "CBC — Sécurisé mais lent en chiffrement"),
    ]:
        subset = sorted([r for r in aes128 if r["mode"] == mode],
                        key=lambda r: r["message_size_bytes"])
        if subset:
            ax.plot([r["message_size_bytes"] for r in subset],
                    [r["throughput_enc_mbps"] for r in subset],
                    marker="o", linewidth=2.2, linestyle=ls, color=color,
                    label=lbl, alpha=0.9, markersize=5)

    ax.set_xscale("log", base=2)
    ax.set_xticks(msg_sizes)
    ax.set_xticklabels([f"{s:,}" for s in msg_sizes])
    ax.set_xlabel("Taille du message (octets)", fontsize=11)
    ax.set_ylabel("Débit de chiffrement (MB/s)", fontsize=11)
    ax.set_title(
        "Débit AES-128 en fonction du mode (sécurité et performance)",
        fontsize=11,
    )
    ax.legend(fontsize=9)
    _style_ax(ax)
    plt.tight_layout()
    savefig("03-modes-chiffrement/aes-securite-vs-performance.png")


# ===========================================================================
# Figure 8 — Heatmap synthèse : algos × métriques (scores normalisés 0→1)
# ===========================================================================
def fig9_synthesis_heatmap():
    best_key  = {"AES": 256, "DES": 64, "3DES": 192, "Twofish": 256, "ChaCha20": 256}
    best_mode = {"AES": "ECB", "DES": "ECB", "3DES": "ECB", "Twofish": "ECB", "ChaCha20": "Stream"}
    target    = 4096
    algo_order = ["AES", "ChaCha20", "DES", "3DES", "Twofish"]

    thr_vals, lat_vals, aval_vals = {}, {}, {}
    for algo in algo_order:
        match = [r for r in rows if r["algorithm"] == algo
                 and r["mode"] == best_mode[algo]
                 and r["key_size_bits"] == best_key[algo]
                 and r["message_size_bytes"] == target]
        if match:
            thr_vals[algo] = match[0]["throughput_enc_mbps"]
            lat_vals[algo] = match[0]["avg_encrypt_time_s"] * 1e6
        avals = [r["avalanche_score"] for r in rows if r["algorithm"] == algo]
        aval_vals[algo] = max(0.0, 1 - abs(np.mean(avals) - 0.5) * 20) if avals else 0

    max_thr = max(thr_vals.values()) or 1
    max_lat = max(lat_vals.values()) or 1

    metrics = ["Débit\n(vitesse)", "Efficacité\nlatence", "Avalanche\n(robustesse)"]
    data = np.array([
        [thr_vals.get(a, 0) / max_thr,
         1 - lat_vals.get(a, 0) / max_lat,
         aval_vals.get(a, 0)]
        for a in algo_order
    ])

    fig, ax = plt.subplots(figsize=(8, 5))
    fig.patch.set_facecolor(BG_COLOR)
    im = ax.imshow(data, cmap="plasma", aspect="auto", vmin=0, vmax=1)
    ax.set_xticks(range(len(metrics)))
    ax.set_xticklabels(metrics, fontsize=11, color=TEXT_COLOR)
    ax.set_yticks(range(len(algo_order)))
    ax.set_yticklabels(algo_order, fontsize=11, color=TEXT_COLOR)
    ax.tick_params(colors=TEXT_COLOR)
    for i in range(len(algo_order)):
        for j in range(len(metrics)):
            val = data[i, j]
            # plasma: dark at low values, bright yellow at high — white text on dark, black on bright
            ax.text(j, i, f"{val:.2f}", ha="center", va="center",
                    fontsize=11, color="white" if val < 0.7 else "black", fontweight="bold")
    cbar = plt.colorbar(im, ax=ax)
    cbar.ax.tick_params(colors=TEXT_COLOR, labelsize=8)
    cbar.ax.yaxis.label.set_color(TEXT_COLOR)
    ax.set_title(
        "Score global en fonction de l'algorithme et de la métrique",
        fontsize=11, color=TEXT_COLOR,
    )
    plt.tight_layout()
    savefig("04-synthese/heatmap-synthese.png")


# ===========================================================================
# Exécution de toutes les figures
# ===========================================================================
if __name__ == "__main__":
    print("Generating charts...")
    for subdir in ["01-debit", "02-effet-avalanche", "03-modes-chiffrement",
                   "04-synthese"]:
        os.makedirs(os.path.join(CHARTS_DIR, subdir), exist_ok=True)

    fig1_throughput_4096()
    fig2_throughput_vs_size()
    fig3_aes_mode_comparison()
    fig4_avalanche()
    fig4b_key_avalanche()
    fig5_enc_vs_dec()
    fig6_key_size_impact()
    fig7_ecb_vs_gcm()
    fig9_synthesis_heatmap()

    print(f"\nDone. Charts saved to: {os.path.abspath(CHARTS_DIR)}")


