"""Construit les graphiques plateforme unique à partir des CSV de benchmark.

Chaîne de traitement
-------------------
1. scripts/experiment.py calcule les mesures et écrit les CSV dans data/results/.
2. scripts/run_charts.py orchestre la génération des dossiers de graphiques.
3. Ce module lit le CSV le plus récent et génère les graphiques x86/plateforme unique.

Structure du fichier
-------------------
- Configuration et chargement des données
- Style réutilisable commun à tous les graphiques
- Graphique 1, Graphique 2, ... : une fonction par graphique
- CHART_GROUPS / GRAPH_OUTPUTS : correspondance dossier -> fonctions -> PNG

Utilisation
-----------
    py scripts/run_charts.py 01
    py scripts/run_charts.py 02
    py scripts/run_charts.py 03
    py scripts/run_charts.py 04

Sortie : data/charts/ (fichiers PNG adaptés à l'insertion dans le rapport)
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
    MODE_COLORS,
    MODE_HATCH,
    TEXT_COLOR,
    save_figure,
    setup_matplotlib,
    style_ax,
)
from chart_pipeline.data_performance import load_latest_rows
from chart_pipeline.shared_paths import CHARTS_DIR


setup_matplotlib(title_pad=12, hatch_linewidth=1.0)

CSV_PATH, rows = load_latest_rows()
print(f"Lecture du fichier: {CSV_PATH}")


def _style_ax(ax):
    style_ax(ax)


def savefig(name: str):
    save_figure(plt.gcf(), CHARTS_DIR, name, facecolor=BG_COLOR)


# ===========================================================================
# Dossier 01 — debit
# ===========================================================================


# ===========================================================================
# Graphique 1 — 01-debit/debit-4096o.png
# Comparaison du débit à 4 096 octets (point médian représentatif)
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
# Graphique 2 — 01-debit/debit-vs-taille-message.png
# Débit en fonction de la taille du message (courbe, mode ECB uniquement)
# Montre la scalabilité de chaque algorithme selon la taille des données.
# ===========================================================================
def fig2_throughput_vs_size():
    # On retient ECB pour comparer les algorithmes sur une base commune.
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
# Dossier 02 — effet-avalanche
# ===========================================================================
# ===========================================================================
# Graphique 3 — 02-effet-avalanche/avalanche-par-algorithme.png
# Score d'avalanche par algorithme (barres, moyenne de tous les modes)
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
# Graphique 4 — 02-effet-avalanche/avalanche-texte-vs-cle.png
# Comparaison avalanche texte clair vs avalanche clé
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
# Dossier 03 — modes-chiffrement
# ===========================================================================


# ===========================================================================
# Graphique 5 — 03-modes-chiffrement/aes-comparaison-modes.png
# Comparaison des modes pour AES-128 sur toutes les tailles de message
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
# Graphique 6 — 03-modes-chiffrement/chiffrement-vs-dechiffrement-ecb.png
# Débit chiffrement vs déchiffrement (barres pairées, 4096 o, mode ECB)
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
# Graphique 7 — 03-modes-chiffrement/aes-impact-taille-cle.png
# Impact de la taille de clé sur le débit AES (ECB, 4096 o)
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

    # --- Chiffrement en flux (ChaCha20) : pas de modes bloc, on trace débit vs taille ---
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

        # Score d'avalanche par taille de message.
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

    # --- Chiffrement par blocs : débit et avalanche par mode et taille de clé (4096 o) ---
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
# Graphique 8 — 03-modes-chiffrement/aes-securite-vs-performance.png
# AES : sécurité vs performance — ECB / GCM / CTR
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
# ===========================================================================
# Dossier 04 — synthese
# ===========================================================================


# ===========================================================================
# Graphique 9 — 04-synthese/heatmap-synthese.png
# Heatmap synthèse : algos × métriques (scores normalisés 0→1)
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
                # Avec la palette plasma: faible = sombre, élevé = clair.
                # On adapte la couleur du texte pour garder un bon contraste.
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


CHART_GROUPS = {
    "01-debit": [
        fig1_throughput_4096,
        fig2_throughput_vs_size,
    ],
    "02-effet-avalanche": [
        fig4_avalanche,
        fig4b_key_avalanche,
    ],
    "03-modes-chiffrement": [
        fig3_aes_mode_comparison,
        fig5_enc_vs_dec,
        fig6_key_size_impact,
        fig7_ecb_vs_gcm,
    ],
    "04-synthese": [
        fig9_synthesis_heatmap,
    ],
}

# Correspondance explicite: fonction de tracé -> fichier PNG de sortie.
# Utile pour vérifier rapidement comment chaque graphique est produit.
GRAPH_OUTPUTS = {
    fig1_throughput_4096: "01-debit/debit-4096o.png",
    fig2_throughput_vs_size: "01-debit/debit-vs-taille-message.png",
    fig3_aes_mode_comparison: "03-modes-chiffrement/aes-comparaison-modes.png",
    fig4_avalanche: "02-effet-avalanche/avalanche-par-algorithme.png",
    fig4b_key_avalanche: "02-effet-avalanche/avalanche-texte-vs-cle.png",
    fig5_enc_vs_dec: "03-modes-chiffrement/chiffrement-vs-dechiffrement-ecb.png",
    fig6_key_size_impact: "03-modes-chiffrement/aes-impact-taille-cle.png",
    fig7_ecb_vs_gcm: "03-modes-chiffrement/aes-securite-vs-performance.png",
    fig9_synthesis_heatmap: "04-synthese/heatmap-synthese.png",
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
        os.makedirs(os.path.join(CHARTS_DIR, group), exist_ok=True)
        for func in CHART_GROUPS[group]:
            func()


# ===========================================================================
# Exécution de toutes les figures
# ===========================================================================
if __name__ == "__main__":
    print("Génération des graphiques...")
    generate_groups()

    print(f"\nTerminé. Graphiques enregistrés dans: {os.path.abspath(CHARTS_DIR)}")



