"""
generate_charts.py
Generates all analysis figures from benchmark CSV data.

Usage
-----
    py scripts/generate_charts.py

Output: data/charts/  (PNG files at 150 dpi, suitable for Word insertion)
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
# Config
# ---------------------------------------------------------------------------
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "results")
CHARTS_DIR  = os.path.join(os.path.dirname(__file__), "..", "data", "charts")
os.makedirs(CHARTS_DIR, exist_ok=True)

# Use the first CSV found (most recent if sorted)
csv_files = sorted(
    [f for f in os.listdir(RESULTS_DIR) if f.endswith(".csv") and f != ".gitkeep"]
)
if not csv_files:
    print("No CSV file found in data/results/")
    sys.exit(1)

CSV_PATH = os.path.join(RESULTS_DIR, csv_files[-1])
print(f"Reading: {CSV_PATH}")

# ---------------------------------------------------------------------------
# Load data
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
# Palette — consistent colours per algorithm
# ---------------------------------------------------------------------------
ALGO_COLORS = {
    "AES":      "#2196F3",  # blue
    "DES":      "#F44336",  # red
    "3DES":     "#FF9800",  # orange
    "Twofish":  "#4CAF50",  # green
    "ChaCha20": "#9C27B0",  # purple
}
MODE_HATCH = {"ECB": "", "CBC": "//", "CTR": "xx", "GCM": ".."}

DPI = 150
FIG_W = 10  # inches

def savefig(name: str):
    path = os.path.join(CHARTS_DIR, name)
    plt.savefig(path, dpi=DPI, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {path}")


# ===========================================================================
# Figure 1 — Throughput comparison at 4 096 bytes (representative mid-point)
# One bar per algorithm+mode combination, grouped by algorithm.
# ===========================================================================
def fig1_throughput_4096():
    target_size = 4096
    data = [r for r in rows if r["message_size_bytes"] == target_size]

    # Group: algo → list of (mode, key_bits, enc_mbps)
    groups = defaultdict(list)
    for r in data:
        label = f"{r['mode']}\n{r['key_size_bits']}b"
        groups[r["algorithm"]].append((label, r["throughput_enc_mbps"]))

    algo_order = ["AES", "DES", "3DES", "Twofish"]
    fig, ax = plt.subplots(figsize=(FIG_W, 5))

    x_pos = 0
    tick_positions, tick_labels = [], []
    group_centers = {}

    for algo in algo_order:
        if algo not in groups:
            continue
        items = groups[algo]
        start = x_pos
        for label, mbps in items:
            ax.bar(x_pos, mbps, color=ALGO_COLORS[algo], edgecolor="white", width=0.7)
            tick_positions.append(x_pos)
            tick_labels.append(label)
            x_pos += 1
        group_centers[algo] = (start + x_pos - 1) / 2
        x_pos += 0.8  # gap between groups

    ax.set_xticks(tick_positions)
    ax.set_xticklabels(tick_labels, fontsize=7)
    ax.set_ylabel("Débit de chiffrement (MB/s)", fontsize=11)
    ax.set_title(
        "Figure 1 — Débit de chiffrement par algorithme et mode\n"
        f"(message de {target_size} octets, plateforme : laptop Windows x86)",
        fontsize=11,
    )

    # Draw group labels below
    for algo, cx in group_centers.items():
        ax.text(cx, -ax.get_ylim()[1] * 0.12, algo,
                ha="center", fontsize=9, fontweight="bold", color=ALGO_COLORS[algo])

    legend_patches = [
        mpatches.Patch(color=c, label=a) for a, c in ALGO_COLORS.items()
    ]
    ax.legend(handles=legend_patches, loc="upper right", fontsize=9)
    ax.set_ylim(bottom=0)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)
    plt.tight_layout()
    savefig("fig1_throughput_4096B.png")


# ===========================================================================
# Figure 2 — Throughput vs message size (line chart, ECB mode only)
# Shows scalability of each algorithm as data size grows.
# ===========================================================================
def fig2_throughput_vs_size():
    # Pick ECB (or CTR for DES/3DES which also have ECB; use ECB for all)
    ecb_data = [r for r in rows if r["mode"] == "ECB"]

    # Best key size per algo for clarity (largest = most common recommendation)
    best_key = {"AES": 256, "DES": 64, "3DES": 192, "Twofish": 256, "ChaCha20": 256}

    msg_sizes = sorted({r["message_size_bytes"] for r in ecb_data})
    fig, ax = plt.subplots(figsize=(FIG_W, 5))

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
                color=ALGO_COLORS[algo], linewidth=2)

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
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)
    plt.tight_layout()
    savefig("fig2_throughput_vs_msgsize.png")


# ===========================================================================
# Figure 3 — Mode comparison for AES-128 across all message sizes
# Encrypt throughput: ECB / CBC / CTR / GCM
# ===========================================================================
def fig3_aes_mode_comparison():
    aes128 = [r for r in rows if r["algorithm"] == "AES" and r["key_size_bits"] == 128]
    modes  = ["ECB", "CBC", "CTR", "GCM"]
    mode_colors = {"ECB": "#1565C0", "CBC": "#42A5F5", "CTR": "#66BB6A", "GCM": "#FFA726"}
    msg_sizes = sorted({r["message_size_bytes"] for r in aes128})

    fig, ax = plt.subplots(figsize=(FIG_W, 5))
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
                color=mode_colors[mode], linewidth=2)

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
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)
    plt.tight_layout()
    savefig("fig3_aes_mode_comparison.png")


# ===========================================================================
# Figure 4 — Avalanche score per algorithm (bar chart, all modes averaged)
# Expected value ≈ 0.50 (ideal diffusion)
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

    fig, ax = plt.subplots(figsize=(7, 4.5))
    bars = ax.bar(algos, means, yerr=stdevs, color=colors, capsize=6,
                  edgecolor="white", width=0.5, error_kw={"linewidth": 1.5})
    ax.axhline(0.5, color="black", linestyle="--", linewidth=1.2,
               label="Valeur idéale (0,50)")
    ax.set_ylim(0.45, 0.55)
    ax.set_ylabel("Score d'effet d'avalanche (proportion de bits modifiés)", fontsize=10)
    ax.set_title(
        "Figure 4 — Effet d'avalanche par algorithme\n"
        "(moyenne ± écart-type, tous modes et tailles confondus)",
        fontsize=11,
    )
    ax.legend(fontsize=9)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)

    # Annotate mean values
    for bar, mean in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width() / 2, mean + 0.001,
                f"{mean:.4f}", ha="center", va="bottom", fontsize=9)

    plt.tight_layout()
    savefig("fig4_avalanche.png")


# ===========================================================================
# Figure 4b — Plaintext avalanche vs Key avalanche comparison
# Shows that all algorithms respond equally to both types of single-bit flip.
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
    w = 0.35
    fig, ax = plt.subplots(figsize=(9, 4.5))
    bars_pt  = ax.bar(x - w/2, means_pt,  w, label="Avalanche (texte clair)",
                      color=[ALGO_COLORS[a] + "AA" for a in algo_order], edgecolor="white")
    bars_key = ax.bar(x + w/2, means_key, w, label="Avalanche (clé)",
                      color=[ALGO_COLORS[a] for a in algo_order], edgecolor="white")
    ax.axhline(0.5, color="black", linestyle="--", linewidth=1.2,
               label="Valeur idéale (0,50)")
    ax.set_xticks(x)
    ax.set_xticklabels(algo_order)
    ax.set_ylim(0.40, 0.60)
    ax.set_ylabel("Score d'avalanche", fontsize=11)
    ax.set_title(
        "Figure 4b — Comparaison de l'effet d'avalanche : flip texte clair vs flip clé\n"
        "(tous modes et tailles confondus)",
        fontsize=11,
    )
    ax.legend(fontsize=9)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)
    for bar, m in zip(bars_pt, means_pt):
        ax.text(bar.get_x() + bar.get_width()/2, m + 0.001,
                f"{m:.3f}", ha="center", va="bottom", fontsize=8)
    for bar, m in zip(bars_key, means_key):
        ax.text(bar.get_x() + bar.get_width()/2, m + 0.001,
                f"{m:.3f}", ha="center", va="bottom", fontsize=8)
    plt.tight_layout()
    savefig("fig4b_key_avalanche.png")


# ===========================================================================
# Figure 5 — Encrypt vs Decrypt throughput (paired bars, 4096 B, ECB mode)
# ===========================================================================
def fig5_enc_vs_dec():
    target_size = 4096
    target_mode = "ECB"
    data = [r for r in rows
            if r["message_size_bytes"] == target_size and r["mode"] == target_mode]

    # One entry per algo+key combination
    labels, enc_vals, dec_vals, colors = [], [], [], []
    for r in sorted(data, key=lambda r: (r["algorithm"], r["key_size_bits"])):
        labels.append(f"{r['algorithm']}\n{r['key_size_bits']}b")
        enc_vals.append(r["throughput_enc_mbps"])
        dec_vals.append(r["throughput_dec_mbps"])
        colors.append(ALGO_COLORS[r["algorithm"]])

    x = np.arange(len(labels))
    w = 0.35
    fig, ax = plt.subplots(figsize=(FIG_W, 5))
    bars_enc = ax.bar(x - w/2, enc_vals, w, label="Chiffrement",
                      color=[c + "CC" for c in colors], edgecolor="white")
    bars_dec = ax.bar(x + w/2, dec_vals, w, label="Déchiffrement",
                      color=colors, edgecolor="white")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylabel("Débit (MB/s)", fontsize=11)
    ax.set_title(
        f"Figure 5 — Débit de chiffrement vs déchiffrement (mode ECB, {target_size} octets)\n"
        "(plateforme : laptop Windows x86)",
        fontsize=11,
    )
    ax.legend(fontsize=9)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)
    plt.tight_layout()
    savefig("fig5_enc_vs_dec_ecb.png")


# ===========================================================================
# Figure 6 — Key size impact on AES throughput (ECB, 4096 B)
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

    fig, ax = plt.subplots(figsize=(8, 5))
    for offset, mode in zip(offsets, modes):
        vals = []
        for kb in key_bits:
            match = [r for r in data if r["mode"] == mode and r["key_size_bits"] == kb]
            vals.append(match[0]["throughput_enc_mbps"] if match else 0)
        ax.bar(x + offset, vals, w, label=mode,
               color=mode_colors.get(mode, "#888"), edgecolor="white")

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
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)
    plt.tight_layout()
    savefig("fig6_aes_key_size.png")


# ===========================================================================
# Run all
# ===========================================================================
if __name__ == "__main__":
    print("Generating charts...")
    fig1_throughput_4096()
    fig2_throughput_vs_size()
    fig3_aes_mode_comparison()
    fig4_avalanche()
    fig4b_key_avalanche()
    fig5_enc_vs_dec()
    fig6_key_size_impact()
    print(f"\nDone. Charts saved to: {os.path.abspath(CHARTS_DIR)}")
