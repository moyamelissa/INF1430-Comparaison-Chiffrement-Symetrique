"""Prépare les données de benchmarking pour les graphiques plateforme unique.

Ce module lit tous les CSV x86 disponibles dans ``data/results/``, les convertit
et calcule la moyenne par combinaison (algorithme, mode, taille de clé, taille
de message) pour que les graphiques reflètent une mesure agrégée sur l'ensemble
des campagnes d'expérience.
"""

from __future__ import annotations

import csv
from pathlib import Path

from chart_pipeline.shared_paths import RESULTS_DIR


# Type simple utilisé par les scripts de rendu pour manipuler librement les mesures.
Row = dict[str, object]


def x86_results_csvs() -> list[Path]:
    """Retourne tous les CSV x86 disponibles dans data/results/, triés."""
    csvs = sorted(
        f for f in RESULTS_DIR.iterdir()
        if f.suffix == ".csv" and f.name != ".gitkeep"
        and ("x86" in f.name or "laptop-windows" in f.name)
    )
    if not csvs:
        raise FileNotFoundError("Aucun CSV x86 trouvé dans data/results/.")
    return csvs


def _average_rows(all_rows: list[Row]) -> list[Row]:
    """Moyenne les mesures numériques par combinaison unique (algo, mode, clé, taille)."""
    from collections import defaultdict
    groups: dict[tuple, list[Row]] = defaultdict(list)
    for row in all_rows:
        key = (row["algorithm"], row["mode"], row["key_size_bytes"], row["message_size_bytes"])
        groups[key].append(row)

    numeric_fields = [
        "avg_encrypt_time_s", "avg_decrypt_time_s",
        "throughput_enc_mbps", "throughput_dec_mbps",
        "avalanche_score", "key_avalanche_score",
    ]
    averaged: list[Row] = []
    for _key, group in sorted(groups.items()):
        base = dict(group[0])
        for field in numeric_fields:
            base[field] = sum(r[field] for r in group) / len(group)  # type: ignore[arg-type]
        averaged.append(base)
    return averaged


def load_latest_rows() -> tuple[list[Path], list[Row]]:
    """Charge et moyenne les lignes de tous les CSV x86 disponibles.

    Retourne la liste des fichiers lus et les lignes moyennées par combinaison
    unique (algorithme, mode, taille de clé, taille de message).
    """
    paths = x86_results_csvs()
    all_rows: list[Row] = []
    for csv_path in paths:
        with csv_path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                all_rows.append({
                    "algorithm": row["algorithm"],
                    "mode": row["mode"],
                    "key_size_bytes": int(row["key_size_bytes"]),
                    "key_size_bits": int(row["key_size_bytes"]) * 8,
                    "message_size_bytes": int(row["message_size_bytes"]),
                    "avg_encrypt_time_s": float(row["avg_encrypt_time_s"]),
                    "avg_decrypt_time_s": float(row["avg_decrypt_time_s"]),
                    "throughput_enc_mbps": float(row["throughput_encrypt_mbps"]),
                    "throughput_dec_mbps": float(row["throughput_decrypt_mbps"]),
                    "avalanche_score": float(row["avalanche_score"]),
                    "key_avalanche_score": float(row["key_avalanche_score"]),
                })
    return paths, _average_rows(all_rows)

