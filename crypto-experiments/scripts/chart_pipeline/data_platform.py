"""Prépare les données de comparaison entre x86 et Raspberry Pi.

Ce module détecte les deux CSV de référence dans ``data/results/`` puis charge
les colonnes utiles dans un format homogène pour les graphiques comparatifs.
"""

from __future__ import annotations

import csv
from pathlib import Path

from chart_pipeline.shared_paths import RESULTS_DIR


# Même convention que data_performance.py : un dictionnaire simple par ligne.
Row = dict[str, object]


def discover_platform_csvs() -> tuple[list[Path], list[Path]]:
    """Retourne tous les CSV x86 et tous les CSV Raspberry Pi disponibles."""
    all_csvs = [f for f in RESULTS_DIR.iterdir() if f.suffix == ".csv" and f.name != ".gitkeep"]

    x86_csvs = sorted(f for f in all_csvs if "x86" in f.name or "laptop-windows" in f.name)
    pi_csvs  = sorted(f for f in all_csvs if "raspberry" in f.name or "raspberry-pi" in f.name)
    if not x86_csvs:
        raise FileNotFoundError("Aucun CSV x86 trouvé dans data/results/.")
    if not pi_csvs:
        raise FileNotFoundError("Aucun CSV Raspberry Pi trouvé dans data/results/.")
    return x86_csvs, pi_csvs


def _load_rows_from_path(path: Path) -> list[Row]:
    """Charge un CSV de plateforme et convertit les champs nécessaires au rendu."""
    rows: list[Row] = []
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            rows.append({
                "algorithm": row["algorithm"],
                "mode": row["mode"],
                "key_size_bits": int(row["key_size_bytes"]) * 8,
                "message_size_bytes": int(row["message_size_bytes"]),
                "throughput_enc": float(row["throughput_encrypt_mbps"]),
                "throughput_dec": float(row["throughput_decrypt_mbps"]),
                "avalanche": float(row["avalanche_score"]),
                "key_avalanche": float(row["key_avalanche_score"]),
                "ci95_enc": float(row.get("ci95_encrypt_mbps", 0)),
            })
    return rows


def _average_rows(all_rows: list[Row]) -> list[Row]:
    """Moyenne les mesures numériques par combinaison unique (algo, mode, clé, taille)."""
    from collections import defaultdict
    groups: dict[tuple, list[Row]] = defaultdict(list)
    for row in all_rows:
        key = (row["algorithm"], row["mode"], row["key_size_bits"], row["message_size_bytes"])
        groups[key].append(row)

    numeric_fields = ["throughput_enc", "throughput_dec", "avalanche", "key_avalanche", "ci95_enc"]
    averaged: list[Row] = []
    for _key, group in sorted(groups.items()):
        base = dict(group[0])
        for field in numeric_fields:
            base[field] = sum(r[field] for r in group) / len(group)  # type: ignore[arg-type]
        averaged.append(base)
    return averaged


def load_averaged_rows(paths: list[Path]) -> list[Row]:
    """Charge et moyenne les lignes de plusieurs CSV d'une même plateforme."""
    all_rows: list[Row] = []
    for path in paths:
        all_rows.extend(_load_rows_from_path(path))
    return _average_rows(all_rows)


def load_platform_rows() -> tuple[list[Path], list[Path], list[Row], list[Row]]:
    """Retourne les chemins des CSV et leurs lignes moyennées par plateforme.

    Cette fonction sert de point d'entrée unique pour les graphiques de
    comparaison inter-plateformes.
    """
    x86_paths, pi_paths = discover_platform_csvs()
    return x86_paths, pi_paths, load_averaged_rows(x86_paths), load_averaged_rows(pi_paths)

