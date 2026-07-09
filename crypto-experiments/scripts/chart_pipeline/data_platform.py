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


def discover_platform_csvs() -> tuple[Path, Path]:
    """Détecte automatiquement le dernier CSV x86 et le dernier CSV Raspberry Pi."""
    all_csvs = [f for f in RESULTS_DIR.iterdir() if f.suffix == ".csv"]

    # Les fichiers ont été nommés à la fois selon la machine et selon la
    # campagne d'expérience. On garde donc une détection tolérante sur le nom.
    x86_csvs = sorted(f for f in all_csvs if "x86" in f.name or "laptop-windows" in f.name)
    pi_csvs = sorted(f for f in all_csvs if "raspberry" in f.name or "raspberry-pi" in f.name)
    if not x86_csvs:
        raise FileNotFoundError("Aucun CSV x86 trouvé dans data/results/.")
    if not pi_csvs:
        raise FileNotFoundError("Aucun CSV Raspberry Pi trouvé dans data/results/.")
    return x86_csvs[-1], pi_csvs[-1]


def load_rows(path: Path) -> list[Row]:
    """Charge un CSV de plateforme et convertit les champs nécessaires au rendu."""
    rows: list[Row] = []

    # Le schéma est volontairement aplati pour faciliter les comparaisons entre
    # les deux plateformes via l'orchestration centralisée de run_charts.py.
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            # Les noms de champs ici sont volontairement plus courts que dans
            # le CSV source pour simplifier les filtres dans les build_*.py.
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


def load_platform_rows() -> tuple[Path, Path, list[Row], list[Row]]:
    """Retourne les chemins des deux CSV et leurs lignes normalisées.

    Cette fonction sert de point d'entrée unique pour les graphiques de
    comparaison inter-plateformes.
    """
    x86_path, pi_path = discover_platform_csvs()
    return x86_path, pi_path, load_rows(x86_path), load_rows(pi_path)

