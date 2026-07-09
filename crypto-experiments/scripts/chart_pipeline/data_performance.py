"""Prépare les données de benchmarking pour les graphiques plateforme unique.

Ce module lit le CSV le plus récent dans ``data/results/`` et convertit les
colonnes utiles vers des types Python directement exploitables par les scripts
de rendu.
"""

from __future__ import annotations

import csv
from pathlib import Path

from chart_pipeline.shared_paths import RESULTS_DIR


# Type simple utilisé par les scripts de rendu pour manipuler librement les mesures.
Row = dict[str, object]


def latest_results_csv() -> Path:
    """Retourne le CSV de résultats le plus récent disponible."""
    csv_files = sorted(
        f for f in RESULTS_DIR.iterdir() if f.suffix == ".csv" and f.name != ".gitkeep"
    )
    if not csv_files:
        raise FileNotFoundError("Aucun fichier CSV trouvé dans data/results/.")
    return csv_files[-1]


def load_latest_rows() -> tuple[Path, list[Row]]:
    """Charge et normalise les lignes du CSV plateforme unique.

    Les conversions vers ``int`` et ``float`` sont faites ici pour éviter de
    répéter cette logique dans les scripts de rendu.
    """
    csv_path = latest_results_csv()
    rows: list[Row] = []

    # Le CSV source contient uniquement des chaînes. On convertit ici les
    # valeurs numériques pour que les modules de rendu restent centrés sur les
    # filtres, agrégations et tracés.
    with csv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            # On conserve une structure simple (dict) pour que les scripts de
            # rendu puissent filtrer et agréger librement les mesures.
            rows.append({
                "algorithm": row["algorithm"],
                "mode": row["mode"],
                "key_size_bytes": int(row["key_size_bytes"]),
                # La plupart des graphiques affichent les tailles de clé en bits.
                "key_size_bits": int(row["key_size_bytes"]) * 8,
                "message_size_bytes": int(row["message_size_bytes"]),
                "avg_encrypt_time_s": float(row["avg_encrypt_time_s"]),
                "avg_decrypt_time_s": float(row["avg_decrypt_time_s"]),
                "throughput_enc_mbps": float(row["throughput_encrypt_mbps"]),
                "throughput_dec_mbps": float(row["throughput_decrypt_mbps"]),
                "avalanche_score": float(row["avalanche_score"]),
                "key_avalanche_score": float(row["key_avalanche_score"]),
            })
    return csv_path, rows

