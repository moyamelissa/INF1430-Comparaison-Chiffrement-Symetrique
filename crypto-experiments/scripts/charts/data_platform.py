"""Prépare les données de comparaison entre x86 et Raspberry Pi.

Ce module détecte les deux CSV de référence dans ``data/results/`` puis charge
les colonnes utiles dans un format homogène pour les graphiques comparatifs.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path

from charts.shared_paths import RESULTS_DIR


# Même convention que data_performance.py : un dictionnaire simple par ligne.
Row = dict[str, object]
_RESULT_NAME_RE = re.compile(r"^(?P<platform>[a-z0-9-]+)_experience(?P<idx>\d+)_(?P<date>\d{8})\.csv$")


def _row_value(row: dict[str, str], key: str) -> str:
    """Retourne une valeur CSV en tolérant les variantes d'entête (BOM/quotes)."""
    if key in row:
        return row[key]
    quoted = f'"{key}"'
    if quoted in row:
        return row[quoted]
    bom_quoted = f'\ufeff"{key}"'
    if bom_quoted in row:
        return row[bom_quoted]
    raise KeyError(key)


def _to_float(value: str) -> float:
    return float(value)


def _to_float_optional(value: str) -> float | None:
    raw = value.strip()
    if not raw or raw == "{}":
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def _is_x86_csv(path: Path) -> bool:
    """Détermine si un CSV appartient à une plateforme x86 (nommage strict)."""
    name = path.name.lower()
    match = _RESULT_NAME_RE.match(name)
    if not match:
        return False
    platform_label = match.group("platform")
    return "x86" in platform_label and "raspberry" not in platform_label


def _is_pi_csv(path: Path) -> bool:
    """Détermine si un CSV appartient à Raspberry Pi (nommage strict)."""
    name = path.name.lower()
    match = _RESULT_NAME_RE.match(name)
    if not match:
        return False
    platform_label = match.group("platform")
    return "raspberry" in platform_label


def discover_platform_csvs() -> tuple[list[Path], list[Path]]:
    """Retourne tous les CSV x86 et tous les CSV Raspberry Pi disponibles."""
    all_csvs = [f for f in RESULTS_DIR.iterdir() if f.suffix == ".csv" and f.name != ".gitkeep"]

    x86_csvs = sorted(f for f in all_csvs if _is_x86_csv(f))
    pi_csvs  = sorted(f for f in all_csvs if _is_pi_csv(f))
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
                "algorithm": _row_value(row, "algorithm"),
                "mode": _row_value(row, "mode"),
                "key_size_bits": int(_row_value(row, "key_size_bytes")) * 8,
                "message_size_bytes": int(_row_value(row, "message_size_bytes")),
                "throughput_enc": _to_float(_row_value(row, "throughput_encrypt_mbps")),
                "throughput_dec": _to_float(_row_value(row, "throughput_decrypt_mbps")),
                "avalanche": _to_float(_row_value(row, "avalanche_score")),
                "key_avalanche": _to_float_optional(_row_value(row, "key_avalanche_score")),
                "ci95_enc": _to_float_optional(
                    row.get("ci95_encrypt_mbps")
                    or row.get('"ci95_encrypt_mbps"')
                    or row.get('\ufeff"ci95_encrypt_mbps"')
                    or ""
                ),
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
            values = [r[field] for r in group if isinstance(r[field], (int, float))]
            if not values:
                raise ValueError(f"Aucune valeur numérique valide pour '{field}' dans le groupe {_key}")
            base[field] = sum(values) / len(values)
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



