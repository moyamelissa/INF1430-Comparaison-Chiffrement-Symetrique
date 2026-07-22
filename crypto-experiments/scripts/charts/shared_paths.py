"""Chemins partagés pour les modules de génération de graphiques."""

from __future__ import annotations

from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]
RESULTS_DIR = BASE_DIR / "data" / "results"
CHARTS_DIR = BASE_DIR / "data" / "charts"


def ensure_chart_dir(relative_dir: str) -> Path:
    path = CHARTS_DIR / relative_dir
    path.mkdir(parents=True, exist_ok=True)
    return path
