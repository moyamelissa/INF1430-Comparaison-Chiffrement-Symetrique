"""Point d'entrée unifié pour la génération des graphiques.

Rôle dans la chaîne
-------------------
1. scripts/experiment.py calcule les mesures et écrit les CSV.
2. Ce script orchestre la génération des figures.
3. Les modules scripts/charts/build_*.py contiennent la logique de tracé.
4. Ce script orchestre les dossiers 01, 02, 03 et 04.

Utilisation (depuis crypto-experiments/):
    python scripts/run_charts.py
    python scripts/run_charts.py all
    python scripts/run_charts.py 01
    python scripts/run_charts.py 02
    python scripts/run_charts.py 03
    python scripts/run_charts.py 04
"""

from __future__ import annotations

import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent

from charts import build_ecb_demo as ecb_demo
from charts import build_performance as perf
from charts import build_platform_comparison as platform_cmp


def _generate_01_debit() -> None:
    perf.generate_groups(["01-throughput"])
    platform_cmp.generate_groups(["01-throughput"])


def _generate_02_effet_avalanche() -> None:
    perf.generate_groups(["02-avalanche-effect"])
    platform_cmp.generate_groups(["02-avalanche-effect"])


def _generate_03_modes_chiffrement() -> None:
    perf.generate_groups(["03-encryption-modes"])
    ecb_demo.generate_ecb_demo_chart()


def _generate_04_synthese() -> None:
    perf.generate_groups(["04-decision-support"])
    platform_cmp.generate_groups(["04-decision-support"])


TARGETS = {
    "01": _generate_01_debit,
    "02": _generate_02_effet_avalanche,
    "03": _generate_03_modes_chiffrement,
    "04": _generate_04_synthese,
}


def main(argv: list[str]) -> int:
    selection = argv[1].lower() if len(argv) > 1 else "all"

    aliases = {
        "01-throughput": "01",
        "02-avalanche-effect": "02",
        "03-encryption-modes": "03",
        "04-decision-support": "04",
        "04-synthesis": "04",
        # Compat aliases (legacy French folder names)
        "01-debit": "01",
        "02-effet-avalanche": "02",
        "03-modes-chiffrement": "03",
        "04-synthese": "04",
    }
    selection = aliases.get(selection, selection)

    if selection in {"all", "*"}:
        ordered = ["01", "02", "03", "04"]
    elif selection in TARGETS:
        ordered = [selection]
    else:
        print("Utilisation: python scripts/run_charts.py [all|01|02|03|04]")
        return 1

    print(f"[run_charts] Sélection: {', '.join(ordered)}")
    for key in ordered:
        print(f"\n[run_charts] Génération du dossier {key}...")
        TARGETS[key]()

    print("\n[run_charts] Terminé.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))



