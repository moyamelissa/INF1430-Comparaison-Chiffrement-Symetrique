"""Exporte un rapport CSV des agregats utilises par les graphes.

Le rapport combine:
- les donnees agregees x86 de data_performance.py
- les donnees agregees x86 et Raspberry Pi de data_platform.py

Usage (depuis crypto-experiments/):
    python scripts/audit/audit_aggregates.py
    python scripts/audit/audit_aggregates.py --out data/validation/audit/audit_aggregates_report.csv
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
import sys

# Permet d'importer plotting depuis scripts/audit/
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from plotting.data_performance import load_latest_rows
from plotting.data_platform import load_platform_rows


def _report_rows() -> list[dict[str, object]]:
    perf_paths, perf_rows = load_latest_rows()
    cmp_x86_paths, cmp_pi_paths, cmp_x86_rows, cmp_pi_rows = load_platform_rows()

    perf_sources = ", ".join(p.name for p in perf_paths)
    cmp_x86_sources = ", ".join(p.name for p in cmp_x86_paths)
    cmp_pi_sources = ", ".join(p.name for p in cmp_pi_paths)

    out: list[dict[str, object]] = []

    for row in perf_rows:
        out.append({
            "context": "performance",
            "platform": "x86",
            "algorithm": row["algorithm"],
            "mode": row["mode"],
            "key_size_bits": row["key_size_bits"],
            "message_size_bytes": row["message_size_bytes"],
            "throughput_enc_mbps": row["throughput_enc_mbps"],
            "throughput_dec_mbps": row["throughput_dec_mbps"],
            "avalanche_score": row["avalanche_score"],
            "key_avalanche_score": row["key_avalanche_score"],
            "ci95_enc_mbps": "",
            "source_csvs": perf_sources,
        })

    for row in cmp_x86_rows:
        out.append({
            "context": "platform_comparison",
            "platform": "x86",
            "algorithm": row["algorithm"],
            "mode": row["mode"],
            "key_size_bits": row["key_size_bits"],
            "message_size_bytes": row["message_size_bytes"],
            "throughput_enc_mbps": row["throughput_enc"],
            "throughput_dec_mbps": row["throughput_dec"],
            "avalanche_score": row["avalanche"],
            "key_avalanche_score": row["key_avalanche"],
            "ci95_enc_mbps": row["ci95_enc"],
            "source_csvs": cmp_x86_sources,
        })

    for row in cmp_pi_rows:
        out.append({
            "context": "platform_comparison",
            "platform": "raspberry_pi",
            "algorithm": row["algorithm"],
            "mode": row["mode"],
            "key_size_bits": row["key_size_bits"],
            "message_size_bytes": row["message_size_bytes"],
            "throughput_enc_mbps": row["throughput_enc"],
            "throughput_dec_mbps": row["throughput_dec"],
            "avalanche_score": row["avalanche"],
            "key_avalanche_score": row["key_avalanche"],
            "ci95_enc_mbps": row["ci95_enc"],
            "source_csvs": cmp_pi_sources,
        })

    return out


def export_report(out_path: Path) -> Path:
    rows = _report_rows()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "context",
        "platform",
        "algorithm",
        "mode",
        "key_size_bits",
        "message_size_bytes",
        "throughput_enc_mbps",
        "throughput_dec_mbps",
        "avalanche_score",
        "key_avalanche_score",
        "ci95_enc_mbps",
        "source_csvs",
    ]

    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return out_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Exporte un audit CSV des agregats utilises pour les graphes.")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("data/validation/audit/audit_aggregates_report.csv"),
        help="Chemin de sortie du rapport CSV",
    )
    args = parser.parse_args()

    out_path = export_report(args.out)
    print(f"Rapport exporte: {out_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

