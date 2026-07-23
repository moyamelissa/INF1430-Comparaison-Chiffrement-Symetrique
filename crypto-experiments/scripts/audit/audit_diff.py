"""Export a CSV diff report between raw values and chart aggregation outputs.

Usage (from crypto-experiments/):
    python scripts/audit/audit_diff.py
    python scripts/audit/audit_diff.py --out data/evidence/audit_diff_report.csv
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path
import sys

# Allow imports from scripts/charts when executed from scripts/audit/
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from charts.data_performance import load_latest_rows
from charts.data_platform import load_platform_rows


GroupKey = tuple[str, str, int, int]
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _ensure_not_results_output(path: Path) -> None:
    """Reject audit outputs written under data/results."""
    results_dir = (PROJECT_ROOT / "data" / "results").resolve()
    resolved_path = path.resolve()
    try:
        resolved_path.relative_to(results_dir)
    except ValueError:
        return
    raise SystemExit(
        "Refusing to write audit output under data/results: "
        f"{resolved_path}. Use data/evidence instead."
    )


def _row_value(row: dict[str, str], key: str) -> str:
    """Read a CSV value while tolerating BOM/quoted header variants."""
    if key in row:
        return row[key]
    quoted = f'"{key}"'
    if quoted in row:
        return row[quoted]
    bom_quoted = f'\ufeff"{key}"'
    if bom_quoted in row:
        return row[bom_quoted]
    raise KeyError(key)


def _to_float_optional(value: str) -> float | None:
    raw = value.strip()
    if not raw or raw == "{}":
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def _row_value_optional(row: dict[str, str], key: str) -> str | None:
    try:
        return _row_value(row, key)
    except KeyError:
        return None


def _load_raw_csv_rows(paths: list[Path]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for path in paths:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            rows.extend(reader)
    return rows


def _group_key_from_raw(row: dict[str, str]) -> GroupKey:
    algorithm = _row_value(row, "algorithm")
    mode = _row_value(row, "mode")
    key_size_bits = int(_row_value(row, "key_size_bytes")) * 8
    message_size_bytes = int(_row_value(row, "message_size_bytes"))
    return (algorithm, mode, key_size_bits, message_size_bytes)


def _compute_raw_stats(
    raw_rows: list[dict[str, str]],
    metric_to_csv_column: dict[str, str],
) -> dict[tuple[GroupKey, str], tuple[int, float | None]]:
    values_by_key_metric: dict[tuple[GroupKey, str], list[float]] = defaultdict(list)

    for row in raw_rows:
        key = _group_key_from_raw(row)
        for metric, csv_col in metric_to_csv_column.items():
            raw_value = _row_value_optional(row, csv_col)
            if raw_value is None:
                continue
            parsed = _to_float_optional(raw_value)
            if parsed is not None:
                values_by_key_metric[(key, metric)].append(parsed)

    stats: dict[tuple[GroupKey, str], tuple[int, float | None]] = {}
    for key_metric, values in values_by_key_metric.items():
        count = len(values)
        stats[key_metric] = (count, (sum(values) / count) if count else None)
    return stats


def _abs_diff(raw_mean: float | None, aggregated_value: float | None) -> float | None:
    if raw_mean is None or aggregated_value is None:
        return None
    return abs(aggregated_value - raw_mean)


def _rel_diff_pct(raw_mean: float | None, abs_diff: float | None) -> float | None:
    if raw_mean is None or abs_diff is None or raw_mean == 0:
        return None
    return (abs_diff / abs(raw_mean)) * 100.0


def _append_context_rows(
    out: list[dict[str, object]],
    *,
    context: str,
    platform: str,
    aggregated_rows: list[dict[str, object]],
    metric_names: list[str],
    raw_stats: dict[tuple[GroupKey, str], tuple[int, float | None]],
    source_csvs: str,
) -> None:
    for agg_row in aggregated_rows:
        key: GroupKey = (
            str(agg_row["algorithm"]),
            str(agg_row["mode"]),
            int(agg_row["key_size_bits"]),
            int(agg_row["message_size_bytes"]),
        )
        for metric in metric_names:
            aggregated_value_obj = agg_row.get(metric)
            aggregated_value = (
                float(aggregated_value_obj)
                if isinstance(aggregated_value_obj, (int, float))
                else None
            )
            raw_count, raw_mean = raw_stats.get((key, metric), (0, None))
            abs_diff = _abs_diff(raw_mean, aggregated_value)
            rel_diff_pct = _rel_diff_pct(raw_mean, abs_diff)
            out.append({
                "context": context,
                "platform": platform,
                "algorithm": key[0],
                "mode": key[1],
                "key_size_bits": key[2],
                "message_size_bytes": key[3],
                "metric": metric,
                "raw_count": raw_count,
                "raw_mean": raw_mean if raw_mean is not None else "",
                "aggregated_value": aggregated_value if aggregated_value is not None else "",
                "abs_diff": abs_diff if abs_diff is not None else "",
                "rel_diff_pct": rel_diff_pct if rel_diff_pct is not None else "",
                "source_csvs": source_csvs,
            })


def _build_report_rows() -> list[dict[str, object]]:
    perf_paths, perf_agg_rows = load_latest_rows()
    cmp_x86_paths, cmp_pi_paths, cmp_x86_agg_rows, cmp_pi_agg_rows = load_platform_rows()

    perf_metric_to_csv = {
        "throughput_enc_mbps": "throughput_encrypt_mbps",
        "throughput_dec_mbps": "throughput_decrypt_mbps",
        "avalanche_score": "avalanche_score",
        "key_avalanche_score": "key_avalanche_score",
        "avg_encrypt_time_s": "avg_encrypt_time_s",
        "avg_decrypt_time_s": "avg_decrypt_time_s",
    }
    platform_metric_to_csv = {
        "throughput_enc": "throughput_encrypt_mbps",
        "throughput_dec": "throughput_decrypt_mbps",
        "avalanche": "avalanche_score",
        "key_avalanche": "key_avalanche_score",
        "ci95_enc": "ci95_encrypt_mbps",
    }

    perf_raw_stats = _compute_raw_stats(_load_raw_csv_rows(perf_paths), perf_metric_to_csv)
    cmp_x86_raw_stats = _compute_raw_stats(_load_raw_csv_rows(cmp_x86_paths), platform_metric_to_csv)
    cmp_pi_raw_stats = _compute_raw_stats(_load_raw_csv_rows(cmp_pi_paths), platform_metric_to_csv)

    out: list[dict[str, object]] = []

    _append_context_rows(
        out,
        context="performance",
        platform="x86",
        aggregated_rows=perf_agg_rows,
        metric_names=list(perf_metric_to_csv.keys()),
        raw_stats=perf_raw_stats,
        source_csvs=", ".join(path.name for path in perf_paths),
    )
    _append_context_rows(
        out,
        context="platform_comparison",
        platform="x86",
        aggregated_rows=cmp_x86_agg_rows,
        metric_names=list(platform_metric_to_csv.keys()),
        raw_stats=cmp_x86_raw_stats,
        source_csvs=", ".join(path.name for path in cmp_x86_paths),
    )
    _append_context_rows(
        out,
        context="platform_comparison",
        platform="raspberry_pi",
        aggregated_rows=cmp_pi_agg_rows,
        metric_names=list(platform_metric_to_csv.keys()),
        raw_stats=cmp_pi_raw_stats,
        source_csvs=", ".join(path.name for path in cmp_pi_paths),
    )

    return sorted(
        out,
        key=lambda row: (
            str(row["context"]),
            str(row["platform"]),
            str(row["algorithm"]),
            str(row["mode"]),
            int(row["key_size_bits"]),
            int(row["message_size_bytes"]),
            str(row["metric"]),
        ),
    )


def export_report(out_path: Path) -> tuple[Path, int, float, float, int]:
    rows = _build_report_rows()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "context",
        "platform",
        "algorithm",
        "mode",
        "key_size_bits",
        "message_size_bytes",
        "metric",
        "raw_count",
        "raw_mean",
        "aggregated_value",
        "abs_diff",
        "rel_diff_pct",
        "source_csvs",
    ]

    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    abs_diffs = [float(row["abs_diff"]) for row in rows if isinstance(row.get("abs_diff"), (int, float))]
    rel_diffs = [float(row["rel_diff_pct"]) for row in rows if isinstance(row.get("rel_diff_pct"), (int, float))]
    non_zero_count = sum(1 for value in abs_diffs if value != 0.0)
    return (
        out_path.resolve(),
        len(rows),
        max(abs_diffs) if abs_diffs else 0.0,
        max(rel_diffs) if rel_diffs else 0.0,
        non_zero_count,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Export a CSV diff audit between raw values and chart aggregates.")
    parser.add_argument(
        "--out",
        type=Path,
        default=PROJECT_ROOT / "data" / "evidence" / "audit_diff_report.csv",
        help="Output CSV path",
    )
    args = parser.parse_args()

    _ensure_not_results_output(args.out)

    out_path, row_count, max_abs_diff, max_rel_diff, non_zero_count = export_report(args.out)
    print(f"Report exported: {out_path}")
    print(f"Rows written: {row_count}")
    print(f"Max abs diff: {max_abs_diff}")
    print(f"Max rel diff pct: {max_rel_diff}")
    print(f"Non-zero abs diffs: {non_zero_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


