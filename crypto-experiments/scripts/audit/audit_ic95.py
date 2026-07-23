"""Export IC95 audit CSV reports from experiment result files.

This script reads all platform CSV files in data/results and computes:
- Relative IC95 per raw row: (ci95_encrypt_mbps / throughput_encrypt_mbps) * 100
- Aggregated metrics per unique combination:
  (platform, algorithm, mode, key_size_bits, message_size_bytes)
- PASS/FAIL using a configurable relative IC95 threshold.

Usage (from crypto-experiments/):
    py scripts/audit/audit_ic95.py
    py scripts/audit/audit_ic95.py --threshold-rel 10
    py scripts/audit/audit_ic95.py --out data/evidence/ic95_audit_report.csv

Usage (from repository root):
    py crypto-experiments/scripts/audit/audit_ic95.py
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path


GroupKey = tuple[str, str, str, int, int]
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


def _to_float_optional(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    raw = str(value).strip()
    if not raw:
        return None
    return float(raw)


def _detect_platform(filename: str) -> str:
    lower = filename.lower()
    if "x86" in lower or lower.startswith("windows_"):
        return "x86"
    if "raspberry" in lower or "arm" in lower:
        return "arm"
    return "unknown"


def _to_float(value: str) -> float:
    return float(value.strip())


def _to_int(value: str) -> int:
    return int(value.strip())


def _get_value(row: dict[str, str], key: str) -> str:
    # Tolerate header variants with BOM and quotes.
    if key in row:
        return row[key]
    quoted = f'"{key}"'
    if quoted in row:
        return row[quoted]
    bom_quoted = f'\ufeff"{key}"'
    if bom_quoted in row:
        return row[bom_quoted]
    raise KeyError(key)


def _discover_result_files(results_dir: Path) -> list[Path]:
    return sorted(
        p
        for p in results_dir.glob("*.csv")
        if "audit" not in p.name.lower()
        and (
            "x86" in p.name.lower()
            or p.name.lower().startswith("windows_")
            or "raspberry" in p.name.lower()
            or "arm" in p.name.lower()
        )
    )


def _load_raw_rows(files: list[Path]) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for path in files:
        platform = _detect_platform(path.name)
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                throughput = _to_float(_get_value(row, "throughput_encrypt_mbps"))
                ci95 = _to_float(_get_value(row, "ci95_encrypt_mbps"))
                rel = (ci95 / throughput) * 100.0 if throughput > 0 else None
                out.append(
                    {
                        "source_csv": path.name,
                        "platform": platform,
                        "algorithm": _get_value(row, "algorithm"),
                        "mode": _get_value(row, "mode"),
                        "key_size_bits": _to_int(_get_value(row, "key_size_bytes")) * 8,
                        "message_size_bytes": _to_int(_get_value(row, "message_size_bytes")),
                        "repetitions": _to_int(_get_value(row, "repetitions")),
                        "throughput_encrypt_mbps": throughput,
                        "ci95_encrypt_mbps": ci95,
                        "ic95_relative_pct": rel,
                    }
                )
    return out


def _group_key(row: dict[str, object]) -> GroupKey:
    return (
        str(row["platform"]),
        str(row["algorithm"]),
        str(row["mode"]),
        int(row["key_size_bits"]),
        int(row["message_size_bytes"]),
    )


def _mean(values: list[float]) -> float:
    return sum(values) / len(values)


def _aggregate_rows(raw_rows: list[dict[str, object]], threshold_rel: float) -> list[dict[str, object]]:
    groups: dict[GroupKey, list[dict[str, object]]] = defaultdict(list)
    for row in raw_rows:
        groups[_group_key(row)].append(row)

    out: list[dict[str, object]] = []
    for key, rows in sorted(groups.items()):
        platform, algorithm, mode, key_bits, msg_size = key
        throughput_vals = [float(r["throughput_encrypt_mbps"]) for r in rows]
        ci95_vals = [float(r["ci95_encrypt_mbps"]) for r in rows]
        rel_vals = [float(r["ic95_relative_pct"]) for r in rows if r["ic95_relative_pct"] is not None]
        reps = [int(r["repetitions"]) for r in rows]
        sources = sorted({str(r["source_csv"]) for r in rows})

        mean_throughput = _mean(throughput_vals)
        mean_ci95 = _mean(ci95_vals)
        mean_rel = _mean(rel_vals) if rel_vals else None
        min_reps = min(reps) if reps else 0
        max_reps = max(reps) if reps else 0

        ci95_confidence_ok = min_reps >= 30
        threshold_ok = (mean_rel is not None) and (mean_rel <= threshold_rel)
        pass_fail = "PASS" if (ci95_confidence_ok and threshold_ok) else "FAIL"

        out.append(
            {
                "platform": platform,
                "algorithm": algorithm,
                "mode": mode,
                "key_size_bits": key_bits,
                "message_size_bytes": msg_size,
                "samples": len(rows),
                "source_files_count": len(sources),
                "source_files": ", ".join(sources),
                "repetitions_min": min_reps,
                "repetitions_max": max_reps,
                "throughput_encrypt_mbps_mean": mean_throughput,
                "ci95_encrypt_mbps_mean": mean_ci95,
                "ic95_relative_pct_mean": mean_rel if mean_rel is not None else "",
                "threshold_rel_ic95_pct": threshold_rel,
                "confidence_95_condition": "PASS" if ci95_confidence_ok else "FAIL",
                "threshold_condition": "PASS" if threshold_ok else "FAIL",
                "overall_status": pass_fail,
            }
        )
    return out


def _write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def evaluate_quality_gates(
    grouped_rows: list[dict[str, object]],
    *,
    min_repetitions: int = 100,
    focus_min_message_size: int = 1024,
    focus_pass_rate_pct: float = 90.0,
    outlier_rel_threshold_pct: float = 20.0,
    outlier_max_count: int = 20,
) -> dict[str, object]:
    total = len(grouped_rows)

    gate1_fail_count = sum(
        1
        for row in grouped_rows
        if int(row["repetitions_min"]) < min_repetitions
    )
    gate1_pass = gate1_fail_count == 0

    focus_rows = [
        row
        for row in grouped_rows
        if int(row["message_size_bytes"]) >= focus_min_message_size
    ]
    focus_total = len(focus_rows)
    focus_pass_count = sum(
        1
        for row in focus_rows
        if str(row["threshold_condition"]) == "PASS"
    )
    focus_pass_rate = ((focus_pass_count * 100.0) / focus_total) if focus_total else 0.0
    gate2_pass = focus_total > 0 and focus_pass_rate >= focus_pass_rate_pct

    outlier_count = 0
    for row in grouped_rows:
        rel = _to_float_optional(row.get("ic95_relative_pct_mean"))
        if rel is not None and rel > outlier_rel_threshold_pct:
            outlier_count += 1
    gate3_pass = outlier_count <= outlier_max_count

    overall_pass = gate1_pass and gate2_pass and gate3_pass
    return {
        "total_rows": total,
        "gate1": {
            "name": f"min repetitions >= {min_repetitions}",
            "pass": gate1_pass,
            "fail_count": gate1_fail_count,
        },
        "gate2": {
            "name": (
                f"message_size >= {focus_min_message_size}B pass rate "
                f">= {focus_pass_rate_pct:.2f}%"
            ),
            "pass": gate2_pass,
            "focus_total": focus_total,
            "focus_pass_count": focus_pass_count,
            "focus_pass_rate_pct": focus_pass_rate,
        },
        "gate3": {
            "name": (
                f"outliers (ic95_relative_pct_mean > {outlier_rel_threshold_pct:.2f}%) "
                f"<= {outlier_max_count}"
            ),
            "pass": gate3_pass,
            "outlier_count": outlier_count,
        },
        "overall_pass": overall_pass,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Export IC95 audit CSV with PASS/FAIL verdicts.")
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=PROJECT_ROOT / "data" / "results",
        help="Directory containing experiment CSV files",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=PROJECT_ROOT / "data" / "evidence" / "ic95_audit_report.csv",
        help="Output CSV path for grouped IC95 audit",
    )
    parser.add_argument(
        "--raw-out",
        type=Path,
        default=PROJECT_ROOT / "data" / "evidence" / "ic95_raw_rows.csv",
        help="Output CSV path for row-level IC95 calculations",
    )
    parser.add_argument(
        "--threshold-rel",
        type=float,
        default=10.0,
        help="Relative IC95 threshold in percent for PASS/FAIL (default: 10)",
    )
    parser.add_argument(
        "--enforce-gates",
        action="store_true",
        help="Exit with non-zero status if quality gates are not met",
    )
    parser.add_argument(
        "--gate-min-repetitions",
        type=int,
        default=100,
        help="Gate 1: minimum repetitions per configuration",
    )
    parser.add_argument(
        "--gate-focus-min-message-size",
        type=int,
        default=1024,
        help="Gate 2: minimum message size (bytes) to evaluate pass-rate quality",
    )
    parser.add_argument(
        "--gate-focus-pass-rate",
        type=float,
        default=90.0,
        help="Gate 2: minimum PASS rate (percent) in focus scope",
    )
    parser.add_argument(
        "--gate-outlier-rel-threshold",
        type=float,
        default=20.0,
        help="Gate 3: relative IC95 percent threshold defining an outlier",
    )
    parser.add_argument(
        "--gate-outlier-max-count",
        type=int,
        default=20,
        help="Gate 3: maximum allowed outlier count",
    )
    args = parser.parse_args()

    _ensure_not_results_output(args.out)
    _ensure_not_results_output(args.raw_out)

    files = _discover_result_files(args.results_dir)
    if not files:
        raise SystemExit(f"No result CSV files found in: {args.results_dir}")

    raw_rows = _load_raw_rows(files)
    grouped_rows = _aggregate_rows(raw_rows, threshold_rel=args.threshold_rel)

    raw_fields = [
        "source_csv",
        "platform",
        "algorithm",
        "mode",
        "key_size_bits",
        "message_size_bytes",
        "repetitions",
        "throughput_encrypt_mbps",
        "ci95_encrypt_mbps",
        "ic95_relative_pct",
    ]
    grouped_fields = [
        "platform",
        "algorithm",
        "mode",
        "key_size_bits",
        "message_size_bytes",
        "samples",
        "source_files_count",
        "source_files",
        "repetitions_min",
        "repetitions_max",
        "throughput_encrypt_mbps_mean",
        "ci95_encrypt_mbps_mean",
        "ic95_relative_pct_mean",
        "threshold_rel_ic95_pct",
        "confidence_95_condition",
        "threshold_condition",
        "overall_status",
    ]

    _write_csv(args.raw_out, raw_rows, raw_fields)
    _write_csv(args.out, grouped_rows, grouped_fields)

    total = len(grouped_rows)
    passed = sum(1 for r in grouped_rows if r["overall_status"] == "PASS")
    failed = total - passed

    gates = evaluate_quality_gates(
        grouped_rows,
        min_repetitions=args.gate_min_repetitions,
        focus_min_message_size=args.gate_focus_min_message_size,
        focus_pass_rate_pct=args.gate_focus_pass_rate,
        outlier_rel_threshold_pct=args.gate_outlier_rel_threshold,
        outlier_max_count=args.gate_outlier_max_count,
    )

    print(f"Raw IC95 rows exported: {args.raw_out.resolve()}")
    print(f"Grouped IC95 audit exported: {args.out.resolve()}")
    file_names = [path.name for path in files]
    name_width = max(len("file"), *(len(name) for name in file_names))
    print(f"Included result CSV files ({len(files)}):")
    print(f"   {'#':>2} | {'file':<{name_width}}")
    print(f"   {'-' * 2}-+-{'-' * name_width}")
    for index, name in enumerate(file_names, start=1):
        print(f"   {index:>2} | {name:<{name_width}}")
    print(f"Threshold (relative IC95): <= {args.threshold_rel:.2f}%")
    print(f"Summary: PASS={passed} FAIL={failed} TOTAL={total}")
    print("\nQuality gates:")
    g1 = gates["gate1"]
    print(
        "  Gate 1 - "
        f"{g1['name']}: "
        f"{'PASS' if g1['pass'] else 'FAIL'} "
        f"(fail_count={g1['fail_count']})"
    )
    g2 = gates["gate2"]
    print(
        "  Gate 2 - "
        f"{g2['name']}: "
        f"{'PASS' if g2['pass'] else 'FAIL'} "
        f"(pass_rate={g2['focus_pass_rate_pct']:.2f}%, "
        f"pass={g2['focus_pass_count']}/{g2['focus_total']})"
    )
    g3 = gates["gate3"]
    print(
        "  Gate 3 - "
        f"{g3['name']}: "
        f"{'PASS' if g3['pass'] else 'FAIL'} "
        f"(outliers={g3['outlier_count']})"
    )

    if args.enforce_gates and not bool(gates["overall_pass"]):
        print("\nQuality gate enforcement: FAIL")
        return 2

    if args.enforce_gates:
        print("\nQuality gate enforcement: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
