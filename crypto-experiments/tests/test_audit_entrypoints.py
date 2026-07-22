from __future__ import annotations

from pathlib import Path
import csv
import runpy
import sys

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = PROJECT_ROOT / "scripts" / "audit"


def _write_result_csv(path: Path) -> None:
    file_path = path / "windows_experience3_20990101.csv"
    with file_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "algorithm",
                "mode",
                "key_size_bytes",
                "message_size_bytes",
                "repetitions",
                "throughput_encrypt_mbps",
                "ci95_encrypt_mbps",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "algorithm": "AES",
                "mode": "ECB",
                "key_size_bytes": "16",
                "message_size_bytes": "4096",
                "repetitions": "100",
                "throughput_encrypt_mbps": "100",
                "ci95_encrypt_mbps": "5",
            }
        )


def test_audit_aggregates_entrypoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    script = AUDIT_DIR / "audit_aggregates.py"
    out = tmp_path / "audit_aggregates_entry.csv"
    monkeypatch.setattr(sys, "argv", [str(script), "--out", str(out)])

    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(script), run_name="__main__")

    assert exc.value.code == 0
    assert out.exists()


def test_audit_diff_entrypoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    script = AUDIT_DIR / "audit_diff.py"
    out = tmp_path / "audit_diff_entry.csv"
    monkeypatch.setattr(sys, "argv", [str(script), "--out", str(out)])

    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(script), run_name="__main__")

    assert exc.value.code == 0
    assert out.exists()


def test_audit_ic95_entrypoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    script = AUDIT_DIR / "audit_ic95.py"
    results_dir = tmp_path / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    _write_result_csv(results_dir)

    out = tmp_path / "ic95_audit_report.csv"
    raw_out = tmp_path / "ic95_raw_rows.csv"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(script),
            "--results-dir",
            str(results_dir),
            "--out",
            str(out),
            "--raw-out",
            str(raw_out),
            "--enforce-gates",
        ],
    )

    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(script), run_name="__main__")

    assert exc.value.code == 0
    assert out.exists()
    assert raw_out.exists()
