from __future__ import annotations

from pathlib import Path
import csv
import importlib.util
import sys

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_IC95_PATH = PROJECT_ROOT / "scripts" / "audit" / "audit_ic95.py"


def _load_audit_ic95_module():
    spec = importlib.util.spec_from_file_location("audit_ic95_module_cli", AUDIT_IC95_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _write_result_csv(path: Path, *, platform_tag: str = "x86", throughput: float = 100.0, ci95: float = 5.0, reps: int = 100):
    # File naming mirrors production discovery conventions.
    csv_name = f"{platform_tag}_experience3_20990101.csv"
    file_path = path / csv_name
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
                "repetitions": str(reps),
                "throughput_encrypt_mbps": str(throughput),
                "ci95_encrypt_mbps": str(ci95),
            }
        )
    return file_path


def test_helpers_cover_header_variants_and_optionals(tmp_path: Path):
    module = _load_audit_ic95_module()

    assert module._to_float_optional(None) is None
    assert module._to_float_optional(1) == 1.0
    assert module._to_float_optional(" ") is None
    assert module._to_float_optional("2.5") == 2.5

    assert module._detect_platform("laptop-x86.csv") == "x86"
    assert module._detect_platform("raspberry-pi.csv") == "arm"
    assert module._detect_platform("unknown.csv") == "unknown"

    row = {"throughput_encrypt_mbps": "100"}
    assert module._get_value(row, "throughput_encrypt_mbps") == "100"

    row_quoted = {'"throughput_encrypt_mbps"': "101"}
    assert module._get_value(row_quoted, "throughput_encrypt_mbps") == "101"

    row_bom = {'\ufeff"throughput_encrypt_mbps"': "102"}
    assert module._get_value(row_bom, "throughput_encrypt_mbps") == "102"

    with pytest.raises(KeyError):
        module._get_value({}, "missing")

    _write_result_csv(tmp_path, platform_tag="laptop-windows-x86")
    _write_result_csv(tmp_path, platform_tag="raspberry-pi")
    (tmp_path / "audit_report.csv").write_text("context\n", encoding="utf-8")

    files = module._discover_result_files(tmp_path)
    names = [p.name for p in files]
    assert any("x86" in name for name in names)
    assert any("raspberry-pi" in name for name in names)
    assert all("audit" not in name.lower() for name in names)


def test_main_success_writes_outputs_and_passes_gates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    module = _load_audit_ic95_module()

    results_dir = tmp_path / "results"
    out_path = tmp_path / "audit" / "ic95_audit_report.csv"
    raw_out_path = tmp_path / "audit" / "ic95_raw_rows.csv"
    results_dir.mkdir(parents=True, exist_ok=True)

    _write_result_csv(results_dir, platform_tag="laptop-windows-x86", throughput=100.0, ci95=5.0, reps=100)
    _write_result_csv(results_dir, platform_tag="raspberry-pi", throughput=95.0, ci95=4.0, reps=100)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "audit_ic95.py",
            "--results-dir",
            str(results_dir),
            "--out",
            str(out_path),
            "--raw-out",
            str(raw_out_path),
            "--enforce-gates",
        ],
    )

    rc = module.main()
    assert rc == 0
    assert out_path.exists()
    assert raw_out_path.exists()


def test_main_returns_2_when_enforced_gates_fail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    module = _load_audit_ic95_module()

    results_dir = tmp_path / "results"
    out_path = tmp_path / "audit" / "ic95_audit_report.csv"
    raw_out_path = tmp_path / "audit" / "ic95_raw_rows.csv"
    results_dir.mkdir(parents=True, exist_ok=True)

    # Deliberately unstable ratios and low repetitions to fail gates.
    _write_result_csv(results_dir, platform_tag="laptop-windows-x86", throughput=1.0, ci95=10.0, reps=10)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "audit_ic95.py",
            "--results-dir",
            str(results_dir),
            "--out",
            str(out_path),
            "--raw-out",
            str(raw_out_path),
            "--enforce-gates",
        ],
    )

    rc = module.main()
    assert rc == 2


def test_main_success_without_enforce_gates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    module = _load_audit_ic95_module()

    results_dir = tmp_path / "results"
    out_path = tmp_path / "audit" / "ic95_audit_report.csv"
    raw_out_path = tmp_path / "audit" / "ic95_raw_rows.csv"
    results_dir.mkdir(parents=True, exist_ok=True)

    _write_result_csv(results_dir, platform_tag="laptop-windows-x86", throughput=100.0, ci95=4.0, reps=100)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "audit_ic95.py",
            "--results-dir",
            str(results_dir),
            "--out",
            str(out_path),
            "--raw-out",
            str(raw_out_path),
        ],
    )

    rc = module.main()
    assert rc == 0


def test_main_raises_when_no_result_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    module = _load_audit_ic95_module()

    results_dir = tmp_path / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(sys, "argv", ["audit_ic95.py", "--results-dir", str(results_dir)])

    with pytest.raises(SystemExit, match="No result CSV files found"):
        module.main()
