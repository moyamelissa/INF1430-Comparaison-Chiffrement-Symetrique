from __future__ import annotations

from pathlib import Path
import csv
import importlib.util
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "audit" / "audit_aggregates.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("audit_aggregates_module", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _fake_inputs(tmp_path: Path):
    perf_path = tmp_path / "windows_experience3_20990101.csv"
    x86_path = tmp_path / "windows_experience2_20990101.csv"
    pi_path = tmp_path / "raspberry_experience3_20990101.csv"

    perf_path.write_text("x\n", encoding="utf-8")
    x86_path.write_text("x\n", encoding="utf-8")
    pi_path.write_text("x\n", encoding="utf-8")

    perf_rows = [
        {
            "algorithm": "AES",
            "mode": "ECB",
            "key_size_bits": 128,
            "message_size_bytes": 4096,
            "throughput_enc_mbps": 100.0,
            "throughput_dec_mbps": 90.0,
            "avalanche_score": 0.5,
            "key_avalanche_score": 0.5,
        }
    ]
    cmp_x86_rows = [
        {
            "algorithm": "AES",
            "mode": "ECB",
            "key_size_bits": 128,
            "message_size_bytes": 4096,
            "throughput_enc": 110.0,
            "throughput_dec": 95.0,
            "avalanche": 0.5,
            "key_avalanche": 0.5,
            "ci95_enc": 2.0,
        }
    ]
    cmp_pi_rows = [
        {
            "algorithm": "AES",
            "mode": "ECB",
            "key_size_bits": 128,
            "message_size_bytes": 4096,
            "throughput_enc": 60.0,
            "throughput_dec": 55.0,
            "avalanche": 0.5,
            "key_avalanche": 0.5,
            "ci95_enc": 1.2,
        }
    ]

    return (
        [perf_path],
        perf_rows,
        [x86_path],
        [pi_path],
        cmp_x86_rows,
        cmp_pi_rows,
    )


def test_report_rows_and_export(tmp_path: Path):
    module = _load_module()
    perf_paths, perf_rows, x86_paths, pi_paths, x86_rows, pi_rows = _fake_inputs(tmp_path)

    module.load_latest_rows = lambda: (perf_paths, perf_rows)
    module.load_platform_rows = lambda: (x86_paths, pi_paths, x86_rows, pi_rows)

    rows = module._report_rows()
    assert len(rows) == 3
    assert {r["context"] for r in rows} == {"performance", "platform_comparison"}

    out = tmp_path / "audit" / "audit_aggregates_report.csv"
    exported = module.export_report(out)
    assert exported == out
    assert out.exists()

    with out.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        written = list(reader)
    assert len(written) == 3


def test_main_writes_file(tmp_path: Path, monkeypatch):
    module = _load_module()
    perf_paths, perf_rows, x86_paths, pi_paths, x86_rows, pi_rows = _fake_inputs(tmp_path)

    module.load_latest_rows = lambda: (perf_paths, perf_rows)
    module.load_platform_rows = lambda: (x86_paths, pi_paths, x86_rows, pi_rows)

    out = tmp_path / "audit" / "custom.csv"
    monkeypatch.setattr(sys, "argv", ["audit_aggregates.py", "--out", str(out)])

    rc = module.main()
    assert rc == 0
    assert out.exists()
