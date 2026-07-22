from __future__ import annotations

from pathlib import Path
import csv
import importlib.util
import sys

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "audit" / "audit_diff.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("audit_diff_module", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _write_raw_csv(path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "algorithm",
                "mode",
                "key_size_bytes",
                "message_size_bytes",
                "throughput_encrypt_mbps",
                "throughput_decrypt_mbps",
                "avalanche_score",
                "key_avalanche_score",
                "avg_encrypt_time_s",
                "avg_decrypt_time_s",
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
                "throughput_encrypt_mbps": "100",
                "throughput_decrypt_mbps": "80",
                "avalanche_score": "0.5",
                "key_avalanche_score": "0.5",
                "avg_encrypt_time_s": "0.01",
                "avg_decrypt_time_s": "0.02",
                "ci95_encrypt_mbps": "5",
            }
        )


def test_helpers_and_stat_functions_cover_branches():
    module = _load_module()

    assert module._row_value({"a": "1"}, "a") == "1"
    assert module._row_value({'"a"': "2"}, "a") == "2"
    assert module._row_value({'\ufeff"a"': "3"}, "a") == "3"
    with pytest.raises(KeyError):
        module._row_value({}, "a")

    assert module._to_float_optional("1.5") == 1.5
    assert module._to_float_optional(" ") is None
    assert module._to_float_optional("{}") is None
    assert module._to_float_optional("abc") is None

    assert module._row_value_optional({"x": "y"}, "x") == "y"
    assert module._row_value_optional({}, "x") is None

    key = module._group_key_from_raw(
        {
            "algorithm": "AES",
            "mode": "ECB",
            "key_size_bytes": "16",
            "message_size_bytes": "4096",
        }
    )
    assert key == ("AES", "ECB", 128, 4096)

    stats = module._compute_raw_stats(
        [
            {
                "algorithm": "AES",
                "mode": "ECB",
                "key_size_bytes": "16",
                "message_size_bytes": "4096",
                "a": "2",
            },
            {
                "algorithm": "AES",
                "mode": "ECB",
                "key_size_bytes": "16",
                "message_size_bytes": "4096",
                "a": "4",
            },
            {
                "algorithm": "AES",
                "mode": "ECB",
                "key_size_bytes": "16",
                "message_size_bytes": "4096",
                "a": "{}",
            },
        ],
        {"metric_a": "a", "missing_metric": "z"},
    )
    assert stats[(("AES", "ECB", 128, 4096), "metric_a")] == (2, 3.0)

    assert module._abs_diff(3.0, 5.0) == 2.0
    assert module._abs_diff(None, 5.0) is None
    assert module._rel_diff_pct(4.0, 1.0) == 25.0
    assert module._rel_diff_pct(0.0, 1.0) is None


def test_load_append_build_export_and_main(tmp_path: Path, monkeypatch):
    module = _load_module()

    perf_csv = tmp_path / "laptop-windows-x86_experience3_20990101.csv"
    x86_csv = tmp_path / "laptop-windows-x86_experience2_20990101.csv"
    pi_csv = tmp_path / "raspberry-pi_experience3_20990101.csv"

    _write_raw_csv(perf_csv)
    _write_raw_csv(x86_csv)
    _write_raw_csv(pi_csv)

    loaded_rows = module._load_raw_csv_rows([perf_csv])
    assert len(loaded_rows) == 1

    perf_agg_rows = [
        {
            "algorithm": "AES",
            "mode": "ECB",
            "key_size_bits": 128,
            "message_size_bytes": 4096,
            "throughput_enc_mbps": 100.0,
            "throughput_dec_mbps": 80.0,
            "avalanche_score": 0.5,
            "key_avalanche_score": 0.5,
            "avg_encrypt_time_s": 0.01,
            "avg_decrypt_time_s": 0.02,
            "non_numeric": "n/a",
        }
    ]
    platform_agg_rows = [
        {
            "algorithm": "AES",
            "mode": "ECB",
            "key_size_bits": 128,
            "message_size_bytes": 4096,
            "throughput_enc": 100.0,
            "throughput_dec": 80.0,
            "avalanche": 0.5,
            "key_avalanche": 0.5,
            "ci95_enc": 5.0,
        }
    ]

    module.load_latest_rows = lambda: ([perf_csv], perf_agg_rows)
    module.load_platform_rows = lambda: ([x86_csv], [pi_csv], platform_agg_rows, platform_agg_rows)

    rows = module._build_report_rows()
    assert rows

    out_rows: list[dict[str, object]] = []
    module._append_context_rows(
        out_rows,
        context="test",
        platform="x86",
        aggregated_rows=[
            {
                "algorithm": "AES",
                "mode": "ECB",
                "key_size_bits": 128,
                "message_size_bytes": 4096,
                "non_numeric": "n/a",
            }
        ],
        metric_names=["non_numeric"],
        raw_stats={},
        source_csvs="raw.csv",
    )
    assert out_rows[0]["aggregated_value"] == ""

    out = tmp_path / "audit" / "audit_diff_report.csv"
    resolved, row_count, max_abs, max_rel, non_zero = module.export_report(out)
    assert resolved == out.resolve()
    assert row_count > 0
    assert max_abs >= 0
    assert max_rel >= 0
    assert non_zero >= 0

    monkeypatch.setattr(sys, "argv", ["audit_diff.py", "--out", str(tmp_path / "audit" / "audit_diff_main.csv")])
    rc = module.main()
    assert rc == 0
