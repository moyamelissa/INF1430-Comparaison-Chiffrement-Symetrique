from pathlib import Path
import importlib.util


PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_IC95_PATH = PROJECT_ROOT / "scripts" / "audit" / "audit_ic95.py"


def _load_audit_ic95_module():
    spec = importlib.util.spec_from_file_location("audit_ic95_module", AUDIT_IC95_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _row(*, msg_size: int, reps: int, threshold_pass: bool, rel_pct: float) -> dict[str, object]:
    return {
        "platform": "x86",
        "algorithm": "AES",
        "mode": "ECB",
        "key_size_bits": 128,
        "message_size_bytes": msg_size,
        "samples": 3,
        "source_files_count": 3,
        "source_files": "exp1.csv, exp2.csv, exp3.csv",
        "repetitions_min": reps,
        "repetitions_max": reps,
        "throughput_encrypt_mbps_mean": 100.0,
        "ci95_encrypt_mbps_mean": 5.0,
        "ic95_relative_pct_mean": rel_pct,
        "threshold_rel_ic95_pct": 10.0,
        "confidence_95_condition": "PASS" if reps >= 30 else "FAIL",
        "threshold_condition": "PASS" if threshold_pass else "FAIL",
        "overall_status": "PASS" if threshold_pass and reps >= 30 else "FAIL",
    }


def test_evaluate_quality_gates_passes_for_valid_dataset():
    module = _load_audit_ic95_module()
    grouped_rows = [
        _row(msg_size=1024, reps=100, threshold_pass=True, rel_pct=7.5),
        _row(msg_size=4096, reps=100, threshold_pass=True, rel_pct=5.0),
        _row(msg_size=16384, reps=120, threshold_pass=True, rel_pct=3.2),
        _row(msg_size=256, reps=100, threshold_pass=False, rel_pct=14.0),
    ]

    result = module.evaluate_quality_gates(
        grouped_rows,
        min_repetitions=100,
        focus_min_message_size=1024,
        focus_pass_rate_pct=90.0,
        outlier_rel_threshold_pct=20.0,
        outlier_max_count=1,
    )

    assert result["gate1"]["pass"] is True
    assert result["gate2"]["pass"] is True
    assert result["gate3"]["pass"] is True
    assert result["overall_pass"] is True


def test_evaluate_quality_gates_fails_when_thresholds_not_met():
    module = _load_audit_ic95_module()
    grouped_rows = [
        _row(msg_size=1024, reps=80, threshold_pass=True, rel_pct=8.0),
        _row(msg_size=4096, reps=100, threshold_pass=False, rel_pct=12.5),
        _row(msg_size=16384, reps=100, threshold_pass=False, rel_pct=25.0),
    ]

    result = module.evaluate_quality_gates(
        grouped_rows,
        min_repetitions=100,
        focus_min_message_size=1024,
        focus_pass_rate_pct=90.0,
        outlier_rel_threshold_pct=20.0,
        outlier_max_count=0,
    )

    assert result["gate1"]["pass"] is False
    assert result["gate2"]["pass"] is False
    assert result["gate3"]["pass"] is False
    assert result["overall_pass"] is False
