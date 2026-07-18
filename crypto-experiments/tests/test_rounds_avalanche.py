from pathlib import Path
import sys


ROOT_DIR = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT_DIR / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


def test_measure_rounds_series_shape_and_bounds():
    from chart_pipeline import data_avalanche_rounds as dar

    series = dar.measure_rounds_series(trials=30)

    assert len(series) == 16
    assert [item["rounds"] for item in series] == list(range(1, 17))

    for item in series:
        assert 0.0 <= item["score"] <= 1.0
        assert item["score_pct"] == item["score"] * 100.0
        assert item["delta_from_ideal_pp"] >= 0.0


def test_measure_avalanche_at_rounds_is_deterministic_with_shared_trials():
    from chart_pipeline import data_avalanche_rounds as dar

    key, trial_set = dar._build_trial_set(40)
    score_8 = dar.measure_avalanche_at_rounds(8, trials=40, key=key, trial_set=trial_set)
    score_8_repeat = dar.measure_avalanche_at_rounds(8, trials=40, key=key, trial_set=trial_set)

    assert score_8 == score_8_repeat


def test_generate_rounds_avalanche_chart_writes_file(monkeypatch, tmp_path):
    from chart_pipeline import build_avalanche_rounds as bar

    fake_series = [
        {
            "rounds": rounds,
            "score": 0.5,
            "score_pct": 50.0,
            "delta_from_ideal_pp": 0.0,
        }
        for rounds in range(1, 17)
    ]

    monkeypatch.setattr(bar, "measure_rounds_series", lambda trials: fake_series)
    monkeypatch.setattr(bar, "TRIALS", 20)
    monkeypatch.setattr(bar, "ensure_chart_dir", lambda _relative_dir: tmp_path)

    bar.generate_rounds_avalanche_chart()

    out = tmp_path / "convergence-avalanche-par-tours.png"
    assert out.exists()
    assert out.stat().st_size > 0