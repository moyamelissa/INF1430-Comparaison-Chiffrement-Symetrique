from pathlib import Path
import importlib.util

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUN_KAT_PATH = PROJECT_ROOT / "scripts" / "run_kat.py"


def _load_run_kat_module():
    spec = importlib.util.spec_from_file_location("run_kat_module", RUN_KAT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_run_kat_main_success(monkeypatch):
    module = _load_run_kat_module()

    monkeypatch.setattr(module.kat_aes, "run", lambda verbose=True: 0)
    monkeypatch.setattr(module.kat_des, "run", lambda verbose=True: 0)
    monkeypatch.setattr(module.kat_3des, "run", lambda verbose=True: 0)
    monkeypatch.setattr(module.kat_modes, "run", lambda verbose=True: 0)
    monkeypatch.setattr(module.kat_gcm, "run", lambda verbose=True: 0)
    monkeypatch.setattr(module.kat_chacha20, "run", lambda verbose=True: 0)

    with pytest.raises(SystemExit) as exc:
        module.main()

    assert exc.value.code == 0


def test_run_kat_main_failure(monkeypatch):
    module = _load_run_kat_module()

    monkeypatch.setattr(module.kat_aes, "run", lambda verbose=True: 0)
    monkeypatch.setattr(module.kat_des, "run", lambda verbose=True: 1)
    monkeypatch.setattr(module.kat_3des, "run", lambda verbose=True: 0)
    monkeypatch.setattr(module.kat_modes, "run", lambda verbose=True: 0)
    monkeypatch.setattr(module.kat_gcm, "run", lambda verbose=True: 0)
    monkeypatch.setattr(module.kat_chacha20, "run", lambda verbose=True: 0)

    with pytest.raises(SystemExit) as exc:
        module.main()

    assert exc.value.code == 1
