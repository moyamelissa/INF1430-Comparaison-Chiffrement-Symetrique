from __future__ import annotations

from pathlib import Path
import importlib.util
import json
import runpy
import sys

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "audit" / "audit_bundle.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("audit_bundle_module", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_run_command_writes_log(tmp_path: Path):
    module = _load_module()
    out_dir = tmp_path / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)

    result = module._run_command(
        "smoke",
        [sys.executable, "-c", "import sys; print('ok'); print('err', file=sys.stderr)"],
        tmp_path,
        out_dir,
    )

    assert result.name == "smoke"
    assert result.returncode == 0
    output_file = out_dir / result.output_file
    assert output_file.exists()
    content = output_file.read_text(encoding="utf-8")
    assert "ok" in content
    assert "--- STDERR ---" in content
    assert "err" in content


def test_copy_if_exists_true_and_false(tmp_path: Path):
    module = _load_module()
    src = tmp_path / "in.txt"
    dst = tmp_path / "out" / "copied.txt"

    assert module._copy_if_exists(src, dst) is False

    src.write_text("hello", encoding="utf-8")
    assert module._copy_if_exists(src, dst) is True
    assert dst.read_text(encoding="utf-8") == "hello"


def test_git_rev_parse_head_ok_and_fail(monkeypatch):
    module = _load_module()

    class _Proc:
        def __init__(self, returncode: int, stdout: str):
            self.returncode = returncode
            self.stdout = stdout

    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: _Proc(0, "abc123\n"))
    assert module._git_rev_parse_head(Path(".")) == "abc123"

    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: _Proc(1, ""))
    assert module._git_rev_parse_head(Path(".")) == "unknown"


def test_build_bundle_skip_run_collects_existing_artifacts(tmp_path: Path, monkeypatch):
    module = _load_module()

    project_root = tmp_path / "project"
    repo_root = tmp_path / "repo"
    bundles_dir = project_root / "data" / "evidence" / "bundle"
    project_root.mkdir(parents=True, exist_ok=True)
    repo_root.mkdir(parents=True, exist_ok=True)
    (project_root / "data" / "evidence").mkdir(parents=True, exist_ok=True)

    (project_root / "coverage.xml").write_text("cov", encoding="utf-8")
    (project_root / "data" / "evidence" / "ic95_raw_rows.csv").write_text("raw", encoding="utf-8")
    (project_root / "data" / "evidence" / "ic95_audit_report.csv").write_text("report", encoding="utf-8")

    monkeypatch.setattr(module, "PROJECT_ROOT", project_root)
    monkeypatch.setattr(module, "REPO_ROOT", repo_root)
    monkeypatch.setattr(module, "BUNDLES_DIR", bundles_dir)
    monkeypatch.setattr(module, "_git_rev_parse_head", lambda _repo: "deadbeef")

    rc = module.build_bundle(skip_run=True)
    assert rc == 0

    bundle_dirs = list(bundles_dir.glob("bundle-*"))
    assert len(bundle_dirs) == 1
    bundle_dir = bundle_dirs[0]

    manifest = json.loads((bundle_dir / "bundle_manifest.json").read_text(encoding="utf-8"))
    assert manifest["skip_run"] is True
    assert manifest["commands"] == []
    assert manifest["artifacts"]["coverage_xml"] is True
    assert manifest["artifacts"]["ic95_raw_rows"] is True
    assert manifest["artifacts"]["ic95_audit_report"] is True


def test_build_bundle_with_failed_command_returns_2(tmp_path: Path, monkeypatch):
    module = _load_module()

    project_root = tmp_path / "project"
    repo_root = tmp_path / "repo"
    bundles_dir = project_root / "data" / "evidence" / "bundle"
    project_root.mkdir(parents=True, exist_ok=True)
    repo_root.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(module, "PROJECT_ROOT", project_root)
    monkeypatch.setattr(module, "REPO_ROOT", repo_root)
    monkeypatch.setattr(module, "BUNDLES_DIR", bundles_dir)
    monkeypatch.setattr(module, "_git_rev_parse_head", lambda _repo: "deadbeef")

    results = [
        module.CommandResult("pytest", ["py"], 0, "pytest.log"),
        module.CommandResult("kat", ["py"], 1, "kat.log"),
        module.CommandResult("ic95", ["py"], 0, "ic95.log"),
    ]

    def _fake_run_command(name: str, command: list[str], cwd: Path, out_dir: Path):
        _ = (command, cwd, out_dir)
        return next(item for item in results if item.name == name)

    monkeypatch.setattr(module, "_run_command", _fake_run_command)

    rc = module.build_bundle(skip_run=False)
    assert rc == 2


def test_main_passes_skip_run_flag(monkeypatch):
    module = _load_module()

    seen: list[bool] = []
    monkeypatch.setattr(module, "build_bundle", lambda skip_run: seen.append(skip_run) or 0)
    monkeypatch.setattr(sys, "argv", ["audit_bundle.py", "--skip-run"])

    rc = module.main()
    assert rc == 0
    assert seen == [True]


def test_entrypoint_main_guard_skip_run(monkeypatch):
    monkeypatch.setattr(sys, "argv", [str(SCRIPT_PATH), "--skip-run"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(SCRIPT_PATH), run_name="__main__")

    assert exc.value.code == 0
