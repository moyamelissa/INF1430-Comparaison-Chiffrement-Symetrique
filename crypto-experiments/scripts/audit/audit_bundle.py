"""Build a reproducible TN4 validation evidence bundle.

Usage from repository root:
    py crypto-experiments/scripts/audit/audit_bundle.py

Usage from crypto-experiments:
    py scripts/audit/audit_bundle.py

The script runs validation commands, captures outputs, and copies key artifacts
into a timestamped bundle directory under data/evidence/bundle.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = PROJECT_ROOT.parent
_DEFAULT_BUNDLES_DIR = PROJECT_ROOT / "data" / "evidence" / "bundle"
BUNDLES_DIR = Path(os.environ.get("AUDIT_BUNDLE_DIR", str(_DEFAULT_BUNDLES_DIR)))


@dataclass
class CommandResult:
    name: str
    command: list[str]
    returncode: int
    output_file: str


def _run_command(name: str, command: list[str], cwd: Path, out_dir: Path) -> CommandResult:
    proc = subprocess.run(
        command,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    output_name = f"{name}.log"
    output_path = out_dir / output_name
    output_path.write_text(proc.stdout + "\n\n--- STDERR ---\n\n" + proc.stderr, encoding="utf-8")
    return CommandResult(
        name=name,
        command=command,
        returncode=proc.returncode,
        output_file=output_name,
    )


def _copy_if_exists(src: Path, dst: Path) -> bool:
    if not src.exists():
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return True


def _git_rev_parse_head(repo_root: Path) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        return "unknown"
    return proc.stdout.strip()


def build_bundle(skip_run: bool) -> int:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    bundle_dir = BUNDLES_DIR / f"bundle-{timestamp}"
    logs_dir = bundle_dir / "logs"
    artifacts_dir = bundle_dir / "artifacts"

    logs_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    command_results: list[CommandResult] = []

    if not skip_run:
        command_results.append(
            _run_command(
                "pytest",
                [sys.executable, "-m", "pytest", "-q"],
                PROJECT_ROOT,
                logs_dir,
            )
        )
        command_results.append(
            _run_command(
                "kat",
                [
                    sys.executable,
                    "scripts/run_kat.py",
                    "--twofish-profile",
                    "full",
                    "--twofish-checksum",
                    "warn",
                    "--quiet",
                ],
                PROJECT_ROOT,
                logs_dir,
            )
        )
        command_results.append(
            _run_command(
                "ic95",
                [sys.executable, "scripts/audit/audit_ic95.py", "--enforce-gates"],
                PROJECT_ROOT,
                logs_dir,
            )
        )

    copied_artifacts: dict[str, bool] = {
        "coverage_xml": _copy_if_exists(PROJECT_ROOT / "coverage.xml", artifacts_dir / "coverage.xml"),
        "ic95_raw_rows": _copy_if_exists(
            PROJECT_ROOT / "data" / "evidence" / "ic95_raw_rows.csv",
            artifacts_dir / "ic95_raw_rows.csv",
        ),
        "ic95_audit_report": _copy_if_exists(
            PROJECT_ROOT / "data" / "evidence" / "ic95_audit_report.csv",
            artifacts_dir / "ic95_audit_report.csv",
        ),
    }

    metadata = {
        "created_utc": timestamp,
        "repo_root": str(REPO_ROOT),
        "project_root": str(PROJECT_ROOT),
        "commit": _git_rev_parse_head(REPO_ROOT),
        "skip_run": skip_run,
        "commands": [
            {
                "name": result.name,
                "command": result.command,
                "returncode": result.returncode,
                "output_file": result.output_file,
            }
            for result in command_results
        ],
        "artifacts": copied_artifacts,
    }

    (bundle_dir / "bundle_manifest.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=True),
        encoding="utf-8",
    )

    print(f"Validation bundle created: {bundle_dir}")
    if command_results:
        for result in command_results:
            print(f"- {result.name}: returncode={result.returncode}, log={result.output_file}")
    else:
        print("- Commands skipped (--skip-run).")

    failed = [r for r in command_results if r.returncode != 0]
    if failed:
        print("One or more validation commands failed. See logs in bundle.")
        return 2
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Build TN4 validation evidence bundle")
    parser.add_argument(
        "--skip-run",
        action="store_true",
        help="Only collect existing artifacts without executing pytest/KAT/IC95",
    )
    args = parser.parse_args()
    return build_bundle(skip_run=args.skip_run)


if __name__ == "__main__":
    raise SystemExit(main())
