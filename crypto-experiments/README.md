# crypto-experiments

Core experiment package for the INF1430 symmetric cryptography comparison project.

For project-level context, SDLC progression, and submission artifacts, see the root README in the repository.

## Folder Structure

| Item | Purpose |
|---|---|
| `application/` | Experiment orchestration layer (`ExperimentController`). |
| `domain/` | Cryptographic primitives, operation modes, and encryption engine. |
| `validation/` | Functional KAT validation suites. |
| `scripts/` | Executable entry points for experiments, audits, and chart generation. |
| `data/` | Generated artifacts: raw results, charts, and audit evidence. |
| `tests/` | Unit and integration test suites. |

## Main Scripts

| Script or folder | Purpose |
|---|---|
| `scripts/experiment.py` | Runs benchmark campaigns and writes CSV results. |
| `scripts/run_kat.py` | Runs cryptographic KAT validation checks. |
| `scripts/run_charts.py` | Builds chart sets from available result CSV files. |
| `scripts/audit/` | IC95 and aggregate consistency audit tooling. |
| `scripts/audit/audit_bundle.py` | Produces reproducibility evidence bundles. |
| `scripts/charts/` | Chart builders, data loaders, and rendering helpers. |

## Versioned Configuration

| File | Why it is tracked |
|---|---|
| `requirements.txt` | Reproducible Python dependency baseline. |
| `requirements-dev.txt` | Development and quality tooling dependencies. |
| `pytest.ini` | Stable local and CI test configuration. |
| `mutmut.ini` | Mutation testing baseline configuration. |

## Quick Start

From repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

From `crypto-experiments/`:

```powershell
python scripts/run_kat.py --quiet
python scripts/experiment.py
python scripts/audit/audit_ic95.py --enforce-gates
python scripts/run_charts.py
```

Targeted chart generation:

```powershell
python scripts/run_charts.py 01
python scripts/run_charts.py 02
python scripts/run_charts.py 03
python scripts/run_charts.py 04
```

## Outputs

- Raw benchmark CSV files are written to `data/results/`.
- Reproducibility evidence is written to `data/evidence/`.
- Report charts are written to `data/charts/`.

## Notes

- Coverage artifacts (`.coverage`, `coverage.xml`, `htmlcov/`) are generated files.
- Twofish KAT runtime vectors are sourced from `../resources/KAT/Twofish-kat/`.
