# crypto-experiments

Paquet principal d'experiences pour la comparaison des chiffrements symetriques INF1430.

## Structure des dossiers

- `application/` : couche d'orchestration (controleur d'experiences)
- `domain/` : primitives de chiffrement, modes et moteur de chiffrement
- `validation/` : suites de validation KAT
- `scripts/` : points d'entree executables et pipelines
  - `experiment.py` : genere les CSV de benchmark
  - `run_kat.py` : execute les verifications cryptographiques KAT
  - `run_charts.py` : genere les ensembles de graphiques depuis les resultats
  - `validation_bundle.py` : collecte un dossier de preuves de validation
  - `audit/` : audits IC95 et coherence des agregats
  - `charts/` : modules de generation de graphiques (`build_*`, `data_*`, style)
- `data/` : artefacts generes
  - `results/` : sorties CSV brutes des experiences
  - `charts/` : images et sorties des graphiques
  - `validation/` : artefacts de validation (`audit/`, `bundle/`)
- `tests/` : tests unitaires et d'integration

## Demarrage rapide

Depuis la racine du depot :

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Depuis `crypto-experiments/` :

```powershell
python scripts/experiment.py
python scripts/run_kat.py --quiet
python scripts/audit/audit_ic95.py --enforce-gates
python scripts/run_charts.py all
```

## Notes

- Les artefacts de couverture et de tests (`.coverage`, `htmlcov/`, `coverage.xml`) sont des fichiers generes.
- Les principales sorties de validation reproductible sont dans `data/validation/`.
