# crypto-experiments

Paquet principal d'experiences pour la comparaison des chiffrements symetriques INF1430.

## Structure des dossiers

| Element | Role |
|---|---|
| `application/` | Couche d'orchestration (controleur d'experiences). |
| `domain/` | Primitives de chiffrement, modes et moteur de chiffrement. |
| `validation/` | Suites de validation KAT. |
| `scripts/` | Points d'entree executables et pipelines. |
| `data/` | Artefacts generes (resultats, graphiques, validation). |
| `tests/` | Tests unitaires et d'integration. |

### Scripts principaux

| Script / Dossier | Role |
|---|---|
| `scripts/experiment.py` | Genere les CSV de benchmark. |
| `scripts/run_kat.py` | Execute les verifications cryptographiques KAT. |
| `scripts/run_charts.py` | Genere les ensembles de graphiques depuis les resultats. |
| `scripts/validation_bundle.py` | Genere un dossier de preuves de validation. |
| `scripts/audit/` | Audits IC95 et coherence des agregats. |
| `scripts/charts/` | Modules de generation de graphiques (`build_*`, `data_*`, style). |

### Fichiers de configuration suivis

| Fichier | Pourquoi il est versionne |
|---|---|
| `requirements.txt` | Fige les dependances Python necessaires pour reproduire l'environnement et les resultats. |
| `pytest.ini` | Centralise la configuration de tests et de couverture pour des executions coherentes en local et CI. |
| `mutmut.ini` | Definit la ligne de base des tests de mutation (qualite avancee) pour reproductibilite et CI. |

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
