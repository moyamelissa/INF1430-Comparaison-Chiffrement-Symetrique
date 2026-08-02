# crypto-experiments

Paquet principal d'expériences pour la comparaison des chiffrements symétriques INF1430.

## Structure des dossiers

| Élément | Rôle |
|---|---|
| `application/` | Couche d'orchestration (contrôleur d'expériences). |
| `domain/` | Primitives de chiffrement, modes et moteur de chiffrement. |
| `validation/` | Suites de validation KAT. |
| `scripts/` | Points d'entrée exécutables et pipelines. |
| `data/` | Artefacts générés (résultats, graphiques, validation). |
| `tests/` | Tests unitaires et d'intégration. |

### Scripts principaux

| Script / Dossier | Rôle |
|---|---|
| `scripts/experiment.py` | Génère les CSV de benchmark. |
| `scripts/run_kat.py` | Exécute les vérifications cryptographiques KAT. |
| `scripts/run_charts.py` | Génère les ensembles de graphiques à partir des résultats. |
| `scripts/audit/audit_bundle.py` | Génère un dossier de preuves. |
| `scripts/audit/` | Audits IC95 et cohérence des agrégats. |
| `scripts/charts/` | Modules de génération de graphiques (`build_*`, `data_*`, style). |

### Fichiers de configuration suivis

| Fichier | Pourquoi il est versionné |
|---|---|
| `requirements.txt` | Fige les dépendances Python nécessaires pour reproduire l'environnement et les résultats. |
| `pytest.ini` | Centralise la configuration des tests et de la couverture pour des exécutions cohérentes en local et en CI. |
| `mutmut.ini` | Définit la ligne de base des tests de mutation (qualité avancée) pour la reproductibilité et la CI. |

## Démarrage rapide

Depuis la racine du dépôt :

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Depuis `crypto-experiments/` :

```powershell
python scripts/experiment.py
python scripts/run_kat.py --quiet
python scripts/audit/audit_ic95.py --enforce-gates
python scripts/run_charts.py
```

Génération ciblée par dossier :

```powershell
python scripts/run_charts.py 01
python scripts/run_charts.py 02
python scripts/run_charts.py 03
python scripts/run_charts.py 04
```

## Notes

- Les artefacts de couverture et de tests (`.coverage`, `htmlcov/`, `coverage.xml`) sont des fichiers générés.
- Les principales sorties d'évidence reproductible sont dans `data/evidence/` (`ic95_raw_rows.csv`, `ic95_audit_report.csv`, `bundle/`).
- Les graphiques du rapport sont générés directement sous la forme `graph-01` à `graph-10` dans `data/charts/`.
