# crypto-experiments

Paquet d’expérimentation principal du projet de comparaison de chiffrement symétrique INF1430.

Pour le contexte général du projet, la progression SDLC et les livrables, consultez le README racine du dépôt.

Langues / Languages : [English](README.md) | Français

## Structure des dossiers

| Élément | Rôle |
|---|---|
| `application/` | Couche d’orchestration des expériences (`ExperimentController`). |
| `domain/` | Primitives cryptographiques, modes d’opération et moteur de chiffrement. |
| `validation/` | Suites de validation fonctionnelle KAT. |
| `scripts/` | Points d’entrée exécutables pour les expériences, audits et génération de graphiques. |
| `data/` | Artefacts générés : résultats bruts, graphiques et preuves d’audit. |
| `tests/` | Suites de tests unitaires et d’intégration. |

## Scripts principaux

| Script ou dossier | Rôle |
|---|---|
| `scripts/experiment.py` | Exécute les campagnes de benchmarks et écrit les résultats CSV. |
| `scripts/run_kat.py` | Exécute les validations cryptographiques KAT. |
| `scripts/run_charts.py` | Construit les jeux de graphiques à partir des CSV de résultats disponibles. |
| `scripts/audit/` | Outils d’audit IC95 et de cohérence agrégée. |
| `scripts/audit/audit_bundle.py` | Produit les bundles de preuves de reproductibilité. |
| `scripts/charts/` | Constructeurs de graphiques, chargeurs de données et utilitaires de rendu. |

## Configuration versionnée

| Fichier | Pourquoi il est suivi |
|---|---|
| `requirements.txt` | Base reproductible des dépendances Python. |
| `requirements-dev.txt` | Dépendances d’outils de développement et qualité. |
| `pytest.ini` | Configuration stable des tests locaux et CI. |
| `mutmut.ini` | Configuration de base pour les tests de mutation. |

## Démarrage rapide

Depuis la racine du dépôt :

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Depuis `crypto-experiments/` :

```powershell
python scripts/run_kat.py --quiet
python scripts/experiment.py
python scripts/audit/audit_ic95.py --enforce-gates
python scripts/run_charts.py
```

Génération ciblée de graphiques :

```powershell
python scripts/run_charts.py 01
python scripts/run_charts.py 02
python scripts/run_charts.py 03
python scripts/run_charts.py 04
```

## Sorties

- Les CSV de benchmarks bruts sont écrits dans `data/results/`.
- Les preuves de reproductibilité sont écrites dans `data/evidence/`.
- Les graphiques de rapport sont écrits dans `data/charts/`.

## Notes

- Les artefacts de couverture (`.coverage`, `coverage.xml`, `htmlcov/`) sont des fichiers générés.
- Les vecteurs runtime Twofish KAT proviennent de `../resources/KAT/Twofish-kat/`.
