# scripts/charts — Documentation technique

## Objectif

Ce répertoire regroupe la chaîne complète de génération des graphiques du projet INF1430.
La structure est organisée pour séparer clairement:

- la préparation des données,
- la construction des figures,
- la génération des livrables par dossier,
- l'orchestration globale.

## Architecture

Le dossier suit une convention de nommage stricte:

- `data_*.py`: préparation et calcul des données d'entrée.
- `build_*.py`: logique de construction des graphiques réutilisables.
- `style_*.py`: style visuel partagé (palette, paramètres matplotlib, sauvegarde).
- `shared_paths.py`: chemins communs vers les entrées/sorties.
- `scripts/run_charts.py`: point d'entrée principal pour l'orchestration.

## Responsabilités par type de module

### 1) Orchestration

- `scripts/run_charts.py`

Responsabilité:
- sélectionner les dossiers à générer (`01`, `02`, `03`, `04`),
- orchestrer directement les modules `build_*.py` dans l'ordre demandé.

### 2) Préparation des données

- `data_performance.py`
- `data_platform.py`
- `data_avalanche_rounds.py`
- `data_ecb_demo.py`

Responsabilité:
- charger les sources (`data/results/`),
- normaliser les structures,
- préparer les séries nécessaires aux graphiques.

### 3) Style et utilitaires transverses

- `style_charts.py`
- `shared_paths.py`

Responsabilité:
- garantir une cohérence visuelle entre toutes les figures,
- centraliser la gestion des répertoires de sortie.

### 4) Construction réutilisable des graphiques

- `build_performance.py`
- `build_platform_comparison.py`
- `build_avalanche_rounds.py`
- `build_ecb_demo.py`

Responsabilité:
- appliquer la logique métier de tracé,
- produire les figures PNG/BMP à partir des données préparées,
- exposer des fonctions appelables par `scripts/run_charts.py` et les commandes ciblées.

## Exécution

Depuis le dossier `crypto-experiments/`:

```bash
python scripts/run_charts.py
```

Exécution ciblée:

```bash
python scripts/run_charts.py 01
python scripts/run_charts.py 02
python scripts/run_charts.py 03
python scripts/run_charts.py 04
```

## Table d'exécution par graphique

Les commandes ci-dessous permettent de générer un seul graphique à la fois.
Elles doivent être lancées depuis le dossier `crypto-experiments/`.

| Titre du graphique | Fichier généré | Commande |
|---|---|---|
| Graphique 1 - Débit de chiffrement en fonction de l'algorithme (x86 et ARM) | `01-throughput/graph-01-throughput-by-algorithm-x86-vs-arm-at-4096-bytes.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from charts import build_platform_comparison as b; b.cmp1_throughput_all()"` |
| Graphique 2 - Ratio de performance en fonction de l'algorithme (x86/ARM) | `01-throughput/graph-02-x86-over-arm-speedup-ratio-by-algorithm.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from charts import build_platform_comparison as b; b.cmp2_speedup_ratio()"` |
| Graphique 3 - ChaCha20 x86 vs ARM selon la taille | `01-throughput/graph-03-throughput-vs-message-size-chacha20-x86-vs-arm.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from charts import build_platform_comparison as b; b.cmp5_chacha20()"` |
| Graphique 4 - Stabilité des mesures (IC95) | `01-throughput/graph-04-ic95-throughput-stability-x86-vs-arm-at-4096-bytes.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from charts import build_platform_comparison as b; b.cmp6_ci95_stability()"` |
| Graphique 5 - Score d'avalanche x86 vs ARM | `02-avalanche-effect/graph-05-avalanche-score-by-algorithm-x86-vs-arm.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from charts import build_platform_comparison as b; b.cmp4_avalanche()"` |
| Graphique 6 - Avalanche texte clair vs avalanche clé | `02-avalanche-effect/graph-06-plaintext-vs-key-avalanche-x86.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from charts import build_performance as b; b.fig4b_key_avalanche()"` |
| Graphique 7 - Compromis sécurité/performance (AES, modes) | `03-encryption-modes/graph-07-aes-operation-mode-security-vs-throughput.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from charts import build_performance as b; b.fig7_ecb_vs_gcm()"` |
| Graphique 8 - Vulnérabilité visuelle du mode ECB | `03-encryption-modes/graph-08-ecb-visual-pattern-leakage-demo.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from charts import build_ecb_demo as b; b.generate_ecb_demo_chart()"` |
| Graphique 9 - Radar de synthèse multi-critères | `04-decision-support/graph-09-algorithm-profile-radar-throughput-portability-avalanche.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from charts import build_platform_comparison as b; b.cmp7_radar()"` |
| Graphique 10 - Heatmap de synthèse normalisée | `04-decision-support/graph-10-multicriteria-heatmap-by-algorithm.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from charts import build_performance as b; b.fig9_synthesis_heatmap()"` |

## Ordre de lecture recommandé

Pour comprendre rapidement le pipeline:

1. `scripts/run_charts.py`
2. `build_*.py`
3. `data_*.py`
4. `style_charts.py`

## Règles de maintenance

- Toute nouvelle figure doit être rattachée à un dossier cible dans `scripts/run_charts.py`.
- Les transformations de données doivent rester dans `data_*.py`.
- Les choix visuels globaux doivent être centralisés dans `style_charts.py`.
- Les chemins doivent passer par `shared_paths.py`.



