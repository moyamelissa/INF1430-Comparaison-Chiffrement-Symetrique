# scripts/chart_pipeline — Documentation technique

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
| Débit de chiffrement en fonction de l'algorithme et du mode | `01-debit/debit-4096o.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from chart_pipeline import build_performance as b; b.fig1_throughput_4096()"` |
| Débit de chiffrement en fonction de la taille du message | `01-debit/debit-vs-taille-message.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from chart_pipeline import build_performance as b; b.fig2_throughput_vs_size()"` |
| Débit de chiffrement en fonction de l'algorithme (x86 et ARM) | `01-debit/comparaison-debit-global.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from chart_pipeline import build_platform_comparison as b; b.cmp1_throughput_all()"` |
| Ratio de performance en fonction de l'algorithme (x86/ARM) | `01-debit/comparaison-ratio-acceleration.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from chart_pipeline import build_platform_comparison as b; b.cmp2_speedup_ratio()"` |
| Débit selon la taille du message (x86 vs ARM) | `01-debit/comparaison-debit-vs-taille-message.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from chart_pipeline import build_platform_comparison as b; b.cmp3_throughput_vs_size()"` |
| ChaCha20 x86 vs ARM selon la taille | `01-debit/chacha20-comparaison-plateformes.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from chart_pipeline import build_platform_comparison as b; b.cmp5_chacha20()"` |
| Stabilité des mesures (IC95) | `01-debit/stabilite-ic95.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from chart_pipeline import build_platform_comparison as b; b.cmp6_ci95_stability()"` |
| Scalabilité globale de tous les algorithmes | `01-debit/scalabilite-tous-algorithmes.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from chart_pipeline import build_platform_comparison as b; b.cmp8_scalability_all_algos()"` |
| Score d'avalanche en fonction de l'algorithme | `02-effet-avalanche/avalanche-par-algorithme.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from chart_pipeline import build_performance as b; b.fig4_avalanche()"` |
| Avalanche texte clair vs avalanche clé | `02-effet-avalanche/avalanche-texte-vs-cle.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from chart_pipeline import build_performance as b; b.fig4b_key_avalanche()"` |
| Score d'avalanche x86 vs ARM | `02-effet-avalanche/comparaison-avalanche.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from chart_pipeline import build_platform_comparison as b; b.cmp4_avalanche()"` |
| Score d'avalanche selon le nombre de tours DES | `02-effet-avalanche/convergence-avalanche-par-tours.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from chart_pipeline import build_avalanche_rounds as b; b.generate_rounds_avalanche_chart()"` |
| AES-128: comparaison des modes de chiffrement | `03-modes-chiffrement/aes-comparaison-modes.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from chart_pipeline import build_performance as b; b.fig3_aes_mode_comparison()"` |
| Chiffrement vs déchiffrement (ECB) | `03-modes-chiffrement/chiffrement-vs-dechiffrement-ecb.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from chart_pipeline import build_performance as b; b.fig5_enc_vs_dec()"` |
| Impact de la taille de clé AES sur le débit | `03-modes-chiffrement/aes-impact-taille-cle.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from chart_pipeline import build_performance as b; b.fig6_key_size_impact()"` |
| Compromis sécurité/performance (ECB vs GCM) | `03-modes-chiffrement/aes-securite-vs-performance.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from chart_pipeline import build_performance as b; b.fig7_ecb_vs_gcm()"` |
| Vulnérabilité visuelle du mode ECB | `03-modes-chiffrement/vulnerabilite-mode-ecb.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from chart_pipeline import build_ecb_demo as b; b.generate_ecb_demo_chart()"` |
| Heatmap de synthèse normalisée | `04-synthese/heatmap-synthese.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from chart_pipeline import build_performance as b; b.fig9_synthesis_heatmap()"` |
| Radar de synthèse multi-critères | `04-synthese/radar-synthese.png` | `python -c "import sys; sys.path.insert(0, 'scripts'); from chart_pipeline import build_platform_comparison as b; b.cmp7_radar()"` |

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

