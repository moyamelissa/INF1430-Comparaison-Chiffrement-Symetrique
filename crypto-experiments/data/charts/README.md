# Graphiques — Organisation et génération

Tous les graphiques d'analyse générés à partir des données CSV de benchmarking, organisés par catégorie.

## Structure des dossiers

```
data/charts/
├── 01-debit/                    # Débits absolus, comparaisons plateformes et stabilité IC95
├── 02-effet-avalanche/          # Scores d'avalanche par algorithme
├── 03-modes-chiffrement/        # Impact des modes sur AES + démo ECB
│   └── demo-ecb/                # Démonstration visuelle vulnérabilité ECB (BMP)
└── 04-synthese/                 # Heatmap et radar multi-critères
```

---

### 01-debit

| Fichier | Description | Script source |
|---|---|---|
| `throughput-by-algo-mode-x86-4kb.png` | Débit de chiffrement par algo et mode — 4096 octets (x86 uniquement) | `scripts/run_charts.py 01` |
| `throughput-by-algo-mode-arm-4kb.png` | Débit de chiffrement par algo et mode — 4096 octets (Raspberry Pi uniquement) | `scripts/run_charts.py 01` |
| `throughput-vs-message-size-x86.png` | Débit ECB selon la taille du message (x86) | `scripts/run_charts.py 01` |
| `throughput-by-algo-x86-vs-arm-4kb.png` | Débit x86 vs ARM — tous algos, 4096 octets | `scripts/run_charts.py 01` |
| `throughput-vs-message-size-x86-vs-arm-ecb.png` | Scalabilité x86 vs ARM — débit selon taille (ECB forcé) | `scripts/run_charts.py 01` |
| `speedup-ratio-x86-over-arm-by-algo.png` | Ratio x86/ARM par algorithme | `scripts/run_charts.py 01` |
| `throughput-vs-message-size-chacha20-x86-vs-arm.png` | ChaCha20 x86 vs ARM — débit selon taille | `scripts/run_charts.py 01` |
| `throughput-vs-message-size-x86-vs-arm-all-algos.png` | Scalabilité x86 vs ARM — tous algorithmes (inclut ChaCha20 en Stream) | `scripts/run_charts.py 01` |
| `ci95-throughput-stability-x86-vs-arm-4kb.png` | Intervalle de confiance 95% — stabilité des mesures | `scripts/run_charts.py 01` |

### 02-effet-avalanche

| Fichier | Description | Script source |
|---|---|---|
| `avalanche-score-by-algo.png` | Score d'avalanche moyen par algorithme | `scripts/run_charts.py 02` |
| `avalanche-plaintext-vs-key.png` | Flip texte clair vs flip clé | `scripts/run_charts.py 02` |
| `avalanche-score-x86-vs-arm.png` | Scores d'avalanche x86 vs ARM | `scripts/run_charts.py 02` |
| `avalanche-convergence-des-rounds.png` | Convergence de l'effet d'avalanche DES par tours | `scripts/run_charts.py 02` |

### 03-modes-chiffrement

| Fichier | Description | Script source |
|---|---|---|
| `aes-throughput-by-mode-128bit.png` | AES-128 — débit par mode (ECB/CBC/CTR/GCM) | `scripts/run_charts.py 03` |
| `aes-security-vs-performance-by-mode.png` | AES-128 — compromis sécurité/perf selon le mode | `scripts/run_charts.py 03` |
| `aes-throughput-by-key-size.png` | Impact de la taille de clé AES sur le débit | `scripts/run_charts.py 03` |
| `throughput-encrypt-vs-decrypt-ecb.png` | Symétrie chiffrement / déchiffrement (ECB) | `scripts/run_charts.py 03` |
| `ecb-visual-pattern-leakage-demo.png` | Démonstration visuelle — ECB vs CBC sur image | `scripts/run_charts.py 03` |

### 03-modes-chiffrement/demo-ecb

Fichiers BMP utilisés pour construire `ecb-visual-pattern-leakage-demo.png`.

| Fichier | Description |
|---|---|
| `image-original.bmp` | Image synthétique de test (régions uniformes) |
| `image-encrypted-ecb.bmp` | Image chiffrée ECB (patterns visibles) |
| `image-encrypted-cbc.bmp` | Image chiffrée CBC (visuellement aléatoire) |

### 04-synthese

| Fichier | Description | Script source |
|---|---|---|
| `multicriteria-score-heatmap.png` | Scores normalisés par métrique (débit, latence, avalanche) | `scripts/run_charts.py 04` |
| `algorithm-profile-radar-chart.png` | Radar multi-critères — débit, portabilité, avalanche | `scripts/run_charts.py 04` |

---

## Génération des graphiques

Depuis `crypto-experiments/` :

```bash
# Commande principale (recommandée)
python scripts/run_charts.py

# Ou génération ciblée par dossier
python scripts/run_charts.py 01
python scripts/run_charts.py 02
python scripts/run_charts.py 03
python scripts/run_charts.py 04
```

Scripts de construction réutilisables :

```bash
scripts/chart_pipeline/build_performance.py
scripts/chart_pipeline/build_platform_comparison.py
scripts/chart_pipeline/build_avalanche_rounds.py
scripts/chart_pipeline/build_ecb_demo.py
```

> `scripts/chart_pipeline/build_platform_comparison.py` s'appuie sur un fichier `laptop-windows-x86_*.csv` **et** un `raspberry-pi_*.csv` dans `data/results/`.

---

## Notes

- Nommage : kebab-case anglais, minuscules, explicite sur la portée (x86, arm, x86-vs-arm) et la condition (4kb, ecb, all-algos).
- Dossiers numérotés pour un ordre de lecture logique.
- Palette officielle INF1430 TN3 — fond blanc `#FFFFFF`, noir `#0A0A0A`, or `#C9A84C`.

