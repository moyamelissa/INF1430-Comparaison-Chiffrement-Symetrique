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
| `debit-4096o.png` | Débit de chiffrement par algo et mode — 4096 octets | `scripts/run_charts.py 01` |
| `debit-vs-taille-message.png` | Débit ECB selon la taille du message (x86) | `scripts/run_charts.py 01` |
| `comparaison-debit-global.png` | Débit x86 vs ARM — tous algos, 4096 octets | `scripts/run_charts.py 01` |
| `comparaison-debit-vs-taille-message.png` | Scalabilité x86 vs ARM — débit selon taille | `scripts/run_charts.py 01` |
| `comparaison-ratio-acceleration.png` | Ratio x86/ARM par algorithme | `scripts/run_charts.py 01` |
| `chacha20-comparaison-plateformes.png` | ChaCha20 x86 vs ARM — débit selon taille | `scripts/run_charts.py 01` |
| `stabilite-ic95.png` | Intervalle de confiance 95% — stabilité des mesures | `scripts/run_charts.py 01` |

### 02-effet-avalanche

| Fichier | Description | Script source |
|---|---|---|
| `avalanche-par-algorithme.png` | Score d'avalanche moyen par algorithme | `scripts/run_charts.py 02` |
| `avalanche-texte-vs-cle.png` | Flip texte clair vs flip clé | `scripts/run_charts.py 02` |
| `comparaison-avalanche.png` | Scores d'avalanche x86 vs ARM | `scripts/run_charts.py 02` |
| `convergence-avalanche-par-tours.png` | Convergence de l'effet d'avalanche DES par tours | `scripts/run_charts.py 02` |

### 03-modes-chiffrement

| Fichier | Description | Script source |
|---|---|---|
| `aes-comparaison-modes.png` | AES-128 — débit par mode (ECB/CBC/CTR/GCM) | `scripts/run_charts.py 03` |
| `aes-securite-vs-performance.png` | AES-128 — compromis sécurité/perf selon le mode | `scripts/run_charts.py 03` |
| `aes-impact-taille-cle.png` | Impact de la taille de clé AES sur le débit | `scripts/run_charts.py 03` |
| `chiffrement-vs-dechiffrement-ecb.png` | Symétrie chiffrement / déchiffrement (ECB) | `scripts/run_charts.py 03` |
| `vulnerabilite-mode-ecb.png` | Démonstration visuelle — ECB vs CBC sur image | `scripts/run_charts.py 03` |

### 03-modes-chiffrement/demo-ecb

Fichiers BMP utilisés pour construire `vulnerabilite-mode-ecb.png`.

| Fichier | Description |
|---|---|
| `image-originale.bmp` | Image synthétique de test (régions uniformes) |
| `image-chiffree-ecb.bmp` | Image chiffrée ECB (patterns visibles) |
| `image-chiffree-cbc.bmp` | Image chiffrée CBC (visuellement aléatoire) |

### 04-synthese

| Fichier | Description | Script source |
|---|---|---|
| `multicriteria-heatmap.png` | Scores normalisés par métrique (débit, latence, avalanche) | `scripts/run_charts.py 04` |
| `algorithm-profile-radar.png` | Radar multi-critères — débit, portabilité, avalanche | `scripts/run_charts.py 04` |

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

- Nommage : kebab-case français, minuscules, sans accents dans les noms de fichiers.
- Dossiers numérotés pour un ordre de lecture logique.
- Palette officielle INF1430 TN3 — fond blanc `#FFFFFF`, noir `#0A0A0A`, or `#C9A84C`.

