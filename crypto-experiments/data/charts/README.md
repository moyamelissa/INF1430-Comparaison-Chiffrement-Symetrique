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
| `debit-4096o.png` | Débit de chiffrement par algo et mode — 4096 octets | `scripts/charts/plot_performance.py` |
| `debit-vs-taille-message.png` | Débit ECB selon la taille du message (x86) | `scripts/charts/plot_performance.py` |
| `comparaison-debit-global.png` | Débit x86 vs ARM — tous algos, 4096 octets | `scripts/charts/plot_platform_comparison.py` |
| `comparaison-debit-vs-taille-message.png` | Scalabilité x86 vs ARM — débit selon taille | `scripts/charts/plot_platform_comparison.py` |
| `comparaison-ratio-acceleration.png` | Ratio x86/ARM par algorithme | `scripts/charts/plot_platform_comparison.py` |
| `chacha20-comparaison-plateformes.png` | ChaCha20 x86 vs ARM — débit selon taille | `scripts/charts/plot_platform_comparison.py` |
| `stabilite-ic95.png` | Intervalle de confiance 95% — stabilité des mesures | `scripts/charts/plot_platform_comparison.py` |

### 02-effet-avalanche

| Fichier | Description | Script source |
|---|---|---|
| `avalanche-par-algorithme.png` | Score d'avalanche moyen par algorithme | `scripts/charts/plot_performance.py` |
| `avalanche-texte-vs-cle.png` | Flip texte clair vs flip clé | `scripts/charts/plot_performance.py` |
| `comparaison-avalanche.png` | Scores d'avalanche x86 vs ARM | `scripts/charts/plot_platform_comparison.py` |
| `convergence-avalanche-par-tours.png` | Convergence de l'effet d'avalanche DES par tours | `scripts/charts/plot_avalanche_rounds.py` |

### 03-modes-chiffrement

| Fichier | Description | Script source |
|---|---|---|
| `aes-comparaison-modes.png` | AES-128 — débit par mode (ECB/CBC/CTR/GCM) | `scripts/charts/plot_performance.py` |
| `aes-securite-vs-performance.png` | AES-128 — compromis sécurité/perf selon le mode | `scripts/charts/plot_performance.py` |
| `aes-impact-taille-cle.png` | Impact de la taille de clé AES sur le débit | `scripts/charts/plot_performance.py` |
| `chiffrement-vs-dechiffrement-ecb.png` | Symétrie chiffrement / déchiffrement (ECB) | `scripts/charts/plot_performance.py` |
| `vulnerabilite-mode-ecb.png` | Démonstration visuelle — ECB vs CBC sur image | `scripts/charts/plot_ecb_demo.py` |

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
| `heatmap-synthese.png` | Scores normalisés par métrique (débit, latence, avalanche) | `scripts/charts/plot_performance.py` |
| `radar-synthese.png` | Radar multi-critères — débit, portabilité, avalanche | `scripts/charts/plot_platform_comparison.py` |

---

## Génération des graphiques

Depuis `crypto-experiments/` :

```bash
# Graphiques plateforme unique (x86)
python scripts/charts/plot_performance.py

# Comparaison x86 vs ARM (requiert les deux CSV)
python scripts/charts/plot_platform_comparison.py

# Convergence avalanche DES par tours
python scripts/charts/plot_avalanche_rounds.py

# Démonstration visuelle ECB vs CBC
python scripts/charts/plot_ecb_demo.py
```

> `scripts/charts/plot_platform_comparison.py` requiert un fichier `laptop-windows-x86_*.csv` **et** un `raspberry-pi_*.csv` dans `data/results/`.

---

## Notes

- Nommage : kebab-case français, minuscules, sans accents dans les noms de fichiers.
- Dossiers numérotés pour un ordre de lecture logique.
- Palette officielle INF1430 TN3 — fond blanc `#FFFFFF`, noir `#0A0A0A`, or `#C9A84C`.
