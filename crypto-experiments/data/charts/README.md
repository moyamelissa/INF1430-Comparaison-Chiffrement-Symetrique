# Graphiques — Organisation et génération

Ce dossier contient tous les graphiques d'analyse générés à partir des données de benchmarking des algorithmes de chiffrement, organisés par catégorie d'analyse.

## Structure des dossiers

Les graphiques sont organisés par type d'analyse pour une navigation facile :

### 01-throughput
Métriques de performance et comparaisons de débit.
- `throughput-4096B.png` — débit avec messages de 4 096 octets
- `throughput-vs-msgsize.png` — variation du débit selon la taille du message
- `comparison-throughput-all.png` — comparaison du débit de tous les chiffres
- `comparison-speedup-ratio.png` — ratios d'accélération entre chiffres
- `comparison-throughput-vs-size.png` — débit vs taille sur tous les chiffres

### 02-avalanche-effect
Analyse de l'effet d'avalanche (sensibilité à l'entrée).
- `key-avalanche.png` — avalanche lors du changement de clé de chiffrement
- `key-avalanche-detailed.png` — analyse détaillée de l'avalanche de clé
- `rounds-avalanche.png` — avalanche selon les variations de tours
- `comparison-avalanche.png` — comparaison d'avalanche entre algorithmes

### 03-encryption-modes
Comparaisons des modes de chiffrement et caractéristiques de sécurité.
- `aes-mode-comparison.png` — comparaison des modes AES (ECB, CBC, CTR, GCM)
- `encryption-vs-decryption-ecb.png` — performance chiffrement vs déchiffrement en ECB
- `aes-key-size-impact.png` — impact de la taille de clé (128, 192, 256-bit) sur AES
- `ecb-vulnerability.png` — démonstration visuelle de la faiblesse de pattern du mode ECB

### 04-ecb-visual-demo
Démonstration visuelle de la faiblesse du mode ECB via chiffrement d'image.
- `original-image.bmp` — image originale de test
- `ecb-encrypted.bmp` — image chiffrée avec ECB (affiche les patterns)
- `cbc-encrypted.bmp` — image chiffrée avec CBC (sécurisée)

### 05-algorithm-comparison
Comparaisons inter-algorithmes et analyses statistiques.
- `chacha20-comparison.png` — ChaCha20 vs autres chiffres
- `ci95-stability.png` — analyse de stabilité intervalle de confiance 95%

### 06-algorithm-profiles
Profils synthétiques de chaque algorithme (vue complète avant comparaisons croisées).
- `aes-profile.png` — AES : débit et avalanche selon modes et tailles de clé
- `des-profile.png` — DES : débit et avalanche selon modes et tailles de clé
- `3des-profile.png` — 3DES (Triple-DES) : débit et avalanche selon modes et tailles de clé
- `twofish-profile.png` — Twofish : débit et avalanche selon modes et tailles de clé
- `chacha20-profile.png` — ChaCha20 : débit et avalanche selon modes et tailles de clé

Chaque profil présente deux graphiques :
1. **Débit** (MB/s) : performance de chiffrement selon le mode et la taille de clé
2. **Effet d'avalanche** : sensibilité à la modification de clé (idéalement ≈ 0,50)

---

## Génération des graphiques

Les graphiques sont générés automatiquement à partir des fichiers CSV de benchmarking.

### Prérequis

Python 3.12+ requis. Installer les dépendances :

```powershell
py -m pip install matplotlib pycryptodome twofish
```

### Générer tous les graphiques

Depuis le dossier `crypto-experiments/` :

```powershell
cd crypto-experiments
py scripts/generate_charts.py
```

Tous les graphiques seront régénérés dans leurs dossiers de catégorie respectifs sous `data/charts/`.

### Source des données

Le script lit automatiquement le fichier CSV le plus récent de `data/results/`.

Fichier actuel :
```
data/results/laptop-windows-x86_experience1.csv
```

Lors de l'ajout d'un nouveau CSV (ex. Raspberry Pi), nommez-le alphabétiquement après les fichiers existants et relancez le script — il lira automatiquement le plus récent.

Exemple de nommage :
```
laptop-windows-x86_experience1.csv
raspberry-pi_experience2.csv
```

---

## Modification ou ajout de graphiques

Source : `scripts/generate_charts.py`

Chaque graphique est une fonction distincte :
- `fig1_throughput_4096()` → graphiques de débit
- `fig2_throughput_vs_size()` → débit vs taille
- `fig3_aes_mode_comparison()` → comparaison des modes
- `fig4_avalanche()` → effet d'avalanche
- `fig4b_key_avalanche()` → avalanche de clé détaillée
- `fig5_enc_vs_dec()` → chiffrement vs déchiffrement
- `fig6_key_size_impact()` → impact de la taille de clé
- `algo_profile(algo_name)` → génère profil synthétique pour un algorithme (AES, DES, 3DES, Twofish, ChaCha20)

Pour ajouter un graphique, créez une nouvelle fonction `figN_...()` ou `algo_profile()` et appelez-la dans le bloc `if __name__ == "__main__":`.

---

## Notes

- Tous les noms de fichiers de graphiques utilisent le kebab-case (minuscules avec traits d'union)
- Les dossiers sont numérotés pour un ordre de consultation logique
- Les graphiques sont organisés par type d'analyse, pas par séquence d'expérience
