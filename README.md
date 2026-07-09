# INF1430 — Comparaison expérimentale des algorithmes de chiffrement symétrique

![CI](https://img.shields.io/github/actions/workflow/status/moyamelissa/INF1430-Comparaison-Chiffrement-Symetrique/tests.yml?branch=main)
![Coverage](https://img.shields.io/badge/Couverture-100%25-2E7D32)
![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)
![Cryptographie](https://img.shields.io/badge/Cryptographie-Sym%C3%A9trique-1F7A8C)
![Plateformes](https://img.shields.io/badge/Plateformes-Windows%20x86%20%7C%20Raspberry%20Pi%20ARM-5C6BC0)
![Validation](https://img.shields.io/badge/Validation-KAT%20NIST%20int%C3%A9gr%C3%A9s-2E7D32)
![Tests KAT](https://img.shields.io/badge/Tests%20KAT-100%25%20pass%C3%A9s-2E7D32)

> Projet académique — Université TÉLUQ · INF1430

---

## Table des matières

1. [Présentation](#présentation)
2. [Objectifs techniques](#objectifs-techniques)
3. [Algorithmes et modes étudiés](#algorithmes-et-modes-étudiés)
4. [Architecture du projet](#architecture-du-projet)
5. [Structure du dépôt](#structure-du-dépôt)
6. [Plateformes testées](#plateformes-testées)
7. [Installation](#installation)
8. [Exécution rapide](#exécution-rapide)
9. [Validation et tests](#validation-et-tests)
10. [Résultats clés](#résultats-clés)
11. [Données brutes](#données-brutes)
12. [Reproductibilité](#reproductibilité)
13. [Références](#références)

---

## Présentation

Ce projet compare empiriquement plusieurs algorithmes de chiffrement symétrique selon trois axes :

- performances (temps d'exécution et débit),
- robustesse (effet d'avalanche),
- comportement multi-plateforme (x86 vs ARM).

L'approche est orientée génie logiciel : architecture modulaire, scripts d'exécution dédiés, validation cryptographique via KAT (Known Answer Tests) et export des résultats en CSV.

## Objectifs techniques

- Mesurer le coût réel des algorithmes et modes dans un contexte expérimental contrôlé.
- Comparer les résultats entre plateformes matérielles différentes.
- Valider la conformité des implémentations à l'aide de vecteurs de test standards (NIST/RFC).
- Produire des artefacts exploitables pour l'analyse : CSV et graphiques.

---

## Algorithmes et modes étudiés

### Algorithmes de chiffrement

| Algorithme | Type | Tailles de clé supportées |
|---|---|---|
| DES | Bloc | 56 bits |
| 3DES | Bloc | 112 / 168 bits |
| AES | Bloc | 128 / 192 / 256 bits |
| Twofish | Bloc | 128 / 192 / 256 bits |
| ChaCha20 | Flux | 256 bits |

### Modes d'opération

| Mode | Applicabilité | Caractéristiques |
|---|---|---|
| ECB | Chiffrement par blocs | Sans IV, utilisé ici à des fins pédagogiques (vulnérable) |
| CBC | Chiffrement par blocs | Chaînage des blocs, IV requis |
| CTR | Chiffrement par blocs | Parallélisable, nonce requis |
| GCM | Chiffrement par blocs | AEAD (confidentialité + intégrité), nonce requis |
| StreamMode | Flux (ChaCha20) | Passe-travers pour chiffrement de flux |

---

## Architecture du projet

Le système suit une architecture en couches afin de maintenir une séparation claire des responsabilités et de faciliter l'extension.

### Couches logicielles

| Couche | Composants principaux | Rôle |
|---|---|---|
| Application | `ExperimentController` | Orchestration des campagnes d'expériences et centralisation des mesures |
| Domaine | `EncryptionEngine`, `CipherPrimitive`, `OperationMode`, `StreamMode` | Abstractions cryptographiques et interface uniforme chiffrement/déchiffrement |
| Exécution | `scripts/*.py` | Lancement benchmark, validation KAT, génération de graphiques, analyses |

### Flux d'exécution (version texte)

1. Un script (`scripts/*.py`) configure et lance une campagne.
2. `ExperimentController` itère sur les combinaisons algorithme/mode/taille et les répétitions.
3. `EncryptionEngine` délègue à la primitive et au mode appropriés.
4. Les mesures sont consolidées puis exportées vers `data/results/*.csv`.
5. Les scripts d'analyse exploitent ces fichiers pour produire les graphiques dans `data/charts/`.

### Pourquoi cette architecture

- Extensibilité : ajout d'un algorithme ou d'un mode sans modifier les couches supérieures.
- Maintenabilité : responsabilités isolées par couche.
- Reproductibilité : même scripts, mêmes paramètres, mêmes formats de sortie.

---

## Structure du dépôt

```text
INF1430-Comparaison-Chiffrement-Symetrique/
├── crypto-experiments/
│   ├── requirements.txt
│   ├── application/
│   │   └── ExperimentController.py
│   ├── domain/
│   │   ├── cipher/                     # AES, DES, 3DES, Twofish, ChaCha20
│   │   ├── engine/
│   │   │   └── EncryptionEngine.py
│   │   └── mode/                       # ECB, CBC, CTR, GCM, StreamMode
│   ├── scripts/
│   │   ├── experiment.py
│   │   ├── run_kat.py
│   │   ├── charts/
│   │   │   ├── render_performance.py
│   │   │   ├── render_platform_comparison.py
│   │   │   ├── render_avalanche_rounds.py
│   │   │   └── render_ecb_demo.py
│   ├── validation/
│   │   ├── kat_aes.py
│   │   ├── kat_des.py
│   │   ├── kat_3des.py
│   │   ├── kat_chacha20.py
│   │   ├── kat_gcm.py
│   │   └── kat_modes.py
│   └── data/
       ├── results/                     # CSV bruts — x86 et Raspberry Pi
       └── charts/
           ├── 01-debit/                # Débits absolus, comparaisons plateformes, IC95
           ├── 02-effet-avalanche/      # Scores d'avalanche par algorithme
           ├── 03-modes-chiffrement/    # Impact des modes AES + demo ECB
           │   └── demo-ecb/            # BMP de la demo visuelle ECB/CBC
           └── 04-synthese/             # Heatmap et radar multi-critères
├── docs/
│   ├── 01-project-instructions/
│   ├── 02-deliverables/
│   ├── 03-analysis-and-calculations/
│   ├── 04-raspberrypi-guides/
│   ├── 05-feedback/
│   └── 99-archive/
└── README.md
```

---

## Plateformes testées

| Attribut | Laptop Windows x86 | Raspberry Pi ARM |
|---|---|---|
| Processeur | Intel Core (AES-NI activé) | ARM Cortex-A72 (pas d'AES-NI) |
| Système | Windows 11 | Raspberry Pi OS (Linux) |
| Python | 3.14 | 3.11+ |
| Bibliothèque | PyCryptodome | PyCryptodome |
| Rôle | Plateforme de référence | Plateforme embarquée |

---

## Installation

### Prérequis

- Python 3.9+
- `pip`

### Dépendances

```bash
cd crypto-experiments
pip install -r requirements.txt
```

Dépendances principales :

- `pycryptodome >= 3.20`
- `twofish >= 0.3`

---

## Exécution rapide

Toutes les commandes ci-dessous s'exécutent depuis `crypto-experiments/`.

### 1) Valider les implémentations (KAT)

```bash
python scripts/run_kat.py
```

### 2) Lancer le benchmark principal

```bash
python scripts/experiment.py
```

> Résultats exportés dans `data/results/` au format CSV.

### 3) Générer les graphiques (commande unique)

```bash
python scripts/run_charts.py
```

### 4) Génération ciblée par dossier (optionnel)

```bash
python scripts/run_charts.py 01
python scripts/run_charts.py 02
python scripts/run_charts.py 03
python scripts/run_charts.py 04
```

### 5) Comparaison multi-plateformes

> **Prérequis** : deux fichiers CSV doivent être présents dans `data/results/` — un nommé `laptop-windows-x86_*.csv` et un `raspberry-pi_*.csv`. Sans les deux, ce script quitte avec un avertissement.

```bash
python scripts/run_charts.py
```

---

## Validation et tests

Le projet inclut une suite de validation fonctionnelle basée sur des vecteurs standards (NIST / RFC).

| Suite KAT | Norme | Fichier |
|---|---|---|
| AES | FIPS 197 | `validation/kat_aes.py` |
| DES | NIST SP 800-67 | `validation/kat_des.py` |
| 3DES | NIST SP 800-67 | `validation/kat_3des.py` |
| ChaCha20 | RFC 8439 | `validation/kat_chacha20.py` |
| GCM | NIST SP 800-38D | `validation/kat_gcm.py` |
| Modes ECB/CBC/CTR | NIST SP 800-38A | `validation/kat_modes.py` |

Exécution globale :

```bash
python scripts/run_kat.py
```

> Objectif : garantir que les résultats de performance sont produits par des implémentations conformes aux standards.

Mesures à 4 096 octets, meilleure clé, ECB (sauf ChaCha20 → Stream), 100 répétitions.

| Algorithme | Débit x86 (MB/s) | Débit ARM (MB/s) | Ratio x86/ARM |
|---|---|---|---|
| AES-256 | 162,6 | 39,9 | **4,1×** |
| ChaCha20-256 | 93,9 | 58,1 | **1,6×** |
| DES-56 | 34,6 | 17,5 | 2,0× |
| 3DES-192 | 6,0 | 4,7 | 1,3× |
| Twofish-256 | 2,8 | 1,3 | 2,3× |

**Observations clés :**
- AES bénéficie massivement de l'accélération matérielle AES-NI sur x86 (ratio 4,1×).
- ChaCha20 est l'algorithme le plus portable (ratio 1,6×) — aucune dépendance matérielle.
- Twofish est l'algorithme le plus lent sur les deux plateformes.
- DES et 3DES produisent des résultats cohérents avec leur statut déprécié.

---

## Données brutes

Les CSV sont versionnés dans `crypto-experiments/data/results/` :

- `laptop-windows-x86_experience3.csv` — campagne de référence x86
- `raspberry-pi_experience3.csv` — campagne de référence ARM

> Les expériences 1 et 2 sont conservées pour traçabilité historique.

---

## Reproductibilité

Pour reproduire une campagne complète sur une nouvelle machine :

```bash
# 1. Installer les dépendances
cd crypto-experiments
pip install -r requirements.txt

# 2. Valider les implémentations
python scripts/run_kat.py

# 3. Lancer le benchmark (génère un nouveau CSV dans data/results/)
python scripts/experiment.py

# 4. Générer les graphiques
python scripts/run_charts.py
```

Pour la comparaison multi-plateformes, copier les CSV des deux machines dans `data/results/` avant d'exécuter `scripts/run_charts.py`.

**Bonnes pratiques :**
- Fermer toute application en arrière-plan pendant le benchmark.
- Conserver les CSV bruts avant toute post-analyse.
- Documenter la plateforme (modèle CPU, fréquence, OS, version Python).

---

## Références

- Paar, C., & Pelzl, J. *Understanding Cryptography: A Textbook for Students and Practitioners*. Springer, 2010.
- Stallings, W. *Cryptography and Network Security: Principles and Practice*. Pearson, 2017.
- NIST FIPS 197 — *Advanced Encryption Standard (AES)*, 2001.
- NIST SP 800-38A — *Recommendation for Block Cipher Modes of Operation*, 2001.
- NIST SP 800-38D — *Galois/Counter Mode (GCM) and GMAC*, 2007.
- NIST SP 800-67 — *Recommendation for the Triple Data Encryption Algorithm (TDEA)*, 2017.
- RFC 8439 — *ChaCha20 and Poly1305 for IETF Protocols*, 2018.
- Schneier, B. et al. *Twofish: A 128-Bit Block Cipher*, 1998.
