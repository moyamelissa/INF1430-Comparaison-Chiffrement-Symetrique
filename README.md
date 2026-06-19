# INF1430 — Comparaison expérimentale des algorithmes de chiffrement symétrique

![INF1430](https://img.shields.io/badge/Cours-INF1430-0A66C2)
![Université TÉLUQ](https://img.shields.io/badge/Université-T%C3%89LUQ-005A9C)
![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)
![Cryptographie](https://img.shields.io/badge/Cryptographie-Sym%C3%A9trique-1F7A8C)
![Plateformes](https://img.shields.io/badge/Plateformes-Windows%20x86%20%7C%20Raspberry%20Pi%20ARM-5C6BC0)
![Validation](https://img.shields.io/badge/Validation-KAT%20NIST%20int%C3%A9gr%C3%A9s-2E7D32)

> Projet académique — Université TÉLUQ · INF1430

---

## Table des matières

1. [Présentation](#présentation)
2. [Objectifs techniques](#objectifs-techniques)
3. [Algorithmes et modes étudiés](#algorithmes-et-modes-étudiés)
4. [Architecture du projet](#architecture-du-projet)
5. [Structure du dépôt](#structure-du-dépôt)
6. [Installation](#installation)
7. [Exécution rapide](#exécution-rapide)
8. [Validation et tests](#validation-et-tests)
9. [Résultats expérimentaux](#résultats-expérimentaux)
10. [Reproductibilité](#reproductibilité)
11. [Références](#références)

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
│   │   ├── generate_charts.py
│   │   ├── analyse_rounds_avalanche.py
│   │   ├── compare_platforms.py
│   │   └── ecb_visual_vulnerability.py
│   ├── validation/
│   │   ├── kat_aes.py
│   │   ├── kat_des.py
│   │   ├── kat_3des.py
│   │   ├── kat_chacha20.py
│   │   ├── kat_gcm.py
│   │   └── kat_modes.py
│   └── data/
│       ├── results/
│       └── charts/
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

### 1) Lancer le benchmark principal

```bash
python scripts/experiment.py
```

### 2) Valider les implémentations (KAT)

```bash
python scripts/run_kat.py
```

### 3) Générer les graphiques

```bash
python scripts/generate_charts.py
```

### 4) Analyses complémentaires

```bash
python scripts/analyse_rounds_avalanche.py
python scripts/ecb_visual_vulnerability.py
python scripts/compare_platforms.py
```

---

## Validation et tests

Le projet inclut une suite de validation fonctionnelle basée sur des vecteurs standards.

### Validation KAT disponible

- AES : `validation/kat_aes.py`
- DES : `validation/kat_des.py`
- 3DES : `validation/kat_3des.py`
- ChaCha20 : `validation/kat_chacha20.py`
- GCM : `validation/kat_gcm.py`
- Modes (ECB/CBC/CTR) : `validation/kat_modes.py`

Exécution globale :

```bash
python scripts/run_kat.py
```

Objectif : garantir que les résultats de performance sont produits par des implémentations conformes.

---

## Résultats expérimentaux

Les données brutes sont stockées dans `crypto-experiments/data/results/`.

Jeux de résultats actuellement versionnés :

- `laptop-windows-x86_experience1.csv`
- `laptop-windows-x86_experience2.csv`
- `laptop-windows-x86_experience3.csv`
- `raspberry-pi_experience1.csv`
- `raspberry-pi_experience2.csv`
- `raspberry-pi_experience3.csv`

Les graphiques sont générés dans `crypto-experiments/data/charts/` (incluant `data/charts/comparison/`).

---

## Reproductibilité

Pour reproduire une campagne complète :

1. Installer les dépendances.
2. Exécuter `scripts/run_kat.py`.
3. Exécuter `scripts/experiment.py`.
4. Générer les figures avec `scripts/generate_charts.py`.

Bonnes pratiques recommandées :

- conserver le même environnement Python entre exécutions,
- documenter la plateforme (CPU/OS),
- conserver les CSV bruts avant toute post-analyse.

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
