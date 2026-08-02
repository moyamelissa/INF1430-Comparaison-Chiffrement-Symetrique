# INF1430 — Comparaison expérimentale des algorithmes de chiffrement symétrique

![CI](https://img.shields.io/github/actions/workflow/status/moyamelissa/INF1430-Comparaison-Chiffrement-Symetrique/tests.yml?branch=main)
![Coverage](https://img.shields.io/badge/Couverture-100%25-2E7D32)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![Cryptographie](https://img.shields.io/badge/Cryptographie-Sym%C3%A9trique-1F7A8C)
![Plateformes](https://img.shields.io/badge/Plateformes-Windows%20x86%20%7C%20Raspberry%20Pi%20ARM-5C6BC0)
![Validation](https://img.shields.io/badge/Validation-KAT%20NIST%20int%C3%A9gr%C3%A9s-2E7D32)
![Tests KAT](https://img.shields.io/badge/Tests%20KAT-100%25%20pass%C3%A9s-2E7D32)
![Audit IC95](https://img.shields.io/badge/Audit%20IC95-Gates%20CI%20actifs-2E7D32)
![Dependabot](https://img.shields.io/badge/Dependabot-activ%C3%A9-0366d6?logo=dependabot&logoColor=white)

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
10. [Audit IC95 en CI](#audit-ic95-en-ci)
11. [Approche SSDLC et DevSecOps](#approche-ssdlc-et-devsecops)
12. [Résultats clés](#résultats-clés)
13. [Données brutes](#données-brutes)
14. [Reproductibilité](#reproductibilité)
15. [Références](#références)

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
│   │   │   ├── build_performance.py
│   │   │   ├── build_platform_comparison.py
│   │   │   ├── build_ecb_demo.py
│   │   │   └── ...
│   │   └── audit/
│   │       ├── audit_ic95.py
│   │       ├── audit_aggregates.py
│   │       ├── audit_diff.py
│   │       └── audit_bundle.py
│   ├── validation/
│   │   ├── kat_aes.py
│   │   ├── kat_des.py
│   │   ├── kat_3des.py
│   │   ├── kat_chacha20.py
│   │   ├── kat_gcm.py
│   │   ├── kat_modes.py
│   │   └── kat_twofish.py
│   └── data/
│       ├── results/                  # CSV bruts - x86 et Raspberry Pi
│       ├── evidence/                 # Rapports d'audit IC95, bundles et preuves
│       ├── charts/
│       │   ├── 01-throughput/        # Graphiques 01 a 04
│       │   ├── 02-avalanche-effect/  # Graphiques 05 et 06
│       │   ├── 03-encryption-modes/  # Graphiques 07 et 08
│       │   │   └── demo-ecb/         # BMP de la demo visuelle ECB/CBC
│       │   └── 04-decision-support/  # Graphiques 09 et 10
│       └── logs/
├── docs/
│   ├── 01-project-instructions/
│   ├── 02-deliverables/
│   ├── 03-feedback/
│   ├── 04-raspberrypi-guides/
│   ├── 05-KAT/
│   ├── 06-demo/
│   └── 07-analysis-and-calculations/
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

- Python 3.11+
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

### 5) Prérequis comparaison multi-plateformes

> Deux fichiers CSV doivent être présents dans `data/results/` : un `windows_*.csv` et un `raspberry_*.csv`.

---

## Validation et tests

Le projet inclut une suite de validation fonctionnelle basée sur des vecteurs standards (NIST / RFC).

| Suite KAT | Norme | Fichier |
|---|---|---|
| AES | FIPS 197 | `validation/kat_aes.py` |
| DES | FIPS 46-3 + NIST SP 800-17 | `validation/kat_des.py` |
| 3DES | NIST SP 800-67 | `validation/kat_3des.py` |
| ChaCha20 | RFC 8439 | `validation/kat_chacha20.py` |
| GCM | NIST SP 800-38D | `validation/kat_gcm.py` |
| Modes ECB/CBC/CTR | NIST SP 800-38A | `validation/kat_modes.py` |
| Twofish (ECB KAT) | Schneier / Counterpane | `validation/kat_twofish.py` |

Exécution globale :

```bash
python scripts/run_kat.py
```

> Objectif : garantir que les résultats de performance sont produits par des implémentations conformes aux standards.

## Audit IC95 en CI

Le workflow CI inclut un contrôle statistique automatique des intervalles de confiance (IC95), exécuté dans un job dédié (`ic95-audit`) du pipeline.

Commande utilisée :

```bash
python scripts/audit/audit_ic95.py --enforce-gates
```

Le job échoue si les seuils de qualité ne sont pas respectés et publie deux artefacts CSV :

- `crypto-experiments/data/evidence/ic95_raw_rows.csv`
- `crypto-experiments/data/evidence/ic95_audit_report.csv`

Les vecteurs Twofish (`ECB_VK.TXT`, `ECB_VT.TXT`, `ECB_TBL.TXT`) sont aussi protégés par des sidecars `.sha256` pour vérifier l'intégrité des données de test avant l'exécution KAT.

Mesures à 4 096 octets, meilleure clé, ECB (sauf ChaCha20 -> Stream), moyennes sur les campagnes CSV disponibles par plateforme.

## Approche SSDLC et DevSecOps

Le projet applique une approche SSDLC (Secure Software Development Life Cycle) adaptée à un contexte académique orienté expérimentation cryptographique. L'objectif est de rendre la sécurité vérifiable, reproductible et continue, au même titre que la performance.

Le cycle est structuré en cinq pratiques opérationnelles.

- Planifier les contrôles : définir en amont les exigences de conformité (KAT), les critères statistiques (IC95) et les points de contrôle de sécurité.
- Construire de manière reproductible : centraliser l'exécution dans des scripts versionnés pour limiter les écarts entre exécution locale et CI.
- Vérifier automatiquement : exécuter tests, audits statistiques et analyses de sécurité à chaque `push` et `pull_request`.
- Réduire l'exposition : détecter les vulnérabilités connues des dépendances et les faiblesses de code tôt dans le pipeline.
- Maintenir dans le temps : automatiser la mise à jour des dépendances et conserver des artefacts d'évidence pour la traçabilité.

Contrôles DevSecOps en place :

- Validation continue via `pytest`.
- Analyse de dépendances avec `pip-audit`.
- Analyse statique de sécurité Python avec `bandit`.
- Analyse CodeQL pour Python et workflows GitHub Actions.
- Mises à jour automatiques via Dependabot.

Fichiers CI concernés :

- `.github/workflows/tests.yml` : tests, couverture et audit IC95.
- `.github/workflows/security.yml` : CodeQL, bandit et scan de dépendances.
- `.github/dependabot.yml` : stratégie de mise à jour hebdomadaire des dépendances.

### Commandes de vérification locale

```bash
cd crypto-experiments
python -m pytest
python -m pip install pip-audit bandit
python -m pip_audit -r requirements.txt
python -m bandit -r application domain scripts
```

> En CI, `security.yml` exécute CodeQL et un scan de sécurité statique, tandis que `tests.yml` exécute la suite de tests et le scan de dépendances sur tous les PRs.

## Résultats clés

| Algorithme | Débit x86 (MB/s) | Débit ARM (MB/s) | Ratio x86/ARM |
|---|---|---|---|
| AES | 398,55 | 69,05 | **5,77×** |
| ChaCha20 | 144,55 | 89,35 | **1,62×** |
| DES | 38,78 | 31,85 | 1,22× |
| 3DES | 13,80 | 11,39 | 1,21× |
| Twofish | 3,14 | 1,44 | 2,18× |

**Observations clés :**
- AES bénéficie massivement de l'accélération matérielle AES-NI sur x86 (ratio 5,77× sur débit maximal).
- ChaCha20 reste l'algorithme le plus portable dans les lectures à taille fixée.
- Twofish est l'algorithme le plus lent sur les deux plateformes.
- DES et 3DES produisent des résultats cohérents avec leur statut obsolète.

Ces valeurs correspondent au tableau de synthèse de la campagne consolidée dans [docs/07-analysis-and-calculations/INF1430-TN4-Melissa-Moya.md](docs/07-analysis-and-calculations/INF1430-TN4-Melissa-Moya.md).

---

## Données brutes

Les CSV sont versionnés dans `crypto-experiments/data/results/` :

- `windows_experienceN_YYYYMMDD.csv` — campagnes Windows x86
- `raspberry_experienceN_YYYYMMDD.csv` — campagnes Raspberry Pi ARM

> Les campagnes successives sont conservées pour traçabilité historique.

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
- [OWASP SAMM](https://owaspsamm.org/) — *Software Assurance Maturity Model*.
- [NIST SP 800-218 (SSDF)](https://csrc.nist.gov/publications/detail/sp/800-218/final) — *Secure Software Development Framework*.
- [GitHub Actions](https://docs.github.com/actions) — *Automate CI/CD pipelines with workflow files*.
- [GitHub Dependabot](https://docs.github.com/code-security/dependabot) — *Automate dependency updates*.
- [GitHub CodeQL](https://docs.github.com/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning-with-codeql) — *Code scanning and security analysis*.
- [pip-audit](https://github.com/pypa/pip-audit) — *Python dependency vulnerability scanner*.
- [Bandit](https://bandit.readthedocs.io/) — *Python security analyzer*.
