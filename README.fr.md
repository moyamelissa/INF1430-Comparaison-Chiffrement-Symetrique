# Analyse cross-plateforme du chiffrement symétrique

![CI](https://img.shields.io/github/actions/workflow/status/moyamelissa/INF1430-Comparaison-Chiffrement-Symetrique/tests.yml?branch=main)
![Coverage](https://img.shields.io/badge/Coverage-100%25-2E7D32)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![Cryptography](https://img.shields.io/badge/Cryptography-Symmetric-1F7A8C)
![Platforms](https://img.shields.io/badge/Platforms-Windows%20x86%20%7C%20Raspberry%20Pi%20ARM-5C6BC0)
![Validation](https://img.shields.io/badge/Validation-KAT%20integrated-2E7D32)
![Audit IC95](https://img.shields.io/badge/IC95%20Audit-CI%20quality%20gates-2E7D32)
![Dependabot](https://img.shields.io/badge/Dependabot-enabled-0366d6?logo=dependabot&logoColor=white)

Projet académique de l’université TELUQ, cours INF1430.

Langues / Languages : [English](README.md) | Français

## Sommaire

- [Vue d’ensemble](#vue-densemble)
- [Périmètre technique](#périmètre-technique)
- [Architecture du projet](#architecture-du-projet)
- [Structure du dépôt](#structure-du-dépôt)
- [Plateformes testées](#plateformes-testées)
- [Installation](#installation)
- [Démarrage rapide](#démarrage-rapide)
- [Phases SDLC et livrables](#phases-sdlc-et-livrables)
- [Contrôles DevSecOps](#contrôles-devsecops)
- [Données et reproductibilité](#données-et-reproductibilité)

## Vue d’ensemble

Ce projet compare des implémentations de cryptographie symétrique selon un workflow reproductible et une approche d’ingénierie logicielle.

L’évaluation porte sur trois axes :

- performance (latence et débit),
- robustesse (effet avalanche),
- comportement multi-plateformes (Windows x86 vs Raspberry Pi ARM).

Les sorties sont générées par des scripts versionnés, validées avec des KAT et exportées sous forme de CSV et de graphiques.

## Périmètre technique

### Algorithmes

| Algorithme | Famille | Tailles de clé prises en charge |
|---|---|---|
| DES | Chiffrement par blocs | 56 bits |
| 3DES | Chiffrement par blocs | 128 / 192 bits |
| AES | Chiffrement par blocs | 128 / 192 / 256 bits |
| Twofish | Chiffrement par blocs | 128 / 192 / 256 bits |
| ChaCha20 | Chiffrement de flux | 256 bits |

### Modes

| Mode | Applicabilité | Notes |
|---|---|---|
| ECB | Chiffrements par blocs | Inclus uniquement à des fins pédagogiques |
| CBC | Chiffrements par blocs | IV requis |
| CTR | Chiffrements par blocs | Nonce requis, parallélisable |
| GCM | Chiffrements par blocs | Mode AEAD (confidentialité + intégrité) |
| StreamMode | ChaCha20 | Encapsulation de flux |

## Architecture du projet

| Couche | Composants principaux | Responsabilité |
|---|---|---|
| Application | ExperimentController | Orchestration des campagnes expérimentales |
| Domaine | EncryptionEngine, primitives, modes | Abstractions unifiées de chiffrement/déchiffrement |
| Exécution | scripts/*.py | Exécution des benchmarks, KAT, graphiques et audits |

## Structure du dépôt

```text
INF1430-Comparaison-Chiffrement-Symetrique/
├── crypto-experiments/
│   ├── application/
│   ├── domain/
│   │   ├── cipher/
│   │   ├── engine/
│   │   └── mode/
│   ├── scripts/
│   ├── validation/
│   └── data/
├── resources/
│   └── KAT/
├── deliverables/
└── README.md
```

## Plateformes testées

| Attribut | Ordinateur Windows x86 | Raspberry Pi ARM |
|---|---|---|
| Classe de CPU | Intel Core avec AES-NI | ARM Cortex-A72 sans AES-NI |
| OS | Windows 11 | Raspberry Pi OS |
| Python | 3.11+ | 3.11+ |
| Backend crypto | PyCryptodome | PyCryptodome |

## Installation

Prérequis :

- Python 3.11+
- pip

```bash
cd crypto-experiments
pip install -r requirements.txt
```

## Démarrage rapide

Exécuter les commandes depuis crypto-experiments/ :

```bash
# 1) Validation fonctionnelle (KAT)
python scripts/run_kat.py

# 2) Campagne de benchmarks
python scripts/experiment.py

# 3) Génération des graphiques
python scripts/run_charts.py
```

## Phases SDLC et livrables

| Phase SDLC | Focus | Livrable principal |
|---|---|---|
| Phase 1 - Portée et conception | cadrage du problème, architecture et planification initiale | [TN1 Rapport](deliverables/INF1430-TN1-Melissa-Moya.pdf) |
| Phase 2 - Implémentation et validation | choix d’implémentation, stratégie de tests et protocole de mesure | [TN2 Rapport](deliverables/INF1430-TN2-Melissa-Moya.pdf) |
| Phase 3 - Exécution expérimentale | collecte des données, génération des graphiques et analyse | [TN3 Présentation](deliverables/INF1430-TN3-Melissa_Moya.pdf) |
| Phase 4 - Synthèse finale | preuves consolidées, conclusions comparatives et recommandations | [TN4 Rapport final](deliverables/INF1430-TN4-Melissa_Moya.pdf) |

## Contrôles DevSecOps

- Tests unitaires et d’intégration via pytest.
- Validation KAT à l’aide de vecteurs NIST/RFC et de vecteurs de référence Twofish.
- Audit qualité IC95 en CI via :

```bash
python scripts/audit/audit_ic95.py --enforce-gates
```

## Données et reproductibilité

- Les CSV bruts sont stockés dans crypto-experiments/data/results/.
- Les graphiques sont exportés dans crypto-experiments/data/charts/.
- Les preuves d’audit sont stockées dans crypto-experiments/data/evidence/.

Pour reproduire le processus complet :

1. Installer les dépendances.
2. Exécuter python scripts/run_kat.py.
3. Exécuter python scripts/experiment.py.
4. Exécuter python scripts/run_charts.py.

---

Contact du portfolio : Melissa Moya - [LinkedIn](https://www.linkedin.com/in/melissa-moya-39329b296)
