# INF1430 — Comparaison expérimentale des algorithmes de chiffrement symétrique

> Projet académique — Université TÉLUQ · Cours INF1430 – Projet de fin d'études

---

## Table des matières

1. [Présentation](#présentation)
2. [Algorithmes et modes étudiés](#algorithmes-et-modes-étudiés)
3. [Architecture du projet](#architecture-du-projet)
4. [Structure du dépôt](#structure-du-dépôt)
5. [Installation](#installation)
6. [Utilisation](#utilisation)
7. [Résultats](#résultats)
8. [État d'avancement](#état-davancement)
9. [Références](#références)

---

## Présentation

Ce projet étudie et compare empiriquement plusieurs algorithmes de **chiffrement symétrique** sous différents angles : performances temporelles, débit de chiffrement/déchiffrement, et diffusion des données (effet d'avalanche).

L'objectif est d'établir un lien rigoureux entre les **choix de conception cryptographique** — algorithme, mode d'opération, taille de clé — et leurs **effets mesurables en pratique**, en fonction de la plateforme matérielle cible.

Le projet suit une démarche de **génie logiciel** : conception orientée objet, séparation des responsabilités, expérimentation reproductible et validation par tests de vecteurs connus (KAT — *Known Answer Tests*).

---

## Algorithmes et modes étudiés

### Algorithmes de chiffrement

| Algorithme | Type       | Tailles de clé supportées |
|------------|------------|---------------------------|
| DES        | Bloc       | 56 bits                   |
| 3DES       | Bloc       | 112 / 168 bits            |
| AES        | Bloc       | 128 / 192 / 256 bits      |
| Twofish    | Bloc       | 128 / 192 / 256 bits      |
| ChaCha20   | Flux       | 256 bits                  |

### Modes d'opération

| Mode   | Applicabilité         | Caractéristiques                        |
|--------|-----------------------|-----------------------------------------|
| ECB    | Chiffrement par blocs | Sans IV — illustre la vulnérabilité ECB |
| CBC    | Chiffrement par blocs | IV aléatoire, chaînage des blocs        |
| CTR    | Chiffrement par blocs | Parallélisable, nonce requis            |
| GCM    | Chiffrement par blocs | Authentifié (AEAD), nonce requis        |
| Stream | Flux (ChaCha20)       | Chiffrement de flux natif               |

---

## Architecture du projet

Le code est organisé selon une architecture en couches qui sépare les responsabilités :

```
Application layer   ExperimentController   — orchestration des expériences, mesures, calcul d'avalanche
     │
Domain layer        EncryptionEngine       — interface uniforme encrypt/decrypt
     │                   │
     │              CipherPrimitive        — abstraction de chaque algorithme (AES, DES, …)
     │              OperationMode          — abstraction de chaque mode (ECB, CBC, CTR, GCM, Stream)
     │
Scripts             experiment.py          — point d'entrée CLI
                    run_kat.py             — validation KAT
                    generate_charts.py     — génération des graphiques
                    analyse_rounds_avalanche.py
                    compare_platforms.py
                    ecb_visual_vulnerability.py
```

**Principes appliqués :**
- **Ouvert/Fermé** — ajouter un algorithme ou un mode ne nécessite qu'une nouvelle classe concrète.
- **Séparation des responsabilités** — la mesure du temps, la cryptographie et la persistance des résultats sont des couches distinctes.
- **Reproductibilité** — chaque expérience est paramétrée et exportée en CSV avec ses métadonnées (plateforme, horodatage, répétitions).

---

## Structure du dépôt

```text
INF1430-Comparaison-Chiffrement-Symetrique/
├── crypto-experiments/
│   ├── requirements.txt
│   ├── application/
│   │   └── ExperimentController.py     # Orchestration et mesure
│   ├── domain/
│   │   ├── cipher/                     # DES, 3DES, AES, Twofish, ChaCha20
│   │   ├── engine/
│   │   │   └── EncryptionEngine.py     # Interface unifiée
│   │   └── mode/                       # ECB, CBC, CTR, GCM, Stream
│   ├── scripts/
│   │   ├── experiment.py               # Point d'entrée principal
│   │   ├── run_kat.py                  # Known Answer Tests
│   │   ├── generate_charts.py          # Visualisation des résultats
│   │   ├── analyse_rounds_avalanche.py # Analyse de l'effet d'avalanche
│   │   ├── compare_platforms.py        # Comparaison multi-plateformes
│   │   └── ecb_visual_vulnerability.py # Démonstration visuelle ECB
│   ├── validation/
│   │   ├── kat_aes.py
│   │   ├── kat_des.py
│   │   ├── kat_3des.py
│   │   ├── kat_chacha20.py
│   │   ├── kat_gcm.py
│   │   └── kat_modes.py
│   └── data/
│       ├── results/                    # Données CSV brutes par plateforme
│       └── charts/                     # Graphiques générés
├── docs/
│   ├── guide-completion-TN.md
│   └── guide-raspberry-pi.md
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

> **Dépendances :** `pycryptodome >= 3.20`, `twofish >= 0.3`

---

## Utilisation

Toutes les commandes s'exécutent depuis le répertoire `crypto-experiments/`.

### Lancer une expérience de benchmarking

```bash
python scripts/experiment.py
```

Les résultats sont exportés dans `data/results/` au format CSV, avec le nom de la plateforme en préfixe (ex. `laptop-windows-x86_experience1.csv`).

### Valider les primitives cryptographiques (KAT)

```bash
python scripts/run_kat.py
```

### Générer les graphiques de comparaison

```bash
python scripts/generate_charts.py
```

### Analyser l'effet d'avalanche

```bash
python scripts/analyse_rounds_avalanche.py
```

### Démonstration de la vulnérabilité ECB

```bash
python scripts/ecb_visual_vulnerability.py
```

### Comparer les résultats entre plateformes

```bash
python scripts/compare_platforms.py
```

---

## Résultats

Les données expérimentales brutes sont stockées dans `crypto-experiments/data/results/`.  
Les graphiques de comparaison sont générés dans `crypto-experiments/data/charts/`.

Plateformes testées à ce jour :

| Identifiant          | Système | Architecture |
|----------------------|---------|--------------|
| `laptop-windows-x86` | Windows | x86-64       |

---

## État d'avancement

| Livrable | Description                           | Statut       |
|----------|---------------------------------------|--------------|
| TN1      | Plan de projet                        | ✅ Complété  |
| TN2      | Modélisation et conception logicielle | ✅ Complété  |
| TN3      | Implémentation et expérimentation     | ✅ Complété  |
| TN4      | Analyse et rapport final              | 🔄 En cours  |

---

## Références

- Paar, C., & Pelzl, J. *Understanding Cryptography: A Textbook for Students and Practitioners*. Springer, 2010.
- Stallings, W. *Cryptography and Network Security: Principles and Practice*. Pearson, 2017.
- NIST FIPS 197 — *Advanced Encryption Standard (AES)*. 2001.
- NIST SP 800-38A — *Recommendation for Block Cipher Modes of Operation*. 2001.
- Bernstein, D. J. *ChaCha, a variant of Salsa20*. 2008.
- Schneier, B. et al. *Twofish: A 128-Bit Block Cipher*. 1998.
