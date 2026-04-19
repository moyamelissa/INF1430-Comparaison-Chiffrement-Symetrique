# INF1430 – Implémentation et comparaison des algorithmes de chiffrement symétrique

## Présentation
Ce dépôt contient un projet académique réalisé dans le cadre du cours **INF1430 – Projet de fin d’études** (Université **TÉLUQ**).  
Le projet vise la **conception** et l’**analyse expérimentale** d’algorithmes de chiffrement symétrique par blocs, afin d’étudier le lien entre :

- les **choix de conception cryptographique** (architecture, taille de clé, modes d’opération),
- et leurs **effets observables en pratique**, notamment en termes de **performances** et de **diffusion**.

## Objectifs

### 1) Algorithmes étudiés
Comparer les algorithmes suivants :
- **DES**
- **3DES**
- **AES**
- **Twofish**

### 2) Paramètres expérimentaux
Évaluer l’influence des paramètres suivants :
- algorithme,
- **mode d’opération** (ex. *ECB, CBC, CTR, GCM*),
- **taille de clé**,
- **plateforme matérielle**.

### 3) Indicateurs mesurés
- **Performances** : temps d’exécution, débit (throughput), etc.
- **Diffusion** : analyse via l’**effet d’avalanche**.

## Approche
Le projet adopte une démarche structurée de génie logiciel, privilégiant :
- la **conception avant l’implémentation**,
- la **séparation des responsabilités** (orchestration des expériences, opérations cryptographiques, mesure, analyse),
- une **expérimentation reproductible**,
- une **analyse fondée sur des indicateurs mesurables**.

> Les détails d’implémentation (bibliothèques Python, code, optimisations) sont volontairement différés après validation du modèle logiciel.

## Structure du dépôt
```text
├── docs/          # Documents, diagrammes et livrables
│   ├── tn1/       # Plan de projet
│   └── tn2/       # Modélisation et conception logicielle
├── src/           # Implémentation (phase ultérieure)
├── results/       # Résultats expérimentaux (phase ultérieure)
└── README.md
```

## État d’avancement
- ✅ **TN1** – Plan de projet
- 🟡 **TN2** – Modélisation et conception logicielle
- ⏳ **TN3** – Implémentation et expérimentation
- ⏳ **TN4** – Analyse et rapport final

## Références principales
- Paar, C., & Pelzl, J. *Understanding Cryptography*.  
- Stallings, W. *Cryptography and Network Security*.  
- NIST **FIPS 197** — *Advanced Encryption Standard (AES)*.  
- NIST **SP 800‑38A** — *Modes d’opération par blocs*.
