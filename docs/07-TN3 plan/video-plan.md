# Plan vidéo de démonstration (priorisé)

Ce document présente les fichiers les plus importants à montrer en vidéo, dans l'ordre recommandé, avec la justification académique.

## Regroupement thématique des vidéos

| Vidéo | Thématique | Pages PowerPoint associées | Durée cible |
|---|---|---|---|
| 1 | Nature du système et architecture | 3 | 4-5 min |
| 2 | Protocole expérimental | 4-5 | 5-6 min |
| 3 | Validation fonctionnelle (KAT) | 6 | 4-5 min |
| 4 | AES: architecture et écarts de performance | 7-10 | 6-8 min |
| 5 | ChaCha20 et comparaison ARM/x86 | 11-13 | 5-6 min |
| 6 | Algorithmes hérités et modes d'opération | 14-15 | 4-5 min |
| 7 | Robustesse et stabilité statistique | 16-18 | 5-6 min |
| 8 | Synthèse et recommandations | 19-22 | 4-5 min |

## Correspondance vidéo -> fichiers à montrer

1. **Vidéo 1 — Nature du système et architecture (pages 3)**
   - Fichier principal: **crypto-experiments/domain/engine/EncryptionEngine.py**
   - Appui: structure des dossiers `domain/`, `application/`, `scripts/`.

2. **Vidéo 2 — Protocole expérimental (pages 4-5)**
   - Fichier principal: **crypto-experiments/scripts/experiment.py**
   - Fichier principal: **crypto-experiments/application/ExperimentController.py**
   - Preuve technique à montrer: **crypto-experiments/domain/cipher/AES.py** (import `Crypto.Cipher`) pour justifier l'usage de routines natives optimisées.
   - Point oral obligatoire: expliquer que la neutralité vient du même protocole de mesure et des mêmes bibliothèques, puis que la comparaison observe l'effet plateforme (x86 vs ARM).

3. **Vidéo 3 — Validation fonctionnelle KAT (page 6)**
   - Fichier principal: **crypto-experiments/scripts/run_kat.py**
   - Fichier principal: **crypto-experiments/validation/kat_aes.py**
   - Appui: **crypto-experiments/tests/test_run_kat.py**

4. **Vidéo 4 — AES: architecture et écarts (pages 7-10)**
   - Fichier principal: **crypto-experiments/domain/cipher/AES.py**
   - Appui: résultats de **crypto-experiments/scripts/compare_platforms.py**

5. **Vidéo 5 — ChaCha20 et ARM/x86 (pages 11-13)**
   - Fichier principal: **crypto-experiments/domain/cipher/ChaCha20.py**
   - Appui: **crypto-experiments/scripts/compare_platforms.py**

6. **Vidéo 6 — Algorithmes hérités et modes (pages 14-15)**
   - Fichiers principaux: **crypto-experiments/domain/cipher/DES.py**, **crypto-experiments/domain/cipher/TripleDES.py**, **crypto-experiments/domain/cipher/Twofish.py**
   - Appui: **crypto-experiments/validation/kat_modes.py**, **crypto-experiments/scripts/ecb_visual_vulnerability.py**

7. **Vidéo 7 — Robustesse et stabilité statistique (pages 16-18)**
   - Fichier principal: **crypto-experiments/application/ExperimentController.py** (avalanche, key avalanche, IC95)
   - Appui: **crypto-experiments/scripts/analyse_rounds_avalanche.py**
   - Preuve obligatoire demandée: graphique rounds vs score d'avalanche (**data/charts/fig7_rounds_avalanche.png** ou figure générée équivalente).

8. **Vidéo 8 — Synthèse et recommandations (pages 19-22)**
   - Fichier principal: **crypto-experiments/scripts/compare_platforms.py**
   - Preuves de données: **crypto-experiments/data/results/laptop-windows-x86_experience*.csv** et **crypto-experiments/data/results/raspberry-pi_experience*.csv**
   - Appui: graphiques consolidés dans **crypto-experiments/data/charts/**

## Couverture des points critiques du professeur (obligatoire)

1. **Effet d'avalanche selon le nombre de tours**
   - Vidéo concernée: **Vidéo 7**
   - Fichiers/preuves: **scripts/analyse_rounds_avalanche.py** + figure rounds vs avalanche.
   - Message à livrer: identifier le seuil de convergence vers un score proche de 0,5.

2. **Justification Python et neutralité expérimentale**
   - Vidéo concernée: **Vidéo 2**
   - Fichiers/preuves: **application/ExperimentController.py** (protocole de mesure) + **domain/cipher/AES.py** (backend PyCryptodome natif).
   - Message à livrer: la neutralité dépend du protocole et de l'homogénéité des conditions de test, pas du langage seul.

3. **Synthèse traçable par fichiers**
   - Vidéo concernée: **Vidéo 8**
   - Fichiers/preuves: **scripts/compare_platforms.py** + CSV x86/Pi + graphiques générés.
   - Message à livrer: chaque recommandation finale doit être reliée à une mesure et à un artefact reproductible.

## Fichiers à présenter en priorité

1. **crypto-experiments/scripts/experiment.py**
   - Rôle: point d'entrée de la campagne expérimentale.
   - Pourquoi c'est important: montre la matrice d'expériences, les répétitions (n), les tailles de messages et l'export CSV.
   - Critères couverts: faisabilité, complétude, clarté méthodologique.

2. **crypto-experiments/application/ExperimentController.py**
   - Rôle: logique scientifique des mesures.
   - Pourquoi c'est important: explique le chronométrage, le calcul des débits, l'effet d'avalanche et l'IC95.
   - Critères couverts: maîtrise des techniques, pertinence, justification des résultats.

3. **crypto-experiments/domain/engine/EncryptionEngine.py**
   - Rôle: abstraction centrale qui compose primitive + mode.
   - Pourquoi c'est important: prouve la séparation des responsabilités et la cohérence de l'architecture.
   - Critères couverts: organisation et qualité du produit.

4. **crypto-experiments/scripts/run_kat.py**
   - Rôle: orchestration de la validation fonctionnelle.
   - Pourquoi c'est important: prouve que les implémentations sont validées avant toute lecture de performance.
   - Critères couverts: concordance, rigueur de validation.

5. **crypto-experiments/validation/kat_aes.py**
   - Rôle: exemple représentatif d'un test KAT.
   - Pourquoi c'est important: démontre concrètement la vérification avec vecteurs de référence.
   - Critères couverts: compréhension des concepts, qualité de validation.

6. **crypto-experiments/scripts/compare_platforms.py**
   - Rôle: comparaison inter-plateformes et génération de graphiques.
   - Pourquoi c'est important: relie les données brutes aux analyses x86 vs Raspberry Pi.
   - Critères couverts: interprétation des résultats, transférabilité.

7. **crypto-experiments/tests/test_run_kat.py**
   - Rôle: tests automatisés du pipeline KAT.
   - Pourquoi c'est important: renforce la fiabilité de l'orchestration pass/fail.
   - Critères couverts: qualité logicielle, robustesse du produit.

## Fichiers à montrer brièvement (couverture)

- **crypto-experiments/validation/kat_modes.py**: appui sur les modes d'opération.
- **crypto-experiments/validation/kat_gcm.py**: validation du mode authentifié moderne.
- **crypto-experiments/tests/test_core_crypto.py**: couverture des primitives et modes.

