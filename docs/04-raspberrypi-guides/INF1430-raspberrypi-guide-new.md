# Guide Raspberry Pi — Mise à jour du dépôt, installation de Twofish et exécution des expériences
## Procédure reproductible — INF1430

---

## Vue d'ensemble

Ce guide décrit la procédure utilisée sur le Raspberry Pi pour :

1. remettre le dépôt local au même état que GitHub;
2. créer un environnement Python isolé;
3. installer `pycryptodome` et `twofish`;
4. corriger `twofish` pour Python 3.13 si nécessaire;
5. valider l’installation;
6. exécuter `experiment.py`;
7. commit et push les résultats vers GitHub.

L’objectif est d’obtenir des résultats reproductibles depuis un Raspberry Pi, en partant d’un dépôt propre et à jour.

**Durée estimée** : 20 à 45 minutes par exécution selon le modèle du Raspberry Pi et la charge du système.

---

## Étape 0 — Prérequis sur le Raspberry Pi

Le Raspberry Pi doit être allumé, connecté au réseau et disposer des outils de base requis.

Exécuter les commandes suivantes :

```bash
python3 --version
sudo apt update
sudo apt install python3 python3-pip python3-venv git -y
```

---

## Étape 1 — Se placer dans le dépôt local

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique
```

Si le dépôt existe déjà sur le Raspberry Pi, continuer avec l’étape suivante. Sinon, le cloner depuis GitHub.

---

## Étape 2 — Mettre le dépôt local à jour avec GitHub

Cette étape permet de repartir d’un dépôt propre, sans conserver les modifications locales du Raspberry Pi.

```bash
git fetch origin
git reset --hard origin/main
git clean -fd
```

### Vérification attendue

```bash
git status
```

La sortie doit indiquer :

- `Your branch is up to date with 'origin/main'`
- `nothing to commit, working tree clean`

> **Important** : cette étape supprime les fichiers non suivis et les modifications locales du Raspberry Pi.

---

## Étape 3 — Créer l’environnement virtuel et installer les dépendances

Depuis le dossier `crypto-experiments/`, exécuter les commandes suivantes :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
python3 -m venv .venv
source .venv/bin/activate
pip install pycryptodome twofish
```

### Vérification attendue

Tester l’import de `twofish` :

```bash
python3 -c "import twofish; print('twofish OK')"
```

Si la commande affiche `twofish OK`, la dépendance est installée correctement.

---

## Étape 4 — Corriger `twofish` si Python 3.13 est utilisé

Sur Python 3.13, la librairie `twofish` peut échouer au chargement car elle dépend de `import imp`, supprimé dans cette version.

> **Appliquer cette étape uniquement si le Raspberry Pi utilise Python 3.13.**

### 4.1 — Ouvrir le fichier `twofish.py`

```bash
nano .venv/lib/python3.13/site-packages/twofish.py
```

> Le chemin peut varier selon la version de Python installée.

### 4.2 — Appliquer le correctif

Remplacer :

```python
import imp
```

par :

```python
import importlib.util
```

Puis remplacer :

```python
_twofish = cdll.LoadLibrary(imp.find_module('_twofish')[1])
```

par :

```python
_twofish = cdll.LoadLibrary(importlib.util.find_spec('_twofish').origin)
```

Sauvegarder avec **Ctrl+O**, **Entrée**, puis quitter avec **Ctrl+X**.

### 4.3 — Revalider l’import

```bash
python3 -c "import twofish; print('twofish OK')"
```

---

## Étape 5 — Vérifier les dépendances

```bash
python3 -c "import Crypto; import twofish; print('Dependencies OK')"
```

La sortie attendue est :

```text
Dependencies OK
```

---

## Étape 6 — Valider les KAT sur le Raspberry Pi

Avant de lancer les benchmarks complets, valider le bon fonctionnement de l’implémentation sur l’architecture ARM.

```bash
python3 scripts/run_kat.py
```

Les assertions doivent réussir et afficher `PASS`.

---

## Étape 7 — Exécuter `experiment.py`

Lancer le benchmark depuis le dossier `crypto-experiments/` :

```bash
python3 scripts/experiment.py
```

Si tout fonctionne, le script doit produire un fichier CSV de résultats dans `data/results/`.

### Vérifier les CSV générés

```bash
find data/results -name "*.csv"
```

Si nécessaire, vérifier que Twofish apparaît bien dans le résultat :

```bash
grep -Rni "Twofish" data/results/*.csv
```

---

## Étape 8 — Renommer les CSV si plusieurs exécutions sont réalisées

Si `experiment.py` est exécuté plusieurs fois, renommer le CSV de chaque exécution avant de relancer le script.

Exemple :

```bash
cd data/results
mv experiment_*.csv raspberry_experience1.csv
```

Puis répéter pour les autres exécutions.

---

## Étape 9 — Vérifier les fichiers produits

À la fin des exécutions, vérifier la présence des fichiers générés :

```bash
ls data/results
```

---

## Étape 10 — Commit et push des résultats vers GitHub

Une fois les CSV validés, envoyer les résultats vers GitHub :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique
git status
git add crypto-experiments/data/results
git commit -m "Add Raspberry Pi experiment results"
git push origin main
```

---

## Résumé des commandes — Raspberry Pi

```bash
# 0. Préparer le système
python3 --version
sudo apt update
sudo apt install python3 python3-pip python3-venv git -y

# 1. Se placer dans le dépôt et repartir d'un état propre
cd ~/INF1430-Comparaison-Chiffrement-Symetrique
git fetch origin
git reset --hard origin/main
git clean -fd

git status

# 2. Créer l'environnement virtuel et installer les dépendances
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
python3 -m venv .venv
source .venv/bin/activate
pip install pycryptodome twofish
python3 -c "import twofish; print('twofish OK')"

# 3. Corriger twofish si Python 3.13 est utilisé
nano .venv/lib/python3.13/site-packages/twofish.py
# Remplacer import imp par import importlib.util
# Remplacer _twofish = cdll.LoadLibrary(imp.find_module('_twofish')[1])
# par _twofish = cdll.LoadLibrary(importlib.util.find_spec('_twofish').origin)

# 4. Vérifier les dépendances
python3 -c "import Crypto; import twofish; print('Dependencies OK')"

# 5. Valider les KAT
python3 scripts/run_kat.py

# 6. Lancer le benchmark
python3 scripts/experiment.py
find data/results -name "*.csv"
grep -Rni "Twofish" data/results/*.csv

# 7. Commit et push
cd ~/INF1430-Comparaison-Chiffrement-Symetrique
git add crypto-experiments/data/results
git commit -m "Add Raspberry Pi experiment results"
git push origin main
```
