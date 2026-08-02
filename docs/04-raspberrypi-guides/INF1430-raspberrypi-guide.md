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

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
mkdir -p data/logs
python scripts/experiment.py > data/logs/benchmark_output_experience2.txt 2>&1
cat data/logs/benchmark_output_experience2.txt
cd data/results
mv experiment_*.csv raspberry-pi_experience2.csv
cd ../..
```

### Exécution 3

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
mkdir -p data/logs
python scripts/experiment.py > data/logs/benchmark_output_experience3.txt 2>&1
cat data/logs/benchmark_output_experience3.txt
cd data/results
mv experiment_*.csv raspberry-pi_experience3.csv
cd ../..
```

> **Important** : le fichier CSV doit être renommé immédiatement après chaque exécution, avant de lancer la suivante. Sinon, plusieurs fichiers `experiment_*.csv` peuvent se retrouver dans `data/results/`, ce qui complique l’identification des résultats.

---

## Étape 8 — Vérifier les fichiers produits

À la fin des trois exécutions, les fichiers suivants doivent être présents au minimum dans le dépôt local du Raspberry Pi :

```text
crypto-experiments/data/logs/pip_install.txt
crypto-experiments/data/logs/dependencies_check.txt
crypto-experiments/data/logs/kat_results.txt
crypto-experiments/data/logs/benchmark_output_experience1.txt
crypto-experiments/data/logs/benchmark_output_experience2.txt
crypto-experiments/data/logs/benchmark_output_experience3.txt
crypto-experiments/data/results/raspberry-pi_experience1.csv
crypto-experiments/data/results/raspberry-pi_experience2.csv
crypto-experiments/data/results/raspberry-pi_experience3.csv
```

Vérifier rapidement la présence des fichiers avec :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
ls data/logs
ls data/results
```

---

## Étape 9 — Commit et push des résultats vers GitHub

Une fois les trois exécutions terminées et les fichiers vérifiés, envoyer les résultats vers GitHub.

Exécuter les commandes suivantes :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique
git status
git add crypto-experiments/data/results crypto-experiments/data/logs
git commit -m "Add Raspberry Pi benchmark runs and logs"
git push
```

Les fichiers doivent ensuite être visibles sur GitHub.

---

## Étape 10 — Régénérer les graphiques de comparaison sur le laptop

Cette étape s’exécute sur le **laptop**, et non sur le Raspberry Pi.

Une fois les fichiers CSV du Raspberry Pi poussés sur GitHub, mettre à jour le dépôt local du laptop puis générer les graphiques de comparaison inter-plateformes :

```powershell
cd "C:\Users\xmeli\OneDrive\Documents\GitHub\INF1430-Comparaison-Chiffrement-Symetrique"
git pull
cd crypto-experiments
py scripts/charts/render_platform_comparison.py
```

Les figures générées sont enregistrées dans `data/charts/comparison/`.

---

## Résumé des commandes — Raspberry Pi

```bash
# 0. Installer les outils de base
python3 --version
sudo apt update
sudo apt install python3 python3-pip python3-venv git -y

# 1. Configurer SSH
ssh-keygen -t ed25519 -C "melissa.moya@ssc-spc.gc.ca"
cat ~/.ssh/id_ed25519.pub
git remote set-url origin git@github.com:moyamelissa/INF1430-Comparaison-Chiffrement-Symetrique.git
ssh -T git@github.com

# 2. Cloner le dépôt
cd ~
git clone git@github.com:moyamelissa/INF1430-Comparaison-Chiffrement-Symetrique.git
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments

# 3. Créer l'environnement virtuel et installer les dépendances
python3 -m venv .venv
source .venv/bin/activate
mkdir -p data/logs
pip install pycryptodome twofish > data/logs/pip_install.txt 2>&1

# 4. Corriger Twofish si Python 3.13 est utilisé
nano .venv/lib/python3.13/site-packages/twofish.py
# Remplacer import imp par import importlib.util
# Remplacer _twofish = cdll.LoadLibrary(imp.find_module('_twofish')[1])
# par _twofish = cdll.LoadLibrary(importlib.util.find_spec('_twofish').origin)

# 5. Vérifier les dépendances
python -c "import Crypto; import twofish; print('Dependencies OK')" > data/logs/dependencies_check.txt 2>&1

# 6. Valider les KAT
python scripts/run_kat.py > data/logs/kat_results.txt 2>&1

# 7. Benchmark Raspberry Pi — exécution 1
python scripts/experiment.py > data/logs/benchmark_output_experience1.txt 2>&1
cd data/results
mv experiment_*.csv raspberry-pi_experience1.csv
cd ../..

# 8. Benchmark Raspberry Pi — exécution 2
python scripts/experiment.py > data/logs/benchmark_output_experience2.txt 2>&1
cd data/results
mv experiment_*.csv raspberry-pi_experience2.csv
cd ../..

# 9. Benchmark Raspberry Pi — exécution 3
python scripts/experiment.py > data/logs/benchmark_output_experience3.txt 2>&1
cd data/results
mv experiment_*.csv raspberry-pi_experience3.csv
cd ../..

# 10. Commit et push
cd ~/INF1430-Comparaison-Chiffrement-Symetrique
git add crypto-experiments/data/results crypto-experiments/data/logs
git commit -m "Add Raspberry Pi benchmark runs and logs"
git push
```
