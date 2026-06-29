# Guide Raspberry Pi — Exécution des expériences de chiffrement
## Procédure reproductible — INF1430

---

## Vue d'ensemble

Ce guide présente une procédure pas à pas pour exécuter les expériences de benchmarking sur un Raspberry Pi à partir d’un dépôt Git cloné depuis GitHub, puis pour envoyer directement les résultats vers le dépôt distant.

L’objectif est de produire **trois exécutions complètes du benchmark sur le Raspberry Pi** afin de conserver une convention cohérente avec les fichiers déjà présents pour le laptop :

- `raspberry-pi_experience1.csv`
- `raspberry-pi_experience2.csv`
- `raspberry-pi_experience3.csv`

**Durée estimée** : 20 à 45 minutes par exécution selon la connexion, le modèle du Raspberry Pi et la charge du système.

---

## Étape 0 — Prérequis sur le Raspberry Pi

Le Raspberry Pi doit être allumé, connecté au réseau et disposer des outils de base requis.

Exécuter les commandes suivantes :

```bash
python3 --version
sudo apt update
sudo apt install python3 python3-pip python3-venv git -y
```

Vérifier que `python3 --version` affiche une version suffisante de Python.

---

## Étape 1 — Configurer l’accès GitHub par SSH

Cette étape permet d’utiliser `git push` depuis le Raspberry Pi sans devoir saisir un nom d’utilisateur et un mot de passe/token HTTPS à chaque envoi.

### 1.1 — Générer une clé SSH

Exécuter la commande suivante :

```bash
ssh-keygen -t ed25519 -C "melissa.moya@ssc-spc.gc.ca"
```

Lorsque le terminal demande le chemin de sauvegarde, appuyer sur **Entrée** pour accepter l’emplacement par défaut :

```text
/home/melissamoya/.ssh/id_ed25519
```

Lorsque le terminal demande une phrase secrète, saisir une phrase secrète si souhaité, ou appuyer sur **Entrée** pour laisser le champ vide.

> **Note** : si une clé existe déjà dans `/home/melissamoya/.ssh/id_ed25519`, ne pas l’écraser sans raison. Dans ce cas, utiliser la clé existante et poursuivre avec les étapes suivantes.

### 1.2 — Afficher la clé publique

Exécuter la commande suivante :

```bash
cat ~/.ssh/id_ed25519.pub
```

Copier la ligne complète affichée dans le terminal.

### 1.3 — Ajouter la clé publique sur GitHub

Dans GitHub :
- ouvrir **Settings** ;
- ouvrir **SSH and GPG keys** ;
- cliquer sur **New SSH key** ;
- choisir **Authentication Key** ;
- coller la clé publique ;
- enregistrer.

### 1.4 — Basculer le dépôt local vers l’URL SSH

Exécuter la commande suivante depuis le dépôt local :

```bash
git remote set-url origin git@github.com:moyamelissa/INF1430-Comparaison-Chiffrement-Symetrique.git
```

Cette commande ne produit généralement aucune sortie si elle réussit.

### 1.5 — Tester la connexion SSH à GitHub

Exécuter la commande suivante :

```bash
ssh -T git@github.com
```

Lors de la première connexion, GitHub peut demander de confirmer l’empreinte du serveur. Répondre :

```text
yes
```

Si la configuration fonctionne correctement, un message semblable au suivant doit s’afficher :

```text
Hi moyamelissa! You've successfully authenticated, but GitHub does not provide shell access.
```

---

## Étape 2 — Cloner le dépôt GitHub

Cloner le dépôt directement sur le Raspberry Pi :

```bash
cd ~
git clone git@github.com:moyamelissa/INF1430-Comparaison-Chiffrement-Symetrique.git
cd ~/INF1430-Comparaison-Chiffrement-Symetrique
```

Cette méthode permet de conserver les résultats produits directement dans un dépôt Git local prêt à être versionné et poussé vers GitHub.

---

## Étape 3 — Créer l’environnement virtuel, installer les dépendances et préparer le dossier de logs

Depuis le dossier `crypto-experiments/`, exécuter les commandes suivantes :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
python3 -m venv .venv
source .venv/bin/activate
mkdir -p data/logs
pip install pycryptodome twofish > data/logs/pip_install.txt 2>&1
cat data/logs/pip_install.txt
```

### Vérifications attendues

- Le terminal doit afficher `(.venv)` au début de la ligne après l’activation de l’environnement virtuel.
- Le dossier `data/logs/` doit exister avant l’utilisation de la redirection `> data/logs/...`.
- Le fichier `data/logs/pip_install.txt` doit être créé automatiquement par la commande.

> **Important** : il n’est pas nécessaire de créer les fichiers `.txt` manuellement. Une redirection de sortie crée automatiquement le fichier si le dossier parent existe.

Si un nouveau terminal est ouvert plus tard, réactiver l’environnement virtuel avec :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
mkdir -p data/logs
```

---

## Étape 4 — Corriger la librairie Twofish si Python 3.13 est utilisé

La librairie `twofish` n’est pas compatible telle quelle avec Python 3.13, car elle utilise `import imp`, qui a été supprimé.

> **Appliquer cette étape uniquement si le Raspberry Pi utilise Python 3.13.**

### 4.1 — Ouvrir le fichier `twofish.py`

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
nano .venv/lib/python3.13/site-packages/twofish.py
```

> **Note** : si une autre version de Python est installée, le chemin du dossier peut différer.

### 4.2 — Appliquer le correctif

Effectuer les remplacements suivants dans le fichier :

1. Remplacer :
   ```python
   import imp
   ```
   par :
   ```python
   import importlib.util
   ```

2. Remplacer :
   ```python
   _twofish = cdll.LoadLibrary(imp.find_module('_twofish')[1])
   ```
   par :
   ```python
   _twofish = cdll.LoadLibrary(importlib.util.find_spec('_twofish').origin)
   ```

3. Sauvegarder avec **Ctrl+O**, **Entrée**, puis quitter avec **Ctrl+X**.

---

## Étape 5 — Vérifier les dépendances

Exécuter les commandes suivantes :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
mkdir -p data/logs
python -c "import Crypto; import twofish; print('Dependencies OK')" > data/logs/dependencies_check.txt 2>&1
cat data/logs/dependencies_check.txt
```

### Sortie attendue

Le fichier `data/logs/dependencies_check.txt` doit contenir :

```text
Dependencies OK
```

---

## Étape 6 — Valider les KAT sur le Raspberry Pi

Avant de lancer le benchmark complet, valider le bon fonctionnement de l’implémentation sur l’architecture ARM.

Exécuter les commandes suivantes :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
mkdir -p data/logs
python scripts/run_kat.py > data/logs/kat_results.txt 2>&1
cat data/logs/kat_results.txt
```

### Vérification attendue

Les 48 assertions réparties sur 6 suites doivent afficher `PASS` dans le fichier de log.

---

## Étape 7 — Exécuter les trois benchmarks Raspberry Pi

Trois exécutions distinctes doivent être réalisées.

Chaque exécution génère :
1. un fichier CSV dans `data/results/` ;
2. un fichier texte de log dans `data/logs/`.

### Exécution 1

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
mkdir -p data/logs
python scripts/experiment.py > data/logs/benchmark_output_experience1.txt 2>&1
cat data/logs/benchmark_output_experience1.txt
cd data/results
mv experiment_*.csv raspberry-pi_experience1.csv
cd ../..
```

### Exécution 2

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
py scripts/compare_platforms.py
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
