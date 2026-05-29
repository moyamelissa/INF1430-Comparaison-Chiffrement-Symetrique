# Guide Raspberry Pi — Exécution des expériences de chiffrement
## Notes personnelles — INF1430

---

## Vue d'ensemble

Ce guide documente la procédure complète utilisée pour exécuter les expériences de benchmarking sur le Raspberry Pi avec un vrai dépôt Git cloné depuis GitHub, puis pour envoyer directement les résultats sur GitHub depuis le Pi.


Je conserve **trois exécutions complètes du benchmark sur le Raspberry Pi** afin d'avoir une convention cohérente avec les trois fichiers déjà présents pour le laptop :

- `raspberry-pi_experience1.csv`
- `raspberry-pi_experience2.csv`
- `raspberry-pi_experience3.csv`

**Durée estimée** : 20 à 45 minutes par exécution selon la connexion, le modèle du Pi et la charge du système.

---

## Étape 0 — Prérequis sur le Raspberry Pi

Le Pi doit être allumé et connecté au réseau. Je commence par installer ou vérifier les outils de base :

```bash
python3 --version
sudo apt update
sudo apt install python3 python3-pip python3-venv git -y
```

Si `python3 --version` affiche `Python 3.11.x` ou plus récente, c'est suffisant.

---

## Étape 1 — Cloner le dépôt GitHub

Au lieu de télécharger un ZIP, je clone directement le dépôt GitHub sur le Raspberry Pi :

```bash
cd ~
git clone https://github.com/moyamelissa/INF1430-Comparaison-Chiffrement-Symetrique.git
cd ~/INF1430-Comparaison-Chiffrement-Symetrique
```

> **Pourquoi cette méthode ?** Avec `git clone`, les résultats produits sur le Raspberry Pi restent dans un vrai dépôt Git local. Je peux donc ensuite faire `git add`, `git commit` et `git push` directement depuis le Pi, sans transfert manuel vers le laptop.

---

## Étape 2 — Créer l'environnement virtuel, installer les dépendances et préparer le dossier de logs

Depuis le dossier `crypto-experiments/` sur le Pi :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
python3 -m venv .venv
source .venv/bin/activate
mkdir -p data/logs
pip install pycryptodome twofish > data/logs/pip_install.txt 2>&1
cat data/logs/pip_install.txt
```

Le dossier `data/logs/` doit être créé **avant** d'exécuter les commandes avec redirection (`> data/logs/...`). Sinon, Bash affiche l'erreur `No such file or directory` et le fichier de sortie ne sera pas créé.

> **Important** : il n'est **pas nécessaire de créer les fichiers `.txt` à la main**. Une fois le dossier `data/logs/` créé, les commandes avec redirection créent automatiquement les fichiers.

Pour vérifier que l'environnement virtuel est actif, le terminal doit afficher `(.venv)` au début de la ligne.

Si j'ouvre un nouveau terminal plus tard, je réactive l'environnement virtuel avec :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
mkdir -p data/logs
```

---

## Étape 3 — Correctif obligatoire pour la librairie Twofish

La librairie `twofish` n'est pas compatible telle quelle avec Python 3.13, car elle utilise `import imp`, qui a été supprimé.

### 3.1 — Ouvrir le fichier `twofish.py`

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
nano .venv/lib/python3.13/site-packages/twofish.py
```

> **Note** : le chemin contient ici `python3.13` parce que c'est la version installée sur mon Raspberry Pi. Si une autre version de Python est installée, le dossier peut être différent.

### 3.2 — Appliquer le correctif

Dans nano, je fais les deux modifications suivantes :

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

### 3.3 — Vérifier le correctif et enregistrer la sortie dans un fichier

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
mkdir -p data/logs
python -c "import Crypto; import twofish; print('Dependencies OK')" > data/logs/dependencies_check.txt 2>&1
cat data/logs/dependencies_check.txt
```

La sortie attendue dans `data/logs/dependencies_check.txt` est :

```text
Dependencies OK
```

---

## Étape 4 — Valider les KAT sur le Pi et enregistrer la sortie

Avant de lancer le benchmark complet, je valide que l'implémentation fonctionne correctement sur l'architecture ARM :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
mkdir -p data/logs
python scripts/run_kat.py > data/logs/kat_results.txt 2>&1
cat data/logs/kat_results.txt
```

Les 26 tests doivent afficher `PASS` dans le fichier de log.

---

## Étape 5 — Lancer les trois benchmarks Raspberry Pi

Je lance maintenant **trois exécutions distinctes** du benchmark sur le Raspberry Pi.

Chaque exécution génère :

1. un **fichier CSV** de résultats dans `data/results/`
2. un **fichier texte de log** dans `data/logs/`

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

> **Important** : il faut renommer le CSV immédiatement après chaque exécution, avant de relancer le benchmark suivant. Sinon, plusieurs fichiers `experiment_*.csv` risquent de se retrouver dans `data/results/` et la commande `mv experiment_*.csv ...` deviendra ambiguë.

---

## Étape 6 — Vérifier les fichiers produits

À la fin des trois exécutions, je dois avoir au minimum les fichiers suivants dans le dépôt local du Raspberry Pi :

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

Je peux vérifier rapidement avec :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
ls data/logs
ls data/results
```

---

## Étape 7 — Où ajouter les fichiers dans le dépôt GitHub

Comme le projet a été cloné avec Git, les fichiers se trouvent déjà **dans le bon dépôt local** sur le Raspberry Pi. Il n'y a plus besoin de les transférer manuellement sur le laptop.

Les fichiers à conserver dans le dépôt sont :

### Dossier `crypto-experiments/data/results/`

```text
crypto-experiments/data/results/raspberry-pi_experience1.csv
crypto-experiments/data/results/raspberry-pi_experience2.csv
crypto-experiments/data/results/raspberry-pi_experience3.csv
```

### Dossier `crypto-experiments/data/logs/`

```text
crypto-experiments/data/logs/pip_install.txt
crypto-experiments/data/logs/dependencies_check.txt
crypto-experiments/data/logs/kat_results.txt
crypto-experiments/data/logs/benchmark_output_experience1.txt
crypto-experiments/data/logs/benchmark_output_experience2.txt
crypto-experiments/data/logs/benchmark_output_experience3.txt
```

---

## Étape 8 — Configurer SSH pour pousser vers GitHub directement depuis le Pi

Pour éviter que `git push` demande un nom d'utilisateur et un mot de passe/token HTTPS, je configure une clé SSH.

### 8.1 — Générer une clé SSH

```bash
ssh-keygen -t ed25519 -C "melissa.moya@ssc-spc.gc.ca"
```

Quand il demande le chemin de sauvegarde, je peux simplement appuyer sur **Entrée** pour accepter la valeur par défaut :

```text
/home/melissamoya/.ssh/id_ed25519
```

### 8.2 — Afficher la clé publique

```bash
cat ~/.ssh/id_ed25519.pub
```

Je copie ensuite la ligne complète affichée.

### 8.3 — Ajouter la clé sur GitHub

Dans GitHub :
- aller à **Settings**
- puis **SSH and GPG keys**
- cliquer sur **New SSH key**
- choisir **Authentication Key**
- coller la clé publique
- enregistrer

### 8.4 — Basculer le dépôt local vers l'URL SSH

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique
git remote set-url origin git@github.com:moyamelissa/INF1430-Comparaison-Chiffrement-Symetrique.git
```

### 8.5 — Tester la connexion SSH

```bash
ssh -T git@github.com
```

Au premier essai, GitHub peut demander de confirmer l'empreinte du serveur. Je réponds :

```text
yes
```

Si tout fonctionne, un message semblable à celui-ci doit s'afficher :

```text
Hi moyamelissa! You've successfully authenticated, but GitHub does not provide shell access.
```

---

## Étape 9 — Commit et push des résultats vers GitHub

Une fois les trois exécutions terminées et les fichiers vérifiés, je peux les envoyer directement sur GitHub depuis le Raspberry Pi :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique
git status
git add crypto-experiments/data/results crypto-experiments/data/logs
git commit -m "Add Raspberry Pi benchmark runs and logs"
git push
```

À ce moment-là, les fichiers sont visibles sur GitHub.

---

## Étape 10 — Régénérer les graphiques de comparaison sur le laptop

Cette étape se fait sur le **laptop**, pas sur le Raspberry Pi.

Une fois les CSV du Pi poussés sur GitHub, je peux mettre à jour mon dépôt local sur le laptop, puis générer les graphiques de comparaison inter-plateformes :

```powershell
cd "C:\Users\xmeli\OneDrive\Documents\GitHub\INF1430-Comparaison-Chiffrement-Symetrique"
git pull
cd crypto-experiments
py scripts/compare_platforms.py
```

Les figures sont enregistrées dans `data/charts/comparison/`.

---

## Résumé des commandes (séquence complète sur le Raspberry Pi)

```bash
# 1. Installer les outils de base
python3 --version
sudo apt update
sudo apt install python3 python3-pip python3-venv git -y

# 2. Cloner le dépôt
cd ~
git clone https://github.com/moyamelissa/INF1430-Comparaison-Chiffrement-Symetrique.git
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments

# 3. Créer l'environnement virtuel et installer les dépendances
python3 -m venv .venv
source .venv/bin/activate
mkdir -p data/logs
pip install pycryptodome twofish > data/logs/pip_install.txt 2>&1

# 4. Corriger Twofish
nano .venv/lib/python3.13/site-packages/twofish.py
# Remplacer import imp par import importlib.util
# Remplacer _twofish = cdll.LoadLibrary(imp.find_module('_twofish')[1])
# par _twofish = cdll.LoadLibrary(importlib.util.find_spec('_twofish').origin)

# 5. Vérifier les dépendances
python -c "import Crypto; import twofish; print('Dependencies OK')" > data/logs/dependencies_check.txt 2>&1

# 6. KAT
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

# 10. Configurer SSH (une seule fois)
ssh-keygen -t ed25519 -C "melissa.moya@ssc-spc.gc.ca"
cat ~/.ssh/id_ed25519.pub
cd ~/INF1430-Comparaison-Chiffrement-Symetrique
git remote set-url origin git@github.com:moyamelissa/INF1430-Comparaison-Chiffrement-Symetrique.git
ssh -T git@github.com

# 11. Commit et push
cd ~/INF1430-Comparaison-Chiffrement-Symetrique
git add crypto-experiments/data/results crypto-experiments/data/logs
git commit -m "Add Raspberry Pi benchmark runs and logs"
git push
```
