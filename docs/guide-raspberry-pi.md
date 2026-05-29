# Guide Raspberry Pi — Exécution des expériences de chiffrement
## Notes personnelles — INF1430

---

## Vue d'ensemble

Ce guide documente la procédure que j'ai suivie pour exécuter les expériences de benchmarking sur le Raspberry Pi. Il couvre toutes les étapes à faire sur le Raspberry Pi en premier, la sauvegarde des résultats localement sur le Pi, puis l'import manuel des fichiers sur le laptop pour régénérer les graphiques.

**Durée estimée** : 20 à 45 minutes selon la connexion et le modèle de Pi.

---

## Étape 0 — Prérequis sur le Raspberry Pi

Le Pi doit être allumé et connecté au réseau. Je commence par vérifier que Python 3 est bien installé :

```bash
python3 --version
```

Si la version affichée est `Python 3.11.x` ou plus récente, c'est suffisant. Sinon, j'installe Python via apt :

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv -y
```

---

## Étape 1 — Télécharger le ZIP

Sur le Pi :

```bash
cd ~
wget https://github.com/moyamelissa/INF1430-Comparaison-Chiffrement-Symetrique/archive/refs/heads/main.zip -O main.zip
sudo apt update
sudo apt install unzip -y
unzip main.zip
mv INF1430-Comparaison-Chiffrement-Symetrique-main INF1430-Comparaison-Chiffrement-Symetrique
cd INF1430-Comparaison-Chiffrement-Symetrique
```

> **Note** : si la commande `unzip` n'existe pas sur le Raspberry Pi, l'installation ci-dessus l'ajoute.
>
> **Note** : avec cette méthode, le dossier n'est pas un dépôt Git. Tous les fichiers produits sur le Pi seront donc enregistrés localement dans le dossier du projet, puis importés manuellement sur le laptop à la fin.

---

## Étape 2 — Créer un environnement virtuel et installer les dépendances Python

Depuis le dossier `crypto-experiments/` sur le Pi :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
python3 -m venv .venv
source .venv/bin/activate
pip install pycryptodome twofish
```

> **Pourquoi cette étape ?** Sur les versions récentes de Raspberry Pi OS, `pip3 install` peut être bloqué par la protection `externally-managed-environment`. L'environnement virtuel évite ce problème.

Pour vérifier que l'environnement virtuel est actif, le terminal doit afficher `(.venv)` au début de la ligne.

Si j'ouvre un nouveau terminal plus tard, je réactive l'environnement virtuel avec :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
```

---

## Étape 3 — Correctif obligatoire pour la librairie Twofish

La librairie `twofish` utilise `import imp`, qui est supprimé depuis Python 3.12. Je dois corriger ce fichier manuellement dans l'environnement virtuel.

### 3.1 — Ouvrir le fichier twofish.py

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
nano .venv/lib/python3.13/site-packages/twofish.py
```

> **Note** : le chemin contient ici `python3.13` parce que c'est la version installée sur mon Raspberry Pi. Si une autre version de Python est installée, le dossier peut être différent.

### 3.2 — Appliquer le correctif

Dans nano, je fais les deux modifications suivantes :

1. **Ctrl+W** → recherche `import imp` → remplace par `import importlib.util`
2. **Ctrl+W** → recherche `imp.find_module` → remplace la ligne contenant `imp.find_module('_twofish')[1]` par :
   ```python
   importlib.util.find_spec('_twofish').origin
   ```
3. **Ctrl+O** puis **Entrée** pour sauvegarder, puis **Ctrl+X** pour quitter.

### 3.3 — Vérifier le correctif

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
python -c "import Crypto; import twofish; print('Dependencies OK')"
```

La sortie doit être `Dependencies OK`.

---

## Étape 4 — Valider les KAT sur le Pi

Avant de lancer le benchmark complet, je valide que l'implémentation fonctionne correctement sur l'architecture ARM :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
python scripts/run_kat.py
```

Les 26 tests doivent afficher `PASS`.

> **Note** : la sortie des tests s'affiche dans le terminal. Si tous les tests passent, cela confirme que les algorithmes produisent les résultats attendus sur le Raspberry Pi.

---

## Étape 5 — Lancer le benchmark

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
python scripts/experiment.py
```

Le script parcourt toutes les combinaisons (algorithme, mode, taille de clé, taille de message), affiche sa progression, puis enregistre automatiquement les résultats dans `data/results/`.

Sur le Raspberry Pi, cette étape peut prendre entre 10 et 30 minutes selon le modèle et la charge du système.

À la fin, une ligne semblable à celle-ci doit apparaître :

```bash
Results saved to: /home/melissamoya/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments/data/results/experiment_20260529_131838.csv
```

---

## Étape 6 — Renommer le fichier CSV produit

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments/data/results
ls *.csv
```

Le fichier généré porte un nom horodaté (ex. `experiment_20260529_131838.csv`). Je le renomme pour suivre la convention du projet :

```bash
mv experiment_*.csv raspberry-pi_experience2.csv
```

À ce stade, tous les fichiers produits sur le Raspberry Pi sont enregistrés localement dans le projet.

---

## Étape 7 — Importer manuellement les fichiers sur le laptop

Une fois le travail terminé sur le Pi, je récupère manuellement les fichiers utiles sur mon laptop.

Le fichier principal à importer est :

```text
crypto-experiments/data/results/raspberry-pi_experience2.csv
```

Je peux le transférer manuellement de la façon qui me convient :
- en l'ouvrant depuis le Raspberry Pi puis en le téléversant dans GitHub,
- en utilisant une clé USB,
- ou en le copiant ensuite dans mon dossier local du projet sur le laptop.

L'objectif est simplement que `raspberry-pi_experience2.csv` se retrouve dans le dossier suivant sur le laptop :

```text
crypto-experiments/data/results/
```

---

## Étape 8 — Régénérer les graphiques de comparaison sur le laptop

Cette étape se fait sur le **laptop**, pas sur le Raspberry Pi.

Une fois le CSV du Pi placé dans `data/results/` sur le laptop, je génère les graphiques de comparaison inter-plateformes :

```powershell
cd "C:\Users\xmeli\OneDrive\Documents\GitHub\INF1430-Comparaison-Chiffrement-Symetrique\crypto-experiments"
py scripts/compare_platforms.py
```

Les figures sont enregistrées dans `data/charts/comparison/`.

> **Important** : ces commandes sont des commandes Windows/PowerShell. Elles doivent être exécutées sur le laptop, et non sur le Raspberry Pi.

---

## Résumé des commandes (séquence complète sur le Raspberry Pi)

```bash
# 1. Télécharger le projet
cd ~
wget https://github.com/moyamelissa/INF1430-Comparaison-Chiffrement-Symetrique/archive/refs/heads/main.zip -O main.zip
sudo apt update
sudo apt install unzip -y
unzip main.zip
mv INF1430-Comparaison-Chiffrement-Symetrique-main INF1430-Comparaison-Chiffrement-Symetrique
cd ~/INF1430-Comparaison-Chiffrement-Symetrique

# 2. Créer et activer l'environnement virtuel
cd crypto-experiments
python3 -m venv .venv
source .venv/bin/activate
pip install pycryptodome twofish

# 3. Corriger Twofish
nano .venv/lib/python3.13/site-packages/twofish.py
# Remplacer import imp par import importlib.util
# Remplacer imp.find_module('_twofish')[1] par importlib.util.find_spec('_twofish').origin

# 4. Vérifier les dépendances
python -c "import Crypto; import twofish; print('Dependencies OK')"

# 5. KAT (validation fonctionnelle)
python scripts/run_kat.py

# 6. Benchmark
python scripts/experiment.py

# 7. Renommer le CSV
cd data/results
mv experiment_*.csv raspberry-pi_experience2.csv
```
