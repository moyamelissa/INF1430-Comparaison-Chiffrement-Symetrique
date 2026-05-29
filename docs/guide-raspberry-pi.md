# Guide Raspberry Pi — Exécution des expériences de chiffrement
## Notes personnelles — INF1430

---

## Vue d'ensemble

Ce guide documente la procédure que j'ai suivie pour exécuter les expériences de benchmarking sur le Raspberry Pi. Il couvre le transfert du projet, l'installation des dépendances dans un environnement virtuel Python, le correctif obligatoire pour la librairie Twofish, l'exécution du benchmark et le rapatriement du fichier CSV.

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
> **Note** : avec cette méthode, le dossier n'est pas un dépôt Git. Pour rapatrier le CSV sur le laptop (Étape 6), utiliser SCP.

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

## Étape 4 — Lancer le benchmark

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
python scripts/experiment.py
```

Le script parcourt toutes les combinaisons (algorithme, mode, taille de clé, taille de message), affiche sa progression, et écrit les résultats dans `data/results/`. L'exécution prend entre 10 et 30 minutes selon le modèle du Pi.

---

## Étape 5 — Renommer le fichier CSV produit

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments/data/results
ls *.csv
```

Le fichier généré porte un nom horodaté (ex. `experiment_20260510_143022.csv`). Je le renomme pour suivre la convention du projet :

```bash
mv experiment_*.csv raspberry-pi_experience2.csv
```

---

## Étape 6 — Rapatrier le CSV sur le laptop

Trouver l'adresse IP du Pi :

```bash
hostname -I
```

Depuis le laptop (PowerShell), remplacer `ADRESSE_IP_DU_PI` par l'IP affichée :

```powershell
scp pi@ADRESSE_IP_DU_PI:~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments/data/results/raspberry-pi_experience2.csv "C:\Users\xmeli\OneDrive\Documents\GitHub\INF1430-Comparaison-Chiffrement-Symetrique\crypto-experiments\data\results\"
```

---

## Étape 7 — Régénérer les graphiques de comparaison

Une fois le CSV du Pi dans `data/results/`, je génère les graphiques de comparaison inter-plateformes depuis le laptop :

```powershell
cd "C:\Users\xmeli\OneDrive\Documents\GitHub\INF1430-Comparaison-Chiffrement-Symetrique\crypto-experiments"
py scripts/compare_platforms.py
```

Les figures sont enregistrées dans `data/charts/comparison/`.

---

## Étape optionnelle — Valider les KAT sur le Pi

Pour confirmer que le code produit les mêmes résultats sur l'architecture ARM :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
python scripts/run_kat.py
```

Les 26 tests doivent afficher `PASS`.

---

## Résumé des commandes (séquence complète)

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
