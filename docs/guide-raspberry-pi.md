# Guide Raspberry Pi — Exécution des expériences de chiffrement
## Notes personnelles — INF1430

---

## Vue d'ensemble

Ce guide documente la procédure que j'ai suivie pour exécuter les expériences de benchmarking sur le Raspberry Pi. Il couvre le transfert du projet, l'installation des dépendances, le correctif obligatoire pour la librairie Twofish, l'exécution du benchmark et le rapatriement du fichier CSV.

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
sudo apt install python3 python3-pip -y
```

---

## Étape 1 — Copier le projet sur le Raspberry Pi

### Option A — Télécharger le ZIP (méthode recommandée)

Sur le Pi :

```bash
cd ~
wget https://github.com/moyamelissa/INF1430-Comparaison-Chiffrement-Symetrique/archive/refs/heads/main.zip -O main.zip
unzip main.zip
mv INF1430-Comparaison-Chiffrement-Symetrique-main INF1430-Comparaison-Chiffrement-Symetrique
cd INF1430-Comparaison-Chiffrement-Symetrique
```

> **Note** : avec cette méthode, le dossier n'est pas un dépôt Git. Pour rapatrier le CSV sur le laptop (Étape 6), utiliser SCP ou clé USB.

### Option B — Via clé USB

1. Je copie tout le dossier du projet sur une clé USB depuis le laptop.
2. Je branche la clé sur le Pi et je lance :

```bash
cp -r /media/pi/NOM_CLE/INF1430-Comparaison-Chiffrement-Symetrique ~/
cd ~/INF1430-Comparaison-Chiffrement-Symetrique
```

---

## Étape 2 — Installer les dépendances Python

Depuis le dossier `crypto-experiments/` sur le Pi :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
pip3 install pycryptodome twofish
```

Si pip3 n'est pas disponible :

```bash
sudo apt install python3-pip -y
pip3 install pycryptodome twofish
```

Le Pi est plus lent pour installer les paquets — c'est normal d'attendre quelques minutes.

---

## Étape 3 — Correctif obligatoire pour la librairie Twofish

La librairie `twofish` utilise `import imp`, qui est supprimé depuis Python 3.12. Je dois corriger ce fichier manuellement.

### 3.1 — Trouver le chemin du fichier twofish.py

```bash
python3 -c "import twofish; print(twofish.__file__)"
```

Le chemin ressemble à :
```
/home/pi/.local/lib/python3.11/site-packages/twofish.py
```

### 3.2 — Appliquer le correctif

```bash
nano /home/pi/.local/lib/python3.11/site-packages/twofish.py
```

Dans nano, je fais les deux modifications suivantes :

1. **Ctrl+W** → recherche `import imp` → remplace par `import importlib.util`
2. **Ctrl+W** → recherche `imp.find_module` → remplace la ligne contenant `imp.find_module('_twofish')[1]` par :
   ```python
   importlib.util.find_spec('_twofish').origin
   ```
3. **Ctrl+O** puis **Entrée** pour sauvegarder, puis **Ctrl+X** pour quitter.

### 3.3 — Vérifier le correctif

```bash
python3 -c "import twofish; print('Twofish OK')"
```

La sortie doit être `Twofish OK`.

---

## Étape 4 — Lancer le benchmark

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
python3 scripts/experiment.py
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

### Option A — Via SCP (méthode recommandée si le Pi est sur le même réseau)

Trouver l'adresse IP du Pi :

```bash
hostname -I
```

Depuis le laptop (PowerShell), remplacer `ADRESSE_IP_DU_PI` par l'IP affichée :

```powershell
scp pi@ADRESSE_IP_DU_PI:~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments/data/results/raspberry-pi_experience2.csv "C:\Users\xmeli\OneDrive\Documents\GitHub\INF1430-Comparaison-Chiffrement-Symetrique\crypto-experiments\data\results\"
```

### Option B — Via clé USB

Sur le Pi :

```bash
cp ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments/data/results/raspberry-pi_experience2.csv /media/pi/NOM_CLE/
```

Ensuite copier le fichier depuis la clé USB vers le dossier `data/results/` sur le laptop.

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
python3 scripts/run_kat.py
```

Les 26 tests doivent afficher `PASS`.

---

## Résumé des commandes (séquence complète)

```bash
# 1. Télécharger le projet
cd ~
wget https://github.com/moyamelissa/INF1430-Comparaison-Chiffrement-Symetrique/archive/refs/heads/main.zip -O main.zip
unzip main.zip
mv INF1430-Comparaison-Chiffrement-Symetrique-main INF1430-Comparaison-Chiffrement-Symetrique
cd ~/INF1430-Comparaison-Chiffrement-Symetrique

# 2. Installation des dépendances
cd crypto-experiments
pip3 install pycryptodome twofish

# 3. Trouver le chemin twofish.py pour le correctif
python3 -c "import twofish; print(twofish.__file__)"
# Éditer le fichier avec nano (voir Étape 3)

# 4. Valider le correctif
python3 -c "import twofish; print('Twofish OK')"

# 5. KAT (validation fonctionnelle)
python3 scripts/run_kat.py

# 6. Benchmark
python3 scripts/experiment.py

# 7. Renommer le CSV
cd data/results
mv experiment_*.csv raspberry-pi_experience2.csv
```
