# Guide Raspberry Pi — Exécution des expériences de chiffrement
## Notes personnelles — INF1430

---

## Vue d'ensemble

Ce guide documente la procédure que j'ai suivie pour exécuter les expériences de benchmarking sur le Raspberry Pi. Il couvre le transfert du projet, l'installation des dépendances, le correctif obligatoire pour la librairie Twofish, et le rapatriement des résultats sur le laptop.

**Durée estimée** : 20 à 45 minutes selon la connexion et le modèle de Pi.

---

## tape 0 — Prérequis sur le Raspberry Pi

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

## tape 1 — Copier le projet sur le Raspberry Pi

### Option A — Via Git (méthode que j'utilise)

Sur le Pi :

```bash
cd ~
git clone https://github.com/xmeli/INF1430-Comparaison-Chiffrement-Symetrique.git
cd INF1430-Comparaison-Chiffrement-Symetrique
```

Si le dépôt est déjà cloné et que je veux juste récupérer les dernières modifications :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique
git pull
```

### Option B — Via clé USB

1. Je copie tout le dossier du projet sur une clé USB depuis le laptop.
2. Je branche la clé sur le Pi et je lance :

```bash
cp -r /media/pi/NOM_CLE/INF1430-Comparaison-Chiffrement-Symetrique ~/
cd ~/INF1430-Comparaison-Chiffrement-Symetrique
```

---

## tape 2 — Installer les dépendances Python

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

## tape 3 — Correctif obligatoire pour la librairie Twofish

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

## tape 4 — Lancer le benchmark

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
python3 scripts/experiment.py
```

Le script parcourt toutes les combinaisons (algorithme  mode  taille de clé  taille de message), affiche sa progression, et écrit les résultats dans `data/results/`. L'exécution prend entre 10 et 30 minutes sur le Pi — je ne ferme pas le terminal.

---

## tape 5 — Renommer le fichier CSV produit

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments/data/results
ls *.csv
```

Le fichier généré porte un nom horodaté (ex. `experiment_20260510_143022.csv`). Je le renomme pour suivre la convention du projet :

```bash
mv experiment_*.csv raspberry-pi_experience2.csv
```

---

## tape 6 — Rapatrier le CSV sur le laptop

### Option A — Via Git (méthode que j'utilise)

Sur le Pi :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique
git add crypto-experiments/data/results/raspberry-pi_experience2.csv
git commit -m "Ajout des résultats Raspberry Pi (expérience 2)"
git push
```

Sur le laptop (PowerShell) :

```powershell
cd "C:\Users\xmeli\OneDrive\Documents\GitHub\INF1430-Comparaison-Chiffrement-Symetrique"
git pull
```

### Option B — Via SCP (si le Pi est sur le même réseau)

Depuis le laptop :

```powershell
scp pi@ADRESSE_IP_DU_PI:~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments/data/results/raspberry-pi_experience2.csv "C:\Users\xmeli\OneDrive\Documents\GitHub\INF1430-Comparaison-Chiffrement-Symetrique\crypto-experiments\data\results\"
```

Je trouve l'adresse IP du Pi avec `hostname -I` sur le Pi.

---

## tape 7 — Régénérer les graphiques de comparaison

Une fois le CSV du Pi dans `data/results/`, je génère les graphiques de comparaison inter-plateformes depuis le laptop :

```powershell
cd "C:\Users\xmeli\OneDrive\Documents\GitHub\INF1430-Comparaison-Chiffrement-Symetrique\crypto-experiments"
py scripts/compare_platforms.py
```

Les figures sont enregistrées dans `data/charts/comparison/`.

---

## tape optionnelle — Valider les KAT sur le Pi

Pour confirmer que le code produit les mêmes résultats sur l'architecture ARM :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
python3 scripts/run_kat.py
```

Les 26 tests doivent afficher `PASS`.

---

## Résumé des commandes (séquence complète)

```bash
# 1. Mise à jour du dépôt
cd ~/INF1430-Comparaison-Chiffrement-Symetrique
git pull

# 2. Installation des dépendances
cd crypto-experiments
pip3 install pycryptodome twofish

# 3. Trouver le chemin twofish.py pour le correctif
python3 -c "import twofish; print(twofish.__file__)"
# diter le fichier avec nano (voir tape 3)

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
