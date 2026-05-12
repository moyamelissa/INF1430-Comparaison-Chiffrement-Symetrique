# Guide Raspberry Pi — Étape par étape
## Comment exécuter les expériences de chiffrement sur le Raspberry Pi

---

## Ce que tu vas faire

Tu vas copier ton projet sur le Raspberry Pi, installer les dépendances, appliquer un correctif à la librairie Twofish, puis lancer le benchmark. À la fin, tu auras un fichier CSV avec les résultats du Pi que tu copieras sur ton laptop.

**Durée estimée** : 20 à 45 minutes selon ta connexion et le modèle de Pi.

---

## ÉTAPE 0 — Prérequis sur le Raspberry Pi

### Le Pi doit être allumé et connecté au réseau.

Sur le Pi, ouvre un terminal (ou connecte-toi en SSH depuis ton laptop).

Vérifie que Python 3 est installé :

```bash
python3 --version
```

Si tu vois `Python 3.11.x` ou plus récent, c'est bon. Sinon :

```bash
sudo apt update
sudo apt install python3 python3-pip -y
```

---

## ÉTAPE 1 — Copier le projet sur le Raspberry Pi

Tu as deux options. Choisis la plus simple pour toi :

### Option A — Via Git (recommandé si le dépôt est sur GitHub)

Sur le Pi :

```bash
cd ~
git clone https://github.com/TON-NOM-UTILISATEUR/INF1430-Comparaison-Chiffrement-Symetrique.git
cd INF1430-Comparaison-Chiffrement-Symetrique
```

> Remplace `TON-NOM-UTILISATEUR` par ton nom d'utilisateur GitHub.

Si tu as déjà cloné avant et veux juste mettre à jour :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique
git pull
```

### Option B — Via clé USB

1. Sur ton laptop, copie tout le dossier du projet sur une clé USB.
2. Branche la clé sur le Pi.
3. Dans le terminal du Pi :

```bash
cp -r /media/pi/NOM_CLE/INF1430-Comparaison-Chiffrement-Symetrique ~/
cd ~/INF1430-Comparaison-Chiffrement-Symetrique
```

---

## ÉTAPE 2 — Installer les dépendances Python

Dans le terminal du Pi, depuis le dossier du projet :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
pip3 install pycryptodome twofish
```

Si pip3 n'est pas disponible :

```bash
sudo apt install python3-pip -y
pip3 install pycryptodome twofish
```

Attends que l'installation soit terminée. Le Pi peut être lent — c'est normal.

---

## ÉTAPE 3 — Corriger la librairie Twofish (OBLIGATOIRE)

La librairie `twofish` utilise une commande obsolète (`import imp`) qui ne fonctionne plus avec Python 3.12+. Il faut la corriger manuellement.

### 3.1 — Trouve le fichier twofish.py sur le Pi

```bash
python3 -c "import twofish; print(twofish.__file__)"
```

Tu verras un chemin comme :
```
/home/pi/.local/lib/python3.11/site-packages/twofish.py
```

Copie ce chemin — tu en as besoin à l'étape suivante.

### 3.2 — Applique le correctif

Remplace `TON_CHEMIN` par le chemin trouvé ci-dessus :

```bash
nano TON_CHEMIN
```

Exemple :
```bash
nano /home/pi/.local/lib/python3.11/site-packages/twofish.py
```

Dans nano :
1. Cherche la ligne `import imp` avec **Ctrl+W**, tape `import imp`, puis Entrée.
2. Remplace `import imp` par `import importlib.util`
3. Cherche maintenant `imp.find_module` avec **Ctrl+W**.
4. Remplace la ligne qui contient `imp.find_module('_twofish')[1]` par :
   ```python
   importlib.util.find_spec('_twofish').origin
   ```
5. Sauvegarde : **Ctrl+O** puis **Entrée**.
6. Quitte : **Ctrl+X**.

### 3.3 — Vérifie que ça fonctionne

```bash
python3 -c "import twofish; print('Twofish OK')"
```

Tu dois voir `Twofish OK`. Si tu vois une erreur, relis l'étape 3.2.

---

## ÉTAPE 4 — Lancer le benchmark

Depuis le dossier `crypto-experiments/` :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
python3 scripts/experiment.py
```

Le script va :
- Tester toutes les combinaisons (algorithme × mode × taille de clé × taille de message)
- Afficher sa progression dans le terminal
- Écrire les résultats dans `data/results/`

**Le Pi est plus lent que ton laptop — cela peut prendre 10 à 30 minutes.** C'est normal. Ne ferme pas le terminal.

---

## ÉTAPE 5 — Renommer le fichier CSV produit

Le script génère un nom avec la date. Renomme-le pour qu'il soit cohérent avec la convention du projet :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments/data/results
ls *.csv
```

Tu verras un fichier comme `experiment_20260510_143022.csv`. Renomme-le :

```bash
mv experiment_XXXXXXXXXX_XXXXXX.csv raspberry-pi_experience2.csv
```

> Remplace `experiment_XXXXXXXXXX_XXXXXX.csv` par le vrai nom affiché.

---

## ÉTAPE 6 — Copier le CSV sur ton laptop

Encore deux options :

### Option A — Via Git

Sur le Pi :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique
git add crypto-experiments/data/results/raspberry-pi_experience2.csv
git commit -m "Ajout des résultats Raspberry Pi (expérience 2)"
git push
```

Sur ton laptop (PowerShell) :

```powershell
cd "C:\Users\xmeli\OneDrive\Documents\GitHub\INF1430-Comparaison-Chiffrement-Symetrique"
git pull
```

### Option B — Via clé USB ou SCP

**Clé USB** : copie le fichier depuis `~/INF1430.../crypto-experiments/data/results/raspberry-pi_experience2.csv` sur la clé, puis colle-le dans `data/results/` sur ton laptop.

**SCP** (depuis ton laptop, si le Pi est sur le même réseau) :

```powershell
scp pi@ADRESSE_IP_DU_PI:~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments/data/results/raspberry-pi_experience2.csv "C:\Users\xmeli\OneDrive\Documents\GitHub\INF1430-Comparaison-Chiffrement-Symetrique\crypto-experiments\data\results\"
```

> Remplace `ADRESSE_IP_DU_PI` par l'IP de ton Pi (trouve-la avec `hostname -I` sur le Pi).

---

## ÉTAPE 7 — Régénérer les graphiques avec les deux jeux de données

Une fois le CSV du Pi dans `data/results/`, sur ton laptop :

```powershell
cd "C:\Users\xmeli\OneDrive\Documents\GitHub\INF1430-Comparaison-Chiffrement-Symetrique\crypto-experiments"
py scripts/generate_charts.py
```

> ⚠️ Le script lit le **dernier CSV en ordre alphabétique**. Avec les noms actuels, il lira `raspberry-pi_experience2.csv`. Pour comparer les deux plateformes dans les graphiques, il faudra modifier `generate_charts.py` — demande à Copilot de le faire quand tu as les deux CSVs.

---

## ÉTAPE OPTIONNELLE — Valider les KAT sur le Pi

Pour confirmer que le code fonctionne correctement sur l'architecture ARM du Pi :

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
python3 scripts/run_kat.py
```

Tu dois voir 26 tests `PASS`. Si l'un échoue, note lequel et demande à Copilot.

---

## Résumé des commandes (copier-coller)

```bash
# Sur le Pi — tout d'un coup après le clone/pull

cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments

pip3 install pycryptodome twofish

# Correctif twofish — trouve le chemin
python3 -c "import twofish; print(twofish.__file__)"
# Puis édite le fichier avec nano (voir Étape 3)

# KAT (optionnel)
python3 scripts/run_kat.py

# Benchmark
python3 scripts/experiment.py

# Renommer le CSV
cd data/results
mv experiment_*.csv raspberry-pi_experience2.csv
```
