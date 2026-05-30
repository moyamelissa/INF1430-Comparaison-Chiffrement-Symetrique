# Validation de la procédure Raspberry Pi
## Journal d’exécution — INF1430

Ce document consigne les sorties observées lors de l’exécution réelle de la procédure décrite dans `docs/guide-raspberry-pi.md`.

---

## Contexte d’exécution

- Machine : Raspberry Pi
- Dépôt : `moyamelissa/INF1430-Comparaison-Chiffrement-Symetrique`
- Date : 2026-05-29

---

## Étape 0 — Prérequis

### Commandes exécutées

```bash
python3 --version
sudo apt update
sudo apt install python3 python3-pip python3-venv git -y
```

### Sortie observée

```text
(.venv) melissamoya@raspberrypi:~/INF1430-Comparaison-Chiffrement-Symetrique $ python3 --version
sudo apt update
sudo apt install python3 python3-pip python3-venv git -y
Python 3.13.5
Hit:1 http://deb.debian.org/debian trixie InRelease
Get:2 http://deb.debian.org/debian trixie-updates InRelease [47.3 kB]
Get:3 http://deb.debian.org/debian-security trixie-security InRelease [43.4 kB]
Hit:4 https://linux.teamviewer.com/deb stable InRelease
Hit:5 https://linux.teamviewer.com/deb preview InRelease
Get:6 http://archive.raspberrypi.com/debian trixie InRelease [54.9 kB]
Get:7 http://archive.raspberrypi.com/debian trixie/main arm64 Packages [449 kB]
Fetched 594 kB in 2s (344 kB/s)
409 packages can be upgraded. Run 'apt list --upgradable' to see them.
python3 is already the newest version (3.13.5-1).
python3-pip is already the newest version (25.1.1+dfsg-1+rpt1).
python3-pip set to manually installed.
python3-venv is already the newest version (3.13.5-1).
git is already the newest version (1:2.47.3-0+deb13u1).
Summary:
  Upgrading: 0, Installing: 0, Removing: 0, Not Upgrading: 409
```

### Conclusion

Étape validée.

- Python 3.13.5 est installé.
- Les paquets `python3`, `python3-pip`, `python3-venv` et `git` sont déjà présents.
- Aucun paquet supplémentaire n’a dû être installé.
- La présence de Python 3.13 confirme que le correctif `twofish` documenté plus loin sera nécessaire.

---

## Étape 1 — Configuration SSH

### Commandes exécutées

```bash
ssh-keygen -t ed25519 -C "melissa.moya@ssc-spc.gc.ca"
git remote set-url origin git@github.com:moyamelissa/INF1430-Comparaison-Chiffrement-Symetrique.git
cat ~/.ssh/id_ed25519.pub
ssh -T git@github.com
```

### Sortie observée

```text
(.venv) melissamoya@raspberrypi:~/INF1430-Comparaison-Chiffrement-Symetrique $ ssh-keygen -t ed25519 -C "melissa.moya@ssc-spc.gc.ca"
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/melissamoya/.ssh/id_ed25519): /home/melissamoya/.ssh/id_ed25519
Enter passphrase for "/home/melissamoya/.ssh/id_ed25519" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/melissamoya/.ssh/id_ed25519
Your public key has been saved in /home/melissamoya/.ssh/id_ed25519.pub
The key fingerprint is:
SHA256:IjkNLfNoDsJuyV6O7Zel3e2E4gCbiIAOkyXpPMi7yMc melissa.moya@ssc-spc.gc.ca
The key's randomart image is:
+--[ED25519 256]--+
|                 |
| .   .           |
|o . + .          |
|B+   O           |
|O*..* + S        |
|Bo=++o o  .      |
|.O.+..=.....     |
|= *E +o.....     |
|.=o+.  .  ..     |
+----[SHA256]-----+
(.venv) melissamoya@raspberrypi:~/INF1430-Comparaison-Chiffrement-Symetrique $ git remote set-url origin git@github.com:moyamelissa/INF1430-Comparaison-Chiffrement-Symetrique.git
(.venv) melissamoya@raspberrypi:~/INF1430-Comparaison-Chiffrement-Symetrique $ cat ~/.ssh/id_ed25519.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOv+Xwjux7E48OLmClk8d0K+VcDlPdv9gQN+AL4cQHbM melissa.moya@ssc-spc.gc.ca
(.venv) melissamoya@raspberrypi:~/INF1430-Comparaison-Chiffrement-Symetrique $ ssh -T git@github.com
Hi moyamelissa! You've successfully authenticated, but GitHub does not provide shell access.
```

### Conclusion

Étape validée.

- Une nouvelle clé SSH `ed25519` a été générée.
- La clé privée a été enregistrée dans `/home/melissamoya/.ssh/id_ed25519`.
- La clé publique a été enregistrée dans `/home/melissamoya/.ssh/id_ed25519.pub`.
- L’URL du dépôt `origin` a été basculée vers le format SSH.
- La clé publique est lisible depuis le système.
- L’authentification SSH vers GitHub fonctionne correctement.

---

## Étape 2 — Clonage du dépôt

### Commandes exécutées

```bash
cd ~
git clone git@github.com:moyamelissa/INF1430-Comparaison-Chiffrement-Symetrique.git
cd INF1430-Comparaison-Chiffrement-Symetrique
```

### Sortie observée

```text
(.venv) melissamoya@raspberrypi:~/INF1430-Comparaison-Chiffrement-Symetrique $ cd ~
git clone git@github.com:moyamelissa/INF1430-Comparaison-Chiffrement-Symetrique.git
cd INF1430-Comparaison-Chiffrement-Symetrique
Cloning into 'INF1430-Comparaison-Chiffrement-Symetrique'...
remote: Enumerating objects: 320, done.
remote: Counting objects: 100% (320/320), done.
remote: Compressing objects: 100% (230/230), done.
remote: Total 320 (delta 129), reused 219 (delta 76), pack-reused 0 (from 0)
Receiving objects: 100% (320/320), 26.95 MiB | 1.01 MiB/s, done.
Resolving deltas: 100% (129/129), done.
(.venv) melissamoya@raspberrypi:~/INF1430-Comparaison-Chiffrement-Symetrique $
```

### Conclusion

Étape validée.

- Le dépôt a été cloné avec succès depuis GitHub via SSH.
- Le dossier local `~/INF1430-Comparaison-Chiffrement-Symetrique` a été créé.
- La procédure peut se poursuivre dans le dépôt cloné.

---

## Étape 3 — Création de l’environnement virtuel et installation des dépendances

### Commandes exécutées

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
python3 -m venv .venv
source .venv/bin/activate
mkdir -p data/logs
pip install pycryptodome twofish > data/logs/pip_install.txt 2>&1
cat data/logs/pip_install.txt
```

### Sortie observée

```text
(.venv) melissamoya@raspberrypi:~/INF1430-Comparaison-Chiffrement-Symetrique $ cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
python3 -m venv .venv
source .venv/bin/activate
mkdir -p data/logs
pip install pycryptodome twofish > data/logs/pip_install.txt 2>&1
cat data/logs/pip_install.txt
Looking in indexes: https://pypi.org/simple, https://www.piwheels.org/simple
Requirement already satisfied: pycryptodome in ./.venv/lib/python3.13/site-packages (3.23.0)
Requirement already satisfied: twofish in ./.venv/lib/python3.13/site-packages (0.3.0)
(.venv) melissamoya@raspberrypi:~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments $
```

### Conclusion

Étape validée.

- Les commandes ont été exécutées dans le bon dossier : `crypto-experiments`.
- L’environnement virtuel `.venv` est présent et activé.
- Le dossier `data/logs` existe.
- Le fichier `data/logs/pip_install.txt` a bien été créé.
- Les dépendances `pycryptodome` et `twofish` sont déjà installées dans l’environnement virtuel.

---

## Étape 4 — Correction de la librairie Twofish pour Python 3.13

### Commandes exécutées

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
nano .venv/lib/python3.13/site-packages/twofish.py
```

### Extrait du fichier corrigé

```python
import importlib.util
import sys

from ctypes import (cdll, Structure,
                    POINTER, pointer,
                    c_char_p, c_int, c_uint32,
                    create_string_buffer)

_twofish = cdll.LoadLibrary(importlib.util.find_spec('_twofish').origin)
```

### Conclusion

Étape validée.

- Le fichier `.venv/lib/python3.13/site-packages/twofish.py` a été corrigé pour Python 3.13.
- L’instruction `import imp` a été remplacée par `import importlib.util`.
- Le chargement de la librairie `_twofish` utilise désormais `importlib.util.find_spec('_twofish').origin`.

---

## Étape 5 — Vérification des dépendances

### Commandes exécutées

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
mkdir -p data/logs
python -c "import Crypto; import twofish; print('Dependencies OK')" > data/logs/dependencies_check.txt 2>&1
cat data/logs/dependencies_check.txt
```

### Sortie observée

```text
(.venv) melissamoya@raspberrypi:~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments $ cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
mkdir -p data/logs
python -c "import Crypto; import twofish; print('Dependencies OK')" > data/logs/dependencies_check.txt 2>&1
cat data/logs/dependencies_check.txt
Dependencies OK
(.venv) melissamoya@raspberrypi:~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments $
```

### Conclusion

Étape validée.

- Les modules `Crypto` et `twofish` peuvent être importés correctement.
- Le correctif appliqué à `twofish.py` fonctionne.
- Le fichier `data/logs/dependencies_check.txt` a été généré avec succès.
