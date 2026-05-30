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

---

## Étape 6 — Validation des KAT

### Commandes exécutées

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
mkdir -p data/logs
python scripts/run_kat.py > data/logs/kat_results.txt 2>&1
cat data/logs/kat_results.txt
```

### Sortie observée

```text
(.venv) melissamoya@raspberrypi:~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments $ cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
mkdir -p data/logs
python scripts/run_kat.py > data/logs/kat_results.txt 2>&1
cat data/logs/kat_results.txt

───────────────────────────────────────────────────────
  AES  (FIPS 197)
───────────────────────────────────────────────────────
  [PASS] FIPS197 App-B AES-128 encrypt
  [PASS] FIPS197 App-B AES-128 encrypt (decrypt round-trip)
  [PASS] FIPS197 App-A.1 AES-128 zero-key zero-plain
  [PASS] FIPS197 App-A.1 AES-128 zero-key zero-plain (decrypt round-trip)
  [PASS] FIPS197 App-C.2 AES-192 encrypt
  [PASS] FIPS197 App-C.2 AES-192 encrypt (decrypt round-trip)
  [PASS] FIPS197 App-C.3 AES-256 encrypt
  [PASS] FIPS197 App-C.3 AES-256 encrypt (decrypt round-trip)
  ✓ All tests passed.

───────────────────────────────────────────────────────
  DES  (SP 800-17)
───────────────────────────────────────────────────────
  [PASS] SP800-17 Table1 P=8000000000000000
  [PASS] SP800-17 Table1 P=8000000000000000 (decrypt round-trip)
  [PASS] SP800-17 Table1 P=4000000000000000
  [PASS] SP800-17 Table1 P=4000000000000000 (decrypt round-trip)
  [PASS] SP800-17 Table1 P=2000000000000000
  [PASS] SP800-17 Table1 P=2000000000000000 (decrypt round-trip)
  [PASS] SP800-17 Table1 P=1000000000000000
  [PASS] SP800-17 Table1 P=1000000000000000 (decrypt round-trip)
  [PASS] SP800-17 Table1 P=0800000000000000
  [PASS] SP800-17 Table1 P=0800000000000000 (decrypt round-trip)
  [PASS] SP800-17 Table1 P=0400000000000000
  [PASS] SP800-17 Table1 P=0400000000000000 (decrypt round-trip)
  [PASS] SP800-17 Table1 P=0200000000000000
  [PASS] SP800-17 Table1 P=0200000000000000 (decrypt round-trip)
  [PASS] SP800-17 Table1 P=0100000000000000
  [PASS] SP800-17 Table1 P=0100000000000000 (decrypt round-trip)
  [PASS] SP800-17 Table1 P=0000000000000001
  [PASS] SP800-17 Table1 P=0000000000000001 (decrypt round-trip)
  ✓ All tests passed.

───────────────────────────────────────────────────────
  3DES (SP 800-67)
───────────────────────────────────────────────────────
  [PASS] 3DES-2key TDEA K1≠K2 plain=0x00..00
  [PASS] 3DES-2key TDEA K1≠K2 plain=0x00..00 (decrypt round-trip)
  [PASS] 3DES-3key TDEA K1≠K2≠K3 plain=0x00..00
  [PASS] 3DES-3key TDEA K1≠K2≠K3 plain=0x00..00 (decrypt round-trip)
  ✓ All tests passed.

───────────────────────────────────────────────────────
  Modes ECB/CBC/CTR (SP 800-38A)
───────────────────────────────────────────────────────
  [PASS] SP800-38A F.1.1 ECB-AES128 Encrypt
  [PASS] SP800-38A F.1.2 ECB-AES128 Decrypt round-trip
  [PASS] SP800-38A F.2.1 CBC-AES128 Encrypt
  [PASS] SP800-38A F.2.2 CBC-AES128 Decrypt round-trip
  [PASS] CTR-AES128 keystream block-0 spot-check (counter=0)
  [PASS] CTR-AES128 encrypt→decrypt round-trip (4 blocks)
  ✓ All tests passed.

───────────────────────────────────────────────────────
  AES-GCM (SP 800-38D)
───────────────────────────────────────────────────────
  [PASS] SP800-38D TC3 AES-128-GCM encrypt
  [PASS] SP800-38D TC3 AES-128-GCM decrypt/verify round-trip
  [PASS] SP800-38D TC3 AES-128-GCM tamper detection
  [PASS] SP800-38D TC4 AES-128-GCM with AAD encrypt
  [PASS] SP800-38D TC4 AES-128-GCM with AAD decrypt/verify round-trip
  [PASS] SP800-38D TC4 AES-128-GCM with AAD tamper detection
  ✓ All tests passed.

───────────────────────────────────────────────────────
  ChaCha20 (RFC 8439)
───────────────────────────────────────────────────────
    PASS  RFC 8439 §2.4.2 — vecteur de chiffrement ChaCha20 (compteur=1)
    PASS  RFC 8439 aller-retour wrapper — 64 B
    PASS  RFC 8439 aller-retour wrapper — 256 B
    PASS  RFC 8439 aller-retour wrapper — 113 B (odd)
    PASS  ChaCha20 falsification — l'octet inversé produit un texte clair différent
    PASS  ChaCha20 rejette une clé de 16 octets (doit être 32 octets)
  ✓ All tests passed.

═══════════════════════════════════════════════════════
  ALL KAT SUITES PASSED
═══════════════════════════════════════════════════════

(.venv) melissamoya@raspberrypi:~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments $
```

### Conclusion

Étape validée.

- Le script `scripts/run_kat.py` s’exécute correctement sur le Raspberry Pi.
- Toutes les suites de tests KAT affichent `PASS`.
- Le fichier `data/logs/kat_results.txt` a été généré avec succès.
- Les implémentations et modes testés sont fonctionnels sur l’architecture ARM.

---

## Étape 7 — Benchmark Raspberry Pi, exécution 1

### Commandes exécutées

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

### Sortie observée

```text
(.venv) melissamoya@raspberrypi:~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments $ cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
mkdir -p data/logs
python scripts/experiment.py > data/logs/benchmark_output_experience1.txt 2>&1
cat data/logs/benchmark_output_experience1.txt
cd data/results
mv experiment_*.csv raspberry-pi_experience1.csv
cd ../..
  Running AES-ECB key=128bit msg=64B … enc=0.074ms thr=0.82MB/s avalanche=0.499
  Running AES-ECB key=128bit msg=256B … enc=0.054ms thr=4.52MB/s avalanche=0.501
  Running AES-ECB key=128bit msg=1024B … enc=0.057ms thr=17.11MB/s avalanche=0.496
  Running AES-ECB key=128bit msg=4096B … enc=0.120ms thr=32.58MB/s avalanche=0.498
  Running AES-ECB key=128bit msg=16384B … enc=0.389ms thr=40.18MB/s avalanche=0.503
  Running AES-ECB key=192bit msg=64B … enc=0.045ms thr=1.36MB/s avalanche=0.499
  Running AES-ECB key=192bit msg=256B … enc=0.050ms thr=4.93MB/s avalanche=0.503
  Running AES-ECB key=192bit msg=1024B … enc=0.058ms thr=16.73MB/s avalanche=0.500
  Running AES-ECB key=192bit msg=4096B … enc=0.123ms thr=31.77MB/s avalanche=0.499
  Running AES-ECB key=192bit msg=16384B … enc=0.423ms thr=36.91MB/s avalanche=0.507
  Running AES-ECB key=256bit msg=64B … enc=0.043ms thr=1.41MB/s avalanche=0.502
  Running AES-ECB key=256bit msg=256B … enc=0.044ms thr=5.54MB/s avalanche=0.495
  Running AES-ECB key=256bit msg=1024B … enc=0.054ms thr=17.96MB/s avalanche=0.499
  Running AES-ECB key=256bit msg=4096B … enc=0.103ms thr=38.08MB/s avalanche=0.500
  Running AES-ECB key=256bit msg=16384B … enc=0.297ms thr=52.53MB/s avalanche=0.492
  Running AES-CBC key=128bit msg=64B … enc=0.294ms thr=0.21MB/s avalanche=0.496
  Running AES-CBC key=128bit msg=256B … enc=0.903ms thr=0.27MB/s avalanche=0.500
  Running AES-CBC key=128bit msg=1024B … enc=3.188ms thr=0.31MB/s avalanche=0.504
  Running AES-CBC key=128bit msg=4096B … enc=13.950ms thr=0.28MB/s avalanche=0.500
  Running AES-CBC key=128bit msg=16384B … enc=46.606ms thr=0.34MB/s avalanche=0.501
  Running AES-CBC key=192bit msg=64B … enc=0.208ms thr=0.29MB/s avalanche=0.499
  Running AES-CBC key=192bit msg=256B … enc=0.673ms thr=0.36MB/s avalanche=0.503
  Running AES-CBC key=192bit msg=1024B … enc=2.547ms thr=0.38MB/s avalanche=0.496
  Running AES-CBC key=192bit msg=4096B … enc=10.063ms thr=0.39MB/s avalanche=0.499
  Running AES-CBC key=192bit msg=16384B … enc=39.904ms thr=0.39MB/s avalanche=0.501
  Running AES-CBC key=256bit msg=64B … enc=0.207ms thr=0.30MB/s avalanche=0.499
  Running AES-CBC key=256bit msg=256B … enc=0.677ms thr=0.36MB/s avalanche=0.503
  Running AES-CBC key=256bit msg=1024B … enc=2.570ms thr=0.38MB/s avalanche=0.503
  Running AES-CBC key=256bit msg=4096B … enc=10.725ms thr=0.36MB/s avalanche=0.498
  Running AES-CBC key=256bit msg=16384B … enc=40.638ms thr=0.38MB/s avalanche=0.502
  Running AES-CTR key=128bit msg=64B … enc=0.060ms thr=1.02MB/s avalanche=0.502
  Running AES-CTR key=128bit msg=256B … enc=0.097ms thr=2.51MB/s avalanche=0.501
  Running AES-CTR key=128bit msg=1024B … enc=0.253ms thr=3.87MB/s avalanche=0.493
  Running AES-CTR key=128bit msg=4096B … enc=0.851ms thr=4.59MB/s avalanche=0.502
  Running AES-CTR key=128bit msg=16384B … enc=3.353ms thr=4.66MB/s avalanche=0.496
  Running AES-CTR key=192bit msg=64B … enc=0.058ms thr=1.05MB/s avalanche=0.503
  Running AES-CTR key=192bit msg=256B … enc=0.099ms thr=2.46MB/s avalanche=0.505
  Running AES-CTR key=192bit msg=1024B … enc=0.251ms thr=3.89MB/s avalanche=0.501
  Running AES-CTR key=192bit msg=4096B … enc=0.868ms thr=4.50MB/s avalanche=0.502
  Running AES-CTR key=192bit msg=16384B … enc=3.390ms thr=4.61MB/s avalanche=0.497
  Running AES-CTR key=256bit msg=64B … enc=0.059ms thr=1.04MB/s avalanche=0.497
  Running AES-CTR key=256bit msg=256B … enc=0.097ms thr=2.52MB/s avalanche=0.497
  Running AES-CTR key=256bit msg=1024B … enc=0.252ms thr=3.88MB/s avalanche=0.498
  Running AES-CTR key=256bit msg=4096B … enc=0.856ms thr=4.57MB/s avalanche=0.503
  Running AES-CTR key=256bit msg=16384B … enc=3.370ms thr=4.64MB/s avalanche=0.499
  Running AES-GCM key=128bit msg=64B … enc=0.258ms thr=0.24MB/s avalanche=0.503
  Running AES-GCM key=128bit msg=256B … enc=0.200ms thr=1.22MB/s avalanche=0.493
  Running AES-GCM key=128bit msg=1024B … enc=0.224ms thr=4.36MB/s avalanche=0.502
  Running AES-GCM key=128bit msg=4096B … enc=0.317ms thr=12.34MB/s avalanche=0.501
  Running AES-GCM key=128bit msg=16384B … enc=0.711ms thr=21.98MB/s avalanche=0.504
  Running AES-GCM key=192bit msg=64B … enc=0.195ms thr=0.31MB/s avalanche=0.500
  Running AES-GCM key=192bit msg=256B … enc=0.291ms thr=0.84MB/s avalanche=0.500
  Running AES-GCM key=192bit msg=1024B … enc=0.384ms thr=2.55MB/s avalanche=0.504
  Running AES-GCM key=192bit msg=4096B … enc=0.367ms thr=10.65MB/s avalanche=0.496
  Running AES-GCM key=192bit msg=16384B … enc=0.847ms thr=18.44MB/s avalanche=0.499
  Running AES-GCM key=256bit msg=64B … enc=0.193ms thr=0.32MB/s avalanche=0.503
  Running AES-GCM key=256bit msg=256B … enc=0.204ms thr=1.20MB/s avalanche=0.496
  Running AES-GCM key=256bit msg=1024B … enc=0.230ms thr=4.24MB/s avalanche=0.499
  Running AES-GCM key=256bit msg=4096B … enc=0.343ms thr=11.40MB/s avalanche=0.499
  Running AES-GCM key=256bit msg=16384B … enc=0.766ms thr=20.39MB/s avalanche=0.495
  Running DES-ECB key=64bit msg=64B … enc=0.054ms thr=1.14MB/s avalanche=0.497
  Running DES-ECB key=64bit msg=256B … enc=0.056ms thr=4.34MB/s avalanche=0.496
  Running DES-ECB key=64bit msg=1024B … enc=0.077ms thr=12.76MB/s avalanche=0.498
  Running DES-ECB key=64bit msg=4096B … enc=0.149ms thr=26.18MB/s avalanche=0.499
  Running DES-ECB key=64bit msg=16384B … enc=0.457ms thr=34.21MB/s avalanche=0.502
  Running DES-CBC key=64bit msg=64B … enc=0.448ms thr=0.14MB/s avalanche=0.494
  Running DES-CBC key=64bit msg=256B … enc=1.583ms thr=0.15MB/s avalanche=0.495
  Running DES-CBC key=64bit msg=1024B … enc=6.291ms thr=0.16MB/s avalanche=0.502
  Running DES-CBC key=64bit msg=4096B … enc=24.589ms thr=0.16MB/s avalanche=0.500
  Running DES-CBC key=64bit msg=16384B … enc=95.707ms thr=0.16MB/s avalanche=0.495
  Running DES-CTR key=64bit msg=64B … enc=0.071ms thr=0.86MB/s avalanche=0.495
  Running DES-CTR key=64bit msg=256B … enc=0.118ms thr=2.06MB/s avalanche=0.502
  Running DES-CTR key=64bit msg=1024B … enc=0.300ms thr=3.26MB/s avalanche=0.506
  Running DES-CTR key=64bit msg=4096B … enc=1.046ms thr=3.74MB/s avalanche=0.495
  Running DES-CTR key=64bit msg=16384B … enc=4.109ms thr=3.80MB/s avalanche=0.510
  Running 3DES-ECB key=128bit msg=64B … enc=0.123ms thr=0.50MB/s avalanche=0.497
  Running 3DES-ECB key=128bit msg=256B … enc=0.137ms thr=1.78MB/s avalanche=0.503
  Running 3DES-ECB key=128bit msg=1024B … enc=0.195ms thr=5.00MB/s avalanche=0.497
  Running 3DES-ECB key=128bit msg=4096B … enc=0.427ms thr=9.15MB/s avalanche=0.501
  Running 3DES-ECB key=128bit msg=16384B … enc=1.327ms thr=11.78MB/s avalanche=0.500
  Running 3DES-ECB key=192bit msg=64B … enc=0.146ms thr=0.42MB/s avalanche=0.509
  Running 3DES-ECB key=192bit msg=256B … enc=0.160ms thr=1.53MB/s avalanche=0.491
  Running 3DES-ECB key=192bit msg=1024B … enc=0.219ms thr=4.46MB/s avalanche=0.503
  Running 3DES-ECB key=192bit msg=4096B … enc=0.442ms thr=8.83MB/s avalanche=0.491
  Running 3DES-ECB key=192bit msg=16384B … enc=1.395ms thr=11.20MB/s avalanche=0.501
  Running 3DES-CBC key=128bit msg=64B … enc=0.135ms thr=0.45MB/s avalanche=0.500
  Running 3DES-CBC key=128bit msg=256B … enc=0.465ms thr=0.53MB/s avalanche=0.500
  Running 3DES-CBC key=128bit msg=1024B … enc=1.831ms thr=0.53MB/s avalanche=0.496
  Running 3DES-CBC key=128bit msg=4096B … enc=7.162ms thr=0.55MB/s avalanche=0.508
  Running 3DES-CBC key=128bit msg=16384B … enc=28.718ms thr=0.54MB/s avalanche=0.500
  Running 3DES-CBC key=192bit msg=64B … enc=0.135ms thr=0.45MB/s avalanche=0.508
  Running 3DES-CBC key=192bit msg=256B … enc=0.465ms thr=0.52MB/s avalanche=0.494
  Running 3DES-CBC key=192bit msg=1024B … enc=1.819ms thr=0.54MB/s avalanche=0.500
  Running 3DES-CBC key=192bit msg=4096B … enc=7.236ms thr=0.54MB/s avalanche=0.499
  Running 3DES-CBC key=192bit msg=16384B … enc=28.980ms thr=0.54MB/s avalanche=0.498
  Running 3DES-CTR key=128bit msg=64B … enc=0.145ms thr=0.42MB/s avalanche=0.499
  Running 3DES-CTR key=128bit msg=256B … enc=0.201ms thr=1.21MB/s avalanche=0.506
  Running 3DES-CTR key=128bit msg=1024B … enc=0.420ms thr=2.33MB/s avalanche=0.495
  Running 3DES-CTR key=128bit msg=4096B … enc=1.316ms thr=2.97MB/s avalanche=0.496
  Running 3DES-CTR key=128bit msg=16384B … enc=4.976ms thr=3.14MB/s avalanche=0.495
  Running 3DES-CTR key=192bit msg=64B … enc=0.167ms thr=0.37MB/s avalanche=0.502
  Running 3DES-CTR key=192bit msg=256B … enc=0.225ms thr=1.09MB/s avalanche=0.506
  Running 3DES-CTR key=192bit msg=1024B … enc=0.457ms thr=2.14MB/s avalanche=0.499
  Running 3DES-CTR key=192bit msg=4096B … enc=1.333ms thr=2.93MB/s avalanche=0.499
  Running 3DES-CTR key=192bit msg=16384B … enc=4.983ms thr=3.14MB/s avalanche=0.493
  Running Twofish-ECB key=128bit msg=64B … enc=0.062ms thr=0.98MB/s avalanche=0.498
  Running Twofish-ECB key=128bit msg=256B … enc=0.186ms thr=1.31MB/s avalanche=0.502
  Running Twofish-ECB key=128bit msg=1024B … enc=0.707ms thr=1.38MB/s avalanche=0.499
  Running Twofish-ECB key=128bit msg=4096B … enc=2.712ms thr=1.44MB/s avalanche=0.496
  Running Twofish-ECB key=128bit msg=16384B … enc=10.893ms thr=1.43MB/s avalanche=0.497
  Running Twofish-ECB key=192bit msg=64B … enc=0.061ms thr=1.00MB/s avalanche=0.502
  Running Twofish-ECB key=192bit msg=256B … enc=0.187ms thr=1.30MB/s avalanche=0.496
  Running Twofish-ECB key=192bit msg=1024B … enc=0.708ms thr=1.38MB/s avalanche=0.496
  Running Twofish-ECB key=192bit msg=4096B … enc=2.751ms thr=1.42MB/s avalanche=0.503
  Running Twofish-ECB key=192bit msg=16384B … enc=10.872ms thr=1.44MB/s avalanche=0.505
  Running Twofish-ECB key=256bit msg=64B … enc=0.061ms thr=1.01MB/s avalanche=0.493
  Running Twofish-ECB key=256bit msg=256B … enc=0.186ms thr=1.32MB/s avalanche=0.499
  Running Twofish-ECB key=256bit msg=1024B … enc=0.698ms thr=1.40MB/s avalanche=0.509
  Running Twofish-ECB key=256bit msg=4096B … enc=2.733ms thr=1.43MB/s avalanche=0.502
  Running Twofish-ECB key=256bit msg=16384B … enc=10.844ms thr=1.44MB/s avalanche=0.496
  Running Twofish-CBC key=128bit msg=64B … enc=0.097ms thr=0.63MB/s avalanche=0.500
  Running Twofish-CBC key=128bit msg=256B … enc=0.301ms thr=0.81MB/s avalanche=0.503
  Running Twofish-CBC key=128bit msg=1024B … enc=1.140ms thr=0.86MB/s avalanche=0.504
  Running Twofish-CBC key=128bit msg=4096B … enc=4.448ms thr=0.88MB/s avalanche=0.496
  Running Twofish-CBC key=128bit msg=16384B … enc=17.631ms thr=0.89MB/s avalanche=0.499
  Running Twofish-CBC key=192bit msg=64B … enc=0.096ms thr=0.64MB/s avalanche=0.498
  Running Twofish-CBC key=192bit msg=256B … enc=0.301ms thr=0.81MB/s avalanche=0.497
  Running Twofish-CBC key=192bit msg=1024B … enc=1.146ms thr=0.85MB/s avalanche=0.499
  Running Twofish-CBC key=192bit msg=4096B … enc=4.458ms thr=0.88MB/s avalanche=0.496
  Running Twofish-CBC key=192bit msg=16384B … enc=17.571ms thr=0.89MB/s avalanche=0.503
  Running Twofish-CBC key=256bit msg=64B … enc=0.096ms thr=0.64MB/s avalanche=0.495
  Running Twofish-CBC key=256bit msg=256B … enc=0.305ms thr=0.80MB/s avalanche=0.495
  Running Twofish-CBC key=256bit msg=1024B … enc=1.139ms thr=0.86MB/s avalanche=0.505
  Running Twofish-CBC key=256bit msg=4096B … enc=4.470ms thr=0.87MB/s avalanche=0.500
  Running Twofish-CBC key=256bit msg=16384B … enc=17.617ms thr=0.89MB/s avalanche=0.498
  Running Twofish-CTR key=128bit msg=64B … enc=0.071ms thr=0.86MB/s avalanche=0.500
  Running Twofish-CTR key=128bit msg=256B … enc=0.234ms thr=1.04MB/s avalanche=0.501
  Running Twofish-CTR key=128bit msg=1024B … enc=0.904ms thr=1.08MB/s avalanche=0.501
  Running Twofish-CTR key=128bit msg=4096B … enc=3.502ms thr=1.12MB/s avalanche=0.504
  Running Twofish-CTR key=128bit msg=16384B … enc=13.999ms thr=1.12MB/s avalanche=0.496
  Running Twofish-CTR key=192bit msg=64B … enc=0.072ms thr=0.85MB/s avalanche=0.497
  Running Twofish-CTR key=192bit msg=256B … enc=0.231ms thr=1.06MB/s avalanche=0.498
  Running Twofish-CTR key=192bit msg=1024B … enc=0.893ms thr=1.09MB/s avalanche=0.497
  Running Twofish-CTR key=192bit msg=4096B … enc=3.507ms thr=1.11MB/s avalanche=0.497
  Running Twofish-CTR key=192bit msg=16384B … enc=13.953ms thr=1.12MB/s avalanche=0.494
  Running Twofish-CTR key=256bit msg=64B … enc=0.072ms thr=0.85MB/s avalanche=0.502
  Running Twofish-CTR key=256bit msg=256B … enc=0.234ms thr=1.04MB/s avalanche=0.495
  Running Twofish-CTR key=256bit msg=1024B … enc=0.892ms thr=1.09MB/s avalanche=0.492
  Running Twofish-CTR key=256bit msg=4096B … enc=3.487ms thr=1.12MB/s avalanche=0.503
  Running Twofish-CTR key=256bit msg=16384B … enc=13.964ms thr=1.12MB/s avalanche=0.501
  Running ChaCha20-Stream key=256bit msg=64B … enc=0.028ms thr=2.16MB/s avalanche=0.593
  Running ChaCha20-Stream key=256bit msg=256B … enc=0.028ms thr=8.80MB/s avalanche=0.595
  Running ChaCha20-Stream key=256bit msg=1024B … enc=0.035ms thr=27.70MB/s avalanche=0.595
  Running ChaCha20-Stream key=256bit msg=4096B … enc=0.059ms thr=66.49MB/s avalanche=0.597
  Running ChaCha20-Stream key=256bit msg=16384B … enc=0.164ms thr=94.99MB/s avalanche=0.593

Results saved to: /home/melissamoya/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments/data/results/experiment_20260529_183323.csv
(.venv) melissamoya@raspberrypi:~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments $
```

### Conclusion

Étape validée.

- La première exécution complète du benchmark Raspberry Pi s’est déroulée correctement.
- Le fichier de log `data/logs/benchmark_output_experience1.txt` a été généré avec succès.
- Un fichier CSV de résultats a été produit puis renommé en `raspberry-pi_experience1.csv`.
- Les mesures ont été obtenues pour AES, DES, 3DES, Twofish et ChaCha20 selon plusieurs tailles de messages et modes de chiffrement.
