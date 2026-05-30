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

### Commandes à exécuter

```bash
ssh-keygen -t ed25519 -C "melissa.moya@ssc-spc.gc.ca"
cat ~/.ssh/id_ed25519.pub
ssh -T git@github.com
```

### Sortie observée

```text
À compléter
```

### Conclusion

À compléter.
