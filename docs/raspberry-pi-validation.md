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

### Sortie observée

```text
À compléter
```

### Conclusion

À compléter.
