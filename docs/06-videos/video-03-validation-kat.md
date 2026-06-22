# Video 3 - Validation KAT

## Objectif
Prouver que les implementations cryptographiques sont conformes avant toute interpretation des performances.

## Portee
- Dossier validation
- Fichiers kat_aes.py, kat_des.py, kat_3des.py, kat_modes.py, kat_gcm.py, kat_chacha20.py
- Script scripts/run_kat.py
- Execution terminal en direct

## Script

### Conventions de lecture (voix + ecran)
- Avant chaque indication de type **(SURLIGNER ...)**, faire une micro-pause.
- Garder une idee principale par phrase.
- Pendant un surlignage, utiliser des phrases courtes et precises.
- Vitesse cible: 130 a 145 mots par minute.
- Dire d abord la regle de validation, puis le resultat observe.

### Introduction
Dans cette video, on demontre la justesse cryptographique du systeme.
Avant de comparer les debits, il faut verifier que les sorties chiffrees sont correctes.
On utilise pour ca des Known Answer Tests, les KAT,
avec des vecteurs de reference issus des standards.
(RESPIRER)

### Repere de rythme (minute par minute)
- 0:00 a 0:40 : enjeu KAT avant performance.
- 0:40 a 3:20 : structure du dossier validation.
- 3:20 a 6:20 : exemple concret dans kat_aes.py.
- 6:20 a 8:30 : orchestration run_kat.py.
- 8:30 a 10:30 : execution terminal.
- 10:30 a 11:30 : statut global et transition.

### Sequence par etape

#### Etape 1
**Action ecran :**
Ouvrir le dossier validation dans VS Code et montrer les fichiers kat_aes.py, kat_des.py, kat_3des.py, kat_modes.py, kat_gcm.py et kat_chacha20.py.

**Texte a dire :**
Dans cette etape, on demontre la couverture fonctionnelle de la validation.
Chaque fichier KAT cible une famille precise: primitives, modes, GCM et ChaCha20.
L objectif est de verifier l ensemble du systeme,
pas seulement un algorithme isole.
(PAUSE) (SURLIGNER: **validation/**) (SURLIGNER: **kat_aes.py**) (SURLIGNER: **kat_modes.py**) (SURLIGNER: **kat_gcm.py**) (SURLIGNER: **kat_chacha20.py**)

#### Etape 2
**Action ecran :**
Rester sur l arborescence validation et survoler rapidement les fichiers.

**Texte a dire :**
Ici, on demontre le principe des KAT.
On prend un plaintext connu,
une cle connue,
et un resultat attendu.
Ensuite, on compare la sortie de notre implementation avec la valeur de reference.
Si ca matche, le comportement est conforme.
(RESPIRER)

#### Etape 3
**Action ecran :**
Ouvrir validation/kat_aes.py.

**Texte a dire :**
Dans cette etape, on demontre la validation des primitives AES.
Ce fichier teste des vecteurs standards pour confirmer que la sortie chiffree est exacte.
On verifie ainsi que la base AES est saine avant d analyser les performances.
(PAUSE) (SURLIGNER: **kat_aes.py**) (SURLIGNER: **vecteur de test**) (SURLIGNER: **ciphertext attendu**)

#### Etape 4
**Action ecran :**
Pointer un vecteur de test dans kat_aes.py: plaintext, key, ciphertext attendu.

**Texte a dire :**
Ici, on demontre la logique de comparaison octet par octet.
Le test charge un plaintext et une cle,
chiffre avec notre implementation,
puis compare le resultat au ciphertext attendu.
C est la verification la plus directe de la conformite algorithmique.
(PAUSE) (SURLIGNER: **plaintext** ) (SURLIGNER: **key** ) (SURLIGNER: **expected ciphertext**)

#### Etape 5
**Action ecran :**
Revenir au dossier validation et montrer rapidement les autres fichiers KAT.

**Texte a dire :**
Dans cette etape, on demontre que la validation n est pas limitee a AES.
Le meme principe est applique a DES, 3DES, aux modes de chiffrement,
au mode GCM authentifie,
et a ChaCha20.
On couvre donc la chaine crypto dans son ensemble.
(PAUSE) (SURLIGNER: **kat_des.py**) (SURLIGNER: **kat_3des.py**) (SURLIGNER: **kat_modes.py**) (SURLIGNER: **kat_gcm.py**) (SURLIGNER: **kat_chacha20.py**)

#### Etape 6
**Action ecran :**
Ouvrir scripts/run_kat.py.

**Texte a dire :**
Ici, on demontre l orchestration centralisee des tests KAT.
Le script run_kat.py lance toutes les suites dans un ordre clair.
Il fournit une execution unique et reproductible,
pratique pour verifier rapidement l etat cryptographique global.
(PAUSE) (SURLIGNER: **scripts/run_kat.py**) (SURLIGNER: **lancement des suites**)

#### Etape 7
**Action ecran :**
Montrer la section ou les suites KAT sont lancees.

**Texte a dire :**
Dans cette etape, on demontre le critere de validation.
Si un test echoue,
la validation globale n est pas acceptee.
Tant que cette etape n est pas verte,
les chiffres de performance ne doivent pas etre interpretes.
(PAUSE) (SURLIGNER: **execution des suites KAT**) (SURLIGNER: **statut pass or fail**)

#### Etape 8
**Action ecran :**
Ouvrir le terminal integre et executer python scripts/run_kat.py.

**Texte a dire :**
Ici, on demontre l execution reelle de la validation.
Je lance la commande python scripts/run_kat.py.
Le terminal doit afficher les suites une a une,
jusqu au statut final global.
(PAUSE) (SURLIGNER: **python scripts/run_kat.py**)

#### Etape 9
**Action ecran :**
Laisser defiler la sortie terminal avec les validations.

**Texte a dire :**
Dans cette etape, on demontre la progression de la verification.
On voit passer AES,
DES,
3DES,
les modes,
GCM,
puis ChaCha20.
Cette sequence confirme que la couverture est complete.
(RESPIRER)
(PAUSE) (SURLIGNER: **AES** ) (SURLIGNER: **DES and 3DES** ) (SURLIGNER: **modes** ) (SURLIGNER: **GCM** ) (SURLIGNER: **ChaCha20**)

#### Etape 10
**Action ecran :**
Rester sur la fin du terminal avec le statut global de succes.

**Texte a dire :**
Ici, on demontre la condition de confiance minimale.
Quand tous les KAT passent,
on peut affirmer que les implementations sont conformes aux references.
Les mesures de performance reposent alors sur une base correcte.
(RESPIRER)
(PAUSE) (SURLIGNER: **statut global succes**)

#### Etape 11
**Action ecran :**
Garder le terminal a l ecran pour transition.

**Texte a dire :**
Conclusion de la video 3:
la conformite cryptographique est validee,
et les resultats experimentaux deviennent interpretables.
Dans la prochaine video, on passe aux resultats de performance,
avec un focus sur l impact de AES-NI.
