# Video 5 - Robustesse cryptographique

## Objectif
Montrer la robustesse cryptographique des algorithmes avec l effet d avalanche, la sensibilite aux cles et la stabilite statistique.
Cette video integre aussi les anciens focus dedies a l effet d avalanche et a IC95.

## Portee
- scripts/charts/plot_avalanche_rounds.py
- Execution terminal
- Graphiques d avalanche, rounds et sensibilite cle

## Script

### Conventions de lecture (voix + ecran)
- Avant chaque indication de type **(SURLIGNER ...)**, faire une micro-pause.
- Expliquer d abord la metrique, puis la tendance du graphe.
- Garder des phrases courtes pendant les surlignages.
- Vitesse cible: 125 a 140 mots par minute.
- Pour chaque metrique: definition, lecture, prudence d interpretation.

### Introduction
Dans cette video, on demontre que la performance ne suffit pas a juger un algorithme.
On regarde la qualite de diffusion cryptographique,
avec l effet d avalanche,
la sensibilite aux cles,
et la stabilite des mesures.
(RESPIRER)

### Repere de rythme (minute par minute)
- 0:00 a 0:40 : cadrage robustesse.
- 0:40 a 2:20 : principe Hamming et avalanche.
- 2:20 a 4:20 : execution du script.
- 4:20 a 7:00 : lecture des scores par algorithme.
- 7:00 a 8:30 : nuance ChaCha20.
- 8:30 a 10:30 : rounds, key avalanche, IC95.
- 10:30 a 11:00 : conclusion.

### Sequence par etape

#### Etape 1
**Action ecran :**
Ouvrir scripts/charts/plot_avalanche_rounds.py.

**Texte a dire :**
Dans cette etape, on demontre ou la robustesse est mesuree dans le code.
Ce script calcule plusieurs indicateurs,
pas seulement un score unique.
(PAUSE) (SURLIGNER: **scripts/charts/plot_avalanche_rounds.py**) (SURLIGNER: **mesures d avalanche**)

#### Etape 2
**Action ecran :**
Montrer la partie qui inverse un bit et calcule la distance de Hamming.

**Texte a dire :**
Ici, on demontre le principe mathematique de l avalanche.
On chiffre une entree,
on inverse un seul bit,
puis on rechiffre.
Ensuite, on mesure combien de bits changent en sortie.
La cible ideale est proche de 0,5.
(RESPIRER)
(PAUSE) (SURLIGNER: **flip one bit**) (SURLIGNER: **Hamming distance**) (SURLIGNER: **score ~ 0.5**)

#### Etape 3
**Action ecran :**
Executer python scripts/charts/plot_avalanche_rounds.py.

**Texte a dire :**
Dans cette etape, on demontre l execution reelle de l analyse de robustesse.
Je lance la commande python scripts/charts/analyse_rounds_avalanche.py.
Le script genere les sorties numeriques et les figures associees.
(PAUSE) (SURLIGNER: **python scripts/charts/analyse_rounds_avalanche.py**)

#### Etape 4
**Action ecran :**
Ouvrir le graphique des scores d avalanche par algorithme.

**Texte a dire :**
Ici, on demontre la diffusion globale des algorithmes.
AES, 3DES et Twofish restent proches de la cible ideale,
alors que DES est en retrait.
Ce graphe donne une vue comparative immediate de la qualite de diffusion.
(PAUSE) (SURLIGNER: **score avalanche par algorithme**) (SURLIGNER: **proche de 0.5**)

#### Etape 5
**Action ecran :**
Pointer la valeur de ChaCha20.

**Texte a dire :**
Dans cette etape, on demontre une limite d interpretation.
ChaCha20 est un chiffrement de flux,
donc la lecture du score doit etre faite avec prudence.
Ce n est pas une preuve de faiblesse,
c est une question d adequation entre metrique et type d algorithme.
(RESPIRER)
(PAUSE) (SURLIGNER: **ChaCha20** ) (SURLIGNER: **stream cipher** ) (SURLIGNER: **interpretation prudente**)

#### Etape 6
**Action ecran :**
Ouvrir le graphique rounds versus avalanche.

**Texte a dire :**
Ici, on demontre la vitesse de convergence vers une bonne diffusion.
Le graphe montre comment le score evolue en fonction des rondes internes.
Plus la convergence est rapide et stable,
plus le comportement est robuste.
(PAUSE) (SURLIGNER: **rounds vs avalanche**) (SURLIGNER: **convergence**)

#### Etape 7
**Action ecran :**
Ouvrir le graphique de sensibilite aux cles.

**Texte a dire :**
Dans cette etape, on demontre la reaction du systeme a un changement de cle minimal.
On modifie un bit de cle,
et on observe la variation du ciphertext.
AES et Twofish restent proches de la cible,
tandis que DES et 3DES montrent une sensibilite moins reguliere.
(PAUSE) (SURLIGNER: **key avalanche**) (SURLIGNER: **bit flip key**)

#### Etape 8
**Action ecran :**
Ouvrir le graphique de stabilite IC95.

**Texte a dire :**
Ici, on demontre la stabilite statistique des mesures.
L intervalle de confiance IC95 permet de voir la variance experimentale.
Cette stabilite depend aussi de la plateforme,
pas uniquement de l algorithme.
(RESPIRER)
(PAUSE) (SURLIGNER: **IC95**) (SURLIGNER: **variance**)

#### Etape 9
**Action ecran :**
Garder le dernier graphique pour transition.

**Texte a dire :**
Conclusion de la video 5:
on a complete la lecture performance par une lecture de robustesse.
Dans la prochaine video,
on passe a la synthese et aux recommandations concretes d usage.
