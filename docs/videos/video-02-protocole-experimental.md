# Video 2 - Protocole experimental

## Objectif
Montrer que la methode de mesure est valide, comparable entre plateformes et reproductible.

## Portee
- application/ExperimentController.py
- scripts/experiment.py
- Execution terminal en direct
- Structure du CSV dans data/results

## Script

### Conventions de lecture (voix + ecran)
- Avant chaque indication de type **(SURLIGNER ...)**, faire une micro-pause.
- Garder une idee principale par phrase.
- Pendant un surlignage, privilegier des phrases courtes.

### Introduction
Dans cette video, on demontre pourquoi le protocole experimental est solide scientifiquement.
L objectif est simple: prouver que la methode est comparable, reproductible et exploitable pour l analyse.
On va voir la logique du protocole, puis verifier son execution reelle et sa sortie CSV.

### Sequence par etape

#### Etape 1
**Action ecran :**
Afficher la slide du protocole experimental (plateformes, algorithmes, repetitions).

**Texte a dire :**
Dans cette etape, on demontre le cadre general de la methode.
Le protocole repose sur trois axes: les plateformes comparees, les algorithmes testes, et les repetitions.
(PAUSE) (SURLIGNER: **plateformes**) (SURLIGNER: **algorithmes**) (SURLIGNER: **repetitions**)

#### Etape 2
**Action ecran :**
Rester sur la slide et pointer les deux plateformes.

**Texte a dire :**
Ici, on demontre une comparaison controlee entre materiels.
On compare AES, DES, 3DES, Twofish et ChaCha20 sur deux environnements:
un portable Windows avec AES-NI,
et un Raspberry Pi ARM sans AES-NI.
Le code reste identique, seule la plateforme change.
(PAUSE) (SURLIGNER: **Windows x86 avec AES-NI**) (SURLIGNER: **Raspberry Pi ARM sans AES-NI**)

#### Etape 3
**Action ecran :**
Ouvrir application/ExperimentController.py dans VS Code.

**Texte a dire :**
Dans cette etape, on demontre ou la methode de mesure est orchestree.
ExperimentController centralise le protocole experimental.
Il se concentre sur la mesure,
pas sur les graphiques,
et pas sur l export final.
(PAUSE) (SURLIGNER: **class ExperimentController**) (SURLIGNER: **def run_performance(...)**)

#### Etape 4
**Action ecran :**
Montrer la boucle des configurations et les repetitions.

**Texte a dire :**
Ici, on demontre la discipline statistique du protocole.
Chaque configuration est repetee 100 fois.
Cette repetition reduit le bruit de mesure et stabilise les estimations,
notamment pour l intervalle de confiance a 95 %.
(PAUSE) (SURLIGNER: *REPETITIONS = 100*)

#### Etape 5
**Action ecran :**
Montrer la partie chronometrage.

**Texte a dire :**
Dans cette etape, on demontre que le chronometrage isole bien le cout cryptographique utile.
Le minuteur encadre uniquement le chiffrement et le dechiffrement.
Il exclut l initialisation,
la preparation des structures,
et l ecriture CSV.
(PAUSE) (SURLIGNER: **time.perf_counter()**) (SURLIGNER: **encrypt(...)**) (SURLIGNER: **decrypt(...)**)

#### Etape 6
**Action ecran :**
Ouvrir scripts/experiment.py.

**Texte a dire :**
Ici, on demontre ou la campagne est parametree de facon declarative.
Dans experiment.py, on retrouve la matrice experimentale,
les tailles de message,
et le nombre de repetitions.
Ce fichier permet de rejouer le protocole facilement.
(PAUSE) (SURLIGNER: **EXPERIMENT_MATRIX**) (SURLIGNER: **MESSAGE_SIZES**) (SURLIGNER: *REPETITIONS = 100*)

#### Etape 7
**Action ecran :**
Pointer rapidement les listes de configuration dans le fichier.

**Texte a dire :**
Dans cette etape, on demontre la maintenabilite du protocole.
Tout est declaratif.
Pour ajouter un scenario,
on ajoute une entree dans la matrice,
sans rearchitecturer le moteur ni le controleur.
(PAUSE) (SURLIGNER: **EXPERIMENT_MATRIX = [...]**)

#### Etape 8
**Action ecran :**
Ouvrir le terminal integre et executer la commande python scripts/experiment.py.

**Texte a dire :**
Ici, on demontre l execution reelle du protocole.
Je lance la commande python scripts/experiment.py depuis le dossier crypto-experiments.
Le script parcourt automatiquement toute la matrice declaree.
(PAUSE) (SURLIGNER: **python scripts/experiment.py**)

#### Etape 9
**Action ecran :**
Laisser tourner quelques secondes et montrer la progression du terminal.

**Texte a dire :**
Dans cette etape, on demontre la reproductibilite en conditions reelles.
Les configurations s enchainent automatiquement,
sans intervention manuelle.
Le meme script est execute tel quel sur Raspberry Pi,
ce qui garantit une comparaison propre entre plateformes.
(PAUSE) (SURLIGNER: **iteration des configurations**) (SURLIGNER: **mesures successives**)

#### Etape 10
**Action ecran :**
Ouvrir un CSV genere dans data/results.

**Texte a dire :**
Ici, on demontre la sortie brute du protocole.
Le resultat est un CSV horodate,
avec une ligne par configuration mesuree.
C est la base factuelle de toute l analyse TN3.
(PAUSE) (SURLIGNER: **data/results/**) (SURLIGNER: **experiment_*.csv**)

#### Etape 11
**Action ecran :**
Montrer les colonnes principales du CSV.

**Texte a dire :**
Dans cette etape, on demontre la qualite analytique des donnees.
On retrouve les identifiants de configuration,
les temps,
les debits,
les scores d avalanche,
et les intervalles de confiance.
Ces colonnes permettent de comparer objectivement les algorithmes.
(PAUSE) (SURLIGNER: **algorithm**) (SURLIGNER: **mode**) (SURLIGNER: **message_size_bytes**) (SURLIGNER: **throughput_encrypt_mbps**) (SURLIGNER: **avalanche_score**) (SURLIGNER: **ci95_encrypt_mbps**)

#### Etape 12
**Action ecran :**
Rester sur le CSV pour la transition vers la prochaine video.

**Texte a dire :**
Conclusion de la video 2:
on a justifie le protocole,
valide la logique de mesure,
et montre une sortie exploitable pour la comparaison.
Dans la prochaine video, on verrouille la justesse cryptographique avec les tests KAT.
