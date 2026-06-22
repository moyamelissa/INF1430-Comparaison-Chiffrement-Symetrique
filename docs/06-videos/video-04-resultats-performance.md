# Video 4 - Resultats de performance

## Objectif
Montrer les resultats de debit et expliquer clairement l impact de l acceleration materielle AES-NI.
Cette video integre aussi les anciens focus ChaCha20 (inter-plateformes) et DES/3DES/Twofish.

## Portee
- scripts/generate_charts.py
- Dossier data/charts
- Graphiques de debit par algorithme et par taille de message
- Lecture comparative orientee interpretation

## Script

### Conventions de lecture (voix + ecran)
- Avant chaque indication de type **(SURLIGNER ...)**, faire une micro-pause.
- Garder une idee principale par phrase.
- Pendant un graphique, commenter d abord la tendance, puis la cause.
- Vitesse cible: 125 a 140 mots par minute sur les graphiques.
- Sur chaque figure: observation, interpretation, implication.

### Introduction
Dans cette video, on demontre ce que donnent les mesures de performance en pratique.
Les KAT et le protocole ayant ete valides,
on peut maintenant interpreter les debits avec confiance.
Le focus principal est l effet de AES-NI sur les ecarts observes.
(RESPIRER)

### Repere de rythme (minute par minute)
- 0:00 a 0:40 : cadrage performance et validite des donnees.
- 0:40 a 2:30 : generation des graphes.
- 2:30 a 5:45 : lecture debit par algorithme et mode.
- 5:45 a 7:30 : focus DES, 3DES, Twofish.
- 7:30 a 9:30 : debit selon taille de message.
- 9:30 a 10:30 : focus AES-NI et transition.

### Sequence par etape

#### Etape 1
**Action ecran :**
Ouvrir scripts/generate_charts.py dans VS Code.

**Texte a dire :**
Dans cette etape, on demontre comment les graphes sont produits a partir des CSV.
Ce script lit les resultats bruts,
construit les visualisations comparatives,
et exporte les figures dans data/charts.
(PAUSE) (SURLIGNER: **scripts/generate_charts.py**) (SURLIGNER: **lecture CSV**) (SURLIGNER: **generation des figures**)

#### Etape 2
**Action ecran :**
Montrer rapidement que le script lit les CSV et construit les figures.

**Texte a dire :**
Ici, on demontre la chaine de transformation des donnees.
On passe d un tableau de mesures a des graphes lisibles.
C est essentiel,
car l interpretation finale depend de cette etape de synthese visuelle.
(RESPIRER)
(PAUSE) (SURLIGNER: **data/results/**) (SURLIGNER: **data/charts/**)

#### Etape 3
**Action ecran :**
Ouvrir le terminal et executer python scripts/generate_charts.py.

**Texte a dire :**
Dans cette etape, on demontre l execution reelle de la generation des graphiques.
Je lance la commande python scripts/generate_charts.py.
Le script produit automatiquement les figures a partir des CSV existants.
(PAUSE) (SURLIGNER: **python scripts/generate_charts.py**)

#### Etape 4
**Action ecran :**
Ouvrir le dossier data/charts.

**Texte a dire :**
Ici, on demontre la sortie exploitable pour l analyse.
Toutes les figures generees sont centralisees dans data/charts.
On va se concentrer sur les deux graphes les plus informatifs pour la performance.
(PAUSE) (SURLIGNER: **data/charts/**)

#### Etape 5
**Action ecran :**
Afficher le graphique debit par algorithme et mode.

**Texte a dire :**
Dans cette etape, on demontre la hierarchie globale des debits.
AES apparait en tete sur la plateforme x86,
en particulier sur les modes les plus favorables au debit.
GCM est plus couteux que ECB,
car il ajoute la couche d authentification.
La lecture correcte est donc: plus de securite integree,
avec un surcout de performance attendu.
(RESPIRER)
(PAUSE) (SURLIGNER: **debit AES**) (SURLIGNER: **ECB**) (SURLIGNER: **GCM**)

#### Etape 6
**Action ecran :**
Rester sur le graphique et pointer DES, 3DES et Twofish.

**Texte a dire :**
Ici, on demontre les limites pratiques des algorithmes heritage.
DES reste en retrait,
3DES est penalise par ses trois passes,
et Twofish reste en dessous de AES dans ce contexte materiel.
Le message est clair:
les choix historiques ne suivent plus les contraintes de performance modernes.
(PAUSE) (SURLIGNER: **DES**) (SURLIGNER: **3DES**) (SURLIGNER: **Twofish**)

#### Etape 7
**Action ecran :**
Afficher le graphique debit selon la taille du message.

**Texte a dire :**
Dans cette etape, on demontre l effet de la taille de message sur le debit.
Pour les petits blocs,
les couts fixes pesent davantage.
Quand la taille augmente,
le debit utile monte,
et les differences entre algorithmes deviennent plus visibles.
(PAUSE) (SURLIGNER: **petites tailles**) (SURLIGNER: **grandes tailles**) (SURLIGNER: **courbe de debit**)

#### Etape 8
**Action ecran :**
Pointer la zone des plus grosses tailles.

**Texte a dire :**
Ici, on demontre l impact direct de AES-NI.
Sur les grandes tailles,
l acceleration materielle de AES sur x86 se voit clairement.
C est ce facteur qui explique une partie majeure de l ecart avec Raspberry Pi,
ou cette acceleration n est pas presente.
(RESPIRER)
(PAUSE) (SURLIGNER: **zone grandes tailles**) (SURLIGNER: **ecart x86 vs Pi**) (SURLIGNER: **AES-NI**)

#### Etape 9
**Action ecran :**
Laisser le graphique a l ecran pour transition.

**Texte a dire :**
Conclusion de la video 4:
les resultats de performance sont coherents avec l architecture materielle,
et l effet AES-NI est visible dans les mesures.
Dans la prochaine video, on complete la lecture avec la robustesse cryptographique,
notamment l effet d avalanche.
