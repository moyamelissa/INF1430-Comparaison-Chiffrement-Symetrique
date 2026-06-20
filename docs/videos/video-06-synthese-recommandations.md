# Video 6 - Synthese et recommandations

## Objectif
Transformer les resultats techniques en recommandations concretes selon le contexte d utilisation.
Cette video integre aussi les anciens focus ECB dangereux et synthese finale 2026.

## Portee
- scripts/ecb_visual_vulnerability.py
- Demonstration ECB vs CBC
- Slide de recommandations
- Transition TN3 vers TN4

## Script

### Conventions de lecture (voix + ecran)
- Expliquer d abord le risque, puis la recommandation.
- Pendant une image comparative, commenter la difference visuelle avant la theorie.

### Introduction
Dans cette video, on passe de l analyse a la decision.
L objectif est de donner des recommandations claires,
basees sur les mesures et la securite.

### Sequence par etape

#### Etape 1
**Action ecran :**
Ouvrir scripts/ecb_visual_vulnerability.py.

**Texte a dire :**
Dans cette etape, on demontre pourquoi le mode d operation est critique.
Le script prepare une comparaison visuelle entre ECB et CBC.
(PAUSE) (SURLIGNER: **scripts/ecb_visual_vulnerability.py**) (SURLIGNER: **ECB vs CBC**)

#### Etape 2
**Action ecran :**
Executer python scripts/ecb_visual_vulnerability.py.

**Texte a dire :**
Ici, on demontre le resultat concret,
pas seulement un argument theorique.
Je lance la commande python scripts/ecb_visual_vulnerability.py.
(PAUSE) (SURLIGNER: **python scripts/ecb_visual_vulnerability.py**)

#### Etape 3
**Action ecran :**
Afficher l image resultat cote a cote.

**Texte a dire :**
Dans cette etape, on demontre la faiblesse structurelle de ECB.
Avec ECB,
les motifs restent visibles.
Avec CBC,
les motifs sont casses.
Conclusion immediate: la vitesse seule ne suffit pas pour choisir un mode.
(PAUSE) (SURLIGNER: **image ECB** ) (SURLIGNER: **image CBC**)

#### Etape 4
**Action ecran :**
Basculer sur la slide de synthese avec le tableau de recommandations.

**Texte a dire :**
Ici, on demontre la traduction operationnelle des resultats.
Pour serveur et cloud,
AES-256-GCM est le choix standard.
Pour ARM sans acceleration AES,
ChaCha20-Poly1305 est souvent plus equilibre.
(PAUSE) (SURLIGNER: **AES-256-GCM** ) (SURLIGNER: **ChaCha20-Poly1305**)

#### Etape 5
**Action ecran :**
Pointer la colonne des choix a eviter.

**Texte a dire :**
Dans cette etape, on demontre les exclusions claires.
DES,
3DES,
et ECB sont a proscrire pour de nouveaux systemes.
C est une conclusion technique,
pas une preference.
(PAUSE) (SURLIGNER: **DES** ) (SURLIGNER: **3DES** ) (SURLIGNER: **ECB**)

#### Etape 6
**Action ecran :**
Basculer sur la slide de conclusion TN3 vers TN4.

**Texte a dire :**
Conclusion de la video 6:
on a transforme les mesures en recommandations actionnables.
Le TN3 fournit une base complete,
et le TN4 approfondira la discussion formelle et la comparaison a la litterature.

