# Video 3 - Resultats de performance

## Objectif
Montrer les resultats de performance de maniere claire et interpretable.
Relier les chiffres observes a trois causes: algorithme, mode de chiffrement, et architecture materielle.

## Duree cible
15 a 20 minutes.

## Portee
- Script de generation: scripts/generate_charts.py
- Donnees source: data/results
- Sortie visuelle: data/charts
- Focus interpretation: debit, tailles de message, impact AES-NI

## Script video (camera-ready)

### 1) Introduction
**Support affiche :**
PowerPoint - Slide d ouverture de la video 3.

**Texte a dire :**
Dans cette video, on presente les resultats de performance obtenus pendant nos experiences.
L objectif est simple: comprendre ce qui explique les ecarts de debit entre algorithmes et entre plateformes.
Les tests de validation et le protocole etant deja verifies, on peut maintenant interpreter les graphes avec confiance.

**Phrase de transition :**
Passons d abord a la source des graphes pour montrer que la lecture repose sur une chaine de traitement maitrisee.

### 2) Rappel rapide de generation
**Support affiche :**
Code - VS Code sur scripts/generate_charts.py.

**Texte a dire :**
Ici, on montre rapidement comment les figures sont generees.
Le script lit les CSV de mesures, construit les visualisations, puis exporte les images dans data/charts.
Cette etape garantit que nos conclusions viennent de donnees tracees et reproductibles.

**Phrase de transition :**
Maintenant que la provenance des graphes est claire, on peut passer a la lecture des performances.

### 3) Vue d ensemble des debits
**Support affiche :**
PowerPoint - Slide resultat global debit par algorithme et mode.

**Texte a dire :**
Ce premier graphe donne la hierarchie globale des debits.
On observe que AES est generalement en tete sur la plateforme x86.
On voit aussi que les modes de chiffrement n ont pas tous le meme cout.

**Phrase de transition :**
Pour rendre cette vue utile en decision, on zoome maintenant sur les algorithmes majeurs.

### 4) Focus AES et ChaCha20
**Support affiche :**
PowerPoint - Slide comparaison AES vs ChaCha20.

**Texte a dire :**
AES montre des debits tres eleves sur x86, notamment grace au support materiel.
ChaCha20 reste une reference solide et stable, surtout quand l acceleration AES n est pas disponible.
Le message ici n est pas de designer un gagnant universel, mais de choisir selon la plateforme cible.

**Phrase de transition :**
Apres les algorithmes modernes, regardons les algorithmes heritage et leurs limites pratiques.

### 5) Focus DES, 3DES, Twofish
**Support affiche :**
PowerPoint - Slide comparaison des algorithmes heritage.

**Texte a dire :**
DES est clairement en retrait en performance et en securite.
3DES est encore plus couteux a cause de ses trois passes de chiffrement.
Twofish reste correct, mais dans notre contexte il est en dessous de AES sur le plan du debit.
Conclusion de ce bloc: ces choix historiques ne sont plus optimaux pour les contraintes actuelles.

**Phrase de transition :**
On a vu l effet de l algorithme; voyons maintenant l effet du mode de chiffrement.

### 6) Impact du mode de chiffrement
**Support affiche :**
PowerPoint - Slide comparaison ECB, CBC, CTR, GCM.

**Texte a dire :**
Les modes n ont pas le meme compromis performance-securite.
GCM ajoute l authentification, ce qui augmente le cout par rapport a des modes plus simples.
Ce surcout est attendu et justifie quand on veut la confidentialite et l integrite dans le meme schema.

**Phrase de transition :**
Apres algorithme et mode, il reste un facteur important: la taille des messages.

### 7) Effet de la taille du message
**Support affiche :**
PowerPoint - Slide debit selon la taille du message.

**Texte a dire :**
Sur petites tailles, les couts fixes pesent davantage sur le debit effectif.
Quand la taille augmente, le debit utile se stabilise mieux et les ecarts deviennent plus lisibles.
Cette lecture est importante pour relier nos resultats a des usages reels.

**Phrase de transition :**
Cette tendance nous amene directement a l interpretation materielle des ecarts.

### 8) Interpretation materielle et AES-NI
**Support affiche :**
PowerPoint - Slide comparaison x86 vs Raspberry Pi.

**Texte a dire :**
La plateforme x86 beneficie de l acceleration AES-NI, ce qui explique une part majeure des gains observes sur AES.
Sur Raspberry Pi, cet avantage materiel n est pas present de la meme facon, donc les ecarts se reduisent ou se deplacent selon les cas.
Le point cle est que la performance cryptographique depend fortement du couple algorithme plus architecture.

**Phrase de transition :**
On termine avec une synthese operationnelle des decisions a retenir.

### 9) Conclusion
**Support affiche :**
PowerPoint - Slide conclusion de la video 3.

**Texte a dire :**
Premier constat: le choix de l algorithme influence fortement le debit, avec un avantage net pour AES sur x86.
Deuxieme constat: le mode de chiffrement ajoute un cout mesurable, notamment quand on integre l authentification.
Troisieme constat: l architecture materielle, et en particulier AES-NI, explique une grande partie des ecarts inter-plateformes.
Dans la prochaine video, on complete cette lecture performance par la robustesse cryptographique, avec l effet d avalanche.
