# Vidéo 4 - Démo complète Windows + Raspberry Pi

## Intro - Objectif de la démo
**Où sommes-nous**
Présentation PowerPoint - Diapo de transition Démo complète

**Texte à lire**
Dans cette vidéo, on fait une démonstration complète du pipeline, du début à la fin, sur Windows puis sur Raspberry Pi.

Le but ici est de montrer que la chaîne est exécutable, traçable et reproductible dans les deux environnements.

On commence par un correctif important lié à la vidéo 1, puis on déroule les exécutions en conditions réelles.

## Section 1 - Retour sur l'erreur de la vidéo 1 et correctif Twofish
**Où sommes-nous**
Présentation PowerPoint - Diapo de correction, puis `scripts/experiment.py`

**Texte à lire**
Avant de lancer la démo complète, je corrige un point important observé pendant la démo de la vidéo 1.

Pendant cette première démo, l'exécution de `scripts/experiment.py` n'incluait pas Twofish dans certains environnements. La cause était une dépendance Python manquante dans l'interpréteur actif, donc le package `twofish` n'était pas importable au moment de la campagne.

Le risque, dans ce cas, c'est de croire que toute la matrice est exécutée alors qu'un algorithme est absent, ce qui rend la sortie incomplète si on ne regarde pas les logs en détail.

Le correctif a été appliqué dans `scripts/experiment.py` avec quatre sécurités. Premièrement, le script détecte explicitement l'erreur d'import Twofish. Deuxièmement, il affiche un message d'alerte clair avec l'interpréteur actif et la commande d'installation recommandée. Sur Raspberry Pi, ce warning est formulé de façon explicite pour signaler immédiatement l'absence de support Twofish dans l'environnement actif. Troisièmement, le script imprime un résumé final par algorithme. Quatrièmement, il retourne un code d'échec si un algorithme attendu est manquant.

Concrètement, si le problème réapparaît, l'utilisateur voit immédiatement un warning explicite dans le terminal, puis un statut de run non conforme en fin d'exécution. Et comme le script retourne un code d'échec, le pipeline CI/CD détecte aussi automatiquement la campagne incomplète. Le but est d'attirer l'attention tout de suite, sans laisser passer une exécution invalide.

## Section 2 - Préparation de la démo Windows
**Où sommes-nous**
Terminal Windows + VS Code

**Texte à lire**
Maintenant, on passe à la démo Windows.

Dans ce bloc, on va exécuter trois scripts dans un ordre fixe. D'abord `experiment.py`, ensuite `run_kat.py`, puis `run_charts.py`.

Le but est de montrer l'exécution réelle, puis de lire les sorties importantes juste après chaque commande.

## Section 3 - Exécution des mesures sur Windows
**Où sommes-nous**
`scripts/experiment.py`

**Texte à lire avant la commande**
On commence par `experiment.py`, qui est le script de campagne de mesure. Il exécute la matrice expérimentale et écrit un CSV de résultats.

```bash
cd crypto-experiments
python scripts/experiment.py
```

**Texte à lire après la commande**
Dans la sortie terminal, on vérifie trois points. Premièrement, les lignes de type `Running ...` qui confirment les exécutions par configuration. Deuxièmement, le tableau `Run summary by algorithm` qui confirme la couverture des algorithmes. Troisièmement, le chemin du fichier CSV exporté dans `data/results/`.

## Section 4 - Exécution KAT sur Windows
**Où sommes-nous**
`scripts/run_kat.py`

**Texte à lire avant la commande**
Ensuite, on lance `run_kat.py`, qui est le script de validation cryptographique. Il vérifie que les implémentations produisent les sorties attendues par les vecteurs de référence.

```bash
python scripts/run_kat.py
```

**Texte à lire après la commande**
Dans la sortie, on vérifie que les suites KAT passent sans échec. C'est cette étape qui confirme que les mesures sont faites sur des implémentations valides.

## Section 5 - Génération des graphes sur Windows
**Où sommes-nous**
`scripts/run_charts.py`

**Texte à lire avant la commande**
Enfin, on lance `run_charts.py`, qui est le script d'orchestration des graphes.

```bash
python scripts/run_charts.py 01
python scripts/run_charts.py 03
```

**Texte à lire après la commande**
Dans la sortie, on vérifie les lignes `Sources x86 (...)` et les chemins des fichiers générés. Cela confirme que les graphes sont bien produits à partir des bonnes sources.

## Section 6 - Vérification des sorties Windows
**Où sommes-nous**
`data/results/` et `data/charts/`

**Texte à lire**
Pour fermer la partie Windows, on ouvre les dossiers de sortie.

On vérifie la présence du CSV horodaté dans `data/results/`, puis la présence des images dans `data/charts/`. Cette vérification confirme que la chaîne Windows est complète de bout en bout.

## Section 7 - Préparation de la démo Raspberry Pi
**Où sommes-nous**
Terminal Raspberry Pi + VS Code (remote)

**Texte à lire**
Maintenant, on reproduit exactement la même séquence sur Raspberry Pi.

Même ordre, mêmes scripts, même logique de vérification. D'abord `experiment.py`, ensuite `run_kat.py`, puis `run_charts.py`.

Cette répétition contrôlée permet de comparer les deux plateformes avec une méthode identique.

## Section 8 - Exécution des mesures sur Raspberry Pi
**Où sommes-nous**
`scripts/experiment.py`

**Texte à lire avant la commande**
On commence par `experiment.py` sur le Pi, pour produire les mesures de la plateforme ARM.

```bash
cd crypto-experiments
python scripts/experiment.py
```

**Texte à lire après la commande**
Dans la sortie, on vérifie les lignes d'exécution, le résumé final par algorithme et le fichier CSV exporté.

Si Twofish n'est pas disponible dans l'environnement Python actif du Pi, on doit voir le warning explicite prévu par le correctif.

## Section 9 - Exécution KAT sur Raspberry Pi
**Où sommes-nous**
`scripts/run_kat.py`

**Texte à lire avant la commande**
Ensuite, on exécute `run_kat.py` sur le Pi pour valider la conformité cryptographique dans cet environnement.

```bash
python scripts/run_kat.py
```

**Texte à lire après la commande**
On confirme que les suites de test passent. Le point important ici, c'est que la validation est rejouée sur la plateforme ARM, pas seulement sur Windows.

## Section 10 - Génération des graphes sur Raspberry Pi
**Où sommes-nous**
`scripts/run_charts.py`

**Texte à lire avant la commande**
Enfin, on génère les graphes sur Raspberry Pi avec les mêmes cibles.

```bash
python scripts/run_charts.py 01
python scripts/run_charts.py 03
```

**Texte à lire après la commande**
On vérifie les sources affichées et les chemins des images générées. Cette étape confirme que le pipeline de visualisation est aussi opérationnel sur le Pi.

## Section 11 - Vérification des sorties Raspberry Pi
**Où sommes-nous**
`data/results/` et `data/charts/`

**Texte à lire**
Pour clôturer la partie Raspberry Pi, on vérifie les artefacts générés.

On confirme la présence du CSV Pi dans `data/results/`, puis la présence des graphes dans `data/charts/`.

## Section 12 - Comparaison finale Windows vs Raspberry Pi
**Où sommes-nous**
`data/results/` + graphes de comparaison inter-plateformes

**Texte à lire**
Dernière étape, on place les deux exécutions côte à côte.

On compare les fichiers de résultats et les graphes inter-plateformes pour montrer que la même chaîne a été rejouée proprement sur Windows et sur Raspberry Pi.

## Conclusion - Démo validée de bout en bout
**Où sommes-nous**
Slide de clôture
