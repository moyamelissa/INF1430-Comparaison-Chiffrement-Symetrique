# Vidéo 4 - Démo complète Windows + Raspberry Pi

## Intro - Objectif de la démo
**Où sommes-nous**
Présentation PowerPoint - Diapo de transition Démo complète

**Texte à lire**
Dans cette vidéo, on ne fait pas de théorie. On montre directement le code en exécution, d'abord sur Windows, puis sur Raspberry Pi.

On va lancer quatre commandes dans le même ordre sur les deux machines. D'abord `python -m pytest`, pour vérifier les tests et la couverture. Ensuite `run_kat.py`, pour valider la conformité cryptographique. Puis `experiment.py`, pour exécuter la campagne de mesure et produire le CSV de résultats. Enfin `run_charts.py`, pour générer les figures à partir des CSV présents.

Après ça, on fait une vérification data visible en terminal. L'objectif est de prouver à l'écran que les fichiers ont bien été écrits localement.

Le but est simplement de montrer que la chaîne s'exécute réellement de bout en bout, avec les mêmes étapes, les mêmes contrôles et les mêmes types de sorties sur les deux plateformes.

## Section 1 - Retour sur l'erreur de la vidéo 1 et correctif Twofish
**Où sommes-nous**
VIDÉO YOUTUBE, puis `scripts/experiment.py`

**Texte à lire**
Avant de lancer la démo complète, je corrige un point important observé pendant la démo de la vidéo 1.

Pendant cette première démo sous Windows, l'exécution de `scripts/experiment.py` n'incluait pas Twofish dans certains environnements. La cause était une dépendance Python manquante dans l'interpréteur actif, donc le package `twofish` n'était pas importable au moment de la campagne.

Le risque, dans ce cas, c'est de croire que toute la matrice est exécutée alors qu'un algorithme est absent, ce qui rend la sortie incomplète si on ne regarde pas les logs en détail.

Le correctif a été appliqué dans `scripts/experiment.py` avec quatre sécurités. Premièrement, le script détecte explicitement l'erreur d'import Twofish. Deuxièmement, il affiche un message d'alerte clair avec l'interpréteur actif et la commande d'installation recommandée. Troisièmement, le script imprime un résumé final par algorithme. Quatrièmement, il retourne un code d'échec si un algorithme planifié ne produit aucun succès.

Concrètement, si le problème réapparaît, l'utilisateur voit immédiatement un warning explicite dans le terminal, puis un statut de run non conforme en fin d'exécution. Si un algorithme planifié n'aboutit pas, le script retourne un code d'échec, ce qui permet au pipeline CI/CD de détecter automatiquement l'exécution incomplète. Le but est d'attirer l'attention tout de suite, sans laisser passer une exécution invalide.

## Section 2 - Préparation de la démo Windows
**Où sommes-nous**
Terminal Windows + VS Code

**Texte à lire**
Maintenant, on passe à la démo Windows.

Les commandes sont lancées depuis `crypto-experiments`, avec l'environnement virtuel du projet déjà activé.

Dans ce bloc, on va exécuter quatre commandes dans un ordre fixe. D'abord `python -m pytest`, ensuite `run_kat.py`, puis `experiment.py`, puis `run_charts.py`.

Le but est de montrer l'exécution réelle, puis de lire les sorties importantes juste après chaque commande.

## Section 3 - Exécution des tests sur Windows
**Où sommes-nous**
`pytest`

**Texte à lire avant la commande**
On commence par `pytest`, pour vérifier que la base logicielle est saine avant de lancer le pipeline. Ici, on veut confirmer que les tests passent et que la couverture atteint bien 100 %.

```bash
cd crypto-experiments
python -m pytest
```

**Texte à lire après la commande**
Dans la sortie, on vérifie deux signaux. D'abord le total de tests exécutés. Ensuite le message de couverture finale, qui doit confirmer 100 % sur le périmètre testé.

## Section 4 - Exécution KAT sur Windows
**Où sommes-nous**
`scripts/run_kat.py`

**Texte à lire avant la commande**
On commence par `run_kat.py`, qui est le script de validation cryptographique. Il vérifie que les implémentations produisent les sorties attendues par les vecteurs de référence.

```bash
cd crypto-experiments
python scripts/run_kat.py
```

**Texte à lire après la commande**
Dans la sortie, on vérifie le signal `ALL KAT SUITES PASSED`. C'est cette étape qui confirme que les fonctions, les sorties et les comportements attendus sont bien valides.

Si ce signal n'apparaît pas, l'échec n'est pas silencieux: il remonte lors du push via le pipeline, ce qui signale immédiatement qu'une partie de la validation n'est pas passée.

## Section 5 - Exécution des mesures sur Windows
**Où sommes-nous**
`scripts/experiment.py`

**Texte à lire avant la commande**
Ensuite, on lance `experiment.py`, qui est le script de campagne de mesure. Il exécute la matrice expérimentale et écrit un CSV de résultats.

```bash
python scripts/experiment.py
```

**Texte à lire après la commande**
Dans la sortie terminal, on vérifie trois points. Premièrement, les lignes de type `Running ...` qui confirment les exécutions par configuration. Deuxièmement, le tableau `Run summary by algorithm` qui confirme la couverture des algorithmes. Troisièmement, le chemin du fichier CSV exporté dans `data/results/`.

Si plusieurs campagnes sont exécutées le même jour, le fichier est suffixé automatiquement en `_1`, `_2`, et ainsi de suite. Il faut donc lire le chemin affiché dans le terminal.

## Section 6 - Génération des graphes sur Windows
**Où sommes-nous**
`scripts/run_charts.py`

**Texte à lire avant la commande**
Enfin, on lance `run_charts.py`, qui est le script d'orchestration des graphes. Son rôle est de résoudre la clé cible, d'appeler les modules `build_*` correspondants, puis de laisser ces modules lire les CSV et écrire les images.

```bash
python scripts/run_charts.py 04
python scripts/run_charts.py all
```

**Texte à lire après la commande**
Dans la sortie, on lit d'abord les sources effectivement utilisées. On voit ici trois CSV côté x86 et trois CSV côté Raspberry Pi. C'est ce bloc qui confirme quels fichiers servent réellement à construire les graphes.

Ensuite, le script affiche la sélection `01, 02, 03, 04`, puis il génère chaque dossier dans l'ordre. Les lignes `Enregistré:` confirment à chaque fois l'écriture réelle des figures dans `data/charts/`.

Au final, cette commande montre bien que toute la chaîne de visualisation fonctionne en une seule exécution, depuis la lecture des CSV jusqu'à l'écriture des figures finales.

Le point important pour la lecture des logs, c'est que `run_charts.py` affiche explicitement les sources utilisées. Pendant la démo, on lit ces lignes à voix haute pour confirmer que les CSV attendus sont bien pris en compte.

La commande `04` montre un cas ciblé de synthèse, puis la commande `all` montre la vue système complète sur `01`, `02`, `03` et `04`.

## Section 7 - Vérification des sorties Windows
**Où sommes-nous**
`data/results/` et `data/charts/`

**Texte à lire**
Pour fermer la partie Windows, on ouvre les dossiers de sortie.

On vérifie la présence du CSV horodaté dans `data/results/`, puis la présence des images dans `data/charts/`. Cette vérification confirme que la chaîne Windows est complète de bout en bout.

Pour le montrer clairement en terminal, on peut exécuter:

```bash
Get-ChildItem data/results/*.csv | Sort-Object LastWriteTime -Descending | Select-Object -First 5 Name, LastWriteTime
Get-ChildItem data/charts -Recurse -File *.png | Sort-Object LastWriteTime -Descending | Select-Object -First 10 FullName, LastWriteTime
```

Avec ces deux commandes, on voit immédiatement les fichiers créés récemment et leur horodatage local.

## Section 8 - Préparation de la démo Raspberry Pi
**Où sommes-nous**
Terminal Raspberry Pi + VS Code (remote)

**Texte à lire**
Maintenant, on reproduit exactement la même séquence sur Raspberry Pi.

Les commandes sont lancées depuis `crypto-experiments`, avec l'environnement virtuel du projet déjà activé.

Même ordre, mêmes scripts, même logique de vérification. D'abord `python -m pytest`, ensuite `run_kat.py`, puis `experiment.py`, puis `run_charts.py`.

Cette répétition contrôlée permet de comparer les deux plateformes avec une méthode identique.

## Section 9 - Exécution des tests sur Raspberry Pi
**Où sommes-nous**
`pytest`

**Texte à lire avant la commande**
On commence par `pytest` sur le Pi, pour vérifier que les tests et la couverture passent aussi dans cet environnement.

```bash
cd crypto-experiments
python -m pytest
```

**Texte à lire après la commande**
On vérifie le total de tests exécutés, puis le message final de couverture. Le point important ici, c'est que la validation logicielle est rejouée sur ARM, pas seulement sur Windows.

## Section 10 - Exécution KAT sur Raspberry Pi
**Où sommes-nous**
`scripts/run_kat.py`

**Texte à lire avant la commande**
On commence par `run_kat.py` sur le Pi pour valider la conformité cryptographique dans cet environnement.

```bash
cd crypto-experiments
python scripts/run_kat.py
```

**Texte à lire après la commande**
On confirme le signal `ALL KAT SUITES PASSED`. Le point important ici, c'est que la validation est rejouée sur la plateforme ARM, pas seulement sur Windows.

Et si ce signal n'apparaît pas, l'échec remonte aussi au moment du push via le pipeline, pour éviter de laisser passer une version invalide.

## Section 11 - Exécution des mesures sur Raspberry Pi
**Où sommes-nous**
`scripts/experiment.py`

**Texte à lire avant la commande**
Ensuite, on lance `experiment.py` sur le Pi, pour produire les mesures de la plateforme ARM.

```bash
python scripts/experiment.py
```

**Texte à lire après la commande**
Dans la sortie, on vérifie les lignes d'exécution, le résumé final par algorithme et le fichier CSV exporté.

Ici, on mentionne le changement récent de nommage: le fichier inclut maintenant la plateforme pour éviter toute confusion entre machines, par exemple `experiment_raspberry-pi_YYYYMMDD.csv`, puis `experiment_raspberry-pi_YYYYMMDD_1.csv` si on relance le même jour.

Si Twofish n'est pas disponible dans l'environnement Python actif du Pi, on doit voir le warning explicite prévu par le correctif.

## Section 12 - Génération des graphes sur Raspberry Pi
**Où sommes-nous**
`scripts/run_charts.py`

**Texte à lire avant la commande**
Enfin, on génère les graphes sur Raspberry Pi avec la même logique d'orchestration, pour rejouer exactement la chaîne côté ARM.

```bash
python scripts/run_charts.py 04
python scripts/run_charts.py all
```

**Texte à lire après la commande**
On vérifie les mêmes quatre signaux que sur Windows: sélection de la cible, génération du dossier, sources lues, puis images enregistrées. Cette symétrie de lecture est importante, parce qu'elle montre que le pipeline de visualisation est opérationnel sur le Pi avec la même méthode de validation.

## Section 13 - Vérification des sorties Raspberry Pi
**Où sommes-nous**
`data/results/` et `data/charts/`

**Texte à lire**
Pour clôturer la partie Raspberry Pi, on vérifie les artefacts générés.

On confirme la présence du CSV Pi dans `data/results/`, puis la présence des graphes dans `data/charts/`.

Pour une preuve simple en terminal Linux:

```bash
ls -lh data/results | head
find data/results -maxdepth 1 -type f -name "*.csv" -printf "%TY-%Tm-%Td %TH:%TM %p\n" | sort | tail -n 5
find data/charts -type f -name "*.png" -printf "%TY-%Tm-%Td %TH:%TM %p\n" | sort | tail -n 10
```

Ces commandes montrent les artefacts générés localement avec date et heure, donc la preuve d'exécution est directe.

## Section 14 - Comparaison finale Windows vs Raspberry Pi
**Où sommes-nous**
`data/results/` + graphes de comparaison inter-plateformes

**Texte à lire**
Dernière étape, on place les deux exécutions côte à côte.

On compare les fichiers de résultats et les graphes inter-plateformes pour montrer que la même chaîne a été rejouée proprement sur Windows et sur Raspberry Pi. Le critère de validation est identique dans les deux cas: mêmes étapes exécutées, mêmes types de logs attendus, même structure de sorties dans `data/results/` et `data/charts/`.

## Conclusion - Démo validée de bout en bout
**Où sommes-nous**
Slide de clôture
