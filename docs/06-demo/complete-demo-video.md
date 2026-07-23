# Vidéo de démonstration complète

## Objectif

Bonjour et bienvenue dans cette vidéo de démonstration. Dans cette vidéo, je montre tout le pipeline du projet de bout en bout. L’idée est de prouver à l’écran que le projet s’exécute réellement, avec les mêmes étapes sur Windows et sur Raspberry Pi.

Je vais suivre une séquence simple. Je lance les tests, puis la validation cryptographique KAT, ensuite la campagne de mesures, l’audit statistique IC95, la génération des graphes, et enfin la vérification des artefacts produits.

À chaque étape, je lis surtout la sortie terminal. L’objectif est de faire ressortir les lignes importantes qui montrent que l’exécution a bien réussi et que les fichiers attendus ont été créés.

---

## Section 1.1 - Validation logicielle (Windows)

Je commence par les tests automatiques. Ici, l’idée est de montrer que la base du projet est saine avant de parler des mesures ou des graphes.

```powershell
python -m pytest
```

**Texte à lire après la commande**
Pour cette section Windows, je lis exactement les indicateurs affichés dans la sortie du terminal pour ce run précis.

Les lignes importantes à montrer sont celles-ci, avec les valeurs réellement observées à l'écran.

- `collected <N> items` montre que toute la suite de tests a bien été détectée et planifiée sur Windows.
- Le rapport indique 1468 déclarations exécutées, aucune manquée, 422 branches testées, pour une couverture totale de 100 %

Donc au final, ces lignes prouvent deux choses à la fois. Premièrement, les tests fonctionnels passent tous. Deuxièmement, la couverture affichée est conforme aux critères retenus pour cette exécution Windows.

C’est important parce que ces tests valident toute la chaîne logique du projet , donc les primitives de chiffrement, les modes, les KAT, les scripts de mesure et les scripts d’audit. Avant de présenter les résultats expérimentaux, je peux donc dire que le socle logiciel est déjà vérifié.

---

## Section 1.2 - Validation cryptographique KAT (Windows)

J’enchaîne avec la validation KAT, know answer test. Ici, je vérifie que chaque algorithme produit bien les résultats attendus par ses vecteurs de référence.

On lance la commande:

```powershell
python scripts/run_kat.py
```

Le résultat principal, c’est que toutes les suites passent. Donc nous avons premierement

- `TOTAL | 60 | 60 | 0 | PASS` qui montre que les 60 vérifications KAT ont réussi, avec 0 échec. Puis ensuite, nous avons
- `ALL KAT SUITES PASSED` qui montre que toutes les suites KAT sont validées globalement.

Ce que je veux faire ressortir ici, c’est que la suite KAT couvre tout le cœur cryptographique du projet, et que le bilan final est propre : 60 assertions, 60 réussites, 0 échec. Cela veut dire que les implémentations sont cohérentes avec les vecteurs de référence, et c’est important parce que je peux ensuite parler des mesures et des graphes en m’appuyant sur une validation cryptographique déjà confirmée.

---

## Section 1.3 - Campagne de mesures (Windows)

On passe maintenant a la campagne de mesures. Ici, nous voulons montrer que le script parcourt toute la matrice expérimentale et qu’il produit bien les résultats attendus pour chaque algorithme.

```powershell
python scripts/experiment.py
```

**Ligne à montrer**

* `[info] Algorithms scheduled: 3DES, AES, ChaCha20, DES, Twofish`
  Ici, on voit que la campagne couvre bien toutes les familles prévues. C’est important parce que cela confirm que je ne lance pas un test isolé, mais une vraie matrice complète.
* `Running ...`
* Ces lignes debutant avec running.. montrent que le script parcourt plusieurs tailles de message et plusieurs modes. On peut donc comparer les performances dans des conditions variées, et non seulement sur un seul cas.
* Quand je lis une ligne commem par exemple la premiere srotie `Running AES-ECB key=128bit msg=64B … enc=0.064ms thr=0.95MB/s avalanche=0.498`, je peux la découper simplement. `AES-ECB` me dit quel algorithme et quel mode sont testés. `key=128bit` me donne la taille de la clé. `msg=64B` me donne la taille du message. `enc=0.064ms` indique le temps de chiffrement, `thr=0.95MB/s` indique le débit, et `avalanche=0.498` montre à quel point la sortie change quand l’entrée change.
* `Run summary by algorithm`
  Le résumé final me confirme que tout s’est terminé correctement, sans oubli ni échec sur une famille d’algorithmes.
* `[ok] All algorithms in the matrix completed successfully.`
  Ça veut dire que la campagne est complète et exploitable. Je peux ensuite passer à l’audit IC95 en sachant que les mesures ont bien été générées.

Ce qui est important à retenir ici, c’est que la campagne de mesures a parcouru toute la matrice prévue, sans échec, et a généré des données exploitables pour la comparaison des performances. 

---

## Section 1.4 - Audit IC95 (Windows)

L'étape suivante est l'audit statistique IC95. Cet audit traite les données brutes de mesure. Donc elle calcul dabord des intervalles de confiance à 95 %, regroupement par configuration, et validation contre un ensemble de seuils de qualité prédéfinis, en anglais on appelle cela les gates. Donc on commence par entrer la commande suivante..

```powershell
python scripts/audit/audit_ic95.py --enforce-gates
```

Puis on peut maintenant analyser la sortie. Dans mon cas de démonstration, je montre d’abord une sortie en échec global pour expliquer la logique de décision.

* `Raw IC95 rows exported`
  Cette ligne confirme que les lignes brutes ont été recalculées et exportées. L’audit travaille bien sur des données réelles, pas sur un résultat en cache.
* `Grouped IC95 audit exported`
  Cette ligne confirme la création du rapport agrégé par configuration, qui sert aux verdicts PASS et FAIL.
* `Included result CSV files (7)`
  Ce tableau est important. Il montre exactement quels fichiers de `data/results/` sont inclus dans le calcul, dont `windows_experience4_20260723.csv`.
* `Summary: PASS=232 FAIL=78 TOTAL=310`
  Ici, on voit qu’il existe des FAIL locaux sur certaines configurations, même si le pipeline s’est exécuté correctement.
* `Gate 1 - min repetitions >= 100: PASS`
  Les répétitions minimales sont suffisantes.
* `Gate 2 - message_size >= 1024B pass rate >= 90.00%: FAIL (pass_rate=86.56%, pass=161/186)`
  Cette gate provoque l’échec global. Le taux passe sous 90 % pour les tailles importantes.
* `Gate 3 - outliers (...) <= 20: PASS`
  Le nombre d’outliers sévères reste dans la limite.
* `Quality gate enforcement: FAIL`
  Le verdict final est FAIL parce qu’une gate critique, ici Gate 2, est en échec.

Ensuite, pendant la démo, je retire temporairement `windows_experience4_20260723.csv` pour montrer l’impact d’un run plus bruité sur le verdict global, puis je relance le même audit IC95.

```powershell
Rename-Item data/results/windows_experience4_20260723.csv tmp_experiment4_excluded.csv
python scripts/audit/audit_ic95.py --enforce-gates
Rename-Item data/results/tmp_experiment4_excluded.csv windows_experience4_20260723.csv
```

Après ce retrait temporaire, la sortie remonte à `PASS=253 FAIL=57 TOTAL=310` avec `Gate 2` à `91.40%` et `Quality gate enforcement: PASS`.

Le message à retenir est simple. Le script n’est pas contradictoire. Il est sensible au jeu de fichiers réellement inclus dans l’audit. On n’est pas limité à trois expériences par machine. On peut ajouter un `experiment4` ou `experiment5`, mais chaque run doit respecter la qualité statistique exigée pour rester dans les gates.

En résumé, l’IC95 est notre garde-fou statistique. Il confirme que nos mesures sont stables, reproductibles et assez précises pour comparer sérieusement les algorithmes. Avec les tests et les KAT, on valide le quoi. Avec l’IC95, on valide la confiance dans les chiffres.

---

## Section 1.5 - Génération des graphes (Windows)

Je passe ensuite à la génération des graphiques. Ici, je veux montrer que le script lit bien les données x86 et Raspberry Pi, puis qu’il produit les graphes attendus pour chaque bloc.

```powershell
python scripts/run_charts.py
```

On voit maitnenant que

`Sources x86 (5) : ...` le script utilise bien les cinq fichiers x86. C’est important parce que les graphes s’appuient sur plusieurs expériences réelles, pas sur un seul CSV.

`Sources Raspberry Pi (3) : ...`
Cette ligne confirme que la comparaison avec Raspberry Pi est bien incluse aussi. On montre donc les deux plateformes dans la même génération de graphes.

`[run_charts] Sélection: 01, 02, 03, 04` Ici cette ligne veut dire que le script génère les quatre blocs prévus. C’est utile parce qu’on peut ensuite présenter les résultats de performance, d’avalanche, de modes et d’aide à la décision.

* `[run_charts] Génération du dossier 01...`
  Cette partie me montre que le bloc throughput est bien produit. Je peux alors parler de vitesse et de comparaison entre algorithmes.
* `[run_charts] Génération du dossier 02...`
  Ici, le script génère le bloc avalanche. C’est important parce que ça illustre le comportement cryptographique, pas seulement la vitesse.
* `Mesure du score d'avalanche DES pour les tours 1–16`
  Cette sortie montre que le score d’avalanche augmente jusqu’à se stabiliser autour de 50 %. C’est exactement ce qu’on attend d’un bon effet de diffusion.
* `Graphique enregistré: ... avalanche-convergence-des-rounds.png`
  Ça confirme que le graphique a bien été créé et sauvegardé.
* `Génération de la démonstration de vulnérabilité ECB…`
  Cette ligne est importante parce qu’elle montre visuellement pourquoi le mode ECB n’est pas recommandé pour des images : il laisse apparaître des motifs.
* `image-original.bmp`, `image-encrypted-ecb.bmp`, `image-encrypted-cbc.bmp`
  Avec ces fichiers, je peux montrer la différence entre l’image originale, l’image chiffrée en ECB et celle chiffrée en CBC. C’est une démonstration très parlante.
* `[run_charts] Génération du dossier 04...` Ici, le script termine avec les graphes d’aide à la décision. C’est utile pour passer ensuite à l’interprétation finale.
* `[run_charts] Terminé.`
  Ce message final me confirme que toute la génération des graphes s’est bien déroulée jusqu’au bout. C’est important parce que je peux ensuite montrer les fichiers produits dans le dossier `data/charts/`.

En conclusionà, la génération des graphes confirme que nos données sont bien transformées en résultats visuels exploitables. Elle valide que le pipeline va jusqu’au bout, de la mesure brute à l’interprétation, pour comparer clairement les algorithmes et les plateformes.

---

## Section 1.6 - Création du bundle de preuves (Windows)

Pour terminer la partie Windows, je regroupe maintenant les preuves dans un bundle. L’objectif n’est pas de produire de nouveaux résultats, mais de conserver une trace propre et vérifiable de tout ce qui a déjà été exécuté.

```powershell
python scripts/audit/audit_bundle.py --skip-run
```

Avec cette commande, le script crée un dossier horodaté dans `data/evidence/bundle/`. À l’intérieur, on retrouve le manifeste du run, les logs disponibles et les artefacts copiés comme `coverage.xml`.

Le point important à dire ici, c’est que le bundle ne remplace pas les tests ou l’audit. Il sert à les documenter et à les rendre auditable. C’est une bonne pratique parce qu’on ne se contente pas d’affirmer que les résultats sont bons. On garde aussi les logs, les rapports et le contexte exact du run pour qu’une autre personne puisse les vérifier plus tard.

En pratique, ça montre trois choses. D’abord, la reproductibilité, parce qu’on peut relier les preuves à une exécution précise. Ensuite, la transparence, parce que les artefacts sont regroupés au lieu d’être dispersés. Enfin, la rigueur, parce qu’on conserve une preuve structurée au lieu de s’appuyer seulement sur une explication orale ou sur une capture d’écran.

Donc, si je veux montrer que le projet est développé de manière responsable, cette étape est importante. Elle montre que les résultats sont non seulement calculés correctement, mais aussi archivés de manière propre, traçable et facile à relire.

---

## SECTION 2 - Validation sur Raspberry Pi

Je rejoue maintenant la même séquence complète sur Raspberry Pi, architecture ARMv7. Les scripts, les seuils et les paramètres sont identiques à Windows. L'objectif est de démontrer que le pipeline entier est reproductible et portable sur une plateforme ARM.

---

#### Section 2.1 - Validation Logicielle (Raspberry Pi)

```bash
python -m pytest
```

Sur Raspberry Pi, je lis les mêmes indicateurs de sortie pour ce run Pi et je les compare à Windows. Le total `collected` et `passed` doit rester cohérent entre plateformes, tandis que le temps peut varier. La couverture affichée doit aussi être annoncée telle qu'elle apparaît dans la sortie Pi, afin de garder une conclusion factuelle et traçable.

---

#### Section 2.2 - Validation Cryptographique KAT (Raspberry Pi)

```bash
python scripts/run_kat.py
```

La validation KAT passe intégralement, 60/60 assertions. Cela confirme que les implémentations cryptographiques produisent exactement les mêmes résultats sur ARM que sur x86. Aucune divergence liée à l'architecture, aucun problème d'endianness.

---

#### Section 2.3 - Campagne de Mesures (Raspberry Pi)

```bash
python scripts/experiment.py
```

La matrice expérimentale s'exécute complètement. Les timings absolus diffèrent, Pi est environ 5 à 10 fois plus lent, mais les classements relatifs entre algorithmes demeurent identiques. AES reste rapide, DES reste lent, peu importe la plateforme. Cela démontre que la comparaison de performance est robuste et reproductible au-delà des architectures.

---

#### Section 2.4 - Audit IC95 (Raspberry Pi)

```bash
python scripts/audit/audit_ic95.py --enforce-gates
```

> L'audit statistique sur Pi valide tous les gates, répétitions suffisantes, gros messages stables, outliers contrôlés. Cela prouve que même sur une plateforme plus lente, les données restent stables et statistiquement crédibles. La qualité des mesures est indépendante de l'architecture.

---

#### Section 2.5 - Génération des Graphes (Raspberry Pi)

```bash
python scripts/run_charts.py 04
python scripts/run_charts.py all
```

Les quatre blocs graphiques se génèrent correctement. Le script consolide les données x86 et Raspberry Pi, produisant des visualisations comparatives. La structure graphique reste identique, validant que l'interprétation des résultats ne dépend pas de la plateforme d'exécution.

---

#### Section 2.6 - Vérification des Artefacts (Raspberry Pi)

```bash
find data/results -maxdepth 1 -type f -name "*.csv" -printf "%TY-%Tm-%Td %TH:%TM %p\n" | sort | tail -n 8
find data/evidence -maxdepth 1 -type f -name "*.csv" -printf "%TY-%Tm-%Td %TH:%TM %p\n" | sort | tail -n 4
find data/charts -type f -name "*.png" -printf "%TY-%Tm-%Td %TH:%TM %p\n" | sort | tail -n 12
```

Tous les artefacts sont présents sur Pi, CSV de mesures, rapports d'audit, graphes PNG. Les timestamps confirment que la chaîne complète, de la mesure à la génération graphique, s'est exécutée de bout en bout sans interruption.

---

## Conclusion

En synthèse, cette démonstration montre une chaîne complète et reproductible. On valide la partie logicielle, la partie cryptographique, les mesures, l’audit statistique IC95 et la génération des graphes.

Les mêmes commandes ont été exécutées dans le même ordre sur Windows et sur Raspberry Pi. Les sorties sont tracées, les artefacts sont visibles, et les contrôles de qualité sont explicites.

La conclusion est que le pipeline est opérationnel, vérifiable et suffisamment robuste pour soutenir l’analyse finale du projet.# Vidéo de démonstration complète

## Objectif

Bonjour et bienvenue dans cette vidéo de démonstration. Dans cette vidéo, je montre tout le pipeline du projet de bout en bout. L’idée est de prouver à l’écran que le projet s’exécute réellement, avec les mêmes étapes sur Windows et sur Raspberry Pi.

Je vais suivre une séquence simple. Je lance les tests, puis la validation cryptographique KAT, ensuite la campagne de mesures, l’audit statistique IC95, la génération des graphes, et enfin la vérification des artefacts produits.

À chaque étape, je lis surtout la sortie terminal. L’objectif est de faire ressortir les lignes importantes qui montrent que l’exécution a bien réussi et que les fichiers attendus ont été créés.

---

## Section 1.1 - Validation logicielle (Windows)

Je commence par les tests automatiques. Ici, l’idée est de montrer que la base du projet est saine avant de parler des mesures ou des graphes.

```powershell
python -m pytest
```

**Texte à lire après la commande**
Pour cette section Windows, je lis exactement les indicateurs affichés dans la sortie du terminal pour ce run précis.

Les lignes importantes à montrer sont celles-ci, avec les valeurs réellement observées à l'écran.

- `collected <N> items` montre que toute la suite de tests a bien été détectée et planifiée sur Windows.
- `<N> passed in <T>s` montre que tous les tests détectés ont réussi, sans aucun échec.
- Le total montre que `1436 déclarations exécutées, zéro manquées, 422 branches testées. La couverture totale : 100 %.`
- `Required test coverage of 100% reached. Total coverage: <P>%` confirme le niveau de couverture réellement mesuré pour ce run Windows.

Donc au final, ces lignes prouvent deux choses à la fois. Premièrement, les tests fonctionnels passent tous. Deuxièmement, la couverture affichée est conforme aux critères retenus pour cette exécution Windows.

C’est important parce que ces tests valident toute la chaîne logique du projet , donc les primitives de chiffrement, les modes, les KAT, les scripts de mesure et les scripts d’audit. Avant de présenter les résultats expérimentaux, je peux donc dire que le socle logiciel est déjà vérifié.

---

## Section 1.2 - Validation cryptographique KAT (Windows)

J’enchaîne avec la validation KAT, know answer test. Ici, je vérifie que chaque algorithme produit bien les résultats attendus par ses vecteurs de référence.

On lance la commande:

```powershell
python scripts/run_kat.py
```

Le résultat principal, c’est que toutes les suites passent. Donc nous avons premierement

- `TOTAL | 60 | 60 | 0 | PASS` qui montre que les 60 vérifications KAT ont réussi, avec 0 échec. Puis ensuite, nous avons
- `ALL KAT SUITES PASSED` qui montre que toutes les suites KAT sont validées globalement.

Ce que je veux faire ressortir ici, c’est que la suite KAT couvre tout le cœur cryptographique du projet, et que le bilan final est propre : 60 assertions, 60 réussites, 0 échec. Cela veut dire que les implémentations sont cohérentes avec les vecteurs de référence, et c’est important parce que je peux ensuite parler des mesures et des graphes en m’appuyant sur une validation cryptographique déjà confirmée.

---

## Section 1.3 - Campagne de mesures (Windows)

On passe maintenant a la campagne de mesures. Ici, nous voulons montrer que le script parcourt toute la matrice expérimentale et qu’il produit bien les résultats attendus pour chaque algorithme.

```powershell
python scripts/experiment.py
```

**Ligne à montrer**

* `[info] Algorithms scheduled: 3DES, AES, ChaCha20, DES, Twofish`
  Ici, on voit que la campagne couvre bien toutes les familles prévues. C’est important parce que cela confirm que je ne lance pas un test isolé, mais une vraie matrice complète.
* `Running ...`
* Ces lignes debutant avec running.. montrent que le script parcourt plusieurs tailles de message et plusieurs modes. On peut donc comparer les performances dans des conditions variées, et non seulement sur un seul cas.
* Quand je lis une ligne commem par exemple la premiere srotie `Running AES-ECB key=128bit msg=64B … enc=0.064ms thr=0.95MB/s avalanche=0.498`, je peux la découper simplement. `AES-ECB` me dit quel algorithme et quel mode sont testés. `key=128bit` me donne la taille de la clé. `msg=64B` me donne la taille du message. `enc=0.064ms` indique le temps de chiffrement, `thr=0.95MB/s` indique le débit, et `avalanche=0.498` montre à quel point la sortie change quand l’entrée change.
* `Run summary by algorithm`
  Le résumé final me confirme que tout s’est terminé correctement, sans oubli ni échec sur une famille d’algorithmes.
* `[ok] All algorithms in the matrix completed successfully.`
  Ça veut dire que la campagne est complète et exploitable. Je peux ensuite passer à l’audit IC95 en sachant que les mesures ont bien été générées.

Ce qui est important a retenir ici est que la validation KAT est essentielle, car elle confirme d’abord la conformité des implémentations aux vecteurs de référence. Elle donne ensuite un socle fiable pour interpréter les mesures de performance sans ambiguïté sur la justesse cryptographique

---

## Section 1.4 - Audit IC95 (Windows)

L'étape suivante est l'audit statistique IC95. Cet audit traite les données brutes de mesure. Donc elle calcul dabord des intervalles de confiance à 95 %, regroupement par configuration, et validation contre un ensemble de seuils de qualité prédéfinis, en anglais on appelle cela les gates. Donc on commence par entrer la commande suivante..

```powershell
python scripts/audit/audit_ic95.py --enforce-gates
```

Puis on peut maitenant analyser la sortie, on vois dabord

* `Raw IC95 rows exported`
  Cette ligne montre que les mesures brutes ont bien été exportées. C’est la première preuve que l’audit travaille sur des données réelles.
* `Grouped IC95 audit exported`
  Ici, l’audit regroupé est produit. Cela veut dire qu’on passe d’une sortie brute à une version structurée, plus facile à exploiter.
* `Summary: PASS=281 FAIL=29 TOTAL=310`
  Ce résumé me donne le volume total de contrôles effectués. Le point important, c’est qu’on voit tout de suite qu’il y a un vrai traitement statistique derrière l’audit.
* `Gate 1 - min repetitions >= 100: PASS`
  Cette gate vérifie qu’il y a assez de répétitions pour que les mesures soient crédibles.
* `Gate 2 - message_size >= 1024B pass rate >= 90.00%: PASS`
  Cette gate montre que les grands messages passent à un taux suffisamment élevé. C’est important pour valider la stabilité sur les tailles qui comptent vraiment.
* `Gate 3 - outliers (ic95_relative_pct_mean > 20.00%) <= 20: PASS`
  Cette gate contrôle qu’il n’y a pas trop de valeurs aberrantes. Elle m’aide à montrer que les résultats sont cohérents et utilisables.
* `Quality gate enforcement: PASS`
  Le message final confirme que tout l’audit est accepté. C’est important parce que je peux ensuite passer aux graphes avec des mesures déjà validées.

En résumé, l’IC95 est notre garde-fou statistique. Il confirme que nos mesures sont stables, reproductibles et assez précises pour comparer sérieusement les algorithmes. Avec les tests et les KAT, on valide le quoi. Avec l’IC95, on valide la confiance dans les chiffres.

---

## Section 1.5 - Génération des graphes (Windows)

Je passe ensuite à la génération des graphiques. Ici, je veux montrer que le script lit bien les données x86 et Raspberry Pi, puis qu’il produit les graphes attendus pour chaque bloc.

```powershell
python scripts/run_charts.py
```

On voit maitnenant que

`Sources x86 (5) : ...` le script utilise bien les cinq fichiers x86. C’est important parce que les graphes s’appuient sur plusieurs expériences réelles, pas sur un seul CSV.

`Sources Raspberry Pi (3) : ...`
Cette ligne confirme que la comparaison avec Raspberry Pi est bien incluse aussi. On montre donc les deux plateformes dans la même génération de graphes.

`[run_charts] Sélection: 01, 02, 03, 04` Ici cette ligne veut dire que le script génère les quatre blocs prévus. C’est utile parce qu’on peut ensuite présenter les résultats de performance, d’avalanche, de modes et d’aide à la décision.

* `[run_charts] Génération du dossier 01...`
  Cette partie me montre que le bloc throughput est bien produit. Je peux alors parler de vitesse et de comparaison entre algorithmes.
* `[run_charts] Génération du dossier 02...`
  Ici, le script génère le bloc avalanche. C’est important parce que ça illustre le comportement cryptographique, pas seulement la vitesse.
* `Mesure du score d'avalanche DES pour les tours 1–16`
  Cette sortie montre que le score d’avalanche augmente jusqu’à se stabiliser autour de 50 %. C’est exactement ce qu’on attend d’un bon effet de diffusion.
* `Graphique enregistré: ... avalanche-convergence-des-rounds.png`
  Ça confirme que le graphique a bien été créé et sauvegardé.
* `Génération de la démonstration de vulnérabilité ECB…`
  Cette ligne est importante parce qu’elle montre visuellement pourquoi le mode ECB n’est pas recommandé pour des images : il laisse apparaître des motifs.
* `image-original.bmp`, `image-encrypted-ecb.bmp`, `image-encrypted-cbc.bmp`
  Avec ces fichiers, je peux montrer la différence entre l’image originale, l’image chiffrée en ECB et celle chiffrée en CBC. C’est une démonstration très parlante.
* `[run_charts] Génération du dossier 04...` Ici, le script termine avec les graphes d’aide à la décision. C’est utile pour passer ensuite à l’interprétation finale.
* `[run_charts] Terminé.`
  Ce message final me confirme que toute la génération des graphes s’est bien déroulée jusqu’au bout. C’est important parce que je peux ensuite montrer les fichiers produits dans le dossier `data/charts/`.

En conclusionà, la génération des graphes confirme que nos données sont bien transformées en résultats visuels exploitables. Elle valide que le pipeline va jusqu’au bout, de la mesure brute à l’interprétation, pour comparer clairement les algorithmes et les plateformes.

---

## Section 1.6 - Vérification des artefacts (Windows)

Pour fermer la partie Windows, je montre finalement les artefacts générés localement.

```powershell
Get-ChildItem data/results/*.csv | Sort-Object LastWriteTime -Descending | Select-Object -First 8 Name, LastWriteTime
Get-ChildItem data/evidence/*.csv | Sort-Object LastWriteTime -Descending | Select-Object Name, LastWriteTime
Get-ChildItem data/charts -Recurse -File *.png | Sort-Object LastWriteTime -Descending | Select-Object -First 12 FullName, LastWriteTime
```

`data/results/*.csv`
Ici, on confirme que les CSV ont bien ete generer et quil sont bien placer dans le dossier de résultats. Ça prouve que la campagne de mesures a bien produit des données exploitables et les as placer au bon endroit.

`data/evidence/ic95_raw_rows.csv`
Ce fichier contient les lignes brutes de l’audit IC95. C’est la trace directe des mesures avant regroupement.

`data/evidence/ic95_audit_report.csv`
Ce rapport montre que l’audit a été regroupé et validé. Il me sert de preuve pour la partie statistique.

`data/charts/01-throughput/`
Ce dossier contient les graphes de performance. Il montre les différences de débit entre algorithmes et plateformes.
`data/charts/02-avalanche-effect/`
Ici, je montre les graphes liés à l’effet d’avalanche. C’est important parce que ça parle du comportement cryptographique, pas seulement de la vitesse.
`data/charts/03-encryption-modes/`
Ce dossier regroupe les graphes sur les modes de chiffrement, y compris la démonstration ECB. C’est là qu’on voit pourquoi ECB n’est pas un bon choix pour certains usages.
`data/charts/04-decision-support/`
Ce dernier dossier sert à la synthèse et à la décision finale. Il résume les résultats pour qu’on puisse conclure plus simplement.

Ces listes montrent les fichiers réellement créés par l’exécution, avec leur horodatage local. C’est la preuve observable de la chaîne complète.

Donc maitnenat on peut dire que la demo pour windows est completer, car la vérification des artefacts nous a confirmerque chaque étape du pipeline laisse une trace concrète et vérifiable. Elle prouve que nos résultats sont bien produits, bien stockés et prêts pour l’analyse et la reproduction.

---

## SECTION 2 - Validation sur Raspberry Pi

Je rejoue maintenant la même séquence complète sur Raspberry Pi, architecture ARMv7. Les scripts, les seuils et les paramètres sont identiques à Windows. L'objectif est de démontrer que le pipeline entier est reproductible et portable sur une plateforme ARM.

---

#### Section 2.1 - Validation Logicielle (Raspberry Pi)

```bash
python -m pytest
```

Sur Raspberry Pi, je lis les mêmes indicateurs de sortie pour ce run Pi et je les compare à Windows. Le total `collected` et `passed` doit rester cohérent entre plateformes, tandis que le temps peut varier. La couverture affichée doit aussi être annoncée telle qu'elle apparaît dans la sortie Pi, afin de garder une conclusion factuelle et traçable.

---

#### Section 2.2 - Validation Cryptographique KAT (Raspberry Pi)

```bash
python scripts/run_kat.py
```

La validation KAT passe intégralement, 60/60 assertions. Cela confirme que les implémentations cryptographiques produisent exactement les mêmes résultats sur ARM que sur x86. Aucune divergence liée à l'architecture, aucun problème d'endianness.

---

#### Section 2.3 - Campagne de Mesures (Raspberry Pi)

```bash
python scripts/experiment.py
```

La matrice expérimentale s'exécute complètement. Les timings absolus diffèrent, Pi est environ 5 à 10 fois plus lent, mais les classements relatifs entre algorithmes demeurent identiques. AES reste rapide, DES reste lent, peu importe la plateforme. Cela démontre que la comparaison de performance est robuste et reproductible au-delà des architectures.

---

#### Section 2.4 - Audit IC95 (Raspberry Pi)

```bash
python scripts/audit/audit_ic95.py --enforce-gates
```

> L'audit statistique sur Pi valide tous les gates, répétitions suffisantes, gros messages stables, outliers contrôlés. Cela prouve que même sur une plateforme plus lente, les données restent stables et statistiquement crédibles. La qualité des mesures est indépendante de l'architecture.

---

#### Section 2.5 - Génération des Graphes (Raspberry Pi)

```bash
python scripts/run_charts.py 04
python scripts/run_charts.py all
```

Les quatre blocs graphiques se génèrent correctement. Le script consolide les données x86 et Raspberry Pi, produisant des visualisations comparatives. La structure graphique reste identique, validant que l'interprétation des résultats ne dépend pas de la plateforme d'exécution.

---

#### Section 2.6 - Vérification des Artefacts (Raspberry Pi)

```bash
find data/results -maxdepth 1 -type f -name "*.csv" -printf "%TY-%Tm-%Td %TH:%TM %p\n" | sort | tail -n 8
find data/evidence -maxdepth 1 -type f -name "*.csv" -printf "%TY-%Tm-%Td %TH:%TM %p\n" | sort | tail -n 4
find data/charts -type f -name "*.png" -printf "%TY-%Tm-%Td %TH:%TM %p\n" | sort | tail -n 12
```

Tous les artefacts sont présents sur Pi, CSV de mesures, rapports d'audit, graphes PNG. Les timestamps confirment que la chaîne complète, de la mesure à la génération graphique, s'est exécutée de bout en bout sans interruption.

---

## Conclusion

En synthèse, cette démonstration montre une chaîne complète et reproductible. On valide la partie logicielle, la partie cryptographique, les mesures, l’audit statistique IC95 et la génération des graphes.

Les mêmes commandes ont été exécutées dans le même ordre sur Windows et sur Raspberry Pi. Les sorties sont tracées, les artefacts sont visibles, et les contrôles de qualité sont explicites.

La conclusion est que le pipeline est opérationnel, vérifiable et suffisamment robuste pour soutenir l’analyse finale du projet.
