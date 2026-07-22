# Vidéo de démonstration complète

## Objectif
**Où sommes-nous ?**
Présentation PowerPoint, diapo de transition vers la démonstration complète

**Texte à lire**
Dans cette vidéo, je montre tout le pipeline du projet de bout en bout. L’idée est de prouver à l’écran que le projet s’exécute réellement, avec les mêmes étapes sur Windows et sur Raspberry Pi.

Je vais suivre une séquence simple. Je lance les tests, puis la validation cryptographique KAT, ensuite la campagne de mesures, l’audit statistique IC95, la génération des graphes, et enfin la vérification des artefacts produits.

À chaque étape, je lis surtout la sortie terminal. L’objectif est de faire ressortir les lignes importantes qui montrent que l’exécution a bien réussi et que les fichiers attendus ont été créés.

---

## Section 1 - Validation logicielle (Windows)
**Où sommes-nous ?**
Terminal Windows + `pytest`

**Texte à lire avant la commande**
Je commence par les tests automatiques. Ici, l’idée est de montrer que la base du projet est saine avant de parler des mesures ou des graphes.

```powershell
python -m pytest
```

**Texte à lire après la commande**
Le résultat à retenir est simple : les 102 tests passent tous et la couverture atteint 100 %.

**Note perso pour le tournage**
- Surbrillance à montrer : `python -m pytest`
- Surbrillance à montrer : `collected 102 items`
- Surbrillance à montrer : `102 passed in 9.08s`
- Surbrillance à montrer : `Required test coverage of 100% reached. Total coverage: 100.00%`

Ces lignes prouvent deux choses à la fois : les tests fonctionnels passent tous, et la couverture de code est complète sur le périmètre évalué.

C’est important parce que ces tests valident toute la chaîne logique du projet : les primitives de chiffrement, les modes, les KAT, les scripts de mesure et les scripts d’audit. Avant de présenter les résultats expérimentaux, je peux donc dire que le socle logiciel est déjà vérifié.

---

## Section 2 - Validation cryptographique KAT (Windows)
**Où sommes-nous ?**
Terminal Windows + `scripts/run_kat.py`

**Texte à lire avant la commande**
J’enchaîne avec la validation KAT. Ici, je vérifie que chaque algorithme produit bien les résultats attendus par ses vecteurs de référence.

```powershell
python scripts/run_kat.py
```

**Texte à lire après la commande**
Le résultat principal, c’est que toutes les suites passent.

**Note perso pour le tournage**
- Surbrillance à montrer : `python scripts/run_kat.py`
- Surbrillance à montrer : `TOTAL | 60 | 60 | 0 | PASS`
- Surbrillance à montrer : `ALL KAT SUITES PASSED`

Ce que je veux faire ressortir, c’est que la suite KAT couvre tout le cœur cryptographique du projet, et que le bilan final est propre : 60 assertions, 60 réussites, 0 échec. Cela veut dire que les implémentations sont cohérentes avec les vecteurs de référence, et c’est important parce que je peux ensuite parler des mesures et des graphes en m’appuyant sur une validation cryptographique déjà confirmée.

---

## Section 3 - Campagne de mesures (Windows)
**Où sommes-nous ?**
Terminal Windows + `scripts/experiment.py`

**Texte à lire avant la commande**
Je lance maintenant la campagne de mesures. Ici, l’idée est de montrer que le script parcourt toute la matrice expérimentale et qu’il produit bien les résultats attendus pour chaque algorithme.

```powershell
python scripts/experiment.py
```

**Texte à lire après la commande**
**Ligne à montrer**
`[info] Algorithms scheduled: 3DES, AES, ChaCha20, DES, Twofish`

**Texte à dire**
Ici, on voit que la campagne couvre bien toutes les familles prévues. C’est important parce que je ne lance pas un test isolé, mais une vraie matrice complète.

**Ligne à montrer**
Une ou deux lignes `Running ...`, par exemple AES, DES et Twofish

**Texte à dire**
Ces lignes montrent que le script parcourt plusieurs tailles de message et plusieurs modes. On peut donc comparer les performances dans des conditions variées, pas seulement sur un seul cas.

**Ligne à montrer**
Les champs `enc=...`, `thr=...` et `avalanche=...`

**Texte à dire**
`enc` donne le temps de chiffrement, `thr` donne le débit, et `avalanche` donne une idée de la diffusion du chiffrement. C’est utile parce qu’on lit à la fois la vitesse et le comportement cryptographique.

**Ligne à montrer**
`Run summary by algorithm`

**Texte à dire**
Le résumé final me confirme que tout s’est terminé correctement, sans oubli ni échec sur une famille d’algorithmes.

**Ligne à montrer**
`[ok] All algorithms in the matrix completed successfully.`

**Texte à dire**
Ça veut dire que la campagne est complète et exploitable. Je peux ensuite passer à l’audit IC95 en sachant que les mesures ont bien été générées.

---

## Petit guide de lecture d’une ligne de mesure
**Où sommes-nous ?**
Toujours dans la sortie de `scripts/experiment.py`

**Texte à lire**
Quand je lis une ligne comme `Running AES-ECB key=128bit msg=64B … enc=0.064ms thr=0.95MB/s avalanche=0.498`, je peux la découper simplement.

`AES-ECB` me dit quel algorithme et quel mode sont testés. `key=128bit` me donne la taille de la clé. `msg=64B` me donne la taille du message. `enc=0.064ms` indique le temps de chiffrement, `thr=0.95MB/s` indique le débit, et `avalanche=0.498` montre à quel point la sortie change quand l’entrée change.

Ce qui est important ici, c’est que cette ligne résume à la fois la performance et le comportement cryptographique. C’est pour ça que je peux commenter la vitesse, puis dire que la valeur d’avalanche est proche de 0.5, donc cohérente avec un bon effet de diffusion.

**Note perso pour le tournage**
- Surbrillance à montrer : une ligne `Running ...`
- Surbrillance à montrer : `key=...`
- Surbrillance à montrer : `msg=...`
- Surbrillance à montrer : `enc=...`
- Surbrillance à montrer : `thr=...`
- Surbrillance à montrer : `avalanche=...`

---

## Section 4 - Audit IC95 (Windows)
**Où sommes-nous ?**
Terminal Windows + `scripts/audit/audit_ic95.py`

**Texte à lire avant la commande**
Après la génération des mesures, je lance l’audit statistique IC95. Ici, le but n’est pas seulement de produire un fichier, mais de vérifier que les mesures sont suffisamment stables pour être présentées et comparées.

```powershell
python scripts/audit/audit_ic95.py --enforce-gates
```

**Texte à lire après la commande**
**Ligne à montrer**
`Raw IC95 rows exported`

**Texte à dire**
Cette ligne montre que les mesures brutes ont bien été exportées. C’est la première preuve que l’audit travaille sur des données réelles.

**Ligne à montrer**
`Grouped IC95 audit exported`

**Texte à dire**
Ici, l’audit regroupé est produit. Cela veut dire qu’on passe d’une sortie brute à une version structurée, plus facile à exploiter.

**Ligne à montrer**
`Summary: PASS=281 FAIL=29 TOTAL=310`

**Texte à dire**
Ce résumé me donne le volume total de contrôles effectués. Le point important, c’est qu’on voit tout de suite qu’il y a un vrai traitement statistique derrière l’audit.

**Ligne à montrer**
`Gate 1 - min repetitions >= 100: PASS`

**Texte à dire**
Cette gate vérifie qu’il y a assez de répétitions pour que les mesures soient crédibles.

**Ligne à montrer**
`Gate 2 - message_size >= 1024B pass rate >= 90.00%: PASS`

**Texte à dire**
Cette gate montre que les grands messages passent à un taux suffisamment élevé. C’est important pour valider la stabilité sur les tailles qui comptent vraiment.

**Ligne à montrer**
`Gate 3 - outliers (ic95_relative_pct_mean > 20.00%) <= 20: PASS`

**Texte à dire**
Cette gate contrôle qu’il n’y a pas trop de valeurs aberrantes. Elle m’aide à montrer que les résultats sont cohérents et utilisables.

**Ligne à montrer**
`Quality gate enforcement: PASS`

**Texte à dire**
Le message final confirme que tout l’audit est accepté. C’est important parce que je peux ensuite passer aux graphes avec des mesures déjà validées.

---

## Section 5 - Génération des graphes (Windows)
**Où sommes-nous ?**
Terminal Windows + `scripts/run_charts.py`

**Texte à lire avant la commande**
Je passe ensuite à la génération des graphes. Ici, je veux montrer que le script lit bien les données x86 et Raspberry Pi, puis qu’il produit les graphes attendus pour chaque bloc.

```powershell
python scripts/run_charts.py 04
python scripts/run_charts.py all
```

**Texte à lire après la commande**
**Ligne à montrer**
`Sources x86 (5) : ...`

**Texte à dire**
Ici, je vois que le script utilise bien les cinq fichiers x86. C’est important parce que les graphes s’appuient sur plusieurs expériences réelles, pas sur un seul CSV.

**Ligne à montrer**
`Sources Raspberry Pi (3) : ...`

**Texte à dire**
Cette ligne confirme que la comparaison avec Raspberry Pi est bien incluse aussi. On montre donc les deux plateformes dans la même génération de graphes.

**Ligne à montrer**
`[run_charts] Sélection: 01, 02, 03, 04`

**Texte à dire**
Ça veut dire que le script génère les quatre blocs prévus. C’est utile parce qu’on peut ensuite présenter les résultats de performance, d’avalanche, de modes et d’aide à la décision.

**Ligne à montrer**
`[run_charts] Génération du dossier 01...`

**Texte à dire**
Cette partie me montre que le bloc throughput est bien produit. Je peux alors parler de vitesse et de comparaison entre algorithmes.

**Ligne à montrer**
`[run_charts] Génération du dossier 02...`

**Texte à dire**
Ici, le script génère le bloc avalanche. C’est important parce que ça illustre le comportement cryptographique, pas seulement la vitesse.

**Ligne à montrer**
`Mesure du score d'avalanche DES pour les tours 1–16`

**Texte à dire**
Cette sortie montre que le score d’avalanche augmente jusqu’à se stabiliser autour de 50 %. C’est exactement ce qu’on attend d’un bon effet de diffusion.

**Ligne à montrer**
`Graphique enregistré: ... avalanche-convergence-des-rounds.png`

**Texte à dire**
Ça confirme que le graphique a bien été créé et sauvegardé.

**Ligne à montrer**
`Génération de la démonstration de vulnérabilité ECB…`

**Texte à dire**
Cette ligne est importante parce qu’elle montre visuellement pourquoi le mode ECB n’est pas recommandé pour des images : il laisse apparaître des motifs.

**Ligne à montrer**
`image-original.bmp`, `image-encrypted-ecb.bmp`, `image-encrypted-cbc.bmp`

**Texte à dire**
Avec ces fichiers, je peux montrer la différence entre l’image originale, l’image chiffrée en ECB et celle chiffrée en CBC. C’est une démonstration très parlante.

**Ligne à montrer**
`[run_charts] Génération du dossier 04...`

**Texte à dire**
Ici, le script termine avec les graphes d’aide à la décision. C’est utile pour passer ensuite à l’interprétation finale.

**Ligne à montrer**
`[run_charts] Terminé.`

**Texte à dire**
Ce message final me confirme que toute la génération des graphes s’est bien déroulée jusqu’au bout. C’est important parce que je peux ensuite montrer les fichiers produits dans le dossier `data/charts/`.

---

## Section 6 - Vérification des artefacts (Windows)
**Où sommes-nous ?**
Terminal Windows + dossiers `data/results/`, `data/evidence/audit/` et `data/charts/`

**Texte à lire avant la commande**
Pour fermer la partie Windows, je montre les artefacts générés localement.

```powershell
Get-ChildItem data/results/*.csv | Sort-Object LastWriteTime -Descending | Select-Object -First 8 Name, LastWriteTime
Get-ChildItem data/evidence/audit/*.csv | Sort-Object LastWriteTime -Descending | Select-Object Name, LastWriteTime
Get-ChildItem data/charts -Recurse -File *.png | Sort-Object LastWriteTime -Descending | Select-Object -First 12 FullName, LastWriteTime
```

**Texte à lire après la commande**
**Fichier à montrer**
`data/results/*.csv`

**Texte à dire**
Ici, je montre les CSV de résultats. Ça prouve que la campagne de mesures a bien produit des données exploitables.

**Fichier à montrer**
`data/evidence/audit/ic95_raw_rows.csv`

**Texte à dire**
Ce fichier contient les lignes brutes de l’audit IC95. C’est la trace directe des mesures avant regroupement.

**Fichier à montrer**
`data/evidence/audit/ic95_audit_report.csv`

**Texte à dire**
Ce rapport montre que l’audit a été regroupé et validé. Il me sert de preuve pour la partie statistique.

**Fichier à montrer**
`data/charts/01-throughput/`

**Texte à dire**
Ce dossier contient les graphes de performance. Il montre les différences de débit entre algorithmes et plateformes.

**Fichier à montrer**
`data/charts/02-avalanche-effect/`

**Texte à dire**
Ici, je montre les graphes liés à l’effet d’avalanche. C’est important parce que ça parle du comportement cryptographique, pas seulement de la vitesse.

**Fichier à montrer**
`data/charts/03-encryption-modes/`

**Texte à dire**
Ce dossier regroupe les graphes sur les modes de chiffrement, y compris la démonstration ECB. C’est là qu’on voit pourquoi ECB n’est pas un bon choix pour certains usages.

**Fichier à montrer**
`data/charts/04-decision-support/`

**Texte à dire**
Ce dernier dossier sert à la synthèse et à la décision finale. Il résume les résultats pour qu’on puisse conclure plus simplement.

Ces listes montrent les fichiers réellement créés par l’exécution, avec leur horodatage local. C’est la preuve observable de la chaîne complète.

---

## Section 7 - Validation logicielle (Raspberry Pi)
**Où sommes-nous ?**
Terminal Raspberry Pi + VS Code Remote

**Texte à lire avant la commande**
Je rejoue maintenant la même séquence sur Raspberry Pi. Ici, je montre surtout que la méthode reste la même sur une deuxième machine.

```bash
python -m pytest
```

**Texte à lire après la commande**
**Ligne à montrer**
`collected ... items`

**Texte à dire**
Je vérifie que tous les tests sont bien relancés.

**Ligne à montrer**
`... passed`

**Texte à dire**
Ça confirme que la validation logicielle passe aussi sur Raspberry Pi.

**Ligne à montrer**
`Required test coverage of 100% reached`

**Texte à dire**
Cette ligne montre que le niveau de couverture attendu est atteint.

---

## Section 8 - Validation cryptographique KAT (Raspberry Pi)
**Où sommes-nous ?**
Terminal Raspberry Pi + `scripts/run_kat.py`

**Texte à lire avant la commande**
Je lance ensuite les KAT sur Raspberry Pi. Le but est juste de vérifier que le même contrôle cryptographique passe sur cette plateforme.

```bash
python scripts/run_kat.py
```

**Texte à lire après la commande**
**Ligne à montrer**
`TOTAL | 60 | 60 | 0 | PASS`

**Texte à dire**
Je montre que tous les tests KAT passent.

**Ligne à montrer**
`ALL KAT SUITES PASSED`

**Texte à dire**
C’est le signal final qui confirme la conformité sur Raspberry Pi.

---

## Section 9 - Campagne de mesures (Raspberry Pi)
**Où sommes-nous ?**
Terminal Raspberry Pi + `scripts/experiment.py`

**Texte à lire avant la commande**
Je lance ensuite la campagne de mesures sur Raspberry Pi. Je veux surtout montrer que les mêmes mesures sont produites sur ARM.

```bash
python scripts/experiment.py
```

**Texte à lire après la commande**
**Ligne à montrer**
`[info] Algorithms scheduled: ...`

**Texte à dire**
Je vois quels algorithmes sont lancés.

**Ligne à montrer**
`Run summary by algorithm`

**Texte à dire**
Cette partie résume les résultats de chaque algorithme.

**Ligne à montrer**
`Exported CSV: ...`

**Texte à dire**
Ça confirme que les mesures ont bien été enregistrées dans un fichier CSV.

---

## Section 10 - Audit IC95 (Raspberry Pi)
**Où sommes-nous ?**
Terminal Raspberry Pi + `scripts/audit/audit_ic95.py`

**Texte à lire avant la commande**
Je rejoue ensuite l’audit IC95 sur Raspberry Pi. L’idée est de garder exactement la même vérification statistique.

```bash
python scripts/audit/audit_ic95.py --enforce-gates
```

**Texte à lire après la commande**
**Ligne à montrer**
`Summary: PASS=... FAIL=... TOTAL=...`

**Texte à dire**
Je montre le résumé global de l’audit.

**Ligne à montrer**
`Quality gate enforcement: PASS`

**Texte à dire**
Cette ligne confirme que les seuils sont respectés sur Raspberry Pi aussi.

---

## Section 11 - Génération des graphes (Raspberry Pi)
**Où sommes-nous ?**
Terminal Raspberry Pi + `scripts/run_charts.py`

**Texte à lire avant la commande**
Je termine la partie Raspberry Pi avec la génération des graphes. Là encore, je garde la même logique que sur Windows.

```bash
python scripts/run_charts.py 04
python scripts/run_charts.py all
```

**Texte à lire après la commande**
**Ligne à montrer**
`Sources x86 (5) : ...`

**Texte à dire**
Je vérifie que les sources de référence sont bien lues.

**Ligne à montrer**
`Sources Raspberry Pi (3) : ...`

**Texte à dire**
Je vois aussi les sources Pi utilisées dans la comparaison.

**Ligne à montrer**
`[run_charts] Terminé.`

**Texte à dire**
Le script a fini correctement et les graphes sont prêts.

---

## Section 12 - Vérification des artefacts (Raspberry Pi)
**Où sommes-nous ?**
Terminal Raspberry Pi + dossiers `data/results/`, `data/evidence/audit/` et `data/charts/`

**Texte à lire avant la commande**
Je termine en montrant les artefacts côté Raspberry Pi. C’est la dernière preuve de reproductibilité.

```bash
find data/results -maxdepth 1 -type f -name "*.csv" -printf "%TY-%Tm-%Td %TH:%TM %p\n" | sort | tail -n 8
find data/evidence/audit -maxdepth 1 -type f -name "*.csv" -printf "%TY-%Tm-%Td %TH:%TM %p\n" | sort | tail -n 4
find data/charts -type f -name "*.png" -printf "%TY-%Tm-%Td %TH:%TM %p\n" | sort | tail -n 12
```

**Texte à lire après la commande**
**Fichier à montrer**
`data/results/*.csv`

**Texte à dire**
Je montre que les résultats de mesures existent aussi sur Pi.

**Fichier à montrer**
`data/evidence/audit/*.csv`

**Texte à dire**
Je montre les exports de l’audit statistique.

**Fichier à montrer**
`data/charts/*.png`

**Texte à dire**
Je montre enfin les graphes générés sur cette plateforme.

---

## Conclusion
**Où sommes-nous ?**
Slide de clôture

**Texte à lire**
Cette démonstration montre une chaîne complète et reproductible. On valide la partie logicielle, la partie cryptographique, les mesures, l’audit statistique IC95 et la génération des graphes.

Les mêmes commandes ont été exécutées dans le même ordre sur Windows et sur Raspberry Pi. Les sorties sont tracées, les artefacts sont visibles, et les contrôles de qualité sont explicites.

La conclusion est que le pipeline est opérationnel, vérifiable et suffisamment robuste pour soutenir l’analyse finale TN4.