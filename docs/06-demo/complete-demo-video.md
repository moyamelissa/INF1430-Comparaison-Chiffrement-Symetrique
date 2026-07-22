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
On peut lire plusieurs signaux importants. D’abord, il y a 102 tests exécutés, et ils passent tous. Ensuite, la couverture est à 100 %, ce qui veut dire que le périmètre testé est entièrement couvert.

C’est important parce que ces tests valident toute la chaîne logique du projet : les primitives de chiffrement, les modes, les KAT, les scripts de mesure et les scripts d’audit. Avant de présenter les résultats expérimentaux, je peux donc dire que le socle logiciel est déjà vérifié.

---

## Section 2 - Validation cryptographique KAT (Windows)
**Où sommes-nous ?**
Terminal Windows + `scripts/run_kat.py`

**Texte à lire avant la commande**
J’enchaîne avec la validation KAT. Cette étape vérifie que les implémentations produisent bien les sorties attendues par les vecteurs de référence.

```powershell
python scripts/run_kat.py
```

**Texte à lire après la commande**
Le signal principal à relever est `ALL KAT SUITES PASSED`. C’est la confirmation que la conformité cryptographique est bonne pour toutes les suites testées.

---

## Section 3 - Campagne de mesures (Windows)
**Où sommes-nous ?**
Terminal Windows + `scripts/experiment.py`

**Texte à lire avant la commande**
Je lance maintenant la campagne de mesures. Le script exécute la matrice expérimentale et écrit un CSV dans `data/results/`.

```powershell
python scripts/experiment.py
```

**Texte à lire après la commande**
Je commente trois choses : les lignes d’exécution des configurations, le résumé final par algorithme, et le chemin exact du CSV généré.

---

## Section 4 - Audit IC95 (Windows)
**Où sommes-nous ?**
Terminal Windows + `scripts/audit/audit_ic95.py`

**Texte à lire avant la commande**
Après la génération des mesures, je lance l’audit statistique IC95. Cette étape contrôle la stabilité des mesures et applique les quality gates.

```powershell
python scripts/audit/audit_ic95.py --enforce-gates
```

**Texte à lire après la commande**
Je montre le résultat des trois gates, puis le message final `Quality gate enforcement PASS`. Je souligne aussi les deux fichiers produits : `ic95_raw_rows.csv` et `ic95_audit_report.csv`.

---

## Section 5 - Génération des graphes (Windows)
**Où sommes-nous ?**
Terminal Windows + `scripts/run_charts.py`

**Texte à lire avant la commande**
Je passe ensuite à la génération des graphes. Je lance d’abord un cas ciblé avec la synthèse, puis la génération complète.

```powershell
python scripts/run_charts.py 04
python scripts/run_charts.py all
```

**Texte à lire après la commande**
Dans la sortie, je lis les sources CSV utilisées, puis la sélection des blocs `01, 02, 03, 04`. Je montre ensuite les lignes `Enregistré` qui prouvent l’écriture effective des images dans `data/charts/`.

---

## Section 6 - Vérification des artefacts (Windows)
**Où sommes-nous ?**
Terminal Windows + dossiers `data/results/`, `data/validation/audit/` et `data/charts/`

**Texte à lire avant la commande**
Pour fermer la partie Windows, je montre les artefacts générés localement.

```powershell
Get-ChildItem data/results/*.csv | Sort-Object LastWriteTime -Descending | Select-Object -First 8 Name, LastWriteTime
Get-ChildItem data/validation/audit/*.csv | Sort-Object LastWriteTime -Descending | Select-Object Name, LastWriteTime
Get-ChildItem data/charts -Recurse -File *.png | Sort-Object LastWriteTime -Descending | Select-Object -First 12 FullName, LastWriteTime
```

**Texte à lire après la commande**
Ces listes montrent les fichiers réellement créés par l’exécution, avec leur horodatage local. C’est la preuve observable de la chaîne complète.

---

## Section 7 - Validation logicielle (Raspberry Pi)
**Où sommes-nous ?**
Terminal Raspberry Pi + VS Code Remote

**Texte à lire avant la commande**
Je rejoue maintenant la même séquence sur Raspberry Pi. Le but est de montrer la reproductibilité de la méthode sur une architecture différente.

```bash
python -m pytest
```

**Texte à lire après la commande**
Je vérifie à nouveau le total des tests et le message de couverture. L’idée est de montrer que la validation logicielle est bien rejouée sur la deuxième plateforme.

---

## Section 8 - Validation cryptographique KAT (Raspberry Pi)
**Où sommes-nous ?**
Terminal Raspberry Pi + `scripts/run_kat.py`

**Texte à lire avant la commande**
Je lance la validation KAT sur Raspberry Pi pour confirmer la conformité cryptographique dans cet environnement aussi.

```bash
python scripts/run_kat.py
```

**Texte à lire après la commande**
Je confirme à nouveau le signal `ALL KAT SUITES PASSED`.

---

## Section 9 - Campagne de mesures (Raspberry Pi)
**Où sommes-nous ?**
Terminal Raspberry Pi + `scripts/experiment.py`

**Texte à lire avant la commande**
Je lance ensuite la campagne de mesures sur ARM. Cette exécution produit son propre CSV dans `data/results/`.

```bash
python scripts/experiment.py
```

**Texte à lire après la commande**
Je lis les lignes d’exécution, le résumé par algorithme et le nom du CSV exporté pour la plateforme Pi.

---

## Section 10 - Audit IC95 (Raspberry Pi)
**Où sommes-nous ?**
Terminal Raspberry Pi + `scripts/audit/audit_ic95.py`

**Texte à lire avant la commande**
Je rejoue le même audit IC95 sur le Pi. Cette étape garantit que la vérification statistique est appliquée de la même manière.

```bash
python scripts/audit/audit_ic95.py --enforce-gates
```

**Texte à lire après la commande**
Je confirme les quality gates et le statut final. Le point important est la symétrie de méthode entre Windows et ARM.

---

## Section 11 - Génération des graphes (Raspberry Pi)
**Où sommes-nous ?**
Terminal Raspberry Pi + `scripts/run_charts.py`

**Texte à lire avant la commande**
Je termine la partie Pi avec la génération des graphes, d’abord ciblée puis complète.

```bash
python scripts/run_charts.py 04
python scripts/run_charts.py all
```

**Texte à lire après la commande**
Je vérifie les mêmes signaux qu’avant. Je confirme les sources lues, les dossiers cibles et les figures enregistrées.

---

## Section 12 - Vérification des artefacts (Raspberry Pi)
**Où sommes-nous ?**
Terminal Raspberry Pi + dossiers `data/results/`, `data/validation/audit/` et `data/charts/`

**Texte à lire avant la commande**
Je montre enfin les artefacts côté Pi pour fermer la démonstration de reproductibilité.

```bash
find data/results -maxdepth 1 -type f -name "*.csv" -printf "%TY-%Tm-%Td %TH:%TM %p\n" | sort | tail -n 8
find data/validation/audit -maxdepth 1 -type f -name "*.csv" -printf "%TY-%Tm-%Td %TH:%TM %p\n" | sort | tail -n 4
find data/charts -type f -name "*.png" -printf "%TY-%Tm-%Td %TH:%TM %p\n" | sort | tail -n 12
```

**Texte à lire après la commande**
On voit les fichiers générés avec la date et l’heure. La preuve d’exécution est directe et vérifiable.

---

## Conclusion
**Où sommes-nous ?**
Slide de clôture

**Texte à lire**
Cette démonstration montre une chaîne complète et reproductible. On valide la partie logicielle, la partie cryptographique, les mesures, l’audit statistique IC95 et la génération des graphes.

Les mêmes commandes ont été exécutées dans le même ordre sur Windows et sur Raspberry Pi. Les sorties sont tracées, les artefacts sont visibles, et les contrôles de qualité sont explicites.

La conclusion est que le pipeline est opérationnel, vérifiable et suffisamment robuste pour soutenir l’analyse finale TN4.