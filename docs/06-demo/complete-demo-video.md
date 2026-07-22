# Vidéo de démonstration complète (Windows + Raspberry Pi)

## Intro - Objectif de la demonstration
**Ou sommes-nous**
Présentation PowerPoint - diapo de transition vers la démonstration complète

**Texte a lire**
Dans cette video, on fait une demonstration unique de tout le pipeline. L'objectif est simple. On veut prouver a l'ecran que le projet s'execute reellement de bout en bout, avec les memes etapes sur Windows et sur Raspberry Pi.

On va suivre une sequence claire. On commence par les tests, puis la validation cryptographique KAT, ensuite la campagne de mesures, la generation des graphes, et enfin la verification des fichiers generes.

La logique de lecture reste la meme a chaque etape. Je lance la commande, puis je lis les signaux importants dans la sortie terminal.

---

## Section 1 - Preparation de l'environnement (Windows)
**Ou sommes-nous**
Terminal Windows + VS Code

**Texte a lire avant la commande**
On commence sur Windows dans le dossier du projet. Je me place dans `crypto-experiments` et j'active l'environnement virtuel pour garantir que toutes les dependances utilisees sont celles du projet.

```powershell
cd crypto-experiments
..\.venv\Scripts\Activate.ps1
python --version
```

**Texte a lire apres la commande**
Ici, je verifie que l'environnement est actif et que Python repond correctement. Cette verification evite les erreurs d'interpreteur avant le lancement du pipeline.

---

## Section 2 - Validation logicielle (Windows)
**Ou sommes-nous**
`pytest`

**Texte a lire avant la commande**
Je lance d'abord les tests automatiques. Cette etape valide le code avant de produire des resultats experimentaux.

```powershell
python -m pytest
```

**Texte a lire apres la commande**
Dans la sortie, je lis deux signaux importants. Le premier est le total de tests executes. Le second est le message de couverture. Le resultat attendu est que tous les tests passent et que la couverture atteigne 100 % sur le perimetre evalue.

---

## Section 3 - Validation cryptographique KAT (Windows)
**Ou sommes-nous**
`scripts/run_kat.py`

**Texte a lire avant la commande**
Ensuite, je lance la validation KAT. Cette etape verifie que les implementations produisent les sorties attendues par les vecteurs de reference.

```powershell
python scripts/run_kat.py
```

**Texte a lire apres la commande**
Le signal que je confirme a l'ecran est `ALL KAT SUITES PASSED`. Cela valide la conformite cryptographique des algorithmes testes.

---

## Section 4 - Campagne de mesures (Windows)
**Ou sommes-nous**
`scripts/experiment.py`

**Texte a lire avant la commande**
Je lance maintenant la campagne de mesures. Le script execute la matrice experimentale et ecrit un CSV dans `data/results/`.

```powershell
python scripts/experiment.py
```

**Texte a lire apres la commande**
Je lis trois elements dans la sortie. D'abord les lignes d'execution des configurations. Ensuite le resume final par algorithme. Enfin le chemin exact du CSV genere.

---

## Section 5 - Audit IC95 (Windows)
**Ou sommes-nous**
`scripts/audit/audit_ic95.py`

**Texte a lire avant la commande**
Apres la generation des mesures, je lance l'audit statistique IC95. Cette etape controle la stabilite des mesures et applique les quality gates.

```powershell
python scripts/audit/audit_ic95.py --enforce-gates
```

**Texte a lire apres la commande**
Je confirme a l'ecran les trois gates et le message final `Quality gate enforcement PASS`. Je montre aussi les deux fichiers produits, `ic95_raw_rows.csv` et `ic95_audit_report.csv`.

---

## Section 6 - Generation des graphes (Windows)
**Ou sommes-nous**
`scripts/run_charts.py`

**Texte a lire avant la commande**
Je lance ensuite la generation des graphes. D'abord un cas cible avec la synthese, puis la generation complete.

```powershell
python scripts/run_charts.py 04
python scripts/run_charts.py all
```

**Texte a lire apres la commande**
Dans la sortie, je lis les sources CSV utilisees, puis la selection des blocs `01, 02, 03, 04`. Je montre ensuite les lignes `Enregistre` qui prouvent l'ecriture effective des images dans `data/charts/`.

---

## Section 7 - Verification des artefacts (Windows)
**Ou sommes-nous**
`data/results/` et `data/charts/`

**Texte a lire avant la commande**
Pour fermer la partie Windows, je montre les artefacts generes localement.

```powershell
Get-ChildItem data/results/*.csv | Sort-Object LastWriteTime -Descending | Select-Object -First 8 Name, LastWriteTime
Get-ChildItem data/validation/audit/*.csv | Sort-Object LastWriteTime -Descending | Select-Object Name, LastWriteTime
Get-ChildItem data/charts -Recurse -File *.png | Sort-Object LastWriteTime -Descending | Select-Object -First 12 FullName, LastWriteTime
```

**Texte a lire apres la commande**
Ces listes montrent les fichiers reels crees par l'execution, avec leur horodatage local. C'est la preuve observable de la chaine complete.

---

## Section 8 - Preparation de l'environnement (Raspberry Pi)
**Ou sommes-nous**
Terminal Raspberry Pi + VS Code Remote

**Texte a lire avant la commande**
Je rejoue maintenant la meme sequence sur Raspberry Pi. Le but est de demontrer la reproductibilite de la methode sur une architecture differente.

```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
python --version
```

**Texte a lire apres la commande**
Je confirme que l'environnement Python du Pi est actif et pret pour la meme chaine d'execution.

---

## Section 9 - Validation logicielle (Raspberry Pi)
**Ou sommes-nous**
`pytest`

**Texte a lire avant la commande**
Je relance les tests sur ARM, avec exactement la meme commande.

```bash
python -m pytest
```

**Texte a lire apres la commande**
Je verifie le total des tests et le message de couverture. L'objectif est de montrer que la validation logicielle est bien rejouee sur la deuxieme plateforme.

---

## Section 10 - Validation cryptographique KAT (Raspberry Pi)
**Ou sommes-nous**
`scripts/run_kat.py`

**Texte a lire avant la commande**
Je lance la validation KAT sur Raspberry Pi pour confirmer la conformite cryptographique dans cet environnement aussi.

```bash
python scripts/run_kat.py
```

**Texte a lire apres la commande**
Je confirme a nouveau le signal `ALL KAT SUITES PASSED`.

---

## Section 11 - Campagne de mesures (Raspberry Pi)
**Ou sommes-nous**
`scripts/experiment.py`

**Texte a lire avant la commande**
Je lance ensuite la campagne de mesures ARM. Cette execution produit son propre CSV dans `data/results/`.

```bash
python scripts/experiment.py
```

**Texte a lire apres la commande**
Je lis les lignes d'execution, le resume par algorithme et le nom du CSV exporte pour la plateforme Pi.

---

## Section 12 - Audit IC95 (Raspberry Pi)
**Ou sommes-nous**
`scripts/audit/audit_ic95.py`

**Texte a lire avant la commande**
Je rejoue le meme audit IC95 sur le Pi. Cette etape garantit que la verification statistique est appliquee de la meme maniere.

```bash
python scripts/audit/audit_ic95.py --enforce-gates
```

**Texte a lire apres la commande**
Je confirme les quality gates et le statut final. Le point important est la symetrie de methode entre Windows et ARM.

---

## Section 13 - Generation des graphes (Raspberry Pi)
**Ou sommes-nous**
`scripts/run_charts.py`

**Texte a lire avant la commande**
Je termine la partie Pi avec la generation des graphes, d'abord ciblee puis complete.

```bash
python scripts/run_charts.py 04
python scripts/run_charts.py all
```

**Texte a lire apres la commande**
Je verifie les memes signaux qu'avant. Je confirme les sources lues, les dossiers cibles et les figures enregistrees.

---

## Section 14 - Verification des artefacts (Raspberry Pi)
**Ou sommes-nous**
`data/results/` et `data/charts/`

**Texte a lire avant la commande**
Je montre enfin les artefacts cote Pi pour fermer la demonstration de reproductibilite.

```bash
find data/results -maxdepth 1 -type f -name "*.csv" -printf "%TY-%Tm-%Td %TH:%TM %p\n" | sort | tail -n 8
find data/validation/audit -maxdepth 1 -type f -name "*.csv" -printf "%TY-%Tm-%Td %TH:%TM %p\n" | sort | tail -n 4
find data/charts -type f -name "*.png" -printf "%TY-%Tm-%Td %TH:%TM %p\n" | sort | tail -n 12
```

**Texte a lire apres la commande**
On voit les fichiers generes avec date et heure. La preuve d'execution est directe et verifiable.

---

## Conclusion - Message final a dire a l'enseignant
**Ou sommes-nous**
Slide de cloture

**Texte a lire**
Cette demonstration montre une chaine complete et reproductible. On valide la partie logicielle, la partie cryptographique, les mesures, l'audit statistique IC95 et la generation des graphes.

Les memes commandes ont ete executees dans le meme ordre sur Windows et sur Raspberry Pi. Les sorties sont tracees, les artefacts sont visibles, et les controles de qualite sont explicites.

La conclusion est que le pipeline est operationnel, verifiable, et suffisamment robuste pour soutenir l'analyse finale TN4.