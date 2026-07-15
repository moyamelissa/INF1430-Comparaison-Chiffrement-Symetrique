# Vidéo 3 - Résultats de performance

## Introduction (ouverture caméra)
**Texte à lire**
Bonjour et bienvenue dans cette troisième vidéo, qui a pour but de présenter et d'interpréter les résultats de performance de notre campagne expérimentale.

Dans les vidéos précédentes, on a posé les bases: la validation fonctionnelle des algorithmes et la méthode de mesure. Maintenant, on répond à la vraie question, celle qui nous intéresse depuis le début: qu'est-ce qui explique les écarts de débit entre les algorithmes, entre les modes d'opération, et entre les plateformes x86 et ARM?

On va d'abord passer par le code pour comprendre d'où viennent exactement les graphiques que vous allez voir. Je vais vous montrer comment le pipeline génère automatiquement chaque figure à partir des données brutes, pour qu'on puisse lire les résultats avec confiance.

Ensuite, on va parcourir les graphiques obtenus, section par section, pour analyser l'effet de la taille des messages, l'impact des modes de chiffrement, la vulnérabilité visuelle d'ECB, et les écarts inter-plateformes entre x86 et le Raspberry Pi.

À la fin de cette vidéo, vous aurez une image claire et justifiée de ce qui détermine réellement la performance en chiffrement symétrique.

## Objectif
Interpréter rigoureusement les performances en reliant chaque écart à trois facteurs, soit l'algorithme, le mode d'opération et l'architecture matérielle.

## Portée
- `scripts/run_charts.py`
- `scripts/chart_pipeline/build_performance.py`
- `scripts/chart_pipeline/build_platform_comparison.py`
- `data/results/laptop-windows-x86_experience1.csv`
- `data/results/laptop-windows-x86_experience2.csv`
- `data/results/laptop-windows-x86_experience3.csv`
- `data/results/raspberry-pi_experience1.csv`
- `data/results/raspberry-pi_experience2.csv`
- `data/results/raspberry-pi_experience3.csv`
- `data/charts/01-debit/comparaison-debit-global.png`
- `data/charts/01-debit/debit-vs-taille-message.png`
- `data/charts/01-debit/debit-4096o.png`
- `data/charts/01-debit/comparaison-ratio-acceleration.png`
- `data/charts/03-modes-chiffrement/aes-comparaison-modes.png`
- `data/charts/03-modes-chiffrement/vulnerabilite-mode-ecb.png`
- `data/charts/01-debit/chacha20-comparaison-plateformes.png`

## Guide d'enregistrement

### Section 1 - Traçabilité des graphes
**Où sommes-nous**
VS Code sur `scripts/run_charts.py`, puis `scripts/chart_pipeline/` et `data/charts/`.

**Texte à lire**
Avant d'interpréter les chiffres, on confirme la traçabilité. Les figures ne sont pas dessinées manuellement. Elles sont générées automatiquement à partir des CSV de mesure.

Le point d'entrée est `scripts/run_charts.py`. Ce script orchestre la génération des dossiers de sortie et délègue le rendu aux modules de `scripts/chart_pipeline/`.

Le dossier `chart_pipeline/` est organisé en quatre types de fichiers, et chacun a un rôle bien défini.

On commence par les fichiers qui ont un préfixe `build_`. Ce sont eux qui contiennent la logique de tracé. C'est là que chaque graphique est construit, du choix des données jusqu'à la mise en forme et l'export de l'image. Par exemple, `build_performance.py` génère les graphiques de débit et de modes, alors que `build_platform_comparison.py` produit les comparaisons entre x86 et ARM.

Ensuite, les scripts de préparation des données sont tous identifiés par un préfixe `data_`. Ils lisent les résultats bruts, convertissent les valeurs et préparent des données propres pour le tracé. L'idée est simple, on sépare la lecture des résultats de leur affichage.

Le fichier `style_charts.py`, lui, centralise toute l'identité visuelle. On y retrouve la palette de couleurs, la taille des figures, le style des axes et la manière commune d'enregistrer les images. Toutes les figures gardent donc le même rendu, sans répétition inutile.

Enfin, `shared_paths.py` garde en un seul endroit les chemins de lecture et d'écriture, pour que chaque partie du pipeline sache où aller chercher les résultats et où déposer les graphiques.

Quand on lance le script run_charts.py avec l'argument 01, il appelle la fonction d'orchestration correspondante. Cette fonction lance ensuite les bons scripts de tracé, qui lisent les données, appliquent le style commun et enregistrent les figures dans le dossier de sortie.

Cette architecture garantit une narration reproductible, parce que chaque conclusion est rattachée à une source mesurée et à une image générée automatiquement.

Pour rendre ça concret, je vais maintenant montrer trois extraits de code qui illustrent chacune de ces étapes.

## Code 1
Premièrement, je vais vous montrer un extrait de `scripts/run_charts.py`, parce que c'est lui qui reçoit l'argument de lancement et qui oriente la génération vers la bonne fonction.

```python
# scripts/run_charts.py
def _generate_01_debit() -> None:
    perf.generate_groups(["01-debit"])
    platform_cmp.generate_groups(["01-debit"])
```

Ici, `_generate_01_debit()` est la fonction d'orchestration de la cible `01`. Son rôle est de transformer une cible de lancement en un plan d'exécution concret. Elle ne produit pas elle-même les figures. Elle appelle d'abord la fonction `generate_groups` du module `perf`, avec l'argument `01-debit`, pour générer les graphiques de débit à partir des données préparées. Ensuite, elle appelle la fonction `generate_groups` du module `platform_cmp`, avec ce même argument, pour générer les graphiques de comparaison entre plateformes.

On montre ce code pour mettre en évidence le contrat du pipeline, car une cible donnée correspond toujours au même ensemble d'actions. Quand on choisit `01`, le programme sait exactement quels groupes de graphiques doivent être lancés. Il n'y a donc ni sélection manuelle ni ambiguïté sur la sortie produite.

```python
TARGETS = {
    "01": _generate_01_debit,
    "02": _generate_02_effet_avalanche,
    "03": _generate_03_modes_chiffrement,
    "04": _generate_04_synthese,
}
```

Ici, `TARGETS` est un dictionnaire de correspondance, avec une structure clé vers fonction. La clé est l'identifiant de cible lu en argument au lancement du script, et la valeur est la fonction d'orchestration à exécuter. Par exemple, la clé `"01"` est associée à la fonction `_generate_01_debit()`, qui déclenche ensuite la génération des graphiques de débit et de comparaison entre plateformes. De la même manière, `"02"` appelle la fonction de l'effet avalanche, `"03"` celle des modes de chiffrement, et `"04"` celle de la synthèse.

```python
def main(argv: list[str]) -> int:
    ...
    for key in ordered:
        TARGETS[key]()
```

Enfin, on montre cet extrait de code pour visualiser le moment exact où la cible choisie devient une exécution concrète dans le pipeline.

Premièrement, à la ligne 62, on a l'entrée de `main()`, qui reçoit les arguments de lancement et prépare la sélection de cible. Ensuite, à la ligne 82, on a la boucle sur les clés à exécuter, avec `for key in ordered`. Finalement, à la ligne 84, on a la résolution clé vers fonction et l'appel, avec `TARGETS[key]()`, ce qui déclenche la bonne fonction d'orchestration pour chaque cible.

Au final, `run_charts.py` joue bien le rôle de routeur d'exécution, car il prend une cible en entrée et lance automatiquement le bon sous-ensemble de génération.

## Code 2

Deuxièmement, je vais vous montrer un extrait du fichier `scripts/chart_pipeline/data_performance.py`, parce que c'est lui qui sélectionne les sources CSV x86 et qui prépare les données avant le tracé. 

On commence par montrer le bloc des lignes 20 à 28, parce qu’il explique la règle de sélection des sources x86. Il parcourt les fichiers CSV disponibles, applique un filtre, trie la liste, puis retient tous les fichiers x86 utiles au calcul.

```python
# scripts/chart_pipeline/data_performance.py
def x86_results_csvs() -> list[Path]:
    csvs = sorted(
        f for f in RESULTS_DIR.iterdir()
        if f.suffix == ".csv" and f.name != ".gitkeep"
        and ("x86" in f.name or "laptop-windows" in f.name)
    )
    return csvs
```

Ici, l'objectif est simple, montrer comment les sources CSV x86 sont choisies de façon traçable. À la ligne 20, `x86_results_csvs()` est la fonction utilitaire qui centralise cette sélection. Aux lignes 22 à 25, la variable `csvs` est construite à partir de `RESULTS_DIR.iterdir()`. Le filtre garde seulement les fichiers `.csv`, exclut `.gitkeep` et conserve les noms x86, puis `sorted()` trie la liste. Enfin, à la ligne 28, `return csvs` retourne l'ensemble des fichiers retenus pour la suite du pipeline.

On montre ce bloc pour justifier la traçabilité de la source, parce qu'avant même de tracer un graphe, on sait exactement quels fichiers CSV sont sélectionnés et selon quelle règle.

```python
def load_latest_rows() -> tuple[list[Path], list[Row]]:
    paths = x86_results_csvs()
    all_rows: list[Row] = []
    for csv_path in paths:
        with csv_path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                all_rows.append({
                    "algorithm": row["algorithm"],
                    "message_size_bytes": int(row["message_size_bytes"]),
                    "throughput_enc_mbps": float(row["throughput_encrypt_mbps"]),
                })
    return paths, _average_rows(all_rows)
```
Ensuite, on va explorer le bloc des lignes 52 à 78, parce qu’il décrit le flux complet de préparation des données avant le tracé.
Il ouvre chaque CSV sélectionné, lit chaque ligne, normalise les types numériques, puis retourne à la fois la liste des sources utilisées et les données moyennées prêtes pour les graphiques.

Premièrement, à la ligne 52, on a la déclaration de `load_latest_rows()`, qui est la fonction de lecture et de normalisation. Ensuite, à la ligne 58, `paths = x86_results_csvs()` récupère les chemins des CSV sélectionnés, puis à la ligne 59, `all_rows` est initialisée comme liste de dictionnaires pour stocker les mesures.

Ensuite, à la ligne 60, la boucle `for csv_path in paths` parcourt chaque fichier, à la ligne 61, `csv_path.open()` est la méthode d'ouverture du fichier, et à la ligne 62, `csv.DictReader` est la classe de la bibliothèque `csv` qui lit chaque ligne sous forme de dictionnaire. Puis, aux lignes 67 et 71, `int` et `float` sont des fonctions de conversion de type pour normaliser les champs numériques.

Finalement, à la ligne 78, `return paths, _average_rows(all_rows)` retourne à la fois la liste des sources exactes et les données déjà moyennées pour le tracé.

Enfin, on montre cet extrait pour visualiser où la préparation des données est centralisée avant l'étape de rendu.

Au final, `data_performance.py` garantit que les modules de tracé reçoivent des données propres, typées et traçables.

## Code 3

Troisièmement, je vais vous montrer un extrait du fichier `scripts/chart_pipeline/build_performance.py`, parce que c'est lui qui affiche les sources réellement utilisées et qui standardise l'export des figures.

Ce troisième extrait joue le rôle de couche de sortie. Son objectif est simple, garder la trace de la source utilisée et enregistrer toutes les figures avec le même format visuel.

```python
# scripts/chart_pipeline/build_performance.py
CSV_PATHS, rows = load_latest_rows()
print(f"Fichiers x86 lus ({len(CSV_PATHS)}) : {', '.join(p.name for p in CSV_PATHS)}")
```

À la ligne 54, `CSV_PATHS` est une variable qui contient la liste des chemins réellement lus et `rows` est la liste des données prêtes à tracer, tous deux retournés par la fonction `load_latest_rows()`. À la ligne 55, `print()` est une fonction d'affichage qui écrit ces sources dans le terminal.

```python
def savefig(name: str):
    save_figure(plt.gcf(), CHARTS_DIR, name, facecolor=BG_COLOR)
```

À la ligne 62, `savefig()` est une fonction locale d'export qui appelle `save_figure()`, une fonction utilitaire de sauvegarde. À la ligne 63, `plt.gcf()` est une méthode Matplotlib qui récupère la figure courante, `CHARTS_DIR` est la variable de chemin du dossier de sortie, et `BG_COLOR` est la variable de style qui fixe la couleur de fond.

Concrètement, ce bloc montre que chaque figure suit le même chemin, de la lecture des données jusqu'à l'enregistrement final. C'est ce qui rend le rapport cohérent d'une figure à l'autre.

**Commande à montrer (terminal)**
```bash
cd crypto-experiments
python scripts/run_charts.py 01
python scripts/run_charts.py 03
```

**Texte à lire pendant la commande**
Je lance maintenant deux cibles pour vérifier le comportement en conditions réelles. Avec `01`, je teste le flux orienté débit. Avec `03`, je teste le flux orienté modes de chiffrement. De cette façon, on valide non seulement que les fonctions sont bien appelées, mais aussi que chaque cible active le bon sous-ensemble du pipeline.
**Texte à lire après la commande**
Dans le terminal, on voit d'abord `Fichiers x86 lus (...)`, ce qui permet d'identifier immédiatement toutes les sources utilisées pour la moyenne côté x86. Ensuite on voit `x86 data (...)` et `Pi data (...)`, ce qui confirme les sources inter-plateformes utilisées pour la comparaison. Enfin on voit les fichiers enregistrés avec leurs chemins complets, ce qui confirme exactement où les sorties sont écrites.

**Transition**
Maintenant que la chaîne de production est claire, on passe à la lecture des débits.

### Section 2 - Débit selon la taille du message
**Visuel à montrer**
`data/charts/01-debit/comparaison-debit-global.png`

**Texte à lire**
On commence par la vue d'ensemble du débit global entre x86 et ARM. Ce graphique compare, pour chaque algorithme, le débit mesuré sur le laptop x86 et sur le Raspberry Pi ARM.

Le message principal est immédiat. AES domine sur x86 avec un écart marqué, ce qui est cohérent avec l'accélération matérielle AES-NI. ChaCha20 reste performant sur les deux plateformes et montre un comportement plus régulier. À l'inverse, 3DES présente un écart inter-plateforme plus faible, mais à un niveau de débit globalement bas.

Cette hiérarchie ne vient donc pas uniquement de l'algorithme, mais aussi de l'architecture d'exécution, en particulier du support matériel disponible sur x86.

Cette première lecture donne la hiérarchie générale. Ensuite, on va expliquer pourquoi cette hiérarchie peut évoluer selon la taille des messages.

**Transition**
Après cette vue d'ensemble inter-plateformes, on analyse l'effet de la taille du message.

### Section 3 - Débit selon la taille du message
**Visuel à montrer**
`data/charts/01-debit/debit-vs-taille-message.png`

**Texte à lire**
Ce graphe montre l'évolution du débit quand la taille du message augmente. Sur les petites tailles, le coût fixe pèse fortement. Quand la taille augmente, ce coût est amorti, et le débit utile se stabilise.

On voit aussi que AES confirme sa position, avec la montée la plus nette quand la taille augmente, surtout côté x86. DES, 3DES et Twofish progressent aussi avec la taille, mais restent nettement derrière sur toute la plage.

L'explication est simple: quand la taille augmente, le coût fixe de lancement est amorti, donc le débit observé reflète davantage le coût réel par bloc et met mieux en valeur les implémentations les plus optimisées.

Le point important est méthodologique, car un algorithme moyen à 64 octets peut devenir compétitif à 4096 ou 16384 octets. C'est pourquoi notre protocole couvre plusieurs tailles de message.

**Transition**
Après la tendance globale selon la taille, on fixe une taille de référence pour comparer plus clairement.

### Section 4 - Impact du mode d'opération sur le débit (AES-128)
**Visuel à montrer**
`data/charts/03-modes-chiffrement/aes-comparaison-modes.png`

**Texte à lire**
Ici, on fixe l'algorithme à AES-128, puis on compare uniquement l'effet du mode d'opération sur le débit. On a choisi AES-128 parce que c'est une version standard, très utilisée, et suffisante pour comparer proprement les modes sans mélanger l'effet de la taille de clé.

La lecture des courbes est nette. ECB reste le plus rapide sur toutes les tailles de message, avec une montée très forte quand la taille augmente.

Pourquoi ECB est devant? Parce que c'est le mode le plus simple sur le plan opérationnel. Chaque bloc est chiffré indépendamment, sans chaînage avec le bloc précédent, sans compteur à maintenir et sans étape d'authentification. Donc il y a moins d'opérations par bloc et moins de dépendances entre blocs, ce qui favorise le débit brut.

GCM arrive ensuite, avec un débit inférieur à ECB, ce qui est attendu parce qu'il ajoute l'authentification en plus du chiffrement. CTR progresse de manière plus modérée, alors que CBC reste le plus limité dans ces mesures, notamment à cause du chaînage qui introduit plus de dépendances dans le traitement.

**Transition**
Après la lecture du débit, on explicite le compromis sécurité-performance des mêmes modes.

### Section 5 - Vulnérabilité ECB — sécurité vs performance
**Visuel à montrer**
`data/charts/03-modes-chiffrement/vulnerabilite-mode-ecb.png`

**Texte à lire**
Ici, on ne compare plus le débit, on compare la sécurité visuelle des modes. On réutilise AES-128 parce que c'est une base standard, simple à lire, et que cela permet de garder la même clé et le même algorithme pendant qu'on change seulement le mode.

Ce qu'on a fait, très simplement, c'est le suivant. D'abord, on a construit une image de test en code, pas une photo réelle. Cette image contient de grandes zones uniformes et des formes très répétitives, pour que les motifs soient faciles à voir.

Ensuite, on a pris exactement cette même image et on l'a chiffrée deux fois avec AES-128, parce que c'est notre base commune pour comparer les modes dans des conditions simples et standard. Une première fois en ECB, une deuxième fois en CBC. La clé reste la même dans les deux cas, donc la seule différence vient du mode de chiffrement.

Avec ECB, chaque bloc est chiffré séparément, c'est-à-dire que le chiffrement d'un bloc ne tient pas compte des blocs avant lui. Donc si deux blocs clairs sont identiques, les blocs chiffrés le restent aussi. C'est pour ça que les bandes et les formes de l'image originale réapparaissent encore dans le résultat.

Avec CBC, chaque bloc dépend du bloc précédent, c'est-à-dire qu'avant de chiffrer le bloc courant, on le mélange avec le résultat du bloc d'avant. Même si deux zones de départ se ressemblent, le résultat chiffré change davantage. La structure visuelle disparaît donc beaucoup plus vite, et l'image ressemble davantage à du bruit.

Le message à retenir est très simple: ECB est rapide, mais il laisse voir les motifs. CBC est un peu plus lourd, mais il cache beaucoup mieux la structure. Donc, si on veut protéger des données qui ont une forme reconnaissable, CBC est le bon choix.

**Transition**
Après cette démonstration visuelle, on revient aux écarts de performance entre plateformes.

### Section 6 - ChaCha20 sur ARM — portabilité sans compromis
**Visuel à montrer**
`data/charts/01-debit/chacha20-comparaison-plateformes.png`

**Texte à lire**
Ici, on compare ChaCha20 sur x86 et sur ARM. L'idée est simple, il ne dépend pas d'une accélération matérielle spéciale comme AES avec AES-NI.

Les deux courbes montent de manière assez parallèle. Quand la taille du message augmente, le débit augmente aussi, et l'écart entre les deux plateformes reste plus limité que pour AES.

Si le Raspberry Pi reste en dessous du laptop x86, c'est surtout parce qu'il est moins puissant en général, avec un processeur plus lent et moins de marge pour traiter de gros volumes.

Le point à retenir, c'est que ChaCha20 est très portable, parce qu'il repose surtout sur des opérations simples bien supportées partout, comme additions, XOR et rotations, sans dépendre d'une extension dédiée de type AES-NI. Il garde donc de bonnes performances sur ARM comme sur x86, ce qui en fait un choix intéressant quand on veut un comportement régulier sur des machines différentes.

**Transition**
Après ChaCha20, on revient à l'effet matériel pour expliquer pourquoi AES peut encore creuser l'écart sur x86.

### Section 7 - Effet plateforme: ratio d'accélération x86 vs ARM
**Visuel à montrer**
`data/charts/01-debit/comparaison-ratio-acceleration.png`

**Texte à lire**
Dans cette dernière figure, on résume l'écart entre x86 et ARM avec un indicateur unique, le ratio de débit x86 sur Pi.

La ligne pointillée à 1 représente des performances égales. Plus la barre monte au-dessus de 1, plus l'avantage va à x86.

On lit tout de suite les extrêmes. AES affiche un ratio de 4,08x, ce qui veut dire que le laptop x86 chiffre plus de quatre fois plus vite que le Raspberry Pi pour le même algorithme. Cet écart est aussi élevé parce que AES profite de l'extension AES-NI sur x86, une accélération matérielle absente sur le Pi. ChaCha20 est à 1,61x, donc x86 est environ une fois et demie plus rapide que le Pi, mais l'écart est beaucoup plus contenu parce que ChaCha20 ne dépend pas d'une telle extension.

Entre les deux, on trouve DES à 1,98x, 3DES à 1,27x et Twofish à 2,26x.

Twofish est plus haut que DES et 3DES parce qu'il est un algorithme structurellement plus complexe, avec des tables de substitution dépendantes de la clé, une matrice de diffusion et un calendrier de clés plus lourd. Ces opérations profitent davantage des caches plus grands et des unités d'exécution plus larges du processeur x86, ce qui creuse plus l'écart avec le Pi.

À l'inverse, 3DES affiche le ratio le plus bas après ChaCha20, à 1,27x. Cela s'explique parce que 3DES est intrinsèquement lent sur les deux plateformes, il applique DES trois fois de suite de façon séquentielle. La lenteur est structurelle, donc les deux machines se retrouvent proportionnellement plus proches.

Le message final est clair. Le débit ne dépend pas seulement de l'algorithme en théorie, il dépend aussi de la machine qui l'exécute.

**Transition**
Après cette dernière slide des résultats de performance, on peut conclure sur les trois facteurs qui expliquent les écarts observés.

### Section 8 - Conclusion vidéo 3
**Texte à lire**
Ce qu'on retient de cette vidéo, c'est que la performance en chiffrement symétrique n'a pas une seule cause. Elle est le résultat de trois facteurs qui se combinent.

Le premier, c'est l'algorithme lui-même. AES est plus rapide que DES, 3DES ou Twofish, pas seulement parce qu'il est moderne, mais parce qu'il a été conçu pour être efficace en logiciel et en matériel.

Le deuxième, c'est le mode d'opération. À algorithme identique, ECB est plus rapide que GCM ou CBC, parce qu'il fait moins d'opérations par bloc. Mais cette rapidité a un coût, ECB est aussi le mode le moins sûr. Le bon choix, c'est GCM, qui offre chiffrement et authentification avec un surcoût acceptable.

Le troisième, c'est l'architecture matérielle. AES sur x86 avec AES-NI affiche un ratio de 4,08x par rapport au Raspberry Pi, alors que ChaCha20 n'est qu'à 1,61x. Ce n'est pas AES qui est meilleur sur toutes les machines, c'est que x86 lui donne un avantage structurel que les autres algorithmes n'ont pas.

Donc, si on devait choisir un algorithme pour un système réel, on dirait AES-GCM sur x86 pour la performance maximale et la sécurité, ou ChaCha20 sur ARM pour un comportement stable et prévisible sans dépendance matérielle.

Dans la vidéo suivante, on complète cette lecture avec la robustesse cryptographique, l'effet d'avalanche et la stabilité statistique.
