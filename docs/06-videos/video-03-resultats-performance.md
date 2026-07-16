# Vidéo 3 - Génération des graphes par le code

## Intro - Objectif et périmètre de démonstration
**Où sommes-nous**
Présentation PowerPoint - Diapo 04c

**Texte à lire**
Bonjour et bienvenue dans cette troisième vidéo, qui a pour but de montrer comment les graphiques sont générés automatiquement à partir de notre code et de nos mesures.

On commence avec la diapo 04c pour visualiser la chaîne complète, du lancement de la campagne jusqu'au CSV de sortie.

Sur cette diapo, on lit le pipeline de gauche à droite.

À gauche, on regarde le bloc `experiment.py`. La flèche `instancie` indique que ce script crée les objets nécessaires au calcul, notamment le contrôleur et les composants de chiffrement.

Au centre, on regarde les blocs de calcul performance et robustesse. La flèche `retourne` indique que ces fonctions renvoient un résultat structuré après chaque mesure. Le bloc performance correspond à la méthode `run_performance()`, qui calcule notamment le débit et l'intervalle de confiance à 95 %. Le bloc robustesse correspond aux méthodes `measure_avalanche()` et `measure_key_avalanche()`, qui mesurent l'effet d'une inversion d'un seul bit, de 0 vers 1 ou de 1 vers 0, côté texte clair et côté clé.

À droite, on regarde le bloc d'export. Les résultats renvoyés sont écrits dans un fichier CSV `experiment_YYYYMMDD.csv`, via `ExperimentResult` qui est une classe de données, avec une ligne par configuration mesurée.

Donc la logique de la diapo est simple et traçable: on lance, on mesure, puis on exporte.

Le point important, ce n'est pas seulement le flux, c'est la séparation des responsabilités. `experiment.py` orchestre, `ExperimentController` calcule, puis l'export sérialise. Cette séparation réduit les erreurs silencieuses et permet de diagnostiquer rapidement où un problème apparaît.

En pratique, pendant la démo, on vérifie trois choses qui donnent de la confiance. Premièrement, le script lance bien toutes les configurations prévues. Deuxièmement, les fonctions de mesure retournent des champs cohérents, par exemple débit, avalanche et intervalle de confiance à 95 %. Troisièmement, l'export final écrit un CSV complet et exploitable par le pipeline de graphes.

Pourquoi c'est essentiel? Parce que si une seule de ces trois étapes est incomplète, les graphes peuvent être visuellement corrects mais scientifiquement incomplets. L'objectif de la vidéo est donc de prouver la fiabilité de la chaîne, pas seulement de montrer des images.

Ensuite, on va explorer quelques parties du code pour comprendre clairement le processus de génération.

Et finalement, on va terminer avec une démonstration en direct dans le terminal.

À la fin de cette vidéo, vous aurez une vue claire, simple et traçable de la génération des graphiques.


### Architecture - Traçabilité et séparation des rôles
**Où sommes-nous**
VS Code sur `scripts/run_charts.py`, puis `scripts/chart_pipeline/` et `data/charts/`.

**Texte à lire**
Avant d'explorer le code ligne par ligne, on va d'abord lire l'architecture pour comprendre comment les rôles sont séparés. Cette architecture garantit la traçabilité: les figures ne sont pas dessinées manuellement, elles sont générées automatiquement à partir des CSV de mesure.

Le point d'entrée est `scripts/run_charts.py`. Ce script orchestre la génération des dossiers de sortie et délègue le rendu aux modules de `scripts/chart_pipeline/`.

Le dossier `chart_pipeline/` est organisé en quatre types de fichiers, et chacun a un rôle bien défini.

On commence par les fichiers qui ont un préfixe `build_`. Ce sont eux qui contiennent la logique de tracé. C'est là que chaque graphique est construit, du choix des données jusqu'à la mise en forme et l'export de l'image. Par exemple, `build_performance.py` génère les graphiques de débit et de modes, alors que `build_platform_comparison.py` produit les comparaisons entre x86 et ARM.

Ensuite, les scripts de préparation des données sont tous identifiés par un préfixe `data_`. Ils lisent les résultats bruts, convertissent les valeurs et préparent des données propres pour le tracé. L'idée est simple, on sépare la lecture des résultats de leur affichage.

Le fichier `style_charts.py`, lui, centralise toute l'identité visuelle. On y retrouve la palette de couleurs, la taille des figures, le style des axes et la manière commune d'enregistrer les images. Toutes les figures gardent donc le même rendu, sans répétition inutile.

Enfin, `shared_paths.py` garde en un seul endroit les chemins de lecture et d'écriture, pour que chaque partie du pipeline sache où aller chercher les résultats et où déposer les graphiques.

Quand on lance le script run_charts.py avec l'argument 01, il appelle la fonction d'orchestration correspondante. Cette fonction lance ensuite les bons scripts de tracé, qui lisent les données, appliquent le style commun et enregistrent les figures dans le dossier de sortie.

Cette architecture garantit une narration reproductible, parce que chaque conclusion est rattachée à une source mesurée et à une image générée automatiquement.

Pour rendre ça concret, je vais maintenant montrer trois extraits de code qui illustrent la chaîne complète, de la mesure brute jusqu'au graphique final.

## Code 1 - Production des mesures et export CSV
Premièrement, je vais vous montrer un extrait de `scripts/experiment.py`, parce que c'est lui qui exécute réellement les campagnes de mesure et qui écrit les CSV sources.

```python
# scripts/experiment.py
EXPERIMENT_MATRIX = [
    ("AES", AES, "ECB", ECB, [16, 24, 32]),
    ("AES", AES, "CBC", CBC, [16, 24, 32]),
    ...
]

for algo, primitive_cls, mode_label, mode_cls, key_sizes in matrix:
    ...
    result = controller.run_performance(...)
    results.append(result)

all_algorithms_ok = _print_run_summary(run_stats)
out_path = _output_path()
```

Ici, à la ligne 55 de `scripts/experiment.py`, `EXPERIMENT_MATRIX` est une variable de configuration. Cette liste définit explicitement les algorithmes, les modes et les tailles de clé qui doivent être exécutés. Cette structure fixe le périmètre de mesure avant même de parler de graphiques.

Ensuite, à la ligne 209, la boucle principale parcourt cette configuration. Puis, à la ligne 237, elle appelle `controller.run_performance(...)`, qui est une méthode de l'objet `controller` de la classe `ExperimentController`. Chaque mesure est ajoutée à la variable liste `results`, ce qui construit progressivement le jeu de données brut.

```python
with open(out_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for r in results:
        writer.writerow(asdict(r))
```

Finalement, à la ligne 261, ce bloc écrit les résultats dans un CSV traçable. `csv.DictWriter` est une classe de la bibliothèque standard, `writeheader()` et `writerow()` sont des méthodes d'écriture CSV, et `asdict()` est une fonction qui convertit un objet de données en dictionnaire. On montre ce passage pour ancrer l'idée clé de la vidéo: les figures ne viennent pas d'une saisie manuelle, elles viennent d'un export mesuré.

```python
if not all_algorithms_ok:
    return 1
```

Enfin, à la ligne 268, on montre cette condition pour rendre explicite la robustesse d'exécution: `all_algorithms_ok` est une variable booléenne calculée par la fonction `_print_run_summary()`, et `return 1` est le code de sortie d'échec du script.

Au final, `experiment.py` joue bien le rôle de producteur de vérité expérimentale, car il exécute, contrôle et exporte les mesures sources.

## Code 2 - Calcul des métriques dans le contrôleur
Deuxièmement, on revient brièvement dans `ExperimentController.py`, non pas pour répéter toute la logique déjà vue, mais pour faire le lien clair entre le calcul interne et ce qu'on observe ensuite dans les graphes.

Le point clé est la méthode `run_performance`, à la ligne 77 de `application/ExperimentController.py`, parce que c'est exactement à cet endroit que la mesure brute devient une métrique exploitable.

```python
# application/ExperimentController.py
def run_performance(...):
    plaintext = os.urandom(message_size_bytes)
    ...
    t0 = time.perf_counter()
    ct = self._engine.encrypt(plaintext)
    ...
    throughput_encrypt_mbps = mb / avg_enc
```

Dans ce bloc, l'idée centrale est que le temps est mesuré autour de l'opération cryptographique elle-même. Aux lignes 108 et 117, `time.perf_counter()` qui est une fonction du module `time` encadre le chiffrement de façon précise. Puis, à la ligne 150, `throughput_encrypt_mbps` qui est une variable numérique transforme ce temps en débit. Autrement dit, la valeur affichée dans la figure n'est pas décorative et elle vient d'une formule directement ancrée dans ce code.

```python
return ExperimentResult(
    ...
    avalanche_score=self.measure_avalanche(),
    key_avalanche_score=self.measure_key_avalanche(),
    ci95_encrypt_mbps=ci95_enc,
)
```

Ensuite, à la ligne 142, le retour `ExperimentResult` rassemble les métriques dans une structure unique, et cette structure part ensuite vers le CSV. Ici, `ExperimentResult` est une classe de données. Les appels à `measure_avalanche()` et `measure_key_avalanche()`, qui sont deux méthodes de la classe `ExperimentController`, montrent que la robustesse est calculée dans la même étape que la performance, avec des définitions aux lignes 162 et 213.

Concrètement, il faut retenir que les graphes ne créent pas de nouvelles valeurs et qu'ils visualisent des métriques déjà calculées pendant la mesure. Ce passage fait la transition entre la logique de calcul et la phase de génération des figures.

## Code 3 - Orchestration et rendu des graphiques

Troisièmement, on va ouvrir `run_charts.py` ensemble, parce que c'est le fichier script qui pilote toute la génération des graphes quand on lance une commande dans le terminal.

```python
# scripts/run_charts.py
def _generate_01_debit() -> None:
    perf.generate_groups(["01-debit"])
    platform_cmp.generate_groups(["01-debit"])
```

Regardez la logique de lecture pendant la vidéo. À la ligne 33, `_generate_01_debit()` est une fonction et son rôle est de lancer le groupe de graphes débit. À la ligne 54, `TARGETS` est une variable dictionnaire qui associe une clé de commande à une fonction. Puis, à la ligne 84, `TARGETS[key]()` exécute réellement la fonction choisie.

Pourquoi on insiste sur ce passage. Parce que c'est lui qui garantit que la commande tapée dans le terminal déclenche le bon sous pipeline, sans ambiguïté et sans intervention manuelle. Quand vous dites à l'écran `python scripts/run_charts.py 01`, vous pouvez expliquer de façon fluide que la clé `01` est lue, qu'elle pointe vers une fonction précise, puis que cette fonction lance exactement les graphes attendus.

## Code 4 - Script `data_` (sélection et agrégation)

Quatrièmement, on passe au script `data_` dans `scripts/chart_pipeline/data_performance.py`, parce que c'est ici que la qualité des graphes se joue vraiment. Avant de tracer quoi que ce soit, on décide d'abord quelles sources sont acceptées, puis on prépare les lignes dans un format stable.

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

Maintenant, regardons la ligne 48. `x86_results_csvs()` est une fonction, et son rôle est de sélectionner les fichiers CSV x86 avec une règle explicite. Ce point est important dans la narration, parce qu'on peut expliquer que la figure ne part pas d'un dossier lu au hasard, elle part d'une sélection contrôlée.

```python
def load_latest_rows() -> tuple[list[Path], list[Row]]:
    paths = x86_results_csvs()
    ...
    return paths, _average_rows(all_rows)
```

Ensuite, on va à la ligne 85. `load_latest_rows()` est une fonction qui lit les fichiers, convertit les valeurs, puis homogénéise les lignes. Et juste après, à la ligne 110, le retour `return paths, _average_rows(all_rows)` nous donne deux sorties complémentaires. `paths` est une variable liste qui garde la trace des fichiers lus. `_average_rows(all_rows)` est l'appel d'une fonction d'agrégation qui stabilise les mesures avant le tracé.

Ce passage est intéressant à dire à voix haute, parce qu'il raconte une vraie logique de projet. D'abord on prouve les sources, ensuite on nettoie les données, puis on agrège. Donc quand on voit un graphe final, on sait exactement d'où il vient et comment il a été préparé.

## Code 5 - Script `build_` (construction et export)

Cinquièmement, on ouvre le script `build_` dans `scripts/chart_pipeline/build_performance.py`, et cette fois on montre comment les données préparées deviennent une image finale cohérente.

```python
# scripts/chart_pipeline/build_performance.py
CSV_PATHS, rows = load_latest_rows()
print(f"Sources x86 ({len(CSV_PATHS)}) : {', '.join(p.name for p in CSV_PATHS)}")
```

On commence avec les lignes 54 et 55. Ici, on montre cet extrait de code parce qu'il permet de voir directement quelles sources sont lues. `CSV_PATHS` est une variable liste de chemins, `rows` est une variable liste de lignes prêtes pour le tracé, et `print()` est une fonction standard qui envoie dans le terminal le nom des sources réellement chargées. Ce passage nous permet donc de vérifier, en direct, que le script lit bien les bons fichiers avant de construire le graphe.

```python
def fig1_throughput_4096():
    target_size = 4096
    data = [r for r in rows if r["message_size_bytes"] == target_size]
    ...

def savefig(name: str):
    save_figure(plt.gcf(), CHARTS_DIR, name, facecolor=BG_COLOR)
```

Puis on avance vers la ligne 76. `fig1_throughput_4096()` est une fonction qui construit un graphe concret de débit pour 4096 octets. C'est là que la donnée agrégée devient vraiment un objet visuel.

Enfin, on revient à la ligne 62. `savefig()` est une fonction locale qui appelle `save_figure()`, et `save_figure()` est une fonction utilitaire d'export. Dans cet appel, `CHARTS_DIR` est une variable de chemin qui fixe le dossier de sortie. En narration, c'est utile de dire que le pipeline ne s'arrête pas au tracé et qu'il va jusqu'à une sortie standardisée, donc facile à retrouver et à comparer.

Au final, ce qu'on retient ici, c'est le rôle précis du script `build_` dans la chaîne. Il prend les données déjà préparées, construit la figure, puis l'exporte dans un dossier de sortie bien défini. On montre ce bloc parce qu'il clôt proprement la génération du graphe et qu'il rend visible la dernière étape du pipeline.


## Démo - Exécution complète et validation des sorties
Je vais maintenant passer à une vérification en conditions réelles, dans le terminal, pour observer directement quelles sources sont chargées et quelles sorties sont produites.

```bash
cd crypto-experiments
cd scripts
python .\run_charts.py 01
python .\run_charts.py 03
```

**Texte à lire pendant la commande**
Dans le terminal, je me place d'abord dans le dossier `crypto-experiments` avec la commande `cd crypto-experiments`. Ensuite, je me place dans le dossier `scripts` avec `cd scripts`, puis je lance `python .\run_charts.py 01` pour générer les figures de débit à partir des CSV déjà présents dans `data/results`.

À l'écran, on voit d'abord les lignes `Sources x86 (...)`. Ici, on comprend immédiatement quels fichiers ont été lus pour construire les graphiques. C'est intéressant à montrer, parce que cela permet de vérifier, en direct, que le pipeline part bien des bonnes sources avant de tracer quoi que ce soit.

Après cela, le terminal affiche les images enregistrées avec leurs chemins complets. Cette sortie confirme que le graphe a bien été construit et sauvegardé dans le bon dossier. Puis je lance `python scripts/run_charts.py 03` pour montrer la même logique sur l'autre cible, toujours avec les mêmes sources déjà préparées.

Petite note pratique à dire pendant la démo. Si un fichier `experiment_YYYYMMDD.csv` existe déjà pour la même date, le script écrit automatiquement `experiment_YYYYMMDD_1.csv`, puis `experiment_YYYYMMDD_2.csv`. C'est simplement une protection pour éviter l'écrasement d'un résultat précédent.

Je lance ensuite `python scripts/run_charts.py 01` pour exécuter la cible orientée débit.

À l'écran, on voit d'abord `Sources x86 (...)`, ce qui permet d'identifier immédiatement toutes les sources utilisées côté laptop Windows. Ensuite, on voit `Sources Raspberry Pi (...)`, ce qui confirme les sources utilisées pour la comparaison inter-plateformes. Enfin, on voit les fichiers enregistrés avec leurs chemins complets, ce qui confirme exactement où les sorties orientées débit sont écrites.

Je lance ensuite `python .\run_charts.py 03` pour exécuter la cible orientée modes de chiffrement. Là encore, le terminal affiche les sources utilisées et les fichiers générés, ce qui permet de vérifier que cette deuxième cible active bien le bon sous-ensemble du pipeline.

Au final, cette démonstration montre la chaîne complète: mesure d'abord, export CSV ensuite, génération des figures enfin.
