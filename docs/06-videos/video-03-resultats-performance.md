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

À droite, on regarde le bloc d'export. Les résultats renvoyés sont écrits dans un fichier CSV `experiment_YYYYMMDD.csv`, via la structure `ExperimentResult`, avec une ligne par configuration mesurée.

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

Ici, `EXPERIMENT_MATRIX` est une variable de configuration au niveau du fichier `scripts/experiment.py`. Cette liste définit explicitement les algorithmes, les modes et les tailles de clé qui doivent être exécutés. Cette structure fixe le périmètre de mesure avant même de parler de graphiques.

Ensuite, la boucle principale parcourt cette variable de configuration et appelle `controller.run_performance(...)`, qui est une méthode de l'objet `controller` de la classe `ExperimentController`. Chaque mesure est ajoutée à la variable liste `results`, ce qui construit progressivement le jeu de données brut.

```python
with open(out_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for r in results:
        writer.writerow(asdict(r))
```

Finalement, ce bloc écrit les résultats dans un CSV traçable. `csv.DictWriter` est une classe de la bibliothèque standard, `writeheader()` et `writerow()` sont des méthodes d'écriture CSV, et `asdict()` est une fonction qui convertit un objet de données en dictionnaire. On montre ce passage pour ancrer l'idée clé de la vidéo: les figures ne viennent pas d'une saisie manuelle, elles viennent d'un export mesuré.

```python
if not all_algorithms_ok:
    return 1
```

Enfin, on montre cette condition pour rendre explicite la robustesse d'exécution: `all_algorithms_ok` est une variable booléenne calculée par la fonction `_print_run_summary()`, et `return 1` est le code de sortie d'échec du script.

Au final, `experiment.py` joue bien le rôle de producteur de vérité expérimentale, car il exécute, contrôle et exporte les mesures sources.

## Code 2 - Calcul des métriques dans le contrôleur
Deuxièmement, je vais vous montrer un extrait du fichier `application/ExperimentController.py`, parce que c'est lui qui calcule les métriques de performance et de robustesse utilisées ensuite dans les CSV.

On commence par montrer le bloc de `run_performance`, qui est une méthode de la classe `ExperimentController`, parce qu'il contient le chronométrage et le calcul du débit.

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

Ici, `time.perf_counter()` est une fonction du module standard `time` qui sert au chronométrage précis et encadre uniquement l'appel cryptographique. Dans ce bloc, `self._engine.encrypt(...)` est une méthode de l'objet moteur de chiffrement, et `throughput_encrypt_mbps` est une variable numérique calculée en MB/s à partir du temps moyen, pour obtenir une métrique comparable entre tailles de messages et plateformes.

On montre ce code pour relier directement le graphe de débit à sa formule de calcul, pas seulement à son affichage.

```python
return ExperimentResult(
    ...
    avalanche_score=self.measure_avalanche(),
    key_avalanche_score=self.measure_key_avalanche(),
    ci95_encrypt_mbps=ci95_enc,
)
```

Ensuite, ce retour de `ExperimentResult` regroupe toutes les métriques clés dans une structure unique. Ici, `ExperimentResult` est une classe de données définie dans `application/ExperimentController.py`, et `measure_avalanche()` ainsi que `measure_key_avalanche()` sont des méthodes de la même classe. Cela simplifie l'export CSV et garantit une correspondance stable avec les colonnes de sortie.

Enfin, on montre ce passage pour souligner que l'avalanche, la sensibilité clé et l'intervalle de confiance à 95 % sont produits au moment de la mesure, et non ajoutés plus tard dans la phase de visualisation.

Au final, `ExperimentController.py` joue bien le rôle de noyau scientifique, car il transforme les exécutions cryptographiques en métriques exploitables.

## Code 3 - Orchestration et rendu des graphiques

Troisièmement, je vais vous montrer la partie pipeline de rendu, parce qu'elle prend les CSV mesurés et les transforme en figures traçables.

Ce troisième extrait joue le rôle de couche de transformation et de sortie. Son objectif est simple, sélectionner les bonnes sources, agréger proprement, puis enregistrer les figures de façon standardisée.

```python
# scripts/run_charts.py
def _generate_01_debit() -> None:
    perf.generate_groups(["01-debit"])
    platform_cmp.generate_groups(["01-debit"])
```

Ici, `_generate_01_debit()` est une fonction d'orchestration dans le fichier `scripts/run_charts.py`. Elle appelle `generate_groups(...)`, qui est une fonction exposée par les modules `perf` et `platform_cmp`, pour déclencher les figures de débit x86 et les comparaisons inter-plateformes. On montre ce bloc pour rappeler où la génération des graphes est pilotée.

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

Ensuite, cette fonction `x86_results_csvs()` centralise la sélection des sources x86. C'est une fonction utilitaire du fichier `data_performance.py`; elle lit le dossier indiqué par la variable de chemin `RESULTS_DIR`, applique une règle explicite de filtrage et retourne une liste ordonnée. On montre ce bloc pour prouver que la lecture des CSV est déterministe et traçable.

```python
# scripts/chart_pipeline/build_performance.py
CSV_PATHS, rows = load_latest_rows()
print(f"Fichiers x86 lus ({len(CSV_PATHS)}) : {', '.join(p.name for p in CSV_PATHS)}")
```

Dans ce bloc, `CSV_PATHS` est une variable qui contient la liste des chemins réellement lus et `rows` est une variable liste des données prêtes à tracer, tous deux retournés par la fonction `load_latest_rows()`. La fonction `print()` écrit ces sources dans le terminal.

```python
def savefig(name: str):
    save_figure(plt.gcf(), CHARTS_DIR, name, facecolor=BG_COLOR)
```

Ici, `savefig()` est une fonction locale d'export qui appelle `save_figure()`, une fonction utilitaire de sauvegarde. `plt.gcf()` est une fonction de l'API Matplotlib qui récupère la figure courante, `CHARTS_DIR` est une variable de chemin du dossier de sortie, et `BG_COLOR` est une variable de style qui fixe la couleur de fond.

Concrètement, ces blocs montrent que chaque figure suit le même chemin, des CSV mesurés jusqu'à l'enregistrement final. C'est ce qui rend le rapport cohérent d'une figure à l'autre.


## Démo - Exécution complète et validation des sorties
Je vais maintenant passer à une vérification en conditions réelles, dans le terminal, pour observer directement quelles sources sont chargées et quelles sorties sont produites.

```bash
cd crypto-experiments
python scripts/experiment.py
python scripts/run_charts.py 01
python scripts/run_charts.py 03
```

**Texte à lire pendant la commande**
Dans le terminal, je me place d'abord dans le dossier `crypto-experiments` avec la commande `cd crypto-experiments`. Ensuite, je lance `python scripts/experiment.py` pour exécuter la campagne de mesure et générer les CSV.

À l'écran, on voit les lignes `Running ...`, puis le tableau `Run summary by algorithm`, puis le chemin du fichier CSV exporté. Cette étape confirme que les données sources sont effectivement produites par le protocole.

Je lance ensuite `python scripts/run_charts.py 01` pour exécuter la cible orientée débit.

À l'écran, on voit d'abord `Sources x86 (...)`, ce qui permet d'identifier immédiatement toutes les sources utilisées côté laptop Windows. Ensuite, on voit `Sources Raspberry Pi (...)`, ce qui confirme les sources utilisées pour la comparaison inter-plateformes. Enfin, on voit les fichiers enregistrés avec leurs chemins complets, ce qui confirme exactement où les sorties orientées débit sont écrites.

Je lance ensuite `python scripts/run_charts.py 03` pour exécuter la cible orientée modes de chiffrement. Là encore, le terminal affiche les sources utilisées et les fichiers générés, ce qui permet de vérifier que cette deuxième cible active bien le bon sous-ensemble du pipeline.

Au final, cette démonstration montre la chaîne complète: mesure d'abord, export CSV ensuite, génération des figures enfin.
