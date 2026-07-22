# Vidéo 3 - Génération des graphes par le code

## Intro - Objectif et périmètre de démonstration
**Où sommes-nous**
Présentation PowerPoint - Diapo 4a

**Texte à lire**
Bonjour et bienvenue dans cette troisième vidéo. Ici, on va voir comment les graphiques sont générés automatiquement à partir du code, depuis la commande lancée dans le terminal jusqu'au dossier de sortie.

On commence avec la diapo 4a qui résume la chaîne complète de génération. Le fichier script `run_charts.py` sélectionne une cible, lit les CSV dans `data/results/`, prépare les données, construit les figures, applique le style commun, puis écrit les graphiques dans `data/charts/`.

Sur cette diapo, on lit le pipeline de gauche à droite.

À gauche, on voit le point d'entrée `run_charts.py`. Ce fichier script reçoit une clé de cible comme `01`, `02`, `03` ou `04`, puis il oriente l'exécution vers la bonne chaîne de traitement.

Au centre, on voit les blocs de préparation, de construction, de style et de gestion des chemins. Les fichiers `data_*.py` lisent et normalisent les résultats, les fichiers `build_*.py` transforment ces données en graphiques, le fichier `style_charts.py` applique un rendu cohérent sur toutes les figures, puis le fichier `shared_paths.py` centralise les chemins d'entrée et de sortie.

À droite, on regarde le bloc d'export. Les graphiques finaux sont écrits dans `data/charts/`, avec un dossier de sortie adapté à chaque cible de génération, par exemple `01-throughput`, `02-avalanche-effect`, `03-encryption-modes` ou `04-decision-support`.

Donc la logique de la diapo reste simple et traçable, puisqu'on lance une commande, on lit des données, on construit des figures, puis on écrit les sorties dans le bon dossier.

Le point important ne concerne pas seulement le flux et il concerne aussi la séparation des responsabilités. Le fichier script `run_charts.py` orchestre l'exécution, les scripts `data_` préparent les entrées, les scripts `build_` construisent les figures, puis l'export les dépose dans le bon dossier. Cette séparation rend le pipeline plus lisible et plus facile à vérifier.

En pratique, pendant la démo, on vérifie trois choses qui donnent de la confiance. Premièrement, la bonne cible est bien sélectionnée. Deuxièmement, les bonnes sources sont lues dans `data/results/`. Troisièmement, les figures sont bien générées et enregistrées dans le dossier prévu.

Pourquoi c'est essentiel. Parce que si une seule de ces trois étapes est incorrecte, la sortie peut sembler correcte visuellement alors qu'elle n'est plus cohérente avec les données de départ. L'objectif de la vidéo consiste donc à montrer une chaîne fiable et non pas seulement un résultat graphique.

Ensuite, on va explorer les blocs de code qui réalisent cette chaîne, puis on terminera par une démonstration dans le terminal.

À la fin de cette vidéo, vous aurez une vue claire, simple et traçable de la génération des graphiques.


### Architecture - Traçabilité et séparation des rôles
**Où sommes-nous**
VS Code sur `scripts/run_charts.py`, puis `scripts/charts/`, `data/results/` et `data/charts/`.

**Texte à lire**
Avant d'explorer le code ligne par ligne, on va d'abord lire l'architecture pour voir comment `run_charts.py` fonctionne réellement. Cette vue montre la chaîne complète et la commande est lancée, puis la bonne cible est choisie, les CSV sont lus, puis les figures sont écrites dans le dossier de sortie.

Le point d'entrée est le fichier `scripts/run_charts.py`. Ce script reçoit une clé comme `01` ou `03`, il la cherche dans la variable dictionnaire `TARGETS`, puis il appelle la fonction associée.

À partir de là, la fonction choisie s'appuie sur les modules du dossier `scripts/charts/` pour faire le travail concret.

Les fichiers `build_` contiennent la logique de tracé. C'est dans ces fichiers que chaque graphique est construit depuis le choix des données jusqu'à l'export de l'image. Par exemple, le fichier `build_performance.py` génère les graphiques de débit et de modes, tandis que le fichier `build_platform_comparison.py` produit les comparaisons entre x86 et ARM.

Les scripts `data_` lisent les résultats bruts dans `data/results/`, ils convertissent les valeurs et ils préparent des données propres pour le tracé. L'idée reste simple et on sépare la lecture des résultats de leur affichage.

Le fichier `style_charts.py` centralise toute l'identité visuelle. On y retrouve la palette de couleurs, la taille des figures, le style des axes et la manière commune d'enregistrer les images. Ainsi, toutes les figures gardent le même rendu sans répétition inutile.

Enfin, `shared_paths.py` garde en un seul endroit les chemins de lecture et d'écriture, pour que chaque partie du pipeline sache où aller chercher les résultats et où déposer les graphiques.

Donc, quand on lance `python .\run_charts.py 01`, on ne lance pas directement un graphe isolé. On déclenche une chaîne complète et la clé `01` pointe vers une fonction précise, puis cette fonction lit les CSV, construit les figures, applique le style commun et enregistre les sorties dans `data/charts/`.

C'est cette architecture qui rend la démonstration claire, puisqu'on voit la commande, puis les fichiers utilisés, puis la sortie produite.

Pour rendre ça concret, je vais maintenant montrer les extraits de code qui illustrent la chaîne de génération, de la commande jusqu'au graphique final.

## Code 1 - Orchestration et rendu des graphiques

Premièrement, on va ouvrir `run_charts.py` ensemble, parce que c'est le fichier script qui pilote toute la génération des graphes quand on lance une commande dans le terminal.

```python
# scripts/run_charts.py
def _generate_01_debit() -> None:
    perf.generate_groups(["01-throughput"])
    platform_cmp.generate_groups(["01-throughput"])
```

Regardez la logique de lecture pendant la vidéo. À la ligne 33, `_generate_01_debit()` est une fonction et son rôle consiste à lancer le groupe de graphes de débit. À la ligne 54, `TARGETS` est une variable dictionnaire qui associe une clé de commande à une fonction. Puis, à la ligne 84, l'appel `TARGETS[key]()` exécute réellement la fonction choisie.

Pourquoi on insiste sur ce passage. Parce que ce bloc garantit que la commande tapée dans le terminal déclenche le bon sous-pipeline sans ambiguïté et sans intervention manuelle. Quand vous affichez `python scripts/run_charts.py 01`, vous pouvez expliquer de façon fluide que la clé `01` est lue, qu'elle pointe vers une fonction précise, puis que cette fonction lance exactement les graphes attendus.

## Code 2 - Script `data_` (sélection et agrégation)

Deuxièmement, on passe au script `data_` dans `scripts/charts/data_performance.py`, parce que c'est ici que la qualité des graphes se joue vraiment. Avant de tracer quoi que ce soit, on décide d'abord quelles sources sont acceptées, puis on prépare les lignes dans un format stable.

```python
# scripts/charts/data_performance.py
def x86_results_csvs() -> list[Path]:
    csvs = sorted(
        f for f in RESULTS_DIR.iterdir()
        if f.suffix == ".csv" and f.name != ".gitkeep"
        and ("x86" in f.name or "laptop-windows" in f.name)
    )
    return csvs
```

Maintenant, regardons la ligne 48. `x86_results_csvs()` est une fonction et son rôle consiste à sélectionner les fichiers CSV x86 avec une règle explicite. Ce point est important dans la narration parce qu'on peut expliquer que la figure ne part pas d'un dossier lu au hasard et qu'elle part d'une sélection contrôlée. On peut aussi insister sur le fait que cette sélection est triée, donc que l'ordre de lecture reste stable d'une exécution à l'autre.

```python
def load_latest_rows() -> tuple[list[Path], list[Row]]:
    paths = x86_results_csvs()
    ...
    return paths, _average_rows(all_rows)
```

Ensuite, on va à la ligne 85. `load_latest_rows()` est une fonction qui lit les fichiers, convertit les valeurs, puis homogénéise les lignes. Concrètement, les colonnes du CSV deviennent des valeurs directement exploitables pour le tracé, par exemple pour les tailles, les temps et les débits. Juste après, à la ligne 110, l'instruction `return paths, _average_rows(all_rows)` donne deux sorties complémentaires. `paths` est une variable de type liste qui garde la trace des fichiers lus. `_average_rows(all_rows)` est l'appel d'une fonction d'agrégation qui stabilise les mesures avant le tracé.

Dans la narration, ce bloc est fort parce qu'il montre une préparation méthodique des données. Le script commence par identifier les bons fichiers, puis il lit chaque ligne et transforme les colonnes du CSV en valeurs cohérentes pour le traitement. Ensuite, il regroupe les mesures qui décrivent la même configuration expérimentale, donc le même algorithme, le même mode, la même taille de clé et la même taille de message. Enfin, il calcule une moyenne sur les champs numériques pour produire une base de comparaison plus stable. Autrement dit, le graphe final ne repose pas sur une lecture brute ni sur une mesure isolée, mais sur des données filtrées, converties et agrégées de façon contrôlée.

## Code 3 - Script `build_` (construction et export)

Troisièmement, on ouvre le script `build_` dans `scripts/charts/build_performance.py`, et cette fois on montre comment les données préparées deviennent une image finale cohérente.

```python
# scripts/charts/build_performance.py
CSV_PATHS, rows = load_latest_rows()
print(f"Sources x86 ({len(CSV_PATHS)}) : {', '.join(p.name for p in CSV_PATHS)}")
```

On commence avec les lignes 54 et 55. À la ligne 54, l'appel `load_latest_rows()` est une fonction de préparation, et son rôle est de renvoyer les lignes déjà nettoyées et agrégées pour le tracé. À la ligne 55, l'appel `print(...)` est une fonction standard qui affiche les sources effectivement lues. Ce passage sert donc à vérifier, en direct, que le graphe part des bons fichiers.

```python
def fig1_throughput_4096():
    target_size = 4096
    data = [r for r in rows if r["message_size_bytes"] == target_size]
    groups = defaultdict(list)
    for r in data:
        label = f"{r['mode']}\n{r['key_size_bits']}b"
        groups[r["algorithm"]].append((label, r["throughput_enc_mbps"]))
    ...
    ax.bar(...)
    _style_ax(ax)
    plt.tight_layout()
    savefig("01-throughput/throughput-by-algo-mode-x86-4kb.png")

def savefig(name: str):
    save_figure(plt.gcf(), CHARTS_DIR, name, facecolor=BG_COLOR)
```

Puis on avance vers la ligne 76 avec `fig1_throughput_4096()`. C'est une fonction de construction de graphe, et son rôle est de produire la figure de débit pour le cas 4096 octets.

À la ligne 81, `defaultdict(list)` est un constructeur de dictionnaire depuis `collections`, et son rôle est de créer automatiquement une liste vide par algorithme pour regrouper les mesures. À la ligne 100, l'appel `ax.bar(...)` est une méthode Matplotlib, et son rôle est de transformer ces valeurs en barres affichables.

Pour la finition, à la ligne 134, `_style_ax(ax)` est une fonction locale définie à la ligne 58, et son rôle est d'appliquer le style commun en relayant vers `style_ax(...)` importée depuis `style_charts.py`. À la ligne 135, `plt.tight_layout()` est une fonction Matplotlib qui ajuste l'espacement de la figure pour éviter les chevauchements de texte.

À la ligne 136, `savefig("01-throughput/throughput-by-algo-mode-x86-4kb.png")` est une fonction locale définie à la ligne 62, et son rôle est de centraliser l'export. Cette fonction appelle `save_figure(...)` avec `CHARTS_DIR` pour écrire l'image dans le bon dossier. Ces deux éléments sont importés depuis les modules communs `style_charts.py` et `shared_paths.py`.

Au final, ce bloc montre clairement la responsabilité de `build_` avec un exemple concret et traçable: il organise les données, trace la figure, applique le style commun, puis délègue l'export à l'utilitaire partagé avec un chemin de sortie centralisé.


## Démo - Exécution complète et validation des sorties
Je vais maintenant passer à une vérification en conditions réelles, dans le terminal, pour montrer comment `run_charts.py` lit les CSV déjà présents et produit les figures attendues.

```bash
cd .\crypto-experiments\scripts
python .\run_charts.py 01
python .\run_charts.py 03
```

**Texte à lire pendant la commande**
Dans le terminal, je me place directement dans le dossier `scripts` avec la commande `cd .\crypto-experiments\scripts`, puis je lance `python .\run_charts.py 01` pour générer les figures de débit à partir des CSV déjà présents dans `data/results`.

À l'écran, on voit d'abord les lignes `Sources x86 (...)`. Ici, on comprend immédiatement quels fichiers ont été lus pour construire les graphiques. C'est ce passage qui nous intéresse, parce qu'il montre que le script ne trace rien au hasard et qu'il part bien des bonnes sources.

Après cela, le terminal affiche les images enregistrées avec leurs chemins complets. Cette sortie confirme que le graphe a bien été construit et sauvegardé dans le bon dossier. Puis je lance `python .\run_charts.py 03` pour montrer la même logique sur l'autre cible, avec le même principe de lecture des sources et de génération des sorties.

Le point important est que cette démonstration ne refait pas la mesure. Elle montre seulement le rôle de `run_charts.py`, qui prend les CSV disponibles, choisit la bonne cible et écrit les figures correspondantes. C'est exactement ce qu'on veut vérifier ici.

Pour conclure cette partie, `run_charts.py` est bien le point d'entrée qu'on veut montrer dans la vidéo. Il ne calcule rien lui-même, il prend des résultats déjà produits, il les transforme en graphiques, puis il les enregistre dans le bon dossier. C'est ça qui démontre clairement la chaîne de génération et le travail de préparation qui a été fait avant.


