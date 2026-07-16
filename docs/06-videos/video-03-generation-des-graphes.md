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

À droite, on regarde le bloc d'export. Les graphiques finaux sont écrits dans `data/charts/`, avec un dossier de sortie adapté à chaque cible de génération, par exemple `01-debit`, `02-effet-avalanche`, `03-modes-chiffrement` ou `04-synthese`.

Donc la logique de la diapo reste simple et traçable, puisqu'on lance une commande, on lit des données, on construit des figures, puis on écrit les sorties dans le bon dossier.

Le point important ne concerne pas seulement le flux et il concerne aussi la séparation des responsabilités. Le fichier script `run_charts.py` orchestre l'exécution, les scripts `data_` préparent les entrées, les scripts `build_` construisent les figures, puis l'export les dépose dans le bon dossier. Cette séparation rend le pipeline plus lisible et plus facile à vérifier.

En pratique, pendant la démo, on vérifie trois choses qui donnent de la confiance. Premièrement, la bonne cible est bien sélectionnée. Deuxièmement, les bonnes sources sont lues dans `data/results/`. Troisièmement, les figures sont bien générées et enregistrées dans le dossier prévu.

Pourquoi c'est essentiel. Parce que si une seule de ces trois étapes est incorrecte, la sortie peut sembler correcte visuellement alors qu'elle n'est plus cohérente avec les données de départ. L'objectif de la vidéo consiste donc à montrer une chaîne fiable et non pas seulement un résultat graphique.

Ensuite, on va explorer les blocs de code qui réalisent cette chaîne, puis on terminera par une démonstration dans le terminal.

À la fin de cette vidéo, vous aurez une vue claire, simple et traçable de la génération des graphiques.


### Architecture - Traçabilité et séparation des rôles
**Où sommes-nous**
VS Code sur `scripts/run_charts.py`, puis `scripts/chart_pipeline/`, `data/results/` et `data/charts/`.

**Texte à lire**
Avant d'explorer le code ligne par ligne, on va d'abord lire l'architecture pour voir comment `run_charts.py` fonctionne réellement. Cette vue montre la chaîne complète et la commande est lancée, puis la bonne cible est choisie, les CSV sont lus, puis les figures sont écrites dans le dossier de sortie.

Le point d'entrée est le fichier `scripts/run_charts.py`. Ce script reçoit une clé comme `01` ou `03`, il la cherche dans la variable dictionnaire `TARGETS`, puis il appelle la fonction associée.

À partir de là, la fonction choisie s'appuie sur les modules du dossier `scripts/chart_pipeline/` pour faire le travail concret.

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
    perf.generate_groups(["01-debit"])
    platform_cmp.generate_groups(["01-debit"])
```

Regardez la logique de lecture pendant la vidéo. À la ligne 33, `_generate_01_debit()` est une fonction et son rôle consiste à lancer le groupe de graphes de débit. À la ligne 54, `TARGETS` est une variable dictionnaire qui associe une clé de commande à une fonction. Puis, à la ligne 84, l'appel `TARGETS[key]()` exécute réellement la fonction choisie.

Pourquoi on insiste sur ce passage. Parce que ce bloc garantit que la commande tapée dans le terminal déclenche le bon sous-pipeline sans ambiguïté et sans intervention manuelle. Quand vous affichez `python scripts/run_charts.py 01`, vous pouvez expliquer de façon fluide que la clé `01` est lue, qu'elle pointe vers une fonction précise, puis que cette fonction lance exactement les graphes attendus.

## Code 2 - Script `data_` (sélection et agrégation)

Deuxièmement, on passe au script `data_` dans `scripts/chart_pipeline/data_performance.py`, parce que c'est ici que la qualité des graphes se joue vraiment. Avant de tracer quoi que ce soit, on décide d'abord quelles sources sont acceptées, puis on prépare les lignes dans un format stable.

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

Maintenant, regardons la ligne 48. `x86_results_csvs()` est une fonction et son rôle consiste à sélectionner les fichiers CSV x86 avec une règle explicite. Ce point est important dans la narration parce qu'on peut expliquer que la figure ne part pas d'un dossier lu au hasard et qu'elle part d'une sélection contrôlée.

```python
def load_latest_rows() -> tuple[list[Path], list[Row]]:
    paths = x86_results_csvs()
    ...
    return paths, _average_rows(all_rows)
```

Ensuite, on va à la ligne 85. `load_latest_rows()` est une fonction qui lit les fichiers, convertit les valeurs, puis homogénéise les lignes. Juste après, à la ligne 110, l'instruction `return paths, _average_rows(all_rows)` donne deux sorties complémentaires. `paths` est une variable de type liste qui garde la trace des fichiers lus. `_average_rows(all_rows)` est l'appel d'une fonction d'agrégation qui stabilise les mesures avant le tracé.

Ce passage est intéressant à dire à voix haute, parce qu'il raconte une vraie logique de projet. D'abord on prouve les sources, ensuite on nettoie les données, puis on agrège. Donc quand on voit un graphe final, on sait exactement d'où il vient et comment il a été préparé.

## Code 3 - Script `build_` (construction et export)

Troisièmement, on ouvre le script `build_` dans `scripts/chart_pipeline/build_performance.py`, et cette fois on montre comment les données préparées deviennent une image finale cohérente.

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

Puis on avance vers la ligne 76. `fig1_throughput_4096()` est une fonction qui construit un graphe concret de débit pour 4096 octets. C'est à cet endroit que la donnée agrégée devient un objet visuel.

Enfin, on revient à la ligne 62. `savefig()` est une fonction locale qui appelle `save_figure()`, puis `save_figure()` est une fonction utilitaire d'export. Dans cet appel, `CHARTS_DIR` est une variable de chemin qui fixe le dossier de sortie. En narration, c'est utile de rappeler que le pipeline ne s'arrête pas au tracé et qu'il va jusqu'à une sortie standardisée qui reste facile à retrouver et à comparer.

Au final, ce qu'on retient ici, c'est le rôle précis du script `build_` dans la chaîne. Il prend les données déjà préparées, construit la figure, puis l'exporte dans un dossier de sortie bien défini. On montre ce bloc parce qu'il clôt proprement la génération du graphe et qu'il rend visible la dernière étape du pipeline.


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
