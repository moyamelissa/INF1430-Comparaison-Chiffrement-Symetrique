# Vidéo 3 - Résultats de performance

## Introduction (ouverture caméra)
**Texte à lire**
Cette vidéo présente les résultats de performance de la campagne expérimentale.

Après la validation fonctionnelle et la méthode de mesure, on répond maintenant à la question centrale, à savoir qu'est-ce qui explique les écarts de débit entre algorithmes, entre modes, et entre plateformes x86 et ARM.

La lecture suit une progression simple. D'abord, on confirme la traçabilité des graphes. Ensuite, on lit l'effet de la taille des messages. Puis on compare les algorithmes et les modes. Enfin, on termine avec l'effet matériel, en particulier AES-NI.

## Objectif
Interpréter rigoureusement les performances en reliant chaque écart à trois facteurs, soit l'algorithme, le mode d'opération et l'architecture matérielle.

## Portée
- `scripts/run_charts.py`
- `scripts/chart_pipeline/build_performance.py`
- `scripts/chart_pipeline/build_platform_comparison.py`
- `data/results/laptop-windows-x86_experience3.csv`
- `data/results/raspberry-pi_experience3.csv`
- `data/charts/01-debit/debit-vs-taille-message.png`
- `data/charts/01-debit/debit-4096o.png`
- `data/charts/01-debit/comparaison-ratio-acceleration.png`
- `data/charts/03-modes-chiffrement/aes-comparaison-modes.png`
- `data/charts/03-modes-chiffrement/aes-securite-vs-performance.png`
- `data/charts/01-debit/chacha20-comparaison-plateformes.png`

## Guide d'enregistrement

### Section 1 - Traçabilité des graphes
**Où sommes-nous**
VS Code sur `scripts/run_charts.py`, puis `scripts/chart_pipeline/` et `data/charts/`.

**Texte à lire**
Avant d'interpréter les chiffres, on confirme la traçabilité. Les figures ne sont pas dessinées manuellement. Elles sont générées automatiquement à partir des CSV de mesure.

Le point d'entrée est `scripts/run_charts.py`. Ce script orchestre la génération des dossiers de sortie et délègue le rendu aux modules de `scripts/chart_pipeline/`.

Le dossier `chart_pipeline/` est organisé en quatre types de fichiers, et chacun a un rôle bien défini.

On commence par les fichiers `build_*.py`, qui contiennent la logique de tracé. C'est là que chaque graphique est construit, du choix des données jusqu'à la mise en forme et l'export de l'image. Par exemple, `build_performance.py` génère les graphiques de débit et de modes, alors que `build_platform_comparison.py` produit les comparaisons entre x86 et ARM.

Ensuite, les fichiers `data_*.py` se chargent du chargement et de la normalisation des données brutes. Ils lisent les CSV dans `data/results/`, convertissent les types et exposent des structures prêtes à l'emploi pour les modules de tracé. C'est ce qui sépare clairement la lecture des données de leur représentation graphique.

Le fichier `style_charts.py`, lui, centralise toute l'identité visuelle. On y retrouve la palette de couleurs par algorithme, les dimensions des figures, le style des axes et une fonction de sauvegarde commune. Toutes les figures partagent donc le même rendu, sans duplication de code.

Enfin, `shared_paths.py` déclare les chemins partagés, c'est-à-dire `data/results/` et `data/charts/`, pour que chaque module sache où lire et où écrire de façon cohérente.

Quand on lance `python scripts/run_charts.py 01`, le script appelle la fonction d'orchestration correspondante, qui elle-même appelle les bons modules `build_*.py`. Ces modules chargent les données via les `data_*.py`, appliquent le style de `style_charts.py`, et exportent les figures dans `data/charts/`.

Cette architecture garantit une narration reproductible, parce que chaque conclusion est rattachée à une source mesurée et à une image générée automatiquement.

Pour rendre ça concret, je vais maintenant montrer trois extraits de code qui illustrent chacune de ces étapes.

Premièrement, je vais vous montrer un extrait du fichier `scripts/run_charts.py`, parce que c'est lui qui reçoit la cible en entrée et qui oriente la génération vers la bonne fonction.

**Code à montrer (1/3 - orchestration)**
```python
# scripts/run_charts.py
def _generate_01_debit() -> None:
    # fonction d'orchestration pour la cible "01"
    perf.generate_groups(["01-debit"])
    platform_cmp.generate_groups(["01-debit"])

TARGETS = {
    # clés string -> fonctions
    "01": _generate_01_debit,
    "02": _generate_02_effet_avalanche,
    "03": _generate_03_modes_chiffrement,
    "04": _generate_04_synthese,
}

def main(argv: list[str]) -> int:
    ...
    for key in ordered:
        TARGETS[key]()
```

**Texte à lire pendant le code**
Ce premier extrait joue le rôle de point de routage du pipeline. D'abord, `main()` est une fonction qui lit la cible passée dans la commande, par exemple `01` dans `python scripts/run_charts.py 01`. Ensuite, `TARGETS` est une variable dictionnaire qui associe cette cible à la bonne fonction d'orchestration. Les clés `"01"`, `"02"`, `"03"` et `"04"` correspondent respectivement aux groupes débit, avalanche, modes et synthèse. Les valeurs associées `_generate_01_debit`, `_generate_02_effet_avalanche`, `_generate_03_modes_chiffrement` et `_generate_04_synthese` sont des fonctions d'orchestration. Plus précisément, `_generate_01_debit` lance les graphiques de débit, `_generate_02_effet_avalanche` lance les graphiques d'avalanche et le graphe de convergence des rounds, `_generate_03_modes_chiffrement` lance les graphiques de modes et la démonstration ECB, puis `_generate_04_synthese` lance les graphiques de synthèse multicritère. 

Concrètement, si j'exécute la commande avec l'argument `01`, `main()` déclenche la fonction `_generate_01_debit`. Cette fonction appelle ensuite `perf.generate_groups`, qui est une fonction du module `build_performance.py` et qui lance les fonctions de tracé du groupe demandé pour produire les graphiques de performance locale, puis `platform_cmp.generate_groups`, qui est une fonction du module `build_platform_comparison.py` et qui lance les fonctions de tracé du même groupe pour produire les comparaisons x86 contre ARM.

Donc, une valeur d'entrée correspond à une action précise, ce qui évite de mélanger les sorties et rend l'exécution facile à expliquer.

Deuxièmement, je vais vous montrer un extrait du fichier `scripts/chart_pipeline/data_performance.py`, parce que c'est lui qui sélectionne la source CSV et qui prépare les données avant le tracé.

**Code à montrer (2/3 - source des données)**
```python
# scripts/chart_pipeline/data_performance.py
def latest_results_csv() -> Path:
    csv_files = sorted(
        f for f in RESULTS_DIR.iterdir() if f.suffix == ".csv" and f.name != ".gitkeep"
    )
    return csv_files[-1]

def load_latest_rows() -> tuple[Path, list[Row]]:
    csv_path = latest_results_csv()
    rows: list[Row] = []
    with csv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            rows.append({
                "algorithm": row["algorithm"],
                "message_size_bytes": int(row["message_size_bytes"]),
                "throughput_enc_mbps": float(row["throughput_enc_mbps"]),
            })
    return csv_path, rows
```

**Texte à lire pendant le code**
Ce deuxième extrait joue le rôle de couche de préparation des données. Son objectif est de livrer des lignes propres aux fonctions de tracé, pour éviter les erreurs de type et garantir des graphiques cohérents.

D'abord, `latest_results_csv()` est une fonction qui choisit le fichier source à utiliser. `RESULTS_DIR` est une variable de chemin, et `iterdir()` est une méthode de cet objet qui parcourt les fichiers du dossier. Ensuite, `load_latest_rows()` est une fonction qui lit ce CSV et qui normalise les champs. Dans cette étape, `csv.DictReader` est une classe de la bibliothèque `csv`, et elle transforme chaque ligne en dictionnaire. Puis `int` et `float` sont des fonctions de conversion qui transforment les chaînes en valeurs numériques exploitables.

Concrètement, ce bloc répond à la question comment les données arrivent au tracé. On sélectionne d'abord le bon CSV, puis on charge les lignes, puis on convertit les types une seule fois ici. Donc, quand les modules de rendu reçoivent les données, elles sont déjà prêtes à filtrer, à agréger et à afficher.

Troisièmement, je vais vous montrer un extrait du fichier `scripts/chart_pipeline/build_performance.py`, parce que c'est lui qui affiche la source réellement utilisée et qui standardise l'export des figures.

**Code à montrer (3/3 - export)**
```python
# scripts/chart_pipeline/build_performance.py
CSV_PATH, rows = load_latest_rows()
print(f"Lecture du fichier: {CSV_PATH}")

def savefig(name: str):
    save_figure(plt.gcf(), CHARTS_DIR, name, facecolor=BG_COLOR)
```

**Texte à lire pendant le code**
Ce troisième extrait joue le rôle de couche de sortie. Son objectif est d'assurer la traçabilité de la source et l'uniformité des exports, pour que toutes les figures aient le même format visuel.

D'abord, `CSV_PATH` et `rows` sont des variables de module qui reçoivent le résultat de `load_latest_rows()`, qui est une fonction importée depuis `data_performance.py`. Ensuite, `print()` est une fonction intégrée qui affiche dans le terminal le fichier réellement chargé. Puis `savefig` est une fonction locale qui encapsule `save_figure`, qui est une fonction importée depuis `style_charts.py`. Enfin, `CHARTS_DIR` et `BG_COLOR` sont des variables de configuration importées et réutilisées à chaque enregistrement.

Concrètement, ce bloc répond à la question comment les figures sont exportées de façon cohérente. Chaque fonction de tracé appelle `savefig`, puis `savefig` applique le même dossier de sortie, le même fond et le même mécanisme d'enregistrement. Donc, les images générées restent homogènes dans tout le rapport.

**Commande à montrer (terminal)**
```bash
cd crypto-experiments
python scripts/run_charts.py 01
python scripts/run_charts.py 03
```

**Texte à lire pendant la commande**
Je lance maintenant deux cibles pour vérifier le comportement en conditions réelles. Avec `01`, je teste le flux orienté débit. Avec `03`, je teste le flux orienté modes de chiffrement. De cette façon, on valide non seulement que les fonctions sont bien appelées, mais aussi que chaque cible active le bon sous-ensemble du pipeline.
**Texte à lire après la commande**
Dans le terminal, on voit d'abord `Lecture du fichier ...`, ce qui répond à la question quelle source a été utilisée. Ensuite on voit les fichiers enregistrés avec leurs chemins complets, ce qui répond à la question où les sorties sont écrites. Enfin, comme cette séquence se répète à chaque exécution de cible, on répond aussi à la question quand le pipeline produit les figures, donc immédiatement après la sélection et l'appel des fonctions d'orchestration.

**Transition**
Maintenant que la chaîne de production est claire, on passe à la lecture des débits.

### Section 2 - Débit selon la taille du message
**Visuel à montrer**
`data/charts/01-debit/debit-vs-taille-message.png`

**Texte à lire**
Ce graphe montre l'évolution du débit quand la taille du message augmente. Sur les petites tailles, le coût fixe pèse fortement. Quand la taille augmente, ce coût est amorti, et le débit utile se stabilise.

Le point important est méthodologique, car un algorithme moyen à 64 octets peut devenir compétitif à 4096 ou 16384 octets. C'est pourquoi notre protocole couvre plusieurs tailles de message.

**Transition**
Après la tendance globale, on fixe une taille de référence pour comparer plus clairement.

### Section 3 - Comparaison à 4096 octets
**Visuel à montrer**
`data/charts/01-debit/debit-4096o.png`

**Texte à lire**
Ici, la taille est fixée à 4096 octets. On isole donc l'effet algorithme et mode, sans mélanger l'effet taille.

AES ressort en tête sur x86 dans plusieurs cas, cohérent avec l'accélération matérielle. ChaCha20 reste régulier et performant, surtout sur des environnements moins favorables à AES-NI. DES et 3DES sont plus lents, en plus de leurs limites de sécurité.

**Transition**
La hiérarchie globale est visible. Regardons maintenant l'effet spécifique des modes.

### Section 4 - Impact des modes d'opération
**Visuels à montrer**
`data/charts/03-modes-chiffrement/aes-comparaison-modes.png`
`data/charts/03-modes-chiffrement/aes-securite-vs-performance.png`

**Texte à lire**
À algorithme constant, le mode change le coût total. Tous les modes n'ont pas la même charge fonctionnelle. Par exemple, GCM ajoute l'authentification en plus du chiffrement.

Le message clé n'est pas de choisir le mode le plus rapide en absolu. Le bon choix est celui qui correspond au besoin de sécurité du système.

**Transition**
On a séparé l'effet taille et l'effet mode. Il reste l'effet plateforme.

### Section 5 - Effet plateforme et rôle d'AES-NI
**Visuels à montrer**
`data/charts/01-debit/comparaison-ratio-acceleration.png`
`data/charts/01-debit/chacha20-comparaison-plateformes.png`

**Texte à lire**
Ici, on explique l'écart x86 versus ARM. Sur x86, AES profite de l'extension AES-NI. Une part importante du gain vient donc du matériel.

Sur Raspberry Pi, ce levier est différent ou absent, et la hiérarchie peut se resserrer. La conclusion est directe, puisque la performance cryptographique est une propriété du couple algorithme plus architecture.

### Section 6 - Conclusion vidéo 3
**Texte à lire**
On retient trois constats. Le débit dépend de la taille de message et de l'algorithme. Le mode d'opération introduit un compromis mesurable entre coût et garanties de sécurité. Et l'architecture matérielle, notamment AES-NI, explique une part majeure des écarts inter-plateformes.

Dans la vidéo suivante, on complète cette lecture avec la robustesse cryptographique, l'effet d'avalanche et la stabilité statistique.
