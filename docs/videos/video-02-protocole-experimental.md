# Vidéo 2 - Protocole expérimental

## Objectif
Démontrer que la méthode de mesure est valide, comparable entre plateformes et reproductible.

## Portée
- application/ExperimentController.py
- scripts/experiment.py
- Structure du CSV dans data/results

## Guide d'enregistrement

### Étape 1 - Cadrage du protocole et comparaison des plateformes
**Où sommes-nous :**
PowerPoint, diapositive 4 (Protocole expérimental).

**Texte à dire :**
Dans cette vidéo, nous allons montrer pourquoi notre protocole expérimental est méthodologiquement solide. Nous allons démontrer qu'il permet une comparaison valide entre plateformes et qu'il produit des résultats interprétables de manière rigoureuse.

Commençons par la diapositive 4 de la présentation PowerPoint.
Elle présente trois paramètres clés, soit 5 algorithmes, 5 tailles de message testées et 100 répétitions.

Nous présentons aussi une comparaison contrôlée entre un ordinateur portable x86 et un Raspberry Pi. Le tableau explicite les différences de contexte qui influencent directement la performance.

Regardons maintenant les caractéristiques une par une.
Pour le processeur, le portable utilise un Intel Core i5-10300H, alors que le Raspberry Pi utilise un ARM Cortex-A72. Ces architectures n'ont pas la même capacité de calcul ni les mêmes optimisations, ce qui peut créer des écarts de débit, même avec le même code.

Pour le système d'exploitation, nous comparons Windows 11 et Raspberry Pi OS.
Raspberry Pi OS est une distribution Linux basée sur Debian. Cette différence de système influence la gestion des processus, des pilotes et de l'ordonnancement, donc le comportement en performance.

Ensuite, la distinction la plus structurante est la présence d'AES-NI sur l'ordinateur portable x86 et son absence sur Raspberry Pi. AES-NI est une extension d'instructions matérielles qui accélère l'exécution de l'algorithme AES. Cette différence s'explique par l'architecture processeur: AES-NI est propre à l'écosystème x86 Intel, alors que le Raspberry Pi repose sur une architecture ARM. Par conséquent, les performances AES peuvent être sensiblement plus élevées sur le portable que sur le Raspberry Pi.

Pour la mémoire vive, le portable dispose d'environ 16 Go contre 4 Go sur Raspberry Pi.
Une mémoire plus élevée réduit en général la pression mémoire et limite les ralentissements liés aux contraintes de ressources lors des campagnes répétées.

Enfin, le contexte d'exécution est multitâche sur le portable et minimaliste sur Raspberry Pi.
Multitâche signifie davantage de bruit potentiel de fond, tandis qu'un contexte minimaliste réduit les interférences externes.

En résumé, ces variables décrivent les conditions expérimentales qui influencent naturellement les résultats.
Comme le protocole, le code et les paramètres de campagne restent constants sur les deux plateformes, les écarts observés s'interprètent comme un effet du matériel et de l'environnement d'exécution, et non comme une variation de méthode.


### Étape 2 - De la configuration à l'export CSV
**Où sommes-nous :**
GitHub repo, fichiers application/ExperimentController.py et scripts/experiment.py.

**Action écran :**
Ouvrir le repo et naviguer à travers les deux fichiers pour suivre la chaîne complète.

---

**Titre de bloc: Modèle de résultat normalisé**

**Class Name: ExperimentResult** (application/ExperimentController.py, lignes 30 à 46)

Voici la classe ExperimentResult. Son rôle, c'est de définir le format standard d'une mesure unique. En d'autres termes, c'est le conteneur qui regroupe tous les éléments importants, soit les paramètres de configuration, les métriques de performance, les indicateurs de robustesse et l'incertitude statistique. Pourquoi c'est crucial? Parce que cette classe sert à créer des objets ExperimentResult, qu'on appelle aussi des instances. Ce sont des copies concrètes créées à partir de cette classe. Chaque objet ExperimentResult représente une mesure réelle. Et qui crée ces objets? C'est ExperimentController qu'on va voir tout de suite. ExperimentController utilise cette classe pour normaliser tous les résultats. Toutes les mesures ont la même forme, ce qui garantit qu'elles sont comparables et exportables correctement.

---

**Titre de bloc: Orchestrateur de campagne**

**Class Name: ExperimentController** (application/ExperimentController.py, lignes 49 à 71)

Passons à ExperimentController. Son rôle, c'est de centraliser toute la logique de mesure au même endroit, plutôt que de la disperser dans plusieurs fichiers. En d'autres termes, c'est l'orchestrateur, le chef d'orchestre qui pilote le flux complet de mesure. La méthode __init__, qu'on voit aux lignes 63 à 71, reçoit le moteur de chiffrement configuré et les étiquettes algorithm et mode. Une fois initialisée, ExperimentController pilote l'exécution complète: elle appelle run_performance, qu'on va voir tout de suite, pour effectuer les mesures pour cette configuration spécifique, puis elle assemble les résultats dans un objet ExperimentResult. Et pourquoi c'est crucial? Parce que ExperimentController crée les instances de ExperimentResult qu'on a vu précédemment. C'est elle qui les remplit avec les données de mesure. Sans ExperimentController, on aurait pas de mesures, et donc pas d'objets ExperimentResult à exporter.

---

**Titre de bloc: Pipeline de mesure d'une configuration**

**Function Name: run_performance(...)** (application/ExperimentController.py, lignes 77 à 156)

C'est run_performance qui fait le cœur du travail. Son rôle, c'est d'exécuter une mesure complète de performance pour une configuration donnée. 

Pense à un test de vitesse automobile. On mesure le temps d'accélération de 0 à 100 km/h, mais pas juste une fois. On le fait plusieurs fois, on ignore les conditions externes, on chronomètre précisément. Et à la fin, on dit: "la voiture fait entre 7,8 et 8,2 secondes avec 95% de certitude". Eh bien, c'est exactement ce que run_performance fait, mais pour un algorithme de chiffrement.

Voici comment. À la ligne 102, la fonction génère un plaintext aléatoire de test. C'est le message qu'on va chiffrer. Aux lignes 108 à 110, elle chronomètre le chiffrement. Elle utilise `perf_counter`, qui est un outil de haute précision. Contrairement aux chronomètres ordinaires, il fournit une mesure monotone et stable, adaptée au benchmarking. Puis aux lignes 117 à 119, elle chronomètre le déchiffrement exactement de la même façon.

Ensuite vient le calcul statistique. Aux lignes 127 à 140, elle calcule l'IC à 95%. C'est l'intervalle de confiance. Elle utilise la fonction `_ci95_mbps`. 

Pourquoi c'est important? Parce que chaque répétition donne un temps légèrement différent. Parfois le CPU fait autre chose. Parfois un processus passe. Parfois le cache est plus chaud.

L'intervalle de confiance à 95% encadre cette variabilité. Il dit: "le vrai débit se situe probablement entre A et B mégaoctets par seconde". Et on peut être sûr à 95% de ça.

Comment on calcule ça? On combine trois éléments. D'abord, la variabilité observée, donc l'écart-type. Ensuite, le nombre de répétitions: plus il est élevé, plus la plage se resserre. Enfin, un coefficient statistique lié au niveau de confiance fixé à 95% et au nombre de mesures.

Pourquoi 100 répétitions, c'est un bon choix? Parce que c'est un compromis professionnel entre fiabilité statistique et temps de calcul. Avec trop peu de répétitions, le résultat est instable et sensible au bruit de la machine. Avec trop de répétitions, on gagne peu en précision, mais on paie beaucoup en temps.

La règle simple est la suivante: la précision s'améliore avec la racine carrée du nombre de répétitions. Donc, pour améliorer nettement la précision, il faut beaucoup plus d'essais. Par exemple, passer de 25 à 100 répétitions ne multiplie pas la précision par quatre, mais environ par deux.

En pratique, 100 répétitions donne des mesures stables, comparables entre plateformes, et reste raisonnable en durée d'exécution. C'est pour ça que ce choix est méthodologiquement défendable.

Et ce coefficient proche de 2, il veut dire quoi? C'est le facteur de sécurité du niveau de confiance à 95%. Plus précisément, il vaut environ 1,96 quand on a assez de mesures. Concrètement, on prend l'incertitude de base, puis on la multiplie par ce facteur pour obtenir une plage qui couvre la vraie valeur dans environ 95% des cas. Le résultat, c'est une plage de confiance claire et fiable.

Enfin, aux lignes 142 à 156, la fonction retourne un objet ExperimentResult complètement rempli avec tous ces chiffres. 

Et qui appelle run_performance? C'est le script `experiment.py`, via `main()`, qui l'appelle sur une instance de `ExperimentController` pour chaque configuration. L'important, c'est que run_performance calcule tous les indicateurs: les temps, les débits, les intervalles de confiance. Et elle retourne un ExperimentResult prêt pour le CSV.

Transition: jusqu'ici, dans `application/ExperimentController.py`, on a vu comment une mesure est calculée et structurée proprement dans un `ExperimentResult`. Maintenant, on passe à `scripts/experiment.py`, qui joue le rôle d'intermédiaire: il enchaîne toutes les configurations, récupère ces `ExperimentResult`, puis les écrit dans le fichier CSV final.

---

**Titre de bloc: Paramétrage déclaratif**

**Configuration de campagne + fonction main()** (scripts/experiment.py, lignes 51 à 127)

Ici, on n'explique pas une classe. On explique un bloc de configuration, puis la fonction `main()` qui applique cette configuration.

Le rôle de ce bloc est simple: définir précisément quoi tester, puis exécuter automatiquement toutes les combinaisons avec des boucles. Cette approche garantit que le protocole est reproductible sur toutes les plateformes.

Les repères importants sont:
- Ligne 51: `REPETITIONS = 100`.
- Lignes 53 à 70: `EXPERIMENT_MATRIX`.
- Ligne 72: `MESSAGE_SIZES`.
- Ligne 97: début de `main()`.
- Lignes 100 à 110: boucles sur algorithme/mode, taille de clé, puis taille de message.
- Ligne 116: création de `ExperimentController`.
- Lignes 124 à 127: appel de `controller.run_performance(..., repetitions=REPETITIONS)`.

Chaîne d'actions: pour chaque combinaison, `main()` crée un `ExperimentController`, lance `run_performance`, récupère un `ExperimentResult`, l'ajoute à `results`, puis le bloc CSV l'exporte. Résultat: une matrice complète de mesures, avec chaque algorithme, chaque mode et chaque taille de message, répétés 100 fois.

---

**Titre de bloc: Traçabilité des résultats CSV**

**CSV Export Logic** (scripts/experiment.py, lignes 143 à 150)

Enfin, l'export en CSV. Son rôle, c'est de convertir tous les objets ExperimentResult en lignes CSV et de les écrire dans un fichier de résultats. En d'autres termes, c'est le dernier maillon de la chaîne: les résultats sont finalisés et sauvegardés de manière structurée. Voici le processus: à la ligne 143, on extrait les noms de colonnes directement de la structure ExperimentResult avec la fonction asdict. Pourquoi faire ça? Parce que ça garantit que les colonnes du CSV correspondent exactement aux champs de la classe ExperimentResult. À la ligne 146, writer.writeheader() écrit l'en-tête du CSV avec ces noms de colonnes. Aux lignes 147 à 148, pour chaque objet ExperimentResult dans notre liste de résultats, on le convertit en dictionnaire avec asdict et on l'écrit ligne par ligne dans le fichier. À la ligne 150, le programme affiche le chemin du fichier CSV généré.

Et si on recule pour voir la chaîne d'actions complète de A à Z? D'abord, ExperimentResult définit la structure: c'est le moule qui spécifie quels champs on va mesurer. Ensuite, les constantes et boucles déclarent la campagne: quels algorithmes, quels modes, quelles tailles de message tester et combien de fois. ExperimentController orchestre les mesures: elle crée une instance pour chaque configuration. run_performance calcule les indicateurs bruts et remplit l'objet ExperimentResult. Tous les objets ExperimentResult sont stockés dans une liste. Enfin, l'export CSV converti chaque objet en dictionnaire et l'écrit ligne par ligne. Et le résultat final? Un fichier CSV qui reflète exactement la structure définie par ExperimentResult, ce qui rend les résultats traçables, vérifiables et exploitables pour les graphiques et les conclusions.

---

**Commande (optionnelle, terminal PowerShell) :**
Get-ChildItem data/results/experiment_*.csv | Sort-Object LastWriteTime -Descending | Select-Object -First 1

### Conclusion
La méthode est comparable entre plateformes, reproductible et statistiquement encadrée.
Les résultats sont exportés de manière structurée, ce qui soutient l'analyse présentée dans TN3.
