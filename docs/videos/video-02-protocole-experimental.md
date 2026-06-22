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


### Étape 2 - Orchestration des mesures
**Où sommes-nous :**
GitHub repo, puis fichier application/ExperimentController.py.

**Action écran :**
Ouvrir le repo, entrer dans application/ExperimentController.py et suivre les blocs ci-dessous.

**Repères code précis :**
Fichier: crypto-experiments/application/ExperimentController.py

**Titre de bloc: Modèle de résultat normalisé**

**Class Name: ExperimentResult**
- (Lignes 30 à 46) Rôle: définir le format standard d'une mesure unique.
- Processus: cette classe regroupe les paramètres de configuration, les métriques de performance, les indicateurs de robustesse et l'incertitude statistique.
- Pourquoi c'est important: toutes les mesures ont la même forme, donc elles sont comparables et exportables proprement.

**Titre de bloc: Orchestrateur de campagne**

**Class Name: ExperimentController**
- (Ligne 49) Rôle: centraliser la logique de mesure au même endroit.
- (Lignes 64 à 74, __init__) Rôle: recevoir le moteur de chiffrement configuré et les étiquettes algorithm/mode.
- Processus: cette classe pilote le flux complet de mesure, plutôt que de disperser la logique dans plusieurs fichiers.

**Titre de bloc: Pipeline de mesure d'une configuration**

**Function Name: run_performance(...)**
- (Lignes 77 à 81) Rôle: point d'entrée principal pour exécuter une mesure complète.
- (Ligne 102) Génère un plaintext de test.
- (Lignes 108 à 110) Chronomètre le chiffrement.
- (Lignes 117 à 119) Chronomètre le déchiffrement.
- (Lignes 127 à 139) Calcule l'IC 95 % pour encadrer la variabilité.

**Titre de bloc: Chaîne d'actions jusqu'au CSV**

**Def/Return: return ExperimentResult(...)**
- (Lignes 142 à 154) Rôle: construire l'objet résultat final de la mesure.
- Chaîne de traitement:
	1. `run_performance` calcule les indicateurs.
	2. `ExperimentController` crée un objet `ExperimentResult`.
	3. Le script appelant convertit cet objet en dictionnaire.
	4. Les dictionnaires sont écrits ligne par ligne dans le CSV.
- Résultat: le CSV reflète exactement la structure définie par `ExperimentResult`.

**Commande :**
Aucune.

### Étape 3 - Chronométrage et IC 95 %
**Où sommes-nous :**
VS Code, même fichier application/ExperimentController.py.

**Action écran :**
Montrer les blocs de chronométrage puis la fonction de calcul d'intervalle de confiance.

**Repères code précis :**
- Fichier: crypto-experiments/application/ExperimentController.py
- SURLIGNER ligne 102: plaintext = os.urandom(message_size_bytes)
- SURLIGNER lignes 108 à 110: chronométrage du chiffrement avec perf_counter
- SURLIGNER lignes 117 à 119: chronométrage du déchiffrement avec perf_counter
- SURLIGNER lignes 127 à 139: fonction _ci95_mbps
- SURLIGNER ligne 154: ci95_encrypt_mbps=ci95_enc

**Texte à dire :**
Le chronométrage entoure uniquement l'appel cryptographique, ce qui limite les biais de mesure.
Le protocole calcule ensuite un IC à 95 %, afin d'encadrer la variabilité observée sur les répétitions.

**Commande :**
Aucune.

### Étape 4 - Paramétrage déclaratif
**Où sommes-nous :**
VS Code, fichier scripts/experiment.py.

**Action écran :**
Montrer les constantes globales puis les boucles d'itération.

**Repères code précis :**
- Fichier: crypto-experiments/scripts/experiment.py
- SURLIGNER ligne 51: REPETITIONS = 100
- SURLIGNER lignes 53 à 69: EXPERIMENT_MATRIX
- SURLIGNER ligne 72: MESSAGE_SIZES = [64, 256, 1024, 4096, 16384]
- SURLIGNER ligne 100: boucle sur EXPERIMENT_MATRIX
- SURLIGNER ligne 110: boucle sur MESSAGE_SIZES
- SURLIGNER lignes 124 à 127: appel controller.run_performance(..., repetitions=REPETITIONS)

**Texte à dire :**
La campagne est définie de manière déclarative via les constantes et la matrice.
Cette organisation permet de rejouer exactement le même protocole sur une autre plateforme.

**Commande :**
Aucune.

### Étape 5 - Traçabilité des résultats CSV
**Où sommes-nous :**
VS Code, fichier scripts/experiment.py puis dossier data/results.

**Action écran :**
Montrer l'écriture du CSV, puis ouvrir un fichier CSV généré.

**Repères code précis :**
- Fichier: crypto-experiments/scripts/experiment.py
- SURLIGNER ligne 143: fieldnames = list(asdict(results[0]).keys())
- SURLIGNER ligne 146: writer.writeheader()
- SURLIGNER lignes 147 à 148: writer.writerow(asdict(r))
- SURLIGNER ligne 150: Results saved to: {out_path}
- Ouvrir ensuite un fichier dans crypto-experiments/data/results/

**Texte à dire :**
Les colonnes du CSV proviennent directement de la structure de résultat.
La sortie est donc traçable et exploitable pour les graphiques et les conclusions.

**Commande (optionnelle, terminal PowerShell) :**
Get-ChildItem data/results/experiment_*.csv | Sort-Object LastWriteTime -Descending | Select-Object -First 1

### Conclusion
La méthode est comparable entre plateformes, reproductible et statistiquement encadrée.
Les résultats sont exportés de manière structurée, ce qui soutient l'analyse présentée dans TN3.
