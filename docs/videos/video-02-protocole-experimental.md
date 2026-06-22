# Vidéo 2 - Protocole expérimental

## Objectif
Démontrer que la méthode de mesure est valide, comparable entre plateformes et reproductible.

Cette vidéo complète la vidéo 1.
La vidéo 1 prouve l’architecture et l’exécution de bout en bout.
Ici, on prouve la rigueur méthodologique.

## Portée
- application/ExperimentController.py
- scripts/experiment.py
- Exécution terminale (extrait court)
- Structure du CSV dans data/results

## Script

### Introduction
Dans cette vidéo, je montre pourquoi nos résultats sont scientifiquement défendables.
On ne refait pas la visite du dépôt: elle est déjà faite en vidéo 1.
Ici, on vérifie trois points: comparabilité, reproductibilité et qualité des données exportées.
(RESPIRER)

### Étape 1 - Cadrage de la preuve
**Action écran :**
Afficher la slide du protocole expérimental.

**Texte à dire :**
Dans cette première étape, on explicite le cadre méthodologique et les facteurs considérés.
L’objectif n’est pas seulement de montrer que le système fonctionne, mais de justifier la validité de la méthode.
La slide montre explicitement trois paramètres clés: 5 algorithmes, 5 paliers de taille et 100 répétitions.
(PAUSE) (SURLIGNER: **5 algorithmes**) (SURLIGNER: **5 paliers**) (SURLIGNER: **100 répétitions**)

### Étape 2 - Comparaison entre plateformes
**Action écran :**
Rester sur la slide et pointer les deux environnements.

**Texte à dire :**
Ici, on démontre une comparaison contrôlée.
On compare les deux colonnes de la slide: Ordinateur portable x86 et Raspberry Pi.
Le détail visible confirme le contexte matériel et logiciel: CPU, OS, AES-NI, RAM et contexte d’exécution.
Le code est identique; seule la plateforme change.
C’est précisément ce qui rend la comparaison crédible.
(PAUSE) (SURLIGNER: **Ordinateur Portable x86**) (SURLIGNER: **Raspberry Pi**) (SURLIGNER: **AES-NI: Oui / Non**)

### Étape 3 - Orchestration des mesures
**Action écran :**
Ouvrir application/ExperimentController.py et montrer la classe de résultat puis la méthode principale.

**Texte à dire :**
Dans cette étape, on montre où la mesure est réellement orchestrée.
La classe ExperimentController centralise le protocole expérimental.
La méthode run_performance encadre les calculs de temps et les indicateurs retournés.
Ce point est important: on isole la logique de mesure de la logique de visualisation.
(PAUSE) (SURLIGNER: **class ExperimentController**) (SURLIGNER: **def run_performance(...)**)

**Repères code précis :**
- Fichier: crypto-experiments/application/ExperimentController.py
- SURLIGNER lignes 30 à 45: class ExperimentResult
- SURLIGNER ligne 49: class ExperimentController
- SURLIGNER lignes 77 à 81: signature run_performance(...)

**Pourquoi c'est une preuve solide :**
- Tu montres la séparation claire entre modèle de résultat et orchestration.
- Tu prouves que la campagne est pilotée par une méthode unique et auditable.

### Étape 4 - Chronométrage et robustesse statistique
**Action écran :**
Montrer les zones de chronométrage dans run_performance.

**Texte à dire :**
Ici, on démontre que le chronométrage est propre.
Le minuteur entoure uniquement le chiffrement et le déchiffrement,
pas l’initialisation et pas l’export des résultats.
Ensuite, le protocole répète les mesures pour réduire le bruit,
et construit un intervalle de confiance à 95 %.
(PAUSE) (SURLIGNER: **time.perf_counter()**) (SURLIGNER: **encrypt(...)**) (SURLIGNER: **decrypt(...)**) (SURLIGNER: **ci95_encrypt_mbps**)

**Repères code précis :**
- Fichier: crypto-experiments/application/ExperimentController.py
- SURLIGNER ligne 102: plaintext = os.urandom(message_size_bytes)
- SURLIGNER lignes 108 à 110: chronométrage encrypt avec perf_counter
- SURLIGNER lignes 117 à 119: chronométrage decrypt avec perf_counter
- SURLIGNER lignes 127 à 139: fonction _ci95_mbps
- SURLIGNER ligne 154: ci95_encrypt_mbps=ci95_enc

**Pourquoi c'est une preuve solide :**
- Tu démontres que le timer encadre l'appel cryptographique, donc la mesure est propre.
- Tu justifies statistiquement le choix n=100 avec la présence explicite de l'IC 95 %.

### Étape 5 - Paramétrage déclaratif de la campagne
**Action écran :**
Ouvrir scripts/experiment.py et pointer les constantes principales.

**Texte à dire :**
Dans cette étape, on démontre la reproductibilité du protocole.
La campagne est définie de manière déclarative:
REPETITIONS, EXPERIMENT_MATRIX et MESSAGE_SIZES.
Autrement dit, pour rejouer l’expérience, on ne modifie pas l’architecture;
on relance le même script avec la même matrice.
(PAUSE) (SURLIGNER: **REPETITIONS = 100**) (SURLIGNER: **EXPERIMENT_MATRIX**) (SURLIGNER: **MESSAGE_SIZES**)

**Repères code précis :**
- Fichier: crypto-experiments/scripts/experiment.py
- SURLIGNER ligne 51: REPETITIONS = 100
- SURLIGNER lignes 53 à 69: EXPERIMENT_MATRIX
- SURLIGNER ligne 72: MESSAGE_SIZES = [64, 256, 1024, 4096, 16384]
- SURLIGNER ligne 100: boucle sur EXPERIMENT_MATRIX
- SURLIGNER ligne 110: boucle sur MESSAGE_SIZES
- SURLIGNER lignes 124 à 127: appel controller.run_performance(..., repetitions=REPETITIONS)

**Pourquoi c'est une preuve solide :**
- Tu montres que les paramètres expérimentaux sont centralisés et rejouables.
- Tu prouves que toutes les combinaisons passent par la même logique de mesure.

### Étape 6 - Preuve par les données exportées
**Action écran :**
Ouvrir un CSV dans data/results et montrer les colonnes clés.

**Texte à dire :**
Dans cette étape, on montre la base factuelle de l’analyse.
Le CSV contient l’identifiant de configuration, les temps, les débits,
les métriques d’avalanche et les intervalles de confiance.
C’est ce jeu de données qui alimente les graphiques et les conclusions TN3.
(PAUSE) (SURLIGNER: **algorithm**) (SURLIGNER: **mode**) (SURLIGNER: **message_size_bytes**) (SURLIGNER: **throughput_encrypt_mbps**) (SURLIGNER: **avalanche_score**) (SURLIGNER: **ci95_encrypt_mbps**)

**Repères code précis :**
- Fichier: crypto-experiments/scripts/experiment.py
- SURLIGNER ligne 143: fieldnames = list(asdict(results[0]).keys())
- SURLIGNER ligne 146: writer.writeheader()
- SURLIGNER lignes 147 à 148: writer.writerow(asdict(r))
- SURLIGNER ligne 150: Results saved to: {out_path}
- Ouvrir ensuite le CSV généré dans crypto-experiments/data/results/

**Pourquoi c'est une preuve solide :**
- Tu fais le lien direct entre structure du dataclass et colonnes CSV.
- Tu montres que la conclusion repose sur des données brutes exportées, pas sur une interprétation manuelle.

### Conclusion
Conclusion de la vidéo 2:
on a justifié la validité de la méthode,
on a montré sa reproductibilité,
et on a vérifié que les données exportées sont exploitables.
Dans la vidéo 3, on verrouille maintenant la justesse cryptographique avec les tests KAT.
(RESPIRER)
