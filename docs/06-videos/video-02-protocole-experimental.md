# Vidéo 2 - Protocole expérimental

## Introduction (ouverture caméra)
**Texte à lire :**
Cette vidéo porte sur le protocole expérimental — la méthode qui sous-tend toutes nos mesures de performance.

Avant d'interpréter un seul résultat, trois questions doivent avoir une réponse claire. Sur quelles plateformes les mesures ont-elles été faites, et dans quelles conditions? Les algorithmes testés sont-ils conformes aux normes cryptographiques officielles? Et comment passe-t-on de la configuration d'une campagne à un fichier de résultats exploitable?

C'est exactement ce qu'on va couvrir. D'abord le cadre expérimental et la comparaison des plateformes. Ensuite le verrou de conformité avec les tests KAT. Enfin le pipeline de mesure, de la configuration jusqu'à l'export CSV.

## Objectif
Démontrer que la méthode de mesure est valide, comparable entre plateformes et reproductible, après une validation cryptographique KAT.

## Portée
- application/ExperimentController.py
- scripts/experiment.py
- Structure du CSV dans data/results
- validation/kat_aes.py, kat_des.py, kat_3des.py, kat_modes.py, kat_gcm.py, kat_chacha20.py
- scripts/run_kat.py

## Guide d'enregistrement

### Section 1 - Cadrage du protocole et comparaison des plateformes
**Où sommes-nous :**
PowerPoint, diapositives 5, 6 et 7.

**Intro (texte à lire) :**
Dans cette section, on fixe le cadre méthodologique de l'expérience. L'objectif est de montrer que notre comparaison est valide entre plateformes, parce que le protocole est identique et les conditions d'exécution sont explicitement documentées.

**Sujet (texte à lire) :**

**Diapo 5 — Environnement de test x86 vs ARM**
Pour commencer, regardons ensemble la diapo 5, qui pose le contexte de comparaison.

On a deux plateformes réelles et très différentes. D'un côté, un laptop en architecture x86, sous Windows 11. De l'autre, un Raspberry Pi 4 en architecture ARM, sous Raspberry Pi OS, donc Linux.

Pourquoi c'est important? Parce que ces deux architectures n'ont pas les mêmes capacités matérielles. Et ça, ça affecte directement les performances qu'on mesure.

L'exemple le plus concret, c'est AES. Le laptop dispose d'une extension matérielle appelée AES-NI, qui est intégrée directement dans le processeur. Concrètement, ça veut dire que certaines opérations de chiffrement AES se font au niveau du hardware, et non par le logiciel seul. C'est beaucoup plus rapide. Le Raspberry Pi, lui, n'a pas ce niveau d'accélération. Donc, si AES est nettement plus rapide sur laptop, ce n'est pas un problème de méthode. C'est simplement un effet du matériel, et c'est exactement ce qu'on veut documenter.

En dehors de ça, d'autres variables de contexte diffèrent aussi: la mémoire disponible, le système d'exploitation, et le niveau de bruit de fond au moment de l'exécution. Ces différences sont réelles, mais elles ne biaisent pas la comparaison. Pourquoi? Parce que le protocole, le code et les paramètres de mesure sont rigoureusement identiques sur les deux plateformes. Les seuls écarts viennent du matériel et de l'environnement d'exécution. Et c'est précisément ce qu'on cherche à observer.

**Diapo 6 — Protocole de mesure**
Maintenant que le contexte des plateformes est posé, voyons comment les mesures ont été concrètement structurées.

La campagne couvre 31 combinaisons d'algorithme, de mode d'opération et de taille de clé. Pour chacune, on teste 5 tailles de message différentes. Ça donne 155 cas mesurés par plateforme, soit 310 au total entre laptop et Raspberry Pi.

Les 31 combinaisons ne sont pas arbitraires. Elles couvrent l'ensemble des configurations valides de notre matrice expérimentale: chaque algorithme testé uniquement avec les modes qui lui sont compatibles, et chaque taille de clé qui respecte les contraintes de la primitive. Autrement dit, on ne teste pas ce qui n'existe pas cryptographiquement.

Les 5 tailles de message permettent d'observer si le comportement en débit est stable ou s'il varie selon la quantité de données traitées. C'est crucial pour comparer des algorithmes qui ont des comportements très différents selon la taille du bloc.

Et les 100 répétitions par configuration? C'est le cœur de la rigueur statistique. Chaque mesure individuelle est bruitée: le CPU peut être occupé, le cache peut être froid, un processus peut passer en arrière-plan. Avec 100 répétitions, on calcule une moyenne stable et un intervalle de confiance à 95%. Ça signifie qu'on peut affirmer avec 95% de certitude où se situe le vrai débit de l'algorithme dans ces conditions.

Ces trois paramètres — les combinaisons, les tailles de message et le nombre de répétitions — sont déclarés comme constantes dans `scripts/experiment.py`. Ce sont `EXPERIMENT_MATRIX`, `MESSAGE_SIZES` et `REPETITIONS`. Le script les parcourt automatiquement pour exécuter chaque cas de façon identique sur les deux plateformes. C'est ce qui rend les résultats comparables et reproductibles.

**Diapo 7 — Matrice algo x mode x clé**
Maintenant qu'on a vu le protocole de mesure, passons à la diapo 7, qui montre exactement ce qu'on a testé, soit les cinq algorithmes de la campagne, leurs modes d'opération compatibles, et les tailles de clé associées.

Les cinq algorithmes sont AES, DES, Triple DES, Twofish et ChaCha20. Ce ne sont pas des choix aléatoires. Ils représentent un spectre large de la cryptographie symétrique moderne et historique, avec des générations différentes, des longueurs de bloc différentes, et des niveaux de sécurité très différents.

La légende de la diapo nous dit exactement comment lire cette matrice. Les cases vertes correspondent aux combinaisons testées en mode bloc standard, soit ECB, CBC et CTR. Les cases jaune marquent les cas à paradigme distinct, comme GCM qui ajoute l'authentification, ou les modes par flot comme ChaCha20. Et les cases grises indiquent les combinaisons structurellement incompatibles, c'est-à-dire celles qu'on a volontairement exclues.

Ce qui rend cette matrice rigoureuse, c'est justement que les combinaisons ne sont pas toutes permises, et ce n'est pas arbitraire. ChaCha20, par exemple, est un chiffrement par flot natif. Ça veut dire qu'il opère octet par octet, sans notion de blocs. Il n'a donc pas besoin d'un mode d'opération comme ECB ou CBC, qui existent précisément pour gérer le découpage en blocs et la façon dont les blocs s'enchaînent. Appliquer ECB à ChaCha20, ça n'a tout simplement pas de sens cryptographiquement. De même, AES en mode GCM est une catégorie à part. Contrairement aux autres modes, il ne fait pas que chiffrer les données, il les authentifie aussi en une seule passe. Autrement dit, il garantit à la fois la confidentialité et l'intégrité du message. Ce n'est pas juste un mode de chiffrement de plus, c'est une primitive avec des propriétés de sécurité supplémentaires, et ça justifie qu'il soit traité séparément dans l'analyse.

Au final, cette sélection donne 31 combinaisons valides sur les deux plateformes. Et dans le code, elles sont toutes déclarées dans la constante `EXPERIMENT_MATRIX` de `scripts/experiment.py`, sous forme de tuples algorithme, modes, tailles de clé. Le script les parcourt entièrement et de façon identique, peu importe la plateforme. C'est ce qui garantit une comparaison propre, sans biais de configuration.

En résumé, cette section établit le cadre de validité de la comparaison. Le protocole, le code et les paramètres de mesure sont constants. Les écarts observés s'interprètent donc comme un effet de la plateforme et de l'architecture, pas comme une variation de méthode.


### Section 2 - Verrou de conformité

**Intro (texte à lire) :**
Avant d'interpréter quoi que ce soit, on pose un verrou de conformité cryptographique. Ce verrou, ce sont les KAT, les Known Answer Tests. L'idée est simple mais essentielle: si un algorithme ne produit pas la bonne sortie sur des vecteurs officiels, ses mesures de débit ne valent rien. On valide d'abord, on mesure ensuite.

---

**Fichier / zone à montrer :** dossier `validation/`, puis `scripts/run_kat.py`

**Intro (texte à lire) :**
Dans le dossier `validation/` que nous voyons a lecran, on y trouve un fichier KAT par algorithme et par famille de modes. Chaque fichier contient des vecteurs extraits directement des publications officielles du NIST, soit les mêmes vecteurs qui servent de référence mondiale pour valider les implémentations cryptographiques.

Par exemple, `kat_aes.py` utilise les vecteurs de FIPS 197, la norme officielle d'AES. Et `kat_gcm.py` utilise ceux de SP 800-38D. Ce ne sont pas des vecteurs inventés. Ce sont les vecteurs officiels.

```python
# kat_aes.py — lignes 35 à 39 (vecteur FIPS 197 Annexe B, AES-128)
{
    "label": "FIPS197 App-B AES-128 encrypt",
    "key":   "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c",
    "plain": "32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34",
    "cipher":"39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32",
},
```

**Texte à lire :**
Voici un exemple concret. Ce vecteur vient directement de l'Annexe B de FIPS 197, la norme officielle d'AES publiée par le NIST. On a une clé de 128 bits, un message en clair connu, et la sortie chiffrée attendue. Notre implémentation doit produire exactement ces octets, au bit près.

C'est ce que fait la fonction `run()` à la ligne 27. Elle prend ces vecteurs, chiffre le plaintext avec la clé donnée, et compare le résultat au cipher attendu. Zéro écart, l'algorithme est conforme. Un seul écart, on arrête tout.

Ce modèle est le même pour chaque fichier KAT du dossier `validation/`. Un fichier par algorithme, des vecteurs officiels, une fonction `run()` qui retourne le nombre d'échecs. C'est simple, traçable, et directement ancré dans les normes publiées par le NIST et l'IETF.

---

**Fichier / zone à montrer :** `scripts/run_kat.py`

**Texte de transition (texte à lire) :**
Maintenant qu'on comprend comment chaque suite fonctionne, regardons comment `run_kat.py` les regroupe et les exécute toutes d'un seul coup.

**Code à montrer :**
```python
# run_kat.py — lignes 20 à 27
suites = [
    ("AES  (FIPS 197)",                kat_aes.run),
    ("DES  (SP 800-17)",               kat_des.run),
    ("3DES (SP 800-67)",               kat_3des.run),
    ("Modes ECB/CBC/CTR (SP 800-38A)", kat_modes.run),
    ("AES-GCM (SP 800-38D)",           kat_gcm.run),
    ("ChaCha20 (RFC 8439)",            kat_chacha20.run),
]
```

**Narration ligne par ligne (texte à lire) :**
À la ligne 17, `run_kat.py` importe toutes les suites KAT depuis le dossier `validation/` en une seule ligne. Ça centralise le point d'entrée.

Aux lignes 20 à 27, on construit la liste `suites`. Chaque entrée est un tuple avec le nom de la suite et sa fonction `run`. On remarque que chaque nom cite explicitement la norme de référence, FIPS 197 pour AES, SP 800-17 pour DES, RFC 8439 pour ChaCha20. Ce n'est pas décoratif. Ça documente directement dans le code quelle autorité valide chaque algorithme.

Aux lignes 30 à 38, le script itère sur chaque suite, exécute le `run()` correspondant, accumule les échecs, et affiche le résultat en temps réel.

À la ligne 49, le script termine avec `sys.exit(0)` si tout est passé, ou `sys.exit(1)` en cas d'échec. Ce code de sortie binaire est important, parce qu'il permet à un pipeline d'intégration continue de bloquer automatiquement si la conformité n'est pas atteinte.

Pour voir le tout en action, on ouvre le terminal et on lance la commande suivante.

**Commande à montrer (terminal) :**
```
cd crypto-experiments
python scripts/run_kat.py
```

**Texte à lire après la commande :**
On voit défiler les résultats suite par suite. Chacune affiche ses vecteurs, et à la fin, le script indique si tout est passé ou non.

**Conclusion (texte à lire) :**
Tous les KAT passent. Ça veut dire que chaque algorithme produit exactement la sortie attendue par les normes officielles. La conformité cryptographique est validée. On peut maintenant interpréter les mesures de performance avec confiance, parce qu'on sait qu'on mesure des implémentations correctes.

### Section 3 - De la configuration à l'export CSV

**Visuel à montrer :** Diapositive "Pipeline de mesure" (diapo 03d)

**Texte à lire :**
Maintenant qu'on sait que chaque algorithme est conforme, on peut s'intéresser à ce qui se passe concrètement quand on lance une campagne de mesure. Ce pipeline, on va le parcourir bloc par bloc, de gauche à droite.

À gauche, on a `experiment.py`. C'est lui qui lance tout. Il déclare trois constantes. D'abord `EXPERIMENT_MATRIX`, qui liste toutes les combinaisons à tester — algorithme, mode, taille de clé. Ensuite `MESSAGE_SIZES`, qui couvre cinq tailles de message. Et enfin `REPETITIONS`, fixé à cent. Ces trois constantes définissent l'ensemble de la campagne, sur les deux plateformes, sans rien changer entre elles.

La flèche "instancie" nous amène au bloc MESURE. Pour chaque combinaison, `experiment.py` crée une instance de `ExperimentController` et appelle sa méthode `run_performance`. C'est là que la mesure se fait. Elle chronomètre le chiffrement et le déchiffrement avec `perf_counter`, répète cent fois, et calcule un intervalle de confiance à 95%. Propre, stable, statistiquement encadrée.

La flèche "écrit" ferme le pipeline. Une fois toutes les mesures complétées, `experiment.py` écrit les résultats dans un fichier CSV horodaté, dans `data/results`. La structure est générée automatiquement depuis les champs de la dataclass — rien de manuel. Une campagne complète produit 310 lignes, une par configuration, sur chaque plateforme.

**Note de régie :** pointer CONFIGURE → flèche "instancie" → MESURE → flèche "écrit" → EXPORTE.

**Texte à lire — fermeture :**
Voilà. Dans cette vidéo, on a établi le cadre de comparaison, validé la conformité de chaque algorithme avec les KAT, et suivi le pipeline complet jusqu'à l'export. Trois couches de rigueur — méthodologique, cryptographique, et statistique — qui fondent la crédibilité de tout ce qu'on va présenter dans les prochaines vidéos.

Merci d'avoir suivi cette deuxième vidéo. On se retrouve dans la prochaine.
