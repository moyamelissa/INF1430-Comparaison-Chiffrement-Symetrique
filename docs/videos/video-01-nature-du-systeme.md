# Vidéo 1 - Nature du système

## Objectif
Présenter l'organisation du dépôt, l'architecture en couches, puis lancer une expérience en direct pour montrer la sortie concrète du système.

## Portée
- Racine du dépôt, docs, Resources
- crypto-experiments et ses couches
- domain/cipher, domain/mode, domain/engine
- application/ExperimentController.py
- scripts/experiment.py
- Exécution live et lecture du CSV généré

## Script

### Introduction
Dans cette vidéo, je présente l'organisation du dépôt du projet de comparaison des algorithmes de chiffrement symétrique.
On va d'abord voir comment le code est structuré, ou se trouvent les primitives, les modes, l'orchestration et les scripts,
puis on termine en lançant une expérience en direct pour montrer concrètement ce que le système produit.

### Racine du dépôt
On voit ici la racine du dépôt avec trois dossiers et le README.
Le dossier docs regroupe les livrables académiques, les guides et les feedbacks reçus durant le projet.
Le dossier Resources contient les références bibliographiques et les documents de support.
Ces deux dossiers sont là pour documenter et encadrer le projet,
mais l'essentiel du système se trouve dans crypto-experiments, et c'est exactement ce qu'on va explorer maintenant.

### Dossier crypto-experiments
Une fois dans crypto-experiments, on voit l'architecture en couches prendre forme concrètement.
On a le dossier domain qui contient la logique cryptographique,
application qui gère l'orchestration,
scripts qui sont les points d'entrée,
validation et tests qui assurent la conformité des implementations,
et data qui stocke les résultats.
On va commencer par explorer le dossier domain, qui est le cœur du système.

### Dossier domain
Dans le dossier domain, on retrouve trois sous-dossiers qui forment le cœur logique du système.
Le dossier cipher contient les primitives de chiffrement,
engine contient le moteur qui les assemble,
et mode contient les modes d'opération.
On commence par cipher.

## DOSSIER CIPHER

### Dossier domain/cipher
Dans domain/cipher, on retrouve les cinq primitives de chiffrement implémentées dans le projet,
soit AES, ChaCha20, DES, TripleDES et Twofish.
On remarque aussi CipherPrimitive.py, qui est la classe abstraite dont toutes les autres héritent.
C'est ce qui garantit une interface uniforme à travers tout le système.

### Fichier CipherPrimitive.py

#### Segment 1 - Lignes 1 à 8, docstring du fichier
On voit ici le docstring qui décrit la responsabilité de cette classe.
La ligne clé est celle-ci: les primitives ne savent rien du chaînage, des vecteurs d'initialisation ou des nonces.
C'est la séparation des responsabilités en une phrase.

#### Segment 2 - Ligne 11 import ABC/abstractmethod, ligne 14 class CipherPrimitive(ABC)
On importe ABC et abstractmethod du module abc de Python.
Ces deux éléments ensemble forment un contrat garanti par le langage.
Chaque algorithme qui hérite de CipherPrimitive est obligé d'implémenter les memes méthodes,
ce qui permet au reste du système de travailler avec n'importe quelle primitive sans jamais savoir laquelle c'est concrètement.
C'est ce qui rend le système extensible et neutre.

#### Segment 3 - Lignes 17 à 25, block_size et key_size
block_size et key_size sont des propriétés abstraites,
ce qui force chaque algorithme a déclarer ses propres valeurs.
Par exemple, AES travaille sur des blocs de 16 octets avec des clés de 128, 192 ou 256 bits,
tandis que DES travaille sur des blocs de 8 octets avec une clé de 56 bits effectifs.
Sans ces deux propriétés exposees de façon uniforme,
le moteur de chiffrement ne pourrait pas savoir comment decouper les donnees ni valider les clés,
peu importe quel algorithme est utilise en dessous.

#### Segment 4 - Lignes 28 à 57, encrypt_block et decrypt_block
encrypt_block et decrypt_block sont les deux méthodes abstraites centrales de cette classe.
Chacune reçoit exactement un bloc d'octets et retourne exactement un bloc d'octets.
Ce qui est important, c'est ce qu'elles ne font pas:
elles ne gerent pas le chaînage, les vecteurs d'initialisation ou les nonces.
Ce n'est pas un oubli, c'est un choix délibéré.
En isolant la primitive à une seule responsabilité,
on peut brancher n'importe quel mode d'opération par-dessus sans jamais modifiér le code de l'algorithme.
C'est la couche mode qui prend en charge tout le reste.

#### Segment 5 - Lignes 59 à 75, encrypt_blocks et boucle par défaut
encrypt_blocks est une méthode concrète, pas abstraite.
Par défaut, elle traite les donnees en appelant encrypt_block bloc par bloc dans une boucle.
C'est fonctionnel mais pas optimal, parce qu'on paie le surcoût de la boucle Python à chaque bloc.
C'est pourquoi le docstring invite explicitement les sous-classes a surcharger cette méthode
avec un appel groupe directement a leur bibliothèque sous-jacente.
On va voir ça tout de suite dans AES.py, ou cette optimisation est concrètement implémenté.

### Fichier AES.py

#### Segment 1 - Lignes 1 à 10, docstring du fichier
On voit ici une implémentation concrète de l'algorithme AES selon la norme FIPS 197.
Le docstring precise les tailles de clé supportees, 128, 192 ou 256 bits,
et confirme qu'on utilise PyCryptodome en mode ECB brut pour traiter un seul bloc à la fois.
La logique de chaînage reste entièrement à l'extérieur, dans la couche mode.

#### Segment 2 - Ligne 19, class AES(CipherPrimitive)
Ici, AES hérite directement de CipherPrimitive.
Cet héritage n'est pas seulement structurel, il impose un contrat,
parce que CipherPrimitive est une classe abstraite avec des méthodes decorees par abstractmethod.
Python refuse d'instancier AES tant que les quatre méthodes obligatoires,
block_size, key_size, encrypt_block et decrypt_block,
ne sont pas toutes implémentées.
C'est ce qui garantit la substituabilité:
n'importe quelle primitive peut remplacer une autre dans le système
sans casser le contrat defini par la classe de base.

#### Segment 3 - Lignes 16 à 44, _VALID_KEY_SIZES, __init__ et validation de la clé
Avant la classe, on définit _VALID_KEY_SIZES,
un ensemble qui contient les tailles de clé acceptees pour AES, soit 16, 24 ou 32 octets.
Le constructeur consulte cette constante immédiatement pour valider la clé recue.
Si la longueur ne correspond a aucune des tailles supportees,
on leve une exception ValueError tout de suite, à la création de l'objet,
plutôt que de laisser une clé invalide se propager silencieusement jusqu'au moment du chiffrement.

#### Segment 4 - Lignes 47 à 52, block_size et key_size
Ici, on voit les deux propriétés abstraites de CipherPrimitive enfin implémentées avec des valeurs concrètes.
block_size retourne toujours 16 octets, la valeur fixe definie par la norme AES.
key_size retourne la longueur reelle de la clé fournie à la construction,
ce qui permet de distinguer une instance AES-128 d'une instance AES-256
sans avoir besoin d'une propriété separee pour chaque variante.
C'est exactement ces deux valeurs que le moteur de chiffrement consulte
pour savoir comment decouper les donnees,
sans jamais avoir besoin de savoir que c'est spécifiquement AES en dessous.

#### Segment 5 - Lignes 54 à 69, encrypt_block et decrypt_block
Ces deux méthodes respectent exactement le contrat defini dans CipherPrimitive:
un bloc en entrée, un bloc en sortie.
A l'intérieur, on valide d'abord que le bloc fait exactement 16 octets,
puis on cree un objet cipher avec PyCryptodome en mode ECB
et on lui delegue le chiffrement ou le dechiffrement.
Le fichier ne contient aucune logique de rondes,
de substitution ou de permutation propre a AES.
Tout ce calcul cryptographique est encapsule dans PyCryptodome,
une bibliothèque reconnue et auditee,
plutôt que reimplémenté à la main.

#### Segment 6 - Lignes 70 à 77, encrypt_blocks et decrypt_blocks
Et voici exactement l'optimisation qu'on annoncait dans CipherPrimitive.
La méthode par défaut de la classe abstraite boucle bloc par bloc,
ce qui coute cher en surcharge Python à chaque iteration.
Ici, AES surcharge complètement cette méthode avec un seul appel a PyCryptodome
qui traite toutes les donnees d'un coup.
C'est en grande partie ce gain qui explique pourquoi AES affiche un debit nettement plus eleve
que les autres algorithmes dans nos résultats.

## DOSSIER MODE

Dans domain/mode, on retrouve les modes d'opération du système.
OperationMode.py est là classe abstraite de base,
suivie de quatre modes par blocs, ECB, CBC, CTR et GCM,
et de StreamMode, qui agit comme une couche de transparence pour les chiffrements par flux comme ChaCha20.
On commence par OperationMode.py pour voir le contrat commun,
exactement comme on l'a fait avec CipherPrimitive.

### Fichier mode/OperationMode.py

#### Segment 1 - Lignes 1 à 9, docstring du fichier
Le docstring etablit le meme principe que dans CipherPrimitive, mais inverse.
CipherPrimitive disait que les primitives ne savent rien des modes.
Ici, c'est l'inverse: la couche mode ne sait rien de quel algorithme elle encapsule.
Elle appelle uniquement encrypt_block et decrypt_block,
peu importe si c'est AES, DES ou Twofish en dessous.
Cette double ignorance entre les deux couches garantit
qu'on peut combiner n'importe quel algorithme avec n'importe quel mode
sans écrire de code spécifique pour chaque combinaison.

#### Segment 2 - Ligne 16, class OperationMode(ABC)
OperationMode hérite de ABC, qui vient du module abc de Python,
et qui empeche la classe d'etre instanciee directement.
C'est le meme mecanisme exact qu'on a vu dans CipherPrimitive.
Les deux classes utilisent ABC et abstractmethod pour forcer leurs sous-classes
a implémenter certaines méthodes.
CipherPrimitive le faisait pour encrypt_block et decrypt_block,
et OperationMode le fait maintenant pour encrypt et decrypt.
Ça force chaque mode concret, ECB, CBC, CTR, GCM ou StreamMode,
à implémenter ces méthodes abstraites,
sinon Python refuse de l'instancier.
C'est ce qui montre que le meme patron de conception est applique
de façon cohérente à travers toute l'architecture du système.

#### Segment 3 - Lignes 19 à 30, __init__ et propriété primitive
Voici la différence structurelle la plus importante avec CipherPrimitive.
Le constructeur reçoit une instance de CipherPrimitive en parametre
et la stocke dans self._primitive.
Ce n'est pas de l'héritage, c'est une relation objet par référence:
un mode ne devient jamais un AES,
il reçoit un AES deja construit et travaille avec lui à travers l'interface commune.
La propriété primitive expose ensuite cet objet en lecture seule.
Dans l'implementation actuelle,
les sous-classes comme ECB ou CBC utilisent directement self._primitive
pour appeler encrypt_block et decrypt_block,
ce qui reste cohérent avec ce contrat.

#### Segment 4 - Lignes 33 à 68, encrypt et decrypt
Ces deux méthodes abstraites definissent le contrat que chaque mode concret doit respecter.
La différence majeure avec encrypt_block dans CipherPrimitive,
c'est que plaintext et ciphertext ici sont de longueur arbitraire,
pas limites à un seul bloc.
C'est la responsabilité du mode de decouper les donnees en blocs,
gerer le rembourrage si necessaire,
et appliquer sa strategie de chaînage spécifique.
On voit aussi le parametre kwargs dans la signature,
qui permet à chaque mode d'accepter des parametres qui lui sont propres,
comme un vecteur d'initialisation pour CBC,
ou un nonce pour CTR ou GCM,
sans forcer tous les modes a exposer les memes parametres inutiles.

### Fichier mode/ECB.py
Maintenant qu'on a vu le contrat abstrait dans OperationMode,
on va l'illustrer concrètement avec ECB.py.
On choisit ce mode en premier parce que c'est le plus simple a comprendre:
chaque bloc est chiffre independamment sans aucun parametre additionnel.
C'est aussi le mode qui va nous servir plus tard dans le projet
pour démontrer une vulnérabilité cryptographique reelle,
donc c'est pertinent de bien comprendre et expliquer son fonctionnement des maintenant.

#### Segment 1 - Lignes 1 à 10, docstring du fichier
Le docstring commence par un avertissement explicite.
ECB est cryptographiquement faible parce que des blocs de texte clair identiques
produisent des blocs chiffres identiques,
ce qui revele des motifs dans les donnees.
Il est inclus dans le projet uniquement a des fins de comparaison académique.
On voit aussi que le rembourrage PKCS7 est applique pour accepter des messages de n'importe quelle longueur.
C'est essentiel parce qu'un chiffrement par blocs comme AES ne peut traiter
que des blocs de taille fixe,
alors que les messages reels font rarement une longueur multiple de cette taille.

#### Segment 2 - Lignes 17 à 25, _pkcs7_pad et _pkcs7_unpad
Ces deux fonctions implémentent le rembourrage PKCS7.
Le principe est simple:
on calcule combien d'octets manquent pour compléter le dernier bloc,
et on ajoute exactement cette valeur répétée comme octets de remplissage.
Au dechiffrement, _pkcs7_unpad lit le dernier octet
pour savoir combien d'octets retirer.
C'est une implementation minimale,
elle ne valide pas que le rembourrage est cohérent avant de le retirer,
ce qui suffit pour notre contexte de benchmarking
mais ne serait pas suffisant dans un système de production expose a des attaques.

#### Segment 3 - Lignes 27 à 35, class ECB(OperationMode) et constructeur
ECB hérite directement d'OperationMode,
exactement le meme mecanisme qu'on a vu entre AES et CipherPrimitive.
Le constructeur ne fait qu'appeler super().__init__(primitive).
Il n'ajoute aucun etat supplementaire,
parce qu'ECB n'a besoin d'aucun parametre additionnel
comme un vecteur d'initialisation ou un nonce.
C'est le mode le plus simple:
chaque bloc est chiffre independamment.

#### Segment 4 - Lignes 37 à 54, encrypt
Voici l'implémentation concrète du contrat défini dans OperationMode.
On recupere le block_size de la primitive associee,
on applique le rembourrage PKCS7,
puis ECB delegue le traitement bloc par bloc à la primitive via encrypt_blocks.
Selon la primitive utilisee,
cette méthode peut etre l'implementation par défaut avec une boucle
ou une version optimisée comme celle qu'on a vue dans AES.py.
Aucun IV n'est necessaire ici,
ce qui est precisement la faiblesse du mode:
chaque bloc identique en clair produit toujours le meme bloc chiffre.

#### Segment 5 - Lignes 55 à 70, decrypt
Le déchiffrement valide d'abord que la longueur du texte chiffre
est un multiple du block_size, sinon une exception est levée.
Ensuite on delegue a decrypt_blocks de la primitive
et on retire le rembourrage avec _pkcs7_unpad.
Cette implementation va etre directement réutilisée plus tard dans le projet
pour démontrer visuellement la vulnérabilité d'ECB sur une image structuree,
comparee au mode CBC qui dissimule les motifs.

## DOSSIER ENGINE

### Fichier domain/engine/EncryptionEngine.py
Maintenant qu'on a vu les primitives et les modes separement,
on regarde comment ils se rejoignent.
EncryptionEngine.py compose une primitive, par exemple AES,
et un mode, par exemple CBC,
pour former un service de chiffrement complet.

#### Segment 1 - Lignes 1 à 9, docstring du fichier
EncryptionEngine est l'objet central du domaine.
La couche application, à travers ExperimentController,
interagit directement avec lui pour executer chaque chiffrement.
C'est un choix de conception délibéré:
il ne sait rien du chronometrage,
des fichiers CSV ou de la configuration des expériences.
Ces responsabilités appartiennent strictement aux couches supérieures.

#### Segment 2 - Lignes 29 à 38, constructeur
Le constructeur reçoit une primitive et un mode deja construits,
et applique une validation critique.
Il vérifie que mode.primitive est exactement le meme objet
que la primitive passee separement,
sinon il leve une exception.
C'est cette vérification qui garantit la cohérence entre le mode et la primitive.
On ne peut pas accidentellement assembler un mode configure avec une primitive
et le combiner avec une primitive différente dans le moteur.

#### Segment 3 - Lignes 44 à 49, propriétés primitive et mode
Les propriétés primitive et mode exposent en lecture seule
la primitive et le mode internes de l'objet,
exactement le meme patron qu'avec primitive dans OperationMode.
Ça permet d'inspecter la configuration d'un moteur déjà construit,
par exemple pour savoir quel algorithme et quel mode sont actifs,
sans jamais pouvoir la modifier après sa création.

#### Segment 4 - Lignes 51 à 67, encrypt et decrypt
Les méthodes encrypt et decrypt se contentent de deleguer directement au mode configure,
en transmettant tous les arguments nommés reçus comme le IV ou le nonce.
EncryptionEngine n'implémente aucune logique cryptographique lui-meme.
Il agit comme une facade,
un point d'entrée unifie vers la combinaison primitive et mode.
C'est exactement cette interface uniforme qu'utilise ExperimentController
pour executer chaque configuration experimentale,
sans jamais avoir besoin de savoir quel algorithme ou quel mode est actif en dessous.

## DOSSIER APPLICATION

### Fichier application/ExperimentController.py
ExperimentController.py est la classe qui orchestre toute la campagne de mesures.
C'est elle qui configure les parametres d'une expérience,
declenche le chronometrage des opérations de chiffrement et de dechiffrement,
calcule l'effet d'avalanche,
et retourne un résultat structuré.
Cette classe ne sait pas quel algorithme ou quel mode est actif en dessous:
elle travaille uniquement à travers l'interface d'EncryptionEngine.
La persistance vers un fichier CSV n'est pas non plus sa responsabilité:
ca appartient au script appelant, experiment.py.

#### Segment 1 - Lignes 29 à 46, dataclass ExperimentResult
ExperimentResult est une dataclass Python qui sert de conteneur pour une mesure complète.
Une dataclass génère automatiquement le constructeur et la representation de l'objet
a partir des attributs déclarées,
ce qui evite d'écrire du code repetitif.
On voit ici toutes les metriques collectees pour chaque configuration testee:
algorithme, mode, taille de clé, taille du message, nombre de répétitions,
temps moyens de chiffrement et de dechiffrement,
debit dans les deux sens,
score d'avalanche du texte,
score d'avalanche de la clé,
et intervalles de confiance a 95% pour le debit.
C'est cette richesse de metriques qui permet une analyse statistique rigoureuse,
plutôt qu'une simple comparaison de chiffres bruts.

#### Segment 2 - Ligne 63, constructeur d'ExperimentController
Le constructeur est volontairement simple.
Il reçoit un moteur de chiffrement deja entièrement configure,
donc une primitive et un mode deja assemblés,
plus deux étiquettes lisibles pour le nom de l'algorithme et du mode.
Ces étiquettes servent uniquement a identifier les lignes de résultats.
Elles n'influencent jamais le comportement du chiffrement lui-meme.

#### Segment 3 - Lignes 108 à 110, chronométrage du chiffrement dans run_performance
Voici le cœur du protocole de mesure.
On généré d'abord un texte en clair aleatoire fixe,
qui sera réutilisé pour toutes les répétitions afin de garantir la comparabilite entre les essais.
Ensuite, on boucle sur le nombre de répétitions,
et à chaque iteration on demarre le chronometre juste avant l'appel a encrypt,
puis on l'arrete immédiatement apres.
C'est precisement ce qu'on appelle un chronometrage neutre:
time.perf_counter encapsule uniquement l'appel cryptographique,
pas l'allocation memoire ni d'autres surcoûts du système.
C'est ce qui garantit que la mesure reflete la performance reelle de l'algorithme
et non des artefacts de l'environnement Python.

#### Segment 4 - Lignes 117 à 119, chronométrage du déchiffrement
Le meme principe est applique au dechiffrement,
mais on utilise systematiquement le dernier texte chiffre généré durant la phase de chiffrement,
plutôt que d'en générer un nouveau à chaque répétition.
Ça garantit que chaque itération de déchiffrement opère sur des données
représentatives de ce que produirait l'algorithme.

#### Segment 5 - Ligne 127, calcul de l'intervalle de confiance a 95%
Le calcul de l'intervalle de confiance a 95% est l'élément le plus rigoureux de ce fichier.
La fonction interne _ci95_mbps calcule la variance des temps mesures,
puis convertit cet ecart-type temporel en ecart-type de debit,
parce que le debit n'est pas une fonction lineaire du temps.
On applique ensuite la formule standard de l'intervalle de confiance,
ou la valeur critique vaut 1.96 pour un echantillon d'au moins 30 répétitions,
ou 2.045 pour un echantillon plus petit,
en utilisant une approximation de Student.
Ce calcul permet de quantifier la marge d'incertitude statistique autour de chaque mesure de debit.

#### Segment 6 - Lignes 142 à 159, assemblage du résultat final
Toutes les valeurs calculees sont assemblées dans un objet ExperimentResult.
On voit que avalanche_score et key_avalanche_score sont calcules
en appelant directement les deux méthodes dédiées,
measure_avalanche et measure_key_avalanche.
Le debit est calcule en divisant la taille du message convertie en megaoctets
par le temps moyen,
avec une protection contre la division par zero
si jamais le temps mesure etait nul.

#### Segment 7 - Lignes 162 à 212, measure_avalanche
Cette méthode mesure l'effet d'avalanche de la primitive,
independamment du mode utilise.
Le principe:
on génère un bloc aléatoire,
on le chiffre pour obtenir un texte chiffre de référence,
puis on inverse exactement un seul bit dans le bloc original.
On chiffre ce bloc modifié,
et on compare les deux textes chiffres bit par bit avec la distance de Hamming.
Le calcul est fait avec le XOR puis un comptage des bits différents.
On répète cette expérience 200 fois et on moyenne le résultat.
Un score ideal est 0.5,
ce qui signifie qu'en moyenne la moitie des bits de sortie changent
quand on modifie un seul bit en entrée.

#### Segment 8 - Lignes 213 à 270, measure_key_avalanche
measure_key_avalanche applique le meme principe statistique,
mais en inversant un bit de la clé plutôt que du texte en clair,
tout en gardant le meme bloc a chiffrer.
Cette méthode repond directement au retour du professeur sur le TN1.
Un detail technique important:
certaines clés modifiées peuvent etre degénérées,
par exemple en 3DES ou K1 peut devenir egal a K2 apres inversion d'un bit.
Le code intercepte alors l'exception
et assigne une valeur ideale de 0.5
plutôt que de faire planter toute la campagne de mesure.

## DOSSIER SCRIPTS

### Survol de scripts/
---
Dans scripts, on trouve les points d'entrée du système.
experiment.py lance les benchmarks de performance.
run_kat.py valide la conformité cryptographique des implementations.
generate_charts.py produit les figures à partir des résultats.
analyse_rounds_avalanche.py mesure la robustesse cryptographique.
ecb_visual_vulnerability.py demontre la vulnérabilité du mode ECB.
compare_platforms.py confronte les résultats entre le laptop et le Raspberry Pi.
On revient en detail sur chacun de ces scripts dans les prochaines vidéos.
Pour l'instant, on se concentre sur experiment.py.

### Fichier scripts/experiment.py

#### Segment 1 - Lignes 1 à 17, docstring
Le docstring resume exactement ce que fait ce fichier.
Il itere sur toutes les combinaisons definies dans EXPERIMENT_MATRIX,
execute les mesures via ExperimentController,
et écrit les résultats dans un CSV horodaté.
La dernière phrase est importante:
aucune logique cryptographique ne se trouve ici.
Ce fichier ne fait que cabler les couches domaine et application
et gerer les entrées-sorties.

#### Segment 2 - Lignes 51 à 70, REPETITIONS et EXPERIMENT_MATRIX
Voici la matrice experimentale complète,
déclarée comme une simple liste de tuples.
Chaque ligne associe un algorithme, sa classe primitive,
un mode, sa classe,
et les tailles de clé valides pour cette combinaison.
On voit par exemple qu'AES est teste avec GCM en plus d'ECB, CBC et CTR,
parce que GCM n'a de sens qu'avec AES dans notre etude.
ChaCha20 utilise StreamMode avec une seule taille de clé de 32 octets,
puisque c'est la seule taille supportee.
Cette structure déclarative permet d'ajouter un nouvel algorithme
ou une nouvelle combinaison sans toucher au reste du système.

#### Segment 3 - Ligne 72, MESSAGE_SIZES
Les tailles de message testees vont de 64 octets jusqu'a 16384 octets,
ce qui couvre à la fois les petits messages ou les couts fixes dominent,
et les gros volumes ou le debit reel de l'algorithme se revele.

#### Segment 4 - Lignes 102 à 107, vérification préalable de la clé
Avant de lancer les mesures,
le code essaie d'instancier la primitive avec une clé de test.
Si ça echoue, par exemple une taille de clé invalide pour cet algorithme,
le code passe directement à la combinaison algorithme-mode suivante,
en sautant les tailles de message pour cette taille de clé spécifique,
plutôt que de faire planter toute la campagne de benchmarking.

#### Segment 5 - Lignes 110 à 135, boucle principale d'exécution
C'est ici que tout s'assemble.
Pour chaque taille de message,
on génère une nouvelle clé,
on construit la primitive, le mode,
puis le moteur de chiffrement,
et on les passe a ExperimentController.
On appelle ensuite run_performance avec la taille de message
et le nombre de répétitions fixe a 100 via REPETITIONS.
Chaque résultat est accumule dans une liste,
et la progression s'affiche en direct dans le terminal
avec le temps de chiffrement, le debit et le score d'avalanche.

#### Segment 6 - Lignes 143 à 149, écriture du CSV
Une fois toutes les configurations testees,
les résultats sont écrits dans un fichier CSV horodaté.
asdict transforme chaque objet ExperimentResult en dictionnaire,
et csv.DictWriter écrit une ligne par résultat
avec les memes noms de colonnes que les attributs de la dataclass.
C'est ce fichier qu'on va ouvrir juste apres l'exécution.

### Basculer vers VS Code et ouvrir le terminal integre
---
On passe maintenant dans Visual Studio Code pour executer une expérience en direct.

### Taper et executer python scripts/experiment.py
---
Je lance la commande python scripts/experiment.py.
Je suis positionne dans le dossier crypto-experiments,
donc la commande fonctionne directement.

### Laisser défiler le terminal — version accélérée
---
Le système parcourt l'ensemble de la matrice expérimentale,
chaque combinaison d'algorithme, de mode, de taille de clé et de taille de message,
et répète chaque mesure cent fois.
L'exécution complète prend plusieurs minutes, donc la suite est accélérée.
On voit chaque ligne s'afficher en direct dans le terminal,
avec le temps de chiffrement moyen, le débit obtenu
et le score d'avalanche calculé pour chaque configuration.

> **Note de tournage** : garder les 10 à 15 premières secondes en temps réel,
> idéalement sur une configuration AES rapide pour que ça bouge bien à l'écran,
> puis accélérer à 4× jusqu'à la fin.
> Éviter de couper pile sur les runs 3DES — c'est la portion la plus lente
> et ça pourrait paraître étrange en accéléré si la progression semble figée
> plus longtemps que les autres.

### Ouvrir le CSV généré
---
A la fin de l'exécution,
le terminal confirme l'emplacement du fichier généré.
Un CSV horodaté est cree dans data/results,
avec une ligne par configuration mesuree
et toutes les metriques collectees:
temps de chiffrement et de dechiffrement,
debit,
scores d'avalanche
et intervalles de confiance.
C'est ce fichier brut qui servira de base
a l'analyse comparative des prochaines vidéos.


