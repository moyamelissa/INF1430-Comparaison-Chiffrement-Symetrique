# Video 1 - Nature du systeme

## Objectif
Presenter l'organisation du depot, l'architecture en couches, puis lancer une experience en direct pour montrer la sortie concrete du systeme.

## Portee
- Racine du depot, docs, Resources
- crypto-experiments et ses couches
- domain/cipher, domain/mode, domain/engine
- application/ExperimentController.py
- scripts/experiment.py
- Execution live et lecture du CSV genere

## Script

### Introduction
Dans cette video, je presente l'organisation du depot du projet de comparaison des algorithmes de chiffrement symetrique.
On va d'abord voir comment le code est structure, ou se trouvent les primitives, les modes, l'orchestration et les scripts,
puis on termine en lancant une experience en direct pour montrer concretement ce que le systeme produit.

### Racine du depot
On voit ici la racine du depot avec trois dossiers et le README.
Le dossier docs regroupe les livrables academiques, les guides et les feedbacks recus durant le projet.
Le dossier Resources contient les references bibliographiques et les documents de support.
Ces deux dossiers sont la pour documenter et encadrer le projet,
mais l'essentiel du systeme se trouve dans crypto-experiments, et c'est exactement ce qu'on va explorer maintenant.

### Dossier crypto-experiments
Une fois dans crypto-experiments, on voit l'architecture en couches prendre forme concretement.
On a le dossier domain qui contient la logique cryptographique,
application qui gere l'orchestration,
scripts qui sont les points d'entree,
validation et tests qui assurent la conformite des implementations,
et data qui stocke les resultats.
On va commencer par explorer le dossier domain, qui est le coeur du systeme.

### Dossier domain
Dans le dossier domain, on retrouve trois sous-dossiers qui forment le coeur logique du systeme.
Le dossier cipher contient les primitives de chiffrement,
engine contient le moteur qui les assemble,
et mode contient les modes d'operation.
On commence par cipher.

## DOSSIER CIPHER

### Dossier domain/cipher
Dans domain/cipher, on retrouve les cinq primitives de chiffrement implementees dans le projet,
soit AES, ChaCha20, DES, TripleDES et Twofish.
On remarque aussi CipherPrimitive.py, qui est la classe abstraite dont toutes les autres heritent.
C'est ce qui garantit une interface uniforme a travers tout le systeme.

### Fichier CipherPrimitive.py

#### Segment 1 - Lignes 1 a 8, docstring du fichier
On voit ici le docstring qui decrit la responsabilite de cette classe.
La ligne cle est celle-ci: les primitives ne savent rien du chainage, des vecteurs d'initialisation ou des nonces.
C'est la separation des responsabilites en une phrase.

#### Segment 2 - Ligne 10 import ABC/abstractmethod, ligne 12 class CipherPrimitive(ABC)
On importe ABC et abstractmethod du module abc de Python.
Ces deux elements ensemble forment un contrat garanti par le langage.
Chaque algorithme qui herite de CipherPrimitive est oblige d'implementer les memes methodes,
ce qui permet au reste du systeme de travailler avec n'importe quelle primitive sans jamais savoir laquelle c'est concretement.
C'est ce qui rend le systeme extensible et neutre.

#### Segment 3 - Lignes 15 a 20, block_size et key_size
block_size et key_size sont des proprietes abstraites,
ce qui force chaque algorithme a declarer ses propres valeurs.
Par exemple, AES travaille sur des blocs de 16 octets avec des cles de 128, 192 ou 256 bits,
tandis que DES travaille sur des blocs de 8 octets avec une cle de 56 bits effectifs.
Sans ces deux proprietes exposees de facon uniforme,
le moteur de chiffrement ne pourrait pas savoir comment decouper les donnees ni valider les cles,
peu importe quel algorithme est utilise en dessous.

#### Segment 4 - Lignes 22 a 45, encrypt_block et decrypt_block
encrypt_block et decrypt_block sont les deux methodes abstraites centrales de cette classe.
Chacune recoit exactement un bloc d'octets et retourne exactement un bloc d'octets.
Ce qui est important, c'est ce qu'elles ne font pas:
elles ne gerent pas le chainage, les vecteurs d'initialisation ou les nonces.
Ce n'est pas un oubli, c'est un choix delibere.
En isolant la primitive a une seule responsabilite,
on peut brancher n'importe quel mode d'operation par-dessus sans jamais modifier le code de l'algorithme.
C'est la couche mode qui prend en charge tout le reste.

#### Segment 5 - Lignes 47 a 63, encrypt_blocks et boucle par defaut
encrypt_blocks est une methode concrete, pas abstraite.
Par defaut, elle traite les donnees en appelant encrypt_block bloc par bloc dans une boucle.
C'est fonctionnel mais pas optimal, parce qu'on paie le surcout de la boucle Python a chaque bloc.
C'est pourquoi le docstring invite explicitement les sous-classes a surcharger cette methode
avec un appel groupe directement a leur bibliotheque sous-jacente.
On va voir ca tout de suite dans AES.py, ou cette optimisation est concretement implemente.

### Fichier AES.py

#### Segment 1 - Lignes 1 a 8, docstring du fichier
On voit ici une implementation concrete de l'algorithme AES selon la norme FIPS 197.
Le docstring precise les tailles de cle supportees, 128, 192 ou 256 bits,
et confirme qu'on utilise PyCryptodome en mode ECB brut pour traiter un seul bloc a la fois.
La logique de chainage reste entierement a l'exterieur, dans la couche mode.

#### Segment 2 - Ligne 12, class AES(CipherPrimitive)
Ici, AES herite directement de CipherPrimitive.
Cet heritage n'est pas seulement structurel, il impose un contrat,
parce que CipherPrimitive est une classe abstraite avec des methodes decorees par abstractmethod.
Python refuse d'instancier AES tant que les quatre methodes obligatoires,
block_size, key_size, encrypt_block et decrypt_block,
ne sont pas toutes implementees.
C'est ce qui garantit la substituabilite:
n'importe quelle primitive peut remplacer une autre dans le systeme
sans casser le contrat defini par la classe de base.

#### Segment 3 - Lignes 18 a 27, __init__ et validation de la cle
Avant la classe, on definit _VALID_KEY_SIZES,
un ensemble qui contient les tailles de cle acceptees pour AES, soit 16, 24 ou 32 octets.
Le constructeur consulte cette constante immediatement pour valider la cle recue.
Si la longueur ne correspond a aucune des tailles supportees,
on leve une exception ValueError tout de suite, a la creation de l'objet,
plutot que de laisser une cle invalide se propager silencieusement jusqu'au moment du chiffrement.

#### Segment 4 - Lignes 31 a 35, block_size et key_size
Ici, on voit les deux proprietes abstraites de CipherPrimitive enfin implementees avec des valeurs concretes.
block_size retourne toujours 16 octets, la valeur fixe definie par la norme AES.
key_size retourne la longueur reelle de la cle fournie a la construction,
ce qui permet de distinguer une instance AES-128 d'une instance AES-256
sans avoir besoin d'une propriete separee pour chaque variante.
C'est exactement ces deux valeurs que le moteur de chiffrement consulte
pour savoir comment decouper les donnees,
sans jamais avoir besoin de savoir que c'est specifiquement AES en dessous.

#### Segment 5 - Lignes 37 a 48, encrypt_block et decrypt_block
Ces deux methodes respectent exactement le contrat defini dans CipherPrimitive:
un bloc en entree, un bloc en sortie.
A l'interieur, on valide d'abord que le bloc fait exactement 16 octets,
puis on cree un objet cipher avec PyCryptodome en mode ECB
et on lui delegue le chiffrement ou le dechiffrement.
Le fichier ne contient aucune logique de rondes,
de substitution ou de permutation propre a AES.
Tout ce calcul cryptographique est encapsule dans PyCryptodome,
une bibliotheque reconnue et auditee,
plutot que reimplemente a la main.

#### Segment 6 - Lignes 50 a 54, encrypt_blocks et decrypt_blocks
Et voici exactement l'optimisation qu'on annoncait dans CipherPrimitive.
La methode par defaut de la classe abstraite boucle bloc par bloc,
ce qui coute cher en surcharge Python a chaque iteration.
Ici, AES surcharge completement cette methode avec un seul appel a PyCryptodome
qui traite toutes les donnees d'un coup.
C'est en grande partie ce gain qui explique pourquoi AES affiche un debit nettement plus eleve
que les autres algorithmes dans nos resultats.

## DOSSIER MODE

Dans domain/mode, on retrouve les modes d'operation du systeme.
OperationMode.py est la classe abstraite de base,
suivie de quatre modes par blocs, ECB, CBC, CTR et GCM,
et de StreamMode, qui agit comme une couche de transparence pour les chiffrements par flux comme ChaCha20.
On commence par OperationMode.py pour voir le contrat commun,
exactement comme on l'a fait avec CipherPrimitive.

### Fichier mode/OperationMode.py

#### Segment 1 - Lignes 1 a 8, docstring du fichier
Le docstring etablit le meme principe que dans CipherPrimitive, mais inverse.
CipherPrimitive disait que les primitives ne savent rien des modes.
Ici, c'est l'inverse: la couche mode ne sait rien de quel algorithme elle encapsule.
Elle appelle uniquement encrypt_block et decrypt_block,
peu importe si c'est AES, DES ou Twofish en dessous.
Cette double ignorance entre les deux couches garantit
qu'on peut combiner n'importe quel algorithme avec n'importe quel mode
sans ecrire de code specifique pour chaque combinaison.

#### Segment 2 - Ligne 13, class OperationMode(ABC)
OperationMode herite de ABC, qui vient du module abc de Python,
et qui empeche la classe d'etre instanciee directement.
C'est le meme mecanisme exact qu'on a vu dans CipherPrimitive.
Les deux classes utilisent ABC et abstractmethod pour forcer leurs sous-classes
a implementer certaines methodes.
CipherPrimitive le faisait pour encrypt_block et decrypt_block,
et OperationMode le fait maintenant pour encrypt et decrypt.
Ca force chaque mode concret, ECB, CBC, CTR, GCM ou StreamMode,
a implementer ces methodes abstraites,
sinon Python refuse de l'instancier.
C'est ce qui montre que le meme patron de conception est applique
de facon coherente a travers toute l'architecture du systeme.

#### Segment 3 - Lignes 14 a 22, __init__ et propriete primitive
Voici la difference structurelle la plus importante avec CipherPrimitive.
Le constructeur recoit une instance de CipherPrimitive en parametre
et la stocke dans self._primitive.
Ce n'est pas de l'heritage, c'est une relation objet par reference:
un mode ne devient jamais un AES,
il recoit un AES deja construit et travaille avec lui a travers l'interface commune.
La propriete primitive expose ensuite cet objet en lecture seule.
Dans l'implementation actuelle,
les sous-classes comme ECB ou CBC utilisent directement self._primitive
pour appeler encrypt_block et decrypt_block,
ce qui reste coherent avec ce contrat.

#### Segment 4 - Lignes 25 a 50, encrypt et decrypt
Ces deux methodes abstraites definissent le contrat que chaque mode concret doit respecter.
La difference majeure avec encrypt_block dans CipherPrimitive,
c'est que plaintext et ciphertext ici sont de longueur arbitraire,
pas limites a un seul bloc.
C'est la responsabilite du mode de decouper les donnees en blocs,
gerer le rembourrage si necessaire,
et appliquer sa strategie de chainage specifique.
On voit aussi le parametre kwargs dans la signature,
qui permet a chaque mode d'accepter des parametres qui lui sont propres,
comme un vecteur d'initialisation pour CBC,
ou un nonce pour CTR ou GCM,
sans forcer tous les modes a exposer les memes parametres inutiles.

### Fichier mode/ECB.py
Maintenant qu'on a vu le contrat abstrait dans OperationMode,
on va l'illustrer concretement avec ECB.py.
On choisit ce mode en premier parce que c'est le plus simple a comprendre:
chaque bloc est chiffre independamment sans aucun parametre additionnel.
C'est aussi le mode qui va nous servir plus tard dans le projet
pour demontrer une vulnerabilite cryptographique reelle,
donc c'est pertinent de bien comprendre et expliquer son fonctionnement des maintenant.

#### Segment 1 - Lignes 1 a 9, docstring du fichier
Le docstring commence par un avertissement explicite.
ECB est cryptographiquement faible parce que des blocs de texte clair identiques
produisent des blocs chiffres identiques,
ce qui revele des motifs dans les donnees.
Il est inclus dans le projet uniquement a des fins de comparaison academique.
On voit aussi que le rembourrage PKCS7 est applique pour accepter des messages de n'importe quelle longueur.
C'est essentiel parce qu'un chiffrement par blocs comme AES ne peut traiter
que des blocs de taille fixe,
alors que les messages reels font rarement une longueur multiple de cette taille.

#### Segment 2 - Lignes 13 a 17, _pkcs7_pad et _pkcs7_unpad
Ces deux fonctions implementent le rembourrage PKCS7.
Le principe est simple:
on calcule combien d'octets manquent pour completer le dernier bloc,
et on ajoute exactement cette valeur repetee comme octets de remplissage.
Au dechiffrement, _pkcs7_unpad lit le dernier octet
pour savoir combien d'octets retirer.
C'est une implementation minimale,
elle ne valide pas que le rembourrage est coherent avant de le retirer,
ce qui suffit pour notre contexte de benchmarking
mais ne serait pas suffisant dans un systeme de production expose a des attaques.

#### Segment 3 - Lignes 19 a 25, class ECB(OperationMode) et constructeur
ECB herite directement d'OperationMode,
exactement le meme mecanisme qu'on a vu entre AES et CipherPrimitive.
Le constructeur ne fait qu'appeler super().__init__(primitive).
Il n'ajoute aucun etat supplementaire,
parce qu'ECB n'a besoin d'aucun parametre additionnel
comme un vecteur d'initialisation ou un nonce.
C'est le mode le plus simple:
chaque bloc est chiffre independamment.

#### Segment 4 - Lignes 27 a 40, encrypt
Voici l'implementation concrete du contrat defini dans OperationMode.
On recupere le block_size de la primitive associee,
on applique le rembourrage PKCS7,
puis ECB delegue le traitement bloc par bloc a la primitive via encrypt_blocks.
Selon la primitive utilisee,
cette methode peut etre l'implementation par defaut avec une boucle
ou une version optimisee comme celle qu'on a vue dans AES.py.
Aucun IV n'est necessaire ici,
ce qui est precisement la faiblesse du mode:
chaque bloc identique en clair produit toujours le meme bloc chiffre.

#### Segment 5 - Lignes 42 a 53, decrypt
Le dechiffrement valide d'abord que la longueur du texte chiffre
est un multiple du block_size, sinon une exception est levee.
Ensuite on delegue a decrypt_blocks de la primitive
et on retire le rembourrage avec _pkcs7_unpad.
Cette implementation va etre directement reutilisee plus tard dans le projet
pour demontrer visuellement la vulnerabilite d'ECB sur une image structuree,
comparee au mode CBC qui dissimule les motifs.

## DOSSIER ENGINE

### Fichier domain/engine/EncryptionEngine.py
Maintenant qu'on a vu les primitives et les modes separement,
on regarde comment ils se rejoignent.
EncryptionEngine.py compose une primitive, par exemple AES,
et un mode, par exemple CBC,
pour former un service de chiffrement complet.

#### Segment 1 - Lignes 1 a 9, docstring du fichier
EncryptionEngine est l'objet central du domaine.
La couche application, a travers ExperimentController,
interagit directement avec lui pour executer chaque chiffrement.
C'est un choix de conception delibere:
il ne sait rien du chronometrage,
des fichiers CSV ou de la configuration des experiences.
Ces responsabilites appartiennent strictement aux couches superieures.

#### Segment 2 - Lignes 29 a 38, constructeur
Le constructeur recoit une primitive et un mode deja construits,
et applique une validation critique.
Il verifie que mode.primitive est exactement le meme objet
que la primitive passee separement,
sinon il leve une exception.
C'est cette verification qui garantit la coherence entre le mode et la primitive.
On ne peut pas accidentellement assembler un mode configure avec une primitive
et le combiner avec une primitive differente dans le moteur.

#### Segment 3 - Lignes 44 a 49, proprietes primitive et mode
Les proprietes primitive et mode exposent en lecture seule
la primitive et le mode internes de l'objet,
exactement le meme patron qu'avec primitive dans OperationMode.
Ca permet d'inspecter la configuration d'un moteur deja construit,
par exemple pour savoir quel algorithme et quel mode sont actifs,
sans jamais pouvoir la modifier apres sa creation.

#### Segment 4 - Lignes 51 a 67, encrypt et decrypt
Les methodes encrypt et decrypt se contentent de deleguer directement au mode configure,
en transmettant tous les arguments nommes recus comme le IV ou le nonce.
EncryptionEngine n'implemente aucune logique cryptographique lui-meme.
Il agit comme une facade,
un point d'entree unifie vers la combinaison primitive et mode.
C'est exactement cette interface uniforme qu'utilise ExperimentController
pour executer chaque configuration experimentale,
sans jamais avoir besoin de savoir quel algorithme ou quel mode est actif en dessous.

## DOSSIER APPLICATION

### Fichier application/ExperimentController.py
ExperimentController.py est la classe qui orchestre toute la campagne de mesures.
C'est elle qui configure les parametres d'une experience,
declenche le chronometrage des operations de chiffrement et de dechiffrement,
calcule l'effet d'avalanche,
et retourne un resultat structure.
Cette classe ne sait pas quel algorithme ou quel mode est actif en dessous:
elle travaille uniquement a travers l'interface d'EncryptionEngine.
La persistance vers un fichier CSV n'est pas non plus sa responsabilite:
ca appartient au script appelant, experiment.py.

#### Segment 1 - Lignes 29 a 43, dataclass ExperimentResult
ExperimentResult est une dataclass Python qui sert de conteneur pour une mesure complete.
Une dataclass genere automatiquement le constructeur et la representation de l'objet
a partir des attributs declares,
ce qui evite d'ecrire du code repetitif.
On voit ici toutes les metriques collectees pour chaque configuration testee:
algorithme, mode, taille de cle, taille du message, nombre de repetitions,
temps moyens de chiffrement et de dechiffrement,
debit dans les deux sens,
score d'avalanche du texte,
score d'avalanche de la cle,
et intervalles de confiance a 95% pour le debit.
C'est cette richesse de metriques qui permet une analyse statistique rigoureuse,
plutot qu'une simple comparaison de chiffres bruts.

#### Segment 2 - Ligne 63, constructeur d'ExperimentController
Le constructeur est volontairement simple.
Il recoit un moteur de chiffrement deja entierement configure,
donc une primitive et un mode deja assembles,
plus deux etiquettes lisibles pour le nom de l'algorithme et du mode.
Ces etiquettes servent uniquement a identifier les lignes de resultats.
Elles n'influencent jamais le comportement du chiffrement lui-meme.

#### Segment 3 - Ligne 104, chronometrage du chiffrement dans run_performance
Voici le coeur du protocole de mesure.
On genere d'abord un texte en clair aleatoire fixe,
qui sera reutilise pour toutes les repetitions afin de garantir la comparabilite entre les essais.
Ensuite, on boucle sur le nombre de repetitions,
et a chaque iteration on demarre le chronometre juste avant l'appel a encrypt,
puis on l'arrete immediatement apres.
C'est precisement ce qu'on appelle un chronometrage neutre:
time.perf_counter encapsule uniquement l'appel cryptographique,
pas l'allocation memoire ni d'autres surcouts du systeme.
C'est ce qui garantit que la mesure reflete la performance reelle de l'algorithme
et non des artefacts de l'environnement Python.

#### Segment 4 - Ligne 113, chronometrage du dechiffrement
Le meme principe est applique au dechiffrement,
mais on utilise systematiquement le dernier texte chiffre genere durant la phase de chiffrement,
plutot que d'en generer un nouveau a chaque repetition.
Ca garantit que chaque iteration de dechiffrement opere sur des donnees
representatives de ce que produirait l'algorithme.

#### Segment 5 - Ligne 127, calcul de l'intervalle de confiance a 95%
Le calcul de l'intervalle de confiance a 95% est l'element le plus rigoureux de ce fichier.
La fonction interne _ci95_mbps calcule la variance des temps mesures,
puis convertit cet ecart-type temporel en ecart-type de debit,
parce que le debit n'est pas une fonction lineaire du temps.
On applique ensuite la formule standard de l'intervalle de confiance,
ou la valeur critique vaut 1.96 pour un echantillon d'au moins 30 repetitions,
ou 2.045 pour un echantillon plus petit,
en utilisant une approximation de Student.
Ce calcul permet de quantifier la marge d'incertitude statistique autour de chaque mesure de debit.

#### Segment 6 - Lignes 144 a 173, assemblage du resultat final
Toutes les valeurs calculees sont assemblees dans un objet ExperimentResult.
On voit que avalanche_score et key_avalanche_score sont calcules
en appelant directement les deux methodes dediees,
measure_avalanche et measure_key_avalanche.
Le debit est calcule en divisant la taille du message convertie en megaoctets
par le temps moyen,
avec une protection contre la division par zero
si jamais le temps mesure etait nul.

#### Segment 7 - Lignes 178 a 218, measure_avalanche
Cette methode mesure l'effet d'avalanche de la primitive,
independamment du mode utilise.
Le principe:
on genere un bloc aleatoire,
on le chiffre pour obtenir un texte chiffre de reference,
puis on inverse exactement un seul bit dans le bloc original.
On chiffre ce bloc modifie,
et on compare les deux textes chiffres bit par bit avec la distance de Hamming.
Le calcul est fait avec le XOR puis un comptage des bits differents.
On repete cette experience 200 fois et on moyenne le resultat.
Un score ideal est 0.5,
ce qui signifie qu'en moyenne la moitie des bits de sortie changent
quand on modifie un seul bit en entree.

#### Segment 8 - Lignes 220 a 270, measure_key_avalanche
measure_key_avalanche applique le meme principe statistique,
mais en inversant un bit de la cle plutot que du texte en clair,
tout en gardant le meme bloc a chiffrer.
Cette methode repond directement au retour du professeur sur le TN1.
Un detail technique important:
certaines cles modifiees peuvent etre degenerees,
par exemple en 3DES ou K1 peut devenir egal a K2 apres inversion d'un bit.
Le code intercepte alors l'exception
et assigne une valeur ideale de 0.5
plutot que de faire planter toute la campagne de mesure.

## DOSSIER SCRIPTS

### Survol de scripts/
---
Dans scripts, on trouve les points d'entree du systeme.
experiment.py lance les benchmarks de performance.
run_kat.py valide la conformite cryptographique des implementations.
generate_charts.py produit les figures a partir des resultats.
analyse_rounds_avalanche.py mesure la robustesse cryptographique.
ecb_visual_vulnerability.py demontre la vulnerabilite du mode ECB.
compare_platforms.py confronte les resultats entre le laptop et le Raspberry Pi.
On revient en detail sur chacun de ces scripts dans les prochaines videos.
Pour l'instant, on se concentre sur experiment.py.

### Fichier scripts/experiment.py

#### Segment 1 - Lignes 1 a 17, docstring
Le docstring resume exactement ce que fait ce fichier.
Il itere sur toutes les combinaisons definies dans EXPERIMENT_MATRIX,
execute les mesures via ExperimentController,
et ecrit les resultats dans un CSV horodate.
La derniere phrase est importante:
aucune logique cryptographique ne se trouve ici.
Ce fichier ne fait que cabler les couches domaine et application
et gerer les entrees-sorties.

#### Segment 2 - Lignes 47 a 62, EXPERIMENT_MATRIX
Voici la matrice experimentale complete,
declaree comme une simple liste de tuples.
Chaque ligne associe un algorithme, sa classe primitive,
un mode, sa classe,
et les tailles de cle valides pour cette combinaison.
On voit par exemple qu'AES est teste avec GCM en plus d'ECB, CBC et CTR,
parce que GCM n'a de sens qu'avec AES dans notre etude.
ChaCha20 utilise StreamMode avec une seule taille de cle de 32 octets,
puisque c'est la seule taille supportee.
Cette structure declarative permet d'ajouter un nouvel algorithme
ou une nouvelle combinaison sans toucher au reste du systeme.

#### Segment 3 - Ligne 64, MESSAGE_SIZES
Les tailles de message testees vont de 64 octets jusqu'a 16384 octets,
ce qui couvre a la fois les petits messages ou les couts fixes dominent,
et les gros volumes ou le debit reel de l'algorithme se revele.

#### Segment 4 - Lignes 85 a 92, verification prealable de la cle
Avant de lancer les mesures,
le code essaie d'instancier la primitive avec une cle de test.
Si ca echoue, par exemple une taille de cle invalide pour cet algorithme,
le code passe directement a la combinaison algorithme-mode suivante,
en sautant les tailles de message pour cette taille de cle specifique,
plutot que de faire planter toute la campagne de benchmarking.

#### Segment 5 - Lignes 94 a 114, boucle principale d'execution
C'est ici que tout s'assemble.
Pour chaque taille de message,
on genere une nouvelle cle,
on construit la primitive, le mode,
puis le moteur de chiffrement,
et on les passe a ExperimentController.
On appelle ensuite run_performance avec la taille de message
et le nombre de repetitions fixe a 100 via REPETITIONS.
Chaque resultat est accumule dans une liste,
et la progression s'affiche en direct dans le terminal
avec le temps de chiffrement, le debit et le score d'avalanche.

#### Segment 6 - Lignes 124 a 132, ecriture du CSV
Une fois toutes les configurations testees,
les resultats sont ecrits dans un fichier CSV horodate.
asdict transforme chaque objet ExperimentResult en dictionnaire,
et csv.DictWriter ecrit une ligne par resultat
avec les memes noms de colonnes que les attributs de la dataclass.
C'est ce fichier qu'on va ouvrir juste apres l'execution.

### Basculer vers VS Code et ouvrir le terminal integre
---
On passe maintenant dans Visual Studio Code pour executer une experience en direct.

### Taper et executer python scripts/experiment.py
---
Je lance la commande python scripts/experiment.py.
Je suis positionne dans le dossier crypto-experiments,
donc la commande fonctionne directement.

### Laisser defiler le terminal
---
Le systeme parcourt l'ensemble de la matrice experimentale,
chaque combinaison d'algorithme, de mode, de taille de cle et de taille de message,
et repete chaque mesure cent fois.
On voit chaque ligne s'afficher en direct dans le terminal,
avec le temps de chiffrement moyen,
le debit obtenu
et le score d'avalanche calcule pour cette configuration.

### Ouvrir le CSV genere
---
A la fin de l'execution,
le terminal confirme l'emplacement du fichier genere.
Un CSV horodate est cree dans data/results,
avec une ligne par configuration mesuree
et toutes les metriques collectees:
temps de chiffrement et de dechiffrement,
debit,
scores d'avalanche
et intervalles de confiance.
C'est ce fichier brut qui servira de base
a l'analyse comparative des prochaines videos.


