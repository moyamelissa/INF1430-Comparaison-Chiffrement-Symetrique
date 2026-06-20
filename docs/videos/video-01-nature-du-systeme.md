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

#### Segment 1 - Lignes 1 à 9, docstring du fichier
On voit ici le docstring du fichier, qui décrit la responsabilité globale de CipherPrimitive.
La ligne clé est celle-ci: les primitives ne savent rien du chaînage, des vecteurs d'initialisation ou des nonces.
C'est la séparation des responsabilités en une phrase.

#### Segment 2 - Ligne 11 import ABC/abstractmethod, ligne 14 class CipherPrimitive(ABC)
**(Surligne ligne 11)** On importe ABC et abstractmethod depuis le module abc de Python.
Ces deux éléments forment un contrat imposé par le langage.
**(Surligne ligne 14)** Chaque algorithme qui hérite de CipherPrimitive est obligé d’implémenter les mêmes méthodes,
ce qui permet au reste du système de fonctionner avec n’importe quelle primitive sans savoir laquelle est utilisée concrètement.
C’est ce qui rend le système extensible et neutre. 


#### Segment 3 - Lignes 17 à 25, block_size et key_size
**(Surligne lignes 19 à 20 - block_size)** block_size est une propriété abstraite: chaque algorithme doit déclarer la taille de ses blocs.
**(Surligne lignes 24 à 25 - key_size)** key_size est aussi une propriété abstraite: chaque algorithme doit déclarer la taille de clé réellement utilisée par l’instance.

**(Surligne les deux propriétés ensemble)** Ce contrat force chaque primitive à exposer les mêmes informations minimales, peu importe l’algorithme.
Par exemple, AES travaille avec des blocs de 16 octets et des clés de 128, 192 ou 256 bits, alors que DES travaille avec des blocs de 8 octets et une clé effective de 56 bits.

#### Segment 4 - Lignes 28 à 57, encrypt_block et decrypt_block
**(Surligne ligne 28 - def encrypt_block(...))** encrypt_block fait partie du contrat abstrait central de la primitive.
**(Surligne ligne 44 - def decrypt_block(...))** decrypt_block complète ce contrat avec l’opération inverse.

**(Surligne les docstrings des deux méthodes)** Chaque méthode prend exactement un bloc d’octets en entrée et retourne exactement un bloc d’octets en sortie.
Ce qui est important, c’est ce qu’elles ne font pas: elles ne gèrent ni le chaînage, ni les vecteurs d’initialisation, ni les nonces.

**(Surligne les deux signatures ensemble)** Ce n’est pas un oubli, c’est un choix de conception délibéré.
En isolant la primitive à une seule responsabilité, on peut brancher n’importe quel mode d’opération par-dessus sans modifier le code de l’algorithme.
C’est la couche mode qui prend en charge tout le reste.


#### Segment 5 - Lignes 59 à 75, encrypt_blocks et boucle par défaut
**(Surligne ligne 59 - def encrypt_blocks(...))** encrypt_blocks est une méthode concrète, pas abstraite.
**(Surligne le docstring de 60 à 67)** Le docstring explique que cette version est un comportement par défaut, et qu’une sous-classe peut la surcharger pour optimiser le traitement.

**(Surligne lignes 68 à 72 - bs, validation, ValueError)** Le code commence par vérifier que la longueur des données est un multiple de block_size.
**(Surligne lignes 73 à 75 - for + encrypt_block)** Ensuite, il chiffre bloc par bloc en appelant encrypt_block dans une boucle Python.
**(Surligne lignes 76)** Puis, il retourne le résultat final sous forme de bytes.

C’est fonctionnel, mais pas optimal: on paie le coût de la boucle à chaque bloc.
C’est exactement pour ça que les sous-classes peuvent surcharger cette méthode avec un appel groupé à la bibliothèque crypto sous-jacente.
On le verra juste après dans AES.py.

### Fichier AES.py

#### Segment 1 - Vue générale de AES.py
AES.py implémente la primitive AES concrète utilisée dans le projet.
Son rôle est de gérer le chiffrement et le déchiffrement par blocs de 16 octets, avec validation des tailles de clé.
Le but est de fournir une implémentation standard compatible avec l'interface CipherPrimitive,
pour que le moteur puisse l'utiliser de façon uniforme avec les différents modes d'opération.

#### Segment 2 - Ligne 19, class AES(CipherPrimitive)
**(Surligne ligne 19 - class AES(CipherPrimitive))** Ici, AES hérite directement de CipherPrimitive.
Cet héritage impose un contrat d'interface:
la classe doit fournir les méthodes et propriétés attendues par le reste du système.
C'est ce qui garantit la substituabilité:
n'importe quelle primitive peut remplacer une autre dans le moteur,
sans logique spéciale et sans casser le contrat de la classe de base.

#### Segment 3 - Lignes 16 à 44, _VALID_KEY_SIZES, __init__ et validation de la clé
**(Surligne ligne 16 - _VALID_KEY_SIZES)** Ici, on fixe les seules tailles de clé acceptées pour AES: 16, 24 ou 32 octets.
**(Surligne lignes 24 à 40 - __init__ + validation)** Le constructeur valide la clé dès la création de l'objet.
Si la longueur est invalide, il lève immédiatement une `ValueError`.
Ça évite de propager une mauvaise clé plus loin dans le moteur.

#### Segment 4 - Lignes 47 à 52, block_size et key_size
**(Surligne lignes 46 à 48 - block_size)** `block_size` retourne une taille fixe de 16 octets.
**(Surligne lignes 50 à 52 - key_size)** `key_size` retourne la taille réelle de la clé de l'instance.
Pourquoi 16 en permanence? La norme AES impose un bloc fixe de 128 bits, soit 16 octets.
La taille de clé peut varier (16, 24, 32), mais pas la taille de bloc.
Ces deux propriétés donnent au moteur les informations minimales pour travailler,
sans dépendre d'une primitive spécifique.

#### Segment 5 - Lignes 54 à 69, encrypt_block et decrypt_block
**(Surligne lignes 54 à 60 - encrypt_block)** `encrypt_block` valide d'abord que le bloc fait exactement 16 octets, puis délègue le chiffrement à la bibliothèque PyCryptodome via l'objet AES importé.
**(Surligne lignes 62 à 68 - decrypt_block)** `decrypt_block` applique la même validation et délègue le déchiffrement de la même façon.
Le point clé: cette classe respecte le contrat d'interface de `CipherPrimitive`
et n'implémente pas elle-même les rondes internes d'AES.

#### Segment 6 - Lignes 70 à 77, encrypt_blocks et decrypt_blocks
**(Surligne ligne 70 - def encrypt_blocks(...))** À partir d'ici, on voit clairement l'intention d'optimisation: AES surcharge la méthode de base.
**(Surligne ligne 72 - return _AES.new(...).encrypt(data))** Au lieu de boucler bloc par bloc en Python, toute la donnée est chiffrée en un seul appel groupé à PyCryptodome.
**(Surligne ligne 74 - def decrypt_blocks(...))** Ensuite, le même choix est reproduit côté déchiffrement.
**(Surligne ligne 76 - return _AES.new(...).decrypt(data))** Là aussi, un seul appel traite l'ensemble des blocs.
Concrètement, on remplace la boucle de la classe abstraite par un traitement groupé,
ce qui diminue le surcoût d'orchestration et explique le meilleur débit observé en benchmark.

## DOSSIER MODE

Dans domain/mode, on retrouve les modes d'opération du système.
OperationMode.py est là classe abstraite de base,
suivie de quatre modes par blocs, ECB, CBC, CTR et GCM,
et de StreamMode, qui agit comme une couche de transparence pour les chiffrements par flux comme ChaCha20.
On commence par OperationMode.py pour voir le contrat commun,
exactement comme on l'a fait avec CipherPrimitive.

### Fichier mode/OperationMode.py

#### Segment 1 - Rôle et concept de OperationMode
OperationMode est l'abstraction pour tous les modes d'opération de chiffrement par blocs.
Son rôle est simple mais fondamental: prendre une primitive de chiffrement par blocs,
comme AES qui ne traite que des blocs de 16 octets,
et la transformer en un service qui peut chiffrer des messages de n'importe quelle longueur.
Chaque mode — ECB, CBC, CTR, GCM — décide comment découper les données,
gérer le rembourrage si nécessaire, et enchaîner les blocs ensemble.
Mais ici, c'est la beauté architecturale: OperationMode ne sait rien du type exact de primitive qu'il encapsule.
Il appelle uniquement encrypt_block et decrypt_block via l'interface commune,
peu importe si c'est AES, DES ou Twofish en dessous.
Cette séparation des responsabilités garantit qu'on peut combiner n'importe quel algorithme
avec n'importe quel mode sans écrire de code spécifique pour chaque paire.
On va voir comment ce contrat est imposé dans les segments suivants.

#### Segment 2 - Lignes 11 et 16, import ABC et class OperationMode(ABC)
**(Surligne ligne 11 - from abc import ABC, abstractmethod)** Comme dans CipherPrimitive, on importe ABC et abstractmethod.
**(Surligne ligne 16 - class OperationMode(ABC))** La classe OperationMode hérite d'ABC, ce qui empêche d'instancier directement cette classe abstraite.
C'est exactement le même mécanisme de contrat qu'on vient de voir.
CipherPrimitive utilisait cela pour forcer encrypt_block et decrypt_block,
et OperationMode le fait maintenant pour encrypt et decrypt.
Le résultat: chaque mode concret, ECB, CBC, CTR, GCM ou StreamMode,
doit obligatoirement implémenter ces deux méthodes abstraites,
sinon Python refuse de l'instancier.
Ce pattern de conception cohérent garantit que tous les modes respectent le même contrat.

#### Segment 3 - Lignes 19 à 30, __init__ et propriété primitive
**(Surligne lignes 19-26 - __init__ et self._primitive)** Ici commence la composition: le constructeur reçoit une primitive déjà instanciée et la stocke dans self._primitive.
C'est différent de l'héritage de CipherPrimitive. Un mode n'est pas une primitive, il la contient.
**(Surligne lignes 28-29 - @property primitive)** La propriété primitive expose cette référence en lecture seule, rendant l'association immutable après construction.
Cette composition permet l'injection de dépendance: on peut passer n'importe quelle primitive concrète — AES, DES, Twofish — 
et le mode travaille uniquement via l'interface CipherPrimitive, sans connaître l'implémentation réelle.
C'est ce qui rend le système flexible au runtime: chaque mode peut fonctionner avec n'importe quel algorithme
sans modification de code, simplement en changeant la primitive injectée au moment de la construction.

#### Segment 4 - Lignes 32 à 70, encrypt et decrypt abstraits
**(Surligne ligne 32 - @abstractmethod)** Les deux méthodes abstraites encrypt et decrypt forment le contrat fondamental que chaque mode doit honorer.
**(Surligne lignes 33-35 - def encrypt(self, plaintext: bytes, **kwargs) -> bytes)** La signature est cruciale ici, plaintext est de type bytes, sans aucune contrainte de longueur.
C'est l'inverse complet d'encrypt_block, qui exigeait exactement un bloc.
Un mode devient en quelque sorte le traducteur entre deux mondes, le monde du chiffrement par blocs rigide,
et le monde applicatif où on veut chiffrer des messages de taille quelconque.
**(Surligne lignes 50-52 - @abstractmethod decrypt)** Le même contrat s'applique au déchiffrement.
**(Surligne ligne 51 - def decrypt(self, ciphertext: bytes, **kwargs) -> bytes)** Et si on compare cette signature à celle d'encrypt qu'on vient de voir,
les deux acceptent un paramètre kwargs en plus du texte principal, ce que Python appelle des arguments nommés variables.
C'est exactement ce qui permet la flexibilité entre les modes, CBC exige un vecteur d'initialisation,
CTR et GCM exigent un nonce, mais ECB n'a besoin de rien du tout.
Plutôt que de créer une signature différente pour chaque mode,
cette signature commune accepte n'importe quel paramètre supplémentaire, que le mode concret peut utiliser ou simplement ignorer.
ECB ignore tranquillement un IV si on lui en passe un par erreur, tandis que CBC l'exige obligatoirement.
C'est une flexibilité par contrat, chaque mode implémente lui-même la validation des paramètres dont il a besoin.

### Fichier mode/ECB.py
Maintenant qu'on a vu le contrat abstrait dans OperationMode,
on passe à sa première implémentation concrète avec ECB.py.
ECB est volontairement simple, et c'est exactement pour ça qu'il est pédagogique:
il montre clairement comment un mode encapsule une primitive,
mais il montre aussi pourquoi un mode peut être correct en code
et rester faible en sécurité cryptographique.

#### Segment 1 - Lignes 1 à 11, docstring du fichier
Pour commencer, regardons ce que le fichier annonce avant même le code.
**(Surligne lignes 5-8 - avertissement de sécurité ECB)** Le fichier annonce immédiatement le point central: ECB est cryptographiquement faible.
Pourquoi? Parce que deux blocs clairs identiques donnent deux blocs chiffrés identiques,
ce qui préserve des motifs observables dans les données.
**(Surligne ligne 10 - PKCS#7)** Le docstring précise aussi que PKCS#7 est appliqué,
car la primitive sous-jacente chiffre uniquement des blocs de taille fixe.
En clair, ECB est ici un mode de référence pour comparer,
pas une recommandation de déploiement.

#### Segment 2 - Lignes 17 à 25, _pkcs7_pad et _pkcs7_unpad
Maintenant, on passe aux deux petites fonctions utilitaires qui gèrent le rembourrage.
**(Surligne lignes 17-19 - fonction _pkcs7_pad)** Ici, on applique le rembourrage PKCS#7 en deux étapes très simples:
on calcule d'abord combien d'octets il manque pour compléter le bloc, puis on ajoute exactement ce nombre d'octets de remplissage.
Chaque octet ajouté porte cette même valeur, ce qui permet de retirer le padding de façon déterministe au déchiffrement.
**(Surligne lignes 22-24 - _pkcs7_unpad)** Au retrait, la version actuelle lit le dernier octet et coupe directement.
Techniquement, c'est suffisant pour un environnement contrôlé de benchmark.
Mais point de réflexion important: en production,
on validerait aussi la cohérence de tous les octets de padding avant suppression
pour réduire la surface d'attaques liées aux erreurs de padding.

#### Segment 3 - Lignes 27 à 35, déclaration de la classe ECB et constructeur
Ensuite, regardons la structure de la classe elle-même.
**(Surligne ligne 27 - déclaration de la classe ECB)** Ici, ECB applique directement le contrat défini dans OperationMode.
**(Surligne lignes 34-35 - constructeur)** Le constructeur reçoit la primitive et la transmet simplement à la classe de base,
sans ajouter d'état interne.
Ce point est important: contrairement à CBC, CTR ou GCM,
ECB n'utilise ni vecteur d'initialisation ni nonce.
C'est justement cette absence de chaînage entre les blocs
qui rend le mode très simple, mais aussi vulnérable à l'analyse de motifs.

#### Segment 4 - Lignes 37 à 54, encrypt
Maintenant qu'on a vu la structure de la classe, regardons le flux concret du chiffrement, étape par étape.
**(Surligne ligne 51 - bs = self._primitive.block_size)** D'abord, ECB récupère la taille de bloc depuis la primitive.
**(Surligne ligne 52 - padded = _pkcs7_pad(plaintext, bs))** Ensuite, il applique le rembourrage pour aligner le message sur cette taille.
**(Surligne ligne 53 - return self._primitive.encrypt_blocks(padded))** Enfin, il confie le chiffrement complet à la primitive.
Autrement dit, ECB ne chiffre pas lui-même: il orchestre les étapes et délègue l'opération cryptographique.
Et c'est précisément là sa faiblesse: sans mélange entre blocs,
deux blocs clairs identiques donnent deux blocs chiffrés identiques, donc les motifs restent visibles.

#### Segment 5 - Lignes 55 à 74, decrypt
Pour terminer, on regarde le chemin inverse, donc le déchiffrement.
**(Surligne lignes 69-73 - validation de longueur + ValueError)** Avant de déchiffrer,
le code refuse tout texte chiffré dont la taille n'est pas un multiple exact de la taille de bloc.
C'est une vérification de robustesse minimale pour éviter un traitement incohérent.
**(Surligne ligne 74 - decrypt_blocks puis _pkcs7_unpad)** Le flux inverse est clair:
déchiffrement des blocs, puis retrait du padding.
Cette section est importante pour la suite de la vidéo,
car c'est exactement ce comportement qui sera comparé à CBC
lors de la démonstration visuelle de la fuite de motifs en ECB.

## DOSSIER ENGINE

### Fichier domain/engine/EncryptionEngine.py
Maintenant qu'on a vu les primitives et les modes séparément,
on regarde l'endroit où ils sont réellement assemblés.
EncryptionEngine.py est la pièce d'intégration du domaine:
il prend une primitive, par exemple AES,
et un mode, par exemple CBC,
pour exposer une interface de chiffrement unique et cohérente.

#### Segment 1 - Lignes 1 à 10, docstring du fichier
Pour commencer, regardons ce que le fichier annonce comme responsabilité.
**(Surligne lignes 2-4 - description du rôle du moteur)** Le moteur combine explicitement primitive et mode pour fournir un service complet.
**(Surligne lignes 6-9 - séparation des responsabilités)** Le point architectural clé est posé dès le docstring:
EncryptionEngine est central pour le domaine,
mais il ne gère ni le chronométrage, ni les CSV, ni la configuration des expériences.
Cette séparation garde une frontière claire entre logique cryptographique
et orchestration applicative.

#### Segment 2 - Lignes 29 à 38, constructeur
Ensuite, on regarde la validation la plus critique de ce fichier.
**(Surligne ligne 29 - signature du constructeur)** Le moteur reçoit une primitive et un mode déjà construits.
**(Surligne lignes 30-35 - vérification d'identité + ValueError)** Le code impose que `mode.primitive` soit exactement le même objet que `primitive`.
Ce n'est pas un simple détail: cette contrainte évite les assemblages incohérents,
par exemple un mode initialisé avec une primitive différente de celle du moteur.
**(Surligne lignes 36-37 - stockage interne)** Une fois validé, le couple est figé dans l'instance.

#### Segment 3 - Lignes 43 à 49, propriétés primitive et mode
Maintenant, on voit comment cette configuration est exposée proprement.
**(Surligne lignes 43-45 - propriété primitive)** La primitive est accessible en lecture seule.
**(Surligne lignes 47-49 - propriété mode)** Le mode l'est aussi, avec le même principe.
Concrètement, ça permet d'inspecter un moteur déjà construit,
sans pouvoir modifier sa configuration interne après initialisation.

#### Segment 4 - Lignes 51 à 66, encrypt et decrypt
Pour terminer, regardons le flux opérationnel du moteur.
**(Surligne lignes 51-58 - méthode encrypt)** `encrypt` délègue directement au mode,
en propageant les paramètres nommés utiles, comme le vecteur d'initialisation, le nonce ou l'AAD.
**(Surligne lignes 60-66 - méthode decrypt)** `decrypt` applique exactement le même principe dans l'autre sens.
La conséquence est essentielle pour l'architecture:
EncryptionEngine n'implémente pas la crypto lui-même,
il sert de façade unifiée au-dessus du couple primitive + mode.
C'est précisément cette interface stable qu'ExperimentController utilise
pour exécuter les expériences sans dépendre d'un algorithme précis.

## DOSSIER APPLICATION

### Fichier application/ExperimentController.py
Après le moteur, on passe à la couche d'orchestration des mesures.
ExperimentController.py ne fait pas de cryptographie de bas niveau.
il pilote le protocole expérimental,
mesure proprement les performances,
calcule les indicateurs d'avalanche,
et retourne un résultat prêt à analyser.
Point architectural important:
la classe reste découplée des implémentations concrètes,
car elle ne dialogue qu'avec l'interface de EncryptionEngine.
Et la persistance CSV reste volontairement hors de cette couche,
dans le script appelant.

#### Segment 1 - Lignes 29 à 46, dataclass ExperimentResult
On commence par la structure de sortie, qui conditionne toute l'analyse.
**(Surligne ligne 29 - décorateur dataclass)** Le choix dataclass formalise un conteneur de mesure clair et typé.
**(Surligne lignes 33-37 - paramètres d'identification de l'essai)** On capture le contexte expérimental: algorithme, mode, taille de clé, taille du message, nombre de répétitions.
**(Surligne lignes 38-45 - métriques de performance et robustesse)** On stocke ensuite les grandeurs utiles à l'interprétation: temps moyens, débits, avalanche texte, avalanche clé, et intervalles de confiance à 95 %.
Cette séparation entre contexte et métriques est très saine:
elle rend les résultats lisibles, exportables et comparables sans ambiguïté.

#### Segment 2 - Ligne 63, constructeur d'ExperimentController
Ensuite, regardons l'initialisation de la classe.
**(Surligne ligne 63 - signature du constructeur)** Le contrôleur reçoit un moteur déjà configuré, plus deux libellés d'identification.
**(Surligne lignes 69-71 - stockage interne)** Ces valeurs sont conservées comme état minimal de l'orchestrateur.
Le point clé, c'est la séparation rôle/fonction:
les deux noms servent uniquement à étiqueter les résultats,
pas à piloter le chiffrement lui-même.

#### Segment 3 - Lignes 108 à 110, chronométrage du chiffrement dans run_performance
Ici, on entre dans le cœur méthodologique des mesures.
**(Surligne ligne 102 - génération d'un plaintext fixe)** Le message aléatoire est créé une seule fois pour assurer la comparabilité entre répétitions.
**(Surligne lignes 108-110 - fenêtre de mesure encrypt)** Le chronométrage encadre strictement l'appel à encrypt via time.perf_counter.
C'est une bonne pratique expérimentale:
on mesure le coût cryptographique utile,
et on limite l'influence des surcoûts périphériques de l'environnement d'exécution.

#### Segment 4 - Lignes 117 à 119, chronométrage du déchiffrement
Le même protocole est ensuite reproduit côté déchiffrement.
**(Surligne ligne 114 - last_ct issu du chiffrement précédent)** Le test s'appuie sur un ciphertext réellement produit par la phase de chiffrement.
**(Surligne lignes 117-119 - fenêtre de mesure decrypt)** Le minuteur encadre uniquement decrypt, comme pour encrypt.
Résultat:
les deux mesures restent symétriques dans la méthode,
et donc plus fiables pour comparer les coûts aller/retour.

#### Segment 5 - Ligne 127, calcul de l'intervalle de confiance a 95%
Ici, on est dans la partie statistique la plus importante du fichier.
**(Surligne ligne 127 - début du calcul d'incertitude)** Le contrôleur calcule une marge d'erreur autour du débit mesuré.
**(Surligne lignes 131-132 - dispersion des temps)** D'abord, il mesure à quel point les temps varient d'une répétition à l'autre.
**(Surligne lignes 133-136 - conversion en incertitude de débit)** Ensuite, il transforme cette variation en marge d'incertitude, avec un seuil à 95 %.
En clair:
on ne regarde pas seulement une moyenne,
on regarde une moyenne accompagnée de son niveau de confiance.

#### Segment 6 - Lignes 142 à 159, assemblage du résultat final
Ici, tout est rassemblé dans un seul résultat.
**(Surligne lignes 142-156 - création du résultat final)** On retrouve dans le même bloc l'identité du test, les performances, les scores d'avalanche et l'intervalle de confiance.
**(Surligne lignes 150-151 - calcul du débit avec protection)** Le débit est calculé à partir du temps moyen, avec une sécurité pour éviter la division par zéro.
**(Surligne lignes 152-153 - calcul des deux scores d'avalanche)** Le score côté texte et le score côté clé sont ajoutés au même moment.
En résumé:
on sort une mesure complète,
directement exploitable pour l'analyse.

#### Segment 7 - Lignes 162 à 212, avalanche sur le texte
Cette méthode mesure l'effet d'avalanche quand on modifie le message d'entrée.
**(Surligne ligne 162 - méthode répétée 200 fois)** Le test est répété 200 fois pour rendre le résultat plus stable.
**(Surligne lignes 193-194 - bloc aléatoire puis chiffrement de référence)** On commence par créer une sortie de référence.
**(Surligne lignes 197-200 - inversion d'un seul bit)** Ensuite, on change exactement un bit dans l'entrée.
**(Surligne lignes 205-209 - comparaison bit à bit)** On compare les deux sorties pour compter combien de bits ont changé.
**(Surligne ligne 211 - moyenne finale)** On calcule ensuite la moyenne de tous les essais.
La cible théorique est autour de 0,5:
changer un seul bit en entrée devrait modifier environ la moitié des bits en sortie.

#### Segment 8 - Lignes 213 à 270, avalanche sur la clé
Dans ce dernier segment, on présente la mesure d'avalanche côté clé.
L'idée est simple: on garde le même message, et on modifie uniquement la clé.
**(Surligne ligne 213 - méthode répétée 200 fois)** Le principe statistique reste le même, avec plusieurs essais.
**(Surligne lignes 252-255 - inversion d'un bit dans la clé)** On crée une clé légèrement modifiée en changeant un seul bit.
**(Surligne ligne 260 - nouvelle primitive avec la clé modifiée)** Puis on compare le chiffrement avec la clé d'origine et avec la clé modifiée.
**(Surligne lignes 261-263 - gestion des cas invalides)** Si la clé modifiée pose problème, le code continue au lieu de faire échouer toute la campagne.
**(Surligne lignes 267-271 - comparaison bit à bit)** On mesure encore la différence de sortie, puis on moyenne sur tous les essais.
Ce bloc est important en pratique:
il permet d'évaluer la sensibilité à la clé,
tout en gardant une exécution robuste.

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
Dans cette section, on présente le script principal qui lance toute la campagne de mesures.
On va suivre son déroulement logique:
la définition des paramètres,
puis l'exécution des tests,
et enfin l'écriture des résultats dans le CSV.

#### Segment 1 - Lignes 1 à 17, docstring
Pour commencer, on présente le rôle global du script.
**(Surligne lignes 11-14 - rôle global du script)** Le docstring dit clairement que ce fichier parcourt la matrice d'expériences, lance les mesures et écrit un CSV horodaté.
**(Surligne lignes 16-17 - séparation des responsabilités)** Point essentiel pour l'architecture: aucune logique cryptographique n'est implémentée ici.
Ce script sert surtout de point d'entrée,
entre les couches métier et les entrées-sorties.

#### Segment 2 - Lignes 51 à 70, REPETITIONS et EXPERIMENT_MATRIX
Dans ce segment, on lit la configuration des tests.
**(Surligne ligne 51 - REPETITIONS)** Ici, le script fixe 100 répétitions par test.
**(Surligne lignes 53-70 - EXPERIMENT_MATRIX)** Ici, on voit la liste complète des combinaisons.
**(Surligne ligne 58 - entrée AES-GCM)** Exemple: AES est testé en mode GCM.
**(Surligne ligne 69 - entrée ChaCha20-StreamMode)** Et ici, ChaCha20 passe par StreamMode avec une clé de 32 octets.
Conclusion simple:
si on veut ajouter un scénario,
on modifie la matrice,
pas la logique du script.

#### Segment 3 - Ligne 72, MESSAGE_SIZES
À ce stade, on précise les tailles de message utilisées.
**(Surligne ligne 72 - MESSAGE_SIZES)** Le script teste de 64 à 16384 octets.
Ça couvre à la fois les petits messages,
où les coûts fixes pèsent plus lourd,
et les gros messages,
où le débit réel se voit mieux.

#### Segment 4 - Lignes 102 à 107, vérification préalable de la clé
Avant d'entrer dans la boucle de mesure,
le script fait une vérification rapide de la clé.
**(Surligne lignes 103-105 - instanciation de vérification)** Il essaie d'instancier la primitive avec une clé de test.
**(Surligne lignes 106-107 - gestion d'échec)** Si cette étape échoue,
le cas est ignoré proprement,
et la campagne continue sans interruption.
Cette garde évite qu'une erreur locale
fasse échouer tout le benchmark.

#### Segment 5 - Lignes 110 à 135, boucle principale d'exécution
Ici, on est dans la boucle principale.
Pour chaque taille de message,
le script prépare toute la chaîne de traitement.
**(Surligne lignes 111-116 - construction de la chaîne d'exécution)** Il crée la primitive, le mode, le moteur, puis le contrôleur.
**(Surligne lignes 124-127 - appel run_performance)** Ensuite, il lance la mesure avec la taille courante et le nombre de répétitions.
**(Surligne ligne 128 - accumulation des résultats)** Le résultat est ajouté à la liste finale.
**(Surligne lignes 129-133 - sortie terminal)** Et le terminal affiche immédiatement les indicateurs clés: temps de chiffrement, débit, avalanche.

#### Segment 6 - Lignes 143 à 149, écriture du CSV
Pour terminer, on passe à l'export.
Une fois la campagne finie,
le script écrit tout dans un CSV horodaté.
**(Surligne ligne 143 - définition des colonnes)** D'abord, il récupère la liste des colonnes.
**(Surligne lignes 145-146 - initialisation du writer + en-tête)** Ensuite, il crée l'écrivain CSV et écrit l'en-tête.
**(Surligne lignes 147-148 - écriture des lignes)** Puis il écrit les résultats, ligne par ligne.
C'est ce fichier final
qu'on ouvre juste après l'exécution.

### Basculer vers VS Code et ouvrir le terminal integre
---
On passe maintenant dans Visual Studio Code pour lancer l'expérience en direct.

### Taper et executer python scripts/experiment.py
---
Je lance la commande `python scripts/experiment.py`.
Je suis déjà dans le bon dossier,
donc elle s'exécute directement.

### Laisser défiler le terminal — version accélérée
---
Le script parcourt maintenant toute la matrice d'expériences.
Chaque combinaison d'algorithme, de mode, de taille de clé et de taille de message est testée.
Chaque mesure est répétée cent fois.
L'exécution complète prend plusieurs minutes, donc la suite est accélérée.
On voit les résultats défiler dans le terminal,
avec le temps moyen, le débit,
et le score d'avalanche pour chaque configuration.

> **Note de tournage** : garder les 10 à 15 premières secondes en temps réel,
> idéalement sur une configuration AES rapide pour que ça bouge bien à l'écran,
> puis accélérer à 4× jusqu'à la fin.
> Éviter de couper pile sur les runs 3DES — c'est la portion la plus lente
> et ça pourrait paraître étrange en accéléré si la progression semble figée
> plus longtemps que les autres.

### Ouvrir le CSV généré
---
À la fin de l'exécution,
le terminal confirme l'emplacement du fichier généré.
Un CSV horodaté est créé dans data/results.
Il contient une ligne par configuration,
avec tous les indicateurs mesurés:
temps de chiffrement et de déchiffrement,
débit,
scores d'avalanche,
et intervalles de confiance.
C'est ce fichier brut
qui servira de base à l'analyse comparative des prochaines vidéos.


