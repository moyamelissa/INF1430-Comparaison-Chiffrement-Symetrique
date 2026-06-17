Excellent Rapport. Tres bonne présentation et structuration du code source (Git). J'ai laissé quelques commentaire dans le document ci-joint. Pour Le TN3, il serait préférable de prépaper une courte video montant le logiciel en action. Donc, une presentation PPT accompagnée d'une video de demonstration.


Feedback 1 
Section : 3.1 Nature du système 
Le système à développé développer est un logiciel technique et algorithmique dont l’objectif principal est de réaliser des expérimentations comparatives rigoureuses sur des schémas de chiffrement symétrique paramétrables. Il est orienté vers le calcul et l’orchestration d’algorithmes, et conçu pour exécuter et évaluer différentes configurations cryptographiques dans un environnement contrôlé, garantissant la répétabilité des mesures.
Contrairement à une application logicielle orientée utilisateur, le système ne comporte ni interface graphique ni scénarios d’utilisation métier. Il agit comme un moteur expérimental, chargé d’assembler, d’exécuter et de comparer des primitives et des modes d’opération. Cette spécialisation permet d’isoler les indicateurs de performance temporelle des indicateurs de sécurité, tels que l’effet d’avalanche, la diffusion et la confusion, en traitant ces derniers comme des propriétés intrinsèques aux algorithmes, indépendantes de l'environnement logiciel.
Bien que la cryptographie symétrique inclue également les chiffrements par flot, ce projet se concentre principalement sur les chiffrements par blocs, tout en intégrant ChaCha20 comme représentant des chiffrements par flot, encapsulé via un « StreamMode » dédié. Ce choix est motivé par trois facteurs:
1.	Conformité au mandat : L'objectif est d'analyser l'impact de paramètres spécifiques aux blocs (taille de bloc, modes de chaînage).
2.	Polyvalence des modes : L'utilisation des modes CTR (Counter) et GCM (Galois/Counter Mode, standardisé par le NIST SP 800-38D) permet de transformer un chiffrement par blocs en un mécanisme de type flot, couvrant ainsi fonctionnellement les enjeux de performance liés au traitement continu des données. Le choix de GCM est également motivé par sa conformité aux standards industriels actuels, ce mode offrant conjointement confidentialité et authentification intégrée, contrairement à des modes plus anciens tels que l’OFB.
3.	Analyse de la robustesse : Les algorithmes par blocs offrent un cadre de comparaison plus riche pour l'étude des mécanismes de substitution et de permutation, piliers de la robustesse cryptographique moderne.
Cette nature spécialisée oriente directement les choix de conception, car elle favorise une organisation centrée sur les abstractions du domaine cryptographique et une séparation stricte des responsabilités. En éliminant les couches dédiées à l’interaction utilisateur, l'architecture minimise les biais potentiels et renforce la neutralité du cadre expérimental (assurée par l'abstraction logicielle de Python) nécessaire à la validation rigoureuse des hypothèses de recherche.
Cette définition de la nature technique du système justifie l'adoption d'une approche de conception capable de modéliser avec précision ces exigences algorithmiques, à savoir la démarche orientée domaine.

Teachers comment: Un environnement contrôlé ne garantit pas nécessairement la répétabilité. Il faut que les primitives utilisées soient indépendantes du système OS utilisés ou paramétrables.

Feedback 2 
Section : 4.5 Diagramme de séquence
Teachers comment: Pourquoi n répétitions? Quel serait la valeur de n?

Feedback 3
Section : 5.2 Environnement technique effectif
La solution est développée en Python, un langage retenu à l'issue d'une évaluation comparative des alternatives disponibles. C++, bien que privilégié en cryptographie pour ses performances brutes, introduit une complexité de gestion mémoire et une dépendance aux optimisations du compilateur qui auraient nui à la reproductibilité des mesures entre plateformes. Java, quant à lui, impose une verbosité architecturale et une machine virtuelle (JVM) dont le comportement d'optimisation dynamique (JIT) constitue une source de biais difficilement contrôlable dans un cadre expérimental rigoureux. 

Teachers comment: Mais, il permet l’optimisation des implémentations pour sons accès aux primitives de bas niveau.

Feedback 4
Section : 5.2 Environnement technique effectif
Il convient toutefois de préciser que PyCryptodome délègue les opérations cryptographiques critiques à des routines C optimisées. Cette caractéristique ne compromet pas la neutralité, dans la mesure où ces routines binaires sont identiques sur les deux plateformes testées : la comparaison porte ainsi sur le comportement du même code natif soumis à des contraintes matérielles différentes, ce qui constitue précisément l'objet de la mesure.

Teachers comment: L’encodage des données peut jouer des tours d’une plateforme a une autre: Linux vs Windows par exemple.

Feedback 5
Section : 7.3 Premières expérimentations
Les premières campagnes expérimentales ont été initiées sur la plateforme Windows (x86-64), suivant une approche de développement incrémental. Elles constituent une phase de tests d'intégration du système dont les objectifs sont les suivants :
1.	Validation de la chaîne d'exécution : vérifier la collaboration entre les scripts de lancement, le contrôleur d'expérimentation et le moteur de chiffrement afin d'assurer un flux de données sans interruption.
2.	Vérification de la portabilité : confirmer que l'artefact logiciel s'exécute de manière identique sur l'ordinateur personnel et sur le Raspberry Pi, garantissant ainsi la neutralité du cadre expérimental.
3.	Fiabilité de la collecte : s'assurer que le bloc d'analyse génère correctement les fichiers de résultats structurés, en distinguant les mesures de performance temporelle (débit) des indicateurs de robustesse sécuritaire (effet d'avalanche).
4.	Validation des indicateurs de sécurité : mesurer l'effet d'avalanche pour chaque primitive, conformément au protocole de distance de Hamming établi, afin d'évaluer les propriétés de diffusion et de confusion intrinsèques aux algorithmes.
5.	Analyse de l'influence du nombre de tours : étudier l'évolution du score d'avalanche en fonction du nombre de tours effectués par chaque primitive, afin d'identifier le seuil de convergence vers un score maximal et de caractériser la contribution structurelle des tours à la diffusion cryptographique.
Ces essais préliminaires sécurisent la phase de collecte systématique des mesures, indispensable pour valider ou infirmer les hypothèses de recherche lors des étapes ultérieures du projet.

Teachers comment : Pous pouvez aussi comparer les résultats expérimentaux avec ceux présentés dans la literature (le livre de stallings par exemple)