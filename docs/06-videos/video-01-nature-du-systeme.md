# Vidéo 1 - Nature du système

## Objectif
Présenter l'architecture du projet et montrer, par le code, comment les couches interagissent pour produire un résultat expérimental traçable.

## Portée
- Racine du dépôt et structure du dossier crypto-experiments
- domain/cipher, domain/mode, domain/engine
- application/ExperimentController.py
- scripts/experiment.py
- Exécution en direct et génération du CSV

## Guide d'enregistrement

### Section 1 - Introduction et presentation du projet
Bonjour et bienvenue dans cette première vidéo, où je présente mon projet sur l'Analyse Comparative des Chiffrements Symétriques. L'objectif est simple, établir une lecture technique claire du système avant toute interprétation des résultats. Nous allons d'abord cadrer la structure globale du dépôt, puis ouvrir le coeur d'exécution dans crypto-experiments, et enfin suivre le chemin complet qui mène des composants logiciels aux sorties expérimentales.

Commençons par la structure de haut niveau du projet. Le fichier README.md sert de point d'entrée technique et présente les objectifs, l'architecture et les procédures d'exécution. Le dossier .github/workflows porte la chaîne d'intégration continue, donc les contrôles automatiques à chaque mise à jour du dépôt. Le dossier Resources regroupe les références techniques et méthodologiques, puis docs formalise le cadre académique avec les consignes, les analyses, le plan de présentation et les scripts vidéo.

On se concentre ensuite sur crypto-experiments, car c'est le noyau d'exécution et la zone centrale du TN3. Le dossier application orchestre les campagnes, domain implémente les abstractions et la logique cryptographique, puis scripts fournit les points d'entrée opérationnels. Le dossier validation vérifie la conformité avec les tests KAT, tandis que tests couvre les contrôles de non-régression. Le dossier data conserve les artefacts produits, soit les tableaux de résultats et les graphiques. Enfin, requirements.txt fixe les dépendances logicielles, pytest.ini définit la configuration de test et coverage.xml documente la couverture mesurée.

Pour relier cette vue d'ensemble à la suite, déroulons le chemin de travail. Maintenant que la structure est posée, on passe à l'exploration guidée des fichiers. D'abord, on identifie les points d'entrée dans scripts. Ensuite, on voit comment application orchestre les campagnes expérimentales. Puis, on descend dans domain pour l'exécution cryptographique. Finalement, on ferme la boucle avec validation et tests, puis on confirme la traçabilité des sorties dans data.

### Section 2 - Contrat des primitives cryptographiques
**Titre :** Contrat, invariants et extensibilité des algorithmes

**Fichier / zone à montrer :** domain/cipher/CipherPrimitive.py

**Intro :**
CipherPrimitive.py pose le contrat de base de toute l'architecture cryptographique. Avant d'aller plus loin, clarifions un terme. Une primitive cryptographique, c'est l'algorithme fondamental qui effectue l'opération de chiffrement au niveau le plus bas. C'est la brique élémentaire. Elle reçoit un bloc d'octets, applique une transformation mathématique, et retourne un bloc chiffré. AES, DES, TripleDES et Twofish sont des primitives de ce type. Ce sont des chiffrements par blocs.

Ce fichier ne définit aucun de ces algorithmes concrètement. Il définit uniquement les règles que chaque primitive devra respecter. Et c'est ce cadre commun qui rend nos comparaisons valides. AES, DES, TripleDES et Twofish passent tous par la même interface, dans les mêmes conditions et avec la même surface d'appel.

Une nuance importante à mentionner. ChaCha20 n'emprunte pas ce même chemin. ChaCha20 est un chiffrement par flot, pas par blocs. Il ne chiffre pas des blocs de taille fixe. À la place, il génère un flux de clés continu qu'il combine directement avec le message. Pour accommoder ce comportement différent, on lui a créé un wrapper spécialisé appelé StreamMode. Un wrapper, c'est une enveloppe logicielle qui adapte une interface existante sans modifier la logique interne. Ici, StreamMode agit comme un adaptateur qui permet à ChaCha20 de s'intégrer dans le même pipeline de mesure que les autres algorithmes, même si son fonctionnement interne est fondamentalement différent. C'est pour cette raison qu'on ne verra pas ChaCha20 dans CipherPrimitive, mais qu'il reste pleinement intégré au reste de l'architecture.

**Code à montrer :**
```python
class CipherPrimitive(ABC):
    @property
    @abstractmethod
    def block_size(self) -> int:
        ...

    @property
    @abstractmethod
    def key_size(self) -> int:
        ...

    @abstractmethod
    def encrypt_block(self, block: bytes) -> bytes:
        ...

    @abstractmethod
    def decrypt_block(self, block: bytes) -> bytes:
        ...

    def encrypt_blocks(self, data: bytes) -> bytes:
        bs = self.block_size
        if len(data) % bs != 0:
            raise ValueError(...)
        ...
```

**Narration ligne par ligne :**

Maintenant que le rôle du contrat est clair, on peut lire le code dans l'ordre et voir comment cette abstraction est appliquée concrètement.

On commence avec `class CipherPrimitive(ABC)`. L'idée clé ici, c'est qu'on définit une classe abstraite, donc une classe qu'on n'instancie jamais directement. Son rôle est de fixer le contrat que toutes les primitives concrètes devront respecter.

Ensuite, les décorateurs `property` et `abstractmethod` sur `block_size` et `key_size` imposent une interface stable. Chaque algorithme doit exposer ces deux informations de façon cohérente. Par exemple, AES renvoie 16 octets, donc 128 bits, et DES renvoie 8 octets, donc 64 bits. Ces valeurs servent ensuite de référence partout dans le moteur.

Puis, avec `encrypt_block` et `decrypt_block`, on pose les deux opérations fondamentales. Elles travaillent toujours sur un bloc de taille fixe, exactement `block_size` octets. C'est cette granularité qui permet ensuite aux modes comme CBC, CTR ou GCM de construire leur logique propre.

Enfin, `encrypt_blocks` traite le message complet avec une validation explicite. Le code vérifie d'abord que la longueur est un multiple de `block_size`. Si ce n'est pas le cas, il lève immédiatement `ValueError`. Ce garde-fou évite les erreurs silencieuses et garantit un comportement prévisible. Si une implémentation dispose d'un chemin natif plus efficace, elle peut surcharger cette méthode pour traiter les données en une seule passe.

**Flux du processus :**
Avec ce contrat en place, la lecture du flux devient plus naturelle. ExperimentController orchestre l'expérience, EncryptionEngine délègue au mode, puis le mode s'appuie sur CipherPrimitive. Cette chaîne garantit que les primitives restent interchangeables et que les écarts observés viennent bien des algorithmes eux-mêmes, pas d'un changement de méthode. On peut maintenant passer à l'implémentation concrète avec AES.

### Section 3 - Exemple concret de primitive (AES)
**Titre :** Implémentation concrète d'une primitive

**Fichier / zone à montrer :** domain/cipher/AES.py

**Intro :**
AES.py montre comment une primitive concrète applique le contrat abstrait. L'intérêt ici n'est pas seulement de voir un algorithme, mais de comprendre comment une primitive réelle s'insère dans notre architecture sans casser l'abstraction commune.

**Code à montrer :**
```python
from Crypto.Cipher import AES as _AES

class AES(CipherPrimitive):
    BLOCK_SIZE = 16

    def __init__(self, key: bytes) -> None:
        if len(key) not in _VALID_KEY_SIZES:
            raise ValueError(...)
        self._key = key

    def encrypt_block(self, block: bytes) -> bytes:
        cipher = _AES.new(self._key, _AES.MODE_ECB)
        return cipher.encrypt(block)

    def encrypt_blocks(self, data: bytes) -> bytes:
        return _AES.new(self._key, _AES.MODE_ECB).encrypt(data)
```

**Narration ligne par ligne :**

Maintenant que la place de cette primitive dans l'architecture est claire, on peut suivre le code dans l'ordre pour voir comment AES concrétise le contrat.

line 12 On commence par importer l'implémentation AES de PyCryptodome, et le suffixe `_AES` sert simplement à éviter toute confusion avec notre classe métier `AES`.

line 19 - Ensuite, la classe `AES` hérite de `CipherPrimitive`, ce qui la rattache directement au contrat abstrait défini plus tôt. Cela signifie qu'elle doit respecter la même interface que les autres primitives.

line 22 - La constante `BLOCK_SIZE = 16` fixe la taille de bloc à 16 octets, donc 128 bits. Cette valeur structure tout le reste, autant la validation des entrées que l'intégration avec les modes.

line 24 - Dans la méthode `__init__` de `AES`, la clé reçue est validée immédiatement contre les tailles autorisées, 16, 24 ou 32 octets. Si la taille est invalide, une `ValueError` est levée tout de suite. Ce comportement fail-fast évite de propager une instance incohérente dans la suite de l'exécution.

line 54,59,60 - Puis `encrypt_block` chiffre un seul bloc en s'appuyant sur PyCryptodome. Le mode ECB est utilisé ici comme brique interne de traitement bloc par bloc, et non comme recommandation de sécurité globale.

line 72 - Enfin, `encrypt_blocks` prend le chemin optimisé pour les messages multi-blocs. Au lieu de boucler en Python, on confie le traitement complet à PyCryptodome. Le résultat est plus proche du comportement réel du moteur et plus pertinent pour la mesure de performance.

**Flux du processus :**
Avec cette implémentation en tête, le trajet d'exécution devient très lisible. ExperimentController déclenche l'opération, EncryptionEngine relaie vers le mode, puis le mode s'appuie sur AES pour exécuter le chiffrement ou le déchiffrement. AES valide la clé, applique la primitive, puis renvoie un résultat conforme au contrat. On peut maintenant passer à la couche suivante, le contrat des modes d'opération.

### Section 4 - Contrat des modes d'opération
**Titre :** Comment le système gère ECB/CBC/CTR/GCM

**Fichier / zone à montrer :** domain/mode/OperationMode.py

**Intro :**
OperationMode.py introduit la couche qui transforme un chiffrement de bloc en chiffrement de message. Le mode d'opération définit la logique de chaînage, de compteur ou d'authentification, tout en restant découplé de l'algorithme concret.

**Code à montrer :**
```python
class OperationMode(ABC):
    def __init__(self, primitive: CipherPrimitive) -> None:
        self._primitive = primitive

    @abstractmethod
    def encrypt(self, plaintext: bytes, **kwargs) -> bytes:
        ...

    @abstractmethod
    def decrypt(self, ciphertext: bytes, **kwargs) -> bytes:
        ...
```

**Narration ligne par ligne :**

line 16 - Maintenant que la primitive est bien cadrée, on voit la couche qui pilote la logique de mode. Avec `class OperationMode(ABC)`, on définit un contrat commun à tous les modes, pour garder une interface stable même si l'implémentation interne change.

line 19 - Dans la méthode `__init__` de `OperationMode`, la primitive est injectée explicitement. C'est une composition volontaire. Le mode ne chiffre jamais seul, il orchestre une primitive déjà validée.

line 33 - Ensuite, la méthode `encrypt` formalise le chiffrement d'un message complet. Les paramètres variables passent par `kwargs`, c'est-à-dire des arguments nommés transmis de façon flexible, par exemple le vecteur d'initialisation, une valeur unique, un compteur, ou encore des données authentifiées mais non chiffrées, selon le mode choisi.

line 51 - Enfin, `decrypt` impose la symétrie du contrat. Chaque mode doit fournir un chemin de déchiffrement cohérent avec sa logique de chiffrement.

**Flux du processus :**
Avec cette couche en place, le flux devient très lisible. EncryptionEngine appelle le mode, le mode applique sa logique de transformation de message, puis délègue les opérations élémentaires à la primitive. Ce découplage permet de changer de mode sans réécrire l'algorithme sous-jacent. On peut maintenant passer au point d'assemblage du domaine avec EncryptionEngine.

### Section 5 - Point d'assemblage du domaine
**Titre :** Rôle de EncryptionEngine

**Fichier / zone à montrer :** domain/engine/EncryptionEngine.py

**Intro :**
EncryptionEngine est la façade du domaine cryptographique. Cette classe centralise la composition primitive plus mode et offre à l'application un point d'entrée stable, sans exposition des détails internes.

**Code à montrer :**
```python
class EncryptionEngine:
    def __init__(self, primitive: CipherPrimitive, mode: OperationMode) -> None:
        if mode.primitive is not primitive:
            raise ValueError(...)
        self._primitive = primitive
        self._mode = mode

    def encrypt(self, plaintext: bytes, **kwargs) -> bytes:
        return self._mode.encrypt(plaintext, **kwargs)
```

**Narration ligne par ligne :**

line 16 - Maintenant qu'on a séparé clairement la primitive et le mode, `EncryptionEngine` joue le rôle de point d'assemblage. Cette classe relie les deux contrats dans un service unique, avec une interface stable pour la couche application.

line 29 - Dans la méthode `__init__`, c'est-à-dire le constructeur appelé au moment de l'instanciation, les deux dépendances reçues explicitement sont la primitive et le mode d'opération, puis la composition est verrouillée immédiatement.

line 30 - La condition `if mode.primitive is not primitive` vérifie un invariant d'identité objet. L'idée est simple, le mode doit travailler avec exactement la même primitive que celle fournie au moteur. Sinon, on introduit une incohérence silencieuse.

line 31 - Si cet invariant est violé, `ValueError` est levée immédiatement. Ce comportement fail-fast protège la validité cryptographique avant toute mesure.

line 36 and 37 - Ensuite, `self._primitive` et `self._mode` deviennent la configuration stable du moteur pour toute l'expérience.

line 51 - Enfin, la méthode `encrypt` ne réimplémente pas la cryptographie. Elle délègue directement au mode, ce qui maintient une séparation des responsabilités claire et garde le moteur centré sur l'orchestration.

**Flux du processus :**
À ce stade, on peut formaliser le passage application vers domaine. Au final, le flux est le suivant. L'application crée la primitive, construit le mode avec cette même primitive, puis instancie EncryptionEngine. Ensuite, toute l'exécution passe par cette façade, avec une API stable et indépendante des choix concrets.

### Section 6 - Orchestration des mesures
**Titre :** Rôle de ExperimentController

**Fichier / zone à montrer :** application/ExperimentController.py

**Intro :**
ExperimentController est la couche qui transforme une exécution cryptographique en mesures exploitables pour la comparaison. À ce stade, on passe de l'architecture logicielle à la logique scientifique.

**Code à montrer :**
```python
@dataclass
class ExperimentResult:
    algorithm: str
    mode: str
    message_size_bytes: int
    throughput_encrypt_mbps: float
    avalanche_score: float
    ci95_encrypt_mbps: float

class ExperimentController:
    def run_performance(self, message_size_bytes: int, repetitions: int) -> ExperimentResult:
        ...
```

**Narration ligne par ligne :**

Maintenant que le rôle de la couche scientifique est posé, on peut suivre la structure de `ExperimentResult` et la méthode `run_performance` dans l'ordre.

line 29 - On commence avec `@dataclass` appliqué à `ExperimentResult`. Cela définit un format de sortie explicite et typé pour chaque expérience, avec les mêmes champs pour toutes les configurations.

Les champs `algorithm` et `mode` conservent l'identité exacte du cas testé, c'est-à-dire l'algorithme et le mode d'opération. Sans ce contexte, les résultats seraient difficiles à comparer proprement.

Ensuite, `message_size_bytes` indique la charge réellement traitée, tandis que `throughput_encrypt_mbps` capture la performance de chiffrement correspondante en mégabits par seconde.

Le champ `avalanche_score` décrit la diffusion cryptographique observée, et `ci95_encrypt_mbps` ajoute l'intervalle de confiance à 95 % autour du débit mesuré. On garde donc robustesse et fiabilité statistique dans la même structure.

line 77 - Enfin, la méthode `run_performance`, avec les paramètres `message_size_bytes` et `repetitions`, orchestre la campagne pour une configuration donnée. Elle exécute les répétitions, chronomètre, agrège les mesures, puis retourne un `ExperimentResult` complet.

**Flux du processus :**
Pour passer de la logique logicielle à la logique scientifique, voici le fil de calcul. Concrètement, le flux se déroule ainsi. run_performance appelle le moteur, collecte les séries temporelles, calcule les indicateurs agrégés et retourne un objet structuré prêt pour l'export CSV et l'analyse comparative.

### Section 7 - Point d'entrée expérimental
**Titre :** Lancement de la matrice de tests

**Fichier / zone à montrer :** scripts/experiment.py

**Intro :**
scripts/experiment.py est le pilote d'exécution global. Ce script parcourt toutes les configurations définies et déclenche systématiquement la même procédure de mesure.

**Code à montrer :**
```python
REPETITIONS = 100
MESSAGE_SIZES = [64, 256, 1024, 4096, 16384]

for algo, primitive_cls, mode_label, mode_cls, key_sizes in EXPERIMENT_MATRIX:
    ...
    result = controller.run_performance(
        message_size_bytes=msg_size,
        repetitions=REPETITIONS,
    )
```

**Narration ligne par ligne :**

Maintenant que le rôle global du script est clair, on peut dérouler ses éléments clés dans l'ordre d'exécution.

line 51 - La constante `REPETITIONS = 100` fixe explicitement le nombre d'itérations par configuration. Ce choix réduit la variance des mesures et améliore la stabilité statistique.

line 72 - La liste `MESSAGE_SIZES = [64, 256, 1024, 4096, 16384]` définit précisément les tailles de messages testées, du cas court au volume plus élevé.

line 100 - Ensuite, on parcourt `EXPERIMENT_MATRIX` avec une boucle `for` Python, qui itère séquentiellement sur une liste de tuples, une configuration à la fois. Chaque entrée regroupe l'algorithme, la primitive associée, le mode d'opération et les tailles de clé à tester.

line 124 - À l'intérieur de la boucle, on instancie la configuration courante puis on délègue la mesure à `controller.run_performance(...)`. Le script garde donc son rôle d'orchestrateur, sans réimplémenter la logique de calcul.

Pour chaque cas, la couche application retourne un résultat structuré, qui sera ensuite accumulé et exporté dans le CSV final.

**Flux du processus :**
Dans une perspective d'orchestration complète, voici la séquence à retenir. On peut donc résumer le flux comme suit. scripts/experiment.py instancie les objets du domaine, appelle ExperimentController pour chaque configuration, accumule les résultats de manière traçable, puis déclenche l'export CSV final.

### Section 8 - Démonstration en direct
**Titre :** Exécution et preuve de sortie

**Fichier / zone à montrer :** terminal + data/results/

**Intro :**
La démonstration en direct valide la chaîne complète dans des conditions réelles d'exécution. Elle sert de preuve opérationnelle que le protocole produit bien des artefacts exploitables.

**Commande à montrer :**
```powershell
python scripts/experiment.py
```

**Narration ligne par ligne :**

Maintenant que le protocole est défini, on peut lire la démonstration en direct dans l'ordre réel d'exécution.

La commande `python scripts/experiment.py` lance la campagne complète selon la matrice définie dans le script.

Pendant l'exécution, la sortie terminal affiche la progression configuration par configuration. On peut donc vérifier en direct quelles combinaisons sont en cours, lesquelles sont terminées, et si une étape échoue.

En fin d'exécution, le script écrit un fichier CSV horodaté dans `data/results`. Cet artefact fige les résultats bruts et sert de base traçable pour l'analyse ultérieure.

**Flux du processus :**
Pour conclure la démonstration, reprenons le fil d'exécution de façon simple. Le terminal lance scripts/experiment.py. Ensuite, chaque cas d'essai passe par ExperimentController puis par EncryptionEngine. La campagne se termine avec un CSV enregistré dans data/results.

### Conclusion
Cette vidéo pose les bases techniques du projet. On a maintenant une architecture modulaire claire, des invariants explicites, une chaîne d'exécution cohérente et des artefacts traçables. Dans la suite, on pourra justifier la méthodologie expérimentale sur une base logicielle déjà vérifiée.
