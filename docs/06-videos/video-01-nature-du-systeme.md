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

### Section 0 - Introduction
Bonjour et bienvenue dans cette première vidéo, où je présente mon projet sur l'Analyse Comparative des Chiffrements Symétriques. L'objectif est simple, établir une lecture technique claire du système avant toute interprétation des résultats. Nous allons d'abord cadrer la structure globale du dépôt, puis ouvrir le coeur d'exécution dans crypto-experiments, et enfin suivre le chemin complet qui mène des composants logiciels aux sorties expérimentales.

### Section 1 - Vue d'ensemble du dépôt
**Titre :** Identifier le périmètre technique

**Fichier / zone à montrer :** racine du dépôt puis dossier crypto-experiments/

**Code / arborescence à montrer :**
```text
INF1430-Comparaison-Chiffrement-Symetrique/
├── .github/workflows/
├── Resources/
├── crypto-experiments/
├── docs/
└── README.md
```

**Narration fluide :**
Commençons par la structure de haut niveau du projet. Le fichier README.md sert de point d'entrée technique et présente les objectifs, l'architecture et les procédures d'exécution. Le dossier .github/workflows porte la chaîne d'intégration continue, donc les contrôles automatiques à chaque mise à jour du dépôt. Le dossier Resources regroupe les références techniques et méthodologiques, puis docs formalise le cadre académique avec les consignes, les analyses, le plan de présentation et les scripts vidéo.

On se concentre ensuite sur crypto-experiments, car c'est le noyau d'exécution et la zone centrale du TN3. Le dossier application orchestre les campagnes, domain implémente les abstractions et la logique cryptographique, puis scripts fournit les points d'entrée opérationnels. Le dossier validation vérifie la conformité avec les tests KAT, tandis que tests couvre les contrôles de non-régression. Le dossier data conserve les artefacts produits, soit les tableaux de résultats et les graphiques. Enfin, requirements.txt fixe les dépendances logicielles, pytest.ini définit la configuration de test et coverage.xml documente la couverture mesurée.

**Flux du processus :**
Pour relier cette vue d'ensemble à la suite, déroulons le chemin de travail. Maintenant que la structure est posée, on passe à l'exploration guidée des fichiers. D'abord, on identifie les points d'entrée dans scripts. Ensuite, on voit comment application orchestre les campagnes expérimentales. Puis, on descend dans domain pour l'exécution cryptographique. Finalement, on ferme la boucle avec validation et tests, puis on confirme la traçabilité des sorties dans data.

### Section 2 - Contrat des primitives cryptographiques
**Titre :** Contrat, invariants et extensibilité des algorithmes

**Fichier / zone à montrer :** domain/cipher/CipherPrimitive.py

**Intro :**
Ce fichier pose le contrat de base de toute l'architecture cryptographique. Il ne définit aucun algorithme concret, uniquement les règles que chaque primitive devra respecter. Et c'est ce cadre commun qui rend nos comparaisons valides, car AES, DES, TripleDES et Twofish passent tous par la même interface, dans les mêmes conditions et avec la même surface d'appel.

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

`class CipherPrimitive(ABC)` — Le mot-clé ABC, pour Abstract Base Class, indique que cette classe ne peut pas être instanciée directement. Elle définit uniquement un contrat que chaque algorithme concret devra honorer.

`@property` et `@abstractmethod` sur `block_size` et `key_size` — Ces deux décorateurs combinés imposent que toute sous-classe expose ces valeurs comme propriétés calculées, pas comme paramètres optionnels. AES retournera 16, DES retournera 8. Ces invariants sont utilisés partout dans le moteur pour allouer les bons buffers et valider les entrées.

`encrypt_block` et `decrypt_block` — Ce sont les deux opérations fondamentales du contrat. Elles travaillent toujours sur exactement un bloc de `block_size` octets. Ni plus ni moins. C'est ce que consomme la couche mode pour construire CBC, CTR ou GCM.

`encrypt_blocks` avec la validation — Cette méthode traite un message complet. Elle commence par vérifier que la longueur est un multiple de `block_size`. Si ce n'est pas le cas, elle lève une `ValueError` immédiatement. Ce garde-fou évite des résultats silencieusement tronqués. Les sous-classes peuvent surcharger cette méthode pour appeler leur bibliothèque native en une seule passe plutôt que bloc par bloc.

**Flux du processus :**
Avant de passer à l'implémentation concrète, posons une lecture commune du flux. En clair, le processus est le suivant. ExperimentController orchestre l'expérience, EncryptionEngine délègue au mode, puis le mode s'appuie sur le contrat CipherPrimitive. Ce cadre garantit que les primitives restent interchangeables et que les différences observées viennent des algorithmes eux-mêmes, pas du protocole de mesure.

### Section 3 - Exemple concret de primitive (AES)
**Titre :** Implémentation concrète d'une primitive

**Fichier / zone à montrer :** domain/cipher/AES.py

**Intro :**
Après le contrat abstrait, on descend maintenant vers une implémentation réelle. Ce fichier montre comment AES prend ce contrat et le transforme en comportement concret. L'intérêt ici n'est pas seulement de voir un algorithme, mais de comprendre comment une primitive réelle s'insère dans notre architecture sans casser l'abstraction commune.

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

`from Crypto.Cipher import AES as _AES` — Ici, on importe l'implémentation native fournie par PyCryptodome. Le suffixe `_AES` permet de distinguer clairement la bibliothèque sous-jacente de notre classe métier `AES`.

`class AES(CipherPrimitive)` — Cette ligne relie l'implémentation concrète au contrat abstrait. La classe hérite de `CipherPrimitive`, donc elle doit fournir les mêmes propriétés et les mêmes opérations.

`BLOCK_SIZE = 16` — Cette constante fixe la taille de bloc AES à 16 octets, soit 128 bits. C'est la valeur qui alimente tout le reste de la chaîne: validation, découpage, et composition avec les modes.

`__init__` et la validation de `key` — Le constructeur applique une validation stricte de longueur avec `_VALID_KEY_SIZES`, donc 16, 24 ou 32 octets, soit 128, 192 ou 256 bits. Si la clé ne respecte pas ces tailles, il lève immédiatement une `ValueError`. Ce mécanisme fail-fast empêche la création d'une instance AES invalide et garantit que toutes les opérations suivantes partent d'un état cryptographique cohérent.

`encrypt_block` — Cette méthode chiffre un bloc unique. Elle crée un chiffreur PyCryptodome en mode ECB brut, puis chiffre exactement un bloc. Le mode ECB ici n'est pas un choix de sécurité globale, c'est une brique interne qui sert à exécuter un bloc isolé.

`encrypt_blocks` — Cette méthode prend le chemin rapide pour plusieurs blocs. Au lieu de boucler bloc par bloc côté Python, elle délègue le traitement groupé à PyCryptodome. C'est plus proche du comportement réel du moteur et plus représentatif pour la mesure de performance.

**Flux du processus :**
Pour garder une lecture fluide, résumons le trajet opérationnel. Retenons le chemin d'exécution. ExperimentController demande une opération, EncryptionEngine transmet au mode, puis le mode appelle AES. AES vérifie la taille de la clé, chiffre les blocs avec PyCryptodome et renvoie un résultat conforme au contrat de la couche supérieure.

### Section 4 - Contrat des modes d'opération
**Titre :** Comment le système gère ECB/CBC/CTR/GCM

**Fichier / zone à montrer :** domain/mode/OperationMode.py

**Intro :**
Après la primitive, cette section introduit la couche qui transforme un chiffrement de bloc en chiffrement de message. Le mode d'opération définit la logique de chaînage, de compteur ou d'authentification, tout en restant découplé de l'algorithme concret.

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

`class OperationMode(ABC)` — Cette classe abstraite impose un contrat commun à tous les modes. On fixe la même interface, puis chaque mode implémente sa logique interne sans casser la couche supérieure.

`__init__(self, primitive: CipherPrimitive)` — Le constructeur injecte explicitement la primitive. Ce choix matérialise une composition claire, le mode ne chiffre rien seul, il orchestre l'usage d'une primitive déjà validée.

`encrypt(self, plaintext: bytes, **kwargs)` — Cette signature formalise le chiffrement d'un message complet. Les `kwargs` absorbent les paramètres dépendants du mode, comme iv, nonce, counter ou aad.

`decrypt(self, ciphertext: bytes, **kwargs)` — Cette méthode impose la symétrie fonctionnelle du contrat. Chaque mode doit garantir un chemin de déchiffrement cohérent avec son propre schéma de chiffrement.

**Flux du processus :**
Pour bien connecter cette couche avec la suivante, gardons le mécanisme en tête. Ici, le flux est simple. EncryptionEngine appelle le mode, le mode applique sa logique de transformation de message, puis délègue les opérations élémentaires à la primitive. Ce découplage garantit que l'on peut changer de mode sans réécrire l'algorithme sous-jacent.

### Section 5 - Point d'assemblage du domaine
**Titre :** Rôle de EncryptionEngine

**Fichier / zone à montrer :** domain/engine/EncryptionEngine.py

**Intro :**
Cette classe est la façade du domaine cryptographique. Elle centralise la composition primitive plus mode et offre un point d'entrée stable à l'application, sans exposition des détails internes.

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

`class EncryptionEngine` — Cette classe représente la brique d'assemblage qui relie contrat de primitive et contrat de mode dans un service unique.

`__init__(primitive, mode)` — Le constructeur reçoit les deux dépendances explicites et verrouille la composition au moment de l'instanciation.

`if mode.primitive is not primitive` — Cette condition impose un invariant d'identité objet. On n'accepte pas un mode lié à une autre primitive, car cela créerait une incohérence silencieuse.

`raise ValueError(...)` — En cas d'incohérence, l'échec est immédiat. Ce comportement fail-fast protège la validité cryptographique avant toute mesure.

`self._primitive` et `self._mode` — Ces références deviennent la configuration de travail stable du moteur pour toute la durée de l'expérience.

`encrypt(...) -> self._mode.encrypt(...)` — EncryptionEngine ne réimplémente pas la cryptographie. Il délègue strictement au mode, ce qui maintient une séparation de responsabilités nette.

**Flux du processus :**
À ce stade, on peut formaliser le passage application vers domaine. Au final, le flux est le suivant. L'application crée la primitive, construit le mode avec cette même primitive, puis instancie EncryptionEngine. Ensuite, toute l'exécution passe par cette façade, avec une API stable et indépendante des choix concrets.

### Section 6 - Orchestration des mesures
**Titre :** Rôle de ExperimentController

**Fichier / zone à montrer :** application/ExperimentController.py

**Intro :**
Ici, on passe de l'architecture logicielle à la logique scientifique. ExperimentController est la couche qui transforme une exécution cryptographique en mesures exploitables pour la comparaison.

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

`@dataclass class ExperimentResult` — Cette structure définit un schéma de sortie explicite et typé pour chaque expérience. Elle garantit une trace homogène des résultats sur toutes les configurations.

`algorithm` et `mode` — Ces champs portent le contexte cryptographique exact de la mesure, indispensable pour comparer correctement les résultats.

`message_size_bytes` et `throughput_encrypt_mbps` — Ces champs relient le volume traité à la performance observée, donc la mesure reste interprétable.

`avalanche_score` et `ci95_encrypt_mbps` — On combine robustesse cryptographique et fiabilité statistique dans le même objet, ce qui évite une lecture partielle des performances.

`run_performance(...)` — Cette méthode orchestre le protocole complet, répétitions, chronométrage, agrégation, puis encapsulation finale dans ExperimentResult.

**Flux du processus :**
Pour passer de la logique logicielle à la logique scientifique, voici le fil de calcul. Concrètement, le flux se déroule ainsi. run_performance appelle le moteur, collecte les séries temporelles, calcule les indicateurs agrégés et retourne un objet structuré prêt pour l'export CSV et l'analyse comparative.

### Section 7 - Point d'entrée expérimental
**Titre :** Lancement de la matrice de tests

**Fichier / zone à montrer :** scripts/experiment.py

**Intro :**
Cette section montre le pilote d'exécution global. Le script parcourt toutes les configurations définies et déclenche systématiquement la même procédure de mesure.

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

`REPETITIONS = 100` — Cette constante fixe le nombre d'itérations de mesure par configuration. Elle limite la variance et améliore la stabilité statistique.

`MESSAGE_SIZES = [...]` — Cette liste définit l'échelle des charges testées, du petit message au volume plus conséquent.

`for ... in EXPERIMENT_MATRIX` — Cette boucle matérialise la couverture expérimentale. Chaque tuple encode une combinaison algorithme plus mode plus taille de clé.

`controller.run_performance(...)` — L'appel délègue la mesure à la couche scientifique sans dupliquer la logique. Le script reste un orchestrateur, pas un calculateur.

**Flux du processus :**
Dans une perspective d'orchestration complète, voici la séquence à retenir. On peut donc résumer le flux comme suit. scripts/experiment.py instancie les objets du domaine, appelle ExperimentController pour chaque configuration, accumule les résultats de manière traçable, puis déclenche l'export CSV final.

### Section 8 - Démonstration en direct
**Titre :** Exécution et preuve de sortie

**Fichier / zone à montrer :** terminal + data/results/

**Intro :**
Cette étape valide la chaîne complète dans des conditions réelles d'exécution. Elle sert de preuve opérationnelle que le protocole produit bien des artefacts exploitables.

**Commande à montrer :**
```powershell
python scripts/experiment.py
```

**Narration ligne par ligne :**

`python scripts/experiment.py` — Cette commande lance toute la campagne selon la matrice de tests définie dans le script.

Progression terminal — La sortie console confirme que chaque configuration est exécutée et mesurée, ce qui rend le déroulement vérifiable en direct.

CSV horodaté dans `data/results` — En fin d'exécution, le système persiste un artefact daté qui fige les résultats bruts pour l'analyse ultérieure.

**Flux du processus :**
Pour conclure la démonstration avec une lecture claire, revenons au fil complet d'exécution. Pour terminer, le flux est très direct. Le terminal lance scripts/experiment.py, qui enchaîne ExperimentController puis EncryptionEngine pour chaque cas d'essai, et la campagne se termine par des résultats persistés en CSV dans data/results.

### Conclusion
Cette vidéo pose les fondations techniques du projet, architecture modulaire, invariants explicites, chaîne d'exécution cohérente et artefacts traçables. Dans la suite, nous pourrons justifier la méthodologie expérimentale sur une base logicielle déjà vérifiée.
