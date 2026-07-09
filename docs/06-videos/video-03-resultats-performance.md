# Vidéo 3 - Résultats de performance

## Introduction (ouverture caméra)
**Texte à lire :**
Cette vidéo est consacrée aux résultats de performance de la campagne expérimentale.

Après avoir validé la conformité cryptographique et le protocole de mesure dans la vidéo précédente, on peut maintenant répondre à la question centrale : qu'est-ce qui explique les écarts de débit observés entre les algorithmes, entre les modes d'opération et entre les plateformes x86 et ARM ?

On va suivre une lecture progressive. D'abord, on confirme la provenance des figures. Ensuite, on lit les graphes de débit selon la taille de message. Puis, on interprète les différences entre algorithmes et modes, avant de terminer par l'impact matériel, notamment l'accélération AES-NI.

## Objectif
Interpréter les résultats de performance de manière rigoureuse, en reliant chaque écart mesuré à trois facteurs : l'algorithme, le mode de chiffrement et l'architecture matérielle.

## Portée
- scripts/charts/plot_performance.py
- data/results/laptop-windows-x86_experience3.csv
- data/results/raspberry-pi_experience3.csv
- data/charts/01-debit/debit-vs-taille-message.png
- data/charts/01-debit/debit-4096o.png
- data/charts/01-debit/comparaison-ratio-acceleration.png
- data/charts/03-modes-chiffrement/aes-comparaison-modes.png
- data/charts/03-modes-chiffrement/aes-securite-vs-performance.png
- data/charts/01-debit/chacha20-comparaison-plateformes.png

## Guide d'enregistrement

### Section 1 - Provenance des graphes et traçabilité
**Où sommes-nous :**
VS Code, fichier scripts/charts/plot_performance.py, puis dossier data/charts.

**Fichier / zone à montrer :**
scripts/charts/plot_performance.py
- Bloc configuration et sélection du CSV (résultats vers graphiques)
- Fonction d'export savefig (écriture des PNG)

**Intro (texte à lire) :**
Avant d'interpréter les chiffres, on vérifie d'où viennent les figures. Le principe est simple : les graphes ne sont pas dessinés manuellement. Ils sont générés automatiquement à partir des CSV exportés par la campagne de mesure.

**Sujet (texte à lire) :**
Le script scripts/charts/plot_performance.py lit le fichier CSV sélectionné dans data/results, applique les mêmes règles de calcul et de visualisation, puis sauvegarde les images dans data/charts. Cette étape est importante, parce qu'elle garantit que la narration repose sur des données traçables et reproductibles. On peut donc lier chaque conclusion à un fichier source précis.

**Code à montrer :**
```python
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RESULTS_DIR = os.path.join(BASE_DIR, "data", "results")
CHARTS_DIR  = os.path.join(BASE_DIR, "data", "charts")
os.makedirs(CHARTS_DIR, exist_ok=True)

csv_files = sorted(
    [f for f in os.listdir(RESULTS_DIR) if f.endswith(".csv") and f != ".gitkeep"]
)
CSV_PATH = os.path.join(RESULTS_DIR, csv_files[-1])
print(f"Reading: {CSV_PATH}")

with open(CSV_PATH, newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    ...

def savefig(name: str):
    path = os.path.join(CHARTS_DIR, name)
    plt.savefig(path, dpi=DPI, bbox_inches="tight", facecolor=BG_COLOR)
    print(f"  Saved: {path}")
```

**Narration ligne par ligne (texte à lire) :**
Aux lignes de configuration, le script fixe d'abord les deux dossiers clés : data/results pour l'entrée et data/charts pour la sortie. Le dossier des figures est créé automatiquement si nécessaire.

Ensuite, le script repère les fichiers CSV disponibles, sélectionne celui qui sera lu pour la génération, puis l'affiche explicitement avec Reading: chemin du fichier. Cette trace est importante, parce qu'elle indique exactement quel jeu de données alimente les graphes.

Puis, avec DictReader, chaque ligne CSV est lue sous forme structurée. C'est ce format structuré qui garantit des transformations cohérentes sur l'ensemble de la campagne.

Enfin, la fonction savefig centralise l'export de toutes les figures PNG et affiche Saved: chemin du fichier. On a donc un cycle complet et traçable : source lue, traitement appliqué, fichier image écrit.

**Commande à montrer (terminal) :**
```bash
cd crypto-experiments
python scripts/charts/plot_performance.py
```

**Texte à lire après la commande :**
Dans le terminal, on voit d'abord Reading:, puis une série de Saved:. Cela confirme que les graphes présentés sont générés automatiquement depuis les mesures, et non produits manuellement.

**Transition (texte à lire) :**
Maintenant que la chaîne de production des figures est claire, on peut passer à la lecture des débits.

### Section 2 - Débit selon la taille de message
**Où sommes-nous :**
PowerPoint, slides résultats débit global et effet taille.

**Visuel à montrer :**
data/charts/01-debit/debit-vs-taille-message.png

**Texte à lire :**
Ce premier graphe montre l'évolution du débit quand la taille du message augmente. La tendance principale est la suivante : sur les petites tailles, le coût fixe de traitement pèse davantage. Quand la taille augmente, ce coût fixe est amorti, et le débit utile devient plus stable.

Cette lecture est essentielle pour éviter les conclusions rapides. Un algorithme qui semble moyen sur 64 octets peut devenir très compétitif sur 4096 ou 16384 octets. C'est pour cela que notre protocole couvre plusieurs tailles de message, et pas une seule valeur arbitraire.

**Transition (texte à lire) :**
Après cette vue d'ensemble, on fixe une taille de référence pour comparer plus directement les algorithmes.

### Section 3 - Comparaison à taille fixe
**Où sommes-nous :**
PowerPoint, slide comparaison à 4096 octets.

**Visuel à montrer :**
data/charts/01-debit/debit-4096o.png

**Texte à lire :**
Ici, on fige la taille du message à 4096 octets pour isoler l'effet algorithme plus mode, sans mélanger les effets de taille. On observe une hiérarchie plus lisible des performances.

AES ressort en tête sur la plateforme x86 dans plusieurs configurations, ce qui est cohérent avec la présence d'une accélération matérielle dédiée. ChaCha20 reste robuste et régulier, surtout dans les contextes où l'accélération AES est absente ou moins favorable. À l'inverse, DES et 3DES montrent des performances inférieures, en plus de leurs limites de sécurité.

**Transition (texte à lire) :**
Cette comparaison donne la hiérarchie globale. Voyons maintenant l'effet spécifique du mode d'opération.

### Section 4 - Impact des modes de chiffrement
**Où sommes-nous :**
PowerPoint, slides modes ECB/CBC/CTR/GCM.

**Visuels à montrer :**
data/charts/03-modes-chiffrement/aes-comparaison-modes.png
data/charts/03-modes-chiffrement/aes-securite-vs-performance.png

**Texte à lire :**
À algorithme constant, le mode d'opération modifie le coût total. Les modes ne portent pas la même charge fonctionnelle. GCM, par exemple, ajoute l'authentification en plus du chiffrement. Ce surcoût est donc attendu, et il s'accompagne d'un gain de sécurité opérationnelle important, puisque l'intégrité est vérifiée en même temps que la confidentialité.

L'idée clé n'est pas de chercher le mode le plus rapide dans l'absolu. L'idée est de choisir le mode qui correspond au besoin de sécurité réel du système. Un mode plus coûteux peut être le bon choix si les garanties qu'il apporte sont nécessaires.

**Transition (texte à lire) :**
On a séparé l'effet taille et l'effet mode. Il reste maintenant à lire l'effet plateforme.

### Section 5 - Effet plateforme et accélération matérielle
**Où sommes-nous :**
PowerPoint, slide x86 vs Raspberry Pi.

**Visuels à montrer :**
data/charts/01-debit/comparaison-ratio-acceleration.png
data/charts/01-debit/chacha20-comparaison-plateformes.png

**Texte à lire :**
Cette section répond à la question du pourquoi entre x86 et ARM. Sur x86, AES profite fortement de l'extension AES-NI. Une partie importante de l'écart de débit vient donc du matériel, pas d'un changement de méthode logicielle. Sur Raspberry Pi, ce levier n'existe pas au même niveau, et la hiérarchie peut se resserrer selon les cas.

Le message à retenir est direct : la performance cryptographique est une propriété du couple algorithme plus architecture. On ne choisit pas une primitive dans le vide. On la choisit pour une plateforme cible et un niveau de sécurité donné.

### Section 6 - Conclusion et transition
**Support affiché :**
PowerPoint, slide de synthèse de la vidéo 3.

**Texte à lire :**
On conclut cette vidéo avec trois constats. Premier constat, le débit dépend fortement de l'algorithme et de la taille de message. Deuxième constat, le mode d'opération introduit un compromis mesurable entre coût et garanties de sécurité. Troisième constat, l'architecture matérielle, notamment AES-NI sur x86, explique une part majeure des écarts inter-plateformes.

Dans la prochaine vidéo, on complète cette lecture par la robustesse cryptographique, avec l'analyse de l'effet d'avalanche et de la stabilité statistique.
