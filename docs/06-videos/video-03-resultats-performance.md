# Vidéo 3 - Résultats de performance

## Introduction (ouverture caméra)
**Texte à lire :**
Cette vidéo présente les résultats de performance de la campagne expérimentale.

Après la validation fonctionnelle et la méthode de mesure, on répond maintenant à la question centrale: qu'est-ce qui explique les écarts de débit entre algorithmes, entre modes, et entre plateformes x86 et ARM?

La lecture suit une progression simple. D'abord, on confirme la traçabilité des graphes. Ensuite, on lit l'effet de la taille des messages. Puis on compare les algorithmes et les modes. Enfin, on termine avec l'effet matériel, en particulier AES-NI.

## Objectif
Interpréter rigoureusement les performances en reliant chaque écart à trois facteurs: algorithme, mode d'opération et architecture matérielle.

## Portée
- `scripts/run_charts.py`
- `scripts/chart_pipeline/build_performance.py`
- `scripts/chart_pipeline/build_platform_comparison.py`
- `data/results/laptop-windows-x86_experience3.csv`
- `data/results/raspberry-pi_experience3.csv`
- `data/charts/01-debit/debit-vs-taille-message.png`
- `data/charts/01-debit/debit-4096o.png`
- `data/charts/01-debit/comparaison-ratio-acceleration.png`
- `data/charts/03-modes-chiffrement/aes-comparaison-modes.png`
- `data/charts/03-modes-chiffrement/aes-securite-vs-performance.png`
- `data/charts/01-debit/chacha20-comparaison-plateformes.png`

## Guide d'enregistrement

### Section 1 - Traçabilité des graphes
**Où sommes-nous :**
VS Code sur `scripts/run_charts.py`, puis `scripts/chart_pipeline/` et `data/charts/`.

**Texte à lire :**
Avant d'interpréter les chiffres, on confirme la traçabilité. Les figures ne sont pas dessinées manuellement. Elles sont générées automatiquement à partir des CSV de mesure.

Le point d'entrée est `scripts/run_charts.py`. Ce script orchestre les dossiers de sortie et appelle les modules `build_performance.py` et `build_platform_comparison.py`. Les fonctions de rendu lisent les données normalisées, tracent les figures et les sauvegardent dans `data/charts`.

Cette étape est essentielle, parce qu'elle garantit une narration reproductible: chaque conclusion est rattachée à une source mesurée et à une image générée automatiquement.

**Code à montrer :**
```python
# scripts/run_charts.py
TARGETS = {
    "01": _generate_01_debit,
    "02": _generate_02_effet_avalanche,
    "03": _generate_03_modes_chiffrement,
    "04": _generate_04_synthese,
}

# scripts/chart_pipeline/build_performance.py
def savefig(name: str):
    save_figure(plt.gcf(), CHARTS_DIR, name, facecolor=BG_COLOR)
```

**Commande à montrer (terminal) :**
```bash
cd crypto-experiments
python scripts/run_charts.py 01
python scripts/run_charts.py 03
```

**Texte à lire après la commande :**
Dans le terminal, on voit les chemins des fichiers enregistrés. Cela confirme que les graphes sont produits directement depuis les données expérimentales.

**Transition :**
Maintenant que la chaîne de production est claire, on passe à la lecture des débits.

### Section 2 - Débit selon la taille du message
**Visuel à montrer :**
`data/charts/01-debit/debit-vs-taille-message.png`

**Texte à lire :**
Ce graphe montre l'évolution du débit quand la taille du message augmente. Sur les petites tailles, le coût fixe pèse fortement. Quand la taille augmente, ce coût est amorti, et le débit utile se stabilise.

Le point important est méthodologique: un algorithme moyen à 64 octets peut devenir compétitif à 4096 ou 16384 octets. C'est pourquoi notre protocole couvre plusieurs tailles de message.

**Transition :**
Après la tendance globale, on fixe une taille de référence pour comparer plus clairement.

### Section 3 - Comparaison à 4096 octets
**Visuel à montrer :**
`data/charts/01-debit/debit-4096o.png`

**Texte à lire :**
Ici, la taille est fixée à 4096 octets. On isole donc l'effet algorithme et mode, sans mélanger l'effet taille.

AES ressort en tête sur x86 dans plusieurs cas, cohérent avec l'accélération matérielle. ChaCha20 reste régulier et performant, surtout sur des environnements moins favorables à AES-NI. DES et 3DES sont plus lents, en plus de leurs limites de sécurité.

**Transition :**
La hiérarchie globale est visible. Regardons maintenant l'effet spécifique des modes.

### Section 4 - Impact des modes d'opération
**Visuels à montrer :**
`data/charts/03-modes-chiffrement/aes-comparaison-modes.png`
`data/charts/03-modes-chiffrement/aes-securite-vs-performance.png`

**Texte à lire :**
À algorithme constant, le mode change le coût total. Tous les modes n'ont pas la même charge fonctionnelle. Par exemple, GCM ajoute l'authentification en plus du chiffrement.

Le message clé n'est pas de choisir le mode le plus rapide en absolu. Le bon choix est celui qui correspond au besoin de sécurité du système.

**Transition :**
On a séparé l'effet taille et l'effet mode. Il reste l'effet plateforme.

### Section 5 - Effet plateforme et rôle d'AES-NI
**Visuels à montrer :**
`data/charts/01-debit/comparaison-ratio-acceleration.png`
`data/charts/01-debit/chacha20-comparaison-plateformes.png`

**Texte à lire :**
Ici, on explique l'écart x86 versus ARM. Sur x86, AES profite de l'extension AES-NI. Une part importante du gain vient donc du matériel.

Sur Raspberry Pi, ce levier est différent ou absent, et la hiérarchie peut se resserrer. La conclusion est directe: la performance cryptographique est une propriété du couple algorithme plus architecture.

### Section 6 - Conclusion vidéo 3
**Texte à lire :**
On retient trois constats. Le débit dépend de la taille de message et de l'algorithme. Le mode d'opération introduit un compromis mesurable entre coût et garanties de sécurité. Et l'architecture matérielle, notamment AES-NI, explique une part majeure des écarts inter-plateformes.

Dans la vidéo suivante, on complète cette lecture avec la robustesse cryptographique, l'effet d'avalanche et la stabilité statistique.
