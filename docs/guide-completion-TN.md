# Guide de complétion — INF1430
## Ce que tu dois ajouter dans ton rapport Word et comment préparer chaque TN

---

## VUE D'ENSEMBLE DES 4 TRAVAUX NOTÉS

| TN | Titre | % | Statut | Échéance |
|----|-------|---|--------|----------|
| TN1 | Plan de projet documenté | 10 % | ✅ Remis + rétroaction reçue | — |
| TN2 | Rapport mi-parcours | 20 % | 🔶 À compléter | 7 juin 2026 |
| TN3 | Produit final fonctionnel | 30 % | 🔶 Code complet — à soumettre | À confirmer avec prof |
| TN4 | Rapport du projet présenté | 40 % | ⏳ Non commencé | À confirmer avec prof |

**Critère de notation commun :** concordance, faisabilité, complétude, transférabilité, qualité du français.

---

## PARTIE 1 — TN2 : CE QUI EST DÉJÀ BIEN

Ton rapport contient :

- ✅ Page de titre complète
- ✅ Section 1 Introduction — solide
- ✅ Section 2 Description du problème — bien articulée
- ✅ Section 3 Analyse du domaine (DDD, langage ubiquitaire)
- ✅ Section 4 Architecture (schéma composantes, déploiement, diagramme de classes, diagramme de séquence)
- ✅ Section 5 Démarche d'ingénierie (Python, PyCryptodome, Git, stratégie de validation)
- ✅ Section 6 Ordre de conception et d'implémentation
- ✅ Section 7 État d'avancement

---

## PARTIE 2 — TN2 : CE QUI MANQUE À AJOUTER

### 2.1 Mettre à jour la Section 7 — État d'avancement

La section 7 dit que l'implémentation « n'a pas encore été lancée » et que la validation est « en phase de préparation ». C'est faux maintenant. Voici ce qu'il faut écrire :

**Sous-section 7.1 — Implémentation réalisée** : REMPLACE le texte actuel par :

> L'ensemble des composants décrits dans le tableau 1 ont été implémentés et intégrés avec succès. La couche domaine comprend quatre primitives cryptographiques (AES, DES, 3DES, Twofish) et quatre modes d'opération (ECB, CBC, CTR, GCM). Le moteur de chiffrement `EncryptionEngine` compose ces éléments de manière agnostique. Le contrôleur d'expérimentation `ExperimentController` orchestre les mesures de performance (débit, temps moyen) et l'analyse de robustesse (effet d'avalanche). Le script `experiment.py` itère sur une matrice de 120 combinaisons (algorithme × mode × taille de clé × taille de message) et produit les données expérimentales au format CSV.

**Sous-section 7.2 — Validation fonctionnelle effectuée** : REMPLACE par :

> La stratégie de validation fonctionnelle décrite en section 5.4 a été intégralement exécutée. La suite de tests de réponse connue (Known Answer Tests) a été implémentée dans le répertoire `validation/` et couvre les standards suivants :
> - **AES** : 4 vecteurs de FIPS 197 (Appendices A.1, B, C.2 et C.3) — AES-128, AES-192, AES-256
> - **DES** : 9 vecteurs de SP 800-17, Table 1
> - **3DES** : 2 vecteurs (clés 16 octets et 24 octets à parité DES vérifiée)
> - **Modes ECB et CBC** : vecteurs SP 800-38A, sections F.1 et F.2
> - **AES-GCM** : vecteurs SP 800-38D, cas de test TC3 et TC4 (avec et sans AAD)
>
> L'exécution de la commande `py scripts/run_kat.py` confirme que l'ensemble des 26 tests passent sans échec. Cette validation constitue le prérequis formel établi avant le démarrage des campagnes expérimentales.

**Sous-section 7.3 — Premières expérimentations** : REMPLACE par :

> Les premières expérimentations ont été réalisées sur la plateforme de développement (ordinateur personnel sous Windows 11, processeur x86-64). La matrice expérimentale comprend 120 combinaisons couvrant les quatre algorithmes, les modes disponibles, les tailles de clés standardisées (64 à 256 bits) et cinq tailles de message (64 à 16 384 octets), avec 100 répétitions par combinaison. Les résultats sont archivés dans `data/results/laptop-windows-x86_experience1.csv`. L'analyse préliminaire confirme le bon fonctionnement de l'architecture et révèle des écarts de performance significatifs entre les algorithmes, qui feront l'objet d'une analyse approfondie dans le rapport final (TN4).

---

### 2.2 Ajouter une Section 8 — Résultats préliminaires

Ajoute une nouvelle section après la section 7. Voici la structure suggérée :

**8.1 Aperçu des performances**

Insère **Figure 1** (`fig1_throughput_4096B.png`) et écris :

> La figure 1 illustre le débit de chiffrement mesuré pour chaque combinaison algorithme-mode sur des messages de 4 096 octets. L'AES en mode ECB atteint un débit de l'ordre de 80 à 115 MB/s selon la taille de la clé, bénéficiant de l'accélération matérielle AES-NI disponible sur l'architecture x86-64 via PyCryptodome. Le DES-ECB affiche environ 33 MB/s malgré sa clé plus courte, en raison de la conception séquentielle de son réseau de Feistel. Le 3DES, réalisant trois opérations DES successives, présente un débit d'environ 12 MB/s, soit environ trois fois moins que le DES simple. Twofish, dont l'implémentation repose sur des liaisons C via ctypes, plafonne à environ 1–2 MB/s sur cette plateforme. Les modes CBC présentent systématiquement un débit réduit par rapport à ECB en raison du chaînage séquentiel imposé lors du chiffrement, tandis que CTR et GCM offrent des performances intermédiaires.

Insère **Figure 2** (`fig2_throughput_vs_msgsize.png`) et écris :

> La figure 2 présente l'évolution du débit selon la taille du message en mode ECB. Pour l'AES, le débit croît de manière significative avec la taille du message, passant de ~3 MB/s pour 64 octets à plus de 300 MB/s pour 16 384 octets, en raison de la réduction de l'overhead de création d'objet et de l'amortissement des coûts fixes sur un plus grand nombre de blocs. DES et 3DES présentent une progression similaire mais à des niveaux inférieurs. Twofish reste relativement stable, ce qui suggère que son overhead est principalement lié à la liaison ctypes plutôt qu'au traitement par bloc.

**8.2 Comparaison des modes d'opération (AES-128)**

Insère **Figure 3** (`fig3_aes_mode_comparison.png`) et écris :

> La figure 3 compare les quatre modes d'opération disponibles pour AES-128. L'ECB est le plus rapide car il n'introduit aucune dépendance entre les blocs et exploite pleinement la vectorisation. Le mode GCM, bien que produisant une authentification cryptographique (tag de 128 bits), offre des débits comparables à l'ECB grâce à son implémentation optimisée dans PyCryptodome. Le mode CTR, convertissant le bloc en flux de clé, présente un débit intermédiaire. Le CBC est le plus lent en chiffrement, car chaque bloc dépend du précédent, empêchant tout parallélisme.

**8.3 Effet d'avalanche**

Insère **Figure 4** (`fig4_avalanche.png`) et écris :

> La figure 4 présente les scores d'effet d'avalanche mesurés pour chaque algorithme. La valeur de référence est 0,50, correspondant à une modification aléatoire de la moitié des bits de sortie lors d'un changement d'un seul bit en entrée. Tous les algorithmes évalués convergent vers cette valeur idéale : AES (0,500), DES (0,502), 3DES (0,501), Twofish (0,499). Ces résultats confirment que les quatre primitives respectent le critère de diffusion strict (principe de Shannon) et qu'aucune ne présente de faiblesse structurelle observable à ce niveau d'analyse.

**8.4 Note sur les performances de Twofish**

> Le faible débit de Twofish (~1–2 MB/s) ne reflète pas les performances intrinsèques de l'algorithme mais constitue une limitation de l'environnement d'implémentation. La bibliothèque `twofish` utilisée requiert une couche d'interopérabilité C (`ctypes`) dont l'overhead domine le temps de traitement pour les petits messages. Sur Raspberry Pi, cette caractéristique sera réévaluée. Les données de performance de Twofish seront donc interprétées comme un plancher de référence de l'architecture logicielle retenue.

---

### 2.3 Ajouter une Section 9 — Extraits de code représentatifs

Cette section documente l'architecture implémentée avec des extraits de code. Voici les **5 extraits à inclure** et pourquoi :

**Extrait 1 — Classe abstraite `CipherPrimitive`** (`domain/cipher/CipherPrimitive.py`)
- Montre le principe d'abstraction DDD : interface contractuelle imposée à toutes les primitives.
- Présente les méthodes `encrypt_block`, `decrypt_block`, `encrypt_blocks`, `decrypt_blocks`.
- **Pourquoi** : démontre la séparation entre interface (contrat) et implémentation.

**Extrait 2 — Primitive AES** (`domain/cipher/AES.py`, méthode `__init__` + `encrypt_blocks`)
- Montre comment PyCryptodome est encapsulé tout en respectant l'interface.
- **Pourquoi** : illustre l'encapsulation et le principe DDD « anti-corruption layer ».

**Extrait 3 — Mode CBC** (`domain/mode/CBC.py`, méthode `encrypt`)
- Montre la logique de chaînage et d'IV, séparée de la primitive.
- **Pourquoi** : démontre la composition (mode + primitive) et la séparation des préoccupations.

**Extrait 4 — Moteur de chiffrement** (`domain/engine/EncryptionEngine.py`, entier)
- Court fichier qui compose primitive + mode.
- **Pourquoi** : démontre le pattern composition et le faible couplage.

**Extrait 5 — Matrice expérimentale** (`scripts/experiment.py`, lignes EXPERIMENT_MATRIX)
- Montre comment les combinaisons sont définies et itérées.
- **Pourquoi** : démontre la reproductibilité et la neutralité de l'orchestration.

---

### 2.4 Mettre à jour la liste des figures

Ton document a des figures 1 à 5 (diagrammes UML). Les nouvelles figures deviennent :

| Numéro | Titre | Fichier |
|--------|-------|---------|
| Figure 6 | Débit par algorithme et mode (4 096 octets) | `fig1_throughput_4096B.png` |
| Figure 7 | Débit selon taille du message (ECB) | `fig2_throughput_vs_msgsize.png` |
| Figure 8 | Comparaison des modes AES-128 | `fig3_aes_mode_comparison.png` |
| Figure 9 | Effet d'avalanche par algorithme | `fig4_avalanche.png` |

> ⚠️ Utilise Insertion → Image dans Word pour insérer les PNG (ne pas coller). Ils sont dans `crypto-experiments/data/charts/`.

---

### 2.5 Vérifier la conclusion

La conclusion devrait maintenant refléter que l'implémentation EST complète et que les expérimentations SONT amorcées. Ajuste toute formulation au futur (« sera implémenté ») pour l'écrire au passé ou au présent.

---

## PARTIE 3 — TN3 : LE PRODUIT FINAL (30 %)

**Critère** : « Organisation, complétude, pertinence, efficience et qualité du produit. »

TN3 est le **code lui-même**. Tu soumets le dépôt GitHub. Voici ce qu'il doit contenir pour être complet :

| Élément | État | Emplacement |
|---------|------|-------------|
| Primitives AES, DES, 3DES, Twofish | ✅ Fait | `domain/cipher/` |
| Modes ECB, CBC, CTR, GCM | ✅ Fait | `domain/mode/` |
| Moteur EncryptionEngine | ✅ Fait | `domain/engine/` |
| Contrôleur d'expérimentation | ✅ Fait | `application/ExperimentController.py` |
| Script experiment.py | ✅ Fait | `scripts/experiment.py` |
| Suite KAT (validation NIST) | ✅ Fait | `validation/`, `scripts/run_kat.py` |
| Données x86 (expérience 1) | ✅ Fait | `data/results/laptop-windows-x86_experience1.csv` |
| Graphiques | ✅ Fait | `data/charts/` |
| ⚠️ Données Raspberry Pi (expérience 2) | ❌ Manque | À faire avant TN3 |
| ⚠️ README utilisateur | ❌ Manque | `README.md` |

**Pour TN3, tu dois aussi** :

1. **Exécuter l'expérience sur Raspberry Pi** — copier le dépôt sur le Pi, installer `pip install pycryptodome twofish`, appliquer le patch twofish (remplacer `import imp` → `import importlib.util`), puis lancer `py scripts/experiment.py`. Le CSV produit doit être nommé `raspberry-pi_experience2.csv`.
2. **Écrire un README minimal** — comment installer et lancer les expériences + les KAT.

---

## PARTIE 4 — TN4 : RAPPORT FINAL (40 %)

TN4 est le rapport complet. Il doit couvrir :

1. **Introduction** — problématique, contexte
2. **Revue de littérature** — sources académiques sur DES, AES, 3DES, Twofish (FIPS 197, SP 800-67, article Twofish original de Bruce Schneier et al., 1998)
3. **Méthodologie** — l'architecture DDD, les paramètres expérimentaux, le protocole de validation KAT
4. **Résultats** — toutes les figures générées + tableau de données numériques
5. **Discussion et comparaison x86 vs Raspberry Pi** — c'est le cœur de l'analyse
6. **Conclusion et recommandations** — quel algorithme recommander selon le contexte ?

> TN4 sera rédigé après que tu auras les données Raspberry Pi. C'est le rapport qui compte pour 40 % — concentre l'effort là-dedans.

---

## RÉCAPITULATIF DES ACTIONS IMMÉDIATES

| Priorité | Action | Pour quel TN |
|----------|--------|--------------|
| 🔴 Urgent | Mettre à jour sections 7.1, 7.2, 7.3 dans Word | TN2 (dû 7 juin) |
| 🔴 Urgent | Ajouter section 8 (résultats préliminaires + 4 figures) dans Word | TN2 (dû 7 juin) |
| 🔴 Urgent | Ajouter section 9 (extraits de code + explication) dans Word | TN2 (dû 7 juin) |
| 🟡 Moyen | Corriger la conclusion dans Word | TN2 (dû 7 juin) |
| 🟡 Moyen | Exécuter experiment.py sur Raspberry Pi | TN3 |
| 🟡 Moyen | Écrire README.md | TN3 |
| 🟢 Futur | Rédiger TN4 complet (après données Pi) | TN4 |
