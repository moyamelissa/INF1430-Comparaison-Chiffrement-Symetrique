# Analyse des résultats — Comparaison des algorithmes de chiffrement symétrique
### INF1430 — Laptop x86 (Windows) vs Raspberry Pi (ARM)

---

## 1. Vue d'ensemble des données

L'expérience mesure cinq algorithmes (AES, DES, 3DES, Twofish, ChaCha20) sur deux architectures matérielles fondamentalement différentes : un processeur **x86-64 moderne** avec extensions AES-NI, et un processeur **ARM Cortex-A** basse consommation (Raspberry Pi). Les métriques collectées couvrent le débit de chiffrement/déchiffrement, l'effet d'avalanche, la sensibilité aux clés, et la stabilité temporelle (intervalle de confiance à 95 %).

**Tableau des pics de débit (chiffrement, MB/s) :**

| Algorithme | x86 (MB/s) | Pi ARM (MB/s) | Ratio x86/Pi |
|------------|:----------:|:-------------:|:------------:|
| AES        | 417.07     | 74.73         | **5.58×**    |
| ChaCha20   | 114.31     | 61.27         | 1.87×        |
| DES        | 40.70      | 18.27         | 2.23×        |
| Twofish    | 2.82       | 1.29          | 2.19×        |
| 3DES       | 12.29      | 7.51          | 1.64×        |

---

## 2. Analyse par algorithme

### 2.1 AES — Le roi du x86, handicapé sur ARM

AES atteint **417 MB/s** sur x86 contre seulement **74.7 MB/s** sur Pi — un écart de **5.58×** qui dépasse largement la différence brute de puissance CPU entre les deux plateformes (~2-3×). Cela s'explique par une seule raison : les **instructions AES-NI**, intégrées dans les processeurs Intel/AMD depuis 2010. Ces instructions exécutent un tour AES complet en un seul cycle, rendant l'algorithme quasi gratuit en termes de coût CPU.

Sur le Pi, AES s'exécute en **logiciel pur**. Les opérations SubBytes, ShiftRows, MixColumns, AddRoundKey sont toutes calculées explicitement. La performance de 74.7 MB/s reste correcte pour de l'ARM embarqué, mais l'écart révèle une **dépendance architecturale critique** : AES est ultrarapide uniquement parce qu'Intel a câblé le circuit.

**Observation clé sur la scalabilité :** Le rapport taille/débit d'AES-128 ECB est frappant :
- 64 octets → 1.37 MB/s (x86) / 1.14 MB/s (Pi)
- 16 384 octets → 382.90 MB/s (x86) / 74.73 MB/s (Pi)

Pour les petits messages, le coût fixe de la mise en place du chiffrement (key scheduling, initialisation) domine complètement. AES n'est pas adapté au chiffrement de nombreux petits messages sans optimisation — un protocole qui chiffre des paquets de 64 octets un par un est presque 280× moins efficace qu'un protocole qui regroupe les données en blocs de 16 Ko.

**Analyse des modes de chiffrement (AES, x86, 4096 B) :**

| Mode | Clé | Chiffrement (MB/s) | Déchiffrement (MB/s) | CI95 |
|------|-----|--------------------|----------------------|------|
| ECB  | 128 | 162.78             | 184.09               | 16.81 |
| GCM  | 128 | 25.78              | 22.19                | 2.02 |
| CTR  | 128 | 6.61               | 6.68                 | 0.13 |
| CBC  | 128 | **0.73**           | 7.69                 | 0.02 |

Le résultat le plus alarmant : **AES-CBC en chiffrement est 223× plus lent que AES-ECB**. Ce n'est pas une erreur — c'est une conséquence directe de la structure de CBC. Le chiffrement CBC est séquentiel par nature : chaque bloc ci = E(pi ⊕ c_{i-1}), ce qui empêche toute parallélisation. Le déchiffrement, lui, peut traiter tous les blocs en parallèle puisque tous les ci sont disponibles dès le départ. Les AES-NI exploitent ce parallélisme massivement. Le même pattern s'observe sur Pi (0.39 MB/s enc vs 5.70 MB/s dec), mais moins amplifié.

**Ce résultat est un signal d'alarme pour les implémentations :** un développeur qui choisit CBC pour ses propriétés de sécurité sans connaître cet écart de performance pourrait être tenté de "contourner" le problème en réutilisant les IVs ou en précalculant — deux pratiques catastrophiques pour la sécurité.

---

### 2.2 ChaCha20 — L'algorithme qui refuse l'inégalité des plateformes

ChaCha20 présente le ratio le plus équilibré entre plateformes (**1.87×**), et sa performance sur Pi (**61.27 MB/s**) est remarquable : elle dépasse DES sur x86 (40.70 MB/s) et se rapproche de AES-GCM sur x86 (25.78 MB/s). C'est exactement l'objectif pour lequel Daniel J. Bernstein a conçu cet algorithme en 2008 : être efficace en **logiciel pur**, sans dépendance au matériel.

ChaCha20 repose sur des opérations ARX (Addition, Rotation, XOR) — des opérations que tout processeur exécute nativement en un seul cycle, qu'il soit ARM, x86, RISC-V, ou MIPS. Là où AES nécessite une lookup table (S-Box) potentiellement vulnérable au cache timing, ChaCha20 est **constant-time par design**.

La convergence des courbes sur le graphique cmp5 à partir de 4096 octets indique que sur les grandes tailles de message, le Pi exploite mieux son pipeline ARM pour ChaCha20 que pour AES — le ratio x86/Pi descend progressivement, révélant que l'avantage hardware d'AES-NI ne se propage pas à ChaCha20.

---

### 2.3 DES — Un fossile fonctionnel

DES fonctionne. C'est à peu près tout ce qu'on peut dire en sa faveur. Avec **40.70 MB/s** sur x86, il dépasse 3DES mais c'est sans intérêt : DES est **cryptographiquement mort** depuis 1998 (cassé en 22 heures par EFF DES Cracker). Sa clé effective de 56 bits est triviale à brute-forcer avec du matériel moderne.

Le ratio 2.23× entre x86 et Pi est cohérent avec la différence brute de puissance des CPUs — DES ne bénéficie d'aucune accélération matérielle sur x86, il s'exécute entièrement en logiciel des deux côtés.

---

### 2.4 3DES — Le pire des deux mondes

3DES est lent (**12.29 MB/s** x86 / **7.51 MB/s** Pi) ET faiblement sécurisé. L'application trois fois de DES donne une sécurité effective de 112 bits (en EDE avec deux clés distinctes) mais au coût de trois passages complets. Le NIST a déprécié 3DES en 2017 et son utilisation est interdite dans les nouveaux systèmes depuis 2023.

Fait notable : **3DES a le ratio le plus faible** (1.64×), ce qui signifie que le Pi est proportionnellement le moins pénalisé par 3DES. Cela s'explique par le fait que la performance de 3DES est déjà tellement contrainte par son design (trois passes DES séquentielles) que les optimisations architecturales de x86 n'apportent pas grand-chose — les deux plateformes sont également "misérables" avec cet algorithme.

---

### 2.5 Twofish — L'oublié de l'AES Contest

Twofish est catastrophiquement lent : **2.82 MB/s** sur x86 et **1.29 MB/s** sur Pi. Pour référence, AES est 147× plus rapide sur x86. Twofish a participé à la finale du concours AES en 1998 et a perdu face à Rijndael (AES) — en grande partie à cause de sa complexité de mise en œuvre et de sa performance.

Son key schedule complexe, ses MDS matrices et ses permutations dépendantes de la clé le rendent intrinsèquement lent en logiciel. Le ratio 2.19× entre plateformes confirme qu'il n'existe aucune accélération matérielle dédiée nulle part.

---

## 3. Analyse de l'effet d'avalanche — La santé cryptographique

L'effet d'avalanche mesure si le chiffrement "diffuse" correctement les changements : modifier un seul bit en entrée doit changer environ 50 % des bits en sortie. Un score de 0.50 est idéal.

**Scores moyens d'avalanche (toutes configurations) :**

| Algorithme | x86   | Pi    | Écart vs idéal | Verdict       |
|------------|-------|-------|----------------|---------------|
| AES        | 0.49974 | 0.49998 | ~0.002%     | ✅ Excellent  |
| 3DES       | 0.50042 | 0.50005 | ~0.004%     | ✅ Excellent  |
| Twofish    | 0.50040 | 0.49952 | ~0.004%     | ✅ Excellent  |
| DES        | 0.49815 | 0.50190 | ~0.19%      | ✅ Acceptable |
| ChaCha20   | **0.59477** | **0.59446** | **~9.5%** | ⚠️ Anomalie |

**L'anomalie ChaCha20 mérite une attention particulière.** Un score de 0.594 signifie que ~59.4 % des bits de sortie changent quand un bit d'entrée est modifié. Pour un chiffrement par bloc, l'idéal est 50 % (distribution aléatoire uniforme). Pour ChaCha20, qui est un chiffrement de flux, la notion d'avalanche est différente : le keystream est calculé indépendamment du plaintext, et le chiffrement est juste un XOR. Ce score élevé reflète probablement la façon dont la métrique est calculée sur un chiffrement par flux plutôt qu'une vraie faille — mais il convient de noter que **la méthodologie d'avalanche n'est pas directement transposable aux stream ciphers**.

---

## 4. Analyse de la sensibilité aux clés — La vraie faiblesse de DES

La sensibilité aux clés mesure combien de bits de sortie changent quand on flippe un seul bit de la **clé**. Score idéal : 0.50. C'est ici que les résultats deviennent vraiment intéressants.

**Scores moyens de key avalanche :**

| Algorithme | x86   | Pi    | Écart vs idéal | Verdict            |
|------------|-------|-------|----------------|--------------------|
| AES        | 0.50065 | 0.50013 | ~0.06%       | ✅ Excellent        |
| Twofish    | 0.50045 | 0.49965 | ~0.04%       | ✅ Excellent        |
| ChaCha20   | 0.59267 | 0.59367 | ~9.3%        | ⚠️ Voir note       |
| DES        | **0.43955** | **0.43766** | **~12%** | 🚨 Faible         |
| 3DES       | **0.44102** | **0.43610** | **~12%** | 🚨 Faible (hérité) |

**DES et 3DES ont une sensibilité aux clés structurellement déficiente.** Un score de 0.439 signifie que modifier un bit de la clé DES ne change que 43.9 % des bits de sortie — au lieu des 50 % attendus d'une distribution aléatoire. Cette faiblesse est **inhérente au key schedule de DES**, qui produit des sous-clés avec des propriétés connues (clés faibles, semi-faibles). Ce n'est pas un artefact de mesure : la cryptanalyse différentielle des clés de DES est documentée depuis les années 1990.

Pour 3DES, la faiblesse est directement héritée : appliquer DES trois fois ne corrige pas le key schedule défectueux.

**AES, en revanche, affiche 0.50065** — pratiquement parfait. L'algorithme de Rijndael a été spécifiquement conçu pour une diffusion maximale à travers toutes ses transformations.

---

## 5. Stabilité des mesures — Le bruit du monde réel

Le CI95 (intervalle de confiance à 95 %) mesure la dispersion des mesures de performance. Un CI95 élevé signifie que les performances sont erratiques — problématique pour les systèmes temps-réel.

| Algorithme | x86 CI95 | Pi CI95  | Observation |
|------------|----------|----------|-------------|
| ChaCha20   | 3.48     | 3.43     | Les deux très variables |
| AES        | 2.28     | 0.23     | x86 très variable, Pi stable |
| DES        | 0.40     | 0.19     | Modérément variable |
| 3DES       | 0.18     | 0.05     | Stable |
| Twofish    | 0.11     | 0.02     | Très stable (car très lent) |

**Observation contre-intuitive : le Raspberry Pi est plus stable que le laptop pour AES.** Le x86 montre un CI95 de 2.28 MB/s contre 0.23 MB/s sur Pi — un facteur 10. Cela s'explique par le contexte d'exécution : Windows 11 sur le laptop est un environnement multitâche agressif (processus en background, gestion de l'alimentation, Turbo Boost variable, caches L3 partagés). Le Pi sous Raspberry Pi OS est beaucoup plus déterministe.

**Implication pour les systèmes embarqués :** Pour une application IoT critique où la latence de chiffrement doit être prévisible (par exemple, un protocole temps-réel ou un HSM), le Pi avec ChaCha20 offre une performance plus consistante que le laptop avec AES — même si le débit brut est inférieur.

---

## 6. Vulnérabilités identifiées

### 🚨 Critique — ECB : l'éléphant dans la pièce

ECB (Electronic Codebook) est le mode le plus rapide dans nos mesures (**162.78 MB/s** sur x86) mais il est **cryptographiquement cassé**. ECB chiffre chaque bloc indépendamment avec la même clé : deux blocs de plaintext identiques produisent deux blocs de ciphertext identiques. Cela préserve les patterns dans les données, permettant à n'importe quel observateur — ou modèle d'IA — d'inférer des informations sur le contenu sans jamais casser la clé.

Le résultat le plus élevé du benchmark est donc le moins sécurisé. C'est l'exemple classique de l'optimisation qui va dans la mauvaise direction.

### 🚨 Critique — DES : mort depuis 1998

DES est présent dans les mesures, mais utiliser DES en production en 2026 est une faute professionnelle. Sa clé de 56 bits peut être brutée en quelques heures avec du matériel grand public.

### ⚠️ Sérieux — AES-CBC : paralysie sur les petits messages

Le débit de 0.73 MB/s pour AES-CBC-128 sur x86 à 4096 octets (contre 162.78 MB/s pour ECB) expose un risque d'implémentation : sous contrainte de performance, des développeurs moins avertis pourraient basculer vers ECB, désactiver l'IV, réutiliser des IVs, ou implémenter CBC incorrectement. La pression de performance est une cause réelle de régression de sécurité.

### ⚠️ Sérieux — Timing side-channel sur x86

Le CI95 élevé d'AES sur x86 (2.28 MB/s) révèle des variations temporelles exploitables. Des attaques de type **Flush+Reload** ou **Prime+Probe** sur les caches L1/L2 pourraient permettre à un processus attaquant coexécuté sur le même CPU de récupérer des bits de clé AES via des mesures temporelles. Sur le Pi, la faiblesse du cache et l'absence de SMT réduisent significativement cette surface d'attaque.

### ⚠️ Modéré — Faiblesse du key schedule DES/3DES

Le score de key avalanche ~0.439 de DES/3DES n'est pas juste une curiosité académique. Il implique que certaines clés DES (les 64 "weak keys" et "semi-weak keys" documentées) produisent un chiffrement significativement moins sécurisé. Une application qui génère des clés DES sans vérifier ces cas particuliers est vulnérable.

---

## 7. Points forts identifiés

### ✅ AES-256-GCM : le bon choix pour 2026

AES-GCM combine chiffrement et authentification (AEAD) dans un seul algorithme. Avec 25.78 MB/s sur x86 et 6.41 MB/s sur Pi, il offre à la fois confidentialité et intégrité sans overhead additionnel. Son CI95 modéré (2.02) reflète la complexité du mode mais reste acceptable. C'est la recommandation du NIST et de TLS 1.3.

### ✅ ChaCha20 sur ARM : le choix natif

ChaCha20 sur Pi (**61.27 MB/s**) surpasse AES-GCM sur Pi (6.41 MB/s) par un facteur 9.5. Pour tout déploiement sur architecture ARM (IoT, Raspberry Pi, téléphones Android), ChaCha20-Poly1305 est le choix optimal — c'est d'ailleurs pour cette raison qu'il est le chiffrement préféré de TLS 1.3 sur les appareils mobiles.

### ✅ Cohérence des scores d'avalanche inter-plateformes

Les scores d'avalanche de message d'AES, 3DES et Twofish sont rigoureusement identiques entre x86 et Pi (différences < 0.001). Cela confirme que la **propriété mathématique des algorithmes est indépendante de l'architecture** — la diffusion est une propriété du design, pas du hardware. L'expérience valide la correctness de l'implémentation sur les deux plateformes.

### ✅ Stabilité de Twofish sur Pi

Malgré ses performances misérables, Twofish affiche le CI95 le plus bas sur Pi (0.02 MB/s) — extrêmement prévisible. Dans un contexte hypothétique où la prévisibilité temporelle serait plus importante que le débit (certains HSMs, certains protocoles d'audit), Twofish serait le plus fiable. Ce n'est pas une recommandation pratique, mais une observation analytique.

---

## 8. Menaces émergentes — IA et Informatique Quantique

### 8.1 Grover's Algorithm — La menace quantique sur les clés symétriques

L'algorithme de Grover (1996) offre une accélération quadratique pour la recherche non-structurée. Appliqué au brute-force de clés symétriques, il réduit effectivement la sécurité de moitié en termes de bits :

| Algorithme | Clé réelle | Sécurité classique | Sécurité post-Grover | Verdict |
|------------|------------|-------------------|----------------------|---------|
| DES        | 56 bits    | ~56 bits          | **28 bits** | 🚨 Trivial à casser |
| 3DES       | 168 bits (EDE) | ~112 bits     | **56 bits** | 🚨 Équivalent DES classique |
| AES-128    | 128 bits   | 128 bits          | **64 bits** | ⚠️ Dangereux sur grands QC |
| AES-192    | 192 bits   | 192 bits          | **96 bits** | ✅ Suffisant |
| AES-256    | 256 bits   | 256 bits          | **128 bits** | ✅ Résistant quantique |
| ChaCha20   | 256 bits   | 256 bits          | **128 bits** | ✅ Résistant quantique |
| Twofish-256| 256 bits   | 256 bits          | **128 bits** | ✅ Résistant quantique |

**Conséquence directe :** AES-128, aujourd'hui parfaitement sécurisé classiquement, devient borderline face à un adversaire avec un ordinateur quantique suffisamment grand. Le NIST recommande déjà de migrer vers AES-256 pour toutes les applications nécessitant une sécurité à long terme (secrets d'État, données médicales, propriété intellectuelle).

DES et 3DES ne survivent à aucun modèle de menace post-2020. Leur présence dans nos benchmarks est strictement historique et pédagogique.

### 8.2 Attaques par IA — La nouvelle surface d'attaque

**8.2.1 ECB et reconnaissance de patterns par ML**

Un réseau de neurones convolutionnel (CNN) entraîné sur des données chiffrées en ECB peut inférer le contenu d'images, de documents structurés, ou de protocoles réseau sans jamais casser la clé. L'homogénéité des blocs dans ECB crée des patterns statistiques que les modèles de ML détectent facilement. Des travaux académiques (2020-2023) ont démontré la faisabilité de cette attaque sur des images JPEG chiffrées en AES-128-ECB avec un taux de reconnaissance de 70-90% selon le type d'image. Nos benchmarks montrent qu'ECB est de loin le mode le plus rapide — mais c'est le plus attaquable par IA.

**8.2.2 Timing Side-Channel augmenté par IA**

La variabilité temporelle observée dans nos données (CI95=2.28 pour AES x86) est exploitable par des attaques de timing classiques. L'IA amplifie cette menace : des modèles LSTM peuvent apprendre des profils de timing complexes sur des milliers de mesures et corriger le bruit de mesure par apprentissage, rendant des attaques timing pratiques qui nécessitaient auparavant une précision nanoseconde. Sur un système multitenant (cloud, VM partagées), la variance x86 observée crée une fenêtre réaliste pour ce type d'attaque.

**8.2.3 Key Schedule Analysis**

La faiblesse du key avalanche de DES (0.439) est précisément le type de structure non-aléatoire que les algorithmes d'apprentissage automatique détectent et exploitent. Des travaux récents (2022-2024) ont montré que des réseaux de neurones peuvent apprendre à distinguer des chiffrements avec des key schedules déficients de chiffrements idéaux, et dans certains cas retrouver des bits de clé à partir de paires plaintext/ciphertext connues avec moins d'effort qu'une cryptanalyse différentielle classique.

**8.2.4 ChaCha20 et les Stream Ciphers — Surface réduite**

L'anomalie d'avalanche de ChaCha20 (~0.594) mérite une mention dans un contexte IA : si ce score reflétait un vrai biais statistique dans le keystream, un modèle génératif pourrait théoriquement en tirer parti. Cependant, ChaCha20 passe tous les tests d'aléatoire connus (NIST SP800-22, TestU01), et l'observation est plus probablement un artefact de la mesure sur un stream cipher. Par sa conception constant-time, ChaCha20 est **la cible la moins attractive pour les attaques side-channel assistées par IA** — aucune variation temporelle à analyser.

### 8.3 Tableau des menaces — Synthèse

| Algorithme | Brute-force IA | ECB Pattern | Timing SC | Key Schedule AI | Grover | Recommandation |
|------------|:--------------:|:-----------:|:---------:|:---------------:|:------:|:--------------:|
| DES        | 🚨 Trivial     | N/A         | ⚠️ Faible | 🚨 Élevé        | 🚨     | **Abandonner** |
| 3DES       | ⚠️ Faisable    | N/A         | ⚠️ Faible | 🚨 Élevé        | 🚨     | **Abandonner** |
| AES-128/ECB| ✅ Solide       | 🚨 Critique | 🚨 Élevé  | ✅ Bon          | ⚠️     | **Mode interdit** |
| AES-128/CBC| ✅ Solide       | ✅ N/A      | 🚨 Élevé  | ✅ Bon          | ⚠️     | Déprécier     |
| AES-128/GCM| ✅ Solide       | ✅ N/A      | ⚠️ Moyen  | ✅ Bon          | ⚠️     | Acceptable    |
| AES-256/GCM| ✅ Solide       | ✅ N/A      | ⚠️ Moyen  | ✅ Bon          | ✅     | **Recommandé** |
| ChaCha20   | ✅ Solide       | N/A         | ✅ Minimal | ✅ Bon         | ✅     | **Recommandé** |
| Twofish-256| ✅ Solide       | N/A         | ✅ Minimal | ✅ Bon         | ✅     | Acceptable    |

---

## 9. Recommandations finales

**Pour un déploiement x86 (serveur, laptop) :**
→ **AES-256-GCM** pour tout chiffrement de données au repos ou en transit. Authentification intégrée, accélération matérielle, résistant aux menaces quantiques à long terme.

**Pour un déploiement ARM/IoT (Raspberry Pi, microcontrôleurs) :**
→ **ChaCha20-Poly1305** en priorité. Performances 9.5× supérieures à AES-GCM sur Pi, constant-time, résistant aux side-channels, résistant quantique avec clé 256 bits.

**À bannir immédiatement :**
→ DES, 3DES — aucune justification de sécurité en 2026.
→ Tout mode ECB — sur n'importe quel algorithme.

**À surveiller :**
→ AES-128 sur les systèmes devant rester sécurisés au-delà de 2035 — migrer vers AES-256 par précaution quantique.
→ Les implémentations AES sur systèmes multitenant — auditer les protections contre les timing side-channels (ASLR, isolation des caches).

---

*Rapport généré à partir des données expérimentales de l'expérience 3 — laptop-windows-x86 et raspberry-pi — INF1430, Mai 2026.*
