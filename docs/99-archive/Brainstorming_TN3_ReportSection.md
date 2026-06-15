TN3 = Implémentation et expérimentation — this is Phase 2 + Phase 3 of your roadmap. You already have the code working and your CSV data collected, so the report sections most relevant are:
Most critical:

Résultats expérimentaux / Performance — you need this to interpret and present your throughput measurements (débit), which you already have in the CSV files (experiences 1, 2, 3)
Effet d'avalanche — you'll need to document your avalanche analysis results per primitive
Validation fonctionnelle (KAT) — to show your implementations pass the Known Answer Tests against NIST reference vectors

Supporting sections:

Modes d'opération (ECB, CBC, CTR, GCM) — to contextualize your experimental configurations and justify observed differences
Description des algorithmes (AES, DES, 3DES, Twofish) — brief reference for your implementation choices
Protocole expérimental — to confirm your methodology matches what was planned in TN1

Less priority for TN3 (more relevant for TN4):

Deep analysis and interpretation of hypotheses — that's the TN4 final report
Security conclusions — also TN4



Table 1 — Validation fonctionnelle (KAT)
Columns: Algorithme | Mode | Statut KAT | Référence NIST
Purpose: show your implementations are correct before presenting any performance data.
Table 2 — Débit de chiffrement moyen par algorithme et mode (laptop Windows x86)
Columns: Algorithme | Taille de clé | Mode | Msg 1KB (MB/s) | Msg 4KB (MB/s) | Msg 16KB (MB/s)
Purpose: the main performance comparison, fed directly from your CSV data.
Table 3 — Débit de déchiffrement moyen (même structure)
Purpose: separate from encryption since ECB enc vs dec can differ, as your fig5_enc_vs_dec_ecb.png already shows.
Table 4 — Variabilité des mesures (écart-type)
Columns: Algorithme | Mode | Msg size | Moy (MB/s) | Écart-type | CV (%)
Purpose: demonstrates statistical rigour and repeatability of your experiments.
Table 5 — Effet d'avalanche par algorithme
Columns: Algorithme | Bits modifiés (%) | Écart-type | Conformité théorique (~50%)
Purpose: covers your diffusion analysis, independent of modes.
Table 6 — Synthèse de l'état d'avancement TN3
Columns: Composant | Statut | Notes
Purpose: a quick status table showing what's implemented, tested, and collected — standard for a mid-point deliverable like TN3.


1. Introduction
Rappel des objectifs du projet, ce que TN3 couvre spécifiquement (phases 2 et 3 : implémentation + expérimentation), et un bref état d'avancement depuis TN2.
2. Implémentation réalisée
Description du code livré — les primitives (AES, DES, 3DES, Twofish), les modes (ECB, CBC, CTR, GCM), et l'architecture modulaire. Référence à ce qui avait été conçu en TN2 pour montrer la continuité.
3. Validation fonctionnelle (KAT)
Présentation des résultats des Known Answer Tests contre les vecteurs NIST. C'est le prérequis qui crédibilise toute la suite.
4. Protocole expérimental appliqué
Brève description de comment les expériences ont été conduites concrètement — plateforme(s), répétitions, tailles de messages. Pas besoin de tout réécrire depuis TN1, juste confirmer ce qui a été suivi ou ajusté.
5. Résultats expérimentaux
Le cœur du rapport — vos tableaux et figures de débit (chiffrement/déchiffrement), l'effet d'avalanche, et l'influence de la taille de message. C'est là que vos CSV et figures entrent.
6. Difficultés rencontrées et ajustements
Ce qui n'a pas marché comme prévu, les adaptations faites. Votre superviseur attend ça — ça montre du recul.
7. Conclusion et perspectives vers TN4
Résumé de ce qui est livré, ce qui reste (analyse approfondie, Raspberry Pi si pas encore fait), et ce qui sera fait en TN4.



Structure de la présentation TN3
Slide 1 — Page titre
Titre, noms, cours INF1430, date
Sous-titre : Comparaison de performance et de robustesse des algorithmes de chiffrement symétrique : x86 vs ARM
Slide 2 — Plan de la présentation
Liste des sections (5-6 points max)
Slide 3 — Rappel : Nature du système (adresse FB1)
Texte : Moteur expérimental, pas une app UI
Diagramme : Architecture en couches (du TN2)
Point clé à ajouter : "La répétabilité est assurée non par l'environnement contrôlé, mais par l'indépendance des primitives cryptographiques : PyCryptodome délègue aux mêmes routines C compilées sur les deux OS — les octets sont des octets, indépendants de la plateforme."
→ Répond directement au commentaire "un environnement contrôlé ne garantit pas la répétabilité"
Slide 4 — Protocole expérimental : Justification de n (adresse FB2)
Tableau : n = 100 répétitions → pourquoi?
Graphique : Courbe de convergence du CI95 en fonction de n (montrer que l'intervalle se stabilise autour de n=80-100)
Formule : 
C
I
95
=
1.96
×
σ
n
CI 
95
​
 =1.96× 
n
​
 
σ
​
 
Message : n=100 a été choisi comme seuil où l'IC à 95 % devient stable — au-delà, le gain de précision est marginal par rapport au coût CPU
Slide 5 — Choix technologique : Python vs C++ vs Java (adresse FB3 + FB4)
Tableau comparatif des 3 langages (performance, biais, reproductibilité)
Adresser le commentaire C++ : "C++ permet effectivement l'accès aux primitives bas niveau et à AES-NI directement — cela aurait produit des débits plus élevés, mais mesuré les optimisations du compilateur autant que les algorithmes. Notre objectif étant de comparer les algorithmes entre plateformes, Python+PyCryptodome isole mieux la variable matérielle."
Adresser l'encodage (FB4) : "L'encodage des messages est fixé en bytes bruts (os.urandom) — pas de conversion str/unicode impliquée, éliminant les biais d'encodage Linux/Windows."
Slide 6 — Plateformes testées
Tableau : Specs CPU, RAM, OS, fréquence, présence/absence AES-NI
Photo du Raspberry Pi + schéma architecture x86 vs ARM
Slide 7 — Résultats : Débit global (cmp1)
Graphique : cmp1_throughput_all.png
3 observations clés en bullet points
Slide 8 — Résultats : Ratio x86 / ARM (cmp2)
Graphique : cmp2_speedup_ratio.png
Tableau : Ratio par algorithme (AES 5.58×, ChaCha20 1.87×, etc.)
Explication : AES-NI = accélération matérielle câblée → ChaCha20 révèle le vrai ratio de puissance CPU brute (~2×)
Slide 9 — Résultats : Impact de la taille des messages (cmp3)
Graphique : cmp3_throughput_vs_size.png
Observation clé : AES passe de 1.37 MB/s (64 B) à 382 MB/s (16 KB) → coût fixe du key scheduling
Slide 10 — Anomalie : AES-CBC chiffrement vs déchiffrement
Tableau :
Mode	Chiffrement (MB/s)	Déchiffrement (MB/s)
ECB	162.78	184.09
GCM	25.78	22.19
CBC	0.73	7.69
Explication : ci = E(pi ⊕ c_{i-1}) → séquentiel par design → AES-NI ne peut pas pipeliner le chiffrement CBC
Slide 11 — Résultats : Effet d'avalanche (cmp4)
Graphique : cmp4_avalanche.png
Tableau key avalanche :
Algorithme	Key Avalanche	Idéal
AES	0.500	0.500
DES	0.439	0.500
3DES	0.441	0.500
Message : Faiblesse structurelle du key schedule DES — mesurable et confirmée par nos données
Slide 12 — Comparaison avec la littérature (adresse FB5)
*C'est le slide le plus important pour répondre au feedback
Tableau à construire :

Métrique	Nos résultats	Valeur Stallings / NIST
Avalanche AES (score)	0.4997	~0.50 attendu (Stallings Ch.5)
Avalanche DES (score)	0.4982	~0.50 attendu (Stallings Ch.3)
AES rounds avant convergence	~3-4 tours	4 tours (Stallings Ch.5, SP800-38)
DES rounds avant convergence	~5-6 tours	5-6 tours (Stallings Ch.3)
Ratio perf AES/DES	10.2×	AES connu ~10× + rapide (NIST AES FIPS 197)
Key schedule DES weak keys	confirmé	64 weak keys documentées (Stallings Ch.3)
Référence : William Stallings, Cryptography and Network Security, 8e éd., Ch. 3 (DES), Ch. 5 (AES), Ch. 6 (modes)
Slide 13 — ChaCha20 : le cas ARM (cmp5)
Graphique : cmp5_chacha20.png
Message : Sur ARM, ChaCha20 (61 MB/s) > AES-GCM (6.4 MB/s) × 9.5 → design constant-time sans dépendance hardware → choix optimal IoT
Slide 14 — Analyse de sécurité : Vulnérabilités
Tableau ECB/CBC/DES/3DES avec verdict rouge/orange/vert
Capture d'écran du résultat ECB visual vulnerability (si tu as le script ecb_visual_vulnerability.py)
Slide 15 — Menaces IA et Quantique (bonus / "surprise me")
Tableau : Grover's algorithm — sécurité effective post-quantum par algorithme
3 bullet points : ECB + ML, timing side-channel, key schedule AI analysis
Recommandation finale : AES-256-GCM (x86) / ChaCha20-Poly1305 (ARM)
Slide 16 — Conclusion
Hypothèses de départ → réponses confirmées/infirmées
3 trouvailles majeures en bullet points
Slide 17 — Référence à la vidéo de démonstration
Screenshot du terminal avec experiment.py en cours
Liste de ce que la vidéo montre : lancement du benchmark, génération CSV, génération des graphiques
Ce que la vidéo doit montrer (selon l'exigence TN3)
Lancement de experiment.py sur le Raspberry Pi → progression visible
Résultat CSV généré dans data/results/
Lancement de compare_platforms.py sur le laptop
Ouverture des 5 graphiques générés
(Optionnel) Lancement de run_kat.py → 26 tests PASS
Point critique à ne pas oublier : les feedbacks 1-5 doivent chacun être adressés verbalement ou visuellement dans les slides correspondants — le professeur a commenté des sections précises du TN2 et vérifiera que les lacunes sont comblées dans TN3.