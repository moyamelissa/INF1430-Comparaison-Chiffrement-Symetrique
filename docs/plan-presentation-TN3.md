# Plan de présentation — INF1430 TN3
### Comparaison de performance et de robustesse des algorithmes de chiffrement symétrique : x86 vs ARM

---

## Structure des diapositives (17 slides + 12 vidéos)

| # | Diapositive | Contenu sur la slide | Vidéo complémentaire | Contenu de la vidéo |
|---|-------------|----------------------|----------------------|---------------------|
| 1 | **Title** | Nom du projet, noms, date, sous-titre | — | — |
| 2 | **Agenda** | Plan en 6 points | — | — |
| 3 | **Nature du système** | Diagramme d'architecture, "moteur expérimental pas une app UI" | **VIDEO 1** | Parcours du repo dans VS Code — montrer les couches (domain/engine/application), ouvrir `EncryptionEngine.py`, expliquer les décisions de conception |
| 4 | **Protocole expérimental** | Tableau specs plateformes, n=100, formule CI95 | **VIDEO 2** | Lancer `experiment.py` en direct, expliquer pourquoi n=100, montrer un CSV généré |
| 5 | **Choix tech : Python** | Tableau comparatif Python vs C++ vs Java | — | (slide courte, pas de vidéo) |
| 6 | **Validation KAT** | Tableau NIST pass/fail par algorithme | **VIDEO 3** | Lancer `run_kat.py` en direct, expliquer ce qu'est un KAT et pourquoi c'est le prérequis de crédibilité avant toute donnée de performance |
| 7 | **AES — Comment ça marche** | Diagramme : tours, SubBytes, AES-NI | **VIDEO 4** | Expliquer AES visuellement — les 10 tours, ce que AES-NI fait en hardware, pourquoi ça explique l'écart x86/Pi |
| 8 | **AES — Résultats** | Graphique AES x86 vs Pi, tableau modes (ECB/GCM/CTR/CBC) | **VIDEO 5** | Parcourir le graphique — "regardez cet écart 5.58×, voici pourquoi..." — expliquer CBC séquentiel vs ECB parallélisable |
| 9 | **ChaCha20 — Comment ça marche** | Diagramme ARX, conçu pour le logiciel pur | **VIDEO 6** | Expliquer les opérations ARX, pourquoi l'absence de S-Box élimine les vulnérabilités de cache timing, contraste avec AES |
| 10 | **ChaCha20 — Résultats** | Graphique ChaCha20 x86 vs Pi (ratio 1.87×) | **VIDEO 7** | "L'algorithme le plus équitable entre plateformes — pourquoi c'est important pour l'IoT et le mobile", montrer la convergence des courbes |
| 11 | **DES / 3DES / Twofish** | Tableau comparatif rapide — les trois "perdants" | **VIDEO 8** | Expliquer pourquoi chacun a échoué : DES 56 bits mort, 3DES triple coût, Twofish key schedule complexe — ~2 min |
| 12 | **Vulnérabilité ECB** | Côte à côte : image chiffrée ECB (patterns visibles) vs CBC (bruit) | **VIDEO 9** | Lancer `ecb_visual_vulnerability.py` en direct — montrer l'image apparaître, expliquer pourquoi blocs identiques = ciphertext identiques = catastrophique |
| 13 | **Effet d'avalanche** | Tableau scores d'avalanche, anomalie ChaCha20 surlignée | **VIDEO 10** | "Flipper un bit — qu'est-ce qui se passe en sortie ?" Expliquer l'idéal 50%, la faiblesse DES (0.439), pourquoi le 0.59 de ChaCha20 est un problème de méthodologie pas une faille |
| 14 | **Sensibilité aux clés** | Tableau key avalanche, DES 0.439 vs AES 0.500 | (couvert dans VIDEO 10) | — |
| 15 | **Stabilité (CI95)** | Tableau CI95 — Pi plus stable que le laptop | **VIDEO 11** | "Le résultat contre-intuitif" — expliquer Turbo Boost, bruit de Windows en background, pourquoi le Pi est plus déterministe pour les systèmes temps-réel |
| 16 | **Synthèse & recommandations** | Flowchart décisionnel : quel algo pour quel contexte | **VIDEO 12** | "Si je devais déployer quelque chose aujourd'hui..." — parcourir le flowchart, connecter les résultats aux choix réels (TLS 1.3, IoT, systèmes legacy) |
| 17 | **Conclusion & TN4** | Ce qui est livré, ce qui vient ensuite | — | — |

---

## Récapitulatif des vidéos (12 vidéos)

| # | Sujet | Durée approx. | Type |
|---|-------|---------------|------|
| 1 | Parcours du repo + architecture | 3–4 min | Écran + voix |
| 2 | `experiment.py` en direct + justification n=100 | 2–3 min | Écran + voix |
| 3 | KAT en direct + explication | 2 min | Écran + voix |
| 4 | Comment fonctionne AES (théorie) | 3–4 min | Écran + voix ou animation |
| 5 | Résultats AES commentés | 3 min | Écran + voix |
| 6 | Comment fonctionne ChaCha20 (théorie) | 2–3 min | Écran + voix |
| 7 | Résultats ChaCha20 commentés | 2 min | Écran + voix |
| 8 | DES / 3DES / Twofish — pourquoi ils ont perdu | 2 min | Écran + voix |
| 9 | Vulnérabilité ECB en démo visuelle | 1–2 min | Écran + voix |
| 10 | Effet d'avalanche expliqué + résultats | 3 min | Écran + voix |
| 11 | Stabilité CI95 — la surprise | 2 min | Écran + voix |
| 12 | Recommandations finales | 2–3 min | Caméra ou écran |

**Durée totale estimée des vidéos : ~30–35 min**

---

## Notes sur les feedbacks TN2 adressés

| Feedback | Slide | Comment adressé |
|----------|-------|-----------------|
| FB1 — Répétabilité ≠ environnement contrôlé | Slide 3 | Expliquer que la répétabilité vient de l'indépendance des primitives C via PyCryptodome |
| FB2 — Pourquoi n répétitions ? | Slide 4 | Graphique de convergence CI95 en fonction de n, formule CI95 = 1.96 × σ/√n |
| FB3 — C++ permet l'accès aux primitives bas niveau | Slide 5 | Reconnaître l'avantage C++, expliquer pourquoi Python isole mieux la variable matérielle |
| FB4 — Encodage peut différer Linux/Windows | Slide 5 | Préciser que les messages sont en `bytes` bruts via `os.urandom`, pas de conversion str/unicode |
| FB5 — Comparer avec la littérature (Stallings) | Slide 16 | Mentionner les références dans la synthèse finale |
