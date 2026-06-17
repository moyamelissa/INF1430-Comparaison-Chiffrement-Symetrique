# Plan de présentation — INF1430 TN3
### Comparaison de performance et de robustesse des algorithmes de chiffrement symétrique : x86 vs ARM

---

## Structure détaillée des diapositives

### Slide 1 — Titre
- Titre : *Comparaison expérimentale des algorithmes de chiffrement symétrique*
- Sous-titre : *Performance et robustesse : architecture x86 (Windows) vs ARM (Raspberry Pi)*
- Infos : INF1430 · Université TÉLUQ · TN3 · [Nom] · 2026
- Visuel : split CPU x86 vs Raspberry Pi board

### Slide 2 — Agenda
6 sections : Nature du système · Protocole · Validation KAT · Performance · Robustesse · Synthèse

### Slide 3 — Nature du système
- Diagramme d'architecture en couches (Scripts → Application → Domain → Cipher/Mode)
- 3 bullets : moteur expérimental, pas UI, isole la variable matérielle
- Callout FB1 : répétabilité via primitives C indépendantes de l'OS
- **▶ VIDEO 1** — Parcours repo VS Code, ouvrir `EncryptionEngine.py`, expliquer les couches (3–4 min)

### Slide 4 — Protocole expérimental
- Tableau specs plateformes : CPU, OS, RAM, AES-NI ✅/❌
- n=100, formule CI95 = 1.96 × σ/√n, 5 algos, 8 tailles de message
- Callout FB2 : convergence CI95 à n≈80-100
- **▶ VIDEO 2** — `experiment.py` en direct, CSV généré, justification n=100 (2–3 min)

### Slide 5 — Choix tech : Python
- Tableau Python vs C++ vs Java (performance, biais, reproductibilité, encodage)
- Callout FB3 : C++ mesurerait le compilateur autant que l'algorithme
- Callout FB4 : messages en `bytes` bruts via `os.urandom()` — pas de biais d'encodage

### Slide 6 — Validation KAT
- Tableau : AES ECB/GCM · DES · 3DES · ChaCha20 · AES CBC/CTR → tous ✅ PASS
- Références : NIST FIPS 197, SP 800-38D, SP 800-67, RFC 7539
- Statement : "toutes les implémentations sont correctes — les résultats de performance qui suivent sont fiables"
- **▶ VIDEO 3** — `run_kat.py` en direct, explication KAT (2 min)

### Slide 7 — AES : Comment ça marche
- Diagramme : 10 tours, SubBytes → ShiftRows → MixColumns → AddRoundKey
- Callout AES-NI (orange) : 1 tour = 1 cycle CPU · Intel/AMD depuis 2010 → 5.58× x86/Pi
- **▶ VIDEO 4** — Explication AES visuellement, ce que AES-NI fait en hardware (3–4 min)

### Slide 8a — AES : Débit global
- **Graphique : `cmp1_throughput_all.png`** (pleine largeur)
- AES x86 domine à 163 MB/s · ChaCha20 2ème · Twofish/3DES en queue
- Callout : "l'écart AES n'est pas dû au CPU — c'est AES-NI (slide suivant)"

### Slide 8b — AES : L'écart x86/Pi expliqué
- **Graphique : `cmp2_speedup_ratio.png`** (pleine largeur)
- AES ratio 4.1× · ChaCha20 1.6× · 3DES 1.27×
- Callout : "AES-NI = 1 tour en 1 cycle. Sans ça, le Pi fait le même travail 4× plus lent"
- **▶ VIDEO 5** — Commenter les deux graphiques, expliquer CBC séquentiel vs ECB parallélisable (3 min)

### Slide 8c — AES : Le piège des modes
- **Graphique : `fig3_aes_mode_comparison.png`** (pleine largeur)
- ECB 162 MB/s (cassé) · GCM recommandé · CBC chiffrement 0.73 MB/s
- Callout rouge : "CBC = 223× plus lent qu'ECB — risque de régressions de sécurité"

### Slide 9 — ChaCha20 : Comment ça marche
- Diagramme ARX (Addition · Rotation · XOR) × 20 tours → Keystream ⊕ Plaintext
- Tableau contraste AES vs ChaCha20 : S-Box vs ARX, AES-NI requis vs natif partout, timing vulnérabilité vs constant-time
- **▶ VIDEO 6** — Expliquer ARX, pourquoi pas de cache timing, pourquoi c'est TLS 1.3 mobile (2–3 min)

### Slide 10 — ChaCha20 : Résultats
- **Graphique : `cmp5_chacha20.png`** (pleine largeur)
- 114 MB/s x86 · 61 MB/s Pi · ratio 1.87× (le plus équitable)
- Callout : "Sur Pi, ChaCha20 (61 MB/s) surpasse AES-GCM sur Pi (6.4 MB/s) par 9.5× → choix IoT/mobile évident"
- **▶ VIDEO 7** — Commenter le graphique, lien IoT/mobile/TLS 1.3 (2 min)

### Slide 11 — DES / 3DES / Twofish
- 3 colonnes : DES (mort 1998, 56 bits) · 3DES (déprécié 2023, 3× plus lent) · Twofish (147× plus lent qu'AES)
- Badges : ⚠️ Déprécié · 🚨 Interdit · ❌ Obsolète
- **▶ VIDEO 8** — Explication rapide et punchy pourquoi chacun a perdu (2 min)

### Slide 12 — Vulnérabilité ECB
- **Graphique : `fig8_ecb_vulnerability.png`** (pleine largeur)
- (a) Original · (b) ECB — patterns visibles ⚠️ · (c) CBC — bruit ✅
- 3 bullets : blocs indépendants, identiques plaintext = identiques ciphertext, structure inférable sans casser la clé
- Callout rouge : "ECB = 162 MB/s — résultat le plus élevé ET le seul mode cassé"
- **▶ VIDEO 9** — `ecb_visual_vulnerability.py` en direct (1–2 min)

### Slide 13 — Effet d'avalanche
- **Graphique : `cmp4_avalanche.png`** (large)
- Tableau verdicts : AES 0.4997 ✅ · 3DES 0.5004 ✅ · Twofish 0.5004 ✅ · DES 0.4982 ✅ · ChaCha20 0.5948 ⚠️
- Callout ambre : anomalie ChaCha20 = limite de méthodologie, pas une faille (stream cipher ≠ block cipher)
- **▶ VIDEO 10** — "Flipper un bit", idéal 50%, faiblesse DES, anomalie ChaCha20 expliquée (3 min)

### Slide 14 — Sensibilité aux clés
- **Graphique : `fig4b_key_avalanche.png`** (large)
- Tableau : AES 0.5007 ✅ · Twofish 0.5005 ✅ · DES 0.4396 🚨 · 3DES 0.4410 🚨
- Callout rouge : "64 clés faibles DES documentées depuis les années 90 — 3DES hérite du problème"

### Slide 15 — Stabilité (CI95)
- **Graphique : `cmp6_ci95_stability.png`** (pleine largeur)
- AES x86 CI95 = 11.28 MB/s vs Pi = 2.0 → laptop 5.6× plus erratique
- Callout : "Windows 11 = Turbo Boost, background processes, L3 partagés. Pi OS = déterministe par nature"
- **▶ VIDEO 11** — "Le résultat contre-intuitif", systèmes temps-réel, HSM (2 min)

### Slide 16 — Synthèse & Recommandations
- Flowchart décisionnel : x86 → AES-256-GCM · ARM/IoT → ChaCha20-Poly1305 · Legacy → AES-CBC ⚠️ · DES/3DES → ❌ · ECB → ❌
- Tableau référence : contexte → algorithme → mode → raison
- Footnote : "Conformes à NIST SP 800-175B et RFC 8446 (TLS 1.3)" — adresse FB5
- **▶ VIDEO 12** — "Si je devais déployer aujourd'hui...", lien résultats → choix réels (2–3 min)

### Slide 17 — Conclusion & TN4
- Colonne gauche ✅ : 5 algos implémentés + validés, 2 plateformes, ~600 mesures, avalanche + CI95 + ECB analysés
- Colonne droite 🔜 : analyse des hypothèses, comparaison Stallings/NIST, rapport final
- Timeline : TN1 → TN2 → **TN3** → TN4
- Closing : *"Le choix d'un algorithme n'est pas qu'une décision de sécurité — c'est une décision d'architecture, de plateforme, et de contexte."*
- Dernière ligne : Merci · Questions ? · [Nom] · INF1430 · TÉLUQ · 2026

---

## Récapitulatif des graphiques utilisés

| Fichier | Slide | Description |
|---------|-------|-------------|
| `cmp1_throughput_all.png` | 8a | Débit global x86 vs Pi — tous algos |
| `cmp2_speedup_ratio.png` | 8b | Ratio d'accélération x86/Pi |
| `fig3_aes_mode_comparison.png` | 8c | AES-128 : ECB / CBC / CTR / GCM |
| `cmp5_chacha20.png` | 10 | ChaCha20 x86 vs Pi sur toutes tailles |
| `fig8_ecb_vulnerability.png` | 12 | Demo visuelle ECB vs CBC |
| `cmp4_avalanche.png` | 13 | Scores d'avalanche x86 vs Pi |
| `fig4b_key_avalanche.png` | 14 | Avalanche texte clair vs clé |
| `cmp6_ci95_stability.png` | 15 | Stabilité CI95 x86 vs Pi |

---

## Récapitulatif des vidéos (12 vidéos)

| # | Slide | Sujet | Durée | Type |
|---|-------|-------|-------|------|
| 1 | 3 | Parcours repo + architecture | 3–4 min | Écran + voix |
| 2 | 4 | `experiment.py` en direct + n=100 | 2–3 min | Écran + voix |
| 3 | 6 | `run_kat.py` en direct + explication KAT | 2 min | Écran + voix |
| 4 | 7 | Comment fonctionne AES + AES-NI | 3–4 min | Écran + voix |
| 5 | 8b | Résultats AES commentés (cmp1 + cmp2) | 3 min | Écran + voix |
| 6 | 9 | Comment fonctionne ChaCha20 (ARX) | 2–3 min | Écran + voix |
| 7 | 10 | Résultats ChaCha20 commentés | 2 min | Écran + voix |
| 8 | 11 | DES / 3DES / Twofish — pourquoi ils ont perdu | 2 min | Écran + voix |
| 9 | 12 | `ecb_visual_vulnerability.py` en direct | 1–2 min | Écran + voix |
| 10 | 13 | Effet d'avalanche + anomalie ChaCha20 | 3 min | Écran + voix |
| 11 | 15 | CI95 — le résultat contre-intuitif | 2 min | Écran + voix |
| 12 | 16 | Recommandations finales | 2–3 min | Caméra ou écran |

**Durée totale estimée : ~30–35 min**

---

## Feedbacks TN2 adressés

| Feedback | Slide | Comment adressé |
|----------|-------|-----------------|
| FB1 — Répétabilité ≠ environnement contrôlé | 3 | Répétabilité via primitives C identiques sur les deux OS |
| FB2 — Pourquoi n répétitions ? | 4 | Formule CI95, convergence à n≈80-100 |
| FB3 — C++ permet l'accès aux primitives bas niveau | 5 | C++ mesurerait le compilateur — Python isole la variable matérielle |
| FB4 — Encodage peut différer Linux/Windows | 5 | Messages en `bytes` bruts via `os.urandom()` — pas de conversion str/unicode |
| FB5 — Comparer avec la littérature (Stallings) | 16 | Footnote NIST SP 800-175B + RFC 8446 dans la synthèse |

