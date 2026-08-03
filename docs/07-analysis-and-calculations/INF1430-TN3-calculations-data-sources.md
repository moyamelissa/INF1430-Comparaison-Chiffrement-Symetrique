# Calculs & sources — INF1430 TN3
### Traçabilité des valeurs présentées dans [INF1430_PPT_TN3.pptx](INF1430_PPT_TN3.pptx)

> **Statut du document :** snapshot intermédiaire de la phase TN3. Les valeurs de ce fichier correspondent à une campagne antérieure et ne remplacent pas les résultats consolidés finaux de TN4.

**Fichiers de données principaux :**
- x86 : [windows_experience3.csv](../../crypto-experiments/data/results/windows_experience3.csv)
- Pi  : [raspberry-pi_experience3.csv](../../crypto-experiments/data/results/raspberry-pi_experience3.csv)

Toutes les valeurs sont extraites de ces deux fichiers, sauf indication contraire.

---

## Slide 4 — Protocole expérimental

| Valeur | Source | Calcul |
|--------|--------|--------|
| 5 paliers de taille | CSV : colonnes `message_size_bytes` | `{64, 256, 1024, 4096, 16384}` — union des valeurs distinctes dans experience3 |
| 64 octets → 16 384 octets | CSV | Min et max de `message_size_bytes` |
| n = 100 répétitions | CSV : colonne `repetitions` | Valeur constante dans toutes les lignes |
| IC₉₅ = 1,96 × σ / √n | Formule statistique | z-score de la loi normale à 95 % · n=100 → IC₉₅ disponible dans colonne `ci95_encrypt_mbps` de [experience3](../../crypto-experiments/data/results/windows_experience3.csv) |
| CPU x86 : Intel Core i5-10300H | Matériel (vérifié physiquement) | — |
| CPU Pi : ARM Cortex-A72 | Matériel Raspberry Pi 4 (vérifié physiquement) | — |
| 32 Go RAM x86 | Matériel | — |
| 4 Go RAM Pi | Matériel Raspberry Pi 4 | — |
| AES-NI ✓ x86 / ✗ Pi | Architecture | Intel depuis 2010 · ARM Cortex-A72 sans AES-NI hardware |

---

## Slide 7 — AES : Comment ça marche

| Valeur | Source | Calcul |
|--------|--------|--------|
| Blocs de 128 bits | NIST FIPS 197 | Standard AES |
| Clés 128/192/256 bits → 10/12/14 tours | NIST FIPS 197 | Standard AES |
| AES-NI depuis 2010 | Intel Architecture Reference | — |
| x86 est 5,58× plus rapide | [x86 CSV](../../crypto-experiments/data/results/windows_experience3.csv) · [Pi CSV](../../crypto-experiments/data/results/raspberry-pi_experience3.csv) | AES-256 ECB 16384B : x86=417,07 MB/s ÷ Pi=74,73 MB/s = **5,58×** |

> **Note :** le ratio 5,58× est calculé sur les valeurs de pic (16 384 octets, AES-256 ECB).

---

## Slide 8 — Débit global : x86 vs Raspberry Pi

**Configuration** : ECB (Stream pour ChaCha20) · 4 096 octets · meilleure clé par algorithme

| Algorithme | Clé | x86 (MB/s) | Pi (MB/s) | Arrondi slide | Source CSV |
|------------|-----|-----------|----------|---------------|-----------|
| AES | 256 bit | 162,78 | 45,97 | 163 / 46 | AES ECB 256bit 4096B |
| DES | 64 bit | 34,59 | ~17,5 | 35 | DES ECB 64bit 4096B |
| 3DES | 192 bit | 5,98 | ~4,71 | 6 | 3DES ECB 192bit 4096B |
| Twofish | 256 bit | 2,82 | 1,25 | 3 | Twofish ECB 256bit 4096B |
| ChaCha20 | 256 bit | 93,90 | 58,12 | 94 / 58 | ChaCha20 Stream 256bit 4096B |

**Calcul ratio Twofish vs AES :**
> 162,78 ÷ 2,82 = **57,7×** → arrondi **57×**

**Graphique** : [comparison-throughput-all.png](../../crypto-experiments/data/charts/01-throughput/comparison-throughput-all.png)

---

## Slide 9 — AES : L'écart x86/Pi expliqué

**Configuration** : ECB (Stream pour ChaCha20) · 4 096 octets · meilleure clé par algorithme

| Algorithme | x86 (MB/s) | Pi (MB/s) | Ratio | Source CSV |
|------------|-----------|----------|-------|-----------|
| AES | 162,78 | 45,97 | **3,54×** | AES ECB 256bit 4096B |
| DES | 34,59 | 17,50 | **1,98×** | DES ECB 64bit 4096B |
| 3DES | 5,98 | 4,71 | **1,27×** | 3DES ECB 192bit 4096B |
| Twofish | 2,82 | 1,25 | **2,26×** | Twofish ECB 256bit 4096B |
| ChaCha20 | 93,90 | 58,12 | **1,61×** | ChaCha20 Stream 256bit 4096B |

**Graphique** : [comparison-speedup-ratio.png](../../crypto-experiments/data/charts/01-throughput/comparison-speedup-ratio.png)

---

## Slide 10 — AES : Le piège des modes d'opération

**Configuration** : AES-128 · 4 096 octets · x86

| Mode | Débit chiffrement (MB/s) | Arrondi slide | Source CSV |
|------|--------------------------|---------------|-----------|
| ECB | 162,78 | 163 | AES ECB 128bit 4096B |
| GCM | 25,78 | 25 | AES GCM 128bit 4096B |
| CTR | 6,61 | 6,6 | AES CTR 128bit 4096B |
| CBC | 0,73 | 0,73 | AES CBC 128bit 4096B |

**Calcul ratio ECB/CBC :**
> 162,78 ÷ 0,73 = **223×**

**Graphique** : [aes-mode-comparison.png](../../crypto-experiments/data/charts/03-encryption-modes/aes-mode-comparison.png)

---

## Slides 12 & 13 — ChaCha20 vs AES

| Valeur | Configuration | x86 | Pi | Calcul |
|--------|--------------|-----|----|--------|
| Débit ChaCha20 (pic) | Stream 256bit 16384B | **114,31 MB/s** | **61,27 MB/s** | Valeurs max dans experience3 |
| Ratio x86/Pi (pic) | Stream 256bit 16384B | — | — | 114,31 ÷ 61,27 = **1,87×** |
| Débit ChaCha20 (4096B) | Stream 256bit 4096B | 93,90 MB/s | **58,12 MB/s** | Ligne directe CSV |
| Débit AES-GCM Pi | GCM 128bit 4096B | — | **6,41 MB/s** | [raspberry-pi_experience3.csv](../../crypto-experiments/data/results/raspberry-pi_experience3.csv) |
| Avantage ChaCha20/AES-GCM sur Pi | — | — | — | 58,12 ÷ 6,41 = **9,07×** → arrondi **9,1×** |

**Graphique** : [chacha20-comparison.png](../../crypto-experiments/data/charts/05-algorithm-comparison/chacha20-comparison.png)

---

## Slide 14 — DES, 3DES, Twofish

**Configuration** : ECB · meilleure clé · valeur de pic (toutes tailles)

| Algorithme | x86 pic (MB/s) | Pi pic (MB/s) | Arrondi slide |
|------------|---------------|--------------|---------------|
| DES | 40,70 | 18,27 | 40,7 / 18,3 |
| 3DES | 12,29 | 7,51 | 12,3 / 7,5 |
| Twofish | 2,82 | 1,29 | 2,82 / 1,29 |

**Calcul AES vs Twofish (163 MB/s référence 4096B) :**
> 162,78 ÷ 2,82 = **57,7×** → arrondi **57×**

**Références historiques :**
- DES cassé en 22h en 1998 : EFF DES Cracker (Electronic Frontier Foundation)
- 3DES déprécié : NIST SP 800-131A Rev. 2 (2019) → interdit dans nouveaux systèmes depuis 2023
- Clé effective 3DES (2-clés EDE) : 112 bits

---

## Slide 16 — Effet d'avalanche

**Source** : colonne `avalanche_score` · experience3 · moyennes sur toutes configurations x86

| Algorithme | Score moyen x86 | Score moyen Pi | Arrondi slide | Idéal |
|------------|----------------|---------------|---------------|-------|
| AES | 0,4997 | 0,49998 | 0,4997 | 0,500 |
| 3DES | 0,5004 | 0,50005 | 0,5004 | 0,500 |
| Twofish | 0,5004 | 0,49952 | 0,5004 | 0,500 |
| DES | 0,4982 | 0,50190 | 0,4982 | 0,500 |
| ChaCha20 | 0,5948 | 0,5945 | 0,5948 | ⚠️ stream cipher |

**Graphique** : [comparison-avalanche.png](../../crypto-experiments/data/charts/02-avalanche-effect/comparison-avalanche.png)

---

## Slide 17 — Sensibilité aux clés

**Source** : colonne `key_avalanche_score` · experience3 · configuration spécifique (ECB, meilleure clé, 4096B)

| Algorithme | Score clé (x86) | Arrondi slide | Verdict |
|------------|----------------|---------------|---------|
| AES | 0,500 | 0,500 | Parfait |
| Twofish | 0,500 | 0,500 | Excellent |
| ChaCha20 | 0,594 | 0,594 | Voir sl.12 |
| DES | 0,438 | 0,438 | Faible |
| 3DES | 0,436 | 0,436 | Faible |

**Note DES :** 64 clés "faibles" documentées depuis les années 1990 — NIST SP 800-67.

**Graphique** : [key-avalanche-detailed.png](../../crypto-experiments/data/charts/02-avalanche-effect/key-avalanche-detailed.png)

---

## Slide 18 — Stabilité CI95

**Source** : colonne `ci95_encrypt_mbps` · experience3 · ECB (Stream pour ChaCha20) · 256bit (64bit DES, 192bit 3DES) · 4 096 octets

| Algorithme | CI95 x86 (MB/s) | CI95 Pi (MB/s) | Arrondi slide |
|------------|----------------|---------------|---------------|
| AES | 11,280 | 2,060 | 11,28 / 2,06 |
| DES | 0,989 | 0,790 | 0,99 / — |
| 3DES | 0,732 | 0,181 | 0,73 / — |
| Twofish | 0,096 | 0,007 | ≈0,10 / ≈0 |
| ChaCha20 | 6,378 | 4,868 | 6,38 / — |

**Calcul ratio AES x86/Pi :**
> 11,280 ÷ 2,060 = **5,47×** → arrondi **5,5×**

**Graphique** : [ci95-stability.png](../../crypto-experiments/data/charts/05-algorithm-comparison/ci95-stability.png)

---

## Slide 15 — Vulnérabilité ECB

**Images générées par** : [build_ecb_demo.py](../../crypto-experiments/scripts/charts/build_ecb_demo.py)

| Fichier | Description |
|---------|-------------|
| [image-original.bmp](../../crypto-experiments/data/charts/03-encryption-modes/demo-ecb/image-original.bmp) | Image originale (régions uniformes visibles) |
| [image-encrypted-ecb.bmp](../../crypto-experiments/data/charts/03-encryption-modes/demo-ecb/image-encrypted-ecb.bmp) | Image chiffrée AES-ECB (patterns préservés) |
| [image-encrypted-cbc.bmp](../../crypto-experiments/data/charts/03-encryption-modes/demo-ecb/image-encrypted-cbc.bmp) | Image chiffrée AES-CBC (bruit uniforme) |

**Référence théorique** : Penguin ECB — démonstration classique de la faiblesse du mode ECB, documentée dans Stallings *Cryptography and Network Security* et NIST SP 800-38A.

---

## Références normatives

| Référence | Utilisation dans la présentation |
|-----------|----------------------------------|
| NIST FIPS 197 | AES — standard, tailles de clés, nombre de tours |
| NIST SP 800-38A | Modes AES : CBC, CTR |
| NIST SP 800-38D | Mode AES-GCM (AEAD) |
| NIST SP 800-67 Rev. 2 | DES et 3DES — spécifications et dépréciation |
| NIST SP 800-131A Rev. 2 | 3DES déprécié 2017, interdit nouveaux systèmes 2023 |
| NIST SP 800-175B | Recommandations cryptographiques 2026 |
| RFC 8439 | ChaCha20 — vecteurs de test KAT |
| RFC 8446 | TLS 1.3 — justification des recommandations |
| Bernstein, D.J. (2008) | ChaCha20 — conception ARX, optimisation logicielle |

---

## Fichiers de données

| Fichier | Plateforme | Contenu |
|---------|-----------|---------|
| [windows_experience1.csv](../../crypto-experiments/data/results/windows_experience1.csv) | x86 | Débit + avalanche (sans key_avalanche ni ci95) |
| [windows_experience2.csv](../../crypto-experiments/data/results/windows_experience2.csv) | x86 | Débit + avalanche + key_avalanche |
| [windows_experience3.csv](../../crypto-experiments/data/results/windows_experience3.csv) | x86 | Débit + avalanche + key_avalanche + ci95 ← **utilisé** |
| [raspberry-pi_experience1.csv](../../crypto-experiments/data/results/raspberry-pi_experience1.csv) | Pi ARM | Débit + avalanche |
| [raspberry-pi_experience2.csv](../../crypto-experiments/data/results/raspberry-pi_experience2.csv) | Pi ARM | Débit + avalanche + key_avalanche |
| [raspberry-pi_experience3.csv](../../crypto-experiments/data/results/raspberry-pi_experience3.csv) | Pi ARM | Débit + avalanche + key_avalanche + ci95 ← **utilisé** |



