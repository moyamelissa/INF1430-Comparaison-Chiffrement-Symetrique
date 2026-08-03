# Références NIST utilisées (KAT et validation)

Références NIST principales utilisées dans les tests, l'analyse et la justification méthodologique.

## Références principales

| Référence | Lien officiel | Utilisation dans le projet |
|---|---|---|
| NIST FIPS 197 - Advanced Encryption Standard (AES) | https://csrc.nist.gov/pubs/fips/197/final | Base normative pour AES (tailles de clé, comportement attendu). |
| NIST SP 800-38A - Recommendation for Block Cipher Modes of Operation: Methods and Techniques | https://csrc.nist.gov/pubs/sp/800/38/a/final | Modes ECB, CBC, CTR et vecteurs KAT associés. |
| NIST SP 800-38D - Galois/Counter Mode (GCM) and GMAC | https://csrc.nist.gov/pubs/sp/800/38/d/final | AES-GCM (AEAD) et validation d'intégrité. |
| NIST SP 800-67 Rev. 2 - Recommendation for the Triple Data Encryption Algorithm (TDEA) Block Cipher | https://csrc.nist.gov/pubs/sp/800/67/r2/final | TDEA / 3DES (comportement EDE). Withdrawn le 1er janvier 2024. |
| NIST SP 800-131A Rev. 2 - Transitioning the Use of Cryptographic Algorithms and Key Lengths | https://csrc.nist.gov/pubs/sp/800/131/a/r2/final | Transition cryptographique et statut d'usage des algorithmes. |
| NIST SP 800-175B - Guideline for Using Cryptographic Standards in the Federal Government: Cryptographic Mechanisms | https://csrc.nist.gov/pubs/sp/800/175/b/final | Recommandations de sélection et d'usage cryptographique. Withdrawn le 31 mars 2020. Suppléé par [SP 800-175B Rev. 1](https://csrc.nist.gov/pubs/sp/800/175/b/r1/final). |

## Ressources locales associées

- Scripts d'audit : `crypto-experiments/scripts/audit/`
