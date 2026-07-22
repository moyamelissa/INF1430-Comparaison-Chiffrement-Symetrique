# Références NIST utilisées (KAT et validation)

Ce document centralise les publications NIST utilisées par les tests, l'analyse et la justification méthodologique.

## Références principales

| Référence | Lien officiel | Utilisation dans le projet |
|---|---|---|
| FIPS 197 (AES) | https://csrc.nist.gov/pubs/fips/197/final | Base normative pour AES (tailles de clé, comportement attendu). |
| SP 800-38A | https://csrc.nist.gov/pubs/sp/800/38/a/final | Modes ECB, CBC, CTR; vecteurs KAT de modes. |
| SP 800-38D | https://csrc.nist.gov/pubs/sp/800/38/d/final | AES-GCM (AEAD), cas de validation d'intégrité. |
| SP 800-67 Rev.2 | https://csrc.nist.gov/pubs/sp/800/67/r2/final | TDEA / 3DES (comportement EDE, statut). |
| SP 800-131A Rev.2 | https://csrc.nist.gov/pubs/sp/800/131/a/r2/final | Transition cryptographique et statut d'usage des algorithmes. |
| SP 800-175B | https://csrc.nist.gov/pubs/sp/800/175/b/final | Recommandations de sélection et d'usage cryptographique. |

## Ressources locales associées

- Rapport de protocole validation : `docs/03-analysis-and-calculations/INF1430-TN4-validation-proof-protocol.md`
- Détails IC95 : `docs/03-analysis-and-calculations/INF1430-TN3-IC95-calcul-detail.md`
- Scripts d'audit : `crypto-experiments/scripts/audit/`

## Remarque

Les liens ci-dessus pointent vers les pages officielles NIST (CSRC) pour garantir la traçabilité des sources normatives.
