# Références RFC utilisées (KAT et recommandations)

Ce document centralise les RFC utilisées dans les tests et dans les recommandations de sélection d'algorithmes.

## Références principales

| RFC | Lien officiel | Utilisation dans le projet |
|---|---|---|
| RFC 8439 | https://www.rfc-editor.org/rfc/rfc8439 | Vecteurs KAT ChaCha20 (validation de conformité). |
| RFC 8446 | https://www.rfc-editor.org/rfc/rfc8446 | Contexte TLS 1.3 pour les recommandations d'usage modernes. Ce RFC est obsolète ; voir RFC 9846. |
| RFC 9846 | https://www.rfc-editor.org/rfc/rfc9846/ | Mise à jour de la spécification TLS 1.3. |

## Ressources locales associées

- Implémentation/validation ChaCha20 : `crypto-experiments/validation/kat_chacha20.py`
- Pilotage global KAT : `crypto-experiments/scripts/run_kat.py`
- Sélection KAT du projet : `docs/07-KAT/kat_selection.md`
