# Références RFC utilisées (KAT et recommandations)

Ce document centralise les RFC utilisées dans les tests et dans les recommandations de sélection d'algorithmes.

## Références principales

| RFC | Lien officiel | Utilisation dans le projet |
|---|---|---|
| RFC 8439 | https://www.rfc-editor.org/rfc/rfc8439 | Vecteurs KAT ChaCha20 (validation de conformité). |
| RFC 8446 | https://www.rfc-editor.org/rfc/rfc8446 | Contexte TLS 1.3 pour les recommandations d'usage modernes. |

## Ressources locales associées

- Implémentation/validation ChaCha20 : `crypto-experiments/validation/kat_chacha20.py`
- Pilotage global KAT : `crypto-experiments/scripts/run_kat.py`
- Sélection KAT du projet : `docs/07-KAT/kat_selection.md`

## Remarque

Les liens ci-dessus pointent vers le RFC Editor pour garantir une source canonique et stable.
