# KAT-twofish

Ce dossier contient les vecteurs KAT Twofish utilisés pour la validation du projet.

## Pourquoi ce dossier existe

- Assurer la traçabilité des vecteurs utilisés dans les tests.
- Permettre une validation reproductible, même hors ligne.
- Conserver une source de référence locale pour les profils `core` et `full`.

## Contenu

- `ECB_VK (2).TXT` : famille de vecteurs variable key.
- `ECB_VT (2).TXT` : famille de vecteurs variable text.
- `ECB_TBL (2).TXT` : famille de vecteurs table.
- `ECB_E_M.TXT`, `ECB_D_M.TXT`, `ECB_IVAL.TXT`, `CBC_E_M.TXT`, `CBC_D_M.TXT` : fichiers complémentaires.
- `README (2)` : fichier d'origine fourni avec le corpus.

## Note sur la structure

La structure a été simplifiée pour garder un seul dossier `KAT-twofish` sans sous-dossier imbriqué.

## Référence de provenance

- Corpus Twofish public (soumission d'algorithme par Schneier et al., historique AES).
- Les tests du projet lisent les vecteurs Twofish depuis `resources/KAT/Twofish-kat/`.

