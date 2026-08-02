# KAT-twofish

Ce dossier contient une copie documentaire des vecteurs KAT Twofish utilisés dans le projet.

## Pourquoi ce dossier existe

- Assurer la traçabilité des vecteurs utilisés dans les tests.
- Permettre une validation reproductible, même hors ligne.
- Conserver une source de référence locale pour consultation.

## Contenu

- `ECB_VK.TXT` : famille de vecteurs variable key.
- `ECB_VT.TXT` : famille de vecteurs variable text.
- `ECB_TBL.TXT` : famille de vecteurs table.
- `ECB_E_M.TXT`, `ECB_D_M.TXT`, `ECB_IVAL.TXT`, `CBC_E_M.TXT`, `CBC_D_M.TXT` : fichiers complémentaires.

## Source active utilisée par les scripts

Les scripts KAT exécutent la validation Twofish depuis :

- `resources/KAT/Twofish-kat/`

Ce dossier actif contient aussi les empreintes `ECB_VK.TXT.sha256`, `ECB_VT.TXT.sha256` et `ECB_TBL.TXT.sha256` pour la vérification d'intégrité avant exécution du profil strict.

## Note sur la structure

Cette copie documentaire est volontairement plate et sans sous-dossier imbriqué.

## Référence de provenance

- Corpus Twofish public (soumission d'algorithme par Schneier et al., historique AES).
- Les tests du projet lisent les vecteurs Twofish depuis `resources/KAT/Twofish-kat/`.

