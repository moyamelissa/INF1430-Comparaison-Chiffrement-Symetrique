# Références Twofish utilisées (KAT et validation)

Références Twofish principales utilisées pour les vecteurs KAT, la validation locale et la justification méthodologique.

## Références principales

| Référence | Lien officiel | Utilisation dans le projet |
|---|---|---|
| Twofish - page officielle | https://www.schneier.com/academic/twofish/ | Point d’entrée principal vers la documentation Twofish, les téléchargements et les archives associées. |
| The Twofish paper | https://www.schneier.com/paper-twofish-paper.html | Description du chiffrement Twofish, de sa conception et de ses paramètres. |
| Source Code | https://www.schneier.com/cryptography/twofish/download.html | Implémentation et matériel de référence publiés par les auteurs. |
| Test Vectors | https://www.schneier.com/wp-content/uploads/2015/12/ecb_ival.txt | Vecteur de test ECB de référence pour les vérifications ponctuelles. |
| Known-Answer Tests | https://www.schneier.com/wp-content/uploads/2015/12/twofish-kat.zip | Corpus KAT public Twofish utilisé comme base de validation. |

## Ressources locales associées

- Implémentation de validation Twofish : `crypto-experiments/validation/kat_twofish.py`
- Corpus KAT local : `docs/07-KAT/KAT-twofish/`
- Sélection KAT du projet : `docs/07-KAT/kat_selection.md`

## Intégrité des fichiers KAT (SHA256)

Les fichiers de référence Twofish `ECB_VK.TXT`, `ECB_VT.TXT` et `ECB_TBL.TXT` sont protégés par des fichiers `.sha256`. Le CI vérifie l’intégrité des données de test avant chaque exécution KAT.

Concrètement, chaque fichier `.sha256` contient l’empreinte attendue de son fichier de vecteurs.

- `ECB_VK.TXT.sha256` pour `ECB_VK.TXT`
- `ECB_VT.TXT.sha256` pour `ECB_VT.TXT`
- `ECB_TBL.TXT.sha256` pour `ECB_TBL.TXT`

Pendant l’exécution CI, le projet recalcule l’empreinte SHA256 des fichiers réels, puis compare le résultat à l’empreinte stockée.

- Si les empreintes correspondent, les fichiers KAT n’ont pas été modifiés silencieusement
- Si les empreintes diffèrent, le pipeline signale une anomalie d’intégrité

## Plain English explanation

**A hash is a fingerprint for data.**

Take any file, run SHA256 on it, and you get a 64-character fingerprint.

- Same file gives the same fingerprint
- A tiny byte-level change gives a different fingerprint

In this project, each Twofish KAT file has a matching `.sha256` sidecar file. CI hashes the real file, compares it with the sidecar hash, and fails if they differ.

This detects accidental edits, transfer corruption, or tampering of test vectors.

Important limit:

The hash check does **not** prove the Twofish implementation is correct. It proves only that test data integrity is preserved.

The proof of algorithmic correctness comes from KAT execution itself, where produced ciphertext and decrypted plaintext are compared against known expected answers.

Together:

- SHA256 sidecars protect vector integrity
- KAT execution validates cryptographic behavior
- Combined, they provide stronger validation evidence