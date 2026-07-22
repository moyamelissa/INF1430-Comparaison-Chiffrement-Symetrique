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