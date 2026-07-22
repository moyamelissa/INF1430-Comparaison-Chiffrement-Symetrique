# INF1430 TN4 Protocole de preuve de validation

## Objectif
Fournir des preuves vérifiables montrant que l'implémentation est suffisamment correcte pour soutenir les conclusions TN4, avec des limites explicites et des étapes de reproductibilité.

## Modèle de preuve
Le projet s'appuie sur un modèle de preuve en couches.

1. Preuve de correction fonctionnelle
- La suite complète de tests automatisés réussit.
- Le seuil de couverture est strict à 100 pour cent des lignes et 100 pour cent des branches.

2. Preuve de conformité cryptographique
- Les suites KAT réussissent sur toutes les primitives et tous les modes pris en charge.
- Le KAT Twofish prend en charge une politique stricte sur les vecteurs externes et une vérification optionnelle des sommes de contrôle.

3. Preuve de robustesse
- Les tests de chemins d'échec couvrent les entrées malformées, la détection d'altération et les échecs en mode strict.
- Les tests différentiels comparent les sorties à des implémentations de référence fiables.

4. Preuve de validité statistique
- Les seuils d'audit IC95 sont validés avec un résultat explicite de succès ou d'échec.
- Les artefacts d'audit sont exportés pour révision.

## Étapes d'exécution reproductibles
Exécuter toutes les commandes depuis la racine du dépôt, sauf indication contraire.

### Générer un dossier de preuves
Utiliser le script de génération pour exporter les journaux, les artefacts et les métadonnées de commit dans un seul dossier.

Depuis la racine du dépôt
```powershell
python crypto-experiments/scripts/validation_bundle.py
```

Depuis crypto-experiments
```powershell
python scripts/validation_bundle.py
```

Emplacement de sortie du dossier de preuves
- crypto-experiments/data/results/validation-bundles/bundle-<timestamp>

Le dossier de preuves inclut
- journal pytest
- journal KAT
- journal des seuils IC95
- coverage.xml
- ic95_raw_rows.csv
- ic95_audit_report.csv
- bundle_manifest.json avec le hash de commit et les codes de retour des commandes

### Exécution locale Windows
```powershell
cd crypto-experiments
..\.venv\Scripts\Activate.ps1
python -m pytest
python scripts/run_kat.py --twofish-profile full --twofish-checksum warn
python scripts/audit/audit_ic95.py --enforce-gates
```

### Exécution locale Raspberry Pi
```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
python -m pytest
python scripts/run_kat.py --twofish-profile full --twofish-checksum warn
python scripts/audit/audit_ic95.py --enforce-gates
```

## Mode strict d'intégrité Twofish
Le mode strict est utilisé lorsque les fichiers officiels et les fichiers compagnons de somme de contrôle sont disponibles.

```bash
python scripts/run_kat.py \
  --twofish-profile full \
  --strict-twofish-vectors \
  --twofish-checksum enforce
```

Ressources requises pour le mode strict
- Resources/KAT/Twofish-kat/ECB_VK.TXT
- Resources/KAT/Twofish-kat/ECB_VT.TXT
- Resources/KAT/Twofish-kat/ECB_TBL.TXT
- Les fichiers compagnons .sha256 correspondants pour chaque fichier

## Signaux attendus
1. Tests
- Tous les tests réussissent.
- Le résumé de couverture indique 100 pour cent des lignes et 100 pour cent des branches.

2. KAT
- Le terminal se termine par ALL KAT SUITES PASSED.
- Si le mode strict est activé, l'absence de vecteurs ou une somme de contrôle invalide doit provoquer un échec.

3. IC95
- Le terminal contient Quality gate enforcement PASS.
- Les artefacts sont écrits sous data/results/audit.

## Politique GitHub de protection de branche
Appliquer cette politique à la branche main.

1. Exiger une pull request avant fusion
2. Exiger au moins une approbation de revue
3. Annuler les approbations périmées lorsqu'un nouveau commit est poussé
4. Exiger la réussite des vérifications de statut avant fusion
5. Vérifications obligatoires
- Tests / pytest
- Tests / kat
- Tests / ic95-audit
6. Restreindre les pushes directs vers main
7. Soumettre aussi les administrateurs à ces règles

Cette politique transforme la qualité technique en qualité de gouvernance, ce qui est essentiel
pour défendre l'intégrité des résultats en TN4.
