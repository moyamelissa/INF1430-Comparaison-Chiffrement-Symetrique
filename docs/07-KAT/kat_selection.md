# Méthode de sélection KAT (TN3)

## Objectif

Ce document explique comment les vecteurs KAT ont été sélectionnés dans ce projet, avec :

- la source de référence utilisée
- les vecteurs et scénarios retenus
- la raison de la sélection
- le nombre d'assertions obtenu

L'objectif est de conserver une méthode transparente et défendable pour TN3.

## Deux stratégies possibles

### Stratégie A - Noyau équilibré (recommandé pour les diapositives principales TN3)

- Utiliser un sous-ensemble réduit et représentatif pour chaque suite.
- Garder une comparaison équitable entre suites.
- Présenter un total compact comme indicateur principal.

### Stratégie B - Corpus étendu (recommandé pour l'annexe et la démo)

- Utiliser les corpus publics complets quand ils existent (par exemple les fichiers Twofish ECB VK, VT, TBL).
- Obtenir une meilleure profondeur, mais moins de symétrie avec les suites qui reposent sur des sous-ensembles ciblés.
- Présenter ce résultat séparément comme validation étendue.

Formulation recommandée pour TN3 : montrer la stratégie A dans le corps principal, et la stratégie B en annexe.

## Détails de sélection par suite (exécution par défaut)

### AES

- Vecteurs retenus : 4 vecteurs au total (2 pour AES-128, 1 pour AES-192, 1 pour AES-256), chacun vérifié avec correspondance au chiffrement et aller-retour au déchiffrement.
- Référence : NIST FIPS 197 (annexes A, B, C).
- Méthode de sélection : un vecteur canonique de type known-answer par taille de clé, plus un cas de robustesse AES-128 clé nulle et texte nul.
- Justification : couvrir toutes les tailles de clé sans exécuter un corpus trop volumineux dans l'exécution principale TN3.
- Assertions : 8.

### DES

- Vecteurs retenus : 9 couples texte clair / texte chiffré tirés d'un sous-ensemble de la table 1 SP 800-17, chacun vérifié avec correspondance au chiffrement et aller-retour au déchiffrement.
- Référence : NIST SP 800-17, table 1.
- Méthode de sélection : les 8 premières entrées plus la dernière entrée de la table.
- Justification : préserver une couverture représentative des positions de bits tout en gardant un temps d'exécution compact.
- Assertions : 18.

### 3DES

- Vecteurs retenus : 2 vecteurs (un cas TDEA à 2 clés et un cas TDEA à 3 clés), chacun vérifié avec correspondance au chiffrement et aller-retour au déchiffrement.
- Référence : NIST SP 800-67 Rev.2 (comportement EDE), avec valeurs attendues recoupées par implémentation de référence.
- Méthode de sélection : un vecteur représentatif valide pour chaque option de keying.
- Justification : garantir la couverture des deux schémas de clés avec un surcoût minimal.
- Assertions : 4.

### Modes (ECB, CBC, CTR)

- Vecteurs retenus : KAT de charge utile ECB + aller-retour, KAT de charge utile CBC + aller-retour, vérification ciblée du flot CTR + aller-retour.
- Référence : NIST SP 800-38A, annexe F.
- Méthode de sélection : un scénario ciblé par comportement de mode, aligné sur les détails d'implémentation du projet.
- Justification : valider chaque chemin de mode (exactitude de la charge utile et déchiffrabilité pratique) sans jeu combinatoire massif.
- Assertions : 6.

### AES-GCM

- Vecteurs retenus : TC3 et TC4 issus du NIST, chacun vérifié sur la sortie de chiffrement, le déchiffrement avec vérification, et la détection de falsification.
- Référence : NIST SP 800-38D, annexe B.
- Méthode de sélection : cas de texte clair non vide qui exercent les chemins AEAD principaux.
- Justification : vérifier confidentialité et intégrité dans un ensemble compact.
- Assertions : 6.

### ChaCha20

- Vecteurs retenus : un KAT de chiffrement known-answer RFC 8439, plus des aller-retours du wrapper (64 B, 256 B, longueur impaire), plus un test de falsification et une validation de taille de clé.
- Référence : RFC 8439.
- Méthode de sélection : combinaison d'un vecteur normatif strict et de vérifications de robustesse spécifiques à l'implémentation.
- Justification : assurer à la fois la justesse mathématique et la robustesse de l'enveloppe logicielle.
- Assertions : 6.

### Twofish (profil noyau, par défaut)

- Vecteurs retenus : 1 vecteur représentatif par famille ECB_VK, ECB_VT, ECB_TBL, chacun vérifié avec correspondance au chiffrement et aller-retour au déchiffrement.
- Référence : Schneier et al. (1998), vecteurs de soumission Counterpane.
- Méthode de sélection : un vecteur canonique par famille depuis le corpus public officiel.
- Justification : garder une comparaison inter-suites équilibrée pour les résultats principaux TN3 tout en conservant une source externe de référence.
- Assertions : 6.

Total exécution par défaut (profil noyau) : 54 assertions.

## Profil Twofish étendu (optionnel)

- Variable d'environnement : `TWOFISH_KAT_PROFILE=full`
- Effet : exécute le corpus complet (ECB_VK 576 vecteurs, ECB_VT 384 vecteurs, ECB_TBL 147 vecteurs)
- Assertions en profil complet : 2214 pour Twofish, 2262 au total

## Détails Twofish (corpus étendu)

- ECB_VK : 576 vecteurs, 1152 assertions.
- ECB_VT : 384 vecteurs, 768 assertions.
- ECB_TBL : 147 vecteurs, 294 assertions.
- Total Twofish étendu : 1107 vecteurs, 2214 assertions.

## Si vous choisissez un TN3 principal équilibré

Deux options propres :

1. Conserver le code actuel et présenter :
   - Résultat principal : total du sous-ensemble équilibré (sans Twofish étendu)
   - Résultat annexe : Twofish étendu (2214) comme validation additionnelle

2. Ajouter un sous-ensemble Twofish noyau pour la comparaison principale :
   - Exemple : 1 à 2 vecteurs par famille (VK, VT, TBL), chacun avec chiffrement + déchiffrement
   - Puis conserver l'exécution corpus complet en annexe

## Formulation orale suggérée

"Notre résultat principal compare des sous-ensembles représentatifs homogènes entre suites. En complément, nous exécutons une validation étendue Twofish sur le corpus public complet des auteurs (ECB_VK/VT/TBL), présentée séparément comme test de stress cryptographique."
