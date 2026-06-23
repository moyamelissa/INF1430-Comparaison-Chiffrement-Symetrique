# Video 3 - Validation KAT

## Objectif
Valider la conformite cryptographique des implementations avant toute interpretation des performances.

## Portee
- Dossier validation/
- Fichiers kat_aes.py, kat_des.py, kat_3des.py, kat_modes.py, kat_gcm.py, kat_chacha20.py
- Script scripts/run_kat.py
- Execution terminal en direct

## Guide d'enregistrement

### Introduction (voix off)
Bienvenue dans cette video consacree a la validation cryptographique. Avant d'analyser les debits, il faut absolument verifier que nos implementations produisent les bons resultats. On va vous montrer comment fonctionne ce systeme de controle KAT. Dans le dossier validation, on a des fichiers de test pour chaque algorithme: AES, DES, 3DES, les modes, GCM et ChaCha20. Chaque fichier valide un composant precis avec des vecteurs de reference officiels NIST. Puis, le script run_kat.py orchestre tout ca en une seule commande. Le lien entre ces fichiers est simple: chaque module retourne un nombre d'echecs, et run_kat agrege ces resultats pour dire pass ou fail. Pourquoi c'est critique? Parce que sans cette validation, on risquerait d'interpreter des mesures de performance sur une base incorrecte. Commençons.

### Section 0
**Titre :** Vue d'ensemble de la couverture KAT

**Action ecran :**
Ouvrir le dossier validation/ dans VS Code et montrer les fichiers.

**Arborescence visuelle :**
```
validation/
├── kat_aes.py      (test FIPS 197 AES-128/192/256)
├── kat_des.py      (test SP 800-17 DES)
├── kat_3des.py     (test SP 800-67 3DES)
├── kat_modes.py    (test SP 800-38A ECB/CBC/CTR)
├── kat_gcm.py      (test SP 800-38D AES-GCM)
├── kat_chacha20.py (test RFC 8439 ChaCha20)
└── __init__.py     (package marker)
```

**Narration fluide :**
Voici le dossier validation. Chaque fichier correspond a une famille d'algorithmes. AES valide les trois variantes de cle. DES et 3DES valident les standards classiques. Les modes testent ECB, CBC, CTR. GCM valide l'authentification. ChaCha20 valide la famille stream cipher moderne. Cette couverture systematique garantit qu'aucun composant cryptographique n'est oublie.

**Flux du processus :**
Chaque fichier kat_*.py expose une fonction run(). Quand run_kat.py demarre, il appelle toutes ces fonctions dans l'ordre. Aucune suite ne peut etre ignoree.

### Section 1
**Titre :** Point d'entree de la validation globale

**Code :** scripts/run_kat.py - import des suites et declaration de main

```python
from validation import kat_aes, kat_des, kat_3des, kat_modes, kat_gcm, kat_chacha20

def main() -> None:
	suites = [
		("AES  (FIPS 197)",                   kat_aes.run),
		("DES  (SP 800-17)",                  kat_des.run),
		("3DES (SP 800-67)",                  kat_3des.run),
		("Modes ECB/CBC/CTR (SP 800-38A)",    kat_modes.run),
		("AES-GCM (SP 800-38D)",              kat_gcm.run),
		("ChaCha20 (RFC 8439)",               kat_chacha20.run),
	]
```

**Narration fluide :**
Ici, on voit le point d'entree de la campagne KAT. La fonction main construit une liste de suites, et chaque suite contient un nom lisible plus une fonction run a appeler. C'est une architecture modulaire: chaque algorithme garde sa logique dans son propre fichier, tandis que run_kat centralise l'orchestration. Autrement dit, ce script joue le role de chef d'orchestre.

**Flux du processus :**
Le script run_kat appelle successivement les fonctions run des modules kat_aes, kat_des, kat_3des, kat_modes, kat_gcm et kat_chacha20. Chaque module retourne un nombre d'echecs. main agrege ces retours pour prendre une decision globale.

### Section 2
**Titre :** Boucle de suites et agregation des resultats

**Code :** scripts/run_kat.py - boucle for, compteur total_failures, code de sortie

```python
	total_failures = 0
	for name, run_fn in suites:
		failures = run_fn(verbose=True)
		total_failures += failures

	sys.exit(0 if total_failures == 0 else 1)
```

**Narration fluide :**
Cette boucle for execute chaque suite de test comme une tache independante. Le parametre verbose=True demande une sortie detaillee, utile pour la demo et le diagnostic. Ensuite, total_failures additionne tous les echecs pour produire un statut final unique. Le code de sortie devient alors un contrat machine: 0 signifie conformite globale, 1 signifie qu'au moins une partie de la chaine crypto est non conforme.

**Flux du processus :**
main -> boucle for -> run_fn(verbose=True) -> retour failures -> agregation dans total_failures -> sys.exit. C'est ce flux qui relie les tests unitaires cryptographiques a une decision executable en terminal ou en CI.

### Section 3
**Titre :** Structure du module KAT AES

**Code :** validation/kat_aes.py - docstring, imports, classe AES importee

```python
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from domain.cipher.AES import AES
```

**Narration fluide :**
Ici, le module kat_aes prepare son contexte d'execution puis importe la classe AES depuis le domaine crypto. Le concept important est la separation des responsabilites: la classe AES implemente l'algorithme, et le module KAT valide son comportement avec des references officielles. Le test ne remplace pas la classe, il l'instancie et l'observe.

**Flux du processus :**
kat_aes depend de la classe AES. Le module de test cree des instances AES avec des cles connues, puis appelle les methodes de chiffrement/dechiffrement pour verifier les sorties.

### Section 4
**Titre :** Fonction utilitaire de conversion

**Code :** validation/kat_aes.py - fonction _h

```python
def _h(hex_str: str) -> bytes:
	return bytes.fromhex(hex_str.replace(" ", ""))
```

**Narration fluide :**
Cette fonction utilitaire convertit une chaine hexadecimale en bytes. Techniquement, c'est une fonction de normalisation de format. Elle permet de passer d'une representation humaine des vecteurs NIST a une representation binaire compatible avec les methodes de la classe AES. Sans elle, les comparaisons seraient fragiles ou incoherentes.

**Flux du processus :**
Vecteur texte -> fonction _h -> bytes valides -> injectes dans l'instance AES et dans les comparaisons attendues.

### Section 5
**Titre :** Fonction run de kat_aes et parametres de test

**Code :** validation/kat_aes.py - signature, compteur, vecteurs

```python
def run(verbose: bool = True) -> int:
	failures = 0
	vectors_128 = [ ... ]
	vectors_192 = [ ... ]
	vectors_256 = [ ... ]
```

**Narration fluide :**
La fonction run est l'API publique du module KAT AES. Le parametre verbose controle le niveau de trace, et la valeur de retour int represente le nombre d'echecs detectes. Les trois collections vectors_128, vectors_192 et vectors_256 structurent les cas de test par type de cle. Cette organisation rend le code lisible, maintenable et extensible si on ajoute de nouveaux vecteurs.

**Flux du processus :**
run initialise failures, charge les vecteurs, puis prepare une execution homogene sur AES-128, AES-192 et AES-256 avant de retourner le total des anomalies.

### Section 6
**Titre :** Boucle principale, instance AES et comparaison chiffrement/dechiffrement

**Code :** validation/kat_aes.py - all_vectors, boucle for, appels de methode

```python
all_vectors = (
	[(v, 16) for v in vectors_128]
	+ [(v, 24) for v in vectors_192]
	+ [(v, 32) for v in vectors_256]
)

for vec, _key_len in all_vectors:
	key = _h(vec["key"])
	plain = _h(vec["plain"])
	cipher = _h(vec["cipher"])

	aes = AES(key)

	result = aes.encrypt_block(plain)
	result_dec = aes.decrypt_block(cipher)
```

**Narration fluide :**
Ici, on voit le flux technique principal. D'abord, les comprehension de liste construisent un seul ensemble de tests. Ensuite, la boucle for traite chaque vecteur un par un. Pour chaque iteration, la fonction _h convertit les champs en bytes, puis on cree une instance de la classe AES avec la cle du cas courant. Cette instance expose deux methodes: encrypt_block et decrypt_block. La logique KAT compare ensuite les sorties obtenues aux sorties attendues, et incremente failures si une divergence apparait. C'est un controle deterministe: meme parametres, meme resultat attendu.

**Flux du processus :**
run -> boucle for sur all_vectors -> _h pour normaliser les parametres -> instance AES(key) -> encrypt_block/decrypt_block -> comparaison -> increment failures -> retour int vers run_kat.main.

### Section 7
**Titre :** Execution terminal et interpretation

**Code :** commande de lancement

```powershell
python scripts/run_kat.py
```

**Narration fluide :**
Quand on lance cette commande, run_kat active chaque module de test, recupere les retours et publie un statut global. Si toutes les suites passent, la base cryptographique est consideree conforme. Si une suite echoue, on stoppe l'interpretation des performances. Cette regle protege la qualite scientifique de l'analyse, car un chiffre de debit n'a de valeur que si l'algorithme est fonctionnellement correct.

**Flux du processus :**
Terminal -> run_kat.main -> suites KAT -> somme des echecs -> exit code -> decision: conforme (0) ou non conforme (1).
