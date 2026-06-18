# Scripts videos TN3

## Objectif du document
Centraliser les scripts de narration pour chaque video de la presentation TN3.

## Preflight technique
Avant de lancer les commandes Python en video, ouvrir un terminal dans le dossier crypto-experiments pour que les commandes python scripts/... fonctionnent directement.

## Video 1 - Nature du systeme

### Sequence par etape

#### Etape 1
**Action ecran :**
Ouvrir le depot GitHub du projet.

**Texte a dire :**
Dans cette premiere video, je vous presente le depot GitHub du projet INF1430. On va faire un survol bref du README, section par section, puis passer a la structure du code.

#### Etape 2
**Action ecran :**
Montrer la racine, ouvrir le README et defiler rapidement les sections principales (Presentation, Algorithmes et modes, Architecture, Structure du depot, Installation, Utilisation, Resultats, References).

**Texte a dire :**
Ici, on voit d abord une description breve du projet. Ensuite, on presente les algorithmes utilises ainsi que les modes d operation. Par apres, on voit l architecture, qui aide a bien naviguer dans le depot GitHub, avec chaque dossier et un commentaire qui decrit ce qu il contient. Finalement, on retrouve les sections installation, utilisation, resultats et references, avec les liens vers les fichiers de resultats laptop versus Raspberry Pi et les graphiques generes a partir de ces donnees.

#### Etape 3
**Action ecran :**
Ouvrir le dossier crypto-experiments. (Note tournage: Montrer l arborescence complete une fois expandue.)

**Texte a dire :**
On entre dans crypto-experiments, qui contient le coeur du systeme experimental.

#### Etape 4
**Action ecran :**
Ouvrir domain/cipher et montrer les fichiers. (Note tournage: Montrer les fichiers .py listes, puis ouvrir rapidement CipherPrimitive.py et pointer class CipherPrimitive(ABC), def encrypt_block(...) et def decrypt_block(...). Ensuite ouvrir AES.py et pointer class AES(CipherPrimitive) pour prouver l heritage concret.)

**Texte a dire :**
Dans domain/cipher, on retrouve les primitives de chiffrement implementees: AES, DES, 3DES, Twofish et ChaCha20. Chacune herite de CipherPrimitive, qui definit l interface abstraite commune et garantit l uniformite des operations de chiffrement et de dechiffrement a travers tout le systeme.

#### Etape 5
**Action ecran :**
Ouvrir domain/mode et montrer les fichiers. (Note tournage: Montrer les fichiers .py listés, pointer StreamMode pour clarifier son role special.)

**Texte a dire :**
Dans domain/mode, on retrouve les modes d operation: ECB, CBC, CTR et GCM pour les algorithmes par blocs, puis StreamMode, qui est un passe-travers concu specifiquement pour les chiffrements par flux comme ChaCha20. Cette separation entre les primitives et les modes permet de composer librement les combinaisons sans modifier le code des algorithmes.

#### Etape 6
**Action ecran :**
Ouvrir le dossier application et montrer ExperimentController.py. (Note tournage: Ouvrir ExperimentController.py en mode lecture pour montrer sa place centrale.)

**Texte a dire :**
Dans le dossier application, la classe ExperimentController orchestre les essais: elle enchaine les combinaisons algorithme-mode, declenche les mesures et centralise les resultats, sans jamais toucher a la logique cryptographique elle-meme.

#### Etape 7
**Action ecran :**
Ouvrir le dossier scripts et montrer les fichiers. (Note tournage: Montrer tous les .py listés, puis pointer les trois scripts d analyse: analyse_rounds_avalanche.py, ecb_visual_vulnerability.py et compare_platforms.py.)

**Texte a dire :**
Dans scripts, on trouve les points d entree du systeme: experiment.py pour les benchmarks de performance, run_kat.py pour la validation cryptographique par vecteurs NIST, generate_charts.py pour produire les figures, et trois scripts d analyse specifiques, analyse_rounds_avalanche.py, ecb_visual_vulnerability.py et compare_platforms.py.

#### Etape 8
**Action ecran :**
Basculer vers Visual Studio Code et ouvrir le terminal integre. (Note tournage: Terminal deja ouvert dans crypto-experiments/.)

**Texte a dire :**
On passe maintenant dans Visual Studio Code pour executer une experience en direct.

#### Etape 9
**Action ecran :**
Taper puis executer la commande python scripts/experiment.py depuis le dossier crypto-experiments. (Note tournage: Utiliser le vrai chiffre: cent repetitions par configuration (depuis REPETITIONS = 100 dans experiment.py).)

**Texte a dire :**
Je lance la commande python scripts/experiment.py. Je suis positionne dans le dossier crypto-experiments, donc la commande fonctionne directement.

#### Etape 10
**Action ecran :**
Laisser defiler le terminal et montrer la fin de l execution. (Note tournage: Laisser tourner assez longtemps pour que plusieurs iterations s affichent visiblement.)

**Texte a dire :**
Le systeme parcourt l ensemble de la matrice experimentale, algorithmes, modes, tailles de cle et tailles de donnees, et repete chaque mesure selon le protocole. On voit les lignes defiler au fur et a mesure des cent repetitions par configuration.

#### Etape 11
**Action ecran :**
Ouvrir le CSV genere dans data/results (ex: experiment_20260618_143020.csv). (Note tournage: Montrer le fichier reel dans data/results/ avec le nom horodatage visible. Ne pas ouvrir le CSV completement, juste le montrer dans l explorateur de fichiers.)

**Texte a dire :**
A la fin de l execution, un fichier CSV horodatage est genere dans data/results. Il contient une ligne par configuration mesuree, avec toutes les metriques collectees: temps de chiffrement et de dechiffrement, debit, effet d avalanche et identifiants de configuration. C est ce fichier brut qui servira de base a l analyse comparative de TN3.

#### Etape 12
**Action ecran :**
Rester sur le CSV ou revenir a la structure du projet. (Note tournage: Transition douce vers video 2 qui expliquera le pourquoi du protocole.)

**Texte a dire :**
Dans la prochaine video, on detaille justement le protocole de mesure et la justification des cent repetitions par configuration.

## Video 2 - Protocole experimental

### Sequence par etape

#### Etape 1
**Action ecran :**
Afficher la slide du protocole experimental (plateformes, algorithmes, repetitions).

**Texte a dire :**
Le protocole experimental, c est le coeur de la demarche scientifique du projet. Avant de regarder le code, voici ce qu on cherche a faire concretement.

#### Etape 2
**Action ecran :**
Rester sur la slide et pointer les deux plateformes.

**Texte a dire :**
On compare cinq algorithmes, AES, DES, 3DES, Twofish et ChaCha20, sur deux plateformes materielles distinctes: un portable Windows avec Intel Core i5 et AES-NI, et un Raspberry Pi en ARM Cortex-A72 sans AES-NI. C est cette difference materielle qu on veut mesurer, a code identique.

#### Etape 3
**Action ecran :**
Ouvrir application/ExperimentController.py dans VS Code.

**Texte a dire :**
Ici, dans ExperimentController, on voit comment la mesure est organisee.

#### Etape 4
**Action ecran :**
Montrer la boucle des configurations et les repetitions.

**Texte a dire :**
Pour chaque configuration, algorithme, mode et taille de donnees, on repete l operation cent fois. Pourquoi cent? Parce qu autour de ce seuil, l intervalle de confiance a 95 pour cent se stabilise.

#### Etape 5
**Action ecran :**
Montrer la partie chronometrage.

**Texte a dire :**
Le chronometrage encadre uniquement le chiffrement et le dechiffrement, pas l initialisation ni l ecriture des resultats. On isole exactement ce qu on veut mesurer.

#### Etape 6
**Action ecran :**
Ouvrir scripts/experiment.py.

**Texte a dire :**
Dans le script de lancement, on voit les parametres configures: les algorithmes, les tailles de donnees et les modes d operation associes.

#### Etape 7
**Action ecran :**
Pointer rapidement les listes de configuration dans le fichier.

**Texte a dire :**
Tout est declaratif. Ajouter un algorithme ou une taille de donnees se fait simplement, sans changer l architecture du systeme.

#### Etape 8
**Action ecran :**
Ouvrir le terminal integre et executer la commande python scripts/experiment.py.

**Texte a dire :**
Je lance maintenant l experience avec la commande python scripts/experiment.py.

#### Etape 9
**Action ecran :**
Laisser tourner quelques secondes et montrer la progression du terminal.

**Texte a dire :**
On voit le systeme iterer automatiquement sur chaque configuration. Aucune intervention manuelle, ce qui renforce la reproductibilite. Le meme script est execute tel quel sur le Raspberry Pi.

#### Etape 10
**Action ecran :**
Ouvrir un CSV genere dans data/results.

**Texte a dire :**
Voici le resultat: un fichier CSV structure avec une ligne par mesure.

#### Etape 11
**Action ecran :**
Montrer les colonnes principales du CSV.

**Texte a dire :**
On y retrouve l algorithme, le mode, la taille du message, le debit, le temps et la plateforme. C est a partir de ces donnees brutes qu on construit toute l analyse comparative.

#### Etape 12
**Action ecran :**
Rester sur le CSV pour la transition vers la prochaine video.

**Texte a dire :**
Dans la prochaine video, on valide maintenant la justesse cryptographique des implementations avec les tests KAT.

## Video 3 - Validation KAT

### Sequence par etape

#### Etape 1
**Action ecran :**
Ouvrir le dossier validation dans VS Code et montrer les fichiers kat_aes.py, kat_des.py, kat_3des.py, kat_modes.py, kat_gcm.py et kat_chacha20.py.

**Texte a dire :**
Avant de faire confiance a une seule mesure de performance, il faut d abord s assurer que le systeme chiffre correctement. C est l objet de cette etape: la validation fonctionnelle par Known Answer Tests, ou KAT.

#### Etape 2
**Action ecran :**
Rester sur l arborescence validation et survoler rapidement les fichiers.

**Texte a dire :**
Le principe est simple. On prend un plaintext connu, une cle connue, et on compare la sortie de notre implementation avec une valeur de reference publiee par les standards.

#### Etape 3
**Action ecran :**
Ouvrir validation/kat_aes.py.

**Texte a dire :**
Ici, kat_aes valide les primitives AES contre FIPS 197.

#### Etape 4
**Action ecran :**
Pointer un vecteur de test dans kat_aes.py: plaintext, key, ciphertext attendu.

**Texte a dire :**
Voila a quoi ressemble un vecteur KAT: plaintext en hexadecimal, cle, puis ciphertext attendu. Notre implementation chiffre, puis on compare octet par octet avec la valeur de reference.

#### Etape 5
**Action ecran :**
Revenir au dossier validation et montrer rapidement les autres fichiers KAT.

**Texte a dire :**
On applique la meme logique sur le reste: DES et 3DES, les modes ECB CBC CTR, le mode GCM authentifie, et ChaCha20.

#### Etape 6
**Action ecran :**
Ouvrir scripts/run_kat.py.

**Texte a dire :**
Le script run_kat.py orchestre toutes ces suites en sequence et associe les tests aux standards de reference, notamment FIPS 197, SP 800-38A, SP 800-38D et RFC 8439.

#### Etape 7
**Action ecran :**
Montrer la section ou les suites KAT sont lancees.

**Texte a dire :**
Si un test echoue, on le voit immediatement et la validation n est pas acceptee. Tant que cette etape n est pas verte, les resultats de performance ne sont pas exploitables.

#### Etape 8
**Action ecran :**
Ouvrir le terminal integre et executer python scripts/run_kat.py.

**Texte a dire :**
Je lance maintenant la validation complete avec python scripts/run_kat.py.

#### Etape 9
**Action ecran :**
Laisser defiler la sortie terminal avec les validations.

**Texte a dire :**
On voit passer les suites une a une: AES, DES, 3DES, les modes, GCM et ChaCha20.

#### Etape 10
**Action ecran :**
Rester sur la fin du terminal avec le statut global de succes.

**Texte a dire :**
Tous les tests passent. On a donc la certitude que les implementations sont conformes aux standards, et que les mesures de performance reposent sur une base correcte.

#### Etape 11
**Action ecran :**
Garder le terminal a l ecran pour transition.

**Texte a dire :**
Dans la prochaine video, on passe aux resultats de performance et a l impact d AES-NI sur les chiffres observes.

## Video 4 - Resultats de performance

### Sequence par etape

#### Etape 1
**Action ecran :**
Ouvrir scripts/generate_charts.py dans VS Code.

**Texte a dire :**
On a les donnees, les KAT sont passes. Maintenant on genere les graphiques.

#### Etape 2
**Action ecran :**
Montrer rapidement que le script lit les CSV et construit les figures.

**Texte a dire :**
Ce script lit les fichiers CSV des experiences et genere automatiquement les figures comparatives.

#### Etape 3
**Action ecran :**
Ouvrir le terminal et executer python scripts/generate_charts.py.

**Texte a dire :**
Je lance la generation avec python scripts/generate_charts.py.

#### Etape 4
**Action ecran :**
Ouvrir le dossier data/charts.

**Texte a dire :**
Les graphiques sont maintenant dans data/charts. On regarde les deux plus parlants.

#### Etape 5
**Action ecran :**
Afficher le graphique debit par algorithme et mode.

**Texte a dire :**
Ici, AES domine clairement. En ECB, on voit des debits tres eleves. En GCM, le debit baisse car on ajoute l authentification, mais on gagne la confidentialite et l integrite.

#### Etape 6
**Action ecran :**
Rester sur le graphique et pointer DES, 3DES et Twofish.

**Texte a dire :**
DES reste limite, 3DES est encore plus lent a cause des trois passes, et Twofish est nettement en dessous d AES sur cette plateforme.

#### Etape 7
**Action ecran :**
Afficher le graphique debit selon la taille du message.

**Texte a dire :**
Ce graphique montre que pour les petits messages, les couts fixes dominent. Quand la taille augmente, AES accelere fortement.

#### Etape 8
**Action ecran :**
Pointer la zone des plus grosses tailles.

**Texte a dire :**
A grande taille, l acceleration materielle AES-NI sur x86 devient visible. C est un facteur cle des ecarts observes.

#### Etape 9
**Action ecran :**
Laisser le graphique a l ecran pour transition.

**Texte a dire :**
Dans la prochaine video, on passe a la robustesse cryptographique avec l effet d avalanche.

## Video 5 - Robustesse cryptographique

### Sequence par etape

#### Etape 1
**Action ecran :**
Ouvrir scripts/analyse_rounds_avalanche.py.

**Texte a dire :**
La performance seule ne suffit pas. Ici, on mesure la robustesse cryptographique avec l avalanche, la sensibilite aux cles et la stabilite.

#### Etape 2
**Action ecran :**
Montrer la partie qui inverse un bit et calcule la distance de Hamming.

**Texte a dire :**
Le principe est simple: on chiffre, on inverse un bit, on rechiffre, puis on compare les sorties. L ideal est proche de 0,500.

#### Etape 3
**Action ecran :**
Executer python scripts/analyse_rounds_avalanche.py.

**Texte a dire :**
Je lance l analyse d avalanche.

#### Etape 4
**Action ecran :**
Ouvrir le graphique des scores d avalanche par algorithme.

**Texte a dire :**
AES, 3DES et Twofish sont tres proches de l ideal. DES est un peu en dessous.

#### Etape 5
**Action ecran :**
Pointer la valeur de ChaCha20.

**Texte a dire :**
ChaCha20 ressort differemment car c est un chiffrement de flux. Ici, c est une limite de la methode d evaluation, pas une faille.

#### Etape 6
**Action ecran :**
Ouvrir le graphique rounds versus avalanche.

**Texte a dire :**
Ce graphique montre la convergence vers l avalanche optimale en fonction des rondes internes.

#### Etape 7
**Action ecran :**
Ouvrir le graphique de sensibilite aux cles.

**Texte a dire :**
Quand on inverse un bit de cle, AES et Twofish restent proches de 0,500. DES et 3DES montrent une faiblesse structurelle plus visible.

#### Etape 8
**Action ecran :**
Ouvrir le graphique de stabilite IC95.

**Texte a dire :**
Enfin, la stabilite des mesures varie selon la plateforme. La variance peut etre plus forte sur x86 a cause du bruit systeme.

#### Etape 9
**Action ecran :**
Garder le dernier graphique pour transition.

**Texte a dire :**
Dans la prochaine video, on fait la synthese generale et les recommandations concretes.

## Video 6 - Synthese et recommandations

### Sequence par etape

#### Etape 1
**Action ecran :**
Ouvrir scripts/ecb_visual_vulnerability.py.

**Texte a dire :**
Avant les recommandations, on termine par une demonstration visuelle qui montre pourquoi le mode d operation compte autant que la vitesse.

#### Etape 2
**Action ecran :**
Executer python scripts/ecb_visual_vulnerability.py.

**Texte a dire :**
Je lance la demonstration ECB contre CBC.

#### Etape 3
**Action ecran :**
Afficher l image resultat cote a cote.

**Texte a dire :**
En ECB, les formes restent visibles. En CBC, les patterns disparaissent. ECB peut etre rapide, mais il fuit la structure des donnees.

#### Etape 4
**Action ecran :**
Basculer sur la slide de synthese avec le tableau de recommandations.

**Texte a dire :**
Pour serveur et cloud, AES-256-GCM est le choix standard. Pour ARM et mobile, ChaCha20-Poly1305 est souvent plus adapte sans acceleration materielle.

#### Etape 5
**Action ecran :**
Pointer la colonne des choix a eviter.

**Texte a dire :**
DES, 3DES et ECB sont a proscrire pour les nouveaux developpements.

#### Etape 6
**Action ecran :**
Basculer sur la slide de conclusion TN3 vers TN4.

**Texte a dire :**
Le projet livre des implementations validees, des mesures reproductibles et une analyse complete. Le TN4 approfondira les hypotheses et la comparaison a la litterature.

## Video 7 - ChaCha20: l algorithme qui refuse l inegalite

### Sequence par etape

#### Etape 1
**Action ecran :**
Ouvrir data/charts/comparison/cmp5_chacha20.png.

**Texte a dire :**
ChaCha20 merite une video a part, car son comportement est plus equitable entre plateformes.

#### Etape 2
**Action ecran :**
Ouvrir data/charts/comparison/cmp2_speedup_ratio.png.

**Texte a dire :**
Le ratio x86 sur Pi est plus faible pour ChaCha20 que pour AES. L ecart de performance entre plateformes est moins brutal.

#### Etape 3
**Action ecran :**
Garder les deux graphiques visibles en alternance.

**Texte a dire :**
La raison est structurelle: ChaCha20 repose sur des operations ARX, sans instruction dediee type AES-NI.

#### Etape 4
**Action ecran :**
Revenir sur le graphique ChaCha20.

**Texte a dire :**
Sur ARM sans acceleration AES, ChaCha20 peut depasser AES-GCM de facon nette dans les tests pratiques.

#### Etape 5
**Action ecran :**
Rester sur le graphique pour transition.

**Texte a dire :**
C est pour cela qu il est tres present en contexte mobile et embarque.

## Video 8 - DES, 3DES, Twofish: pourquoi ils ont perdu

### Sequence par etape

#### Etape 1
**Action ecran :**
Afficher la slide dediee DES 3DES Twofish.

**Texte a dire :**
Cette section explique pourquoi ces algorithmes ne sont plus des choix prioritaires aujourd hui.

#### Etape 2
**Action ecran :**
Ouvrir data/charts/comparison/cmp1_throughput_all.png.

**Texte a dire :**
Visuellement, leur debit est loin derriere AES dans notre benchmark.

#### Etape 3
**Action ecran :**
Pointer DES.

**Texte a dire :**
DES est historiquement important, mais sa cle de 56 bits est insuffisante depuis longtemps.

#### Etape 4
**Action ecran :**
Pointer 3DES.

**Texte a dire :**
3DES corrige partiellement la securite de DES, mais au prix d un cout de performance tres eleve et d une deprecation officielle.

#### Etape 5
**Action ecran :**
Pointer Twofish.

**Texte a dire :**
Twofish reste solide en theorie, mais son cout pratique et son adoption reduite le rendent moins pertinent que AES dans ce contexte.

#### Etape 6
**Action ecran :**
Laisser slide plus graphique pour transition.

**Texte a dire :**
Le message est clair: robustesse et adoption industrielle doivent aller ensemble.

## Video 9 - ECB: le mode le plus rapide est le plus dangereux

### Sequence par etape

#### Etape 1
**Action ecran :**
Ouvrir scripts/ecb_visual_vulnerability.py.

**Texte a dire :**
Ici, on montre pourquoi un mode tres rapide peut etre le pire choix de securite.

#### Etape 2
**Action ecran :**
Montrer rapidement la generation d image et les appels ECB/CBC.

**Texte a dire :**
On chiffre la meme image avec AES-ECB puis AES-CBC, en gardant le meme algorithme et la meme cle.

#### Etape 3
**Action ecran :**
Executer python scripts/ecb_visual_vulnerability.py.

**Texte a dire :**
Je lance la demonstration.

#### Etape 4
**Action ecran :**
Ouvrir fig8_ecb_vulnerability.png et garder les 3 images a l ecran.

**Texte a dire :**
Le resultat est immediat: en ECB, les patterns restent visibles. En CBC, ils disparaissent.

#### Etape 5
**Action ecran :**
Pointer la partie ECB.

**Texte a dire :**
ECB chiffre chaque bloc independamment. Des blocs identiques en entree donnent des blocs identiques en sortie.

#### Etape 6
**Action ecran :**
Pointer la partie CBC.

**Texte a dire :**
CBC introduit un chainage qui casse cette structure repetitive.

#### Etape 7
**Action ecran :**
Rester sur l image pour conclusion.

**Texte a dire :**
Conclusion: meme si ECB est rapide, il est cryptographiquement inadapte pour des donnees reelles.

## Video 10 - Effet d avalanche: la sante cryptographique

### Sequence par etape

#### Etape 1
**Action ecran :**
Ouvrir data/charts/fig4_avalanche.png.

**Texte a dire :**
L effet d avalanche mesure a quel point un petit changement en entree diffuse dans la sortie.

#### Etape 2
**Action ecran :**
Pointer les scores principaux.

**Texte a dire :**
La cible est autour de 0,500. AES, 3DES et Twofish sont tres proches. DES est un peu en dessous.

#### Etape 3
**Action ecran :**
Pointer ChaCha20.

**Texte a dire :**
Pour ChaCha20, la valeur doit etre interpretee avec prudence car c est un chiffrement de flux.

#### Etape 4
**Action ecran :**
Ouvrir data/charts/fig7_rounds_avalanche.png.

**Texte a dire :**
Ce graphique montre en combien de rondes internes chaque algorithme converge vers une diffusion stable.

#### Etape 5
**Action ecran :**
Ouvrir data/charts/fig4b_key_avalanche.png.

**Texte a dire :**
On compare ensuite avalanche sur le plaintext et avalanche sur la cle pour valider la diffusion dans les deux dimensions.

#### Etape 6
**Action ecran :**
Garder le graphique cle pour transition.

**Texte a dire :**
Dans la prochaine video, on relie cette sensibilite a la stabilite statistique IC95.

## Video 11 - Sensibilite aux cles et stabilite IC95

### Sequence par etape

#### Etape 1
**Action ecran :**
Afficher la slide des scores de sensibilite aux cles.

**Texte a dire :**
On commence par la sensibilite aux cles: on modifie un bit de cle et on observe la diffusion dans le ciphertext.

#### Etape 2
**Action ecran :**
Ouvrir data/charts/fig4b_key_avalanche.png.

**Texte a dire :**
AES et Twofish restent proches de 0,500, alors que DES et 3DES montrent une faiblesse plus marquee.

#### Etape 3
**Action ecran :**
Basculer sur la slide des chiffres IC95.

**Texte a dire :**
On passe maintenant a la stabilite des mesures, via l intervalle de confiance a 95 pour cent.

#### Etape 4
**Action ecran :**
Ouvrir le graphique de stabilite IC95 dans data/charts/comparison.

**Texte a dire :**
On observe que la machine la plus puissante n est pas toujours la plus stable. Le bruit systeme peut augmenter la variance sur x86.

#### Etape 5
**Action ecran :**
Pointer les barres x86 et Pi pour AES.

**Texte a dire :**
Turbo Boost, planification OS et processus en arriere-plan expliquent une partie de cette variabilite.

#### Etape 6
**Action ecran :**
Rester sur le graphique pour transition.

**Texte a dire :**
On retient que la fiabilite statistique est aussi importante que la vitesse brute.

## Video 12 - Synthese: quel algorithme choisir en 2026?

### Sequence par etape

#### Etape 1
**Action ecran :**
Afficher la slide du tableau de recommandations contextuelles.

**Texte a dire :**
On conclut le benchmark avec une question pratique: quel choix faire en 2026 selon le contexte?

#### Etape 2
**Action ecran :**
Pointer la ligne serveur/cloud.

**Texte a dire :**
Pour serveur et cloud, AES-256-GCM est le choix standard: securite forte, integrite integree et bonne performance avec acceleration materielle.

#### Etape 3
**Action ecran :**
Pointer la ligne IoT/ARM/mobile.

**Texte a dire :**
Pour IoT et ARM sans AES-NI, ChaCha20-Poly1305 est souvent plus equilibre et plus performant.

#### Etape 4
**Action ecran :**
Pointer la ligne chiffrement de masse.

**Texte a dire :**
Pour des flux volumineux avec integrite geree separement, AES-CTR reste un choix efficace grace a sa parallelisation.

#### Etape 5
**Action ecran :**
Pointer la zone a eviter/interdit.

**Texte a dire :**
ECB, DES et 3DES sont a exclure pour les nouveaux systemes.

#### Etape 6
**Action ecran :**
Basculer sur la slide conclusion TN3/TN4.

**Texte a dire :**
Le TN3 fournit la base experimentale complete. Le TN4 consolidera l analyse formelle et les recommandations finales documentees.

#### Etape 7
**Action ecran :**
Rester sur la slide finale.

**Texte a dire :**
Le choix d un algorithme n est pas seulement une decision de securite. C est une decision d architecture, de plateforme et de contexte d utilisation.

