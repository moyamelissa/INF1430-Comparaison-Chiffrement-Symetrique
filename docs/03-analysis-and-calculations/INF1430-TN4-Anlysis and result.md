# INF1430 — TN4 Analysis and Result

## Résultats et analyse

Cette
section synthétise les principaux résultats expérimentaux obtenus pour les cinq
algorithmes sur les deux plateformes, en mettant l'accent sur le débit de
chiffrement, la stabilité statistique des mesures et l'effet d'avalanche. Ces
trois axes correspondent directement aux objectifs de performance et de
diffusion énoncés en introduction, et sont présentés dans cet ordre afin de
construire l'analyse progressivement, en établissant d'abord la performance
brute observée, puis en évaluant la fiabilité statistique de ces mesures, avant
d'examiner une propriété cryptographique indépendante du débit. Chaque résultat
est, dans la mesure du possible, mis en relation avec les sources normatives et
la littérature déjà mobilisées dans ce rapport.

### Débit de chiffrement selon la plateforme

Le tableau suivant présente les débits maximaux observés en chiffrement, exprimés en mégaoctets par seconde, en retenant pour chaque algorithme la taille de message, parmi celles testées, ayant produit le débit le plus élevé. Les valeurs reprises ici proviennent de la même campagne finale consolidée que le reste de la section. Contrairement au Graphique 1, qui fixe une taille de message unique de 4096 octets afin de comparer les algorithmes dans des conditions strictement identiques, ce tableau vise à capturer la performance de pointe atteignable par chaque algorithme.

**Tableau 2 — Débit maximal de chiffrement par algorithme, x86 versus ARM**

| Algorithme | x86 (MB/s) | Pi ARM (MB/s) | Ratio x86/Pi |
| ---------- | ---------: | ------------: | -----------: |
| AES        |     279,46 |         54,68 |       5,11× |
| ChaCha20   |     112,71 |         87,02 |       1,30× |
| DES        |      32,19 |         30,76 |       1,05× |
| Twofish    |       2,38 |          1,45 |       1,65× |
| 3DES       |      11,47 |         11,32 |       1,01× |

AES se démarque nettement avec le débit le plus élevé sur les deux plateformes, ce qui s'explique par le jeu d'instructions AES-NI présent sur le processeur x86 et absent sur le Raspberry Pi, d'où le ratio le plus élevé du tableau à 5,11 fois. Ce résultat rejoint la littérature, Stallings (2017) rapportant que le jeu d'instructions AES d'Intel procure des gains de vitesse de l'ordre d'une grandeur par rapport à une implémentation purement logicielle. ChaCha20 obtient le deuxième meilleur débit sur x86 avec un ratio de 1,30 fois, une stabilité qui correspond directement à la justification de conception donnée par la RFC 8439 (Nir et Langley, 2018), selon laquelle ChaCha20 répond au fait que l'AES perd une part importante de son avantage sur les plateformes sans matériel dédié. DES et 3DES affichent quant à eux les ratios les plus bas du tableau, respectivement 1,05 et 1,01 fois, cohérents avec des algorithmes plus anciens et sans optimisation matérielle dédiée. Twofish affiche le débit le plus faible sur les deux plateformes, restant environ 117 fois plus lent qu'AES sur x86, ce qui reflète l'absence totale d'accélération matérielle pour cet algorithme peu importe la plateforme utilisée.

Le graphique suivant présente le débit de chiffrement observé pour les cinq algorithmes testés à une taille de message fixe de 4096 octets, avec une paire de barres par algorithme opposant la plateforme x86 sous Windows au Raspberry Pi sous architecture ARM, exprimé en mégaoctets par seconde. Comme pour le Tableau 2, la configuration de référence correspond au mode ECB pour les quatre chiffrements par blocs et au mode natif Stream pour ChaCha20.

**Graphique 1 — Débit par algorithme, x86 versus ARM à 4096 octets**

[Voir le graphique source](../../crypto-experiments/data/charts/01-throughput/throughput-by-algo-x86-vs-arm-4kb.png)

En fixant la taille du message, ce graphique isole l'effet de la plateforme des variations liées au volume traité. Il montre qu'AES domine largement sur x86 grâce à l'accélération matérielle AES-NI, avec un écart d'environ 2,36 fois par rapport au Raspberry Pi, un écart réduit par rapport au 5,11 fois observé au débit maximal, ce qui confirme que l'avantage d'AES-NI (Stallings, 2017) s'exprime pleinement seulement quand le volume traité par appel est assez élevé pour amortir les coûts fixes, exactement la logique qui justifiait le choix de tester plusieurs tailles de messages dans le protocole. DES et 3DES affichent les écarts les plus faibles du graphique, avec des ratios de 1,13 et 1,12 fois respectivement, cohérents avec leur position déjà observée au débit maximal. ChaCha20 présente un écart modéré d'environ 1,22 fois, conforme à sa conception peu dépendante du matériel. Twofish affiche un écart intermédiaire d'environ 1,53 fois malgré son débit très faible sur les deux plateformes, ce qui montre que l'absence d'accélération matérielle touche autant sa vitesse absolue que la stabilité de son comportement d'une architecture à l'autre. Ce constat renforce l'idée que le choix d'un algorithme doit tenir compte du contexte matériel cible plutôt que d'une performance mesurée sur une seule plateforme de référence.

Ces deux premières lectures, débit de pointe au Tableau 2 et débit à taille fixe au Graphique 1, remplissent des rôles méthodologiques distincts qui se complètent plutôt qu'ils ne se répètent. Le débit maximal renseigne sur la capacité de traitement la plus élevée qu'un algorithme peut atteindre dans les conditions les plus favorables du protocole, une information utile pour dimensionner un système autour de sa charge de pointe. Le débit à 4096 octets, à l'inverse, reflète une taille de message représentative d'un usage courant, plus proche de ce qu'on rencontre concrètement dans des échanges réseau typiques ou des blocs de stockage usuels, plutôt qu'un scénario optimisé pour maximiser le débit. Cette distinction explique en partie pourquoi le ratio d'AES se contracte notablement entre les deux mesures, le gain apporté par les instructions AES-NI dépend d'un coût fixe amorti sur chaque appel, notamment la préparation du calendrier de clés, un coût qui pèse proportionnellement moins lorsque le message traité est volumineux. Cette nuance justifie de ne pas se fier à une seule de ces deux lectures pour orienter un choix d'algorithme, la performance de pointe et la performance représentative pouvant classer les mêmes algorithmes différemment selon le contexte d'utilisation réel visé.

Le deuxième tableau et le premier graphique ont révélé des écarts de débit variables entre x86 et Raspberry Pi selon l'algorithme utilisé. Pour quantifier directement cet écart, le graphique suivant présente le rapport entre le débit obtenu sur x86 et celui obtenu sur Raspberry Pi pour chaque algorithme, avec la même configuration que le Graphique 1, mode ECB ou Stream, message de 4096 octets, et clés fixées à AES 256 bits, DES 56 bits, 3DES 192 bits, Twofish 256 bits et ChaCha20 256 bits. Un ratio proche de 1 indique une performance comparable entre les deux plateformes, alors qu'un ratio élevé révèle une dépendance plus forte au matériel x86.

**Graphique 2 — Ratio d'accélération x86 sur ARM par algorithme**

[Voir le graphique source](../../crypto-experiments/data/charts/01-throughput/speedup-ratio-x86-over-arm-by-algo.png)

Ce graphique confirme qu'AES reste l'algorithme le plus dépendant du matériel x86, avec un ratio de 2,36 fois, cohérent avec les deux graphiques précédents. Le classement se complète avec Twofish, à 1,53 fois, puis ChaCha20 à 1,22 fois, DES à 1,13 fois et 3DES à 1,12 fois. Le graphique reproduit ainsi la même hiérarchie que celle observée au Tableau 2, mais avec des écarts globalement moins marqués à cette taille de message intermédiaire, en particulier pour AES, dont le ratio passe de 5,11 fois au débit maximal à 2,36 fois à 4096 octets. Le ratio de Twofish se situe nettement au-dessus de celui de DES, 3DES et ChaCha20, qui ne bénéficient pourtant pas non plus d'accélération matérielle, un écart qui reflète probablement l'hétérogénéité logicielle documentée en méthodologie plutôt qu'un effet matériel additionnel.

Le deuxième graphique a montré que les ratios plateforme se regroupent majoritairement près de 1, à l'exception notable d'AES et, dans une moindre mesure, de Twofish. ChaCha20, seul chiffrement de flux de l'échantillon, affiche l'un des ratios les plus bas de ce classement. Pour vérifier si cette faible dépendance matérielle se maintient à travers différents volumes de données, plutôt que d'être un effet propre à la taille de 4096 octets, le graphique suivant présente son débit de chiffrement sur les deux plateformes pour cinq tailles de messages croissantes, de 64 à 16 384 octets.

**Graphique 3 — Débit de ChaCha20 en fonction de la taille du message**

[Voir le graphique source](../../crypto-experiments/data/charts/01-throughput/throughput-vs-message-size-chacha20-x86-vs-arm.png)

Le tableau suivant reprend les valeurs exactes utilisées pour tracer ce graphique. Il permet de lire directement le débit mesuré sur chaque plateforme pour les cinq tailles de message testées.

**Tableau 3 — Débit de ChaCha20 selon la taille du message**

| Taille du message (octets) | x86 (MB/s) | Pi ARM (MB/s) | Ratio x86/Pi |
| -------------------------- | ---------: | ------------: | -----------: |
| 64                         |   2,868888 |      2,200209 |   1,303916× |
| 256                        |  12,018057 |      8,701194 |   1,381196× |
| 1024                       |  39,588272 |     27,531695 |   1,437916× |
| 4096                       |  77,230578 |     63,463658 |   1,216926× |
| 16384                      | 112,706147 |     87,017987 |   1,295205× |

Ce graphique révèle que l'écart de débit entre x86 et Raspberry Pi pour ChaCha20 varie entre 1,22 et 1,44 fois selon la taille du message, sans tendance claire à la hausse ou à la baisse. Il est aussi intéressant de noter qu'à 16384 octets, ChaCha20 sur Raspberry Pi atteint 87,02 MB/s, ce qui dépasse largement le débit obtenu par DES sur x86 à cette même taille de message, soit environ 32,19 MB/s. Cet écart s'explique par la conception de ChaCha20, fondée sur des opérations d'addition, de rotation et de XOR (ARX) qui s'exécutent nativement et en temps constant sur pratiquement toutes les architectures, un choix de conception motivé notamment par le fait que plusieurs implémentations d'AES demeurent vulnérables aux attaques par synchronisation de cache (cache-timing), un problème que la RFC 8439 (Nir et Langley, 2018) identifie explicitement comme l'une des motivations de ChaCha20, alors que DES reste pénalisé par sa structure historique en réseau de Feistel avec des permutations bit à bit coûteuses. Cette sous-section se referme ainsi sur les deux extrêmes déjà entrevus au Tableau 2, la stabilité inter-plateforme de ChaCha20 d'une part, et Twofish d'autre part, qui demeure l'algorithme le plus pénalisé par l'absence d'accélération matérielle, avec un écart d'environ 117 fois par rapport au débit maximal atteint par AES sur x86.
