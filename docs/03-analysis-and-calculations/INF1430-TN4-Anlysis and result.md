# Résultats et analyse

Cette section synthétise les principaux résultats expérimentaux obtenus pour les cinq algorithmes sur les deux plateformes, en mettant l'accent sur le débit de chiffrement, la stabilité statistique des mesures et l'effet d'avalanche. Ces trois axes correspondent directement aux objectifs de performance et de diffusion énoncés en introduction, et sont présentés dans cet ordre afin de construire l'analyse progressivement, en établissant d'abord la performance brute observée, puis en évaluant la fiabilité statistique de ces mesures, avant d'examiner une propriété cryptographique indépendante du débit. Chaque résultat est, dans la mesure du possible, mis en relation avec les sources normatives et la littérature déjà mobilisées dans ce rapport.

## Débit de chiffrement selon la plateforme

Le tableau suivant présente les débits maximaux observés en chiffrement, exprimés en mégaoctets par seconde, en retenant pour chaque algorithme la taille de message, parmi celles testées, ayant produit le débit le plus élevé. Les valeurs reprises ici proviennent de la même campagne finale consolidée que le reste de la section. Contrairement au Graphique 1, qui fixe une taille de message unique de 4096 octets afin de comparer les algorithmes dans des conditions strictement identiques, ce tableau vise à capturer la performance de pointe atteignable par chaque algorithme.

**Tableau 2 — Débit maximal de chiffrement par algorithme, x86 versus ARM**

| Algorithme | x86 (MB/s) | Pi ARM (MB/s) | Ratio x86/Pi |
| --- | ---: | ---: | ---: |
| AES | 279,46 | 54,68 | 5,11× |
| ChaCha20 | 112,71 | 87,02 | 1,30× |
| DES | 32,19 | 30,76 | 1,05× |
| Twofish | 2,38 | 1,45 | 1,64× |
| 3DES | 11,47 | 11,32 | 1,01× |

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

**Graphique 3 — Débit en fonction de la taille du message, ChaCha20 x86 versus ARM**

[Voir le graphique source](../../crypto-experiments/data/charts/01-throughput/throughput-vs-message-size-chacha20-x86-vs-arm.png)

Ce graphique révèle que l'écart de débit entre x86 et Raspberry Pi pour ChaCha20 varie selon la taille du message, sans tendance claire à la hausse ou à la baisse, ce qui confirme que la faible dépendance matérielle observée au Graphique 2 n'était pas propre à une seule taille de message. Le tableau suivant reprend les valeurs exactes utilisées pour tracer ce graphique, afin de lire précisément le débit mesuré sur chaque plateforme pour chacune des cinq tailles testées.

**Tableau 3 — Débit de ChaCha20 selon la taille du message**

| Taille du message (octets) | x86 (MB/s) | Pi ARM (MB/s) | Ratio x86/Pi |
| --- | ---: | ---: | ---: |
| 64 | 2,87 | 2,20 | 1,30× |
| 256 | 12,02 | 8,70 | 1,38× |
| 1024 | 39,59 | 27,53 | 1,44× |
| 4096 | 77,23 | 63,46 | 1,22× |
| 16384 | 112,71 | 87,02 | 1,30× |

Ce tableau confirme que le ratio oscille entre 1,22 et 1,44 fois selon la taille de message, sans direction constante. Il est aussi intéressant de noter qu'à 16384 octets, ChaCha20 sur Raspberry Pi atteint 87,02 MB/s, ce qui dépasse largement le débit obtenu par DES sur x86 à cette même taille de message, soit environ 32,19 MB/s, malgré l'absence de matériel dédié sur cette plateforme. Cet écart s'explique par la conception de ChaCha20, fondée sur des opérations d'addition, de rotation et de XOR (ARX) qui s'exécutent nativement et en temps constant sur pratiquement toutes les architectures, alors que DES reste pénalisé par sa structure historique en réseau de Feistel, avec des permutations bit à bit coûteuses en logiciel. Ce choix de construction ARX répond par ailleurs, selon la RFC 8439 (Nir et Langley, 2018), à une préoccupation de sécurité plus large, certaines implémentations de chiffrements reposant sur des tables de substitution, comme l'AES, demeurant vulnérables aux attaques par synchronisation de cache, un problème que la structure de ChaCha20 évite par construction. Cette sous-section se referme ainsi sur les deux extrêmes déjà entrevus au Tableau 2, la stabilité inter-plateforme de ChaCha20 d'une part, et Twofish d'autre part, qui demeure l'algorithme le plus pénalisé par l'absence d'accélération matérielle, avec un écart d'environ 117 fois par rapport au débit maximal atteint par AES sur x86.

## Stabilité statistique des mesures

La stabilité des mesures de débit a été évaluée à l'aide de l'IC95, appliqué à l'ensemble des campagnes expérimentales x86 et Raspberry Pi. Sur un total de 310 mesures agrégées, 284 respectent un seuil de largeur relative d'au plus 10 pour cent, soit environ 91,61 pour cent des configurations. Ce taux monte à 95,16 pour cent pour les messages de 1024 octets et plus, avec 177 mesures conformes sur 186, contre 86,29 pour cent pour les messages de 64 et 256 octets, avec 107 mesures conformes sur 124. Cette répartition confirme que le bruit relatif se concentre surtout sur les petites tailles de message, où les durées d'exécution deviennent très brèves même avec 100 répétitions par configuration.

**Graphique 4 — Stabilité du débit IC95, x86 versus ARM à 4096 octets**

[Voir le graphique source](../../crypto-experiments/data/charts/01-throughput/ci95-throughput-stability-x86-vs-arm-4kb.png)

Ce graphique permet de juger si les écarts de débit observés entre algorithmes se situent clairement au-dessus de la marge d'incertitude de la mesure. La largeur des intervalles de confiance y est exprimée en valeur absolue plutôt qu'en pourcentage, ce qui explique pourquoi AES affiche la largeur la plus élevée du graphique à 11,85 MB/s sur x86, devant ChaCha20 à 7,68 MB/s, DES à 1,73 MB/s, 3DES à 0,56 MB/s et Twofish à 0,10 MB/s. Rapportée au débit correspondant à 4096 octets, cette largeur représente toutefois 13,34 pour cent pour AES sur x86, ce qui dépasse le seuil relatif de 10 pour cent retenu pour le protocole, alors que ChaCha20 reste tout juste sous ce seuil à 9,95 pour cent. Du côté Raspberry Pi, les largeurs observées au même point sont plus faibles pour tous les algorithmes, avec 2,72 MB/s pour AES, 1,99 MB/s pour ChaCha20, 0,76 MB/s pour DES, 0,33 MB/s pour 3DES et 0,01 MB/s pour Twofish. La lecture conjointe du graphique et de l'audit IC95 montre donc que, malgré une conformité globale majoritaire, certaines mesures rapides sur x86 demeurent sensiblement plus sensibles au bruit que leurs équivalents sur ARM.

## Effet d’avalanche

L'effet d'avalanche mesure la proportion de bits du texte chiffré qui sont modifiés lorsqu'un seul bit du texte clair est changé. Cette propriété constitue un indicateur fondamental de la qualité de diffusion d'un algorithme cryptographique, un chiffrement robuste devant idéalement produire un changement d'environ la moitié des bits de sortie pour toute perturbation minimale de l'entrée. Le graphique suivant présente le score d'avalanche moyen obtenu pour chaque algorithme, calculé sur l'ensemble des configurations testées, tant sur la plateforme x86 que sur le Raspberry Pi.

**Graphique 5 — Score d’avalanche par algorithme, x86 versus ARM**

[Voir le graphique source](../../crypto-experiments/data/charts/02-avalanche-effect/avalanche-score-x86-vs-arm.png)

Les propriétés de diffusion mesurées correspondent directement au critère de diffusion stricte, le strict avalanche criterion, décrit par Stallings comme une propriété de conception recherchée pour les chiffrements par blocs, et rattaché par Katz et Lindell au paradigme confusion diffusion de Shannon. Les cinq algorithmes se situent ici très près du point idéal de 50 pour cent, avec des moyennes de 50,004 pour cent et 50,026 pour cent pour AES, 50,141 pour cent et 50,072 pour cent pour DES, 49,935 pour cent et 50,085 pour cent pour 3DES, 50,053 pour cent et 50,006 pour cent pour Twofish, puis 49,987 pour cent et 50,017 pour cent pour ChaCha20, respectivement sur x86 et sur Raspberry Pi. L'écart interplateforme maximal n'atteint que 0,149 point de pourcentage, observé pour 3DES, ce qui confirme empiriquement que la diffusion mesurée dépend du design cryptographique lui-même et non de l'architecture matérielle utilisée pour l'exécuter.

Après avoir observé le comportement global de l'effet d'avalanche, il est pertinent de distinguer les deux sources possibles de diffusion, soit une perturbation du texte clair et une perturbation de la clé, afin de vérifier si chaque algorithme réagit de façon équivalente aux deux types de changement. Le graphique suivant compare, pour chaque algorithme, le score d'avalanche obtenu par un basculement d'un bit du texte clair à celui obtenu par un basculement d'un bit de la clé, sur les données mesurées sur la plateforme x86.

**Graphique 6 — Avalanche du texte en clair versus avalanche de la clé**

[Voir le graphique source](../../crypto-experiments/data/charts/02-avalanche-effect/avalanche-plaintext-vs-key.png)

AES, Twofish et ChaCha20 présentent un comportement pratiquement identique entre les deux mécanismes, avec un écart inférieur à 0,1 point de pourcentage entre l'avalanche du texte clair et l'avalanche de la clé. Sur x86, AES passe ainsi de 50,004 pour cent à 50,011 pour cent, Twofish de 50,053 pour cent à 49,991 pour cent, et ChaCha20 de 49,987 pour cent à 49,989 pour cent. Une fois les bits de parité exclus du tirage du bit de clé pour DES et 3DES, ces deux algorithmes reviennent eux aussi au voisinage immédiat de 50 pour cent. Le score d'avalanche de la clé atteint alors 50,172 pour cent pour DES et 50,127 pour cent pour 3DES, contre 50,141 pour cent et 49,935 pour cent pour l'avalanche du texte clair. L'écart résiduel tombe ainsi à 0,031 point pour DES et 0,192 point pour 3DES. Le graphique confirme donc que, dans les cinq cas, la diffusion reste essentiellement équivalente qu'on perturbe le texte clair ou la clé. L'asymétrie observée dans la version précédente provenait d'un biais méthodologique, car environ 12,5 pour cent des bits d'une clé DES ou 3DES sont des bits de parité ignorés par le calcul cryptographique effectif.
