# Résultats et analyse

Cette section présente une synthèse des principaux résultats expérimentaux obtenus pour les cinq algorithmes sur les deux plateformes. L'analyse met l'accent sur trois axes, le débit de chiffrement, la stabilité statistique des mesures et l'effet d'avalanche. Ces axes correspondent directement aux objectifs de performance et de diffusion définis en introduction. Ils sont traités dans cet ordre afin de construire l'argumentation de façon progressive, d'abord la performance brute observée, ensuite la fiabilité statistique des mesures, puis une propriété cryptographique indépendante du débit. Chaque résultat est mis en relation, lorsque pertinent, avec les sources normatives et la littérature mobilisées dans le rapport.

## Débit de chiffrement selon la plateforme

Le tableau suivant présente les débits maximaux observés en chiffrement, exprimés en mégaoctets par seconde, en retenant pour chaque algorithme la taille de message, parmi celles testées, ayant produit le débit le plus élevé. Les valeurs reprises ici proviennent de la même campagne finale consolidée que le reste de la section. Contrairement au premier graphique, qui fixe une taille de message unique de 4096 octets afin de comparer les algorithmes dans des conditions strictement identiques, ce tableau vise à capturer la performance de pointe atteignable par chaque algorithme.

**Deuxième tableau — Débit maximal de chiffrement par algorithme, x86 versus ARM**

| Algorithme | x86 (MB/s) | Pi ARM (MB/s) | Ratio x86/Pi |
| ---------- | ---------: | ------------: | -----------: |
| AES        |     398,55 |         69,05 |       5,77× |
| ChaCha20   |     144,55 |         89,35 |       1,62× |
| DES        |      38,78 |         31,85 |       1,22× |
| Twofish    |       3,14 |          1,44 |       2,18× |
| 3DES       |      13,80 |         11,39 |       1,21× |

Le deuxième tableau met en évidence une hiérarchie nette des débits maximaux. AES atteint le niveau le plus élevé sur les deux plateformes et son ratio x86/Pi monte à 5,77. ChaCha20 suit à 1,62. DES et 3DES restent proches de 1,22 et 1,21. Twofish demeure le plus lent. Cette distribution s'explique principalement par la présence d'AES-NI sur x86, absente sur Raspberry Pi, tandis que les autres algorithmes reposent davantage sur des chemins logiciels sans accélération dédiée. Cette lecture rejoint la littérature de Stallings (2017) et les recommandations NIST sur les schémas hérités. En conséquence, un débit maximal élevé reflète ici autant le design cryptographique que l'adéquation entre l'algorithme et les capacités matérielles de la plateforme cible.

Afin d'isoler l'effet de la plateforme, la comparaison suivante fixe la taille du message à 4096 octets. Le graphique présente, pour chaque algorithme, une paire de barres opposant la plateforme x86 sous Windows au Raspberry Pi sous architecture ARM, en mégaoctets par seconde. Comme pour le deuxième tableau, la configuration de référence correspond au mode ECB pour les chiffrements par blocs et au mode natif Stream pour ChaCha20.

**Premier graphique — Débit par algorithme, x86 versus ARM à 4096 octets**

[Voir le graphique source](../../crypto-experiments/data/charts/01-throughput/graph-01-throughput-by-algorithm-x86-vs-arm-at-4096-bytes.png)


Le premier graphique confirme cette tendance dans un cadre à taille contrôlée. À 4096 octets, AES reste en tête avec un ratio x86/Pi de 3,59. Twofish suit à 2,03, puis ChaCha20, 3DES et DES autour de 1,40, 1,32 et 1,27. L'accélération matérielle demeure le facteur principal pour AES. Toutefois, l'écart plus faible qu'au débit maximal montre aussi que l'amortissement des coûts fixes dépend de la taille du message, ce qui réduit partiellement l'avantage observé en condition de pointe. Sur le plan méthodologique, la comparaison inter-plateforme doit donc toujours être lue à taille de message explicite, car un classement établi à débit maximal ne se transpose pas automatiquement à une charge représentative.

Ces deux premières lectures, débit de pointe au deuxième tableau et débit à taille fixe au premier graphique, remplissent des rôles méthodologiques distincts qui se complètent plutôt qu'ils ne se répètent. Le débit maximal renseigne sur la capacité de traitement la plus élevée qu'un algorithme peut atteindre dans les conditions les plus favorables du protocole, une information utile pour dimensionner un système autour de sa charge de pointe. Le débit à 4096 octets, à l'inverse, reflète une taille de message représentative d'un usage courant, plus proche de ce qu'on rencontre concrètement dans des échanges réseau typiques ou des blocs de stockage usuels, plutôt qu'un scénario optimisé pour maximiser le débit. Cette distinction explique en partie pourquoi le ratio d'AES se contracte notablement entre les deux mesures, le gain apporté par les instructions AES-NI dépend d'un coût fixe amorti sur chaque appel, notamment la préparation du calendrier de clés, un coût qui pèse proportionnellement moins lorsque le message traité est volumineux. Cette nuance justifie de ne pas se fier à une seule de ces deux lectures pour orienter un choix d'algorithme, la performance de pointe et la performance représentative pouvant classer les mêmes algorithmes différemment selon le contexte d'utilisation réel visé.

Les deux lectures précédentes mettent en évidence des écarts qui varient selon l'algorithme. Pour quantifier cet effet de manière directe, le graphique suivant exprime le rapport entre le débit x86 et le débit Raspberry Pi, dans la même configuration que le premier graphique. Un ratio proche de 1 traduit une portabilité de performance élevée, alors qu'un ratio plus grand indique une dépendance accrue au matériel x86.

**Deuxième graphique — Ratio d'accélération x86 sur ARM par algorithme**

[Voir le graphique source](../../crypto-experiments/data/charts/01-throughput/graph-02-x86-over-arm-speedup-ratio-by-algorithm.png)

Le deuxième graphique confirme que la dépendance à la plateforme diffère selon l'algorithme. AES présente le ratio x86/Pi le plus élevé à 3,59, suivi de Twofish à 2,03, puis de ChaCha20, 3DES et DES à 1,40, 1,32 et 1,27. Ce profil combine l'effet d'AES-NI, l'absence d'instructions dédiées pour DES et 3DES, et un coût logiciel de Twofish plus sensible aux contraintes de cache et de fréquence sur ARM. Il en résulte que la portabilité ne peut pas être inférée d'un seul algorithme. Les gains dus au matériel doivent donc être distingués de ceux liés à l'implémentation.

La lecture de ce ratio soulève une question naturelle, le comportement observé à 4096 octets reste-t-il stable lorsque la taille des messages varie. Le cas de ChaCha20 est particulièrement pertinent pour cette vérification, car il constitue le seul chiffrement de flux de l'échantillon et présente un ratio intermédiaire d'environ 1,40. Le troisième graphique suit donc son débit sur les deux plateformes de 64 à 16 384 octets.

**Troisième graphique — Débit en fonction de la taille du message, ChaCha20 x86 versus ARM**

[Voir le graphique source](../../crypto-experiments/data/charts/01-throughput/graph-03-throughput-vs-message-size-chacha20-x86-vs-arm.png)

Le troisième graphique montre que l'écart x86 versus Raspberry Pi pour ChaCha20 varie avec la taille du message et ne suit pas une trajectoire monotone. Cette variation est cohérente avec l'équilibre entre coûts fixes et coûts proportionnels. Les petites tailles amplifient les surcoûts d'appel, alors que les grandes tailles les amortissent davantage, avant que la hiérarchie mémoire et l'ordonnancement ne reprennent du poids. Cette observation indique qu'un point unique de mesure ne suffit pas à caractériser la portabilité de ChaCha20. Une lecture multi-tailles, appuyée par le tableau numérique suivant, est donc nécessaire.

**Troisième tableau — Débit de ChaCha20 selon la taille du message**

| Taille du message (octets) | x86 (MB/s) | Pi ARM (MB/s) | Ratio x86/Pi |
| -------------------------- | ---------: | ------------: | -----------: |
| 64                         |       4,27 |          2,13 |       2,00× |
| 256                        |      16,52 |          8,07 |       2,05× |
| 1024                       |      49,46 |         26,68 |       1,85× |
| 4096                       |      90,17 |         64,40 |       1,40× |
| 16384                      |     144,55 |         89,35 |       1,62× |

Le troisième tableau confirme ce comportement de manière chiffrée. Le ratio x86/Pi de ChaCha20 oscille entre 1,40 et 2,05. À 16384 octets, ChaCha20 sur Raspberry Pi atteint 89,35 MB/s, au-dessus de DES sur x86 à 38,78 MB/s. Ce résultat est cohérent avec le design ARX de ChaCha20, qui exploite efficacement les opérations natives des processeurs généralistes, alors que DES reste freiné par des permutations bit à bit coûteuses en logiciel, conformément aux arguments de la RFC 8439 (Nir et Langley, 2018). Ainsi, ChaCha20 présente une robustesse inter-plateforme solide pour des charges réelles, tandis que Twofish demeure le cas le plus pénalisé en performance relative sans accélération matérielle dédiée.

## Stabilité statistique des mesures

Après l'analyse des niveaux de débit, il est nécessaire de qualifier la robustesse statistique des mesures. Cette stabilité est évaluée au moyen de l'IC95 sur l'ensemble des campagnes x86 et Raspberry Pi. Sur 310 mesures agrégées, 297 respectent un seuil de largeur relative d'au plus 10 pour cent, soit 95,81 pour cent des configurations. Le taux atteint 97,31 pour cent pour les messages d'au moins 1024 octets, avec 181 mesures conformes sur 186, contre 93,55 pour cent pour les tailles 64 et 256 octets, avec 116 mesures conformes sur 124. Cette distribution confirme que le bruit relatif se concentre surtout sur les petites tailles, où les durées d'exécution sont très brèves malgré 100 répétitions par configuration.

**Quatrième graphique — Stabilité du débit IC95, x86 versus ARM à 4096 octets**

[Voir le graphique source](../../crypto-experiments/data/charts/01-throughput/graph-04-ic95-throughput-stability-x86-vs-arm-at-4096-bytes.png)

Le quatrième graphique confirme une stabilité globale élevée des mesures. À 4096 octets, AES sur x86 atteint toutefois une largeur absolue de 17,26 MB/s et une largeur relative de 11,09 pour cent, légèrement au-dessus du seuil protocolaire. Cette situation s'explique par le fait que les algorithmes les plus rapides convertissent de petites fluctuations temporelles en variations MB/s plus visibles, avec une sensibilité possible aux variations de fréquence et aux tâches d'arrière-plan sur l'hôte x86. Les écarts moyens restent donc interprétables. En revanche, les conclusions fines sur les cas les plus rapides doivent conserver une marge de prudence statistique explicite.

## Effet d’avalanche

Au-delà du débit et de sa stabilité, l'analyse doit aussi couvrir la qualité de diffusion cryptographique. L'effet d'avalanche mesure la proportion de bits du texte chiffré modifiés lorsqu'un seul bit du texte clair est inversé. Un chiffrement robuste doit idéalement produire une variation proche de la moitié des bits de sortie pour une perturbation minimale en entrée. Le graphique suivant présente le score moyen obtenu pour chaque algorithme sur x86 et sur Raspberry Pi.

**Cinquième graphique — Score d’avalanche par algorithme, x86 versus ARM**

[Voir le graphique source](../../crypto-experiments/data/charts/02-avalanche-effect/graph-05-avalanche-score-by-algorithm-x86-vs-arm.png)

Le cinquième graphique montre une diffusion correcte et homogène, les cinq algorithmes restant très proches de l'idéal de 50 pour cent sur x86 comme sur Raspberry Pi, avec un écart interplateforme maximal de 0,038 point de pourcentage. Ce résultat découle de la nature de la métrique, l'effet d'avalanche reflétant d'abord la structure interne de l'algorithme plutôt que les capacités de l'hôte d'exécution, en cohérence avec le strict avalanche criterion discuté par Stallings et le cadre confusion diffusion de Katz et Lindell. La qualité de diffusion peut donc être considérée comme stable d'une plateforme à l'autre dans cette campagne, ce qui évite de confondre variation de performance et robustesse cryptographique.

L'étape suivante consiste à distinguer les deux sources de diffusion, une perturbation du texte clair et une perturbation de la clé. Cette comparaison permet de vérifier si chaque algorithme conserve une réponse homogène entre ces deux mécanismes. Le graphique suivant confronte, pour la plateforme x86, le score d'avalanche lié au texte clair et celui lié à la clé.

**Sixième graphique — Avalanche du texte en clair versus avalanche de la clé**

[Voir le graphique source](../../crypto-experiments/data/charts/02-avalanche-effect/graph-06-plaintext-vs-key-avalanche-x86.png)

Le sixième graphique confirme la cohérence interne des mesures d'avalanche. Pour AES, DES, 3DES et Twofish, l'écart entre avalanche du texte clair et avalanche de la clé reste inférieur à 0,1 point de pourcentage. ChaCha20 demeure très proche avec un écart d'environ 0,10 point. Cette proximité s'explique par le fait que les deux perturbations testent la même capacité de diffusion globale du chiffrement, tandis que l'asymétrie observée précédemment provenait d'un artefact de protocole lié aux bits de parité de DES et 3DES, non pris en compte dans le calcul cryptographique effectif. Les scores retenus peuvent ainsi être interprétés comme homogènes entre les deux mécanismes de test, ce qui renforce la validité comparative de l'analyse d'avalanche.

## Modes de chiffrement

Après la comparaison inter-algorithmes, l'analyse se recentre sur l'effet du mode d'opération pour un même algorithme. Ce changement d'échelle est important, car le mode influence simultanément le débit et le niveau de sécurité opérationnelle. Le graphique suivant présente le débit d'AES-128 en ECB, CBC, CTR et GCM sur la plateforme x86 pour différentes tailles de message.

**Septième graphique — Débit et niveau de sécurité selon le mode d'opération AES**

[Voir le graphique source](../../crypto-experiments/data/charts/03-encryption-modes/graph-07-aes-operation-mode-security-vs-throughput.png)

Le septième graphique met en évidence le classement des modes, ECB est le plus rapide, GCM et CTR suivent, puis CBC ferme la marche. Ce résultat est structurel, ECB et CTR exploitent mieux l'indépendance des blocs ou la parallélisation du flot, GCM bénéficie d'optimisations matérielles modernes malgré le surcoût d'authentification, alors que CBC impose un chaînage séquentiel qui limite le parallélisme. En pratique, le choix d'un mode ne peut donc pas être guidé par le seul débit et doit intégrer simultanément le niveau de sécurité attendu dans le scénario visé.

La supériorité d'ECB en débit ne suffit toutefois pas à établir sa pertinence en pratique. La démonstration suivante explicite la limite structurelle du mode en comparant visuellement le chiffrement d'une même image en ECB et en CBC.

**Huitième graphique — Fuite visuelle des motifs en mode ECB**

[Voir le graphique source](../../crypto-experiments/data/charts/03-encryption-modes/graph-08-ecb-visual-pattern-leakage-demo.png)

Le huitième graphique fournit une démonstration visuelle directe, l'image chiffrée en ECB conserve des motifs répétitifs alors que la version CBC apparaît comme un bruit homogène sans structure exploitable. Cette différence provient du fonctionnement déterministe d'ECB sur des blocs identiques, alors que le chaînage de CBC casse ces répétitions d'un bloc à l'autre. Par conséquent, ECB doit être écarté des usages réels malgré son avantage de débit, en cohérence avec les recommandations de NIST SP 800-38A.

## Vue synthétique multicritère

Les analyses précédentes fournissent des lectures partielles complémentaires. Pour consolider l'interprétation, le graphique suivant réunit les résultats dans une représentation globale. Le diagramme radar combine quatre axes normalisés, le débit sur x86, le débit sur Raspberry Pi, la qualité de l'effet d'avalanche et la portabilité définie par le rapport Pi sur x86.

**Neuvième graphique — Radar de profil par algorithme, débit, portabilité et avalanche**

[Voir le graphique source](../../crypto-experiments/data/charts/04-decision-support/graph-09-algorithm-profile-radar-throughput-portability-avalanche.png)

Le neuvième graphique met en évidence un compromis multicritère. Aucun algorithme n'occupe simultanément les positions dominantes sur débit, portabilité et avalanche. Cette configuration découle de mécanismes distincts, AES tire parti du matériel dédié, ChaCha20 bénéficie d'un design ARX plus homogène entre architectures, et DES, 3DES ainsi que Twofish restent contraints par des implémentations logicielles moins avantagées sur le matériel actuel. La décision finale doit donc rester contextuelle, avec une pondération explicite des critères prioritaires du cas d'usage.

Pour prolonger cette lecture synthétique, le graphique suivant propose une carte de chaleur multicritère. Chaque algorithme y est croisé avec trois dimensions normalisées, le débit, l'efficacité en latence et la robustesse d'avalanche.

**Dixième graphique — Carte de chaleur multicritère par algorithme**

[Voir le graphique source](../../crypto-experiments/data/charts/04-decision-support/graph-10-multicriteria-heatmap-by-algorithm.png)

Le dixième graphique confirme cette lecture comparative sous un autre angle, la carte de chaleur reproduit les mêmes rapports de force que le radar entre performance, latence et diffusion. Cette cohérence est méthodologique, les deux visualisations sont construites à partir du même ensemble de métriques normalisées issues de la campagne consolidée. Les recommandations qui en découlent gagnent ainsi en robustesse, car elles ne dépendent pas d'une seule représentation visuelle mais convergent vers la même lecture décisionnelle.
