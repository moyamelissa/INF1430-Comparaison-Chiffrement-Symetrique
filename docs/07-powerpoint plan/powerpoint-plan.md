# Structure PowerPoint recommandée

Ce document présente la structure recommandée de la présentation PowerPoint du projet INF1430 sur la comparaison d'algorithmes de chiffrement symétrique.

## Plan par page

| Page | Titre de la page | Objectif de la page |
|---|---|---|
| 1 | Titre du projet | Poser le contexte, l'équipe, le cours et le périmètre de l'étude. |
| 2 | Agenda | Donner la vue d'ensemble du déroulement et annoncer la logique de la démonstration. |
| 3 | Nature du système étudié | Expliquer l'architecture logicielle, les composants et les algorithmes inclus dans le projet. |
| 4 | Protocole expérimental | Décrire la méthodologie de mesure: paramètres, répétitions, contrôle des conditions et reproductibilité. |
| 5 | Choix technologique: pourquoi Python | Justifier le langage en lien avec la lisibilité, la modularité et la rapidité de prototypage scientifique. |
| 6 | Validation fonctionnelle par KAT | Montrer que les implémentations sont correctes avant toute interprétation des performances. |
| 7 | AES: architecture interne | Présenter les éléments structurants d'AES et ce qui influence ses performances. |
| 8 | Débit global x86 vs Raspberry Pi | Comparer les résultats globaux entre plateformes et mettre en évidence les tendances majeures. |
| 9 | AES: écart de performance et AES-NI | Expliquer l'écart observé par l'accélération matérielle sur x86 et son absence sur ARM. |
| 10 | AES: impact des modes d'opération | Montrer que le mode influence la performance et les garanties de sécurité. |
| 11 | ChaCha20: conception orientée logiciel | Expliquer pourquoi ChaCha20 est efficace sans accélération matérielle spécifique. |
| 12 | ChaCha20 vs AES sur ARM | Analyser la comparaison ciblée sur ARM et discuter les implications pratiques. |
| 13 | ChaCha20 et équité inter-plateformes | Montrer en quoi ChaCha20 est plus stable d'une plateforme à l'autre. |
| 14 | DES, 3DES, Twofish: limites actuelles | Justifier, avec données, pourquoi ces options sont moins pertinentes aujourd'hui. |
| 15 | ECB: rapide mais risqué | Expliquer clairement le compromis performance/sécurité et la vulnérabilité d'ECB. |
| 16 | Effet d'avalanche | Démontrer la diffusion cryptographique et sa contribution à la robustesse. |
| 17 | Sensibilité aux clés | Montrer comment de faibles variations de clé modifient fortement les sorties. |
| 18 | Stabilité statistique (IC₉₅) | Valider la fiabilité des mesures avec l'intervalle de confiance à 95 %. |
| 19 | Synthèse: comment choisir en 2026 | Transformer les résultats techniques en cadre de décision clair selon le contexte d'usage. |
| 20 | Recommandations finales | Donner des recommandations concrètes par plateforme, objectif de sécurité et contrainte de performance. |
| 21 | Conclusion | Récapituler les apprentissages clés et la valeur de la démarche expérimentale. |
| 22 | Références | Citer les standards, sources scientifiques et ressources techniques utilisées. |
