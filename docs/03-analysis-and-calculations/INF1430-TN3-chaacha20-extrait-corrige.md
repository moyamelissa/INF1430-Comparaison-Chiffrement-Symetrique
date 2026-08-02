# Extrait corrigé — ChaCha20 et comparaison plateforme

Le point de transition avant le graphique de ratio doit utiliser **DES 56 bits** et non 64 bits, afin de rester cohérent avec la clé effective utilisée dans le reste du rapport.

**Tableau — Débit de ChaCha20 selon la taille du message**

| Taille du message (octets) | x86 (MB/s) | Pi ARM (MB/s) | Ratio x86/Pi |
|---|---:|---:|---:|
| 64 | 2.868888 | 2.200209 | 1.303916× |
| 256 | 12.018057 | 8.701194 | 1.381196× |
| 1024 | 39.588272 | 27.531695 | 1.437916× |
| 4096 | 77.230578 | 63.463658 | 1.216926× |
| 16384 | 112.706147 | 87.017987 | 1.295205× |

Ce tableau montre que le ratio x86/Pi reste dans une plage étroite, entre **1,22×** et **1,44×**, sans changement de tendance marqué selon la taille du message. Dans la matrice actuelle, ChaCha20 est mesuré uniquement sur les tailles 64, 256, 1024, 4096 et 16384 octets.

**Graphique 3 — Débit de ChaCha20 en fonction de la taille du message**

[Voir le graphique source](../../crypto-experiments/data/charts/01-throughput/throughput-vs-message-size-chacha20-x86-vs-arm.png)

À 16384 octets, ChaCha20 atteint environ **112,71 MB/s** sur x86 et **87,02 MB/s** sur Raspberry Pi. L'écart observé reste modéré et confirme que ChaCha20 conserve un comportement relativement stable d'une plateforme à l'autre.
