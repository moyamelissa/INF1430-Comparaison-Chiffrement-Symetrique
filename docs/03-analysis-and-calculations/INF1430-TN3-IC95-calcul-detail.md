# Calcul de l'intervalle de confiance à 95 % — Détail méthodologique

## Contexte

Dans le protocole expérimental, chaque configuration est mesurée 100 fois.
Chaque répétition produit un temps de chiffrement légèrement différent à cause du bruit système.
L'intervalle de confiance à 95 % (IC 95 %) encadre cette variabilité pour produire une plage fiable autour du débit moyen mesuré.

---

## Formule utilisée dans `_ci95_mbps` (ExperimentController.py, lignes 127 à 140)

$$IC_{95\%} = t_{crit} \times \frac{\sigma_{débit}}{\sqrt{n}}$$

Où:
- $n$ = nombre de répétitions (100 dans notre protocole)
- $\sigma_{débit}$ = écart-type du débit estimé (voir conversion ci-dessous)
- $t_{crit}$ = 1,96 si $n \ge 30$ (approximation normale), sinon 2,045

### Conversion du temps en débit

Le code mesure les temps en secondes, mais le résultat est exprimé en mégaoctets par seconde (Mo/s).
La conversion de l'écart-type temporel en écart-type de débit utilise l'approximation:

$$\sigma_{débit} \approx \frac{mb \times \sigma_t}{\bar{t}^2}$$

Où:
- $mb$ = taille du message en mégaoctets
- $\sigma_t$ = écart-type des temps mesurés
- $\bar{t}$ = temps moyen mesuré

---

## Exemple numérique concret

**Hypothèses:**
- Taille du message: 4096 octets = 0,00390625 Mo
- Temps moyen de chiffrement: $\bar{t} = 0,0008$ s
- Écart-type du temps: $\sigma_t = 0,00008$ s
- Répétitions: $n = 100$

**Calcul du débit moyen:**

$$\bar{D} = \frac{0,00390625}{0,0008} = 4,88 \text{ Mo/s}$$

**Calcul de l'écart-type du débit:**

$$\sigma_{débit} \approx \frac{0,00390625 \times 0,00008}{(0,0008)^2} = 0,488$$

**Calcul de l'IC 95 %:**

$$IC_{95\%} = 1,96 \times \frac{0,488}{\sqrt{100}} = 1,96 \times 0,0488 = 0,096 \text{ Mo/s}$$

**Résultat final:**

$$\bar{D} \pm IC_{95\%} = 4,88 \pm 0,096 \text{ Mo/s} \Rightarrow [4,78 \, ; \, 4,97] \text{ Mo/s}$$

Cela signifie: on est sûr à 95 % que le vrai débit de chiffrement se situe entre 4,78 et 4,97 Mo/s.

---

## Pourquoi 100 répétitions est un bon choix

La demi-largeur de l'IC diminue en $\frac{1}{\sqrt{n}}$.

| Répétitions ($n$) | $\sqrt{n}$ | IC relatif (demi-largeur) |
|---|---|---|
| 25 | 5 | 0,192 Mo/s |
| 50 | 7,07 | 0,136 Mo/s |
| **100** | **10** | **0,096 Mo/s** |
| 200 | 14,14 | 0,068 Mo/s |
| 400 | 20 | 0,048 Mo/s |

Passer de 25 à 100 répétitions divise la demi-largeur par 2.
Passer de 100 à 400 répétitions ne la divise que par 2 à nouveau, pour 4x plus de temps d'exécution.
**100 répétitions est le point de rendement optimal.**

---

## Pourquoi le coefficient vaut environ 1,96

Le coefficient $t_{crit} = 1,96$ correspond au quantile 97,5 % de la loi normale standard $Z$.

$$P(-1,96 \le Z \le 1,96) = 0,95$$

Autrement dit: pour une distribution normale, 95 % des observations tombent dans l'intervalle $[\bar{x} - 1,96\sigma, \bar{x} + 1,96\sigma]$.

Ce coefficient s'applique quand $n \ge 30$, car à partir de cette valeur, la distribution de la moyenne échantillonnale converge vers une loi normale (théorème central limite). Pour $n < 30$, on utilise la loi de Student avec $t_{0,975, n-1} \approx 2,045$.

Dans notre protocole, $n = 100 \ge 30$, donc $t_{crit} = 1,96$ est correct.

---

## Référence dans le code

```python
# ExperimentController.py, lignes 127 à 140
def _ci95_mbps(times: list, avg_t: float) -> float:
    n = len(times)
    if n < 2 or avg_t <= 0:
        return 0.0
    variance = sum((t - avg_t) ** 2 for t in times) / (n - 1)
    std_dev  = math.sqrt(variance)
    std_thr  = mb * std_dev / (avg_t ** 2)
    t_crit   = 1.96 if n >= 30 else 2.045
    return t_crit * std_thr / math.sqrt(n)
```
