# Graphiques d'analyse — Comment les générer

Les fichiers PNG dans ce dossier sont générés automatiquement à partir des données CSV de benchmark.

## Prérequis

Python 3.12+ doit être installé. Installe les dépendances si ce n'est pas déjà fait :

```powershell
py -m pip install matplotlib pycryptodome twofish
```

## Générer tous les graphiques

Depuis le dossier `crypto-experiments/` :

```powershell
cd crypto-experiments
py scripts/generate_charts.py
```

Les 6 PNG seront (re)créés dans ce dossier (`data/charts/`).

---

## Graphiques produits

| Fichier | Description |
|---------|-------------|
| `fig1_throughput_4096B.png` | Débit de chiffrement (MB/s) par algorithme et mode, message de 4 096 octets. Vue d'ensemble comparative. |
| `fig2_throughput_vs_msgsize.png` | Évolution du débit selon la taille du message (mode ECB, meilleure clé par algo). Montre la scalabilité. |
| `fig3_aes_mode_comparison.png` | Comparaison des 4 modes d'opération pour AES-128 (ECB / CBC / CTR / GCM) selon la taille du message. |
| `fig4_avalanche.png` | Score d'effet d'avalanche par algorithme (moyenne ± écart-type). Valeur idéale = 0,50. |
| `fig5_enc_vs_dec_ecb.png` | Débit de chiffrement vs déchiffrement (mode ECB, 4 096 octets) pour chaque algo+clé. |
| `fig6_aes_key_size.png` | Impact de la taille de clé (128 / 192 / 256 bits) sur le débit AES, par mode. |

---

## Source des données

Le script lit automatiquement le dernier CSV trouvé dans `data/results/`.

Le fichier actuel est :
```
data/results/laptop-windows-x86_experience1.csv
```

Si tu ajoutes un nouveau CSV (ex. Raspberry Pi), renomme-le avec un nom alphabétiquement postérieur et relance le script — il sera lu automatiquement.

Exemple de nommage :
```
laptop-windows-x86_experience1.csv   ← expérience 1 (laptop)
raspberry-pi_experience2.csv         ← expérience 2 (Pi)
```

---

## Modifier ou ajouter un graphique

Le script source est `scripts/generate_charts.py`. Chaque figure est définie dans sa propre fonction :

- `fig1_throughput_4096()` → fig1
- `fig2_throughput_vs_size()` → fig2
- `fig3_aes_mode_comparison()` → fig3
- `fig4_avalanche()` → fig4
- `fig5_enc_vs_dec()` → fig5
- `fig6_key_size_impact()` → fig6

Pour ajouter un graphique, crée une nouvelle fonction `figN_...()` et appelle-la dans le bloc `if __name__ == "__main__":` à la fin du fichier.
