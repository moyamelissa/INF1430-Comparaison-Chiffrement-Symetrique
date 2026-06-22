# Videos Plan

This folder contains the video production structure:
- one global overview table
- one file per video

## Overview

| Video | Objective | Files or folders to explain | Script file |
| --- | --- | --- | --- |
| 1 | Nature du systeme, architecture et execution en direct | Root, README, domain/cipher, domain/mode, domain/engine, application/ExperimentController.py, scripts/, run experiment.py, generated CSV | [video-01-nature-du-systeme.md](video-01-nature-du-systeme.md) |
| 2 | Protocole experimental, justification des 100 repetitions | application/ExperimentController.py, scripts/experiment.py, live run, CSV structure | [video-02-protocole-experimental.md](video-02-protocole-experimental.md) |
| 3 | Validation KAT, conformite cryptographique | validation/, scripts/run_kat.py, live run | [video-03-validation-kat.md](video-03-validation-kat.md) |
| 4 | Resultats de performance, impact AES-NI | scripts/generate_charts.py, run, throughput charts | [video-04-resultats-performance.md](video-04-resultats-performance.md) |
| 5 | Robustesse cryptographique, effet d'avalanche | scripts/analyse_rounds_avalanche.py, run, avalanche charts | [video-05-robustesse-cryptographique.md](video-05-robustesse-cryptographique.md) |
| 6 | Synthese et recommandations | scripts/ecb_visual_vulnerability.py, run, recommendation slide, TN3 to TN4 transition | [video-06-synthese-recommandations.md](video-06-synthese-recommandations.md) |
| 7 | ChaCha20, equite entre plateformes | data/charts/comparison/cmp5_chacha20, cmp2_speedup_ratio | [video-07-chacha20-equite-plateformes.md](video-07-chacha20-equite-plateformes.md) |
| 8 | DES, 3DES, Twofish, pourquoi ils ont perdu | dedicated slide, cmp1_throughput_all.png | [video-08-des-3des-twofish.md](video-08-des-3des-twofish.md) |
| 9 | ECB, mode rapide mais dangereux | scripts/ecb_visual_vulnerability.py, run, fig8_ecb_vulnerability.png | [video-09-ecb-dangereux.md](video-09-ecb-dangereux.md) |
| 10 | Effet d'avalanche, sante cryptographique | fig4_avalanche.png, fig7_rounds_avalanche.png, fig4b_key_avalanche.png | [video-10-effet-avalanche.md](video-10-effet-avalanche.md) |
| 11 | Sensibilite aux cles et stabilite IC95 | key sensitivity slide, fig4b_key_avalanche.png, IC95 stability chart | [video-11-cles-stabilite-ic95.md](video-11-cles-stabilite-ic95.md) |
| 12 | Synthese finale, quel algorithme choisir en 2026 | recommendation slide, TN3/TN4 transition, conclusion | [video-12-synthese-finale-2026.md](video-12-synthese-finale-2026.md) |
