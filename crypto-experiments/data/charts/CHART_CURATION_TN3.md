# Chart Curation Review (TN3)

## Objective

Reduce chart noise and keep only figures that directly support TN3 claims.

Current decision: keep one unified set of charts (no strict core/annex folder split for now).

## Selection rule

A chart is considered priority if it satisfies at least one of these:

1. It appears in slides or oral script.
2. It answers a main TN3 question (throughput, avalanche, mode trade-off, synthesis).
3. It is needed to compare x86 vs Raspberry Pi.

Otherwise, keep it as secondary support in the same numbered folders.

## Priority charts (recommended)

### 01-debit

- throughput-by-algo-mode-x86-4kb.png
- throughput-by-algo-mode-arm-4kb.png
- throughput-by-algo-x86-vs-arm-4kb.png
- speedup-ratio-x86-over-arm-by-algo.png
- throughput-vs-message-size-x86-vs-arm-all-algos.png
- ci95-throughput-stability-x86-vs-arm-4kb.png

Why: these six cover absolute performance, platform gap, scalability, and measurement stability.

### 02-effet-avalanche

- avalanche-score-by-algo.png
- avalanche-score-x86-vs-arm.png
- avalanche-plaintext-vs-key.png

Why: these three cover correctness and platform consistency of avalanche behavior.

### 03-modes-chiffrement

- aes-throughput-by-mode-128bit.png
- aes-security-vs-performance-by-mode.png
- ecb-visual-pattern-leakage-demo.png

Why: these three clearly communicate mode impact and security/performance trade-off.

### 04-synthese

- multicriteria-score-heatmap.png
- algorithm-profile-radar-chart.png

Why: these two are final decision visuals and should stay in the priority set.

## Secondary charts (recommended)

- 01-debit/throughput-vs-message-size-x86.png
- 01-debit/throughput-vs-message-size-x86-vs-arm-ecb.png
- 01-debit/throughput-vs-message-size-chacha20-x86-vs-arm.png
- 02-effet-avalanche/avalanche-convergence-des-rounds.png
- 03-modes-chiffrement/aes-throughput-by-key-size.png
- 03-modes-chiffrement/throughput-encrypt-vs-decrypt-ecb.png
- 03-modes-chiffrement/demo-ecb/* (technical assets)

These are useful for backup discussion but not essential for the main story.

## Naming convention (adopted)

Use this schema:

- <theme>-<metric>-<scope>-<condition>.png

Examples:

- throughput-by-algo-mode-x86-4kb.png
- throughput-by-algo-x86-vs-arm-4kb.png
- avalanche-score-x86-vs-arm.png
- aes-security-vs-performance-by-mode.png

Rules:

1. lowercase
2. kebab-case
3. include unit/condition when relevant (4kb, all-algos, ecb)
4. avoid ambiguous numbers in filenames

## Concrete cleanup actions

1. Keep current 01-04 folders.
2. Keep all generated files in those folders with explicit names.
3. Keep `README.md` as the single index of filenames and meaning.
4. Regenerate with `python scripts/run_charts.py` when output files drift.

## Quick implementation plan

1. Keep generation commands unchanged (`python scripts/run_charts.py`, or 01/02/03/04 targets).
2. Enforce naming consistency only in `build_*.py` save paths.
3. Keep docs synchronized after each rename round.
