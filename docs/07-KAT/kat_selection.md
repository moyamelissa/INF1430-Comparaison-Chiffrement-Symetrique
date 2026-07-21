# KAT Selection Method (TN3)

## Goal

This document explains how KAT vectors were selected in this project, with:

- reference source used
- vectors/scenarios selected
- reason for selection
- resulting assertion count

It is meant to keep the method transparent and defensible in TN3.

## Two possible strategies

### Strategy A - Balanced core set (recommended for main TN3 slides)

- Use a small representative subset for every suite.
- Keep cross-suite comparison fair.
- Report a compact total as the main KPI.

### Strategy B - Extended corpus (recommended for annex/demo)

- Use full public corpora when available (for example Twofish ECB VK/VT/TBL files).
- Better depth, but not symmetric with suites that currently use curated subsets.
- Report separately as "extended validation".

Recommended TN3 framing: show Strategy A in main slides, Strategy B in annex.

## Per-suite selection details (default run)

### AES

- Vectors chosen: 4 vectors total (2 for AES-128, 1 for AES-192, 1 for AES-256), each checked with encrypt match and decrypt round-trip.
- Reference: NIST FIPS 197 (Appendices A, B, C).
- How selected: one canonical known-answer vector per key size, plus AES-128 zero-key/zero-plain sanity vector.
- Why this choice: cover all key sizes without running a very large corpus in the main TN3 run.
- Assertions: 8.

### DES

- Vectors chosen: 9 plaintext/ciphertext pairs from SP 800-17 Table 1 subset, each checked with encrypt match and decrypt round-trip.
- Reference: NIST SP 800-17, Table 1.
- How selected: first 8 entries plus the last entry of the table.
- Why this choice: preserve representative bit-position coverage while keeping runtime compact.
- Assertions: 18.

### 3DES

- Vectors chosen: 2 vectors (one 2-key TDEA and one 3-key TDEA), each checked with encrypt match and decrypt round-trip.
- Reference: NIST SP 800-67 Rev.2 (EDE behavior), expected values cross-checked with a reference implementation.
- How selected: one valid representative vector for each keying option.
- Why this choice: guarantee coverage of both keying schemes with minimal overhead.
- Assertions: 4.

### Modes (ECB, CBC, CTR)

- Vectors chosen: ECB payload KAT + round-trip, CBC payload KAT + round-trip, CTR keystream spot-check + round-trip.
- Reference: NIST SP 800-38A, Appendix F.
- How selected: one focused test scenario per mode behavior that maps to the project implementation details.
- Why this choice: validate each mode path (payload correctness + practical decryptability) without a combinatorial test set.
- Assertions: 6.

### AES-GCM

- Vectors chosen: TC3 and TC4 from NIST, each checked for encrypt output, decrypt/verify, and tamper detection.
- Reference: NIST SP 800-38D, Appendix B.
- How selected: non-empty plaintext cases that exercise core AEAD code paths.
- Why this choice: verify confidentiality and integrity checks in a compact set.
- Assertions: 6.

### ChaCha20

- Vectors chosen: RFC 8439 encryption known-answer test, plus wrapper round-trips (64B, 256B, odd length), plus tamper behavior and key-size validation.
- Reference: RFC 8439.
- How selected: mix one strict normative ciphertext vector with implementation-specific behavior checks.
- Why this choice: ensure mathematical correctness and wrapper robustness.
- Assertions: 6.

### Twofish (core profile, default)

- Vectors chosen: 1 representative vector from each family: ECB_VK, ECB_VT, ECB_TBL; each checked with encrypt match and decrypt round-trip.
- Reference: Schneier et al. (1998), Counterpane submission vectors.
- How selected: choose one canonical vector per family from the official public corpus.
- Why this choice: keep cross-suite comparison balanced for TN3 main results while still using an external reference source.
- Assertions: 6.

Default run total (core profile): 54 assertions.

## Optional Twofish extended profile

- Environment variable: `TWOFISH_KAT_PROFILE=full`
- Effect: run full corpus (ECB_VK 576 vectors, ECB_VT 384 vectors, ECB_TBL 147 vectors)
- Assertions in full profile: 2214 for Twofish, 2262 total

## Twofish details (extended corpus)

- ECB_VK: 576 vectors, 1152 assertions.
- ECB_VT: 384 vectors, 768 assertions.
- ECB_TBL: 147 vectors, 294 assertions.
- Total Twofish extended: 1107 vectors, 2214 assertions.

## If you choose balanced TN3 main slides

Two clean options:

1. Keep current code and present:
   - Main result: balanced subset totals (without extended Twofish)
   - Annex result: extended Twofish (2214) as additional validation

2. Add a Twofish core subset for main comparison:
   - Example: 1-2 vectors from each family (VK, VT, TBL), each with encrypt + decrypt
   - Then keep the full corpus run as annex.

## Suggested oral wording

"Notre resultat principal compare des sous-ensembles representatifs homogenes entre suites. En complement, nous executons une validation etendue Twofish sur le corpus public complet des auteurs (ECB_VK/VT/TBL), presentee separement comme stress test cryptographique."
