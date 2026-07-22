# INF1430 TN4 Validation Proof Protocol

## Objective
Provide auditable evidence that the implementation is correct enough for TN4 conclusions, with explicit limits and reproducibility steps.

## Proof Model
The project uses a layered evidence model.

1. Functional correctness evidence
- Full automated test suite passes.
- Coverage gate is strict at 100 percent lines and 100 percent branches.

2. Cryptographic conformance evidence
- KAT suites pass on all supported primitives and modes.
- Twofish KAT supports strict external-vector policy and optional checksum enforcement.

3. Robustness evidence
- Failure-path tests cover malformed input, tamper detection, and strict-mode failures.
- Differential tests compare outputs to trusted reference implementations.

4. Statistical validity evidence
- IC95 audit gates pass with explicit pass or fail outcome.
- Audit artifacts are exported for review.

## Reproducible Execution Steps
Run all commands from the repository root unless noted.

### Generate an evidence bundle
Use the bundle script to export logs, artifacts, and commit metadata in one folder.

From repository root
```powershell
python crypto-experiments/scripts/validation_bundle.py
```

From crypto-experiments
```powershell
python scripts/validation_bundle.py
```

Bundle output location
- crypto-experiments/data/results/validation-bundles/bundle-<timestamp>

The bundle includes
- pytest log
- KAT log
- IC95 gate log
- coverage.xml
- ic95_raw_rows.csv
- ic95_audit_report.csv
- bundle_manifest.json with commit hash and command return codes

### Windows local
```powershell
cd crypto-experiments
..\.venv\Scripts\Activate.ps1
python -m pytest
python scripts/run_kat.py --twofish-profile full --twofish-checksum warn
python scripts/audit/audit_ic95.py --enforce-gates
```

### Raspberry Pi local
```bash
cd ~/INF1430-Comparaison-Chiffrement-Symetrique/crypto-experiments
source .venv/bin/activate
python -m pytest
python scripts/run_kat.py --twofish-profile full --twofish-checksum warn
python scripts/audit/audit_ic95.py --enforce-gates
```

## Strict Twofish Integrity Mode
Strict mode is used when official files and sidecar checksums are available.

```bash
python scripts/run_kat.py \
  --twofish-profile full \
  --strict-twofish-vectors \
  --twofish-checksum enforce
```

Required assets for strict mode
- Resources/KAT/Twofish-kat/ECB_VK.TXT
- Resources/KAT/Twofish-kat/ECB_VT.TXT
- Resources/KAT/Twofish-kat/ECB_TBL.TXT
- Corresponding .sha256 sidecars for each file

## Expected Signals
1. Tests
- All tests pass.
- Coverage summary reports 100 percent lines and 100 percent branches.

2. KAT
- Terminal ends with ALL KAT SUITES PASSED.
- In strict mode, missing vectors or checksum mismatch must fail.

3. IC95
- Terminal includes Quality gate enforcement PASS.
- Artifacts are written under data/results/audit.

## Claims You Can Defend
Use high-confidence wording instead of absolute certainty.

Recommended wording
- Results are strongly supported by reproducible automated validation.
- Conformance is verified against known-answer vectors and reference implementations.
- Statistical quality gates are enforced before conclusions are accepted.

Avoid wording
- Perfectly correct
- Guaranteed bug-free
- Bulletproof

## Evidence Package Checklist
For TN4 submission or oral defense, include

1. Latest pytest output with coverage section
2. Latest KAT run output with summary table
3. Latest IC95 gate output
4. Generated audit CSV artifacts
5. Commit hashes corresponding to validation upgrades

## GitHub Branch Protection Policy
Apply this policy to branch main.

1. Require a pull request before merging
2. Require at least one approval review
3. Dismiss stale approvals when new commits are pushed
4. Require status checks to pass before merging
5. Required checks
- Tests / pytest
- Tests / kat
- Tests / ic95-audit
6. Restrict direct pushes to main
7. Keep administrators subject to these rules

This policy converts technical quality into governance quality, which is critical
for defending result integrity in TN4.
