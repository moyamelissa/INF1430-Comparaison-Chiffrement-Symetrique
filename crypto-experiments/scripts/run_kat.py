"""
run_kat.py
Point d'entrée pour la suite de tests de vecteurs connus (KAT).

Usage
-----
    py scripts/run_kat.py

Sortie avec le code 0 si tous les tests passent, 1 sinon.
"""
import sys
import os

# Ajoute la racine crypto-experiments au chemin d'importation
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from validation import kat_aes, kat_des, kat_3des, kat_modes, kat_gcm, kat_chacha20


def main() -> None:
    suites = [
        ("AES  (FIPS 197)",                   kat_aes.run),
        ("DES  (SP 800-17)",                  kat_des.run),
        ("3DES (SP 800-67)",                  kat_3des.run),
        ("Modes ECB/CBC/CTR (SP 800-38A)",    kat_modes.run),
        ("AES-GCM (SP 800-38D)",              kat_gcm.run),
        ("ChaCha20 (RFC 8439)",               kat_chacha20.run),
    ]

    total_failures = 0
    for name, run_fn in suites:
        print(f"\n{'─' * 55}")
        print(f"  {name}")
        print(f"{'─' * 55}")
        failures = run_fn(verbose=True)
        total_failures += failures
        if failures == 0:
            print(f"  ✓ All tests passed.")
        else:
            print(f"  ✗ {failures} test(s) FAILED.")

    print(f"\n{'═' * 55}")
    if total_failures == 0:
        print("  ALL KAT SUITES PASSED")
    else:
        print(f"  TOTAL FAILURES: {total_failures}")
    print(f"{'═' * 55}\n")

    sys.exit(0 if total_failures == 0 else 1)


if __name__ == "__main__":
    main()
