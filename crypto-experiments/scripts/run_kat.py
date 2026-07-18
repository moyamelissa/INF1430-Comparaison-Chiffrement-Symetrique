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

from validation import (
    kat_aes,
    kat_des,
    kat_3des,
    kat_modes,
    kat_gcm,
    kat_chacha20,
    kat_twofish,
)


def _format_summary_row(
    name: str,
    assertions: int,
    passed: int,
    failed: int,
    name_width: int,
    assertions_width: int,
    passed_width: int,
    failed_width: int,
    status_width: int,
) -> str:
    status = "PASS" if failed == 0 else "FAIL"
    return (
        f"  {name:<{name_width}} | {assertions:>{assertions_width}} | "
        f"{passed:>{passed_width}} | {failed:>{failed_width}} | {status:<{status_width}}"
    )


def _print_summary_table(rows: list[dict[str, int | str]]) -> None:
    name_values = [str(row["name"]) for row in rows] + ["TOTAL"]
    assertion_values = [int(row["assertions"]) for row in rows]
    failure_values = [int(row["failures"]) for row in rows]
    passed_values = [a - f for a, f in zip(assertion_values, failure_values)]

    name_width = max(len("Suite"), max(len(name) for name in name_values))
    assertions_width = max(len("Assertions"), max(len(str(v)) for v in assertion_values + [0]))
    passed_width = max(len("Passed"), max(len(str(v)) for v in passed_values + [0]))
    failed_width = max(len("Failed"), max(len(str(v)) for v in failure_values + [0]))
    status_width = max(len("Stat"), len("PASS"), len("FAIL"))

    table_width = (
        2
        + name_width
        + 3
        + assertions_width
        + 3
        + passed_width
        + 3
        + failed_width
        + 3
        + status_width
    )

    print(f"\n{'═' * table_width}")
    print("  KAT SUMMARY")
    print(f"{'═' * table_width}")
    print(
        f"  {'Suite':<{name_width}} | {'Assertions':>{assertions_width}} | "
        f"{'Passed':>{passed_width}} | {'Failed':>{failed_width}} | {'Stat':<{status_width}}"
    )
    print(f"{'─' * table_width}")

    total_assertions = 0
    total_passed = 0
    total_failed = 0
    for row in rows:
        assertions = int(row["assertions"])
        failed = int(row["failures"])
        passed = assertions - failed
        print(
            _format_summary_row(
                str(row["name"]),
                assertions,
                passed,
                failed,
                name_width,
                assertions_width,
                passed_width,
                failed_width,
                status_width,
            )
        )
        total_assertions += assertions
        total_passed += passed
        total_failed += failed

    print(f"{'─' * table_width}")
    print(
        _format_summary_row(
            "TOTAL",
            total_assertions,
            total_passed,
            total_failed,
            name_width,
            assertions_width,
            passed_width,
            failed_width,
            status_width,
        )
    )
    print(f"{'═' * table_width}")


def main() -> None:
    suites = [
        {
            "name": "AES  (FIPS 197)",
            "runner": kat_aes.run,
            "assertions": 8,
        },
        {
            "name": "DES  (SP 800-17)",
            "runner": kat_des.run,
            "assertions": 18,
        },
        {
            "name": "3DES (SP 800-67)",
            "runner": kat_3des.run,
            "assertions": 4,
        },
        {
            "name": "Modes ECB/CBC/CTR (SP 800-38A)",
            "runner": kat_modes.run,
            "assertions": 6,
        },
        {
            "name": "AES-GCM (SP 800-38D)",
            "runner": kat_gcm.run,
            "assertions": 6,
        },
        {
            "name": "ChaCha20 (RFC 8439)",
            "runner": kat_chacha20.run,
            "assertions": 6,
        },
        {
            "name": "Twofish ECB KAT",
            "runner": kat_twofish.run,
            "assertions": 0,
        },
    ]

    total_failures = 0
    summary_rows: list[dict[str, int | str]] = []

    for suite in suites:
        name = str(suite["name"])
        run_fn = suite["runner"]
        print(f"\n{'─' * 55}")
        print(f"  {name}")
        print(f"{'─' * 55}")
        failures = run_fn(verbose=True)
        total_failures += failures

        if name == "Twofish ECB KAT":
            twofish_stats = kat_twofish.get_last_stats()
            if twofish_stats:
                for item in twofish_stats:
                    summary_rows.append(
                        {
                            "name": str(item["label"]),
                            "assertions": int(item["assertions"]),
                            "failures": int(item["failures"]),
                        }
                    )
            else:
                summary_rows.append(
                    {
                        "name": name,
                        "assertions": 0,
                        "failures": failures,
                    }
                )
        else:
            summary_rows.append(
                {
                    "name": name,
                    "assertions": int(suite["assertions"]),
                    "failures": failures,
                }
            )

        if failures == 0:
            print(f"  ✓ All tests passed.")
        else:
            print(f"  ✗ {failures} test(s) FAILED.")

    _print_summary_table(summary_rows)

    print(f"\n{'═' * 55}")
    if total_failures == 0:
        print("  ALL KAT SUITES PASSED")
    else:
        print(f"  TOTAL FAILURES: {total_failures}")
    print(f"{'═' * 55}\n")

    sys.exit(0 if total_failures == 0 else 1)


if __name__ == "__main__":
    main()
