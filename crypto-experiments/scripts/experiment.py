"""
experiment.py
Entry point for the benchmarking campaign.

Usage
-----
Run from the crypto-experiments/ root directory:

    python scripts/experiment.py

The script iterates over all algorithm / mode / key-size / message-size
combinations defined in EXPERIMENT_MATRIX, runs performance + avalanche
measurements via ExperimentController, and writes results to
data/results/experiment_<timestamp>.csv.

No cryptographic logic lives here — this file only wires up the domain and
application layers and handles I/O.
"""

import csv
import os
import sys
from dataclasses import asdict
from datetime import datetime

# Make the project root importable regardless of working directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from domain.cipher.AES import AES
from domain.cipher.DES import DES
from domain.cipher.TripleDES import TripleDES
from domain.cipher.Twofish import Twofish
from domain.cipher.ChaCha20 import ChaCha20
from domain.mode.ECB import ECB
from domain.mode.CBC import CBC
from domain.mode.CTR import CTR
from domain.mode.GCM import GCM
from domain.mode.StreamMode import StreamMode
from domain.engine.EncryptionEngine import EncryptionEngine
from application.ExperimentController import ExperimentController

# ------------------------------------------------------------------ #
#  Experiment matrix                                                   #
# ------------------------------------------------------------------ #
# Each entry: (algorithm_label, primitive_factory, mode_label, mode_class,
#              key_sizes_bytes, message_sizes_bytes, repetitions)
#
# key_sizes_bytes is a list because AES supports 128/192/256-bit keys.
# GCM is only valid for AES so it is included only in the AES block.

REPETITIONS = 100

EXPERIMENT_MATRIX = [
    # (algo, primitive_cls, mode_label, mode_cls, key_sizes)
    ("AES",    AES,       "ECB", ECB, [16, 24, 32]),
    ("AES",    AES,       "CBC", CBC, [16, 24, 32]),
    ("AES",    AES,       "CTR", CTR, [16, 24, 32]),
    ("AES",    AES,       "GCM", GCM, [16, 24, 32]),
    ("DES",    DES,       "ECB", ECB, [8]),
    ("DES",    DES,       "CBC", CBC, [8]),
    ("DES",    DES,       "CTR", CTR, [8]),
    ("3DES",   TripleDES, "ECB", ECB, [16, 24]),
    ("3DES",   TripleDES, "CBC", CBC, [16, 24]),
    ("3DES",   TripleDES, "CTR", CTR, [16, 24]),
    ("Twofish",Twofish,   "ECB", ECB,        [16, 24, 32]),
    ("Twofish",Twofish,   "CBC", CBC,        [16, 24, 32]),
    ("Twofish",Twofish,   "CTR", CTR,        [16, 24, 32]),
    # Stream cipher — uses StreamMode wrapper (nonce is built into the primitive)
    ("ChaCha20", ChaCha20, "Stream", StreamMode, [32]),
]

MESSAGE_SIZES = [64, 256, 1024, 4096, 16384]  # bytes

# ------------------------------------------------------------------ #
#  Helpers                                                             #
# ------------------------------------------------------------------ #

def _make_key(size: int) -> bytes:
    """Generate a random key of the given size."""
    return os.urandom(size)


def _output_path() -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data", "results",
    )
    os.makedirs(out_dir, exist_ok=True)
    return os.path.join(out_dir, f"experiment_{ts}.csv")


# ------------------------------------------------------------------ #
#  Main                                                                #
# ------------------------------------------------------------------ #

def main() -> None:
    results = []

    for algo, primitive_cls, mode_label, mode_cls, key_sizes in EXPERIMENT_MATRIX:
        for key_size in key_sizes:
            # Pre-check: can we instantiate this primitive at all?
            try:
                _probe_key = _make_key(key_size)
                _probe = primitive_cls(_probe_key)
            except Exception as exc:  # noqa: BLE001
                print(f"  SKIPPED {algo} (key={key_size*8}bit) — {exc}")
                break  # Skip all message sizes / modes for this key size too

            for msg_size in MESSAGE_SIZES:
                key = _make_key(key_size)
                try:
                    primitive = primitive_cls(key)
                    mode = mode_cls(primitive)
                    engine = EncryptionEngine(primitive, mode)
                    controller = ExperimentController(engine, algo, mode_label)

                    print(
                        f"  Running {algo}-{mode_label} "
                        f"key={key_size*8}bit msg={msg_size}B …",
                        end=" ",
                        flush=True,
                    )
                    result = controller.run_performance(
                        message_size_bytes=msg_size,
                        repetitions=REPETITIONS,
                    )
                    results.append(result)
                    print(
                        f"enc={result.avg_encrypt_time_s*1000:.3f}ms "
                        f"thr={result.throughput_encrypt_mbps:.2f}MB/s "
                        f"avalanche={result.avalanche_score:.3f}"
                    )

                except Exception as exc:  # noqa: BLE001
                    print(f"  SKIPPED {algo}-{mode_label} key={key_size*8}bit msg={msg_size}B — {exc}")

    if not results:
        print("No results collected.")
        return

    out_path = _output_path()
    fieldnames = list(asdict(results[0]).keys())
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))

    print(f"\nResults saved to: {out_path}")


if __name__ == "__main__":
    main()
