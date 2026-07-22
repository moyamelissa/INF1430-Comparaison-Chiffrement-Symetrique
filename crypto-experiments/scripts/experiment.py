"""
experiment.py
Point d'entrée de la campagne de benchmarking.

Usage
-----
Lancer depuis le répertoire racine crypto-experiments/ :

    python scripts/experiment.py

Le script itère sur toutes les combinaisons algorithme / mode / taille de clé /
taille de message définies dans EXPERIMENT_MATRIX, exécute les mesures de
performance + avalanche via ExperimentController, et écrit les résultats dans
data/results/<plateforme>_experienceX_YYYYMMDD.csv, par exemple
``windows_experience4_20260717.csv``. L'index ``X`` est incrémenté
automatiquement pour chaque nouvelle campagne d'une même plateforme.

Aucune logique cryptographique ne se trouve ici — ce fichier ne fait que
cabler les couches domaine et application et gérer les E/S.
"""

import csv
import os
import platform
import re
import sys
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime

# Chemin racine du projet rendu importable quel que soit le répertoire de travail
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
#  Matrice d'expériences                                               #
# ------------------------------------------------------------------ #
# Chaque entrée : (label_algo, usine_primitive, label_mode, classe_mode,
#                  tailles_cles_octets, tailles_messages_octets, repetitions)
#
# key_sizes_bytes est une liste car AES supporte les clés 128/192/256 bits.
# GCM n'est valide que pour AES, donc inclus uniquement dans le bloc AES.

REPETITIONS = 100

EXPERIMENT_MATRIX = [
    # (algo, primitive_cls, label_mode, mode_cls, tailles_cles)
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
    # Chiffre de flux — utilise le wrapper StreamMode (nonce intégré dans la primitive)
    ("ChaCha20", ChaCha20, "Stream", StreamMode, [32]),
]

MESSAGE_SIZES = [64, 256, 1024, 4096, 16384]  # bytes

# ------------------------------------------------------------------ #
#  Fonctions utilitaires                                               #
# ------------------------------------------------------------------ #

def _make_key(size: int) -> bytes:
    """Génère une clé aléatoire de la taille donnée."""
    return os.urandom(size)


def _platform_label() -> str:
    """Construit un identifiant plateforme lisible pour le nom de CSV."""
    if _is_raspberry_pi():
        return "raspberry-pi"

    system = platform.system().lower() or "unknown"
    machine = platform.machine().lower() or "unknown"

    aliases = {
        "amd64": "x86_64",
        "x64": "x86_64",
        "i386": "x86",
        "i686": "x86",
        "aarch64": "arm64",
        "armv7l": "arm",
    }
    machine = aliases.get(machine, machine)

    # Garder un slug stable: lettres/chiffres seulement, séparés par des tirets.
    raw = f"{system}-{machine}"
    slug = re.sub(r"[^a-z0-9]+", "-", raw).strip("-")
    return slug or "unknown-platform"


def _platform_results_prefix() -> str:
    """Retourne le préfixe utilisé dans data/results pour la plateforme courante."""
    label = _platform_label()
    aliases = {
        "windows-x86-64": "windows",
        "windows-x86": "windows",
        "raspberry-pi": "raspberry-pi",
    }
    return aliases.get(label, label)


def _output_path() -> str:
    ts = datetime.now().strftime("%Y%m%d")
    prefix = _platform_results_prefix()
    out_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data", "results",
    )
    os.makedirs(out_dir, exist_ok=True)

    pattern = re.compile(
        rf"^{re.escape(prefix)}_experience(?P<idx>\d+)(?:_\d{{8}})?\.csv$"
    )
    max_index = 0
    for name in os.listdir(out_dir):
        match = pattern.match(name)
        if not match:
            continue
        max_index = max(max_index, int(match.group("idx")))

    next_index = max_index + 1
    return os.path.join(out_dir, f"{prefix}_experience{next_index}_{ts}.csv")


def _twofish_import_error() -> str | None:
    """Retourne l'erreur d'import Twofish, ou None si l'import réussit."""
    try:
        import twofish  # noqa: F401
        return None
    except Exception as exc:  # noqa: BLE001
        return str(exc)


def _is_raspberry_pi() -> bool:
    """Détecte si le runtime courant est probablement un Raspberry Pi."""
    node = platform.node().lower()
    if "raspberry" in node:
        return True

    if platform.system().lower() != "linux":
        return False

    machine = platform.machine().lower()
    if not (machine.startswith("arm") or machine.startswith("aarch64")):
        return False

    model_paths = [
        "/proc/device-tree/model",
        "/sys/firmware/devicetree/base/model",
    ]
    for model_path in model_paths:
        try:
            with open(model_path, "rb") as handle:
                model = handle.read().decode("utf-8", errors="ignore").lower()
            if "raspberry" in model:
                return True
        except OSError:
            continue

    try:
        with open("/etc/os-release", "r", encoding="utf-8") as handle:
            os_release = handle.read().lower()
        if "raspbian" in os_release or "raspberry pi" in os_release:
            return True
    except OSError:
        pass

    return False


def _print_run_summary(stats: dict[str, dict[str, int]]) -> bool:
    """Affiche un tableau synthèse et retourne True si tous les algorithmes sont présents."""
    print("\nRun summary by algorithm")
    header = f"{'Algorithm':<12} {'Planned':>8} {'Success':>8} {'Skipped':>8}  Status"
    print(header)
    print("-" * len(header))

    missing_algorithms: list[str] = []
    for algo in sorted(stats.keys()):
        planned = stats[algo]["planned"]
        success = stats[algo]["success"]
        skipped = stats[algo]["skipped"]
        status = "OK"
        if success == 0:
            status = "MISSING"
            missing_algorithms.append(algo)
        elif skipped > 0:
            status = "PARTIAL"

        print(f"{algo:<12} {planned:>8} {success:>8} {skipped:>8}  {status}")

    if missing_algorithms:
        print(
            "\n[error] One or more expected algorithms produced no successful runs: "
            + ", ".join(missing_algorithms)
        )
        return False
    else:
        print("\n[ok] All algorithms in the matrix completed successfully.")
        return True


# ------------------------------------------------------------------ #
#  Point d'entrée principal                                            #
# ------------------------------------------------------------------ #

def main() -> int:
    results = []
    running_on_rpi = _is_raspberry_pi()
    run_stats: dict[str, dict[str, int]] = defaultdict(
        lambda: {"planned": 0, "success": 0, "skipped": 0}
    )

    matrix = EXPERIMENT_MATRIX
    twofish_error = _twofish_import_error()
    if twofish_error is not None:
        if running_on_rpi:
            print(
                "[warning] Raspberry Pi detected. Twofish support is unavailable "
                "in this Python environment. "
                f"Interpréteur actif: {sys.executable}. "
                f"Erreur d'import: {twofish_error}. "
                "If you need Twofish on Pi, install/fix it in this interpreter: "
                f"{sys.executable} -m pip install twofish"
            )
        else:
            print(
                "[warning] Twofish indisponible dans cet environnement Python. "
                f"Interpréteur actif: {sys.executable}. "
                f"Erreur d'import: {twofish_error}. "
                "Installez avec cet interpréteur: "
                f"{sys.executable} -m pip install twofish"
            )
        matrix = [entry for entry in EXPERIMENT_MATRIX if entry[0] != "Twofish"]

    scheduled_algorithms = sorted({entry[0] for entry in matrix})
    print("[info] Algorithms scheduled: " + ", ".join(scheduled_algorithms))

    for algo, primitive_cls, mode_label, mode_cls, key_sizes in matrix:
        for key_size in key_sizes:
            planned_for_key = len(MESSAGE_SIZES)
            run_stats[algo]["planned"] += planned_for_key

            # Vérification préalable : peut-on instancier cette primitive ?
            try:
                _probe_key = _make_key(key_size)
                _probe = primitive_cls(_probe_key)
            except Exception as exc:  # noqa: BLE001
                print(f"  SKIPPED {algo} (key={key_size*8}bit) — {exc}")
                run_stats[algo]["skipped"] += planned_for_key
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
                    run_stats[algo]["success"] += 1
                    print(
                        f"enc={result.avg_encrypt_time_s*1000:.3f}ms "
                        f"thr={result.throughput_encrypt_mbps:.2f}MB/s "
                        f"avalanche={result.avalanche_score:.3f}"
                    )

                except Exception as exc:  # noqa: BLE001
                    run_stats[algo]["skipped"] += 1
                    print(f"  SKIPPED {algo}-{mode_label} key={key_size*8}bit msg={msg_size}B — {exc}")

    all_algorithms_ok = _print_run_summary(run_stats)

    if not results:
        print("No results collected.")
        return 1

    out_path = _output_path()
    fieldnames = list(asdict(results[0]).keys())
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))

    print(f"\nResults saved to: {out_path}")
    if not all_algorithms_ok:
        print("[error] Experiment completed with missing algorithms. Exiting with status 1.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
