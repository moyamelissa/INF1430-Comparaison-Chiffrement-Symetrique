"""
kat_twofish.py
Tests a reponse connue (KAT) pour la primitive Twofish.

Sources
-------
* Vecteurs publics Twofish KAT (Bruce Schneier / Counterpane)
  - ECB_VK.TXT : variable key
  - ECB_VT.TXT : variable text
  - ECB_TBL.TXT : table checks

Les fichiers sont lus depuis Resources/KAT/Twofish-kat.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from domain.cipher.Twofish import Twofish


_HEX_LINE_RE = re.compile(r"^(KEY|PT|CT)\s*=\s*([0-9A-Fa-f]+)$")
_LAST_STATS: list[dict[str, int | str]] = []


def _resources_dir() -> Path:
    # validation/kat_twofish.py -> crypto-experiments -> repository root
    return Path(__file__).resolve().parents[2] / "Resources" / "KAT" / "Twofish-kat"


def _resolve_vector_file(*names: str) -> Path:
    base = _resources_dir()
    for name in names:
        candidate = base / name
        if candidate.exists():
            return candidate

    # Tolerate alternate names such as "ECB_VK (2).TXT".
    stem = Path(names[0]).stem
    wildcard_matches = sorted(base.glob(f"{stem}*.TXT"))
    if wildcard_matches:
        return wildcard_matches[0]

    raise FileNotFoundError(f"Twofish KAT file not found for {names[0]} in {base}")


def _parse_ecb_vectors(path: Path) -> list[tuple[bytes, bytes, bytes]]:
    vectors: list[tuple[bytes, bytes, bytes]] = []
    defaults: dict[str, str] = {}
    record: dict[str, str] = {}
    in_record = False

    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";"):
            continue

        if line.startswith("KEYSIZE="):
            # New key-size section may redefine defaults.
            defaults = {}
            record = {}
            in_record = False
            continue

        if line.startswith("I="):
            in_record = True
            record = {}
            continue

        match = _HEX_LINE_RE.match(line)
        if not match:
            continue

        field, value = match.group(1), match.group(2)
        if in_record:
            record[field] = value
            if field == "CT":
                key_hex = record.get("KEY") or defaults.get("KEY")
                pt_hex = record.get("PT") or defaults.get("PT")
                ct_hex = record.get("CT")
                if key_hex and pt_hex and ct_hex:
                    vectors.append((bytes.fromhex(key_hex), bytes.fromhex(pt_hex), bytes.fromhex(ct_hex)))
        else:
            if field in ("KEY", "PT"):
                defaults[field] = value

    return vectors


def _run_file(label: str, path: Path, verbose: bool) -> tuple[int, int, int]:
    failures = 0
    vectors = _parse_ecb_vectors(path)
    assertions = len(vectors) * 2
    if verbose:
        print(f"  [INFO] {label}: {len(vectors)} vecteur(s) charges depuis {path.name}")

    for idx, (key, plain, expected_cipher) in enumerate(vectors, start=1):
        tf = Twofish(key)
        got_cipher = tf.encrypt_block(plain)

        ok_enc = got_cipher == expected_cipher
        if not ok_enc:
            failures += 1
        if verbose:
            status = "PASS" if ok_enc else "FAIL"
            print(f"  [{status}] {label} #{idx} encrypt")
            if not ok_enc:
                print(f"         expected: {expected_cipher.hex()}")
                print(f"         got:      {got_cipher.hex()}")

        got_plain = tf.decrypt_block(expected_cipher)
        ok_dec = got_plain == plain
        if not ok_dec:
            failures += 1
        if verbose:
            status = "PASS" if ok_dec else "FAIL"
            print(f"  [{status}] {label} #{idx} decrypt round-trip")
            if not ok_dec:
                print(f"         expected: {plain.hex()}")
                print(f"         got:      {got_plain.hex()}")

    return failures, len(vectors), assertions


def get_last_stats() -> list[dict[str, int | str]]:
    """Retourne les statistiques de la derniere execution de run()."""
    return list(_LAST_STATS)


def run(verbose: bool = True) -> int:
    """Execute les vecteurs KAT Twofish ECB. Retourne le nombre d'echecs."""
    global _LAST_STATS
    _LAST_STATS = []

    failures = 0

    try:
        vk_path = _resolve_vector_file("ECB_VK.TXT", "ECB_VK (2).TXT")
        vt_path = _resolve_vector_file("ECB_VT.TXT", "ECB_VT (2).TXT")
        tbl_path = _resolve_vector_file("ECB_TBL.TXT", "ECB_TBL (2).TXT")
    except FileNotFoundError as exc:
        if verbose:
            print(f"  [FAIL] Twofish vectors missing: {exc}")
        return 1

    for label, path in (
        ("Twofish ECB_VK", vk_path),
        ("Twofish ECB_VT", vt_path),
        ("Twofish ECB_TBL", tbl_path),
    ):
        file_failures, vectors, assertions = _run_file(label, path, verbose)
        failures += file_failures
        _LAST_STATS.append(
            {
                "label": label,
                "vectors": vectors,
                "assertions": assertions,
                "failures": file_failures,
            }
        )

    return failures
