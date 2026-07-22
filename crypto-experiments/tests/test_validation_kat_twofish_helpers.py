from __future__ import annotations

from pathlib import Path

import pytest

from validation import kat_twofish


V1 = (
    "9F589F5CF6122C32B6BFEC2F2AE8C35A",
    "D491DB16E7B1C39E86CB086B789F5419",
    "019F9809DE1711858FAAC3A3BA20FBC3",
)
V2 = (
    "88B2B2706B105E36B446BB6D731A1E88EFA71F788965BD44",
    "39DA69D6BA4997D585B6DC073CA341B2",
    "182B02D81497EA45F9DAACDC29193A65",
)
V3 = (
    "D43BB7556EA32E46F2A282B7D45B4E0D57FF739D4DC92C1BD7FC01700CC8216F",
    "90AFE91BB288544F2C32DC239B2635E6",
    "6CB4561C40BF0A9705931CB6D408E7FA",
)


def _write_vector_file(path: Path, vector: tuple[str, str, str]) -> None:
    key_hex, pt_hex, ct_hex = vector
    path.write_text(
        "\n".join(
            [
                "; sample Twofish vector file",
                "KEYSIZE=128",
                f"KEY={key_hex}",
                f"PT={pt_hex}",
                "I=1",
                f"CT={ct_hex}",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _write_sha256_sidecar(path: Path) -> None:
    digest = kat_twofish._sha256_hex(path)
    path.with_suffix(path.suffix + ".sha256").write_text(
        f"{digest}  {path.name}\n",
        encoding="utf-8",
    )


def test_resolve_parse_run_file_and_profile(tmp_path: Path, monkeypatch):
    base = tmp_path / "Twofish-kat"
    base.mkdir(parents=True, exist_ok=True)

    vk = base / "ECB_VK.TXT"
    vt = base / "ECB_VT (2).TXT"
    tbl = base / "ECB_TBL_ALT.TXT"

    _write_vector_file(vk, V1)
    _write_vector_file(vt, V2)
    _write_vector_file(tbl, V3)

    monkeypatch.setattr(kat_twofish, "_resources_dir", lambda: base)

    resolved_vk = kat_twofish._resolve_vector_file("ECB_VK.TXT", "ECB_VK (2).TXT")
    assert resolved_vk == vk

    # Exact alternative name supported by argument list.
    resolved_vt = kat_twofish._resolve_vector_file("ECB_VT.TXT", "ECB_VT (2).TXT")
    assert resolved_vt == vt

    # Wildcard fallback when named variants are missing.
    resolved_tbl = kat_twofish._resolve_vector_file("ECB_TBL.TXT")
    assert resolved_tbl == tbl

    vectors = kat_twofish._parse_ecb_vectors(vk)
    assert len(vectors) == 1

    failures, count, assertions = kat_twofish._run_file("Twofish ECB_VK", vk, verbose=True)
    assert failures == 0
    assert count == 1
    assert assertions == 2

    all_vectors = {
        "Twofish ECB_VK": vectors,
        "Twofish ECB_VT": kat_twofish._parse_ecb_vectors(vt),
        "Twofish ECB_TBL": kat_twofish._parse_ecb_vectors(tbl),
    }
    assert kat_twofish._apply_profile_subset(all_vectors, "full") == all_vectors
    core_subset = kat_twofish._apply_profile_subset(all_vectors, "core")
    assert all(len(v) == 1 for v in core_subset.values())


def test_parse_tolerates_unknown_lines(tmp_path: Path):
    path = tmp_path / "ECB_VK.TXT"
    path.write_text(
        "\n".join(
            [
                "KEYSIZE=128",
                "FOO=BAR",
                f"KEY={V1[0]}",
                f"PT={V1[1]}",
                "I=1",
                f"CT={V1[2]}",
            ]
        ),
        encoding="utf-8",
    )

    vectors = kat_twofish._parse_ecb_vectors(path)
    assert len(vectors) == 1


def test_parse_record_lines_with_key_pt_inside_record(tmp_path: Path):
    path = tmp_path / "ECB_VT.TXT"
    path.write_text(
        "\n".join(
            [
                "KEYSIZE=128",
                "I=1",
                f"KEY={V1[0]}",
                f"PT={V1[1]}",
                f"CT={V1[2]}",
                "I=2",
                "KEY=",  # malformed, ignored by regex
                "PT=",   # malformed, ignored by regex
                f"CT={V1[2]}",
            ]
        ),
        encoding="utf-8",
    )
    vectors = kat_twofish._parse_ecb_vectors(path)
    assert vectors


def test_parse_ct_outside_record_is_ignored(tmp_path: Path):
    path = tmp_path / "ECB_MISC.TXT"
    path.write_text(
        "\n".join(
            [
                "KEYSIZE=128",
                f"KEY={V1[0]}",
                f"PT={V1[1]}",
                f"CT={V1[2]}",  # Outside I= record, should be ignored for vectors
                "I=1",
                f"CT={V1[2]}",
            ]
        ),
        encoding="utf-8",
    )
    vectors = kat_twofish._parse_ecb_vectors(path)
    assert len(vectors) == 1


def test_resolve_missing_raises(tmp_path: Path, monkeypatch):
    base = tmp_path / "Twofish-kat"
    base.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(kat_twofish, "_resources_dir", lambda: base)

    with pytest.raises(FileNotFoundError):
        kat_twofish._resolve_vector_file("ECB_VK.TXT")


class _BadTwofish:
    def __init__(self, _key: bytes):
        pass

    def encrypt_block(self, _block: bytes) -> bytes:
        return b"\x00" * 16

    def decrypt_block(self, _block: bytes) -> bytes:
        return b"\x00" * 16


def test_run_vectors_failure_branch(monkeypatch):
    monkeypatch.setattr(kat_twofish, "Twofish", _BadTwofish)

    vectors = [
        (bytes.fromhex(V1[0]), bytes.fromhex(V1[1]), bytes.fromhex(V1[2])),
    ]
    failures, count, assertions = kat_twofish._run_vectors(
        "Twofish ECB_VK",
        vectors,
        "embedded",
        verbose=True,
    )
    assert failures > 0
    assert count == 1
    assert assertions == 2


def test_run_file_failure_branch(tmp_path: Path, monkeypatch):
    path = tmp_path / "ECB_VK.TXT"
    _write_vector_file(path, V1)

    monkeypatch.setattr(kat_twofish, "Twofish", _BadTwofish)
    failures, count, assertions = kat_twofish._run_file("Twofish ECB_VK", path, verbose=True)
    assert failures > 0
    assert count == 1
    assert assertions == 2


def test_run_file_success_silent(tmp_path: Path):
    path = tmp_path / "ECB_VK.TXT"
    _write_vector_file(path, V1)

    failures, count, assertions = kat_twofish._run_file("Twofish ECB_VK", path, verbose=False)
    assert failures == 0
    assert count == 1
    assert assertions == 2


def test_run_with_real_files_and_profile_variants(tmp_path: Path, monkeypatch):
    base = tmp_path / "Twofish-kat"
    base.mkdir(parents=True, exist_ok=True)

    _write_vector_file(base / "ECB_VK.TXT", V1)
    _write_vector_file(base / "ECB_VT.TXT", V2)
    _write_vector_file(base / "ECB_TBL.TXT", V3)

    monkeypatch.setattr(kat_twofish, "_resources_dir", lambda: base)
    _write_sha256_sidecar(base / "ECB_VK.TXT")
    _write_sha256_sidecar(base / "ECB_VT.TXT")
    _write_sha256_sidecar(base / "ECB_TBL.TXT")

    monkeypatch.setenv("TWOFISH_KAT_PROFILE", "full")
    assert kat_twofish.run(verbose=True) == 0
    stats_full = kat_twofish.get_last_stats()
    assert stats_full and all(str(item["profile"]) == "full" for item in stats_full)

    monkeypatch.setenv("TWOFISH_KAT_PROFILE", "invalid-profile")
    assert kat_twofish.run(verbose=True) == 0
    stats_core = kat_twofish.get_last_stats()
    assert stats_core and all(str(item["profile"]) == "core" for item in stats_core)


def test_run_with_missing_vectors_verbose_false(monkeypatch):
    missing_base = Path("this/path/does/not/exist")
    monkeypatch.setattr(kat_twofish, "_resources_dir", lambda: missing_base)
    assert kat_twofish.run(verbose=False) == 0


def test_run_with_missing_vectors_verbose_true(monkeypatch):
    missing_base = Path("this/path/does/not/exist")
    monkeypatch.setattr(kat_twofish, "_resources_dir", lambda: missing_base)
    assert kat_twofish.run(verbose=True) == 0


def test_run_with_missing_vectors_strict_mode_fails(monkeypatch):
    missing_base = Path("this/path/does/not/exist")
    monkeypatch.setattr(kat_twofish, "_resources_dir", lambda: missing_base)
    monkeypatch.setenv("TWOFISH_KAT_ALLOW_FALLBACK", "0")
    assert kat_twofish.run(verbose=False) == 1
    stats = kat_twofish.get_last_stats()
    assert stats and str(stats[0]["profile"]) == "strict-missing"


def test_run_with_missing_vectors_strict_mode_verbose(monkeypatch):
    missing_base = Path("this/path/does/not/exist")
    monkeypatch.setattr(kat_twofish, "_resources_dir", lambda: missing_base)
    monkeypatch.setenv("TWOFISH_KAT_ALLOW_FALLBACK", "0")
    assert kat_twofish.run(verbose=True) == 1


def test_run_with_real_files_verbose_false(tmp_path: Path, monkeypatch):
    base = tmp_path / "Twofish-kat"
    base.mkdir(parents=True, exist_ok=True)
    _write_vector_file(base / "ECB_VK.TXT", V1)
    _write_vector_file(base / "ECB_VT.TXT", V2)
    _write_vector_file(base / "ECB_TBL.TXT", V3)
    _write_sha256_sidecar(base / "ECB_VK.TXT")
    _write_sha256_sidecar(base / "ECB_VT.TXT")
    _write_sha256_sidecar(base / "ECB_TBL.TXT")
    monkeypatch.setattr(kat_twofish, "_resources_dir", lambda: base)
    monkeypatch.setenv("TWOFISH_KAT_PROFILE", "full")
    assert kat_twofish.run(verbose=False) == 0


def test_run_backend_unavailable_soft_skip(monkeypatch):
    class _BrokenTwofish:
        def __init__(self, _key: bytes):
            raise ImportError("backend init failed")

    monkeypatch.setattr(kat_twofish, "Twofish", _BrokenTwofish)
    assert kat_twofish.run(verbose=True) == 0
    stats = kat_twofish.get_last_stats()
    assert stats
    assert all(str(item["profile"]) == "backend-unavailable" for item in stats)
    assert all(int(item["failures"]) == 0 for item in stats)


def test_run_backend_unavailable_soft_skip_silent(monkeypatch):
    class _BrokenTwofish:
        def __init__(self, _key: bytes):
            raise ImportError("backend init failed")

    monkeypatch.setattr(kat_twofish, "Twofish", _BrokenTwofish)
    assert kat_twofish.run(verbose=False) == 0


def test_checksum_mode_invalid_defaults_to_warn(monkeypatch):
    monkeypatch.setenv("TWOFISH_KAT_CHECKSUM", "invalid")
    assert kat_twofish._checksum_mode() == "warn"


def test_verify_vector_integrity_off(tmp_path: Path, monkeypatch):
    path = tmp_path / "ECB_VK.TXT"
    _write_vector_file(path, V1)
    monkeypatch.setenv("TWOFISH_KAT_CHECKSUM", "off")
    assert kat_twofish._verify_vector_integrity([path], verbose=True) == 0


def test_verify_vector_integrity_warn_missing_sidecar(tmp_path: Path, monkeypatch):
    path = tmp_path / "ECB_VK.TXT"
    _write_vector_file(path, V1)
    monkeypatch.setenv("TWOFISH_KAT_CHECKSUM", "warn")
    assert kat_twofish._verify_vector_integrity([path], verbose=True) == 0


def test_verify_vector_integrity_warn_missing_sidecar_silent(tmp_path: Path, monkeypatch):
    path = tmp_path / "ECB_VK.TXT"
    _write_vector_file(path, V1)
    monkeypatch.setenv("TWOFISH_KAT_CHECKSUM", "warn")
    assert kat_twofish._verify_vector_integrity([path], verbose=False) == 0


def test_verify_vector_integrity_enforce_missing_sidecar(tmp_path: Path, monkeypatch):
    path = tmp_path / "ECB_VK.TXT"
    _write_vector_file(path, V1)
    monkeypatch.setenv("TWOFISH_KAT_CHECKSUM", "enforce")
    assert kat_twofish._verify_vector_integrity([path], verbose=True) == 1


def test_verify_vector_integrity_enforce_missing_sidecar_silent(tmp_path: Path, monkeypatch):
    path = tmp_path / "ECB_VK.TXT"
    _write_vector_file(path, V1)
    monkeypatch.setenv("TWOFISH_KAT_CHECKSUM", "enforce")
    assert kat_twofish._verify_vector_integrity([path], verbose=False) == 1


def test_verify_vector_integrity_enforce_bad_hash(tmp_path: Path, monkeypatch):
    path = tmp_path / "ECB_VK.TXT"
    _write_vector_file(path, V1)
    sidecar = path.with_suffix(path.suffix + ".sha256")
    sidecar.write_text("0" * 64 + "  ECB_VK.TXT\n", encoding="utf-8")
    monkeypatch.setenv("TWOFISH_KAT_CHECKSUM", "enforce")
    assert kat_twofish._verify_vector_integrity([path], verbose=True) == 1


def test_verify_vector_integrity_enforce_ok_hash(tmp_path: Path, monkeypatch):
    path = tmp_path / "ECB_VK.TXT"
    _write_vector_file(path, V1)
    _write_sha256_sidecar(path)
    monkeypatch.setenv("TWOFISH_KAT_CHECKSUM", "enforce")
    assert kat_twofish._verify_vector_integrity([path], verbose=True) == 0


def test_read_expected_sha256_missing_or_invalid(tmp_path: Path):
    sidecar = tmp_path / "ECB_VK.TXT.sha256"
    assert kat_twofish._read_expected_sha256(sidecar) is None
    sidecar.write_text("\n", encoding="utf-8")
    assert kat_twofish._read_expected_sha256(sidecar) is None
    sidecar.write_text("not-a-hash\n", encoding="utf-8")
    assert kat_twofish._read_expected_sha256(sidecar) is None


def test_run_integrity_failure_is_reported(tmp_path: Path, monkeypatch):
    base = tmp_path / "Twofish-kat"
    base.mkdir(parents=True, exist_ok=True)
    _write_vector_file(base / "ECB_VK.TXT", V1)
    _write_vector_file(base / "ECB_VT.TXT", V2)
    _write_vector_file(base / "ECB_TBL.TXT", V3)

    # Deliberately wrong checksums to force integrity failure in run().
    bad = "0" * 64 + "  bad\n"
    (base / "ECB_VK.TXT.sha256").write_text(bad, encoding="utf-8")
    (base / "ECB_VT.TXT.sha256").write_text(bad, encoding="utf-8")
    (base / "ECB_TBL.TXT.sha256").write_text(bad, encoding="utf-8")

    monkeypatch.setattr(kat_twofish, "_resources_dir", lambda: base)
    monkeypatch.setenv("TWOFISH_KAT_CHECKSUM", "enforce")
    assert kat_twofish.run(verbose=False) > 0
    stats = kat_twofish.get_last_stats()
    assert stats and str(stats[0]["profile"]).startswith("integrity-")


def test_run_vectors_empty_fails():
    failures, count, assertions = kat_twofish._run_vectors(
        "Twofish ECB_VK",
        [],
        "source-name",
        verbose=False,
    )
    assert failures == 1
    assert count == 0
    assert assertions == 0


def test_run_vectors_empty_verbose_fails():
    failures, count, assertions = kat_twofish._run_vectors(
        "Twofish ECB_VK",
        [],
        "source-name",
        verbose=True,
    )
    assert failures == 1
    assert count == 0
    assert assertions == 0


def test_run_file_empty_fails(tmp_path: Path):
    path = tmp_path / "EMPTY.TXT"
    path.write_text("KEYSIZE=128\n", encoding="utf-8")
    failures, count, assertions = kat_twofish._run_file("Twofish empty", path, verbose=False)
    assert failures == 1
    assert count == 0
    assert assertions == 0


def test_run_file_empty_verbose_fails(tmp_path: Path):
    path = tmp_path / "EMPTY.TXT"
    path.write_text("KEYSIZE=128\n", encoding="utf-8")
    failures, count, assertions = kat_twofish._run_file("Twofish empty", path, verbose=True)
    assert failures == 1
    assert count == 0
    assert assertions == 0
