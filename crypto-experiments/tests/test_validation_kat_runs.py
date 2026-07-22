from validation import (
    kat_3des,
    kat_aes,
    kat_chacha20,
    kat_des,
    kat_gcm,
    kat_modes,
    kat_twofish,
)


def test_kat_aes_run_passes():
    assert kat_aes.run(verbose=True) == 0
    assert kat_aes.run(verbose=False) == 0


def test_kat_des_run_passes():
    assert kat_des.run(verbose=True) == 0
    assert kat_des.run(verbose=False) == 0


def test_kat_3des_run_passes():
    assert kat_3des.run(verbose=True) == 0
    assert kat_3des.run(verbose=False) == 0


def test_kat_modes_run_passes():
    assert kat_modes.run(verbose=True) == 0
    assert kat_modes.run(verbose=False) == 0


def test_kat_gcm_run_passes():
    assert kat_gcm.run(verbose=True) == 0
    assert kat_gcm.run(verbose=False) == 0


def test_kat_chacha20_run_passes():
    assert kat_chacha20.run(verbose=True) == 0
    assert kat_chacha20.run(verbose=False) == 0


def test_kat_twofish_run_passes():
    assert kat_twofish.run(verbose=True) == 0
    assert kat_twofish.run(verbose=False) == 0
    stats = kat_twofish.get_last_stats()
    assert stats
