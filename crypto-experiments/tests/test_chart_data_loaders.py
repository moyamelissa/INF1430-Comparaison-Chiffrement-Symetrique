from pathlib import Path
import sys


ROOT_DIR = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT_DIR / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


def _write_csv(path: Path, header: str, rows: list[str]) -> None:
    path.write_text(header + "\n" + "\n".join(rows) + "\n", encoding="utf-8")


def test_data_performance_load_latest_rows_averages_and_handles_bom(monkeypatch, tmp_path):
    from charts import data_performance as dp

    header_bom = (
        '"algorithm","mode","key_size_bytes","message_size_bytes","repetitions",'
        '"avg_encrypt_time_s","avg_decrypt_time_s","throughput_encrypt_mbps",'
        '"throughput_decrypt_mbps","avalanche_score","key_avalanche_score"'
    )
    header_std = (
        'algorithm,mode,key_size_bytes,message_size_bytes,repetitions,'
        'avg_encrypt_time_s,avg_decrypt_time_s,throughput_encrypt_mbps,'
        'throughput_decrypt_mbps,avalanche_score,key_avalanche_score'
    )

    # key_avalanche_score manquant dans un fichier ("{}") : ne doit pas casser.
    rows_1 = [
        '"AES","ECB","16","64","100","1.0","2.0","10.0","20.0","0.50","{}"'
    ]
    rows_2 = [
        'AES,ECB,16,64,100,3.0,4.0,30.0,40.0,0.70,0.90'
    ]

    _write_csv(tmp_path / "laptop-windows-x86_experience1_20260717.csv", header_bom, rows_1)
    _write_csv(tmp_path / "laptop-windows-x86_experience2_20260717.csv", header_std, rows_2)
    # Legacy name: should be ignored by strict loader
    _write_csv(tmp_path / "experiment_windows-x86-64_20260717.csv", header_std, rows_2)
    _write_csv(tmp_path / "raspberry-pi_experience1_20260717.csv", header_std, rows_2)

    monkeypatch.setattr(dp, "RESULTS_DIR", tmp_path)
    paths, rows = dp.load_latest_rows()

    assert len(paths) == 2
    assert len(rows) == 1
    row = rows[0]
    assert row["algorithm"] == "AES"
    assert row["mode"] == "ECB"
    assert row["throughput_enc_mbps"] == 20.0
    assert row["throughput_dec_mbps"] == 30.0
    # Avalanche texte moyen (0.50 + 0.70) / 2
    assert row["avalanche_score"] == 0.6
    # key_avalanche: une valeur invalide ignorée, la valeur valide est conservée
    assert row["key_avalanche_score"] == 0.9


def test_data_platform_load_platform_rows_averages_both_platforms(monkeypatch, tmp_path):
    from charts import data_platform as dplat

    header = (
        'algorithm,mode,key_size_bytes,message_size_bytes,repetitions,'
        'avg_encrypt_time_s,avg_decrypt_time_s,throughput_encrypt_mbps,'
        'throughput_decrypt_mbps,avalanche_score,key_avalanche_score,ci95_encrypt_mbps'
    )
    x86_r1 = ['AES,ECB,16,64,100,1.0,2.0,10.0,20.0,0.50,0.60,1.0']
    x86_r2 = ['AES,ECB,16,64,100,1.0,2.0,30.0,40.0,0.70,0.80,3.0']
    pi_r1 = ['AES,ECB,16,64,100,1.0,2.0,5.0,10.0,0.40,0.50,0.5']
    pi_r2 = ['AES,ECB,16,64,100,1.0,2.0,15.0,20.0,0.60,0.70,1.5']

    _write_csv(tmp_path / "laptop-windows-x86_experience1_20260717.csv", header, x86_r1)
    _write_csv(tmp_path / "laptop-windows-x86_experience2_20260717.csv", header, x86_r2)
    _write_csv(tmp_path / "raspberry-pi_experience1_20260717.csv", header, pi_r1)
    _write_csv(tmp_path / "raspberry-pi_experience2_20260717.csv", header, pi_r2)
    # Legacy names should not be picked anymore.
    _write_csv(tmp_path / "experiment_windows-x86-64_20260717.csv", header, x86_r1)
    _write_csv(tmp_path / "experiment_raspberry-pi_20260717.csv", header, pi_r1)

    monkeypatch.setattr(dplat, "RESULTS_DIR", tmp_path)
    x86_paths, pi_paths, x86_rows, pi_rows = dplat.load_platform_rows()

    assert len(x86_paths) == 2
    assert len(pi_paths) == 2
    assert len(x86_rows) == 1
    assert len(pi_rows) == 1

    xr = x86_rows[0]
    pr = pi_rows[0]
    assert xr["throughput_enc"] == 20.0
    assert xr["throughput_dec"] == 30.0
    assert xr["avalanche"] == 0.6
    assert xr["key_avalanche"] == 0.7
    assert xr["ci95_enc"] == 2.0

    assert pr["throughput_enc"] == 10.0
    assert pr["throughput_dec"] == 15.0
    assert pr["avalanche"] == 0.5
    assert pr["key_avalanche"] == 0.6
    assert pr["ci95_enc"] == 1.0

