import importlib

import pytest

experiment_module = importlib.import_module("application.ExperimentController")
from application.ExperimentController import ExperimentController, ExperimentResult
from domain.cipher.CipherPrimitive import CipherPrimitive
from domain.engine import EncryptionEngine
from domain.mode.OperationMode import OperationMode


class ToyPrimitive(CipherPrimitive):
    def __init__(self, key: bytes) -> None:
        self._key = key

    @property
    def block_size(self) -> int:
        return 4

    @property
    def key_size(self) -> int:
        return len(self._key)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError("bad block")
        return bytes(block[i] ^ self._key[i % len(self._key)] for i in range(self.block_size))

    def decrypt_block(self, block: bytes) -> bytes:
        return self.encrypt_block(block)


class ToyMode(OperationMode):
    def encrypt(self, plaintext: bytes, **kwargs) -> bytes:
        return self._primitive.encrypt_blocks(plaintext)

    def decrypt(self, ciphertext: bytes, **kwargs) -> bytes:
        return self._primitive.decrypt_blocks(ciphertext)


class UnstablePrimitive(ToyPrimitive):
    def __init__(self, key: bytes) -> None:
        if key[:1] == b"\x01":
            raise ValueError("degenerate key")
        super().__init__(key)


def _make_controller(primitive_cls: type[ToyPrimitive] = ToyPrimitive) -> ExperimentController:
    primitive = primitive_cls(bytes([0, 1, 2, 3]))
    mode = ToyMode(primitive)
    engine = EncryptionEngine(primitive, mode)
    return ExperimentController(engine, "TOY", "MODE")


def test_run_performance_returns_result(monkeypatch):
    controller = _make_controller()
    perf_values = iter([0.0, 0.1, 0.2, 0.35, 0.5, 0.7, 0.9, 1.15])

    monkeypatch.setattr(experiment_module.time, "perf_counter", lambda: next(perf_values))
    monkeypatch.setattr(controller, "measure_avalanche", lambda trials=200: 0.5)
    monkeypatch.setattr(controller, "measure_key_avalanche", lambda trials=200: 0.5)

    result = controller.run_performance(message_size_bytes=4, repetitions=2)

    assert isinstance(result, ExperimentResult)
    assert result.algorithm == "TOY"
    assert result.mode == "MODE"
    assert result.repetitions == 2
    assert result.throughput_encrypt_mbps > 0
    assert result.throughput_decrypt_mbps > 0
    assert result.ci95_encrypt_mbps > 0
    assert result.ci95_decrypt_mbps > 0


def test_run_performance_zero_timing_returns_zero_metrics(monkeypatch):
    controller = _make_controller()
    perf_values = iter([1.0] * 8)

    monkeypatch.setattr(experiment_module.time, "perf_counter", lambda: next(perf_values))
    monkeypatch.setattr(controller, "measure_avalanche", lambda trials=200: 0.25)
    monkeypatch.setattr(controller, "measure_key_avalanche", lambda trials=200: 0.75)

    result = controller.run_performance(message_size_bytes=4, repetitions=2)

    assert result.throughput_encrypt_mbps == 0.0
    assert result.throughput_decrypt_mbps == 0.0
    assert result.ci95_encrypt_mbps == 0.0
    assert result.ci95_decrypt_mbps == 0.0


def test_measure_avalanche_range(monkeypatch):
    controller = _make_controller()
    values = iter([0, 0, 1, 1] * 20)

    monkeypatch.setattr(experiment_module.os, "urandom", lambda n: b"\x00" * n)
    monkeypatch.setattr(experiment_module.secrets, "randbelow", lambda n: next(values))

    score = controller.measure_avalanche(trials=4)

    assert 0.0 <= score <= 1.0


def test_measure_key_avalanche_handles_modified_key_failure(monkeypatch):
    controller = _make_controller(UnstablePrimitive)
    values = iter([0, 0] * 10)

    monkeypatch.setattr(experiment_module.os, "urandom", lambda n: b"\x00" * n)
    monkeypatch.setattr(experiment_module.secrets, "randbelow", lambda n: next(values))

    score = controller.measure_key_avalanche(trials=1)

    assert score == 0.5


def test_measure_key_avalanche_normal_path(monkeypatch):
    controller = _make_controller()
    values = iter([0, 0] * 20)

    monkeypatch.setattr(experiment_module.os, "urandom", lambda n: b"\x00" * n)
    monkeypatch.setattr(experiment_module.secrets, "randbelow", lambda n: next(values))

    score = controller.measure_key_avalanche(trials=2)

    assert 0.0 <= score <= 1.0


def test_normalize_avalanche_ciphertext_keeps_block_sized_output():
    controller = _make_controller()

    ciphertext = b"\xAA\xBB\xCC\xDD"

    normalized = controller._normalize_avalanche_ciphertext(ciphertext, block_size=4)

    assert normalized == ciphertext


def test_normalize_avalanche_ciphertext_strips_12_byte_prefix():
    controller = _make_controller()

    payload = b"\x10\x20\x30\x40"
    prefixed = (b"\x00" * 12) + payload

    normalized = controller._normalize_avalanche_ciphertext(prefixed, block_size=4)

    assert normalized == payload


def test_normalize_avalanche_ciphertext_keeps_unexpected_length():
    controller = _make_controller()

    ciphertext = b"\x01\x02\x03\x04\x05"

    normalized = controller._normalize_avalanche_ciphertext(ciphertext, block_size=4)

    assert normalized == ciphertext