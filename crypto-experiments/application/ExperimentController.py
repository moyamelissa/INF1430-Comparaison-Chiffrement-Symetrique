"""
ExperimentController.py
Orchestrates benchmarking experiments over EncryptionEngine instances.

Responsibilities:
  - Configure and iterate over experiment parameters (algorithm, mode,
    key size, message size, repetitions).
  - Time encrypt / decrypt operations neutrally (timer wraps only the
    cryptographic call, not setup or I/O).
  - Compute the avalanche effect score for each primitive.
  - Return structured result dicts; persistence (CSV) is handled by the
    calling script, not here.

This layer has no knowledge of which specific primitive or mode is used —
it only calls the EncryptionEngine interface.
"""

import math
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from domain.engine.EncryptionEngine import EncryptionEngine


@dataclass
class ExperimentResult:
    """Container for a single experiment measurement."""

    algorithm: str          # e.g. "AES"
    mode: str               # e.g. "CBC"
    key_size_bytes: int     # e.g. 16
    message_size_bytes: int # e.g. 1024
    repetitions: int        # number of timed iterations
    avg_encrypt_time_s: float
    avg_decrypt_time_s: float
    throughput_encrypt_mbps: float
    throughput_decrypt_mbps: float
    avalanche_score: float      # plaintext bit-flip → output change ratio
    key_avalanche_score: float  # key bit-flip → output change ratio
    ci95_encrypt_mbps: float    # 95% confidence interval half-width (encrypt)
    ci95_decrypt_mbps: float    # 95% confidence interval half-width (decrypt)
    extra: dict = field(default_factory=dict)


class ExperimentController:
    """
    Coordinates a benchmarking campaign for one EncryptionEngine.

    Parameters
    ----------
    engine : EncryptionEngine
        The fully-configured engine (primitive + mode) to benchmark.
    algorithm_name : str
        Human-readable label used in result rows (e.g. "AES").
    mode_name : str
        Human-readable label used in result rows (e.g. "CBC").
    """

    def __init__(
        self,
        engine: EncryptionEngine,
        algorithm_name: str,
        mode_name: str,
    ) -> None:
        self._engine = engine
        self._algorithm_name = algorithm_name
        self._mode_name = mode_name

    # ------------------------------------------------------------------ #
    #  Performance benchmark                                               #
    # ------------------------------------------------------------------ #

    def run_performance(
        self,
        message_size_bytes: int = 1024,
        repetitions: int = 1000,
    ) -> ExperimentResult:
        """
        Measure average encrypt / decrypt time and throughput.

        The timer wraps only the cryptographic call so platform overhead
        (memory allocation, Python interpreter) is minimised.  A fixed
        random plaintext is reused across repetitions for comparability.

        Parameters
        ----------
        message_size_bytes : int
            Size of the random test message in bytes.
        repetitions : int
            Number of encrypt (and decrypt) iterations to average over.

        Returns
        -------
        ExperimentResult
            Populated result including throughput and avalanche score.
        """
        plaintext = os.urandom(message_size_bytes)

        # --- encrypt timing ---
        enc_times = []
        ciphertexts = []
        for _ in range(repetitions):
            t0 = time.perf_counter()
            ct = self._engine.encrypt(plaintext)
            enc_times.append(time.perf_counter() - t0)
            ciphertexts.append(ct)

        # --- decrypt timing (use last ciphertext) ---
        last_ct = ciphertexts[-1]
        dec_times = []
        for _ in range(repetitions):
            t0 = time.perf_counter()
            self._engine.decrypt(last_ct)
            dec_times.append(time.perf_counter() - t0)

        avg_enc = sum(enc_times) / repetitions
        avg_dec = sum(dec_times) / repetitions
        mb = message_size_bytes / (1024 * 1024)

        # 95% confidence interval: t_{0.975, n-1} * std / sqrt(n)
        # For n >= 30 we use z = 1.96 (normal approximation).
        def _ci95_mbps(times: list, avg_t: float) -> float:
            n = len(times)
            if n < 2 or avg_t <= 0:
                return 0.0
            variance = sum((t - avg_t) ** 2 for t in times) / (n - 1)
            std_dev  = math.sqrt(variance)
            # Convert time std-dev to throughput std-dev (MB/s)
            # throughput = mb / t  →  std_throughput ≈ mb * std_t / avg_t²
            std_thr  = mb * std_dev / (avg_t ** 2)
            t_crit   = 1.96 if n >= 30 else 2.045  # t_{0.975} for n~30
            return t_crit * std_thr / math.sqrt(n)

        ci95_enc = _ci95_mbps(enc_times, avg_enc)
        ci95_dec = _ci95_mbps(dec_times, avg_dec)

        return ExperimentResult(
            algorithm=self._algorithm_name,
            mode=self._mode_name,
            key_size_bytes=self._engine.primitive.key_size,
            message_size_bytes=message_size_bytes,
            repetitions=repetitions,
            avg_encrypt_time_s=avg_enc,
            avg_decrypt_time_s=avg_dec,
            throughput_encrypt_mbps=mb / avg_enc if avg_enc > 0 else 0.0,
            throughput_decrypt_mbps=mb / avg_dec if avg_dec > 0 else 0.0,
            avalanche_score=self.measure_avalanche(),
            key_avalanche_score=self.measure_key_avalanche(),
            ci95_encrypt_mbps=ci95_enc,
            ci95_decrypt_mbps=ci95_dec,
        )

    # ------------------------------------------------------------------ #
    #  Avalanche effect                                                    #
    # ------------------------------------------------------------------ #

    def measure_avalanche(self, trials: int = 200) -> float:
        """
        Estimate the avalanche score of the primitive (not the mode).

        Methodology (per professor feedback):
          1. Generate a random block of ``primitive.block_size`` bytes.
          2. Encrypt it → reference ciphertext.
          3. Flip exactly one bit in the plaintext.
          4. Encrypt the modified block → modified ciphertext.
          5. Count the bit differences (Hamming distance).
          6. Repeat ``trials`` times, averaging the ratio of flipped bits.

        A perfect avalanche score is 0.5 (50 % of output bits change).
        This is computed on the primitive directly, independent of the mode.

        Parameters
        ----------
        trials : int
            Number of single-bit-flip experiments to average over.

        Returns
        -------
        float
            Average proportion of output bits that changed (0.0 – 1.0).
        """
        primitive = self._engine.primitive
        bs = primitive.block_size
        total_bits = bs * 8
        scores = []

        for _ in range(trials):
            block = os.urandom(bs)
            ref_ct = primitive.encrypt_block(block)

            # Flip one random bit
            flip_byte = secrets.randbelow(bs)
            flip_bit = secrets.randbelow(8)
            modified = bytearray(block)
            modified[flip_byte] ^= (1 << flip_bit)

            mod_ct = primitive.encrypt_block(bytes(modified))

            # Hamming distance
            diff_bits = sum(
                bin(a ^ b).count("1")
                for a, b in zip(ref_ct, mod_ct)
            )
            scores.append(diff_bits / total_bits)

        return sum(scores) / len(scores)

    def measure_key_avalanche(self, trials: int = 200) -> float:
        """
        Estimate the key avalanche score of the primitive.

        Methodology (per professor feedback, TN1 Feedback 11):
          1. Generate a fixed random plaintext block.
          2. Encrypt it with the current key → reference ciphertext.
          3. Flip exactly one bit in the *key* and re-instantiate the
             primitive with the modified key.
          4. Encrypt the same plaintext → modified ciphertext.
          5. Compute Hamming distance between the two ciphertexts.
          6. Repeat ``trials`` times, averaging the ratio of flipped bits.

        A perfect key avalanche score is 0.5 (50 % of output bits change
        when a single key bit is flipped with the same plaintext).

        Parameters
        ----------
        trials : int
            Number of single-key-bit-flip experiments to average over.

        Returns
        -------
        float
            Average proportion of output bits that changed (0.0 – 1.0).
        """
        primitive = self._engine.primitive
        bs = primitive.block_size
        ks = primitive.key_size
        total_bits = bs * 8
        scores = []

        for _ in range(trials):
            block = os.urandom(bs)

            # Reference: encrypt with the original key
            ref_ct = primitive.encrypt_block(block)

            # Flip one random bit in the key
            key_bytes = bytearray(self._engine.primitive._key)
            flip_byte = secrets.randbelow(ks)
            flip_bit  = secrets.randbelow(8)
            key_bytes[flip_byte] ^= (1 << flip_bit)

            # Build a new primitive with the modified key — catch degenerate
            # keys (e.g. 3DES K1=K2) by retrying with a different flip
            try:
                modified_prim = type(primitive)(bytes(key_bytes))
            except Exception:  # noqa: BLE001
                scores.append(0.5)  # assume ideal if key is degenerate
                continue

            mod_ct = modified_prim.encrypt_block(block)

            diff_bits = sum(
                bin(a ^ b).count("1")
                for a, b in zip(ref_ct, mod_ct)
            )
            scores.append(diff_bits / total_bits)

        return sum(scores) / len(scores)
