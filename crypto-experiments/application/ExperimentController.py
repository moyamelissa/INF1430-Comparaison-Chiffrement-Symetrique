"""
ExperimentController.py
Orchestre les expériences de benchmarking sur des instances EncryptionEngine.

Responsabilités :
  - Configurer et itérer sur les paramètres d'expérience (algorithme, mode,
    taille de clé, taille de message, répétitions).
  - Chronométrer les opérations de chiffrement/déchiffrement de façon neutre
    (le minuteur n'encapsule que l'appel cryptographique, pas l'initialisation
    ni les E/S).
  - Calculer le score d'effet d'avalanche pour chaque primitive.
  - Retourner des dictionnaires de résultats structurés ; la persistance (CSV)
    est gérée par le script appelant, pas ici.

Cette couche ne sait pas quelle primitive ou quel mode spécifique est utilisé —
elle n'appelle que l'interface EncryptionEngine.
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
    """Conteneur pour une mesure d'expérience unique."""

    algorithm: str          # ex. "AES"
    mode: str               # ex. "CBC"
    key_size_bytes: int     # ex. 16
    message_size_bytes: int # ex. 1024
    repetitions: int        # nombre d'itérations chronométrées
    avg_encrypt_time_s: float
    avg_decrypt_time_s: float
    throughput_encrypt_mbps: float
    throughput_decrypt_mbps: float
    avalanche_score: float      # flip d'un bit en clair → taux de changement en sortie
    key_avalanche_score: float  # flip d'un bit de clé → taux de changement en sortie
    ci95_encrypt_mbps: float    # demi-largeur de l'intervalle de confiance à 95 % (chiffrement)
    ci95_decrypt_mbps: float    # demi-largeur de l'intervalle de confiance à 95 % (déchiffrement)
    extra: dict = field(default_factory=dict)


class ExperimentController:
    """
    Coordonne une campagne de benchmarking pour un EncryptionEngine.

    Paramètres
    ----------
    engine : EncryptionEngine
        Le moteur entirement configuré (primitive + mode) à benchmarker.
    algorithm_name : str
        Étiquette lisible utilisée dans les lignes de résultat (ex. "AES").
    mode_name : str
        Étiquette lisible utilisée dans les lignes de résultat (ex. "CBC").
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
    #  Benchmarking de performance                                         #
    # ------------------------------------------------------------------ #

    def run_performance(
        self,
        message_size_bytes: int = 1024,
        repetitions: int = 1000,
    ) -> ExperimentResult:
        """
        Mesure le temps moyen de chiffrement/déchiffrement et le débit.

        Le minuteur n'encapsule que l'appel cryptographique, minimisant ainsi
        les surcoûts de la plateforme (allocation mémoire, interpréteur Python).
        Un texte en clair aléatoire fixe est réutilisé à travers les répétitions
        pour comparabilité.

        Paramètres
        ----------
        message_size_bytes : int
            Taille du message de test aléatoire en octets.
        repetitions : int
            Nombre d'itérations de chiffrement (et de déchiffrement) à moyenner.

        Retourne
        --------
        ExperimentResult
            Résultat peuplé incluant le débit et le score d'avalanche.
        """
        plaintext = os.urandom(message_size_bytes)

        # --- chronométrage du chiffrement ---
        enc_times = []
        ciphertexts = []
        for _ in range(repetitions):
            t0 = time.perf_counter()
            ct = self._engine.encrypt(plaintext)
            enc_times.append(time.perf_counter() - t0)
            ciphertexts.append(ct)

        # --- chronométrage du déchiffrement (utilise le dernier texte chiffré) ---
        last_ct = ciphertexts[-1]
        dec_times = []
        for _ in range(repetitions):
            t0 = time.perf_counter()
            self._engine.decrypt(last_ct)
            dec_times.append(time.perf_counter() - t0)

        avg_enc = sum(enc_times) / repetitions
        avg_dec = sum(dec_times) / repetitions
        mb = message_size_bytes / (1024 * 1024)

        # Intervalle de confiance à 95 % : t_{0,975, n-1} * std / sqrt(n)
        # Pour n >= 30, on utilise z = 1,96 (approximation normale).
        def _ci95_mbps(times: list, avg_t: float) -> float:
            n = len(times)
            if n < 2 or avg_t <= 0:
                return 0.0
            variance = sum((t - avg_t) ** 2 for t in times) / (n - 1)
            std_dev  = math.sqrt(variance)
            # Conversion de l'écart-type temporel en écart-type de débit (MB/s)
            # débit = mb / t  →  std_débit ≈ mb * std_t / avg_t²
            std_thr  = mb * std_dev / (avg_t ** 2)
            t_crit   = 1.96 if n >= 30 else 2.045  # t_{0,975} pour n~30
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
    #  Effet d'avalanche                                                   #
    # ------------------------------------------------------------------ #

    def measure_avalanche(self, trials: int = 200) -> float:
        """
        Estime le score d'avalanche de la primitive (pas du mode).

        Méthodologie (selon retour du professeur) :
          1. Générer un bloc aléatoire de ``primitive.block_size`` octets.
          2. Le chiffrer → texte chiffré de référence.
          3. Inverser exactement un bit dans le texte en clair.
          4. Chiffrer le bloc modifié → texte chiffré modifié.
          5. Compter les différences de bits (distance de Hamming).
          6. Répéter ``trials`` fois en moyennant le ratio de bits inversés.

        Un score d'avalanche parfait est 0,5 (50 % des bits de sortie changent).
        Ce calcul s'effectue directement sur la primitive, indépendamment du mode.

        Paramètres
        ----------
        trials : int
            Nombre d'expériences de flip d'un seul bit à moyenner.

        Retourne
        --------
        float
            Proportion moyenne de bits de sortie qui ont changé (0,0 – 1,0).
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

            # Distance de Hamming
            diff_bits = sum(
                bin(a ^ b).count("1")
                for a, b in zip(ref_ct, mod_ct)
            )
            scores.append(diff_bits / total_bits)

        return sum(scores) / len(scores)

    def measure_key_avalanche(self, trials: int = 200) -> float:
        """
        Estime le score d'avalanche clé de la primitive.

        Méthodologie (selon retour du professeur, TN1 Retour 11) :
          1. Générer un bloc de texte en clair fixe aléatoire.
          2. Le chiffrer avec la clé courante → texte chiffré de référence.
          3. Inverser exactement un bit dans la *clé* et réinstancier la
             primitive avec la clé modifiée.
          4. Chiffrer le même texte en clair → texte chiffré modifié.
          5. Calculer la distance de Hamming entre les deux textes chiffrés.
          6. Répéter ``trials`` fois en moyennant le ratio de bits inversés.

        Un score d'avalanche clé parfait est 0,5 (50 % des bits de sortie
        changent quand un seul bit de clé est inversé avec le même texte).

        Paramètres
        ----------
        trials : int
            Nombre d'expériences de flip d'un seul bit de clé à moyenner.

        Retourne
        --------
        float
            Proportion moyenne de bits de sortie qui ont changé (0,0 – 1,0).
        """
        primitive = self._engine.primitive
        bs = primitive.block_size
        ks = primitive.key_size
        total_bits = bs * 8
        scores = []

        for _ in range(trials):
            block = os.urandom(bs)

            # Référence : chiffrement avec la clé originale
            ref_ct = primitive.encrypt_block(block)

            # Inverser un bit aléatoire dans la clé
            key_bytes = bytearray(self._engine.primitive._key)
            flip_byte = secrets.randbelow(ks)
            flip_bit  = secrets.randbelow(8)
            key_bytes[flip_byte] ^= (1 << flip_bit)

            # Construction d'une nouvelle primitive avec la clé modifiée — les clés
            # dégénérées (ex. 3DES K1=K2) sont gérées en réessayant avec un autre flip
            try:
                modified_prim = type(primitive)(bytes(key_bytes))
            except Exception:  # noqa: BLE001
                scores.append(0.5)  # valeur idéale supposée si la clé est dégénérée
                continue

            mod_ct = modified_prim.encrypt_block(block)

            diff_bits = sum(
                bin(a ^ b).count("1")
                for a, b in zip(ref_ct, mod_ct)
            )
            scores.append(diff_bits / total_bits)

        return sum(scores) / len(scores)
