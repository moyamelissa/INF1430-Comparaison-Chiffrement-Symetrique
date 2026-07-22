"""
Twofish.py
Implémentation concrète de la primitive de chiffrement Twofish.

Tailles de clé supportées : 128, 192 ou 256 bits (16, 24, 32 octets).
Taille de bloc : 128 bits (16 octets).

PyCryptodome ne fournit pas Twofish nativement. Ce module encapsule le paquet
Python pur `twofish` (pip install twofish). L'interface est identique à celle
de toutes les autres sous-classes de CipherPrimitive, de sorte que le reste
du système ignore la différence d'implémentation.
"""

import importlib
import importlib.machinery
import sys
from types import ModuleType

from .CipherPrimitive import CipherPrimitive

_VALID_KEY_SIZES = {16, 24, 32}  # 128 / 192 / 256 bits (tailles de clé valides)


def _ensure_imp_compat_module() -> None:
    """Provide a minimal imp compatibility module when stdlib imp is absent.

    The third-party `twofish` package imports `imp` and calls `find_module`.
    Python 3.12+ removed stdlib imp, so we register a tiny runtime shim only
    for that import path instead of shadowing stdlib globally in the project.
    """
    if "imp" in sys.modules:
        return

    imp_mod = ModuleType("imp")

    # Legacy constants expected by some old callers.
    imp_mod.SEARCH_ERROR = 0
    imp_mod.PY_SOURCE = 1
    imp_mod.PY_COMPILED = 2
    imp_mod.C_EXTENSION = 3
    imp_mod.PY_RESOURCE = 4
    imp_mod.PKG_DIRECTORY = 5
    imp_mod.C_BUILTIN = 6
    imp_mod.PY_FROZEN = 7

    def get_suffixes() -> list[tuple[str, str, int]]:
        suffixes: list[tuple[str, str, int]] = []
        for ext in importlib.machinery.EXTENSION_SUFFIXES:
            suffixes.append((ext, "rb", imp_mod.C_EXTENSION))
        for src in importlib.machinery.SOURCE_SUFFIXES:
            suffixes.append((src, "r", imp_mod.PY_SOURCE))
        for bc in importlib.machinery.BYTECODE_SUFFIXES:
            suffixes.append((bc, "rb", imp_mod.PY_COMPILED))
        return suffixes

    def find_module(
        name: str,
        path: list[str] | None = None,
    ) -> tuple[None, str, tuple[str, str, int]]:
        spec = importlib.machinery.PathFinder.find_spec(name, path)
        if spec is None or spec.origin is None:
            raise ImportError(f"No module named {name!r}")

        origin = spec.origin
        if origin in {"built-in", "frozen"}:
            kind = imp_mod.C_BUILTIN if origin == "built-in" else imp_mod.PY_FROZEN
            desc = ("", "", kind)
        elif spec.submodule_search_locations is not None:
            desc = ("", "", imp_mod.PKG_DIRECTORY)
        elif any(origin.endswith(ext) for ext in importlib.machinery.EXTENSION_SUFFIXES):
            ext = importlib.machinery.EXTENSION_SUFFIXES[0]
            desc = (ext, "rb", imp_mod.C_EXTENSION)
        elif any(origin.endswith(ext) for ext in importlib.machinery.BYTECODE_SUFFIXES):
            desc = (".pyc", "rb", imp_mod.PY_COMPILED)
        else:
            desc = (".py", "r", imp_mod.PY_SOURCE)

        return None, origin, desc

    def load_module(name: str):
        if name in sys.modules:
            return sys.modules[name]
        return importlib.import_module(name)

    imp_mod.get_suffixes = get_suffixes
    imp_mod.find_module = find_module
    imp_mod.load_module = load_module

    sys.modules["imp"] = imp_mod


class Twofish(CipherPrimitive):
    """Chiffre par blocs Twofish."""

    BLOCK_SIZE = 16  # octets

    def __init__(self, key: bytes) -> None:
        """
        Paramètres
        ----------
        key : bytes
            16, 24 ou 32 octets (clé de 128 / 192 / 256 bits).

        Lève
        ----
        ValueError
            Si la longueur de la clé n'est pas une taille supportée.
        ImportError
            Si le paquet `twofish` n'est pas installé.
        """
        if len(key) not in _VALID_KEY_SIZES:
            raise ValueError(
                f"Twofish key must be 16, 24 or 32 bytes; got {len(key)}."
            )
        try:
            _ensure_imp_compat_module()
            from twofish import Twofish as _Twofish  # type: ignore[import]
        except ImportError as exc:
            # Distinguish between a missing dependency and an internal failure in
            # the dependency itself (e.g. incompatibility with Python runtime).
            if getattr(exc, "name", None) == "twofish":
                raise ImportError(
                    "The 'twofish' package is required for Twofish support. "
                    "Install it with: python -m pip install twofish"
                ) from exc
            raise ImportError(
                "Failed to import the 'twofish' package dependency. "
                f"Original import error: {exc}"
            ) from exc

        self._key = key
        self._cipher = _Twofish(key)

    # ------------------------------------------------------------------ #
    #  Interface CipherPrimitive                                           #
    # ------------------------------------------------------------------ #

    @property
    def block_size(self) -> int:
        return self.BLOCK_SIZE

    @property
    def key_size(self) -> int:
        return len(self._key)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.BLOCK_SIZE:
            raise ValueError(
                f"Block must be exactly {self.BLOCK_SIZE} bytes; got {len(block)}."
            )
        return bytes(self._cipher.encrypt(block))

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.BLOCK_SIZE:
            raise ValueError(
                f"Block must be exactly {self.BLOCK_SIZE} bytes; got {len(block)}."
            )
        return bytes(self._cipher.decrypt(block))
