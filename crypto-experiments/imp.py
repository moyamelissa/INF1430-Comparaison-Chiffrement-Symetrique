"""Compatibility layer for legacy code importing :mod:`imp`.

On Python versions where stdlib ``imp`` still exists (<= 3.11), this module
delegates to the real stdlib implementation so behavior matches CPython.
On newer versions where ``imp`` was removed, a minimal fallback is provided
for dependencies that only need legacy lookup/loading helpers.
"""

from __future__ import annotations

import importlib
import importlib.machinery
import importlib.util
import os
import sys
import sysconfig
from typing import Any, Optional


def _load_stdlib_imp_if_available() -> bool:
    """Load stdlib imp.py and re-export its public attributes when available."""
    stdlib_dir = sysconfig.get_path("stdlib")
    if not stdlib_dir:
        return False

    stdlib_imp = os.path.join(stdlib_dir, "imp.py")
    if not os.path.isfile(stdlib_imp):
        return False

    spec = importlib.util.spec_from_file_location("_stdlib_imp", stdlib_imp)
    if spec is None or spec.loader is None:
        return False

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    for name in dir(module):
        if name.startswith("__") and name not in {"__all__", "__doc__"}:
            continue
        globals()[name] = getattr(module, name)
    return True


if not _load_stdlib_imp_if_available():
    # Legacy constants kept for compatibility with old callers.
    SEARCH_ERROR = 0
    PY_SOURCE = 1
    PY_COMPILED = 2
    C_EXTENSION = 3
    PY_RESOURCE = 4
    PKG_DIRECTORY = 5
    C_BUILTIN = 6
    PY_FROZEN = 7

    _SOURCE_DESC = (".py", "r", PY_SOURCE)
    _BYTECODE_DESC = (".pyc", "rb", PY_COMPILED)
    _EXT_DESC = (
        importlib.machinery.EXTENSION_SUFFIXES[0]
        if importlib.machinery.EXTENSION_SUFFIXES
        else "",
        "rb",
        C_EXTENSION,
    )

    def get_suffixes() -> list[tuple[str, str, int]]:
        suffixes: list[tuple[str, str, int]] = []
        for ext in importlib.machinery.EXTENSION_SUFFIXES:
            suffixes.append((ext, "rb", C_EXTENSION))
        for src in importlib.machinery.SOURCE_SUFFIXES:
            suffixes.append((src, "r", PY_SOURCE))
        for bc in importlib.machinery.BYTECODE_SUFFIXES:
            suffixes.append((bc, "rb", PY_COMPILED))
        return suffixes

    def find_module(
        name: str,
        path: Optional[list[str]] = None,
    ) -> tuple[Any, str, tuple[str, str, int]]:
        spec = importlib.machinery.PathFinder.find_spec(name, path)
        if spec is None or spec.origin is None:
            raise ImportError(f"No module named {name!r}")

        origin = spec.origin
        if origin in {"built-in", "frozen"}:
            desc = ("", "", C_BUILTIN if origin == "built-in" else PY_FROZEN)
        elif spec.submodule_search_locations is not None:
            desc = ("", "", PKG_DIRECTORY)
        elif any(origin.endswith(ext) for ext in importlib.machinery.EXTENSION_SUFFIXES):
            desc = _EXT_DESC
        elif any(origin.endswith(ext) for ext in importlib.machinery.BYTECODE_SUFFIXES):
            desc = _BYTECODE_DESC
        else:
            desc = _SOURCE_DESC

        return None, origin, desc

    def load_module(name: str) -> Any:
        if name in sys.modules:
            return sys.modules[name]
        return importlib.import_module(name)
