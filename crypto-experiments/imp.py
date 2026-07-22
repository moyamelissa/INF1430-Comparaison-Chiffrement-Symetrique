"""Compatibility shim for legacy code that still imports :mod:`imp`.

Only the tiny subset needed by the bundled `twofish` dependency is provided.
"""

from __future__ import annotations

import importlib.util
from types import ModuleType
from typing import Any, Optional, Tuple


def find_module(name: str, path: Optional[list[str]] = None) -> tuple[Any, str, tuple[str, str, int]]:
    spec = importlib.util.find_spec(name)
    if spec is None or spec.origin is None:
        raise ImportError(f"No module named {name!r}")
    return None, spec.origin, ("", "", 1)
