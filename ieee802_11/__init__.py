"""Local ieee802_11 shim package.

For dev runs, prefer the in-tree pybind module built under
external/build/python/bindings over any system-installed package.
"""

from __future__ import annotations

import os
import sys

_pkg_dir = os.path.dirname(__file__)
_repo_dir = os.path.abspath(os.path.join(_pkg_dir, os.pardir))
_bindings_dir = os.path.join(_repo_dir, "external", "build", "python", "bindings")
_pure_py_dir = os.path.join(_repo_dir, "external", "python")

# Ensure local build artifacts are searched first.
for _p in (_bindings_dir, _pure_py_dir):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Import pybind11-generated symbols into this package namespace.
from ieee802_11_python import *  # noqa: F401,F403

# Import pure-python helpers when available.
try:
    from utils import *  # noqa: F401,F403
except ModuleNotFoundError:
    pass
