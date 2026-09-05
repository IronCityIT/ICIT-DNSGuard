"""Put the shared framework on the path so modules import as they do at runtime."""

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
for path in (str(ROOT), str(ROOT / "module_framework")):
    if path not in sys.path:
        sys.path.insert(0, path)
