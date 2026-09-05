"""
registry.py — discover modules and resolve selections.

Selection is the whole point of the reframe: run one module, a few, or a named
group. This resolves --modules a,b,c and --group deep into the actual module set,
and powers the dashboard's checkboxes + group presets from the same source.

Two module TYPES share this machinery: active ScanModules (package `modules`) and
passive FileModules (package `file_modules`). Discovery is parameterized by base
class; select()/all_groups()/catalog() are structural and work on either — a module
of either type has a `name` and `groups`. catalog() tags each entry with its `kind`
so the dashboard renders active scanners and file-ingest modules from one source.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import TypeVar

from base import FileModule, ScanModule

# Anything with .name/.groups that we discover and select over.
Module = ScanModule | FileModule
M = TypeVar("M", bound=Module)


def _discover(package: str, base_cls: type[M]) -> dict[str, M]:
    """Import every file in the package, instantiate each concrete base_cls subclass."""
    pkg = importlib.import_module(package)
    found: dict[str, M] = {}
    for _, modname, _ in pkgutil.iter_modules(pkg.__path__):
        sub = importlib.import_module(f"{package}.{modname}")
        for _, obj in inspect.getmembers(sub, inspect.isclass):
            if issubclass(obj, base_cls) and obj is not base_cls and not inspect.isabstract(obj):
                inst = obj()
                if not inst.name:
                    raise ValueError(f"{obj.__name__} has no name")
                found[inst.name] = inst
    return found


def discover(package: str = "modules") -> dict[str, ScanModule]:
    """Discover active scan modules (the run(target, ctx) contract)."""
    # base_cls is used only for issubclass() filtering, never instantiated —
    # passing an abstract class here is intentional and safe.
    return _discover(package, ScanModule)  # type: ignore[type-abstract]


def discover_files(package: str = "file_modules") -> dict[str, FileModule]:
    """Discover passive file-ingest modules (the ingest(file, ctx) contract)."""
    return _discover(package, FileModule)  # type: ignore[type-abstract]


def all_groups(reg: dict[str, M]) -> set[str]:
    return {g for m in reg.values() for g in m.groups}


def select(
    reg: dict[str, M],
    modules: list[str] | None = None,
    group: str | None = None,
    default_group: str = "standard",
) -> list[M]:
    """Resolve a selection. --modules wins if given; else --group; else default_group.

    Works for either module type — file ingestion passes default_group='ingest'.
    """
    if modules:
        missing = [m for m in modules if m not in reg]
        if missing:
            raise KeyError(f"unknown modules: {', '.join(missing)}")
        return [reg[m] for m in modules]

    grp = group or default_group
    chosen = [m for m in reg.values() if grp in m.groups]
    if not chosen:
        raise KeyError(f"no modules in group {grp!r}; groups: {sorted(all_groups(reg))}")
    return chosen


def catalog(reg: dict[str, M]) -> list[dict]:
    """Machine-readable module list for --list-modules and the dashboard.

    Kind-aware: active scanners expose `target_kinds`, file modules expose
    `extensions`. Both carry a `kind` so the UI can group them.
    """
    out: list[dict] = []
    for m in sorted(reg.values(), key=lambda x: x.name):
        entry: dict = {"name": m.name, "description": m.description, "groups": list(m.groups)}
        if isinstance(m, FileModule):
            entry["kind"] = "file"
            entry["extensions"] = list(m.extensions)
        else:
            entry["kind"] = "scan"
            entry["target_kinds"] = list(m.target_kinds)
        out.append(entry)
    return out
