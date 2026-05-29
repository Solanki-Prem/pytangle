# SPDX-License-Identifier: MIT
"""Phase 3 — build the dependency graph and parse modern lockfiles.

The installed-environment graph is built from :mod:`importlib.metadata`, which
is fast, dependency-free, and exact for the *active* interpreter. ``uv`` is
used opportunistically to confirm availability but never to execute lockfile
content. Lockfiles are parsed strictly as data (TOML/JSON) — never imported or
evaluated.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from importlib import metadata as importlib_metadata
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from pytangle.models import Conflict, Package

# tomllib is stdlib from 3.11; tomli is the backport for 3.9/3.10.
if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on <3.11
    import tomli as tomllib

LOCKFILE_NAMES = ("uv.lock", "poetry.lock", "Pipfile.lock")
_MAX_LOCKFILE_BYTES = 32 * 1024 * 1024  # refuse absurdly large lockfiles


@dataclass
class DependencyGraph:
    """A resolved set of packages and the edges between them."""

    packages: dict[str, Package] = field(default_factory=dict)
    source: str = "environment"

    def add(self, pkg: Package) -> None:
        self.packages[pkg.key] = pkg

    def get(self, name: str) -> Package | None:
        return self.packages.get(canonicalize_name(name))

    def edges(self) -> list[tuple[str, str]]:
        """Return (dependent_key, dependency_key) pairs present in the graph."""
        out: list[tuple[str, str]] = []
        for pkg in self.packages.values():
            for raw in pkg.requires:
                dep_key = _requirement_name(raw)
                if dep_key and dep_key in self.packages:
                    out.append((pkg.key, dep_key))
        return out

    def __len__(self) -> int:
        return len(self.packages)


def _requirement_name(raw: str) -> str | None:
    """Extract the canonical distribution name from a requirement string."""
    try:
        return canonicalize_name(Requirement(raw).name)
    except InvalidRequirement:
        return None


# --------------------------------------------------------------------------- #
# Installed-environment graph
# --------------------------------------------------------------------------- #


def _applicable_requirement(raw: str) -> bool:
    """Filter out requirements gated by extras or non-matching env markers."""
    try:
        req = Requirement(raw)
    except InvalidRequirement:
        return False
    if req.marker is None:
        return True
    # Evaluate the marker against the current environment, ignoring extras
    # (we only want the always-installed runtime dependencies).
    try:
        return req.marker.evaluate()
    except Exception:
        # Markers referencing an undefined "extra" raise; treat as optional.
        return False


def build_environment_graph() -> DependencyGraph:
    """Build the dependency graph for the active interpreter."""
    graph = DependencyGraph(source="environment")
    for dist in importlib_metadata.distributions():
        try:
            name = dist.metadata["Name"]
            version = dist.version
        except (KeyError, AttributeError):
            continue
        if not name:
            continue
        requires = tuple(
            r for r in (dist.requires or []) if _applicable_requirement(r)
        )
        graph.add(
            Package(
                name=name,
                version=version or "0",
                requires=requires,
                source="environment",
            )
        )
    return graph


# --------------------------------------------------------------------------- #
# Lockfile loading
# --------------------------------------------------------------------------- #


def _read_lockfile_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) > _MAX_LOCKFILE_BYTES:
        raise ValueError(f"Lockfile too large to parse safely: {path}")
    return data


def discover_lockfiles(root: Path) -> list[Path]:
    """Return known lockfiles present in *root*, most-preferred first."""
    return [root / name for name in LOCKFILE_NAMES if (root / name).is_file()]


def load_lockfile(path: Path) -> DependencyGraph:
    """Parse a supported lockfile into a :class:`DependencyGraph`."""
    name = path.name
    if name == "uv.lock":
        return _parse_uv_lock(path)
    if name == "poetry.lock":
        return _parse_poetry_lock(path)
    if name == "Pipfile.lock":
        return _parse_pipfile_lock(path)
    raise ValueError(f"Unsupported lockfile: {name}")


def _parse_uv_lock(path: Path) -> DependencyGraph:
    data = tomllib.loads(_read_lockfile_bytes(path).decode("utf-8"))
    graph = DependencyGraph(source="uv.lock")
    for entry in data.get("package", []):
        pkg_name = entry.get("name")
        if not pkg_name:
            continue
        deps = entry.get("dependencies", []) or []
        requires = tuple(d["name"] for d in deps if isinstance(d, dict) and d.get("name"))
        graph.add(
            Package(
                name=pkg_name,
                version=str(entry.get("version", "0")),
                requires=requires,
                source="uv.lock",
            )
        )
    return graph


def _parse_poetry_lock(path: Path) -> DependencyGraph:
    data = tomllib.loads(_read_lockfile_bytes(path).decode("utf-8"))
    graph = DependencyGraph(source="poetry.lock")
    for entry in data.get("package", []):
        pkg_name = entry.get("name")
        if not pkg_name:
            continue
        # poetry stores deps as {name: constraint | [list] | {table}}.
        deps_field = entry.get("dependencies", {}) or {}
        requires = tuple(str(k) for k in deps_field)
        graph.add(
            Package(
                name=pkg_name,
                version=str(entry.get("version", "0")),
                requires=requires,
                source="poetry.lock",
            )
        )
    return graph


def _parse_pipfile_lock(path: Path) -> DependencyGraph:
    data = json.loads(_read_lockfile_bytes(path).decode("utf-8"))
    graph = DependencyGraph(source="Pipfile.lock")
    for section in ("default", "develop"):
        for pkg_name, spec in (data.get(section) or {}).items():
            version = "0"
            if isinstance(spec, dict):
                raw = spec.get("version", "")
                version = raw.lstrip("=") if isinstance(raw, str) else "0"
            graph.add(
                Package(
                    name=pkg_name,
                    version=version or "0",
                    requires=(),  # Pipfile.lock is flat — no per-package edges
                    source="Pipfile.lock",
                )
            )
    return graph


# --------------------------------------------------------------------------- #
# Conflict detection
# --------------------------------------------------------------------------- #


def find_conflicts(graph: DependencyGraph) -> list[Conflict]:
    """Detect packages whose installed version violates a dependent's spec."""
    # package_key -> {dependent_name: SpecifierSet-as-string}
    demands: dict[str, dict[str, str]] = {}
    for pkg in graph.packages.values():
        for raw in pkg.requires:
            try:
                req = Requirement(raw)
            except InvalidRequirement:
                continue
            if not str(req.specifier):
                continue
            dep_key = canonicalize_name(req.name)
            demands.setdefault(dep_key, {})[pkg.name] = str(req.specifier)

    conflicts: list[Conflict] = []
    for canon_key, reqs in demands.items():
        target = graph.packages.get(canon_key)
        installed = target.version if target else None
        if installed is None:
            continue  # not installed in this graph; map() will flag separately
        try:
            installed_v = Version(installed)
        except InvalidVersion:
            continue
        violating = {
            dependent: spec
            for dependent, spec in reqs.items()
            if not _satisfies(installed_v, spec)
        }
        if violating:
            conflicts.append(
                Conflict(
                    package=target.name if target else str(canon_key),
                    installed=installed,
                    requirements=violating,
                )
            )
    return conflicts


def _satisfies(version: Version, specifier: str) -> bool:
    from packaging.specifiers import InvalidSpecifier, SpecifierSet

    try:
        # prereleases=True so a pinned pre-release install isn't a false positive.
        return SpecifierSet(specifier).contains(version, prereleases=True)
    except InvalidSpecifier:
        return True  # unparseable spec — don't cry wolf


def iter_package_names(graph: DependencyGraph) -> Iterable[tuple[str, str]]:
    """Yield (name, version) for every package, for downstream API queries."""
    for pkg in graph.packages.values():
        yield pkg.name, pkg.version
