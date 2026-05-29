# SPDX-License-Identifier: MIT
"""Typed data models shared across PyTangle modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Health(str, Enum):
    """Per-package health classification, ordered by severity."""

    HEALTHY = "healthy"
    OUTDATED = "outdated"
    DEPRECATED = "deprecated"
    CONFLICT = "conflict"
    VULNERABLE = "vulnerable"

    @property
    def severity(self) -> int:
        order = {
            Health.HEALTHY: 0,
            Health.OUTDATED: 1,
            Health.DEPRECATED: 2,
            Health.CONFLICT: 3,
            Health.VULNERABLE: 4,
        }
        return order[self]

    @property
    def color(self) -> str:
        """Hex colour used for graph nodes and Rich styling."""
        return {
            Health.HEALTHY: "#2ecc71",
            Health.OUTDATED: "#f1c40f",
            Health.DEPRECATED: "#e67e22",
            Health.CONFLICT: "#e74c3c",
            Health.VULNERABLE: "#c0392b",
        }[self]


@dataclass(frozen=True)
class Package:
    """An installed (or locked) distribution and its declared requirements."""

    name: str
    version: str
    requires: tuple[str, ...] = ()  # raw requirement strings, e.g. "idna>=2.5"
    source: str = "environment"  # environment | poetry.lock | uv.lock | Pipfile.lock

    @property
    def key(self) -> str:
        """Normalised lookup key (PEP 503)."""
        return self.name.lower().replace("_", "-")


@dataclass
class Vulnerability:
    """A single advisory affecting a package, as reported by OSV."""

    id: str
    summary: str = ""
    aliases: tuple[str, ...] = ()  # e.g. CVE identifiers
    severity: str = ""
    fixed_version: str | None = None


@dataclass
class Conflict:
    """A version-requirement conflict for one package across dependents."""

    package: str
    installed: str | None
    # dependent name -> the specifier it requires (e.g. "numpy<2.0")
    requirements: dict[str, str] = field(default_factory=dict)


@dataclass
class PackageReport:
    """Aggregated health/security findings for one package."""

    package: Package
    health: Health = Health.HEALTHY
    latest_version: str | None = None
    is_yanked: bool = False
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class FixSuggestion:
    """An actionable remediation for a conflict or vulnerability."""

    package: str
    target_version: str
    reason: str
    command: str
    confidence: str = "medium"  # low | medium | high
