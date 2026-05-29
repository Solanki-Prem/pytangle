# SPDX-License-Identifier: MIT
"""Phase 4 — package health checks against the PyPI JSON API.

Determines, per package: the latest released version, whether the installed
version is outdated, and whether it (or all of its releases) have been yanked
or otherwise look deprecated. Combined with OSV results and conflict data to
produce the final :class:`~pytangle.models.PackageReport` per package.
"""

from __future__ import annotations

from packaging.version import InvalidVersion, Version

from pytangle._safety import SafeSession, SafetyError, is_valid_package_name
from pytangle.models import Conflict, Health, PackageReport, Vulnerability
from pytangle.parser import DependencyGraph

PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"


def build_reports(
    graph: DependencyGraph,
    *,
    vulnerabilities: dict[str, list[Vulnerability]] | None = None,
    conflicts: list[Conflict] | None = None,
    check_pypi: bool = True,
    session: SafeSession | None = None,
) -> list[PackageReport]:
    """Produce a sorted list of per-package health reports (worst first)."""
    vulnerabilities = vulnerabilities or {}
    conflict_keys = {
        c.package.lower().replace("_", "-") for c in (conflicts or [])
    }

    owns_session = session is None
    if check_pypi and session is None:
        session = SafeSession()

    reports: list[PackageReport] = []
    try:
        for pkg in graph.packages.values():
            report = PackageReport(package=pkg)
            if check_pypi and session is not None:
                _enrich_from_pypi(session, report)
            _apply_vulnerabilities(report, vulnerabilities.get(pkg.key, []))
            if pkg.key in conflict_keys:
                report.health = _worse(report.health, Health.CONFLICT)
                report.notes.append("Version conflict with a dependent package")
            reports.append(report)
    finally:
        if owns_session and session is not None:
            session.close()

    reports.sort(
        key=lambda r: (-r.health.severity, r.package.key)
    )
    return reports


def _enrich_from_pypi(session: SafeSession, report: PackageReport) -> None:
    pkg = report.package
    if not is_valid_package_name(pkg.name):
        report.notes.append("Skipped PyPI check: invalid package name")
        return
    try:
        resp = session.get(PYPI_JSON_URL.format(name=pkg.name))
    except SafetyError:
        return
    if resp.status_code == 404:
        report.notes.append("Not found on PyPI (private or local package?)")
        return
    if resp.status_code != 200:
        return
    try:
        data = resp.json()
    except ValueError:
        return

    info = data.get("info", {}) or {}
    latest = info.get("version")
    report.latest_version = latest

    releases = data.get("releases", {}) or {}
    report.is_yanked = _installed_release_is_yanked(releases, pkg.version)

    if report.is_yanked:
        report.health = _worse(report.health, Health.DEPRECATED)
        report.notes.append("Installed release is yanked on PyPI")

    if _classifiers_look_deprecated(info):
        report.health = _worse(report.health, Health.DEPRECATED)
        report.notes.append("PyPI classifiers mark this as inactive/deprecated")

    if latest and _is_outdated(pkg.version, latest):
        report.health = _worse(report.health, Health.OUTDATED)
        report.notes.append(f"Outdated: {pkg.version} < {latest}")


def _installed_release_is_yanked(releases: dict, installed: str) -> bool:
    files = releases.get(installed)
    if not files:
        return False
    # A release is yanked only if every distribution file for it is yanked.
    return all(isinstance(f, dict) and f.get("yanked") for f in files)


def _classifiers_look_deprecated(info: dict) -> bool:
    classifiers = info.get("classifiers") or []
    for c in classifiers:
        lowered = str(c).lower()
        if "inactive" in lowered or "development status :: 7" in lowered:
            return True
    return False


def _is_outdated(installed: str, latest: str) -> bool:
    try:
        return Version(installed) < Version(latest)
    except InvalidVersion:
        return False


def _apply_vulnerabilities(
    report: PackageReport, vulns: list[Vulnerability]
) -> None:
    if not vulns:
        return
    report.vulnerabilities = vulns
    report.health = _worse(report.health, Health.VULNERABLE)
    report.notes.append(f"{len(vulns)} known vulnerability(ies)")


def _worse(current: Health, candidate: Health) -> Health:
    return candidate if candidate.severity > current.severity else current
