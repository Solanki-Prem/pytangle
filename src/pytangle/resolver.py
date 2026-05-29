# SPDX-License-Identifier: MIT
"""Phase 5 — the auto-fix engine for ``pytangle suggest``.

Given detected conflicts and known vulnerabilities, compute the safest
version that satisfies every dependent's requirement (the intersection of all
specifiers, evaluated against the versions PyPI actually publishes), and emit
an actionable ``uv pip install`` command.

This is a lightweight constraint solver, not a full SAT resolver: it solves
each conflicting package independently. That covers the common "two packages
disagree about X" case while staying fast and explainable.
"""

from __future__ import annotations

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from pytangle._safety import SafeSession, SafetyError, is_valid_package_name
from pytangle.models import Conflict, FixSuggestion, PackageReport, Vulnerability

PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"


def suggest_fixes(
    conflicts: list[Conflict],
    reports: list[PackageReport],
    *,
    session: SafeSession | None = None,
) -> list[FixSuggestion]:
    """Compute remediation suggestions for conflicts and vulnerabilities."""
    owns_session = session is None
    session = session or SafeSession()
    suggestions: list[FixSuggestion] = []
    try:
        for conflict in conflicts:
            suggestion = _solve_conflict(session, conflict)
            if suggestion:
                suggestions.append(suggestion)
        suggestions.extend(_solve_vulnerabilities(reports))
    finally:
        if owns_session:
            session.close()
    return suggestions


def _solve_conflict(
    session: SafeSession, conflict: Conflict
) -> FixSuggestion | None:
    if not is_valid_package_name(conflict.package):
        return None

    # Intersect every dependent's specifier into one constraint set.
    combined = SpecifierSet()
    for spec in conflict.requirements.values():
        try:
            combined &= SpecifierSet(spec)
        except InvalidSpecifier:
            continue

    candidates = _available_versions(session, conflict.package)
    if not candidates:
        return None

    satisfying = [v for v in candidates if combined.contains(v, prereleases=False)]
    dependents = ", ".join(sorted(conflict.requirements))

    if satisfying:
        best = max(satisfying)
        return FixSuggestion(
            package=conflict.package,
            target_version=str(best),
            reason=(
                f"{conflict.package}=={conflict.installed} violates constraints "
                f"from {dependents}; {best} satisfies all of: "
                f"{_format_specs(conflict.requirements)}."
            ),
            command=f"uv pip install '{conflict.package}=={best}'",
            confidence="high",
        )

    # No single version satisfies everyone — the conflict is unsatisfiable as-is.
    return FixSuggestion(
        package=conflict.package,
        target_version="(none)",
        reason=(
            f"No published version of {conflict.package} satisfies all dependents "
            f"({dependents}). Constraints are mutually exclusive: "
            f"{_format_specs(conflict.requirements)}. Consider upgrading the "
            f"dependents or relaxing a pin."
        ),
        command=f"uv pip index versions {conflict.package}",
        confidence="low",
    )


def _solve_vulnerabilities(
    reports: list[PackageReport],
) -> list[FixSuggestion]:
    out: list[FixSuggestion] = []
    for report in reports:
        if not report.vulnerabilities:
            continue
        fixed = _best_fixed_version(report.vulnerabilities)
        name = report.package.name
        if fixed:
            out.append(
                FixSuggestion(
                    package=name,
                    target_version=fixed,
                    reason=(
                        f"{name}=={report.package.version} is affected by "
                        f"{len(report.vulnerabilities)} advisory(ies); "
                        f"{fixed} contains the fix."
                    ),
                    command=f"uv pip install '{name}>={fixed}'",
                    confidence="high",
                )
            )
        else:
            out.append(
                FixSuggestion(
                    package=name,
                    target_version="(latest)",
                    reason=(
                        f"{name}=={report.package.version} is vulnerable but OSV "
                        f"lists no fixed version. Upgrade to the latest release "
                        f"and review the advisory."
                    ),
                    command=f"uv pip install --upgrade {name}",
                    confidence="medium",
                )
            )
    return out


def _best_fixed_version(vulns: list[Vulnerability]) -> str | None:
    """Pick the highest 'fixed' version across advisories (covers them all)."""
    fixed: list[Version] = []
    for v in vulns:
        if v.fixed_version:
            try:
                fixed.append(Version(v.fixed_version))
            except InvalidVersion:
                continue
    return str(max(fixed)) if fixed else None


def _available_versions(session: SafeSession, name: str) -> list[Version]:
    try:
        resp = session.get(PYPI_JSON_URL.format(name=name))
    except SafetyError:
        return []
    if resp.status_code != 200:
        return []
    try:
        data = resp.json()
    except ValueError:
        return []

    versions: list[Version] = []
    for raw, files in (data.get("releases", {}) or {}).items():
        # Skip releases with no files or where every file is yanked.
        if not files or all(isinstance(f, dict) and f.get("yanked") for f in files):
            continue
        try:
            versions.append(Version(raw))
        except InvalidVersion:
            continue
    return versions


def _format_specs(requirements: dict[str, str]) -> str:
    return "; ".join(f"{dep} needs {spec}" for dep, spec in sorted(requirements.items()))
