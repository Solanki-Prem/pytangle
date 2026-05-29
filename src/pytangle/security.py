# SPDX-License-Identifier: MIT
"""Phase 4 — query the OSV.dev API for known vulnerabilities.

Uses the batched ``querybatch`` endpoint to look up many packages in a single
request, then resolves vulnerability details. All traffic goes through the
SSRF-hardened :class:`~pytangle._safety.SafeSession`.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from pytangle._safety import SafeSession, SafetyError, is_valid_package_name, is_valid_version
from pytangle.models import Vulnerability

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
_BATCH_SIZE = 200  # OSV accepts up to 1000; stay conservative.


def scan(
    packages: Sequence[tuple[str, str]],
    *,
    session: SafeSession | None = None,
) -> dict[str, list[Vulnerability]]:
    """Return ``{canonical_name: [Vulnerability, ...]}`` for vulnerable packages.

    *packages* is a sequence of ``(name, version)`` pairs. Invalid names or
    versions are skipped defensively so a malformed lockfile can't reach OSV.
    """
    queries: list[dict] = []
    index_map: list[str] = []  # parallel to queries: the package name per query
    for name, version in packages:
        if not is_valid_package_name(name) or not is_valid_version(version):
            continue
        queries.append(
            {"version": version, "package": {"name": name, "ecosystem": "PyPI"}}
        )
        index_map.append(name)

    if not queries:
        return {}

    owns_session = session is None
    session = session or SafeSession()
    results: dict[str, list[Vulnerability]] = {}
    try:
        for start in range(0, len(queries), _BATCH_SIZE):
            chunk = queries[start : start + _BATCH_SIZE]
            names = index_map[start : start + _BATCH_SIZE]
            _scan_chunk(session, chunk, names, results)
    finally:
        if owns_session:
            session.close()
    return results


def _scan_chunk(
    session: SafeSession,
    chunk: list[dict],
    names: list[str],
    results: dict[str, list[Vulnerability]],
) -> None:
    try:
        resp = session.post_json(OSV_QUERYBATCH_URL, {"queries": chunk})
    except SafetyError:
        return
    if resp.status_code != 200:
        return
    try:
        payload = resp.json()
    except ValueError:
        return

    for name, result in zip(names, payload.get("results", [])):
        vulns = result.get("vulns") or []
        if not vulns:
            continue
        collected = [_to_vulnerability(session, v) for v in vulns]
        key = name.lower().replace("_", "-")
        results.setdefault(key, []).extend(collected)


def _to_vulnerability(session: SafeSession, vuln: dict) -> Vulnerability:
    """Build a Vulnerability from a (possibly partial) OSV record."""
    vuln_id = str(vuln.get("id", "")) or "UNKNOWN"
    summary = vuln.get("summary") or vuln.get("details") or ""
    aliases = tuple(str(a) for a in (vuln.get("aliases") or []))
    severity = _extract_severity(vuln)
    fixed = _extract_fixed_version(vuln)

    # querybatch returns only IDs; fetch details if the summary is missing.
    if not summary and vuln_id != "UNKNOWN":
        detail = _fetch_detail(session, vuln_id)
        if detail:
            summary = detail.get("summary") or detail.get("details") or ""
            aliases = aliases or tuple(str(a) for a in (detail.get("aliases") or []))
            severity = severity or _extract_severity(detail)
            fixed = fixed or _extract_fixed_version(detail)

    return Vulnerability(
        id=vuln_id,
        summary=_truncate(summary),
        aliases=aliases,
        severity=severity,
        fixed_version=fixed,
    )


def _fetch_detail(session: SafeSession, vuln_id: str) -> dict | None:
    # Defend against path-injection into the vulns/ URL.
    if not vuln_id.replace("-", "").replace("_", "").replace(".", "").isalnum():
        return None
    try:
        resp = session.get(OSV_VULN_URL + vuln_id)
    except SafetyError:
        return None
    if resp.status_code != 200:
        return None
    try:
        return resp.json()
    except ValueError:
        return None


def _extract_severity(vuln: dict) -> str:
    severities = vuln.get("severity") or []
    for sev in severities:
        if isinstance(sev, dict) and sev.get("score"):
            return f"{sev.get('type', 'CVSS')}:{sev['score']}"
    # database_specific sometimes carries a human-readable level.
    db = vuln.get("database_specific") or {}
    return str(db.get("severity", "")) if isinstance(db, dict) else ""


def _extract_fixed_version(vuln: dict) -> str | None:
    """Pull the first 'fixed' version from OSV affected ranges, if any."""
    for affected in vuln.get("affected") or []:
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if isinstance(event, dict) and event.get("fixed"):
                    return str(event["fixed"])
    return None


def _truncate(text: str, limit: int = 240) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def collect_aliases(vulns: Iterable[Vulnerability]) -> list[str]:
    """Flatten and de-duplicate CVE/GHSA aliases for display."""
    seen: dict[str, None] = {}
    for v in vulns:
        for alias in v.aliases:
            seen.setdefault(alias, None)
        seen.setdefault(v.id, None)
    return list(seen.keys())
