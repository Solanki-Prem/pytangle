# SPDX-License-Identifier: MIT
"""Rich rendering helpers for tables and summaries."""

from __future__ import annotations

from rich.table import Table

from pytangle.models import Conflict, FixSuggestion, Health, PackageReport
from pytangle.security import collect_aliases

_HEALTH_LABEL = {
    Health.HEALTHY: "[green]● healthy[/]",
    Health.OUTDATED: "[yellow]● outdated[/]",
    Health.DEPRECATED: "[dark_orange]● deprecated[/]",
    Health.CONFLICT: "[red]● conflict[/]",
    Health.VULNERABLE: "[bold red]● vulnerable[/]",
}


def health_table(reports: list[PackageReport], *, only_issues: bool = False) -> Table:
    """Build a table summarising package health and security status."""
    table = Table(title="Package Health & Security", header_style="bold magenta")
    table.add_column("Package", style="cyan", no_wrap=True)
    table.add_column("Installed", justify="right")
    table.add_column("Latest", justify="right")
    table.add_column("Status")
    table.add_column("CVEs / Notes")

    shown = 0
    for r in reports:
        if only_issues and r.health is Health.HEALTHY:
            continue
        shown += 1
        latest = r.latest_version or "—"
        latest_style = (
            f"[yellow]{latest}[/]"
            if r.latest_version and r.latest_version != r.package.version
            else latest
        )
        detail = _detail_cell(r)
        table.add_row(
            r.package.name,
            r.package.version,
            latest_style,
            _HEALTH_LABEL[r.health],
            detail,
        )

    if shown == 0:
        table.add_row("—", "—", "—", "[green]all clear[/]", "No issues found")
    return table


def _detail_cell(report: PackageReport) -> str:
    parts: list[str] = []
    if report.vulnerabilities:
        aliases = collect_aliases(report.vulnerabilities)
        parts.append("[red]" + ", ".join(aliases[:4]) + "[/]")
    if report.notes:
        parts.append("[dim]" + "; ".join(report.notes[:2]) + "[/]")
    return "\n".join(parts) if parts else "—"


def conflicts_table(conflicts: list[Conflict]) -> Table:
    table = Table(title="Version Conflicts", header_style="bold red")
    table.add_column("Package", style="cyan")
    table.add_column("Installed", justify="right")
    table.add_column("Conflicting requirements")
    for c in conflicts:
        reqs = "\n".join(f"{dep} → {spec}" for dep, spec in sorted(c.requirements.items()))
        table.add_row(c.package, c.installed or "—", reqs)
    return table


def suggestions_table(suggestions: list[FixSuggestion]) -> Table:
    table = Table(title="Suggested Fixes", header_style="bold green")
    table.add_column("Package", style="cyan")
    table.add_column("Target", justify="right")
    table.add_column("Confidence")
    table.add_column("Run")
    conf_style = {"high": "green", "medium": "yellow", "low": "red"}
    for s in suggestions:
        table.add_row(
            s.package,
            s.target_version,
            f"[{conf_style.get(s.confidence, 'white')}]{s.confidence}[/]",
            f"[bold]{s.command}[/]",
        )
    return table
