# SPDX-License-Identifier: MIT
"""PyTangle command-line interface (Typer + Rich)."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from pytangle import __version__, checker, environment, parser, report, resolver, security
from pytangle.parser import DependencyGraph

app = typer.Typer(
    name="pytangle",
    help="The lightning-fast, visual dependency detective for Python environments.",
    add_completion=True,
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()
err_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"pytangle {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    _version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """PyTangle — untangle and fix your Python environments."""


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #


def _load_graph(lockfile: Optional[Path], path: Path) -> DependencyGraph:
    """Load a graph from an explicit lockfile, auto-discovery, or the env."""
    if lockfile is not None:
        if not lockfile.is_file():
            err_console.print(f"[red]Lockfile not found:[/] {lockfile}")
            raise typer.Exit(code=2)
        return parser.load_lockfile(lockfile)

    discovered = parser.discover_lockfiles(path)
    if discovered:
        chosen = discovered[0]
        console.print(f"[dim]Using lockfile: {chosen.name}[/]")
        return parser.load_lockfile(chosen)

    return parser.build_environment_graph()


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


@app.command()
def status() -> None:
    """Diagnose the active interpreter and virtual environment."""
    info = environment.collect()
    console.print(environment.render(info))


@app.command()
def map(  # noqa: A001 - command name intentionally mirrors the verb
    output: Path = typer.Option(
        Path("pytangle-graph.html"),
        "--output",
        "-o",
        help="Where to write the interactive HTML graph.",
    ),
    lockfile: Optional[Path] = typer.Option(
        None, "--lockfile", "-l", help="Parse a specific lockfile instead of the env."
    ),
    path: Path = typer.Option(
        Path("."), "--path", "-p", help="Directory to scan for lockfiles."
    ),
) -> None:
    """Map the dependency graph and render an interactive visualisation."""
    graph = _load_graph(lockfile, path)
    if len(graph) == 0:
        err_console.print("[yellow]No packages found to map.[/]")
        raise typer.Exit(code=1)

    conflicts = parser.find_conflicts(graph)
    console.print(
        f"Mapped [bold cyan]{len(graph)}[/] packages "
        f"({len(graph.edges())} edges) from [bold]{graph.source}[/]."
    )
    if conflicts:
        console.print(report.conflicts_table(conflicts))

    try:
        from pytangle import visualizer

        written = visualizer.render_graph(graph, output)
    except ImportError as exc:
        err_console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]✓[/] Interactive graph written to [bold]{written}[/]")


@app.command()
def check(
    lockfile: Optional[Path] = typer.Option(
        None, "--lockfile", "-l", help="Parse a specific lockfile instead of the env."
    ),
    path: Path = typer.Option(
        Path("."), "--path", "-p", help="Directory to scan for lockfiles."
    ),
    offline: bool = typer.Option(
        False, "--offline", help="Skip all network calls (no PyPI/OSV lookups)."
    ),
    no_vulns: bool = typer.Option(
        False, "--no-vulns", help="Skip the OSV vulnerability scan."
    ),
    only_issues: bool = typer.Option(
        False, "--only-issues", help="Show only packages with a problem."
    ),
) -> None:
    """Check packages for conflicts, outdated/deprecated status, and CVEs."""
    graph = _load_graph(lockfile, path)
    if len(graph) == 0:
        err_console.print("[yellow]No packages found to check.[/]")
        raise typer.Exit(code=1)

    conflicts = parser.find_conflicts(graph)

    vulns: dict = {}
    if not offline and not no_vulns:
        with console.status("Scanning OSV for vulnerabilities…"):
            vulns = security.scan(list(parser.iter_package_names(graph)))

    with console.status("Checking package health on PyPI…", spinner="dots"):
        reports = checker.build_reports(
            graph,
            vulnerabilities=vulns,
            conflicts=conflicts,
            check_pypi=not offline,
        )

    console.print(report.health_table(reports, only_issues=only_issues))

    n_vuln = sum(1 for r in reports if r.vulnerabilities)
    if conflicts:
        console.print(f"[red]✗ {len(conflicts)} version conflict(s).[/]")
    if n_vuln:
        console.print(f"[bold red]✗ {n_vuln} vulnerable package(s).[/]")
    if conflicts or n_vuln:
        console.print("[dim]Run [bold]pytangle suggest[/] for fixes.[/]")
        raise typer.Exit(code=1)
    console.print("[green]✓ No conflicts or known vulnerabilities.[/]")


@app.command()
def suggest(
    lockfile: Optional[Path] = typer.Option(
        None, "--lockfile", "-l", help="Parse a specific lockfile instead of the env."
    ),
    path: Path = typer.Option(
        Path("."), "--path", "-p", help="Directory to scan for lockfiles."
    ),
    no_vulns: bool = typer.Option(
        False, "--no-vulns", help="Skip vulnerability-driven suggestions."
    ),
) -> None:
    """Suggest the safest commands to resolve conflicts and vulnerabilities."""
    graph = _load_graph(lockfile, path)
    conflicts = parser.find_conflicts(graph)

    vulns: dict = {}
    if not no_vulns:
        with console.status("Scanning OSV for vulnerabilities…"):
            vulns = security.scan(list(parser.iter_package_names(graph)))

    reports = checker.build_reports(
        graph, vulnerabilities=vulns, conflicts=conflicts, check_pypi=False
    )

    with console.status("Solving constraints…", spinner="dots"):
        suggestions = resolver.suggest_fixes(conflicts, reports)

    if not suggestions:
        console.print("[green]✓ Nothing to fix — your environment looks healthy.[/]")
        return
    console.print(report.suggestions_table(suggestions))
    console.print(
        "[dim]Review each command before running it. PyTangle never modifies "
        "your environment automatically.[/]"
    )


if __name__ == "__main__":  # pragma: no cover
    app()
