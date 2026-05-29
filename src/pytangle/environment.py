# SPDX-License-Identifier: MIT
"""Phase 2 — environment diagnostics for ``pytangle status``."""

from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import dataclass

from rich.panel import Panel
from rich.table import Table


@dataclass
class EnvironmentInfo:
    """A snapshot of the active Python interpreter and environment."""

    executable: str
    version: str
    implementation: str
    platform: str
    prefix: str
    base_prefix: str
    in_virtualenv: bool
    virtual_env_var: str | None
    uv_path: str | None
    uv_version: str | None


def _detect_uv() -> tuple[str | None, str | None]:
    """Locate ``uv`` and read its version (best-effort, never raises)."""
    path = shutil.which("uv")
    if path is None:
        return None, None
    # Local import avoids a hard dependency cycle and keeps import time low.
    from pytangle._safety import CommandError, run_command

    try:
        proc = run_command(["uv", "--version"], timeout=10)
    except CommandError:
        return path, None
    return path, proc.stdout.strip() or None


def collect() -> EnvironmentInfo:
    """Gather diagnostics about the running interpreter and environment."""
    # ``sys.prefix != sys.base_prefix`` is the canonical venv signal (PEP 405);
    # the VIRTUAL_ENV variable is a secondary, user-visible hint.
    in_venv = sys.prefix != sys.base_prefix
    uv_path, uv_version = _detect_uv()
    impl = sys.implementation.name
    return EnvironmentInfo(
        executable=sys.executable or "<unknown>",
        version=platform.python_version(),
        implementation=impl,
        platform=platform.platform(),
        prefix=sys.prefix,
        base_prefix=sys.base_prefix,
        in_virtualenv=in_venv,
        virtual_env_var=os.environ.get("VIRTUAL_ENV"),
        uv_path=uv_path,
        uv_version=uv_version,
    )


def render(info: EnvironmentInfo) -> Panel:
    """Build a Rich panel summarising the environment."""
    table = Table.grid(padding=(0, 2))
    table.add_column(justify="right", style="bold cyan")
    table.add_column()

    venv_status = (
        "[bold green]active[/]" if info.in_virtualenv else "[bold yellow]not detected[/]"
    )
    table.add_row("Python", f"{info.version} ({info.implementation})")
    table.add_row("Interpreter", info.executable)
    table.add_row("Platform", info.platform)
    table.add_row("Virtualenv", venv_status)
    if info.virtual_env_var:
        table.add_row("VIRTUAL_ENV", info.virtual_env_var)
    table.add_row("Prefix", info.prefix)
    if info.in_virtualenv:
        table.add_row("Base prefix", info.base_prefix)

    if info.uv_path:
        uv_text = f"[green]{info.uv_version or 'found'}[/]  [dim]({info.uv_path})[/]"
    else:
        uv_text = "[yellow]not installed — falling back to importlib.metadata[/]"
    table.add_row("uv engine", uv_text)

    return Panel(
        table,
        title="[bold]PyTangle · Environment[/]",
        border_style="cyan",
        expand=False,
    )
