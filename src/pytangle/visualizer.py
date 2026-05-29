# SPDX-License-Identifier: MIT
"""Phase 3/4 — render the dependency graph as an interactive HTML network.

Security notes:
  * Every label/title rendered into the HTML is passed through
    :func:`pytangle._safety.safe_label`, which HTML-escapes and length-bounds
    it — a hostile package name in a lockfile cannot inject markup or script.
  * Pyvis is configured with ``cdn_resources="local"`` so the page does not
    pull JavaScript from a third-party CDN at view time.
"""

from __future__ import annotations

import re
from pathlib import Path

from pytangle._safety import safe_label
from pytangle.models import Health, PackageReport
from pytangle.parser import DependencyGraph


def render_graph(
    graph: DependencyGraph,
    output: Path,
    *,
    reports: list[PackageReport] | None = None,
    title: str = "PyTangle dependency map",
) -> Path:
    """Write an interactive HTML visualisation of *graph* to *output*.

    Returns the resolved path actually written. Raises ImportError with a
    helpful message if Pyvis is unavailable.
    """
    try:
        from pyvis.network import Network
    except ImportError as exc:  # pragma: no cover - dependency guaranteed by pyproject
        raise ImportError(
            "Pyvis is required for visualisation. Install with: uv pip install pyvis"
        ) from exc

    health_by_key = {r.package.key: r.health for r in (reports or [])}

    net = Network(
        height="800px",
        width="100%",
        directed=True,
        bgcolor="#1e1e2e",
        font_color="#cdd6f4",
        cdn_resources="in_line",  # embed JS/CSS so the page makes no network calls
        notebook=False,
    )
    net.toggle_physics(True)

    # Count incoming edges to size nodes by how many packages depend on them.
    in_degree: dict[str, int] = {}
    for _dependent, dependency in graph.edges():
        in_degree[dependency] = in_degree.get(dependency, 0) + 1

    for pkg in graph.packages.values():
        health = health_by_key.get(pkg.key, Health.HEALTHY)
        degree = in_degree.get(pkg.key, 0)
        tooltip = (
            f"{safe_label(pkg.name)} {safe_label(pkg.version)} · "
            f"{safe_label(health.value)} · {degree} dependents"
        )
        net.add_node(
            pkg.key,  # canonical key; safe (validated PEP 503 charset)
            label=safe_label(f"{pkg.name}\n{pkg.version}"),
            title=tooltip,
            color=health.color,
            size=12 + min(degree * 3, 40),
        )

    for dependent, dependency in graph.edges():
        net.add_edge(dependent, dependency, color="#585b70")

    net.set_options(
        """
        {
          "interaction": {"hover": true, "tooltipDelay": 120},
          "physics": {
            "barnesHut": {"gravitationalConstant": -8000, "springLength": 120},
            "stabilization": {"iterations": 200}
          }
        }
        """
    )

    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    # open_browser=False: never auto-launch a browser. With cdn_resources=
    # "in_line" the core vis-network library is embedded; we then strip any
    # remaining external <script>/<link> tags (Pyvis hard-codes a cosmetic
    # Bootstrap CDN link) so the file is fully self-contained and issues no
    # outbound network requests — no referrer leak, no offline breakage.
    net.write_html(str(output), open_browser=False, notebook=False)
    html = output.read_text(encoding="utf-8")
    output.write_text(_strip_external_resources(html), encoding="utf-8")
    return output


# Match <script src="http..."></script> and <link ... href="http..." ...> tags
# that reference a remote (http/https or protocol-relative) resource.
_EXTERNAL_SCRIPT_RE = re.compile(
    r"""<script\b[^>]*\bsrc\s*=\s*["'](?:https?:)?//[^"']*["'][^>]*>\s*</script>""",
    re.IGNORECASE,
)
_EXTERNAL_LINK_RE = re.compile(
    r"""<link\b[^>]*\bhref\s*=\s*["'](?:https?:)?//[^"']*["'][^>]*>""",
    re.IGNORECASE,
)


def _strip_external_resources(html: str) -> str:
    """Remove tags that would fetch resources from a remote origin."""
    html = _EXTERNAL_SCRIPT_RE.sub("", html)
    html = _EXTERNAL_LINK_RE.sub("", html)
    return html
