# SPDX-License-Identifier: MIT
import re

from pytangle import visualizer
from pytangle.models import Health, Package, PackageReport
from pytangle.parser import DependencyGraph

_EXTERNAL_REF = re.compile(r"""(?:src|href)\s*=\s*["'](?:https?:)?//""", re.IGNORECASE)


def _graph():
    g = DependencyGraph()
    g.add(Package(name="requests", version="2.31.0", requires=("urllib3>=1.0",)))
    g.add(Package(name="urllib3", version="2.0.7"))
    return g


def test_render_writes_self_contained_html(tmp_path):
    out = tmp_path / "graph.html"
    written = visualizer.render_graph(_graph(), out)
    assert written.is_file()
    html = written.read_text(encoding="utf-8")
    # The whole point of the security hardening: no remote resource fetches.
    assert not _EXTERNAL_REF.search(html), "HTML must not reference remote resources"


def test_render_escapes_malicious_package_name(tmp_path):
    g = DependencyGraph()
    g.add(Package(name="evil", version="<script>alert(1)</script>"))
    out = tmp_path / "graph.html"
    html = visualizer.render_graph(g, out).read_text(encoding="utf-8")
    # The dangerous, executable form must never appear verbatim, and the
    # payload must never sit between unescaped angle brackets (our HTML-escape
    # plus Pyvis's JSON-escape both neutralise it).
    assert "<script>alert(1)</script>" not in html
    assert ">alert(1)<" not in html


def test_render_colors_by_health(tmp_path):
    g = _graph()
    reports = [
        PackageReport(package=g.get("requests"), health=Health.VULNERABLE),
        PackageReport(package=g.get("urllib3"), health=Health.HEALTHY),
    ]
    html = visualizer.render_graph(g, tmp_path / "g.html", reports=reports).read_text()
    assert Health.VULNERABLE.color in html
    assert Health.HEALTHY.color in html


def test_strip_external_resources_unit():
    dirty = (
        '<link href="https://cdn.jsdelivr.net/x.css" rel="stylesheet">'
        '<script src="//cdnjs.cloudflare.com/y.js"></script>'
        '<script>var local = 1;</script>'
    )
    clean = visualizer._strip_external_resources(dirty)
    assert "cdn.jsdelivr" not in clean
    assert "cdnjs" not in clean
    assert "var local = 1;" in clean  # inline script preserved
