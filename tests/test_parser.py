# SPDX-License-Identifier: MIT
import pytest

from pytangle import parser
from pytangle.models import Package
from pytangle.parser import DependencyGraph

UV_LOCK = """
version = 1

[[package]]
name = "requests"
version = "2.31.0"
dependencies = [
    { name = "urllib3" },
    { name = "idna" },
]

[[package]]
name = "urllib3"
version = "2.0.7"

[[package]]
name = "idna"
version = "3.4"
"""

POETRY_LOCK = """
[[package]]
name = "flask"
version = "3.0.0"
description = "A web framework"

[package.dependencies]
werkzeug = ">=3.0"
jinja2 = ">=3.1"

[[package]]
name = "werkzeug"
version = "3.0.1"
"""

PIPFILE_LOCK = """
{
  "_meta": {"hash": {"sha256": "x"}},
  "default": {
    "django": {"version": "==4.2.0"},
    "sqlparse": {"version": "==0.4.4"}
  },
  "develop": {
    "pytest": {"version": "==8.0.0"}
  }
}
"""


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content)
    return p


def test_parse_uv_lock(tmp_path):
    g = parser.load_lockfile(_write(tmp_path, "uv.lock", UV_LOCK))
    assert g.source == "uv.lock"
    assert len(g) == 3
    req = g.get("requests")
    assert req is not None
    assert req.version == "2.31.0"
    assert set(req.requires) == {"urllib3", "idna"}
    assert ("requests", "urllib3") in g.edges()


def test_parse_poetry_lock(tmp_path):
    g = parser.load_lockfile(_write(tmp_path, "poetry.lock", POETRY_LOCK))
    assert g.source == "poetry.lock"
    flask = g.get("flask")
    assert flask is not None
    assert set(flask.requires) == {"werkzeug", "jinja2"}


def test_parse_pipfile_lock(tmp_path):
    g = parser.load_lockfile(_write(tmp_path, "Pipfile.lock", PIPFILE_LOCK))
    assert g.source == "Pipfile.lock"
    assert len(g) == 3
    assert g.get("django").version == "4.2.0"
    assert g.get("pytest").version == "8.0.0"


def test_discover_prefers_uv_lock(tmp_path):
    _write(tmp_path, "uv.lock", UV_LOCK)
    _write(tmp_path, "poetry.lock", POETRY_LOCK)
    found = parser.discover_lockfiles(tmp_path)
    assert found[0].name == "uv.lock"


def test_oversized_lockfile_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(parser, "_MAX_LOCKFILE_BYTES", 10)
    p = _write(tmp_path, "uv.lock", UV_LOCK)
    with pytest.raises(ValueError):
        parser.load_lockfile(p)


def test_unsupported_lockfile(tmp_path):
    p = _write(tmp_path, "weird.lock", "{}")
    with pytest.raises(ValueError):
        parser.load_lockfile(p)


def test_find_conflicts_detects_violation():
    g = DependencyGraph()
    g.add(Package(name="numpy", version="2.0.0"))
    g.add(Package(name="pkg-a", version="1.0", requires=("numpy<2.0",)))
    g.add(Package(name="pkg-b", version="1.0", requires=("numpy>=1.20",)))
    conflicts = parser.find_conflicts(g)
    assert len(conflicts) == 1
    c = conflicts[0]
    assert c.package == "numpy"
    assert c.installed == "2.0.0"
    assert "pkg-a" in c.requirements
    assert "pkg-b" not in c.requirements  # numpy 2.0 satisfies >=1.20


def test_find_conflicts_none_when_satisfied():
    g = DependencyGraph()
    g.add(Package(name="numpy", version="1.26.0"))
    g.add(Package(name="pkg-a", version="1.0", requires=("numpy<2.0",)))
    assert parser.find_conflicts(g) == []
