# SPDX-License-Identifier: MIT
from pytangle import checker
from pytangle.models import Conflict, Health, Package, Vulnerability
from pytangle.parser import DependencyGraph
from tests.conftest import FakeResponse, FakeSession


def _graph(*pkgs):
    g = DependencyGraph()
    for p in pkgs:
        g.add(p)
    return g


def test_outdated_detection():
    g = _graph(Package(name="requests", version="2.20.0"))
    session = FakeSession(
        get_routes=[
            ("requests/json", FakeResponse({"info": {"version": "2.32.0"}, "releases": {}}))
        ]
    )
    reports = checker.build_reports(g, session=session)
    assert reports[0].health is Health.OUTDATED
    assert reports[0].latest_version == "2.32.0"


def test_yanked_release_is_deprecated():
    g = _graph(Package(name="badpkg", version="1.0.0"))
    session = FakeSession(
        get_routes=[
            (
                "badpkg/json",
                FakeResponse(
                    {
                        "info": {"version": "1.0.0"},
                        "releases": {"1.0.0": [{"yanked": True}]},
                    }
                ),
            )
        ]
    )
    reports = checker.build_reports(g, session=session)
    assert reports[0].is_yanked is True
    assert reports[0].health is Health.DEPRECATED


def test_vulnerability_outranks_outdated():
    g = _graph(Package(name="requests", version="2.20.0"))
    session = FakeSession(
        get_routes=[
            ("requests/json", FakeResponse({"info": {"version": "2.32.0"}, "releases": {}}))
        ]
    )
    vulns = {"requests": [Vulnerability(id="GHSA-1")]}
    reports = checker.build_reports(g, vulnerabilities=vulns, session=session)
    assert reports[0].health is Health.VULNERABLE


def test_conflict_marked():
    g = _graph(Package(name="numpy", version="2.0.0"))
    conflicts = [Conflict(package="numpy", installed="2.0.0", requirements={"a": "<2.0"})]
    reports = checker.build_reports(
        g, conflicts=conflicts, check_pypi=False
    )
    assert reports[0].health is Health.CONFLICT


def test_reports_sorted_worst_first():
    g = _graph(
        Package(name="healthy", version="1.0"),
        Package(name="vuln", version="1.0"),
    )
    vulns = {"vuln": [Vulnerability(id="GHSA-1")]}
    reports = checker.build_reports(g, vulnerabilities=vulns, check_pypi=False)
    assert reports[0].package.name == "vuln"
