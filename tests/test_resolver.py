# SPDX-License-Identifier: MIT
from pytangle import resolver
from pytangle.models import Conflict, Package, PackageReport, Vulnerability
from tests.conftest import FakeResponse, FakeSession


def _pypi_releases(versions):
    return FakeResponse(
        {"releases": {v: [{"yanked": False}] for v in versions}}
    )


def test_conflict_resolved_to_satisfying_version():
    conflict = Conflict(
        package="numpy",
        installed="2.0.0",
        requirements={"pkg-a": "<2.0", "pkg-b": ">=1.21"},
    )
    session = FakeSession(
        get_routes=[("numpy/json", _pypi_releases(["1.21.0", "1.26.4", "2.0.0"]))]
    )
    fixes = resolver.suggest_fixes([conflict], [], session=session)
    assert len(fixes) == 1
    assert fixes[0].target_version == "1.26.4"  # highest that is <2.0 and >=1.21
    assert "uv pip install" in fixes[0].command
    assert fixes[0].confidence == "high"


def test_unsatisfiable_conflict_reports_low_confidence():
    conflict = Conflict(
        package="numpy",
        installed="1.5.0",
        requirements={"pkg-a": ">=2.0", "pkg-b": "<1.0"},
    )
    session = FakeSession(
        get_routes=[("numpy/json", _pypi_releases(["0.9", "2.0.0"]))]
    )
    fixes = resolver.suggest_fixes([conflict], [], session=session)
    assert fixes[0].target_version == "(none)"
    assert fixes[0].confidence == "low"


def test_vulnerability_suggests_fixed_version():
    report = PackageReport(
        package=Package(name="requests", version="2.20.0"),
        vulnerabilities=[
            Vulnerability(id="GHSA-1", fixed_version="2.31.0"),
            Vulnerability(id="GHSA-2", fixed_version="2.32.0"),
        ],
    )
    fixes = resolver.suggest_fixes([], [report], session=FakeSession())
    assert fixes[0].target_version == "2.32.0"  # highest fix covers both
    assert "requests>=2.32.0" in fixes[0].command


def test_vulnerability_without_fix_suggests_upgrade():
    report = PackageReport(
        package=Package(name="requests", version="2.20.0"),
        vulnerabilities=[Vulnerability(id="GHSA-1")],
    )
    fixes = resolver.suggest_fixes([], [report], session=FakeSession())
    assert fixes[0].target_version == "(latest)"
    assert "--upgrade" in fixes[0].command
