# SPDX-License-Identifier: MIT
from pytangle import security
from tests.conftest import FakeResponse, FakeSession


def test_scan_skips_invalid_inputs():
    # Invalid name / version pairs must never reach OSV.
    result = security.scan([("../evil", "1.0"), ("requests", "not a version")])
    assert result == {}


def test_scan_maps_vulnerabilities():
    batch = FakeResponse(
        {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-xxxx",
                            "summary": "Bad bug",
                            "aliases": ["CVE-2024-0001"],
                            "affected": [
                                {"ranges": [{"events": [{"fixed": "2.32.0"}]}]}
                            ],
                        }
                    ]
                },
                {},  # second package: no vulns
            ]
        }
    )
    session = FakeSession(post_routes=[("querybatch", batch)])
    result = security.scan(
        [("requests", "2.20.0"), ("idna", "3.4")], session=session
    )
    assert "requests" in result
    assert "idna" not in result
    vuln = result["requests"][0]
    assert vuln.id == "GHSA-xxxx"
    assert vuln.fixed_version == "2.32.0"
    assert "CVE-2024-0001" in vuln.aliases


def test_scan_handles_non_200():
    session = FakeSession(post_routes=[("querybatch", FakeResponse(None, 500))])
    assert security.scan([("requests", "2.20.0")], session=session) == {}


def test_collect_aliases_dedupes():
    from pytangle.models import Vulnerability

    vulns = [
        Vulnerability(id="GHSA-1", aliases=("CVE-1", "CVE-2")),
        Vulnerability(id="GHSA-2", aliases=("CVE-2",)),
    ]
    aliases = security.collect_aliases(vulns)
    assert aliases.count("CVE-2") == 1
    assert "GHSA-1" in aliases and "GHSA-2" in aliases
