# SPDX-License-Identifier: MIT
import pytest

from pytangle import _safety
from pytangle._safety import (
    CommandError,
    SafetyError,
    is_valid_package_name,
    is_valid_version,
    run_command,
    safe_label,
    validate_url,
)


@pytest.mark.parametrize(
    "name,ok",
    [
        ("requests", True),
        ("Flask-SQLAlchemy", True),
        ("zope.interface", True),
        ("", False),
        ("../evil", False),
        ("name with space", False),
        ("a" * 200, False),
        (123, False),
    ],
)
def test_is_valid_package_name(name, ok):
    assert is_valid_package_name(name) is ok


@pytest.mark.parametrize(
    "version,ok",
    [("1.2.3", True), ("2.0.0rc1", True), ("1!2.0", True), ("", False), ("a b", False)],
)
def test_is_valid_version(version, ok):
    assert is_valid_version(version) is ok


def test_safe_label_escapes_html():
    out = safe_label("<script>alert(1)</script>")
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_safe_label_truncates():
    assert len(safe_label("x" * 500, max_len=20)) <= 20


@pytest.mark.parametrize(
    "url",
    [
        "http://pypi.org/x",  # not https
        "https://evil.com/x",  # not allowlisted
        "https://user:pw@pypi.org/x",  # credentials
        "https://127.0.0.1/x",  # IP literal
        "https://169.254.169.254/latest",  # metadata SSRF
        "https://pypi.org:8080/x",  # non-standard port
    ],
)
def test_validate_url_rejects_bad(url):
    with pytest.raises(SafetyError):
        validate_url(url)


def test_validate_url_accepts_allowlisted():
    assert validate_url("https://api.osv.dev/v1/query") == "https://api.osv.dev/v1/query"


def test_run_command_rejects_string():
    with pytest.raises(CommandError):
        run_command("echo hi")  # type: ignore[arg-type]


def test_run_command_missing_executable():
    with pytest.raises(CommandError):
        run_command(["definitely-not-a-real-binary-xyz"])


def test_run_command_success():
    proc = run_command(["python", "-c", "print('ok')"], timeout=10)
    assert proc.returncode == 0
    assert "ok" in proc.stdout


def test_run_command_check_raises_on_failure():
    with pytest.raises(CommandError):
        run_command(["python", "-c", "import sys; sys.exit(3)"], timeout=10)


def test_scrubbed_env_has_minimal_keys():
    env = _safety._scrubbed_env({"EXTRA": "1"})
    assert "PATH" in env
    assert env["EXTRA"] == "1"
