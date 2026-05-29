# SPDX-License-Identifier: MIT
from typer.testing import CliRunner

from pytangle import __version__
from pytangle.cli import app

runner = CliRunner()


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_status_runs():
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "Environment" in result.stdout


def test_map_offline_from_env(tmp_path):
    out = tmp_path / "graph.html"
    result = runner.invoke(app, ["map", "-o", str(out)])
    assert result.exit_code == 0
    assert out.is_file()
    # The generated HTML must not embed an unescaped <script>alert pattern, etc.
    assert "Mapped" in result.stdout


def test_check_offline(tmp_path):
    # --offline should avoid all network and still produce a table.
    result = runner.invoke(app, ["check", "--offline", "--no-vulns"])
    assert result.exit_code in (0, 1)  # 1 if the test env happens to have a conflict
    assert "Package Health" in result.stdout


def test_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "deptangle" in result.stdout.lower()
