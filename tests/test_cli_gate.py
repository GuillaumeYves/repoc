"""CLI exit-code behaviour for the --fail-on CI gate."""

from typer.testing import CliRunner

from repoc.cli import app

runner = CliRunner()


def _write(tmp_path, name, content):
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_fail_on_high_trips_on_eval(tmp_path):
    _write(tmp_path, "app.py", "def f(s):\n    return eval(s)\n")
    result = runner.invoke(app, ["inspect", str(tmp_path), "--local", "--fail-on", "high"])
    assert result.exit_code == 1


def test_fail_on_critical_ignores_high_eval(tmp_path):
    _write(tmp_path, "app.py", "def f(s):\n    return eval(s)\n")
    result = runner.invoke(app, ["inspect", str(tmp_path), "--local", "--fail-on", "critical"])
    assert result.exit_code == 0


def test_no_gate_by_default(tmp_path):
    _write(tmp_path, "app.py", "def f(s):\n    return eval(s)\n")
    result = runner.invoke(app, ["inspect", str(tmp_path), "--local"])
    assert result.exit_code == 0


def test_coverage_finding_does_not_trip_gate(tmp_path):
    # Many files + a tiny cap => a partial-scan (COV001, LOW) finding, but the
    # coverage category must never fail a --fail-on gate.
    for i in range(5):
        _write(tmp_path, f"f{i}.py", "x = 1\n")
    result = runner.invoke(
        app,
        ["inspect", str(tmp_path), "--local", "--max-files", "1", "--fail-on", "low"],
    )
    assert result.exit_code == 0


def test_report_includes_coverage_and_version(tmp_path):
    _write(tmp_path, "app.py", "x = 1\n")
    result = runner.invoke(app, ["inspect", str(tmp_path), "--local", "--format", "json"])
    assert result.exit_code == 0
    assert '"repoc_version"' in result.stdout
    assert '"coverage"' in result.stdout
