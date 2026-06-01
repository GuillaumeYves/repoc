# repoc: ignore-file -- fixtures intentionally contain risky-looking patterns.

"""Findings in test/example/fixture paths should be down-ranked, not silenced."""

from repoc.analyzers.security import is_low_trust_path, scan_files
from repoc.models import Severity


def _by_rule(findings):
    return {f.rule_id: f for f in findings}


def test_is_low_trust_path():
    assert is_low_trust_path("tests/test_app.py")
    assert is_low_trust_path("src/examples/demo.py")
    assert is_low_trust_path("config/settings.py.example")
    assert not is_low_trust_path("src/app.py")


def test_secret_in_test_fixture_is_downranked(make_file):
    src = 'TOKEN = "ghp_' + "a" * 36 + '"\n'
    prod = _by_rule(scan_files([make_file("app.py", src)]))
    test = _by_rule(scan_files([make_file("tests/fixtures.py", src)]))
    assert prod["SEC001"].severity == Severity.CRITICAL
    # One tier down from CRITICAL.
    assert test["SEC001"].severity == Severity.HIGH


def test_eval_in_examples_is_downranked(make_file):
    src = "def f(x):\n    return eval(x)\n"
    prod = _by_rule(scan_files([make_file("app.py", src)]))
    example = _by_rule(scan_files([make_file("examples/demo.py", src)]))
    assert prod["PY001"].severity == Severity.HIGH
    assert example["PY001"].severity == Severity.MEDIUM
