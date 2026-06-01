# repoc: ignore-file -- test fixtures here include synthetic secrets and risky patterns by design.

import json

from repoc.analyzers.security import scan_files
from repoc.models import Severity
from repoc.utils import redact_secret


def _findings_by_rule(findings):
    return {f.rule_id: f for f in findings}


def test_detects_curl_pipe_bash(make_file):
    files = [make_file("install.sh", "#!/bin/bash\ncurl https://example.com/install.sh | bash\n")]
    findings = scan_files(files)
    assert "SH001" in _findings_by_rule(findings)


def test_detects_python_eval(make_file):
    files = [make_file("app.py", "def run(s):\n    return eval(s)\n")]
    findings = scan_files(files)
    rule_ids = {f.rule_id for f in findings}
    assert "PY001" in rule_ids


def test_detects_install_hook_from_package_json(make_file):
    pkg = json.dumps({"scripts": {"postinstall": "node bad.js"}})
    findings = scan_files([make_file("package.json", pkg)])
    by_id = _findings_by_rule(findings)
    assert "JS100" in by_id
    assert by_id["JS100"].severity == Severity.HIGH


def test_detects_aws_access_key(make_file):
    sample = 'AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n'
    findings = scan_files([make_file("config.py", sample)])
    by_id = _findings_by_rule(findings)
    assert "SEC003" in by_id
    # the literal value must not appear unredacted in the description
    assert "AKIAABCDEFGHIJKLMNOP" not in by_id["SEC003"].description


def test_detects_dockerfile_root_user(make_file):
    files = [make_file("Dockerfile", "FROM ubuntu\nUSER root\nRUN echo hi\n")]
    findings = scan_files(files)
    assert "DK001" in _findings_by_rule(findings)


def test_detects_pull_request_target(make_file):
    workflow = """
name: CI
on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.TOKEN }}
"""
    files = [make_file(".github/workflows/ci.yml", workflow)]
    findings = scan_files(files)
    rule_ids = {f.rule_id for f in findings}
    assert "GH001" in rule_ids
    assert "GH002" in rule_ids  # secret expansion


def test_detects_committed_env_file(make_file):
    files = [make_file(".env", "API_TOKEN=abcdef123456")]
    findings = scan_files(files)
    assert "SEC011" in _findings_by_rule(findings)


def test_inline_ignore_suppresses_matching_rule(make_file):
    source = "def run(s):\n    return eval(s)  # repoc: ignore PY001\n"
    findings = scan_files([make_file("app.py", source)])
    assert "PY001" not in {f.rule_id for f in findings}


def test_inline_ignore_without_rule_id_suppresses_all(make_file):
    source = "def run(s):\n    return eval(s)  # repoc: ignore\n"
    findings = scan_files([make_file("app.py", source)])
    assert findings == []


def test_inline_ignore_does_not_suppress_other_rules(make_file):
    # ignore PY001 only — PY002 (exec) on the next line should still fire
    source = "def a(s):\n    eval(s)  # repoc: ignore PY001\ndef b(s):\n    exec(s)\n"
    findings = scan_files([make_file("app.py", source)])
    rule_ids = {f.rule_id for f in findings}
    assert "PY001" not in rule_ids
    assert "PY002" in rule_ids


def test_file_ignore_marker_skips_whole_file(make_file):
    source = "# repoc: ignore-file\ndef run(s):\n    return eval(s)\n"
    assert scan_files([make_file("app.py", source)]) == []


def test_redact_secret_keeps_prefix_only():
    assert redact_secret("ghp_abcdefghijklmnop").startswith("ghp_")
    assert "abcdefghijklmnop" not in redact_secret("ghp_abcdefghijklmnop")
