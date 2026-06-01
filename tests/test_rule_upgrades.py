# repoc: ignore-file -- fixtures intentionally contain risky-looking code.

"""1.0 ruleset upgrades: false-positive fixes + new high-value sinks."""

from repoc.analyzers.security import scan_files


def _ids(findings):
    return {f.rule_id for f in findings}


def _by_id(findings):
    return {f.rule_id: f for f in findings}


# --- False-positive fixes ----------------------------------------------------

def test_python_method_named_eval_not_flagged(make_file):
    src = "import pandas as pd\nresult = df.eval('a + b')\n"
    assert "PY001" not in _ids(scan_files([make_file("a.py", src)]))


def test_python_real_eval_still_flagged(make_file):
    assert "PY001" in _ids(scan_files([make_file("a.py", "x = eval(s)\n")]))


def test_js_method_named_eval_not_flagged(make_file):
    src = "const v = $scope.$eval(expr);\nconst w = obj.eval(x);\n"
    assert "JS001" not in _ids(scan_files([make_file("a.js", src)]))


def test_js_real_eval_still_flagged(make_file):
    assert "JS001" in _ids(scan_files([make_file("a.js", "return eval(s);\n")]))


# --- Python new sinks --------------------------------------------------------

def test_python_yaml_load_without_safeloader(make_file):
    assert "PY008" in _ids(scan_files([make_file("a.py", "data = yaml.load(raw)\n")]))


def test_python_yaml_load_with_safeloader_ok(make_file):
    src = "data = yaml.load(raw, Loader=yaml.SafeLoader)\n"
    assert "PY008" not in _ids(scan_files([make_file("a.py", src)]))


def test_python_safe_load_ok(make_file):
    assert "PY008" not in _ids(scan_files([make_file("a.py", "data = yaml.safe_load(raw)\n")]))


def test_python_yaml_load_multiline_safeloader_ok(make_file):
    # Regression (#5): SafeLoader on a following line must not be a false positive.
    src = "data = yaml.load(\n    stream,\n    Loader=yaml.SafeLoader,\n)\n"
    assert "PY008" not in _ids(scan_files([make_file("a.py", src)]))


def test_python_verify_false(make_file):
    assert "PY009" in _ids(scan_files([make_file("a.py", "requests.get(u, verify=False)\n")]))


# --- JavaScript new sinks ----------------------------------------------------

def test_js_inner_html_sink(make_file):
    assert "JS006" in _ids(scan_files([make_file("a.js", "el.innerHTML = userInput;\n")]))


def test_js_inner_html_append_sink(make_file):
    assert "JS006" in _ids(scan_files([make_file("a.js", "el.innerHTML += userInput;\n")]))


def test_js_inner_html_comparison_not_flagged(make_file):
    # Regression (#3): reading/comparing innerHTML is not an assignment sink.
    assert "JS006" not in _ids(scan_files([make_file("a.js", "if (el.innerHTML === stored) {}\n")]))


def test_js_settimeout_string(make_file):
    assert "JS007" in _ids(scan_files([make_file("a.js", "setTimeout('doStuff()', 100);\n")]))


def test_js_settimeout_function_ok(make_file):
    assert "JS007" not in _ids(scan_files([make_file("a.js", "setTimeout(doStuff, 100);\n")]))


def test_js_settimeout_method_call_not_flagged(make_file):
    # Regression (#6): a custom obj.setTimeout(...) is not the global timer.
    assert "JS007" not in _ids(scan_files([make_file("a.js", "this.setTimeout('x', 5);\n")]))


# --- Ruby new sinks ----------------------------------------------------------

def test_ruby_marshal_load(make_file):
    assert "RB006" in _ids(scan_files([make_file("a.rb", "obj = Marshal.load(blob)\n")]))


def test_ruby_yaml_load(make_file):
    assert "RB007" in _ids(scan_files([make_file("a.rb", "cfg = YAML.load(text)\n")]))


# --- PHP new sinks -----------------------------------------------------------

def test_php_extract_superglobal(make_file):
    assert "PHP007" in _ids(scan_files([make_file("a.php", "<?php extract($_GET);\n")]))


def test_php_create_function(make_file):
    src = "<?php $f = create_function('$x', 'return $x;');\n"
    assert "PHP008" in _ids(scan_files([make_file("a.php", src)]))


def test_php_assert_string(make_file):
    assert "PHP009" in _ids(scan_files([make_file("a.php", "<?php assert(\"1 == 1\");\n")]))


# --- Shell / Docker / GitHub Actions ----------------------------------------

def test_shell_insecure_tls(make_file):
    src = "#!/bin/bash\ncurl -k https://example.com/install.sh\n"
    assert "SH008" in _ids(scan_files([make_file("setup.sh", src)]))


def test_docker_latest_tag(make_file):
    assert "DK005" in _ids(scan_files([make_file("Dockerfile", "FROM python:latest\nRUN echo hi\n")]))


def _gh_run(expr: str):
    workflow = (
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        f"      - run: echo \"{expr}\"\n"
    )
    return _ids(scan_files([_make_yaml(workflow)]))


def _make_yaml(content):
    from repoc.models import RepoFile

    return RepoFile(path=".github/workflows/ci.yml", content=content)


def test_gh_actions_script_injection_pr_title(make_file):
    assert "GH006" in _gh_run("${{ github.event.pull_request.title }}")


def test_gh_actions_script_injection_commit_message(make_file):
    assert "GH006" in _gh_run("${{ github.event.head_commit.message }}")


def test_gh_actions_script_injection_comment_body(make_file):
    assert "GH006" in _gh_run("${{ github.event.comment.body }}")


def test_gh_actions_benign_repository_name_not_flagged(make_file):
    # Regression (#4): repository.name is not attacker-controlled.
    assert "GH006" not in _gh_run("${{ github.event.repository.name }}")


def test_gh_actions_benign_sender_login_not_flagged(make_file):
    assert "GH006" not in _gh_run("${{ github.event.repository.default_branch }}")
