# repoc: ignore-file -- fixtures intentionally contain risky-looking PHP.

"""PHP code-pattern detection (with comment/string masking)."""

from repoc.analyzers.security import scan_files


def _ids(findings):
    return {f.rule_id for f in findings}


def test_detects_php_eval(make_file):
    src = "<?php\nfunction run($s){ return eval($s); }\n"
    assert "PHP001" in _ids(scan_files([make_file("app.php", src)]))


def test_detects_php_command_exec(make_file):
    src = "<?php\n$out = shell_exec($cmd);\n"
    assert "PHP002" in _ids(scan_files([make_file("app.php", src)]))


def test_detects_php_unserialize(make_file):
    src = "<?php\n$obj = unserialize($_GET['data']);\n"
    assert "PHP003" in _ids(scan_files([make_file("app.php", src)]))


def test_benign_dynamic_include_is_low_not_lfi(make_file):
    # An autoloader / view renderer including a computed path: PHP005 (LOW),
    # NOT the HIGH LFI rule.
    src = "<?php\nfunction load($file){ require $file; }\n"
    findings = {f.rule_id: f for f in scan_files([make_file("src/autoload.php", src)])}
    assert "PHP005" in findings
    assert findings["PHP005"].severity.value == "low"
    assert "PHP006" not in findings


def test_request_controlled_include_is_high_lfi(make_file):
    src = "<?php\ninclude $_GET['page'] . '.php';\n"
    findings = {f.rule_id: f for f in scan_files([make_file("app.php", src)])}
    assert "PHP006" in findings
    assert findings["PHP006"].severity.value == "high"
    # The benign LOW rule should not double-report the same superglobal include.
    assert "PHP005" not in findings


def test_php_eval_in_comment_is_not_flagged(make_file):
    src = "<?php\n# do not use eval($x)\n// or eval here either\n$y = 1;\n"
    assert "PHP001" not in _ids(scan_files([make_file("app.php", src)]))


def test_php_eval_in_string_is_not_flagged(make_file):
    src = "<?php\n$msg = 'never call eval( on input';\n"
    assert "PHP001" not in _ids(scan_files([make_file("app.php", src)]))


def test_php_method_named_eval_is_not_flagged(make_file):
    # $this->evaluate( should not match the bare eval( rule.
    src = "<?php\n$r = $this->evaluate($expr);\n"
    assert "PHP001" not in _ids(scan_files([make_file("app.php", src)]))
