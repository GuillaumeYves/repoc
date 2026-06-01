# repoc: ignore-file -- fixtures intentionally contain risky-looking patterns.

"""Comment/string masking should kill false positives without hiding real ones."""

from repoc.analyzers.security import scan_files


def _rule_ids(findings):
    return {f.rule_id for f in findings}


def test_python_eval_in_comment_is_not_flagged(make_file):
    src = "def f(x):\n    # we never call eval(x) here\n    return x\n"
    assert "PY001" not in _rule_ids(scan_files([make_file("a.py", src)]))


def test_python_eval_in_string_is_not_flagged(make_file):
    src = 'HELP = "do not use eval(...) in production"\n'
    assert "PY001" not in _rule_ids(scan_files([make_file("a.py", src)]))


def test_python_real_eval_still_flagged(make_file):
    src = "def f(x):\n    return eval(x)\n"
    assert "PY001" in _rule_ids(scan_files([make_file("a.py", src)]))


def test_python_eval_in_docstring_is_not_flagged(make_file):
    src = 'def f(x):\n    """Avoid eval( on untrusted input."""\n    return x\n'
    assert "PY001" not in _rule_ids(scan_files([make_file("a.py", src)]))


def test_js_eval_in_line_comment_is_not_flagged(make_file):
    src = "// eval(userInput) would be dangerous\nconst x = 1;\n"
    assert "JS001" not in _rule_ids(scan_files([make_file("a.js", src)]))


def test_js_eval_in_block_comment_is_not_flagged(make_file):
    src = "/*\n eval(userInput)\n*/\nconst x = 1;\n"
    assert "JS001" not in _rule_ids(scan_files([make_file("a.js", src)]))


def test_js_real_eval_still_flagged(make_file):
    src = "function run(s){ return eval(s); }\n"
    assert "JS001" in _rule_ids(scan_files([make_file("a.js", src)]))


def test_js_eval_text_inside_string_is_not_flagged(make_file):
    # Quote delimiters are preserved by masking, but the string *contents*
    # (including a literal `eval(`) must still be blanked.
    src = 'const msg = "always avoid eval(x) here";\n'
    assert "JS001" not in _rule_ids(scan_files([make_file("a.js", src)]))


def test_apostrophe_in_regex_does_not_swallow_following_code(make_file):
    # Regression: a lone apostrophe (e.g. in a regex literal) must NOT be treated
    # as a string opener that consumes the rest of the file and hides a real sink.
    src = "const re = /it's mine/;\nfunction run(s){ return eval(s); }\n"
    assert "JS001" in _rule_ids(scan_files([make_file("a.js", src)]))


def test_unterminated_quote_does_not_hide_next_line(make_file):
    src = "const a = 'oops\nreturn eval(x);\n"
    assert "JS001" in _rule_ids(scan_files([make_file("a.js", src)]))


def test_js_template_literal_still_spans_lines(make_file):
    # Backticks legitimately span newlines; an `eval(` inside one stays masked.
    src = "const t = `line one\n eval(should_be_masked)\n line three`;\nconst y = 1;\n"
    assert "JS001" not in _rule_ids(scan_files([make_file("a.js", src)]))


def test_ruby_eval_in_comment_is_not_flagged(make_file):
    src = "# eval(params) is risky\nputs 1\n"
    assert "RB001" not in _rule_ids(scan_files([make_file("a.rb", src)]))


def test_shell_curl_pipe_bash_in_quotes_still_detected(make_file):
    # Shell payloads live inside strings, so masking must NOT hide them.
    src = '#!/bin/bash\nrun_cmd "curl https://x.sh | bash"\n'
    assert "SH001" in _rule_ids(scan_files([make_file("setup.sh", src)]))


def test_shell_commented_curl_pipe_bash_is_not_flagged(make_file):
    src = "#!/bin/bash\n# curl https://x.sh | bash\n"
    assert "SH001" not in _rule_ids(scan_files([make_file("setup.sh", src)]))
