"""PHP suspicious patterns."""

# repoc: ignore-file -- regex literals here intentionally match the rules themselves.

from __future__ import annotations

from ..models import Severity
from .common import Rule, compile_pattern

PHP_GLOBS = ("*.php", "*.phtml", "*.php5", "*.phps")


RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="PHP001",
        title="`eval(...)` call",
        severity=Severity.HIGH,
        pattern=compile_pattern(r"(?<![\w$>])eval\s*\("),
        description="`eval` executes arbitrary PHP at runtime.",
        recommendation="Remove dynamic code execution; parse data explicitly instead.",
        file_globs=PHP_GLOBS,
    ),
    Rule(
        rule_id="PHP002",
        title="Command execution (`system`/`exec`/`shell_exec`/`passthru`/`popen`/`proc_open`)",
        severity=Severity.MEDIUM,
        pattern=compile_pattern(
            r"(?<![\w$>])(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\("
        ),
        description="The code runs an OS command. User input reaching these is a command-injection sink.",
        recommendation="Avoid shelling out with untrusted input; use escapeshellarg/escapeshellcmd or a safe API.",
        file_globs=PHP_GLOBS,
    ),
    Rule(
        rule_id="PHP003",
        title="`unserialize(...)` on possibly untrusted data",
        severity=Severity.HIGH,
        pattern=compile_pattern(r"(?<![\w$>])unserialize\s*\("),
        description="Deserialising untrusted input can trigger PHP object injection and arbitrary code execution.",
        recommendation="Use `json_decode` for data, or pass `['allowed_classes' => false]`.",
        file_globs=PHP_GLOBS,
    ),
    Rule(
        rule_id="PHP004",
        title="`base64_decode(...)`",
        severity=Severity.LOW,
        pattern=compile_pattern(r"(?<![\w$>])base64_decode\s*\("),
        description="Base64 decoding is sometimes used to obfuscate payloads (a common webshell trait).",
        recommendation="Confirm whether the decoded value is data or executable code.",
        file_globs=PHP_GLOBS,
    ),
    Rule(
        rule_id="PHP005",
        title="Dynamic `include`/`require` with a variable",
        # Deliberately LOW: autoloaders and template/view renderers legitimately
        # include from a computed path. It's worth a glance, not an alarm. The
        # genuinely dangerous case (request-controlled path) is PHP006 below.
        severity=Severity.LOW,
        pattern=compile_pattern(
            r"(?<![\w$>])(?:include|require)(?:_once)?\s*\(?\s*\$(?!_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b)"
        ),
        description="A file is included from a variable path. Common and benign in autoloaders/templating; risky only if the path is built from request input.",
        recommendation="Confirm the path is internal (class map / view name), not derived from request input.",
        file_globs=PHP_GLOBS,
    ),
    Rule(
        rule_id="PHP006",
        title="`include`/`require` of a request superglobal (LFI/RFI)",
        severity=Severity.HIGH,
        pattern=compile_pattern(
            r"(?<![\w$>])(?:include|require)(?:_once)?\b[^;\n]*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b"
        ),
        description="A file path passed to include/require comes directly from a request superglobal — a classic local/remote file inclusion sink.",
        recommendation="Never include a path built from request input. Map the input to a fixed allowlist of files.",
        file_globs=PHP_GLOBS,
    ),
    Rule(
        rule_id="PHP007",
        title="`extract(...)` of a request superglobal",
        severity=Severity.HIGH,
        pattern=compile_pattern(r"(?<![\w$>])extract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b"),
        description="`extract` on request data lets an attacker overwrite arbitrary local variables (variable injection).",
        recommendation="Never `extract` request input; read specific keys explicitly.",
        file_globs=PHP_GLOBS,
    ),
    Rule(
        rule_id="PHP008",
        title="`create_function(...)`",
        severity=Severity.HIGH,
        pattern=compile_pattern(r"(?<![\w$>])create_function\s*\("),
        description="`create_function` compiles its argument as PHP code — an eval in disguise (removed in PHP 8).",
        recommendation="Use a real closure (`function () { ... }`) instead.",
        file_globs=PHP_GLOBS,
    ),
    Rule(
        rule_id="PHP009",
        title="`assert(...)` on a string",
        severity=Severity.MEDIUM,
        pattern=compile_pattern(r"(?<![\w$>])assert\s*\(\s*['\"]"),
        description="`assert` evaluates a string argument as PHP code on older versions — another code-execution sink.",
        recommendation="Assert on boolean expressions only; never pass a string built from input.",
        file_globs=PHP_GLOBS,
    ),
)
