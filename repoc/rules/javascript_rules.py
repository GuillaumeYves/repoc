"""JavaScript / TypeScript suspicious patterns."""

# repoc: ignore-file -- regex literals here intentionally match the rules themselves.

from __future__ import annotations

from ..models import Severity
from .common import Rule, compile_pattern

JS_GLOBS = ("*.js", "*.mjs", "*.cjs", "*.jsx", "*.ts", "*.tsx")

RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="JS001",
        title="`eval(...)` call",
        severity=Severity.HIGH,
        # Lookbehind avoids method calls like `foo.eval(` and AngularJS `$scope.$eval(`.
        pattern=compile_pattern(r"(?<![\w.$])eval\s*\("),
        description="`eval` executes arbitrary JavaScript.",
        recommendation="Replace with safer parsing (JSON.parse, dedicated parsers).",
        file_globs=JS_GLOBS,
    ),
    Rule(
        rule_id="JS002",
        title="`new Function(...)` call",
        severity=Severity.HIGH,
        pattern=compile_pattern(r"\bnew\s+Function\s*\("),
        description="`new Function()` is equivalent to eval: it compiles arbitrary code at runtime.",
        recommendation="Refactor to avoid dynamic code generation.",
        file_globs=JS_GLOBS,
    ),
    Rule(
        rule_id="JS003",
        title="`child_process.exec` / `spawn`",
        severity=Severity.MEDIUM,
        pattern=compile_pattern(r"\bchild_process\.(?:exec|execSync|spawn|spawnSync)\b"),
        description="Spawning child processes with user input is a common command-injection sink.",
        recommendation="Validate inputs and prefer the array form of `spawn` over `exec` for untrusted data.",
        file_globs=JS_GLOBS,
    ),
    Rule(
        rule_id="JS004",
        title="`fs.rm` / `fs.unlink` on dynamic paths",
        severity=Severity.LOW,
        pattern=compile_pattern(r"\bfs\.(?:rm|unlink|rmSync|unlinkSync)\s*\("),
        description="Filesystem deletion APIs were found.",
        recommendation="Confirm paths cannot be attacker-controlled.",
        file_globs=JS_GLOBS,
    ),
    Rule(
        rule_id="JS005",
        title="`Buffer.from(..., 'base64')`",
        severity=Severity.LOW,
        pattern=compile_pattern(r"\bBuffer\.from\s*\([^)]*,\s*['\"]base64['\"]\s*\)"),
        description="Decoding base64 to bytes is sometimes used to obfuscate payloads.",
        recommendation="Inspect the decoded content.",
        file_globs=JS_GLOBS,
    ),
    Rule(
        rule_id="JS006",
        title="DOM XSS sink (`innerHTML` / `document.write` / `insertAdjacentHTML`)",
        severity=Severity.LOW,
        # `=(?!=)` matches assignment (incl. `+=`) but not `==`/`===` comparisons,
        # so reading/comparing innerHTML is not flagged.
        pattern=compile_pattern(
            r"\.(?:inner|outer)HTML\s*\+?=(?!=)|\bdocument\.write(?:ln)?\s*\(|\.insertAdjacentHTML\s*\("
        ),
        description="Assigning to these sinks renders raw HTML; with untrusted input it is a cross-site scripting vector.",
        recommendation="Set text via `textContent`, or sanitize HTML with a vetted library before injecting it.",
        file_globs=JS_GLOBS,
    ),
    Rule(
        rule_id="JS007",
        title="`setTimeout` / `setInterval` with a string argument",
        severity=Severity.MEDIUM,
        # Lookbehind avoids method calls like `obj.setTimeout(...)`.
        pattern=compile_pattern(r"(?<![\w.])(?:setTimeout|setInterval)\s*\(\s*['\"`]"),
        description="Passing a string to these functions evaluates it like `eval`.",
        recommendation="Pass a function reference instead of a string.",
        file_globs=JS_GLOBS,
    ),
)

# NB: npm install-hook findings (JS100) are produced in analyzers/security.py
# from the parsed package.json scripts, not from a regex rule here.
