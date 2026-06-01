"""Ruby suspicious patterns."""

# repoc: ignore-file -- regex literals here intentionally match the rules themselves.

from __future__ import annotations

from ..models import Severity
from .common import Rule, compile_pattern

RB_GLOBS = ("*.rb", "Rakefile", "Gemfile")

RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="RB001",
        title="`eval` call",
        severity=Severity.HIGH,
        pattern=compile_pattern(r"(?<![\w.])eval\s*\("),
        description="`eval` runs arbitrary Ruby code.",
        recommendation="Replace with explicit logic.",
        file_globs=RB_GLOBS,
    ),
    Rule(
        rule_id="RB002",
        title="`system` / `exec` / backticks / `%x()`",
        severity=Severity.MEDIUM,
        pattern=compile_pattern(r"(?<![\w.])(?:system|exec)\s*\(|%x\{|`[^`]+`"),
        description="Command-execution primitives were found.",
        recommendation="Validate any user-controlled input passed to these calls.",
        file_globs=RB_GLOBS,
    ),
    Rule(
        rule_id="RB003",
        title="`Open3.capture*`",
        severity=Severity.LOW,
        pattern=compile_pattern(r"\bOpen3\.capture[23]?\b"),
        description="`Open3.capture*` runs a subprocess. Confirm inputs are safe.",
        recommendation="Use the argument-array form rather than building shell strings.",
        file_globs=RB_GLOBS,
    ),
    Rule(
        rule_id="RB004",
        title="`Base64.decode64`",
        severity=Severity.LOW,
        pattern=compile_pattern(r"\bBase64\.decode64\b"),
        description="Base64 decoding can be used to hide payloads.",
        recommendation="Verify the source and decoded contents.",
        file_globs=RB_GLOBS,
    ),
    Rule(
        rule_id="RB005",
        title="`Net::HTTP` request to runtime-supplied URL",
        severity=Severity.INFO,
        pattern=compile_pattern(r"\bNet::HTTP\."),
        description="The code performs HTTP requests; review whether destinations are constants or user-controlled.",
        recommendation="Pin URLs to constants or validate before request.",
        file_globs=RB_GLOBS,
    ),
    Rule(
        rule_id="RB006",
        title="`Marshal.load(...)`",
        severity=Severity.HIGH,
        pattern=compile_pattern(r"\bMarshal\.load\b"),
        description="Deserialising untrusted Marshal data instantiates arbitrary Ruby objects and can lead to code execution.",
        recommendation="Never `Marshal.load` data from an untrusted source; use JSON for external data.",
        file_globs=RB_GLOBS,
    ),
    Rule(
        rule_id="RB007",
        title="`YAML.load(...)` / `Psych.load(...)`",
        severity=Severity.MEDIUM,
        pattern=compile_pattern(r"\b(?:YAML|Psych)\.load\b"),
        description="On older Ruby/Psych, `YAML.load` can build arbitrary objects from untrusted input.",
        recommendation="Use `YAML.safe_load` (or `Psych.safe_load`) for untrusted YAML.",
        file_globs=RB_GLOBS,
    ),
)
