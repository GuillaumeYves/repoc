"""Python-language suspicious patterns."""

# repoc: ignore-file -- regex literals here intentionally match the rules themselves.

from __future__ import annotations

from ..models import Severity
from .common import Rule, compile_pattern

PY_GLOBS = ("*.py",)

RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="PY001",
        title="`eval(...)` call",
        severity=Severity.HIGH,
        # Negative lookbehind avoids matching method calls like `df.eval(...)`
        # (pandas/numexpr) which are common and benign.
        pattern=compile_pattern(r"(?<![\w.])eval\s*\("),
        description="`eval` executes arbitrary Python and is rarely needed in production code.",
        recommendation="Replace with `ast.literal_eval` for data, or explicit parsing for expressions.",
        file_globs=PY_GLOBS,
    ),
    Rule(
        rule_id="PY002",
        title="`exec(...)` call",
        severity=Severity.HIGH,
        pattern=compile_pattern(r"(?<![\w.])exec\s*\("),
        description="`exec` runs arbitrary Python at runtime. Confirm the input cannot be attacker-controlled.",
        recommendation="Avoid dynamic code execution where possible.",
        file_globs=PY_GLOBS,
    ),
    Rule(
        rule_id="PY003",
        title="`os.system(...)` call",
        severity=Severity.MEDIUM,
        pattern=compile_pattern(r"\bos\.system\s*\("),
        description="`os.system` runs a command through the shell; user input concatenated here is a classic command-injection bug.",
        recommendation="Prefer `subprocess.run(..., shell=False)` with an argument list.",
        file_globs=PY_GLOBS,
    ),
    Rule(
        rule_id="PY004",
        title="`subprocess` with `shell=True`",
        severity=Severity.MEDIUM,
        pattern=compile_pattern(r"\bsubprocess\.(?:run|call|Popen|check_output)\([^)]*shell\s*=\s*True"),
        description="`shell=True` re-introduces shell-injection risk that subprocess otherwise avoids.",
        recommendation="Pass the command as a list of arguments without `shell=True`.",
        file_globs=PY_GLOBS,
    ),
    Rule(
        rule_id="PY005",
        title="`pickle.loads(...)` / `marshal.loads(...)`",
        severity=Severity.HIGH,
        pattern=compile_pattern(r"\b(?:pickle|marshal)\.loads?\s*\("),
        description="Deserialising untrusted pickle/marshal data leads to arbitrary code execution.",
        recommendation="Use a safe format (JSON, msgpack with allowlist) when the source is not fully trusted.",
        file_globs=PY_GLOBS,
    ),
    Rule(
        rule_id="PY006",
        title="`base64.b64decode(...)`",
        severity=Severity.LOW,
        pattern=compile_pattern(r"\bbase64\.b64decode\s*\("),
        description="Base64 decoding is sometimes used to hide payloads. Confirm the source of the encoded value.",
        recommendation="Verify whether the decoded value is data or executable code.",
        file_globs=PY_GLOBS,
    ),
    Rule(
        rule_id="PY007",
        title="Direct socket usage",
        severity=Severity.LOW,
        pattern=compile_pattern(r"\bsocket\.socket\s*\("),
        description="Direct socket creation can indicate network beacons or reverse shells in suspicious projects.",
        recommendation="Inspect the surrounding code to determine intent.",
        file_globs=PY_GLOBS,
    ),
    Rule(
        rule_id="PY008",
        title="`yaml.load(...)` without `SafeLoader`",
        severity=Severity.HIGH,
        # Flags yaml.load(...) unless a SafeLoader is passed in the same call.
        # `[^)]*` (not `[^)\n]*`) lets the lookahead span a multi-line call so a
        # `Loader=SafeLoader` on a following line is not a false positive.
        pattern=compile_pattern(r"\byaml\.load\s*\((?![^)]*(?:Safe|CSafe)Loader)"),
        description="`yaml.load` with the default loader can construct arbitrary Python objects, leading to code execution.",
        recommendation="Use `yaml.safe_load(...)` or pass `Loader=yaml.SafeLoader`.",
        file_globs=PY_GLOBS,
    ),
    Rule(
        rule_id="PY009",
        title="TLS verification disabled (`verify=False`)",
        severity=Severity.MEDIUM,
        pattern=compile_pattern(r"\bverify\s*=\s*False\b"),
        description="Disabling certificate verification (e.g. on `requests`) exposes traffic to man-in-the-middle attacks.",
        recommendation="Remove `verify=False`; trust the system CA bundle or pin a known certificate.",
        file_globs=PY_GLOBS,
    ),
)
