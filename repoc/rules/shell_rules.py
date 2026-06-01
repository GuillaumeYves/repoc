"""Shell / generic command-line suspicious patterns."""

# repoc: ignore-file -- regex literals here intentionally match the rules themselves.

from __future__ import annotations

from ..models import Severity
from .common import Rule, compile_pattern

SHELL_GLOBS = ("*.sh", "*.bash", "*.zsh", "Makefile", "makefile", "*.mk", "install.*")

RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="SH001",
        title="`curl ... | bash` pipeline",
        severity=Severity.HIGH,
        pattern=compile_pattern(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:bash|sh|zsh)\b"),
        description="Piping the output of a network fetch directly into a shell executes whatever the remote server returns.",
        recommendation="Download the script, inspect it, then run it explicitly.",
        file_globs=SHELL_GLOBS,
    ),
    Rule(
        rule_id="SH002",
        title="`chmod +x` on downloaded content",
        severity=Severity.LOW,
        pattern=compile_pattern(r"\bchmod\s+\+x\b"),
        description="A script grants execute permission. Confirm the target was obtained from a trusted source.",
        recommendation="Manually review the file being made executable.",
        file_globs=SHELL_GLOBS,
    ),
    Rule(
        rule_id="SH003",
        title="`sudo` usage in script",
        severity=Severity.MEDIUM,
        pattern=compile_pattern(r"(?m)^\s*sudo\b"),
        description="The script escalates privileges. Privileged installers are a common abuse vector.",
        recommendation="Read the elevated commands carefully before executing.",
        file_globs=SHELL_GLOBS,
    ),
    Rule(
        rule_id="SH004",
        title="`rm -rf` on a parameterised path",
        severity=Severity.MEDIUM,
        pattern=compile_pattern(r"\brm\s+-rf?\s+[\$\"\'/~*]"),
        description="A recursive delete operates on a variable, glob, or absolute path. Misconfiguration can wipe unrelated data.",
        recommendation="Inspect the deletion target and ensure paths cannot be empty or attacker-controlled.",
        file_globs=SHELL_GLOBS,
    ),
    Rule(
        rule_id="SH005",
        title="`base64 -d` decoding",
        severity=Severity.MEDIUM,
        pattern=compile_pattern(r"\bbase64\s+(?:-d|--decode)\b"),
        description="Base64 decoding inside a script is sometimes used to obfuscate commands.",
        recommendation="Decode the payload manually and inspect what it contains.",
        file_globs=SHELL_GLOBS,
    ),
    Rule(
        rule_id="SH006",
        title="`eval` of dynamic content",
        severity=Severity.HIGH,
        pattern=compile_pattern(r"\beval\s+[\"'`\$]"),
        description="`eval` executes arbitrary shell. Dynamic input here can lead to command injection.",
        recommendation="Replace `eval` with explicit, well-defined commands.",
        file_globs=SHELL_GLOBS,
    ),
    Rule(
        rule_id="SH007",
        title="Reverse-shell building blocks",
        severity=Severity.CRITICAL,
        pattern=compile_pattern(r"\bnc\s+-[el]e?\b|mkfifo\b|/dev/tcp/"),
        description="Patterns consistent with a reverse shell were found (`nc -e`, `mkfifo`, `/dev/tcp/...`).",
        recommendation="Investigate this file immediately. It may be a deliberate backdoor.",
        file_globs=SHELL_GLOBS,
    ),
    Rule(
        rule_id="SH008",
        title="TLS verification disabled in download",
        severity=Severity.MEDIUM,
        pattern=compile_pattern(
            r"\bcurl\b[^\n|]*\s(?:-k|--insecure)\b|\bwget\b[^\n|]*\s--no-check-certificate\b"
        ),
        description="Fetching over HTTPS with certificate checks disabled (`curl -k`, `wget --no-check-certificate`) allows a man-in-the-middle to swap the payload.",
        recommendation="Drop the insecure flag and fix the underlying certificate trust instead.",
        file_globs=SHELL_GLOBS,
    ),
)
