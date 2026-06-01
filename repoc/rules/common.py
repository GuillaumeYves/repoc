"""Shared rule types and secret-scanning regexes."""

# repoc: ignore-file -- regex literals here intentionally match the rules themselves.

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field, replace

from ..models import Severity


@dataclass(frozen=True)
class Rule:
    """A single regex-based detector."""

    rule_id: str
    title: str
    severity: Severity
    pattern: re.Pattern[str]
    description: str
    recommendation: str
    file_globs: tuple[str, ...] = field(default_factory=tuple)
    redact_match: bool = False
    # Drives scoring and whether the rule runs against raw or comment/string-masked
    # text. "secret" rules run on raw text (secrets live in string literals);
    # "code_pattern" rules run on masked text to avoid matching inside comments
    # and strings. See analyzers/security.py.
    category: str = "code_pattern"


def compile_pattern(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


# --- Secrets -----------------------------------------------------------------

# Patterns are intentionally conservative. We label them as "possible" findings.
_SECRET_RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="SEC001",
        title="Possible GitHub personal access token",
        severity=Severity.CRITICAL,
        pattern=compile_pattern(r"\bghp_[A-Za-z0-9]{36,}\b"),
        description="A token matching the GitHub PAT format was found in the source.",
        recommendation="Verify whether this is a real credential. If so, rotate it and remove it from history.",
        redact_match=True,
    ),
    Rule(
        rule_id="SEC002",
        title="Possible GitHub fine-grained token",
        severity=Severity.CRITICAL,
        pattern=compile_pattern(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
        description="A token matching the GitHub fine-grained PAT format was found.",
        recommendation="Verify and rotate the token if it is real.",
        redact_match=True,
    ),
    Rule(
        rule_id="SEC003",
        title="Possible AWS access key ID",
        severity=Severity.HIGH,
        pattern=compile_pattern(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        description="A value matching the AWS access key ID format was found.",
        recommendation="Confirm and rotate if real. Pair access key IDs are useless without their secret, but exposed IDs still help attackers target your account.",
        redact_match=True,
    ),
    Rule(
        rule_id="SEC004",
        title="Possible AWS secret access key",
        severity=Severity.CRITICAL,
        pattern=compile_pattern(
            r"(?i)aws(.{0,20})?(secret|sk)[^A-Za-z0-9]{1,4}[\"']?([A-Za-z0-9/+=]{40})[\"']?"
        ),
        description="A string near an `aws_secret` keyword matches a 40-char base64 key shape.",
        recommendation="Treat as a real key until proven otherwise; rotate immediately.",
        redact_match=True,
    ),
    Rule(
        rule_id="SEC005",
        title="Possible private key (PEM)",
        severity=Severity.CRITICAL,
        pattern=compile_pattern(r"-----BEGIN ((?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY-----"),
        description="A PEM-encoded private key header was found in the source.",
        recommendation="Confirm whether this is a test fixture or a live key. Rotate and remove from git history if it is real.",
        redact_match=False,
    ),
    Rule(
        rule_id="SEC006",
        title="Possible JSON Web Token",
        severity=Severity.MEDIUM,
        pattern=compile_pattern(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        description="A value matching the JWT format (three dot-separated base64 sections) was found.",
        recommendation="If this is a live token, treat it as a credential and rotate the signing secret.",
        redact_match=True,
    ),
    Rule(
        rule_id="SEC007",
        title="Possible database URL with embedded credentials",
        severity=Severity.HIGH,
        pattern=compile_pattern(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:'\"@]+:[^\s'\"@]+@[^\s'\"/]+"
        ),
        description="A connection string that bundles a username and password was found.",
        recommendation="Verify whether the password is real, and move secrets out of source control if so.",
        redact_match=True,
    ),
    Rule(
        rule_id="SEC008",
        title="Possible Slack webhook",
        severity=Severity.HIGH,
        pattern=compile_pattern(r"https://hooks\.slack\.com/services/[A-Z0-9/]{20,}"),
        description="A Slack incoming webhook URL was found.",
        recommendation="Rotate the webhook; anyone with the URL can post to your channel.",
        redact_match=True,
    ),
    Rule(
        rule_id="SEC009",
        title="Possible Discord webhook",
        severity=Severity.HIGH,
        pattern=compile_pattern(r"https://(?:discord|discordapp)\.com/api/webhooks/\d{15,}/[A-Za-z0-9_-]{40,}"),
        description="A Discord webhook URL was found.",
        recommendation="Rotate the webhook.",
        redact_match=True,
    ),
    Rule(
        rule_id="SEC010",
        title="Possible Stripe secret key",
        severity=Severity.CRITICAL,
        pattern=compile_pattern(r"\bsk_(?:test|live)_[A-Za-z0-9]{16,}\b"),
        description="A value matching the Stripe secret key format was found.",
        recommendation="Rotate immediately in the Stripe dashboard if this is a live key.",
        redact_match=True,
    ),
)

# All secret detectors share the "secret" category so the scanner runs them
# against raw (un-masked) text and the scorer weighs them heavily.
SECRET_RULES: tuple[Rule, ...] = tuple(replace(r, category="secret") for r in _SECRET_RULES)


def iter_matches(rules: Iterable[Rule], path: str, content: str):
    """Yield (rule, match, line_number) for every regex hit."""

    line_starts: list[int] = []
    pos = 0
    for line in content.splitlines(keepends=True):
        line_starts.append(pos)
        pos += len(line)

    def line_of(offset: int) -> int:
        # binary search would be nicer, but file slices are tiny here
        line = 1
        for i, start in enumerate(line_starts, start=1):
            if start > offset:
                break
            line = i
        return line

    for rule in rules:
        if rule.file_globs:
            from fnmatch import fnmatch

            if not any(fnmatch(path, glob) for glob in rule.file_globs):
                continue
        for match in rule.pattern.finditer(content):
            yield rule, match, line_of(match.start())
