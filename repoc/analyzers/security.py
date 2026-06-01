"""Orchestrates the rule packs against the loaded file set."""

from __future__ import annotations

import re
from collections.abc import Iterable
from itertools import chain

from ..models import SEVERITY_ORDER, Finding, RepoFile, Severity
from ..rules import (
    common,
    docker_rules,
    github_actions_rules,
    javascript_rules,
    php_rules,
    python_rules,
    ruby_rules,
    shell_rules,
)
from ..rules.common import Rule, iter_matches
from ..rules.masking import mask_code
from ..utils import redact_secret

# Inline suppressions, modelled on bandit/semgrep "nosec" markers.
#   # repoc: ignore                -> suppress all rules on this line
#   # repoc: ignore PY001          -> suppress PY001 on this line
#   # repoc: ignore PY001, PY002   -> suppress multiple
#   # repoc: ignore-file           -> suppress all rules in the whole file
# Comment marker is not significant — works for `#`, `//`, `--`, YAML, etc.
_IGNORE_LINE = re.compile(r"repoc:\s*ignore(?:\s+([A-Z0-9,\s]+))?")
_IGNORE_FILE = re.compile(r"repoc:\s*ignore-file")

# Secret detectors run against raw text (secrets live in string literals).
SECRET_RULES: tuple[Rule, ...] = common.SECRET_RULES

# Code-pattern detectors run against comment/string-masked text so that an
# `eval(` inside a comment, docstring, or string literal does not fire.
CODE_RULES: tuple[Rule, ...] = (
    *python_rules.RULES,
    *javascript_rules.RULES,
    *ruby_rules.RULES,
    *php_rules.RULES,
    *shell_rules.RULES,
    *docker_rules.RULES,
    *github_actions_rules.RULES,
)

# Paths where a match is far more likely to be a fixture/sample than a real
# problem. Findings here are down-ranked one severity tier.
_LOW_TRUST_DIR = re.compile(
    r"(?:^|/)(?:tests?|spec|specs|__tests__|__mocks__|examples?|samples?|"
    r"fixtures?|mocks?|testdata|docs?|vendor|third_party|node_modules)(?:/|$)",
    re.IGNORECASE,
)
_LOW_TRUST_FILE = re.compile(
    r"\.(?:example|sample|dist|template|tmpl)$|\.(?:test|spec)\.[A-Za-z0-9]+$",
    re.IGNORECASE,
)


def scan_files(files: Iterable[RepoFile]) -> list[Finding]:
    files = list(files)
    findings: list[Finding] = []
    for file in files:
        if not file.content or file.is_binary or file.truncated:
            continue
        if _file_ignored(file.content):
            continue
        raw = file.content
        masked = mask_code(file.path, raw)
        source_lines = raw.splitlines()
        matches = chain(
            iter_matches(SECRET_RULES, file.path, raw),
            iter_matches(CODE_RULES, file.path, masked),
        )
        for rule, match, line in matches:
            ignored = _line_ignores(source_lines, line)
            if ignored is not None and ("*" in ignored or rule.rule_id in ignored):
                continue
            snippet = match.group(0)
            if rule.redact_match:
                snippet = redact_secret(snippet)
            description = rule.description
            if rule.severity in {Severity.HIGH, Severity.CRITICAL} or rule.redact_match:
                description = f"{description}\n\nMatched value: `{snippet}`"
            findings.append(
                _apply_path_context(
                    Finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        severity=rule.severity,
                        file_path=file.path,
                        line_number=line,
                        description=description,
                        recommendation=rule.recommendation,
                        category=rule.category,
                    )
                )
            )

    findings.extend(_scan_install_hooks(files))
    findings.extend(_scan_env_files(files))
    return _dedupe(findings)


def is_low_trust_path(path: str | None) -> bool:
    """True for test/example/fixture/docs/vendor paths."""

    if not path:
        return False
    return bool(_LOW_TRUST_DIR.search(path) or _LOW_TRUST_FILE.search(path))


def _downrank(severity: Severity) -> Severity:
    order = SEVERITY_ORDER[severity]
    if order <= 0:
        return severity
    for sev, value in SEVERITY_ORDER.items():
        if value == order - 1:
            return sev
    return severity


def _apply_path_context(finding: Finding) -> Finding:
    """Lower the severity of findings that sit in test/example/fixture paths."""

    if finding.category not in {"secret", "code_pattern"}:
        return finding
    if not is_low_trust_path(finding.file_path):
        return finding
    lowered = _downrank(finding.severity)
    if lowered == finding.severity:
        return finding
    note = (
        "\n\n_Down-ranked: this match is in a test/example/fixture path, where "
        "such patterns are often intentional fixtures rather than live issues._"
    )
    return finding.model_copy(
        update={"severity": lowered, "description": finding.description + note}
    )


def _file_ignored(content: str) -> bool:
    """Honour a `repoc: ignore-file` marker found in the first 20 lines."""

    head = "\n".join(content.splitlines()[:20])
    return bool(_IGNORE_FILE.search(head))


def _line_ignores(source_lines: list[str], line_number: int) -> set[str] | None:
    """Return the rule_ids ignored on a line, `{"*"}` for all, or None."""

    idx = line_number - 1
    if idx < 0 or idx >= len(source_lines):
        return None
    match = _IGNORE_LINE.search(source_lines[idx])
    if not match:
        return None
    payload = match.group(1)
    if not payload:
        return {"*"}
    return {token.strip() for token in payload.split(",") if token.strip()}


def _scan_install_hooks(files: Iterable[RepoFile]) -> list[Finding]:
    from .framework import js_install_hooks  # local import avoids cycle at import time

    out: list[Finding] = []
    for file in files:
        if file.path.endswith("package.json") and file.content:
            hooks = js_install_hooks([file])
            for hook, command in hooks.items():
                out.append(
                    Finding(
                        rule_id="JS100",
                        title=f"npm `{hook}` script declared",
                        severity=Severity.HIGH if hook != "prepare" else Severity.MEDIUM,
                        file_path=file.path,
                        description=(
                            f"`scripts.{hook}` runs automatically when this package is installed. "
                            f"Command: `{command[:200]}`"
                        ),
                        recommendation="Read the script before running `npm/yarn/pnpm install`.",
                        category="install_hook",
                    )
                )
    return out


def _scan_env_files(files: Iterable[RepoFile]) -> list[Finding]:
    out: list[Finding] = []
    for file in files:
        name = file.path.rsplit("/", 1)[-1]
        if name in {".env", ".env.local", ".env.production"} and file.content:
            out.append(
                Finding(
                    rule_id="SEC011",
                    title=f"`{name}` committed to the repository",
                    severity=Severity.HIGH,
                    file_path=file.path,
                    description="`.env` files often contain credentials and should not be checked in.",
                    recommendation="Move sensitive values to a secrets manager and add `.env*` to `.gitignore`.",
                    category="secret",
                )
            )
    return out


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str | None, int | None, str]] = set()
    out: list[Finding] = []
    for f in findings:
        # Allow multiple matches per rule per file, but cap at one per (rule, file, line).
        key = (f.rule_id, f.file_path, f.line_number, f.title)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
