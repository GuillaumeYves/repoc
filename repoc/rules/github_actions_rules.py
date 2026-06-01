"""GitHub Actions workflow suspicious patterns."""

# repoc: ignore-file -- regex literals here intentionally match the rules themselves.

from __future__ import annotations

from ..models import Severity
from .common import Rule, compile_pattern

GH_GLOBS = (".github/workflows/*.yml", ".github/workflows/*.yaml")

RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="GH001",
        title="`pull_request_target` trigger",
        severity=Severity.HIGH,
        pattern=compile_pattern(r"(?m)^\s*pull_request_target\b\s*:"),
        description="`pull_request_target` runs in the context of the base repository with access to secrets. Combined with PR-supplied code it has been used for severe supply-chain exploits.",
        recommendation="Use `pull_request` unless you really need write access; never check out the PR HEAD inside a `pull_request_target` job.",
        file_globs=GH_GLOBS,
    ),
    Rule(
        rule_id="GH002",
        title="Workflow references `secrets.*` while running untrusted code",
        severity=Severity.MEDIUM,
        pattern=compile_pattern(r"\$\{\{\s*secrets\.[A-Z0-9_]+\s*\}\}"),
        description="The workflow expands secrets into shell context.",
        recommendation="Confirm the surrounding job is not triggered by untrusted contributors or PRs.",
        file_globs=GH_GLOBS,
    ),
    Rule(
        rule_id="GH003",
        title="`curl | bash` step in workflow",
        severity=Severity.HIGH,
        pattern=compile_pattern(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:bash|sh)\b"),
        description="Workflow step pipes a remote installer into a shell.",
        recommendation="Pin to a release artifact with a known checksum.",
        file_globs=GH_GLOBS,
    ),
    Rule(
        rule_id="GH004",
        title="`sudo` in workflow step",
        severity=Severity.LOW,
        pattern=compile_pattern(r"(?m)^\s*-?\s*run:.*\bsudo\b"),
        description="The workflow uses `sudo`. GitHub-hosted runners already allow root via sudo, but auditing the elevated command is worthwhile.",
        recommendation="Review what the elevated step actually does.",
        file_globs=GH_GLOBS,
    ),
    Rule(
        rule_id="GH005",
        title="Uses a third-party action pinned to a branch or tag",
        severity=Severity.LOW,
        pattern=compile_pattern(r"(?m)^\s*uses:\s*[^\s@]+@(?:main|master|v\d+(?:\.\d+)*)\s*$"),
        description="Third-party actions are easier to audit when pinned by SHA. Tag/branch references can be moved.",
        recommendation="Pin actions to a specific commit SHA.",
        file_globs=GH_GLOBS,
    ),
    Rule(
        rule_id="GH006",
        title="Untrusted `github.event.*` value used in an expression",
        severity=Severity.MEDIUM,
        # Anchored to the specific fields an external contributor controls (PR/
        # issue/discussion titles & bodies, comment/review bodies, PR head ref,
        # commit messages). This deliberately excludes benign fields such as
        # `github.event.repository.name` to avoid false positives.
        pattern=compile_pattern(
            r"\$\{\{\s*github\.event\.(?:"
            r"(?:issue|pull_request|discussion)\.(?:title|body)"
            r"|(?:comment|review|review_comment)\.body"
            r"|pull_request\.head\.(?:ref|label)"
            r"|(?:head_commit\.|commits[^}]*\.)message"
            r")"
        ),
        description="Fields like a PR title or issue body are attacker-controlled. Interpolated into a `run:` step they enable script injection into the runner.",
        recommendation="Pass the value through an `env:` variable and reference it as `\"$VAR\"`, never inline in `run:`.",
        file_globs=GH_GLOBS,
    ),
)
