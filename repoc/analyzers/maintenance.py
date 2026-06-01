"""Repository maintenance signals derived from GitHub metadata."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from ..models import Finding, RepoFile, RepositoryMetadata, Severity

# Heuristic signatures used to label a LICENSE file found locally. Order matters:
# more specific patterns (e.g. "Apache License") come before generic ones.
_LICENSE_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Apache-2.0", re.compile(r"Apache License,?\s+Version\s+2\.0", re.IGNORECASE)),
    ("MIT", re.compile(r"\bMIT License\b", re.IGNORECASE)),
    ("MIT", re.compile(r"Permission is hereby granted, free of charge", re.IGNORECASE)),
    ("BSD-3-Clause", re.compile(r"Redistribution and use in source and binary forms.*3\.\s*Neither", re.IGNORECASE | re.DOTALL)),
    ("BSD-2-Clause", re.compile(r"Redistribution and use in source and binary forms", re.IGNORECASE)),
    ("GPL-3.0", re.compile(r"GNU GENERAL PUBLIC LICENSE.*Version 3", re.IGNORECASE | re.DOTALL)),
    ("GPL-2.0", re.compile(r"GNU GENERAL PUBLIC LICENSE.*Version 2", re.IGNORECASE | re.DOTALL)),
    ("AGPL-3.0", re.compile(r"GNU AFFERO GENERAL PUBLIC LICENSE", re.IGNORECASE)),
    ("LGPL", re.compile(r"GNU LESSER GENERAL PUBLIC LICENSE", re.IGNORECASE)),
    ("MPL-2.0", re.compile(r"Mozilla Public License Version 2\.0", re.IGNORECASE)),
    ("ISC", re.compile(r"ISC License", re.IGNORECASE)),
    ("Unlicense", re.compile(r"This is free and unencumbered software released into the public domain", re.IGNORECASE)),
)

_LICENSE_FILENAMES = {"license", "license.md", "license.txt", "copying", "copying.md"}


def detect_local_license(files: list[RepoFile]) -> str | None:
    """Best-effort SPDX-ish identifier for a LICENSE file in a local checkout.

    Returns None when no LICENSE file is present. Returns a heuristic SPDX id
    when the content matches a known signature, otherwise the literal string
    "Detected" so the caller knows a LICENSE file exists even if we cannot
    identify it.
    """

    for f in files:
        if "/" in f.path:
            continue
        if f.path.lower() not in _LICENSE_FILENAMES:
            continue
        if not f.content:
            return "Detected"
        # Only sniff the first ~4KB — license headers are always near the top.
        head = f.content[:4096]
        for spdx, pattern in _LICENSE_SIGNATURES:
            if pattern.search(head):
                return spdx
        return "Detected"
    return None


def analyze_maintenance(metadata: RepositoryMetadata) -> list[Finding]:
    findings: list[Finding] = []

    if metadata.archived:
        findings.append(
            Finding(
                rule_id="MN001",
                title="Repository is archived",
                severity=Severity.MEDIUM,
                description="The repository is archived on GitHub. It will not receive updates or security fixes from upstream.",
                recommendation="Treat as read-only. Prefer a maintained fork if you need to depend on this code.",
            )
        )

    if metadata.license is None:
        findings.append(
            Finding(
                rule_id="MN002",
                title="No license detected",
                severity=Severity.MEDIUM,
                description="GitHub did not return a license for this repository. Without a license you have no legal right to use, copy, or distribute the code.",
                recommendation="Ask the maintainer to add an OSI license, or treat the code as all-rights-reserved.",
            )
        )

    pushed_age = _days_since(metadata.pushed_at)
    if pushed_age is not None and pushed_age > 365:
        findings.append(
            Finding(
                rule_id="MN003",
                title="No commits in over 12 months",
                severity=Severity.MEDIUM,
                description=f"Last push was {pushed_age} days ago.",
                recommendation="Confirm the project is still maintained before depending on it.",
            )
        )
    elif pushed_age is not None and pushed_age > 180:
        findings.append(
            Finding(
                rule_id="MN004",
                title="No commits in the last 6 months",
                severity=Severity.LOW,
                description=f"Last push was {pushed_age} days ago.",
                recommendation="Check whether maintainers are still responsive.",
            )
        )

    if metadata.open_issues is not None and metadata.open_issues > 500:
        findings.append(
            Finding(
                rule_id="MN005",
                title="Large open issue + PR backlog",
                severity=Severity.LOW,
                # GitHub's open_issues_count bundles issues *and* pull requests,
                # so this is a combined backlog signal, not pure issue count.
                description=(
                    f"{metadata.open_issues} open issues and pull requests combined "
                    "(GitHub reports them together) — may signal slow triage."
                ),
                recommendation="Skim the most-upvoted issues to gauge maintainer responsiveness.",
            )
        )

    return [f.model_copy(update={"category": "maintenance"}) for f in findings]


def _days_since(iso_timestamp: str | None) -> int | None:
    if not iso_timestamp:
        return None
    try:
        ts = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    now = datetime.now(UTC)
    return max(0, (now - ts).days)


def maintenance_score(metadata: RepositoryMetadata, findings: list[Finding]) -> int:
    """Return a 0..100 score, penalising the findings above."""

    score = 100
    severity_penalty = {Severity.LOW: 5, Severity.MEDIUM: 15, Severity.HIGH: 30, Severity.CRITICAL: 50}
    for finding in findings:
        score -= severity_penalty.get(finding.severity, 0)

    pushed_age = _days_since(metadata.pushed_at)
    if pushed_age is None:
        score -= 5  # unknown freshness
    elif pushed_age < 30:
        score += 5  # very fresh
    return max(0, min(100, score))


def popularity_score(metadata: RepositoryMetadata) -> int:
    """Log-ish scoring on stars + forks; capped 0..100."""

    import math

    stars = metadata.stars or 0
    forks = metadata.forks or 0
    if stars == 0 and forks == 0:
        return 25
    # 10 stars -> ~33, 100 -> ~50, 1000 -> ~66, 10000 -> ~83.
    value = math.log10(stars + forks + 1) * 20
    return max(0, min(100, int(value) + 25))
