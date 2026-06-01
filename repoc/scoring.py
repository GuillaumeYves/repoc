"""Aggregate per-area scores into a single trust score + risk level."""

from __future__ import annotations

from collections import defaultdict

from .models import SEVERITY_ORDER, Finding, RiskLevel, ScoreBreakdown, Severity

# Trust score weights (sum to 100).
WEIGHTS: dict[str, int] = {
    "security": 35,
    "maintenance": 25,
    "documentation": 20,
    "popularity": 10,
    "structure": 10,
}

# Per-category, per-severity penalties applied to the security score.
#
# Committed secrets and install hooks are "stop and look" signals and are
# penalised heavily. Code patterns (`eval`, `subprocess`, `curl | bash`) are
# "worth reviewing" signals — common in legitimate code — so a single one
# barely moves the score. Anything else (e.g. an unrecognised rule) is treated
# as a heavy signal so we fail safe.
_HEAVY = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 12,
    Severity.HIGH: 22,
    Severity.CRITICAL: 40,
}
_LIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 3,
    Severity.HIGH: 6,
    Severity.CRITICAL: 10,
}
_PENALTIES: dict[str, dict[Severity, int]] = {
    "secret": _HEAVY,
    "install_hook": _HEAVY,
    "code_pattern": _LIGHT,
}

# Categories that should *not* count toward the security score at all — they are
# scored in their own dimensions, or are purely informational (coverage).
_NON_SECURITY = {"maintenance", "documentation", "coverage"}


def _diminishing_factor(index: int) -> float:
    """Repeated findings of the same kind matter less and less."""

    if index < 2:
        return 1.0
    if index < 5:
        return 0.5
    return 0.25


def security_score(findings: list[Finding]) -> int:
    """0..100 security score with category weighting and diminishing returns.

    Twenty `subprocess` calls in a large codebase should not zero the score the
    way twenty committed private keys would.
    """

    buckets: dict[str, list[Severity]] = defaultdict(list)
    for f in findings:
        if f.category in _NON_SECURITY:
            continue
        buckets[f.category].append(f.severity)

    score = 100.0
    for category, severities in buckets.items():
        table = _PENALTIES.get(category, _HEAVY)
        # Count the worst findings at full weight, then taper.
        ordered = sorted(severities, key=lambda s: SEVERITY_ORDER[s], reverse=True)
        for index, severity in enumerate(ordered):
            score -= table.get(severity, 0) * _diminishing_factor(index)
    return max(0, min(100, round(score)))


def structure_score(file_count: int, has_tests: bool, has_dependency_manifest: bool, has_ci: bool) -> int:
    score = 40
    if file_count >= 5:
        score += 15
    if file_count >= 20:
        score += 10
    if has_dependency_manifest:
        score += 15
    if has_tests:
        score += 10
    if has_ci:
        score += 10
    return min(100, score)


def compute_trust_score(breakdown: ScoreBreakdown) -> int:
    """Weighted average of the per-area scores.

    Dimensions set to None on the breakdown (e.g. popularity for a local
    repository with no stars/forks signal) are excluded and the remaining
    weights are re-normalized so the result stays on a 0..100 scale.
    """

    parts: list[tuple[int, int]] = [
        (breakdown.security, WEIGHTS["security"]),
        (breakdown.maintenance, WEIGHTS["maintenance"]),
        (breakdown.documentation, WEIGHTS["documentation"]),
        (breakdown.structure, WEIGHTS["structure"]),
    ]
    if breakdown.popularity is not None:
        parts.append((breakdown.popularity, WEIGHTS["popularity"]))

    total_weight = sum(w for _, w in parts)
    if total_weight == 0:
        return 0
    weighted = sum(score * weight for score, weight in parts)
    return round(weighted / total_weight)


def risk_level(findings: list[Finding], trust_score: int) -> RiskLevel:
    """Map findings + trust score onto a risk level.

    Key change from the naive version: a single HIGH-severity *code pattern*
    (e.g. one ``eval(`` in a 50k-star repo) no longer forces HIGH risk. Only
    CRITICAL findings, or HIGH/CRITICAL committed secrets / install hooks,
    escalate on their own — everything else flows through the trust score.
    """

    has_critical = any(f.severity == Severity.CRITICAL for f in findings)
    blocking_high = any(
        f.severity in {Severity.HIGH, Severity.CRITICAL}
        and f.category in {"secret", "install_hook"}
        for f in findings
    )
    if has_critical:
        return RiskLevel.CRITICAL
    if blocking_high or trust_score < 45:
        return RiskLevel.HIGH
    if trust_score < 65:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def build_recommendations(findings: list[Finding], breakdown: ScoreBreakdown) -> list[str]:
    recs: list[str] = []
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    high = [f for f in findings if f.severity == Severity.HIGH]
    if critical:
        recs.append(
            "Treat this repository as untrusted until the critical findings are resolved or explained."
        )
    if high:
        recs.append("Inspect every HIGH-severity finding before running install or build commands.")
    if breakdown.security < 60:
        recs.append("Review shell scripts and install hooks before executing anything from this repo.")
    if breakdown.documentation < 50:
        recs.append("Limited documentation — ask the maintainer for setup and security guidance.")
    if breakdown.maintenance < 50:
        recs.append("Maintenance signals are weak; consider a maintained fork or alternative.")
    if not recs:
        recs.append("No major issues detected. Still review the code before granting elevated privileges.")
    return recs
