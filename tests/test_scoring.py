from repoc.models import Finding, RepositoryMetadata, ScoreBreakdown, Severity
from repoc.scoring import (
    WEIGHTS,
    compute_trust_score,
    risk_level,
    security_score,
    structure_score,
)


def _finding(rule_id: str, severity: Severity, category: str = "secret") -> Finding:
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=severity,
        description="x",
        recommendation="x",
        category=category,
    )


def test_security_score_penalises_severity():
    base = security_score([])
    with_low = security_score([_finding("X", Severity.LOW)])
    with_critical = security_score([_finding("X", Severity.CRITICAL)])
    assert base == 100
    assert with_low < base
    assert with_critical < with_low


def test_security_score_floors_at_zero():
    findings = [_finding(f"X{i}", Severity.CRITICAL) for i in range(10)]
    assert security_score(findings) == 0


def test_code_patterns_penalise_far_less_than_secrets():
    # One eval() should barely move the score; one committed secret should not.
    one_eval = security_score([_finding("PY001", Severity.HIGH, category="code_pattern")])
    one_secret = security_score([_finding("SEC001", Severity.HIGH, category="secret")])
    assert one_eval >= 90
    assert one_secret < one_eval


def test_security_score_has_diminishing_returns_for_code_patterns():
    # Twenty subprocess calls in a big repo must not zero the score.
    many = [
        _finding(f"PY00{i}", Severity.MEDIUM, category="code_pattern") for i in range(20)
    ]
    assert security_score(many) > 50


def test_security_score_ignores_maintenance_and_docs():
    findings = [
        _finding("MN001", Severity.HIGH, category="maintenance"),
        _finding("DOC001", Severity.HIGH, category="documentation"),
    ]
    assert security_score(findings) == 100


def test_weights_sum_to_100():
    assert sum(WEIGHTS.values()) == 100


def test_trust_score_uses_weighted_average():
    bd = ScoreBreakdown(security=100, maintenance=100, documentation=100, popularity=100, structure=100)
    assert compute_trust_score(bd) == 100

    bd_low = ScoreBreakdown(security=0, maintenance=0, documentation=0, popularity=0, structure=0)
    assert compute_trust_score(bd_low) == 0


def test_trust_score_excludes_popularity_when_none():
    # When popularity is None (e.g. local scan with no stars/forks signal),
    # the score must be the weighted average of the remaining dimensions —
    # not a hidden 0 or 25 baseline that drags the trust score down.
    bd = ScoreBreakdown(
        security=100, maintenance=100, documentation=100, popularity=None, structure=100
    )
    assert compute_trust_score(bd) == 100

    bd_mixed = ScoreBreakdown(
        security=80, maintenance=80, documentation=80, popularity=None, structure=80
    )
    assert compute_trust_score(bd_mixed) == 80


def test_risk_level_critical_overrides_score():
    findings = [_finding("X", Severity.CRITICAL)]
    assert risk_level(findings, trust_score=95).value == "Critical"


def test_risk_level_uses_score_when_no_findings():
    assert risk_level([], trust_score=80).value == "Low"
    assert risk_level([], trust_score=60).value == "Medium"
    assert risk_level([], trust_score=40).value == "High"


def test_single_code_pattern_high_does_not_force_high_risk():
    # The core fix: one eval() in an otherwise healthy repo is not HIGH risk.
    findings = [_finding("PY001", Severity.HIGH, category="code_pattern")]
    assert risk_level(findings, trust_score=85).value == "Low"


def test_committed_secret_high_escalates_to_high_risk():
    findings = [_finding("SEC001", Severity.HIGH, category="secret")]
    assert risk_level(findings, trust_score=85).value == "High"


def test_structure_score_grows_with_signals():
    low = structure_score(file_count=0, has_tests=False, has_dependency_manifest=False, has_ci=False)
    high = structure_score(file_count=30, has_tests=True, has_dependency_manifest=True, has_ci=True)
    assert high > low


def test_repository_metadata_optional_fields():
    meta = RepositoryMetadata(name="x")
    assert meta.stars is None
    assert meta.archived is None
