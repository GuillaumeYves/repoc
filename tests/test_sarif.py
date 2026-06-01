"""SARIF 2.1.0 renderer."""

import json

from repoc.models import (
    AnalysisResult,
    Finding,
    RepositoryMetadata,
    ScoreBreakdown,
    Severity,
)
from repoc.renderers import sarif


def _result(findings):
    return AnalysisResult(
        repository=RepositoryMetadata(name="x"),
        verdict="v",
        trust_score=50,
        risk_level="Medium",
        findings=findings,
        score_breakdown=ScoreBreakdown(
            security=50, maintenance=50, documentation=50, popularity=None, structure=50
        ),
    )


def _finding(rule_id, severity, **kw):
    return Finding(
        rule_id=rule_id,
        title=f"{rule_id} title",
        severity=severity,
        description="line one\nline two",
        recommendation="do the thing",
        **kw,
    )


def test_sarif_is_valid_json_with_required_shape():
    out = json.loads(sarif.render(_result([_finding("PY001", Severity.HIGH)])))
    assert out["version"] == "2.1.0"
    assert "$schema" in out
    driver = out["runs"][0]["tool"]["driver"]
    assert driver["name"] == "repoc"
    assert driver["rules"][0]["id"] == "PY001"


def test_severity_maps_to_level():
    findings = [
        _finding("A", Severity.CRITICAL),
        _finding("B", Severity.MEDIUM),
        _finding("C", Severity.LOW),
    ]
    out = sarif.build(_result(findings))
    levels = {r["ruleId"]: r["level"] for r in out["runs"][0]["results"]}
    assert levels == {"A": "error", "B": "warning", "C": "note"}


def test_result_location_uses_file_and_line():
    f = _finding("SH001", Severity.HIGH, file_path="scripts/install.sh", line_number=12)
    out = sarif.build(_result([f]))
    loc = out["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "scripts/install.sh"
    assert loc["region"]["startLine"] == 12


def test_finding_without_file_has_no_location():
    out = sarif.build(_result([_finding("MN002", Severity.MEDIUM, category="maintenance")]))
    assert "locations" not in out["runs"][0]["results"][0]


def test_rules_are_deduped_by_id():
    findings = [
        _finding("PY001", Severity.HIGH, file_path="a.py", line_number=1),
        _finding("PY001", Severity.HIGH, file_path="b.py", line_number=2),
    ]
    out = sarif.build(_result(findings))
    rules = out["runs"][0]["tool"]["driver"]["rules"]
    assert len([r for r in rules if r["id"] == "PY001"]) == 1
    assert len(out["runs"][0]["results"]) == 2


def test_security_severity_property_present():
    out = sarif.build(_result([_finding("PY001", Severity.CRITICAL)]))
    rule = out["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "9.5"
