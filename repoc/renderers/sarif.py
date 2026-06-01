"""Render an :class:`AnalysisResult` as SARIF 2.1.0.

SARIF lets repoc findings flow into GitHub code scanning (the Security tab) and
other CI dashboards via `upload-sarif`. We emit one run with a `repoc` driver,
one reportingDescriptor per distinct rule, and one result per finding.
"""

from __future__ import annotations

import json

from .. import __version__
from ..models import AnalysisResult, Finding, Severity

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# SARIF result levels — SARIF only has error/warning/note/none.
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub reads `properties.security-severity` (a CVSS-like 0-10 number) to bucket
# findings in the Security tab. Map our severities onto representative values.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
    Severity.INFO: "0.0",
}


def render(result: AnalysisResult) -> str:
    return json.dumps(build(result), indent=2)


def build(result: AnalysisResult) -> dict:
    rules, rule_index = _rule_descriptors(result.findings)
    results = [_result(f, rule_index) for f in result.findings]
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "repoc",
                        "version": __version__,
                        "informationUri": "https://github.com/GuillaumeYves/repoc",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _rule_descriptors(findings: list[Finding]) -> tuple[list[dict], dict[str, int]]:
    """One reportingDescriptor per distinct rule_id, plus a rule_id -> index map."""

    rules: list[dict] = []
    index: dict[str, int] = {}
    for finding in findings:
        if finding.rule_id in index:
            continue
        index[finding.rule_id] = len(rules)
        rules.append(
            {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": _first_line(finding.description)},
                "helpText": finding.recommendation,
                "defaultConfiguration": {"level": _LEVEL[finding.severity]},
                "properties": {
                    "category": finding.category,
                    "security-severity": _SECURITY_SEVERITY[finding.severity],
                },
            }
        )
    return rules, index


def _result(finding: Finding, rule_index: dict[str, int]) -> dict:
    result: dict = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index[finding.rule_id],
        "level": _LEVEL[finding.severity],
        "message": {"text": _first_line(finding.description)},
        "properties": {
            "severity": finding.severity.value,
            "category": finding.category,
        },
    }
    if finding.file_path:
        region = {"startLine": max(1, finding.line_number or 1)}
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                    "region": region,
                }
            }
        ]
    # Stable-ish fingerprint so the same finding dedupes across runs.
    result["partialFingerprints"] = {
        "repoc/v1": f"{finding.rule_id}:{finding.file_path or ''}:{finding.line_number or 0}"
    }
    return result


def _first_line(text: str) -> str:
    return text.splitlines()[0] if text else ""
