"""Opt-in dependency vulnerability analysis via OSV.dev (`--check-deps`)."""

from __future__ import annotations

from .. import osv
from ..deps_versions import extract_versions
from ..models import Finding, RepoFile, Severity

# Cap findings per dependency so one ancient, heavily-CVE'd package doesn't
# flood the report.
_MAX_VULNS_PER_DEP = 10


def analyze_dependencies(files: list[RepoFile], *, timeout: float = 20.0) -> list[Finding]:
    """Return dependency-vulnerability findings (network call to OSV)."""

    deps = extract_versions(files)
    if not deps:
        return []

    try:
        hits = osv.query_batch(deps, timeout=timeout)
    except osv.OSVError as exc:
        # Never fail the whole scan because the vuln check couldn't run; surface
        # it as an informational note (category "coverage" => not scored/gated).
        return [
            Finding(
                rule_id="DEP000",
                title="Dependency vulnerability check could not complete",
                severity=Severity.INFO,
                description=f"The OSV.dev lookup failed: {exc}",
                recommendation="Re-run with network access, or check dependencies manually.",
                category="coverage",
            )
        ]

    if not hits:
        return []

    all_ids = [vid for ids in hits.values() for vid in ids]
    try:
        details = osv.fetch_details(all_ids, timeout=timeout)
    except osv.OSVError:
        details = {}

    findings: list[Finding] = []
    for dep, vuln_ids in hits.items():
        for vid in vuln_ids[:_MAX_VULNS_PER_DEP]:
            detail = details.get(vid)
            severity = osv.severity_of(detail)
            summary = osv.summarize(detail, vid)
            findings.append(
                Finding(
                    rule_id=vid,
                    title=f"{dep.name} {dep.version}: known vulnerability ({vid})",
                    severity=severity,
                    file_path=dep.source,
                    description=(
                        f"`{dep.name}` {dep.version} ({dep.ecosystem}) is affected by {vid}: "
                        f"{summary}"
                    ),
                    recommendation=(
                        f"Check https://osv.dev/vulnerability/{vid} and upgrade `{dep.name}` "
                        "to a fixed version."
                    ),
                    category="dependency",
                )
            )
    return findings
