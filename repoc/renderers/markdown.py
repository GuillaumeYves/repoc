"""Render an :class:`AnalysisResult` as a Markdown report."""

from __future__ import annotations

from ..models import AnalysisResult, Finding
from ..scoring import WEIGHTS

SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


def render(result: AnalysisResult) -> str:
    repo = result.repository
    title = repo.url or (f"{repo.owner}/{repo.name}" if repo.owner else repo.name)

    lines: list[str] = [f"# Repoc Report: {title}", ""]

    # Verdict ----------------------------------------------------------------
    lines.append("## Verdict")
    lines.append("")
    lines.append(f"- Risk level: **{result.risk_level}**")
    lines.append(f"- Trust score: **{result.trust_score}/100**")
    lines.append(f"- Project type: {result.project_type or 'Unknown'}")
    primary_lang = result.detected_languages[0].name if result.detected_languages else "Unknown"
    lines.append(f"- Primary language: {primary_lang}")
    if result.detected_frameworks:
        stack = ", ".join(f.name for f in result.detected_frameworks[:6])
        lines.append(f"- Detected stack: {stack}")
    lines.append("")

    # Summary ----------------------------------------------------------------
    lines.append("## Summary")
    lines.append("")
    lines.append(result.verdict)
    lines.append("")

    # Metadata ---------------------------------------------------------------
    if any([repo.stars, repo.forks, repo.open_issues, repo.license, repo.pushed_at, repo.archived is not None]):
        lines.append("## Repository Metadata")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|---|---|")
        if repo.description:
            lines.append(f"| Description | {repo.description} |")
        if repo.stars is not None:
            lines.append(f"| Stars | {repo.stars} |")
        if repo.forks is not None:
            lines.append(f"| Forks | {repo.forks} |")
        if repo.open_issues is not None:
            lines.append(f"| Open issues + PRs | {repo.open_issues} |")
        if repo.license:
            lines.append(f"| License | {repo.license} |")
        if repo.pushed_at:
            lines.append(f"| Last push | {repo.pushed_at} |")
        if repo.archived is not None:
            lines.append(f"| Archived | {'yes' if repo.archived else 'no'} |")
        lines.append("")

    # Tech -------------------------------------------------------------------
    lines.append("## Detected Technologies")
    lines.append("")
    lines.append("| Category | Name | Confidence | Evidence |")
    lines.append("|---|---|---:|---|")
    for tech in [*result.detected_languages, *result.detected_frameworks]:
        evidence = ", ".join(tech.evidence) or "—"
        lines.append(
            f"| {tech.category} | {tech.name} | {tech.confidence:.2f} | {evidence} |"
        )
    if not (result.detected_languages or result.detected_frameworks):
        lines.append("| — | — | — | No technologies detected |")
    lines.append("")

    # Findings ---------------------------------------------------------------
    lines.append("## Security Findings")
    lines.append("")
    if result.findings:
        lines.append("| Severity | Rule | File | Description |")
        lines.append("|---|---|---|---|")
        for finding in _sorted_findings(result.findings):
            file_path = finding.file_path or "—"
            if finding.line_number:
                file_path = f"{file_path}:{finding.line_number}"
            description = finding.description.splitlines()[0]
            severity = SEVERITY_LABEL.get(finding.severity.value, finding.severity.value.upper())
            lines.append(f"| {severity} | {finding.rule_id} | {file_path} | {description} |")
    else:
        lines.append("_No findings._")
    lines.append("")

    # Coverage ---------------------------------------------------------------
    cov = result.coverage
    if cov is not None:
        lines.append("## Scan Coverage")
        lines.append("")
        if cov.is_partial:
            lines.append(
                f"> **Partial scan.** {cov.analyzed} file(s) inspected; "
                f"{cov.not_inspected} intended file(s) were not read"
                f"{' (file cap reached)' if cov.cap_reached else ''}. "
                "A clean result here does not cover the un-scanned files."
            )
        else:
            lines.append(f"> {cov.analyzed} file(s) inspected"
                         f"{' (deep scan)' if cov.deep else ''}.")
        if cov.source_uncovered:
            lines.append("")
            lines.append(
                f"> **No source code inspected.** This repo has "
                f"{cov.source_files_in_repo} source file(s) that the default scan does not "
                "read. Re-run with `--deep` to analyze the code."
            )
        details = []
        if cov.skipped_large:
            details.append(f"{cov.skipped_large} skipped (too large)")
        if cov.skipped_binary:
            details.append(f"{cov.skipped_binary} skipped (binary)")
        if details:
            lines.append("")
            lines.append("- " + "; ".join(details))
        lines.append("")

    # Scores -----------------------------------------------------------------
    lines.append("## Score Breakdown")
    lines.append("")
    lines.append("| Area | Score | Weight |")
    lines.append("|---|---:|---:|")
    bd = result.score_breakdown
    rows: list[tuple[str, int | None, int]] = [
        ("Security", bd.security, WEIGHTS["security"]),
        ("Maintenance", bd.maintenance, WEIGHTS["maintenance"]),
        ("Documentation", bd.documentation, WEIGHTS["documentation"]),
        ("Popularity", bd.popularity, WEIGHTS["popularity"]),
        ("Structure", bd.structure, WEIGHTS["structure"]),
    ]
    active_weight = sum(w for _, s, w in rows if s is not None) or 100
    security_uncovered = cov is not None and cov.source_uncovered
    for label, score, weight in rows:
        if score is None:
            lines.append(f"| {label} | — | n/a |")
        else:
            effective = round(weight * 100 / active_weight)
            # A perfect Security score is meaningless if no code was scanned.
            if label == "Security" and security_uncovered:
                lines.append(f"| {label} | {score} (code not scanned) | {effective}% |")
            else:
                lines.append(f"| {label} | {score} | {effective}% |")
    lines.append("")

    # Recommendations --------------------------------------------------------
    lines.append("## Recommendations")
    lines.append("")
    for rec in result.recommendations:
        lines.append(f"- {rec}")
    lines.append("")
    lines.append(
        "> repoc does not prove that a repository is safe. It highlights suspicious patterns, "
        "metadata, and maintenance signals that deserve manual review."
    )
    lines.append("")

    return "\n".join(lines)


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    from ..models import SEVERITY_ORDER

    return sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER[f.severity], f.rule_id, f.file_path or "", f.line_number or 0),
    )
