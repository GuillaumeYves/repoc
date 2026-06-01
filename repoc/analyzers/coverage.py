"""Compute how much of the repository was actually inspected.

A "can I trust this repo?" tool must never let a *partial* scan look like a
clean one. This module turns the loaded file set into a :class:`ScanCoverage`
summary and emits explicit findings when coverage is incomplete.
"""

from __future__ import annotations

from pathlib import PurePosixPath

from ..models import Finding, RepoFile, ScanCoverage, Severity

# Extensions that carry executable source code (i.e. what the code-pattern and
# secret scanners actually need to see). HTML/CSS/data files are excluded.
SOURCE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py", ".pyi", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".rb",
        ".go", ".rs", ".java", ".kt", ".kts", ".cs", ".c", ".h", ".cc", ".cpp",
        ".cxx", ".hpp", ".php", ".phtml", ".sh", ".bash", ".zsh", ".pl", ".lua",
        ".scala", ".swift", ".m", ".mm", ".ex", ".exs",
    }
)


def is_source_path(path: str) -> bool:
    return PurePosixPath(path).suffix.lower() in SOURCE_EXTENSIONS


def build_coverage(
    files: list[RepoFile],
    *,
    intended: int,
    cap_reached: bool,
    deep: bool,
    source_files_in_repo: int | None = None,
) -> ScanCoverage:
    analyzed = sum(1 for f in files if f.content is not None and not f.is_binary and not f.truncated)
    skipped_binary = sum(1 for f in files if f.is_binary)
    skipped_large = sum(1 for f in files if f.truncated)
    not_inspected = max(0, intended - len(files))
    source_inspected = sum(
        1 for f in files if f.content is not None and is_source_path(f.path)
    )
    # When the caller can't enumerate the whole repo (e.g. a local walk that
    # reads everything), fall back to what we inspected.
    in_repo = source_files_in_repo if source_files_in_repo is not None else source_inspected
    return ScanCoverage(
        intended=max(intended, len(files)),
        analyzed=analyzed,
        skipped_binary=skipped_binary,
        skipped_large=skipped_large,
        not_inspected=not_inspected,
        cap_reached=cap_reached,
        deep=deep,
        source_files_in_repo=max(in_repo, source_inspected),
        source_files_inspected=source_inspected,
    )


def coverage_findings(coverage: ScanCoverage) -> list[Finding]:
    """Findings that flag blind spots. Category 'coverage' => excluded from scoring."""

    findings: list[Finding] = []
    if coverage.cap_reached or coverage.not_inspected > 0:
        findings.append(
            Finding(
                rule_id="COV001",
                title="Scan is partial — not all files were inspected",
                severity=Severity.LOW,
                description=(
                    f"{coverage.not_inspected} file(s) repoc intended to read were skipped "
                    "because the --max-files cap was reached. The absence of findings in "
                    "uninspected files does NOT mean they are clean."
                ),
                recommendation="Re-run with a higher --max-files (and --deep) to widen coverage.",
                category="coverage",
            )
        )
    if coverage.skipped_large > 0:
        findings.append(
            Finding(
                rule_id="COV002",
                title="Oversized files were not scanned",
                severity=Severity.LOW,
                description=(
                    f"{coverage.skipped_large} file(s) exceeded the --max-file-size limit and "
                    "were not scanned. Large/minified files can hide secrets or payloads."
                ),
                recommendation="Inspect oversized files manually, or raise --max-file-size.",
                category="coverage",
            )
        )
    if coverage.source_uncovered:
        findings.append(
            Finding(
                rule_id="COV003",
                title="No source code was inspected (metadata-only scan)",
                severity=Severity.MEDIUM,
                description=(
                    f"This repository contains {coverage.source_files_in_repo} source file(s), "
                    "but the default scan only reads manifests, config, workflows, and docs. "
                    "The security verdict therefore does NOT reflect the actual code."
                ),
                recommendation="Re-run with --deep to download and scan the source files.",
                category="coverage",
            )
        )
    return findings
