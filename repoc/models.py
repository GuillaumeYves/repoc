"""Typed data models used across analyzers, scoring, and renderers."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class RiskLevel(StrEnum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    UNKNOWN = "Unknown"


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    file_path: str | None = None
    line_number: int | None = None
    description: str
    recommendation: str
    # One of: "secret", "install_hook", "code_pattern", "maintenance",
    # "documentation". Drives scoring weight and risk-level escalation.
    category: str = "code_pattern"


class DetectedTechnology(BaseModel):
    name: str
    category: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)


class RepositoryMetadata(BaseModel):
    name: str
    owner: str | None = None
    url: str | None = None
    description: str | None = None
    default_branch: str | None = None
    stars: int | None = None
    forks: int | None = None
    watchers: int | None = None
    open_issues: int | None = None
    license: str | None = None
    archived: bool | None = None
    pushed_at: str | None = None


class ScoreBreakdown(BaseModel):
    security: int = Field(ge=0, le=100)
    maintenance: int = Field(ge=0, le=100)
    documentation: int = Field(ge=0, le=100)
    # None means the dimension was not applicable (e.g. popularity for a local repo)
    # and should be excluded from the weighted trust score.
    popularity: int | None = Field(default=None, ge=0, le=100)
    structure: int = Field(ge=0, le=100)


class ScanCoverage(BaseModel):
    """How much of the repository was actually inspected.

    Surfaced in every report so a partial scan (file cap reached, oversized or
    binary files skipped) can never masquerade as a clean bill of health.
    """

    # Files repoc intended to read for this run (curated set, or all source
    # files under --deep / a local walk).
    intended: int = 0
    analyzed: int = 0          # files whose text content was scanned
    skipped_binary: int = 0
    skipped_large: int = 0     # exceeded --max-file-size
    not_inspected: int = 0     # intended but not loaded (e.g. --max-files cap)
    cap_reached: bool = False
    deep: bool = False
    # Source-code coverage: how many code files exist vs were actually read.
    source_files_in_repo: int = 0
    source_files_inspected: int = 0

    @property
    def is_partial(self) -> bool:
        return self.cap_reached or self.not_inspected > 0

    @property
    def source_uncovered(self) -> bool:
        """True when the repo has source files that were not inspected at all."""

        return self.source_files_in_repo > 0 and self.source_files_inspected == 0


class AnalysisResult(BaseModel):
    repository: RepositoryMetadata
    verdict: str
    trust_score: int = Field(ge=0, le=100)
    risk_level: str
    detected_languages: list[DetectedTechnology] = Field(default_factory=list)
    detected_frameworks: list[DetectedTechnology] = Field(default_factory=list)
    project_type: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    score_breakdown: ScoreBreakdown
    recommendations: list[str] = Field(default_factory=list)
    coverage: ScanCoverage | None = None
    repoc_version: str | None = None


class RepoFile(BaseModel):
    """Lightweight in-memory representation of a single repo file."""

    path: str
    size: int = 0
    content: str | None = None
    is_binary: bool = False
    truncated: bool = False
