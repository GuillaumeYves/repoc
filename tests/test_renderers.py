import json as stdlib_json

from repoc.models import (
    AnalysisResult,
    DetectedTechnology,
    Finding,
    RepositoryMetadata,
    ScoreBreakdown,
    Severity,
)
from repoc.renderers import json as json_renderer
from repoc.renderers import markdown as markdown_renderer


def _make_result() -> AnalysisResult:
    return AnalysisResult(
        repository=RepositoryMetadata(
            name="repo",
            owner="owner",
            url="https://github.com/owner/repo",
            stars=42,
            license="MIT",
            archived=False,
            pushed_at="2026-04-01T12:00:00Z",
            default_branch="main",
        ),
        verdict="Test repository.",
        trust_score=72,
        risk_level="Medium",
        detected_languages=[
            DetectedTechnology(name="Python", category="Language", confidence=0.95, evidence=[".py files"])
        ],
        detected_frameworks=[
            DetectedTechnology(name="FastAPI", category="Framework", confidence=0.9, evidence=["fastapi in pyproject.toml"])
        ],
        project_type="Backend API",
        findings=[
            Finding(
                rule_id="JS100",
                title="postinstall script",
                severity=Severity.HIGH,
                file_path="package.json",
                description="postinstall declared",
                recommendation="review",
            ),
        ],
        score_breakdown=ScoreBreakdown(security=62, maintenance=84, documentation=71, popularity=78, structure=80),
        recommendations=["Review install scripts before running."],
    )


def test_markdown_renderer_includes_key_sections():
    body = markdown_renderer.render(_make_result())
    assert "# Repoc Report:" in body
    assert "## Verdict" in body
    assert "Trust score: **72/100**" in body
    assert "FastAPI" in body
    assert "JS100" in body
    assert "## Score Breakdown" in body
    assert "## Recommendations" in body


def test_json_renderer_is_valid_json_and_matches_model():
    body = json_renderer.render(_make_result())
    parsed = stdlib_json.loads(body)
    assert parsed["trust_score"] == 72
    assert parsed["risk_level"] == "Medium"
    assert parsed["score_breakdown"]["security"] == 62
    assert parsed["findings"][0]["rule_id"] == "JS100"


def _make_local_result() -> AnalysisResult:
    return AnalysisResult(
        repository=RepositoryMetadata(name="repo", license="MIT"),
        verdict="Local repository.",
        trust_score=85,
        risk_level="Low",
        detected_languages=[
            DetectedTechnology(name="Python", category="Language", confidence=0.95, evidence=[".py files"])
        ],
        detected_frameworks=[],
        project_type="CLI tool",
        findings=[],
        score_breakdown=ScoreBreakdown(
            security=100, maintenance=80, documentation=80, popularity=None, structure=80
        ),
        recommendations=["No major issues detected."],
    )


def test_markdown_renderer_handles_local_popularity_n_a():
    body = markdown_renderer.render(_make_local_result())
    # The Popularity row must render with an n/a weight, and the remaining
    # weights must re-normalize away from the original 35/25/20/10/10 split.
    assert "| Popularity | — | n/a |" in body
    assert "| Security | 100 | 39%" in body  # 35 / 90 * 100 rounded


def test_json_renderer_serializes_null_popularity():
    body = json_renderer.render(_make_local_result())
    parsed = stdlib_json.loads(body)
    assert parsed["score_breakdown"]["popularity"] is None
