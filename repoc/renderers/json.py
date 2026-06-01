"""Render an :class:`AnalysisResult` as JSON."""

from __future__ import annotations

from ..models import AnalysisResult


def render(result: AnalysisResult, indent: int | None = 2) -> str:
    return result.model_dump_json(indent=indent)
