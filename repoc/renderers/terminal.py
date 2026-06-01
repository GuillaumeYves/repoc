"""Render an :class:`AnalysisResult` to the terminal using Rich."""

from __future__ import annotations

from rich.console import Console
from rich.markdown import Markdown

from ..models import AnalysisResult
from . import markdown as markdown_renderer


def render(result: AnalysisResult, console: Console | None = None) -> None:
    console = console or Console()
    body = markdown_renderer.render(result)
    console.print(Markdown(body))
