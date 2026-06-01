"""Output renderers for AnalysisResult."""

from . import json as json_renderer
from . import markdown, terminal

__all__ = ["json_renderer", "markdown", "terminal"]
