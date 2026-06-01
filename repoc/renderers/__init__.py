"""Output renderers for AnalysisResult."""

from . import json as json_renderer
from . import markdown, sarif, terminal

__all__ = ["json_renderer", "markdown", "sarif", "terminal"]
