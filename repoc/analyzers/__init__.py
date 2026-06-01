"""Analyzers transform a list of files + metadata into typed signals."""

from . import (
    coverage,
    dependencies,
    documentation,
    framework,
    language,
    maintenance,
    project_type,
    security,
    vulnerabilities,
)

__all__ = [
    "coverage",
    "dependencies",
    "documentation",
    "framework",
    "language",
    "maintenance",
    "project_type",
    "security",
    "vulnerabilities",
]
