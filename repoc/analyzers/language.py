"""Language detection from GitHub API + file extensions + dependency files."""

from __future__ import annotations

from collections import Counter
from pathlib import PurePosixPath

from ..models import DetectedTechnology, RepoFile

EXTENSION_MAP: dict[str, str] = {
    ".py": "Python",
    ".pyi": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".rb": "Ruby",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".kt": "Kotlin",
    ".cs": "C#",
    ".c": "C",
    ".h": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".php": "PHP",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "CSS",
    ".sass": "CSS",
    ".swift": "Swift",
    ".m": "Objective-C",
    ".scala": "Scala",
    ".lua": "Lua",
    ".r": "R",
    ".dart": "Dart",
    ".ex": "Elixir",
    ".exs": "Elixir",
}

DEPENDENCY_FILE_HINTS: dict[str, str] = {
    "pyproject.toml": "Python",
    "requirements.txt": "Python",
    "Pipfile": "Python",
    "setup.py": "Python",
    "package.json": "JavaScript",
    "tsconfig.json": "TypeScript",
    "Gemfile": "Ruby",
    "go.mod": "Go",
    "Cargo.toml": "Rust",
    "pom.xml": "Java",
    "build.gradle": "Java",
    "build.gradle.kts": "Kotlin",
    "composer.json": "PHP",
    "Dockerfile": "Dockerfile",
}


def detect_languages(
    files: list[RepoFile],
    github_languages: dict[str, int] | None = None,
) -> list[DetectedTechnology]:
    """Return a sorted list of detected languages with confidence + evidence."""

    counts: Counter[str] = Counter()
    evidence: dict[str, set[str]] = {}

    for file in files:
        name = PurePosixPath(file.path).name
        ext = PurePosixPath(file.path).suffix.lower()
        hint = DEPENDENCY_FILE_HINTS.get(name)
        if hint:
            counts[hint] += 5
            evidence.setdefault(hint, set()).add(name)
        lang = EXTENSION_MAP.get(ext)
        if lang:
            counts[lang] += 1
            evidence.setdefault(lang, set()).add(f"`{ext}` files")

    if github_languages:
        # GitHub reports bytes per language; normalize against the largest.
        total = max(github_languages.values()) or 1
        for lang, bytes_ in github_languages.items():
            normalised = lang
            counts[normalised] = max(counts[normalised], int(20 * bytes_ / total))
            evidence.setdefault(normalised, set()).add("GitHub language stats")

    if not counts:
        return []

    top = counts.most_common(1)[0][1]
    detected: list[DetectedTechnology] = []
    for lang, count in counts.most_common():
        confidence = min(0.99, round(count / max(top, 1), 2))
        if confidence < 0.05:
            continue
        detected.append(
            DetectedTechnology(
                name=lang,
                category="Language",
                confidence=confidence,
                evidence=sorted(evidence.get(lang, set())),
            )
        )
    return detected


def primary_language(detected: list[DetectedTechnology]) -> str | None:
    return detected[0].name if detected else None
