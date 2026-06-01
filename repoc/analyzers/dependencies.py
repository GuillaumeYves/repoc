"""Identify dependency / build manifests present in the repository."""

from __future__ import annotations

from pathlib import PurePosixPath

from ..models import RepoFile

# (file_name, package_manager, ecosystem)
KNOWN_MANIFESTS: tuple[tuple[str, str, str], ...] = (
    ("requirements.txt", "pip", "Python"),
    ("pyproject.toml", "pip / poetry / pdm", "Python"),
    ("poetry.lock", "poetry", "Python"),
    ("Pipfile", "pipenv", "Python"),
    ("Pipfile.lock", "pipenv", "Python"),
    ("setup.py", "setuptools", "Python"),
    ("package.json", "npm", "JavaScript"),
    ("package-lock.json", "npm", "JavaScript"),
    ("pnpm-lock.yaml", "pnpm", "JavaScript"),
    ("yarn.lock", "yarn", "JavaScript"),
    ("Gemfile", "bundler", "Ruby"),
    ("Gemfile.lock", "bundler", "Ruby"),
    ("go.mod", "go modules", "Go"),
    ("go.sum", "go modules", "Go"),
    ("Cargo.toml", "cargo", "Rust"),
    ("Cargo.lock", "cargo", "Rust"),
    ("pom.xml", "maven", "Java"),
    ("build.gradle", "gradle", "Java"),
    ("build.gradle.kts", "gradle", "Java/Kotlin"),
    ("composer.json", "composer", "PHP"),
    ("composer.lock", "composer", "PHP"),
    ("Dockerfile", "docker", "Container"),
    ("docker-compose.yml", "docker", "Container"),
)


def detect_dependency_manifests(files: list[RepoFile]) -> list[dict[str, str]]:
    """Return a list of {path, manager, ecosystem} dicts for each manifest found.

    This is an extension point. The MVP only reports presence; a future version
    can hand each manifest to a vulnerability database (e.g. OSV.dev).
    """

    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for file in files:
        name = PurePosixPath(file.path).name
        for known, manager, ecosystem in KNOWN_MANIFESTS:
            if name == known and file.path not in seen:
                seen.add(file.path)
                out.append({"path": file.path, "manager": manager, "ecosystem": ecosystem})
                break
    return out
