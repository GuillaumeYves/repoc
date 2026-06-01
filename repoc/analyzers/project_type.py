"""Infer the high-level project type from detected technologies + files."""

from __future__ import annotations

from pathlib import PurePosixPath

from ..models import DetectedTechnology, RepoFile

FRONTEND_FRAMEWORKS = {"React", "Vue", "Svelte", "Angular", "Next.js", "Nuxt"}
BACKEND_FRAMEWORKS = {"Express", "NestJS", "Django", "Flask", "FastAPI", "Rails", "Spring Boot", "Laravel", "Symfony"}
ML_DEPS = {"numpy", "pandas", "scikit-learn", "sklearn", "tensorflow", "torch", "keras", "transformers"}
GAME_DEPS = {"pygame", "godot", "unity", "phaser", "love"}


def classify_project_type(
    files: list[RepoFile],
    frameworks: list[DetectedTechnology],
    languages: list[DetectedTechnology],
) -> str:
    framework_names = {f.name for f in frameworks}
    language_names = {lang.name for lang in languages}
    paths = {f.path for f in files}

    has_dockerfile = any(_basename(p) == "Dockerfile" for p in paths)
    has_terraform = any(p.endswith(".tf") for p in paths)
    has_helm = any(_basename(p) == "Chart.yaml" for p in paths)
    has_ipynb = any(p.endswith(".ipynb") for p in paths)
    has_manifest_xml = any(_basename(p) == "manifest.json" for p in paths)
    has_chrome_manifest = any("background.js" in p or "content_script" in p for p in paths)

    if has_terraform or has_helm:
        return "Infrastructure/devops repo"

    if has_ipynb and (language_names & {"Python"}):
        return "Data science notebook repo"

    frontend = framework_names & FRONTEND_FRAMEWORKS
    backend = framework_names & BACKEND_FRAMEWORKS
    if frontend and backend:
        return "Fullstack app"
    if frontend:
        return "Frontend app"
    if backend:
        return "Backend API"

    # CLI detection
    if {"Typer", "Click"} & framework_names:
        return "CLI tool"
    if "Clap" in framework_names and "Rust" in language_names:
        return "CLI tool"
    if "Cobra" in framework_names and "Go" in language_names:
        return "CLI tool"

    # Library detection
    if any(_basename(p) in {"pyproject.toml", "setup.py"} for p in paths) and not backend and not frontend:
        return "Library/package"
    if "package.json" in {_basename(p) for p in paths} and "Electron" in framework_names:
        return "Desktop app"

    if has_chrome_manifest or (has_manifest_xml and any("popup" in p for p in paths)):
        return "Browser extension"

    if has_dockerfile and not (backend or frontend):
        return "Dockerized service"

    if any(name in {f.name.lower() for f in frameworks} for name in GAME_DEPS):
        return "Game project"

    if "Swift" in language_names or "Kotlin" in language_names or "Dart" in language_names:
        return "Mobile app"

    return "Unknown"


def _basename(path: str) -> str:
    return PurePosixPath(path).name
