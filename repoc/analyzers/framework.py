"""Framework / library detection from manifest files."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import PurePosixPath

from ..models import DetectedTechnology, RepoFile

# (display_name, dependency_name(s), category)
PY_FRAMEWORKS: list[tuple[str, tuple[str, ...], str]] = [
    ("Django", ("django",), "Framework"),
    ("Flask", ("flask",), "Framework"),
    ("FastAPI", ("fastapi",), "Framework"),
    ("SQLAlchemy", ("sqlalchemy",), "Library"),
    ("Pydantic", ("pydantic",), "Library"),
    ("Pytest", ("pytest",), "Test"),
    ("Celery", ("celery",), "Library"),
    ("Streamlit", ("streamlit",), "Framework"),
    ("Jupyter", ("jupyter", "notebook", "jupyterlab"), "Framework"),
    ("Typer", ("typer",), "Library"),
    ("Click", ("click",), "Library"),
]

JS_FRAMEWORKS: list[tuple[str, tuple[str, ...], str]] = [
    ("React", ("react",), "Framework"),
    ("Next.js", ("next",), "Framework"),
    ("Vue", ("vue",), "Framework"),
    ("Nuxt", ("nuxt",), "Framework"),
    ("Svelte", ("svelte",), "Framework"),
    ("Express", ("express",), "Framework"),
    ("NestJS", ("@nestjs/core",), "Framework"),
    ("Vite", ("vite",), "Tooling"),
    ("Electron", ("electron",), "Framework"),
    ("Jest", ("jest",), "Test"),
    ("Vitest", ("vitest",), "Test"),
    ("Playwright", ("@playwright/test", "playwright"), "Test"),
    ("Cypress", ("cypress",), "Test"),
]

RUBY_FRAMEWORKS: list[tuple[str, tuple[str, ...], str]] = [
    ("Rails", ("rails",), "Framework"),
    ("Sinatra", ("sinatra",), "Framework"),
    ("RSpec", ("rspec", "rspec-rails"), "Test"),
    ("Sidekiq", ("sidekiq",), "Library"),
]

GO_FRAMEWORKS: list[tuple[str, tuple[str, ...], str]] = [
    ("Gin", ("github.com/gin-gonic/gin",), "Framework"),
    ("Fiber", ("github.com/gofiber/fiber",), "Framework"),
    ("Gorilla Mux", ("github.com/gorilla/mux",), "Framework"),
    ("Cobra", ("github.com/spf13/cobra",), "Library"),
]

RUST_FRAMEWORKS: list[tuple[str, tuple[str, ...], str]] = [
    ("Actix Web", ("actix-web",), "Framework"),
    ("Rocket", ("rocket",), "Framework"),
    ("Axum", ("axum",), "Framework"),
    ("Tokio", ("tokio",), "Library"),
    ("Clap", ("clap",), "Library"),
]

JAVA_FRAMEWORKS: list[tuple[str, tuple[str, ...], str]] = [
    ("Spring Boot", ("spring-boot",), "Framework"),
    ("Hibernate", ("hibernate-core",), "Library"),
    ("JUnit", ("junit",), "Test"),
]

PHP_FRAMEWORKS: list[tuple[str, tuple[str, ...], str]] = [
    ("Laravel", ("laravel/framework",), "Framework"),
    ("Symfony", ("symfony/framework-bundle",), "Framework"),
    ("PHPUnit", ("phpunit/phpunit",), "Test"),
]


def detect_frameworks(files: list[RepoFile]) -> list[DetectedTechnology]:
    by_path = {f.path: f for f in files}
    detected: dict[str, DetectedTechnology] = {}

    def add(name: str, category: str, confidence: float, evidence: str) -> None:
        existing = detected.get(name)
        if existing is None:
            detected[name] = DetectedTechnology(
                name=name, category=category, confidence=confidence, evidence=[evidence]
            )
            return
        existing.confidence = max(existing.confidence, confidence)
        if evidence not in existing.evidence:
            existing.evidence.append(evidence)

    # Python
    py_deps = _python_dependencies(by_path)
    if py_deps:
        for display, keys, category in PY_FRAMEWORKS:
            for key in keys:
                if key in py_deps:
                    add(display, category, 0.9, f"`{key}` in {py_deps[key]}")
                    break

    # JavaScript / TypeScript
    js_deps, js_scripts = _javascript_dependencies(by_path)
    if js_deps:
        for display, keys, category in JS_FRAMEWORKS:
            for key in keys:
                if key in js_deps:
                    add(display, category, 0.9, f"`{key}` in package.json")
                    break
    if any(p.endswith("vite.config.ts") or p.endswith("vite.config.js") for p in by_path):
        add("Vite", "Tooling", 0.85, "vite.config.* present")
    if any(p.endswith("next.config.js") or p.endswith("next.config.mjs") for p in by_path):
        add("Next.js", "Framework", 0.9, "next.config.* present")
    if any(p.endswith("nuxt.config.ts") or p.endswith("nuxt.config.js") for p in by_path):
        add("Nuxt", "Framework", 0.9, "nuxt.config.* present")
    if "angular.json" in by_path:
        add("Angular", "Framework", 0.9, "angular.json present")
    if js_scripts:
        for hook in ("preinstall", "install", "postinstall", "prepare"):
            if hook in js_scripts:
                # framework/tooling signal kept distinct from security finding
                add("npm install hook", "Tooling", 0.6, f"package.json scripts.{hook}")

    # Ruby
    rb_deps = _ruby_dependencies(by_path)
    if rb_deps:
        for display, keys, category in RUBY_FRAMEWORKS:
            for key in keys:
                if key in rb_deps:
                    add(display, category, 0.9, f"`{key}` in {rb_deps[key]}")
                    break

    # Go
    go_deps = _go_dependencies(by_path)
    if go_deps:
        for display, keys, category in GO_FRAMEWORKS:
            for key in keys:
                if any(dep.startswith(key) for dep in go_deps):
                    add(display, category, 0.9, f"`{key}` in go.mod")
                    break

    # Rust
    rust_deps = _rust_dependencies(by_path)
    if rust_deps:
        for display, keys, category in RUST_FRAMEWORKS:
            for key in keys:
                if key in rust_deps:
                    add(display, category, 0.9, f"`{key}` in Cargo.toml")
                    break

    # Java
    java_blob = _java_blob(by_path)
    if java_blob:
        for display, keys, category in JAVA_FRAMEWORKS:
            for key in keys:
                if key in java_blob:
                    add(display, category, 0.85, f"`{key}` in pom.xml/build.gradle")
                    break

    # PHP
    php_deps = _php_dependencies(by_path)
    if php_deps:
        for display, keys, category in PHP_FRAMEWORKS:
            for key in keys:
                if key in php_deps:
                    add(display, category, 0.9, f"`{key}` in composer.json")
                    break

    # Runtimes / infra
    if "Dockerfile" in by_path or any(_basename(p) == "Dockerfile" for p in by_path):
        add("Docker", "Runtime", 0.8, "Dockerfile present")
    if any(_basename(p) in {"docker-compose.yml", "compose.yml"} for p in by_path):
        add("Docker Compose", "Runtime", 0.7, "compose file present")

    return sorted(detected.values(), key=lambda t: (-t.confidence, t.name))


# --- per-ecosystem dependency parsing ---------------------------------------

def _basename(path: str) -> str:
    return PurePosixPath(path).name


def _content_for(by_path: dict[str, RepoFile], name: str) -> str | None:
    for path, file in by_path.items():
        if _basename(path) == name and file.content:
            return file.content
    return None


def _python_dependencies(by_path: dict[str, RepoFile]) -> dict[str, str]:
    """Map dependency name -> source file."""

    deps: dict[str, str] = {}

    req = _content_for(by_path, "requirements.txt")
    if req:
        for line in req.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            name = re.split(r"[<>=!~\[\s]", line, maxsplit=1)[0].lower()
            if name:
                deps[name] = "requirements.txt"

    pyproject = _content_for(by_path, "pyproject.toml")
    if pyproject:
        for name in re.findall(r'"([A-Za-z0-9_.\-]+)\s*(?:[<>=!~\[].*)?"', pyproject):
            deps.setdefault(name.lower(), "pyproject.toml")

    pipfile = _content_for(by_path, "Pipfile")
    if pipfile:
        for name in re.findall(r"(?m)^([A-Za-z0-9_.\-]+)\s*=", pipfile):
            if name.lower() not in {"name", "url", "verify_ssl", "python_version"}:
                deps.setdefault(name.lower(), "Pipfile")

    setup = _content_for(by_path, "setup.py")
    if setup:
        block = re.search(r"install_requires\s*=\s*\[(.*?)\]", setup, re.DOTALL)
        if block:
            for name in re.findall(r"['\"]([A-Za-z0-9_.\-]+)", block.group(1)):
                deps.setdefault(name.lower(), "setup.py")
    return deps


def _javascript_dependencies(by_path: dict[str, RepoFile]) -> tuple[dict[str, str], dict[str, str]]:
    pkg = _content_for(by_path, "package.json")
    if not pkg:
        return {}, {}
    try:
        data = json.loads(pkg)
    except json.JSONDecodeError:
        return {}, {}

    deps: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name in data.get(section) or {}:
            deps[name] = section
    scripts = {k: str(v) for k, v in (data.get("scripts") or {}).items() if v}
    return deps, scripts


def _ruby_dependencies(by_path: dict[str, RepoFile]) -> dict[str, str]:
    gemfile = _content_for(by_path, "Gemfile")
    lock = _content_for(by_path, "Gemfile.lock")
    deps: dict[str, str] = {}
    if gemfile:
        for name in re.findall(r"(?m)^\s*gem\s+['\"]([^'\"]+)['\"]", gemfile):
            deps[name] = "Gemfile"
    if lock:
        for name in re.findall(r"(?m)^\s{4}([A-Za-z0-9_\-]+)\s*\(", lock):
            deps.setdefault(name, "Gemfile.lock")
    return deps


def _go_dependencies(by_path: dict[str, RepoFile]) -> set[str]:
    gomod = _content_for(by_path, "go.mod")
    if not gomod:
        return set()
    deps: set[str] = set()
    for line in gomod.splitlines():
        line = line.strip()
        if line.startswith(("module ", "go ", "//")):
            continue
        parts = line.split()
        if parts:
            deps.add(parts[0])
    return deps


def _rust_dependencies(by_path: dict[str, RepoFile]) -> set[str]:
    cargo = _content_for(by_path, "Cargo.toml")
    if not cargo:
        return set()
    deps: set[str] = set()
    in_deps_section = False
    for line in cargo.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_deps_section = "dependencies" in stripped
            continue
        if in_deps_section and "=" in stripped and not stripped.startswith("#"):
            name = stripped.split("=", 1)[0].strip().strip('"')
            if name:
                deps.add(name)
    return deps


def _java_blob(by_path: dict[str, RepoFile]) -> str:
    parts: list[str] = []
    for name in ("pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle"):
        content = _content_for(by_path, name)
        if content:
            parts.append(content)
    return "\n".join(parts)


def _php_dependencies(by_path: dict[str, RepoFile]) -> set[str]:
    composer = _content_for(by_path, "composer.json")
    if not composer:
        return set()
    try:
        data = json.loads(composer)
    except json.JSONDecodeError:
        return set()
    deps: set[str] = set()
    for section in ("require", "require-dev"):
        deps.update((data.get(section) or {}).keys())
    return deps


def js_install_hooks(files: Iterable[RepoFile]) -> dict[str, str]:
    """Return the install-hook scripts declared in package.json (if any)."""

    for file in files:
        if _basename(file.path) != "package.json" or not file.content:
            continue
        try:
            data = json.loads(file.content)
        except json.JSONDecodeError:
            return {}
        scripts = data.get("scripts") or {}
        return {k: str(v) for k, v in scripts.items() if k in {"preinstall", "install", "postinstall", "prepare"}}
    return {}
