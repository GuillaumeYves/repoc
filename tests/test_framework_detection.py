import json

from repoc.analyzers.framework import detect_frameworks, js_install_hooks
from repoc.analyzers.project_type import classify_project_type


def test_detects_fastapi_from_pyproject(make_file):
    pyproject = """
[project]
name = "demo"
dependencies = ["fastapi", "pydantic"]
"""
    files = [make_file("pyproject.toml", pyproject), make_file("app.py", "from fastapi import FastAPI")]
    frameworks = detect_frameworks(files)
    names = {f.name for f in frameworks}
    assert {"FastAPI", "Pydantic"} <= names


def test_detects_react_from_package_json(make_file):
    pkg = json.dumps({
        "name": "demo",
        "dependencies": {"react": "^18.0.0", "react-dom": "^18.0.0"},
        "scripts": {"build": "vite build"},
    })
    files = [make_file("package.json", pkg), make_file("vite.config.ts", "export default {}")]
    frameworks = detect_frameworks(files)
    names = {f.name for f in frameworks}
    assert "React" in names
    assert "Vite" in names


def test_install_hooks_detected_in_package_json(make_file):
    pkg = json.dumps({
        "name": "demo",
        "scripts": {"postinstall": "node bad.js", "build": "vite build"},
    })
    hooks = js_install_hooks([make_file("package.json", pkg)])
    assert "postinstall" in hooks
    assert "build" not in hooks


def test_project_type_python_cli(make_file):
    pyproject = """
[project]
name = "demo"
dependencies = ["typer"]
"""
    files = [make_file("pyproject.toml", pyproject), make_file("demo/cli.py", "import typer")]
    frameworks = detect_frameworks(files)
    languages = []  # not needed for this rule
    assert classify_project_type(files, frameworks, languages) == "CLI tool"


def test_project_type_frontend(make_file):
    pkg = json.dumps({
        "name": "demo",
        "dependencies": {"next": "^14"},
    })
    files = [make_file("package.json", pkg), make_file("next.config.js", "module.exports = {}")]
    frameworks = detect_frameworks(files)
    from repoc.models import DetectedTechnology
    languages = [DetectedTechnology(name="JavaScript", category="Language", confidence=0.9, evidence=[])]
    assert classify_project_type(files, frameworks, languages) == "Frontend app"
