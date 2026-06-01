from repoc.analyzers.language import detect_languages, primary_language


def test_detects_python_from_extensions_and_manifest(make_file):
    files = [
        make_file("repoc/__init__.py", "x = 1"),
        make_file("repoc/cli.py", "import typer"),
        make_file("pyproject.toml", "[project]\nname = 'x'\n"),
    ]
    languages = detect_languages(files)
    assert primary_language(languages) == "Python"
    assert any(t.name == "Python" and t.confidence > 0.5 for t in languages)


def test_typescript_outranks_javascript_when_more_files(make_file):
    files = [
        make_file("src/index.ts", "export const x = 1"),
        make_file("src/util.ts", "export const y = 2"),
        make_file("src/legacy.js", "const z = 3"),
        make_file("tsconfig.json", "{}"),
    ]
    languages = detect_languages(files)
    names = [t.name for t in languages]
    assert "TypeScript" in names
    assert names.index("TypeScript") < names.index("JavaScript")


def test_github_language_stats_are_merged(make_file):
    files = [make_file("README.md", "# hi")]
    languages = detect_languages(files, github_languages={"Go": 80_000, "Shell": 5_000})
    names = [t.name for t in languages]
    assert "Go" in names
    assert primary_language(languages) == "Go"
