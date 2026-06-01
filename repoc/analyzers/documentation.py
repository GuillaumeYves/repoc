"""Documentation analysis: look for the usual project files."""

from __future__ import annotations

from pathlib import PurePosixPath

from ..models import Finding, RepoFile, Severity

EXPECTED = {
    "README": (("readme.md", "readme.rst", "readme.txt", "readme"), 30),
    "LICENSE": (("license", "license.md", "license.txt", "copying"), 20),
    "CONTRIBUTING": (("contributing.md", "contributing.rst"), 10),
    "SECURITY": (("security.md",), 15),
    "CODE_OF_CONDUCT": (("code_of_conduct.md", "code-of-conduct.md"), 5),
    "CHANGELOG": (("changelog.md", "changes.md", "history.md"), 10),
    "docs/": ("docs",),
    "examples/": ("examples", "example"),
}


def analyze_documentation(files: list[RepoFile]) -> tuple[int, list[Finding]]:
    paths_lower = {f.path.lower() for f in files}
    top_level_names = {PurePosixPath(p).name.lower() for p in paths_lower if "/" not in p}
    dirs_lower = {p.split("/", 1)[0] for p in paths_lower if "/" in p}

    score = 0
    findings: list[Finding] = []

    def has_file(names: tuple[str, ...]) -> bool:
        return any(name in top_level_names for name in names)

    def has_dir(names: tuple[str, ...]) -> bool:
        return any(name in dirs_lower for name in names)

    if has_file(EXPECTED["README"][0]):
        score += EXPECTED["README"][1]
    else:
        findings.append(
            Finding(
                rule_id="DOC001",
                title="No README found",
                severity=Severity.MEDIUM,
                description="Repositories without a README are harder to evaluate.",
                recommendation="Add a README that describes what the project is and how to use it.",
            )
        )

    if has_file(EXPECTED["LICENSE"][0]):
        score += EXPECTED["LICENSE"][1]
    if has_file(EXPECTED["CONTRIBUTING"][0]):
        score += EXPECTED["CONTRIBUTING"][1]
    if has_file(EXPECTED["SECURITY"][0]):
        score += EXPECTED["SECURITY"][1]
    else:
        findings.append(
            Finding(
                rule_id="DOC002",
                title="No SECURITY.md",
                severity=Severity.LOW,
                description="The project does not document how to report security issues.",
                recommendation="Add a SECURITY.md with reporting instructions.",
            )
        )
    if has_file(EXPECTED["CODE_OF_CONDUCT"][0]):
        score += EXPECTED["CODE_OF_CONDUCT"][1]
    if has_file(EXPECTED["CHANGELOG"][0]):
        score += EXPECTED["CHANGELOG"][1]
    if has_dir(EXPECTED["docs/"]):
        score += 5
    if has_dir(EXPECTED["examples/"]):
        score += 5

    findings = [f.model_copy(update={"category": "documentation"}) for f in findings]
    return min(100, score), findings
