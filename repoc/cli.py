"""Typer-based CLI entry point for repoc."""

from __future__ import annotations

import contextlib
import sys
from enum import StrEnum
from pathlib import Path

import typer
from rich.console import Console

from . import __version__
from .analyzers import (
    coverage as coverage_analyzer,
)
from .analyzers import (
    dependencies,
    documentation,
    framework,
    language,
    maintenance,
    project_type,
    security,
)
from .auth import AuthError, device_login, read_token_from_stdin
from .github_client import GitHubClient, GitHubError, RateLimitError
from .models import (
    SEVERITY_ORDER,
    AnalysisResult,
    DetectedTechnology,
    RepoFile,
    RepositoryMetadata,
    ScanCoverage,
    ScoreBreakdown,
    Severity,
)
from .renderers import json as json_renderer
from .renderers import markdown as markdown_renderer
from .renderers import terminal as terminal_renderer
from .scoring import (
    build_recommendations,
    compute_trust_score,
    risk_level,
    security_score,
    structure_score,
)
from .utils import Target, in_skip_dir, load_local_repo, parse_target


def _force_utf8_streams() -> None:
    """Make stdout/stderr UTF-8.

    On Windows the default console encoding (cp1252) cannot represent the box
    characters Rich uses for Markdown rendering, nor arbitrary non-ASCII repo
    content — writing either would raise UnicodeEncodeError when the output is
    piped or redirected. Reconfiguring to UTF-8 keeps reports valid everywhere.
    """

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):  # pragma: no cover
                reconfigure(encoding="utf-8", errors="replace")


_force_utf8_streams()

app = typer.Typer(
    name="repoc",
    help="repo + doctor. Inspect a repository for trust, stack, and security signals.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


class OutputFormat(StrEnum):
    TERMINAL = "terminal"
    MARKDOWN = "markdown"
    JSON = "json"


class FailOn(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Categories that count toward a CI gate. Maintenance/documentation/coverage
# findings are informational and never fail a --fail-on gate.
_GATE_CATEGORIES = {"secret", "install_hook", "code_pattern"}


# Curated list of paths we always try to fetch when inspecting a remote repo.
RELEVANT_FILES: tuple[str, ...] = (
    "README.md", "README.rst", "README.txt", "README",
    "LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING",
    "CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md", "CHANGELOG.md",
    "pyproject.toml", "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock", "setup.py", "setup.cfg",
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "tsconfig.json", "vite.config.js", "vite.config.ts", "next.config.js", "next.config.mjs",
    "nuxt.config.ts", "nuxt.config.js", "angular.json",
    "Gemfile", "Gemfile.lock", "config/routes.rb", "config/application.rb",
    "go.mod", "go.sum",
    "Cargo.toml", "Cargo.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
    "composer.json", "composer.lock", "artisan",
    "Dockerfile", "docker-compose.yml", "compose.yml",
    "Makefile", "makefile",
    "install.sh", "scripts/install.sh", "bootstrap.sh", "setup.sh",
    ".env", ".env.example",
)

ACTIONS_PREFIX = ".github/workflows/"

# Source-file suffixes pulled in by --deep (in addition to the curated manifests).
INTERESTING_SUFFIXES = (
    ".py", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".rb", ".php", ".phtml",
    ".go", ".rs", ".java", ".kt", ".cs", ".c", ".cc", ".cpp", ".h", ".hpp",
    ".sh", ".bash", ".zsh",
)


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"repoc {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=version_callback,
        is_eager=True,
        help="Show repoc version and exit.",
    ),
) -> None:
    """repo + doctor."""


@app.command()
def inspect(
    target: str = typer.Argument(..., help="owner/repo, a github.com URL, or a local path."),
    local: bool = typer.Option(False, "--local", help="Force the target to be interpreted as a local path."),
    format: OutputFormat = typer.Option(
        OutputFormat.TERMINAL, "--format", "-f", help="Output format."
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write report to this file instead of stdout."
    ),
    deep: bool = typer.Option(False, "--deep", help="Inspect a wider set of files (slower)."),
    no_network: bool = typer.Option(False, "--no-network", help="Skip all GitHub API calls."),
    max_files: int = typer.Option(500, "--max-files", help="Maximum number of files to load."),
    max_file_size: int = typer.Option(200_000, "--max-file-size", help="Maximum file size in bytes."),
    github_token: str | None = typer.Option(
        None, "--github-token", envvar="GITHUB_TOKEN", help="GitHub token for authenticated requests."
    ),
    token_stdin: bool = typer.Option(
        False,
        "--token-stdin",
        help="Read a GitHub token from stdin (keeps it out of shell history/argv). Not stored.",
    ),
    login: bool = typer.Option(
        False,
        "--login",
        help="Authorize via GitHub's one-time device-code flow for this run only. Nothing is stored.",
    ),
    fail_on: FailOn = typer.Option(
        FailOn.NONE,
        "--fail-on",
        help="Exit non-zero (code 1) if any security finding meets/exceeds this severity. For CI gates.",
    ),
) -> None:
    """Inspect a repository and print or write a report."""

    try:
        parsed_target = parse_target(target, force_local=local)
    except ValueError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    # Resolve an ephemeral token (precedence: explicit flag/env > stdin > device
    # login). The token is held in memory for this run only and never persisted.
    try:
        github_token = _resolve_token(
            github_token=github_token, token_stdin=token_stdin, login=login
        )
    except AuthError as exc:
        err_console.print(f"[red]Authentication error:[/red] {exc}")
        raise typer.Exit(code=4) from exc

    try:
        result = run_analysis(
            parsed_target,
            deep=deep,
            no_network=no_network,
            max_files=max_files,
            max_file_size=max_file_size,
            github_token=github_token,
        )
    except RateLimitError as exc:
        err_console.print(
            f"[red]GitHub API rate limit hit.[/red] Try again after the reset window "
            f"or set GITHUB_TOKEN. ({exc.message})"
        )
        raise typer.Exit(code=3) from exc
    except GitHubError as exc:
        err_console.print(f"[red]GitHub error:[/red] {exc}")
        raise typer.Exit(code=3) from exc
    except ValueError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    _write_output(result, format=format, output=output)

    if fail_on is not FailOn.NONE:
        breached = _gate_severity(result, Severity(fail_on.value))
        if breached is not None:
            err_console.print(
                f"[red]--fail-on {fail_on.value}:[/red] found a "
                f"{breached.value.upper()} security finding. Exiting with code 1."
            )
            raise typer.Exit(code=1)


def _fetch_remote_files(
    client: GitHubClient,
    owner: str,
    repo: str,
    ref: str,
    tree_paths: list[str],
    *,
    deep: bool,
    max_files: int,
    max_file_size: int,
) -> tuple[list[RepoFile], int, bool]:
    """Return (files, intended_count, cap_reached) for a remote repo.

    --deep downloads the repo as a single tarball (one request) instead of one
    API call per file. If that fails (e.g. a private repo whose tarball redirect
    drops auth, or a network error) we fall back to the curated per-file fetch.
    """

    if deep:
        try:
            scan = client.download_tarball(
                owner, repo, ref, max_files=max_files, max_file_size=max_file_size
            )
            return scan.files, scan.total_seen, scan.cap_reached
        except GitHubError:
            pass  # fall through to the curated fetch below

    candidates = list(RELEVANT_FILES)
    candidates.extend(p for p in tree_paths if p.startswith(ACTIONS_PREFIX))
    if deep:
        candidates.extend(
            p for p in tree_paths
            if p.endswith(INTERESTING_SUFFIXES) and p not in candidates
        )
    tree_set = set(tree_paths)
    intended = len({c for c in candidates if c in tree_set})
    files = client.fetch_relevant_files(
        owner, repo, ref, candidates=candidates,
        max_files=max_files, max_file_size=max_file_size,
    )
    return files, intended, len(files) >= max_files


def _gate_severity(result: AnalysisResult, threshold: Severity) -> Severity | None:
    """Return the worst security finding severity that meets the threshold, else None."""

    minimum = SEVERITY_ORDER[threshold]
    breaching = [
        f.severity
        for f in result.findings
        if f.category in _GATE_CATEGORIES and SEVERITY_ORDER[f.severity] >= minimum
    ]
    if not breaching:
        return None
    return max(breaching, key=lambda s: SEVERITY_ORDER[s])


def _resolve_token(*, github_token: str | None, token_stdin: bool, login: bool) -> str | None:
    """Return an in-memory GitHub token, or None. Never persisted anywhere."""

    if github_token:
        return github_token
    if token_stdin:
        return read_token_from_stdin()
    if login:
        return device_login(prompt=lambda msg: err_console.print(msg))
    return None


def run_analysis(
    target: Target,
    *,
    deep: bool = False,
    no_network: bool = False,
    max_files: int = 500,
    max_file_size: int = 200_000,
    github_token: str | None = None,
) -> AnalysisResult:
    """Orchestrate file loading + analyzers + scoring."""

    metadata: RepositoryMetadata
    files: list[RepoFile]
    coverage: ScanCoverage
    github_languages: dict[str, int] = {}
    has_ci = False

    if target.kind == "github":
        if no_network:
            raise ValueError("--no-network was set but the target is a GitHub repository.")
        assert target.owner and target.repo
        with GitHubClient(token=github_token) as client:
            raw = client.get_repo(target.owner, target.repo)
            metadata = _metadata_from_github(raw)
            github_languages = client.get_languages(target.owner, target.repo)
            default_branch = metadata.default_branch or "HEAD"
            tree_paths = client.fetch_paths_from_tree(target.owner, target.repo, default_branch)

            files, intended, cap_reached = _fetch_remote_files(
                client, target.owner, target.repo, default_branch, tree_paths,
                deep=deep, max_files=max_files, max_file_size=max_file_size,
            )
        has_ci = any(f.path.startswith(ACTIONS_PREFIX) for f in files)
        source_in_repo = sum(
            1 for p in tree_paths
            if coverage_analyzer.is_source_path(p) and not in_skip_dir(p)
        )
        coverage = coverage_analyzer.build_coverage(
            files, intended=intended, cap_reached=cap_reached, deep=deep,
            source_files_in_repo=source_in_repo,
        )
    else:
        assert target.local_path is not None
        scan = load_local_repo(
            target.local_path, max_files=max_files, max_file_size=max_file_size
        )
        files = scan.files
        metadata = RepositoryMetadata(
            name=target.local_path.name,
            license=maintenance.detect_local_license(files),
        )
        has_ci = any(f.path.startswith(ACTIONS_PREFIX) for f in files)
        coverage = coverage_analyzer.build_coverage(
            files, intended=scan.total_seen, cap_reached=scan.cap_reached, deep=deep
        )

    languages = language.detect_languages(files, github_languages=github_languages or None)
    frameworks = framework.detect_frameworks(files)
    proj_type = project_type.classify_project_type(files, frameworks, languages)
    manifests = dependencies.detect_dependency_manifests(files)

    findings = []
    findings.extend(security.scan_files(files))
    findings.extend(maintenance.analyze_maintenance(metadata))
    doc_score, doc_findings = documentation.analyze_documentation(files)
    findings.extend(doc_findings)
    findings.extend(coverage_analyzer.coverage_findings(coverage))

    # security_score ignores maintenance/documentation findings internally.
    sec_score = security_score(findings)
    maint_score = maintenance.maintenance_score(metadata, [f for f in findings if f.rule_id.startswith("MN")])
    # Popularity is only meaningful for remote GitHub targets — stars/forks are
    # unknowable for a local checkout, so we exclude the dimension instead of
    # baking a misleading "25/100 unknown" baseline into the trust score.
    pop_score = maintenance.popularity_score(metadata) if target.kind == "github" else None
    has_tests = any(
        f.path.startswith(("tests/", "test/", "spec/")) or "/tests/" in f.path or "/test/" in f.path
        for f in files
    )
    has_manifest = bool(manifests)
    struct_score = structure_score(len(files), has_tests, has_manifest, has_ci)

    breakdown = ScoreBreakdown(
        security=sec_score,
        maintenance=maint_score,
        documentation=doc_score,
        popularity=pop_score,
        structure=struct_score,
    )
    trust = compute_trust_score(breakdown)
    risk = risk_level(findings, trust)

    verdict = _build_verdict(metadata, proj_type, languages, frameworks, findings, manifests)
    recommendations = build_recommendations(findings, breakdown)

    return AnalysisResult(
        repository=metadata,
        verdict=verdict,
        trust_score=trust,
        risk_level=risk.value,
        detected_languages=languages,
        detected_frameworks=frameworks,
        project_type=proj_type,
        findings=findings,
        score_breakdown=breakdown,
        recommendations=recommendations,
        coverage=coverage,
        repoc_version=__version__,
    )


def _metadata_from_github(raw: dict) -> RepositoryMetadata:
    owner = (raw.get("owner") or {}).get("login")
    license_block = raw.get("license") or {}
    return RepositoryMetadata(
        name=raw.get("name") or "unknown",
        owner=owner,
        url=raw.get("html_url"),
        description=raw.get("description"),
        default_branch=raw.get("default_branch"),
        stars=raw.get("stargazers_count"),
        forks=raw.get("forks_count"),
        watchers=raw.get("subscribers_count") or raw.get("watchers_count"),
        open_issues=raw.get("open_issues_count"),
        license=license_block.get("spdx_id") if license_block else None,
        archived=raw.get("archived"),
        pushed_at=raw.get("pushed_at"),
    )


def _build_verdict(
    metadata: RepositoryMetadata,
    proj_type: str | None,
    languages: list[DetectedTechnology],
    frameworks: list[DetectedTechnology],
    findings: list,
    manifests: list[dict],
) -> str:
    bits: list[str] = []
    name = metadata.url or metadata.name
    primary = languages[0].name if languages else "an unknown language"
    framework_names = ", ".join(f.name for f in frameworks[:3])
    stack = f" using {framework_names}" if framework_names else ""
    # proj_type can be the literal string "Unknown" (not None), so normalise it
    # to avoid the ungrammatical "a Unknown".
    type_phrase = proj_type if proj_type and proj_type != "Unknown" else "project of unknown type"
    bits.append(f"{name} appears to be a {type_phrase} written in {primary}{stack}.")

    if metadata.archived:
        bits.append("The repository is archived on GitHub and will not receive updates.")
    if not findings:
        bits.append("No suspicious patterns were detected by the rule-based scanner.")
    else:
        from .models import Severity
        criticals = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        highs = sum(1 for f in findings if f.severity == Severity.HIGH)
        if criticals or highs:
            bits.append(
                f"The scan produced {criticals} CRITICAL and {highs} HIGH severity findings that deserve manual review."
            )
        else:
            bits.append("The scan produced low-severity findings only.")

    if manifests:
        ecosystems = sorted({m["ecosystem"] for m in manifests})
        bits.append(f"Dependency manifests found for: {', '.join(ecosystems)}.")
    return " ".join(bits)


def _write_output(result: AnalysisResult, *, format: OutputFormat, output: Path | None) -> None:
    if format == OutputFormat.JSON:
        body = json_renderer.render(result)
    elif format == OutputFormat.MARKDOWN:
        body = markdown_renderer.render(result)
    else:  # terminal
        if output is not None:
            body = markdown_renderer.render(result)
        else:
            terminal_renderer.render(result, console=console)
            return

    if not body.endswith("\n"):
        body += "\n"

    if output is not None:
        output.write_text(body, encoding="utf-8")
        err_console.print(f"[green]Report written to {output}[/green]")
    else:
        # Write UTF-8 bytes directly so JSON/Markdown stay valid even when the
        # console's default encoding (e.g. cp1252 on Windows) can't represent a
        # character from the repo's content.
        buffer = getattr(sys.stdout, "buffer", None)
        if buffer is not None:
            buffer.write(body.encode("utf-8"))
            buffer.flush()
        else:  # pragma: no cover - exotic stdout (e.g. captured stream)
            sys.stdout.write(body)


if __name__ == "__main__":  # pragma: no cover
    app()
