"""Shared helpers: target parsing, file loading, redaction."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from .models import RepoFile

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".class", ".jar", ".war",
    ".pyc", ".pyo", ".whl",
    ".mp3", ".mp4", ".mov", ".wav", ".avi", ".mkv", ".webm",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".bin", ".dat", ".db", ".sqlite", ".sqlite3",
}

SKIP_DIRECTORIES = {
    ".git", ".hg", ".svn",
    "node_modules", "bower_components",
    ".venv", "venv", "env",
    "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache",
    "dist", "build", ".next", ".nuxt", "target",
    ".idea", ".vscode",
}


@dataclass(frozen=True)
class Target:
    """Parsed user-supplied target."""

    kind: str  # "github" or "local"
    owner: str | None = None
    repo: str | None = None
    local_path: Path | None = None

    @property
    def display(self) -> str:
        if self.kind == "github":
            return f"{self.owner}/{self.repo}"
        assert self.local_path is not None
        return str(self.local_path)


_GITHUB_SLUG = re.compile(r"^(?P<owner>[A-Za-z0-9_.\-]+)/(?P<repo>[A-Za-z0-9_.\-]+?)(?:\.git)?$")


def parse_target(value: str, force_local: bool = False) -> Target:
    """Parse a CLI target into a structured Target."""

    if force_local:
        path = Path(value).expanduser().resolve()
        if not path.exists():
            raise ValueError(f"Local path does not exist: {path}")
        return Target(kind="local", local_path=path)

    candidate = value.strip()

    # URL form
    if candidate.startswith(("http://", "https://", "git@")):
        if candidate.startswith("git@"):
            # git@github.com:owner/repo.git
            _, _, rest = candidate.partition(":")
            slug = rest
        else:
            parsed = urlparse(candidate)
            if "github.com" not in parsed.netloc:
                raise ValueError(f"Only github.com URLs are supported, got: {parsed.netloc}")
            slug = parsed.path.lstrip("/")
        match = _GITHUB_SLUG.match(slug)
        if not match:
            raise ValueError(f"Could not extract owner/repo from URL: {value}")
        return Target(kind="github", owner=match["owner"], repo=match["repo"])

    # owner/repo form
    match = _GITHUB_SLUG.match(candidate)
    if match and "/" in candidate and not Path(candidate).exists():
        return Target(kind="github", owner=match["owner"], repo=match["repo"])

    # Local path fallback
    path = Path(candidate).expanduser().resolve()
    if not path.exists():
        raise ValueError(
            f"Target is neither a valid GitHub reference nor an existing local path: {value}"
        )
    return Target(kind="local", local_path=path)


def is_probably_binary(path: Path | str, sample: bytes | None = None) -> bool:
    suffix = Path(path).suffix.lower()
    if suffix in BINARY_EXTENSIONS:
        return True
    if sample is None:
        return False
    return b"\x00" in sample


def in_skip_dir(path: str) -> bool:
    """True if any parent directory of a posix path is in SKIP_DIRECTORIES."""

    return any(part in SKIP_DIRECTORIES for part in path.split("/")[:-1])


def _is_within(path: Path, root: Path) -> bool:
    """True if ``path`` (already resolved) is inside ``root`` (resolved)."""

    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class LocalScan:
    """Result of walking a local repository, including coverage signal."""

    files: list[RepoFile]
    total_seen: int      # candidate text/dir files encountered (incl. beyond the cap)
    cap_reached: bool


def load_local_repo(
    root: Path,
    max_files: int = 500,
    max_file_size: int = 200_000,
) -> LocalScan:
    """Walk a local directory and return text files up to the given limits.

    Symlinks are never followed and entries that resolve outside ``root`` are
    skipped. A repository is untrusted input: without this, a crafted symlink
    (e.g. pointing at your home directory or ``/``) could make repoc read files
    well outside the target and bake them — even redacted — into a report.

    ``total_seen`` counts candidate files even past the ``max_files`` cap so the
    caller can report honest scan coverage.
    """

    root_resolved = root.resolve()
    files: list[RepoFile] = []
    total_seen = 0
    cap_reached = False

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Prune skip dirs and any symlinked directories in place so os.walk does
        # not descend into them. Sort for deterministic ordering.
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in SKIP_DIRECTORIES and not (Path(dirpath) / d).is_symlink()
        )
        for filename in sorted(filenames):
            full = Path(dirpath) / filename
            if full.is_symlink():
                continue
            try:
                resolved = full.resolve()
            except OSError:
                continue
            if not _is_within(resolved, root_resolved):
                continue
            try:
                size = full.stat().st_size
            except OSError:
                continue

            total_seen += 1
            if len(files) >= max_files:
                cap_reached = True
                continue

            rel = full.relative_to(root).as_posix()

            if size > max_file_size:
                files.append(RepoFile(path=rel, size=size, truncated=True))
                continue

            try:
                raw = full.read_bytes()
            except OSError:
                continue

            if is_probably_binary(full, raw[:1024]):
                files.append(RepoFile(path=rel, size=size, is_binary=True))
                continue

            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("utf-8", errors="replace")

            files.append(RepoFile(path=rel, size=size, content=text))

    return LocalScan(files=files, total_seen=total_seen, cap_reached=cap_reached)


def redact_secret(value: str, keep: int = 4) -> str:
    """Show only the first few chars of a possible secret."""

    if not value:
        return ""
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "*" * max(8, len(value) - keep)
