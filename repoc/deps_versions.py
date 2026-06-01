"""Extract pinned (ecosystem, name, version) tuples from lockfiles.

Only lockfiles/manifests that carry an *exact* resolved version are parsed —
querying OSV needs a concrete version, and a range like `^1.2.3` from a bare
package.json would be ambiguous. Ecosystem names match OSV's vocabulary
(https://ossf.github.io/osv-schema/#defined-ecosystems).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import PurePosixPath
from typing import NamedTuple

from .models import RepoFile


class DepVersion(NamedTuple):
    ecosystem: str
    name: str
    version: str
    source: str  # manifest path the version came from


def extract_versions(files: list[RepoFile]) -> list[DepVersion]:
    out: list[DepVersion] = []
    seen: set[tuple[str, str, str]] = set()
    for f in files:
        if not f.content:
            continue
        parser = _PARSERS.get(PurePosixPath(f.path).name)
        if parser is None:
            continue
        for dep in parser(f.content, f.path):
            key = (dep.ecosystem, dep.name, dep.version)
            if key in seen:
                continue
            seen.add(key)
            out.append(dep)
    return out


# --- per-manifest parsers ----------------------------------------------------

_REQ_LINE = re.compile(r"^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _parse_requirements(content: str, path: str) -> Iterator[DepVersion]:
    for raw in content.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _REQ_LINE.match(line)
        if m:
            yield DepVersion("PyPI", m.group(1).lower(), m.group(2), path)


def _toml_packages(content: str, eco: str, path: str, *, lower: bool) -> Iterator[DepVersion]:
    # poetry.lock and Cargo.lock both use [[package]] blocks with name/version.
    for block in content.split("[[package]]")[1:]:
        name = re.search(r'(?m)^\s*name\s*=\s*"([^"]+)"', block)
        ver = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', block)
        if name and ver:
            n = name.group(1)
            yield DepVersion(eco, n.lower() if lower else n, ver.group(1), path)


def _parse_poetry_lock(content: str, path: str) -> Iterator[DepVersion]:
    yield from _toml_packages(content, "PyPI", path, lower=True)


def _parse_cargo_lock(content: str, path: str) -> Iterator[DepVersion]:
    yield from _toml_packages(content, "crates.io", path, lower=False)


def _parse_pipfile_lock(content: str, path: str) -> Iterator[DepVersion]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return
    for section in ("default", "develop"):
        for name, spec in (data.get(section) or {}).items():
            version = spec.get("version", "") if isinstance(spec, dict) else ""
            m = re.match(r"==\s*([A-Za-z0-9][A-Za-z0-9._-]*)", str(version).strip())
            if m:
                yield DepVersion("PyPI", str(name).lower(), m.group(1), path)


def _parse_package_lock(content: str, path: str) -> Iterator[DepVersion]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return
    # npm lockfile v2/v3: a "packages" map keyed by install path.
    packages = data.get("packages")
    if isinstance(packages, dict):
        for pkg_path, spec in packages.items():
            if not pkg_path or not isinstance(spec, dict):
                continue  # "" is the root project
            name = pkg_path.split("node_modules/")[-1]
            version = spec.get("version")
            if name and version:
                yield DepVersion("npm", name, str(version), path)
        return
    # v1: nested "dependencies" tree.
    stack = [data.get("dependencies")]
    while stack:
        deps = stack.pop()
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(spec, dict):
                continue
            version = spec.get("version")
            if version:
                yield DepVersion("npm", str(name), str(version), path)
            stack.append(spec.get("dependencies"))


_GEMFILE_SPEC = re.compile(r"^    ([A-Za-z0-9._-]+) \(([0-9][^)]*)\)\s*$")


def _parse_gemfile_lock(content: str, path: str) -> Iterator[DepVersion]:
    # Exact resolved gems sit under GEM/specs indented exactly 4 spaces.
    for line in content.splitlines():
        m = _GEMFILE_SPEC.match(line)
        if m:
            yield DepVersion("RubyGems", m.group(1), m.group(2), path)


def _parse_composer_lock(content: str, path: str) -> Iterator[DepVersion]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section) or []:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            version = str(pkg.get("version", ""))
            if version.startswith("dev-") or not name or not version:
                continue
            yield DepVersion("Packagist", name, version.lstrip("v"), path)


_GOMOD_REQUIRE = re.compile(r"^(?:require\s+)?([^\s]+)\s+(v[0-9][^\s]*)")


def _parse_go_mod(content: str, path: str) -> Iterator[DepVersion]:
    in_block = False
    for raw in content.splitlines():
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if not (in_block or line.startswith("require ")):
            continue
        # strip a trailing "// indirect" comment
        line = line.split("//", 1)[0].strip()
        m = _GOMOD_REQUIRE.match(line)
        if m:
            yield DepVersion("Go", m.group(1), m.group(2).lstrip("v"), path)


_PARSERS = {
    "requirements.txt": _parse_requirements,
    "poetry.lock": _parse_poetry_lock,
    "Cargo.lock": _parse_cargo_lock,
    "Pipfile.lock": _parse_pipfile_lock,
    "package-lock.json": _parse_package_lock,
    "Gemfile.lock": _parse_gemfile_lock,
    "composer.lock": _parse_composer_lock,
    "go.mod": _parse_go_mod,
}
