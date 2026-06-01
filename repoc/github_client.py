"""Minimal GitHub REST API client used by repoc."""

from __future__ import annotations

import base64
import io
import os
import tarfile
from dataclasses import dataclass, field
from typing import Any, NamedTuple

import httpx

from .models import RepoFile
from .utils import in_skip_dir, is_probably_binary

GITHUB_API = "https://api.github.com"

# Guard against pathologically large downloads / decompression bombs.
_MAX_TARBALL_BYTES = 80 * 1024 * 1024


class RemoteScan(NamedTuple):
    files: list[RepoFile]
    total_seen: int
    cap_reached: bool


class GitHubError(RuntimeError):
    """Raised for unrecoverable GitHub API errors."""


@dataclass
class RateLimitError(GitHubError):
    reset_seconds: int = 0
    message: str = "GitHub API rate limit exceeded."


@dataclass
class GitHubClient:
    token: str | None = None
    timeout: float = 15.0
    _client: httpx.Client | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        token = self.token or os.environ.get("GITHUB_TOKEN")
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "repoc/0.1 (+https://github.com/GuillaumeYves/repoc)",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(base_url=GITHUB_API, headers=headers, timeout=self.timeout)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> GitHubClient:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # --- helpers --------------------------------------------------------

    def _get(self, path: str, **kwargs: Any) -> httpx.Response:
        assert self._client is not None
        try:
            response = self._client.get(path, **kwargs)
        except httpx.HTTPError as exc:
            raise GitHubError(f"Network error contacting GitHub: {exc}") from exc

        if response.status_code == 404:
            raise GitHubError(f"GitHub resource not found: {path}")
        if response.status_code == 401:
            raise GitHubError("GitHub returned 401 Unauthorized. Check your GITHUB_TOKEN.")
        if response.status_code == 403:
            remaining = response.headers.get("X-RateLimit-Remaining")
            if remaining == "0":
                reset = int(response.headers.get("X-RateLimit-Reset", "0"))
                raise RateLimitError(reset_seconds=reset)
            raise GitHubError(f"GitHub returned 403: {response.text[:200]}")
        if response.status_code >= 400:
            raise GitHubError(f"GitHub error {response.status_code}: {response.text[:200]}")
        return response

    # --- public API -----------------------------------------------------

    def get_repo(self, owner: str, repo: str) -> dict[str, Any]:
        return self._get(f"/repos/{owner}/{repo}").json()

    def get_languages(self, owner: str, repo: str) -> dict[str, int]:
        try:
            return self._get(f"/repos/{owner}/{repo}/languages").json()
        except GitHubError:
            return {}

    def get_tree(self, owner: str, repo: str, ref: str) -> list[dict[str, Any]]:
        """Recursive tree for a ref. Returns list of {path,type,size,sha}."""

        response = self._get(f"/repos/{owner}/{repo}/git/trees/{ref}", params={"recursive": "1"})
        data = response.json()
        return data.get("tree", [])

    def get_file(self, owner: str, repo: str, path: str, ref: str | None = None) -> str | None:
        """Fetch a single file's UTF-8 content, or None if missing/binary."""

        params = {"ref": ref} if ref else None
        try:
            response = self._get(f"/repos/{owner}/{repo}/contents/{path}", params=params)
        except GitHubError:
            return None
        data = response.json()
        if isinstance(data, list):
            return None
        if data.get("encoding") != "base64" or "content" not in data:
            return None
        try:
            raw = base64.b64decode(data["content"])  # repoc: ignore PY006 -- GitHub contents API delivers base64
        except Exception:
            return None
        if is_probably_binary(path, raw[:1024]):
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("utf-8", errors="replace")

    def fetch_relevant_files(
        self,
        owner: str,
        repo: str,
        ref: str,
        candidates: list[str],
        max_files: int = 500,
        max_file_size: int = 200_000,
    ) -> list[RepoFile]:
        """Fetch a curated set of files by path from a given ref."""

        try:
            tree = self.get_tree(owner, repo, ref)
        except GitHubError:
            tree = []

        by_path: dict[str, dict[str, Any]] = {
            entry["path"]: entry for entry in tree if entry.get("type") == "blob"
        }

        out: list[RepoFile] = []
        seen: set[str] = set()
        for candidate in candidates:
            if len(out) >= max_files:
                break
            if candidate in seen:
                continue
            seen.add(candidate)
            entry = by_path.get(candidate)
            if entry is None:
                continue
            size = int(entry.get("size") or 0)
            if size > max_file_size:
                out.append(RepoFile(path=candidate, size=size, truncated=True))
                continue
            content = self.get_file(owner, repo, candidate, ref=ref)
            if content is None:
                out.append(RepoFile(path=candidate, size=size, is_binary=True))
            else:
                out.append(RepoFile(path=candidate, size=size, content=content))
        return out

    def fetch_paths_from_tree(self, owner: str, repo: str, ref: str) -> list[str]:
        """Return the list of all blob paths in the tree."""

        try:
            tree = self.get_tree(owner, repo, ref)
        except GitHubError:
            return []
        return [entry["path"] for entry in tree if entry.get("type") == "blob"]

    def download_tarball(
        self,
        owner: str,
        repo: str,
        ref: str,
        max_files: int = 500,
        max_file_size: int = 200_000,
    ) -> RemoteScan:
        """Fetch the whole repo in a single request and extract text files.

        Used for ``--deep`` so we don't make one API call per file (which
        exhausts the rate limit on large repos). Everything is processed
        in-memory; nothing is written to disk and non-regular tar members
        (symlinks, devices) are ignored.
        """

        response = self._get(f"/repos/{owner}/{repo}/tarball/{ref}", follow_redirects=True)
        data = response.content
        if len(data) > _MAX_TARBALL_BYTES:
            raise GitHubError("Repository archive is too large to inspect in memory.")

        files: list[RepoFile] = []
        total_seen = 0
        cap_reached = False
        # A malformed/truncated archive, or a 200 that isn't actually a gzip
        # tarball (proxy/captive-portal HTML), raises tarfile/OSError. Surface it
        # as GitHubError so the caller falls back to the curated fetch instead of
        # crashing `inspect --deep` with a traceback.
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                for member in tar:
                    if not member.isfile():
                        continue
                    # Archive members are prefixed with a "owner-repo-sha/" root dir.
                    _, _, path = member.name.partition("/")
                    if not path or in_skip_dir(path):
                        continue
                    total_seen += 1
                    if len(files) >= max_files:
                        cap_reached = True
                        continue
                    if member.size > max_file_size:
                        files.append(RepoFile(path=path, size=member.size, truncated=True))
                        continue
                    extracted = tar.extractfile(member)
                    if extracted is None:
                        continue
                    raw = extracted.read()
                    if is_probably_binary(path, raw[:1024]):
                        files.append(RepoFile(path=path, size=member.size, is_binary=True))
                        continue
                    files.append(
                        RepoFile(path=path, size=member.size, content=raw.decode("utf-8", errors="replace"))
                    )
        except (tarfile.TarError, OSError, EOFError) as exc:
            raise GitHubError(f"Could not read repository archive: {exc}") from exc
        return RemoteScan(files=files, total_seen=total_seen, cap_reached=cap_reached)
