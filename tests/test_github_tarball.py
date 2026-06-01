"""--deep tarball fetch: one request, in-memory extraction, limits respected."""

import io
import tarfile

import httpx

from repoc.github_client import GITHUB_API, GitHubClient


def _make_targz(files: dict[str, bytes], prefix: str = "owner-repo-abc123") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(f"{prefix}/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _client_returning(gz: bytes) -> GitHubClient:
    client = GitHubClient(token=None)
    client._client = httpx.Client(
        base_url=GITHUB_API,
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=gz)),
    )
    return client


def test_download_tarball_extracts_and_strips_prefix():
    gz = _make_targz({"app.py": b"import os\n", "src/util.py": b"x = 1\n"})
    scan = _client_returning(gz).download_tarball("o", "r", "main")
    paths = {f.path for f in scan.files}
    assert paths == {"app.py", "src/util.py"}
    body = {f.path: f.content for f in scan.files}
    assert body["app.py"] == "import os\n"
    assert scan.total_seen == 2
    assert not scan.cap_reached


def test_download_tarball_respects_size_and_binary_limits():
    gz = _make_targz(
        {
            "small.py": b"x = 1\n",
            "huge.py": b"x" * 1000,
            "blob.bin": b"\x00\x01\x02\x03",
        }
    )
    scan = _client_returning(gz).download_tarball("o", "r", "main", max_file_size=100)
    by_path = {f.path: f for f in scan.files}
    assert by_path["small.py"].content == "x = 1\n"
    assert by_path["huge.py"].truncated is True
    assert by_path["huge.py"].content is None
    assert by_path["blob.bin"].is_binary is True


def test_download_tarball_caps_file_count():
    gz = _make_targz({f"f{i}.py": b"x = 1\n" for i in range(10)})
    scan = _client_returning(gz).download_tarball("o", "r", "main", max_files=3)
    assert len(scan.files) == 3
    assert scan.total_seen == 10
    assert scan.cap_reached is True


def test_download_tarball_skips_vendored_dirs():
    gz = _make_targz({"app.py": b"x = 1\n", "node_modules/dep/index.js": b"y = 2\n"})
    scan = _client_returning(gz).download_tarball("o", "r", "main")
    assert {f.path for f in scan.files} == {"app.py"}


def test_malformed_archive_raises_githuberror_not_crash():
    # A 200 response that isn't a valid gzip tarball (e.g. a proxy HTML page)
    # must surface as GitHubError so --deep falls back, not crash with a traceback.
    import pytest

    from repoc.github_client import GitHubError

    client = _client_returning(b"<html>not a tarball</html>")
    with pytest.raises(GitHubError):
        client.download_tarball("o", "r", "main")
