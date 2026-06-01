"""Shared fixtures for repoc tests."""

from __future__ import annotations

import pytest

from repoc.models import RepoFile


@pytest.fixture
def make_file():
    def _make(path: str, content: str = "", size: int | None = None) -> RepoFile:
        return RepoFile(
            path=path,
            content=content,
            size=size if size is not None else len(content.encode("utf-8")),
        )

    return _make
