"""Tests for the maintenance analyzer, including local LICENSE detection."""

from __future__ import annotations

from repoc.analyzers.maintenance import (
    analyze_maintenance,
    detect_local_license,
)
from repoc.models import RepositoryMetadata


def test_detect_local_license_mit(make_file):
    files = [
        make_file(
            "LICENSE",
            "MIT License\n\nCopyright (c) 2026 Someone\n\n"
            "Permission is hereby granted, free of charge, to any person obtaining a copy",
        )
    ]
    assert detect_local_license(files) == "MIT"


def test_detect_local_license_apache(make_file):
    files = [
        make_file(
            "LICENSE",
            "                              Apache License\n"
            "                        Version 2.0, January 2004\n"
            "                     http://www.apache.org/licenses/\n",
        )
    ]
    assert detect_local_license(files) == "Apache-2.0"


def test_detect_local_license_falls_back_to_detected(make_file):
    files = [make_file("LICENSE", "Some custom license text that matches nothing.")]
    assert detect_local_license(files) == "Detected"


def test_detect_local_license_none_when_absent(make_file):
    files = [make_file("README.md", "# repo")]
    assert detect_local_license(files) is None


def test_detect_local_license_ignores_nested_license_files(make_file):
    # A LICENSE buried under vendor/ should not satisfy the project-level check.
    files = [make_file("vendor/dep/LICENSE", "MIT License")]
    assert detect_local_license(files) is None


def test_mn002_not_fired_when_license_known():
    meta = RepositoryMetadata(name="repo", license="MIT")
    findings = analyze_maintenance(meta)
    assert all(f.rule_id != "MN002" for f in findings)


def test_mn002_fired_when_license_missing():
    meta = RepositoryMetadata(name="repo")
    findings = analyze_maintenance(meta)
    assert any(f.rule_id == "MN002" for f in findings)
