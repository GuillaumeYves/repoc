"""Scan-coverage transparency: partial scans must be visible, not silent."""

from repoc.analyzers.coverage import build_coverage, coverage_findings
from repoc.models import RepoFile


def _files():
    return [
        RepoFile(path="a.py", content="x = 1\n"),
        RepoFile(path="b.py", content="y = 2\n"),
        RepoFile(path="big.min.js", size=999999, truncated=True),
        RepoFile(path="logo.png", size=1234, is_binary=True),
    ]


def test_build_coverage_counts():
    cov = build_coverage(_files(), intended=10, cap_reached=True, deep=False)
    assert cov.analyzed == 2
    assert cov.skipped_large == 1
    assert cov.skipped_binary == 1
    assert cov.not_inspected == 6  # 10 intended - 4 loaded
    assert cov.is_partial


def test_full_scan_is_not_partial():
    files = [RepoFile(path="a.py", content="x = 1\n")]
    cov = build_coverage(files, intended=1, cap_reached=False, deep=True)
    assert not cov.is_partial
    assert cov.deep


def test_partial_scan_emits_finding():
    cov = build_coverage(_files(), intended=10, cap_reached=True, deep=False)
    ids = {f.rule_id for f in coverage_findings(cov)}
    assert "COV001" in ids  # partial
    assert "COV002" in ids  # oversized skipped


def test_coverage_findings_are_non_scoring_category():
    cov = build_coverage(_files(), intended=10, cap_reached=True, deep=False)
    for f in coverage_findings(cov):
        assert f.category == "coverage"


def test_clean_full_scan_has_no_coverage_findings():
    files = [RepoFile(path="a.py", content="x = 1\n")]
    cov = build_coverage(files, intended=1, cap_reached=False, deep=False)
    assert coverage_findings(cov) == []


def test_metadata_only_scan_flags_uninspected_source():
    # Mirrors the real-world PHP case: only the README was read, but the repo
    # has source files that were never inspected.
    files = [RepoFile(path="README.md", content="# hi\n")]
    cov = build_coverage(
        files, intended=1, cap_reached=False, deep=False, source_files_in_repo=12
    )
    assert cov.source_uncovered
    ids = {f.rule_id for f in coverage_findings(cov)}
    assert "COV003" in ids


def test_source_inspected_means_not_uncovered():
    files = [RepoFile(path="app.php", content="<?php $x = 1;\n")]
    cov = build_coverage(
        files, intended=1, cap_reached=False, deep=True, source_files_in_repo=1
    )
    assert not cov.source_uncovered
    assert "COV003" not in {f.rule_id for f in coverage_findings(cov)}
