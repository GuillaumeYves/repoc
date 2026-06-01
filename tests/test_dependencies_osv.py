"""Dependency version parsing + OSV.dev vulnerability lookup (mocked)."""

import json

import httpx
import pytest

from repoc import osv
from repoc.analyzers import vulnerabilities
from repoc.deps_versions import DepVersion, extract_versions
from repoc.models import RepoFile, Severity

# --- version parsing ---------------------------------------------------------

def test_requirements_only_exact_pins():
    f = RepoFile(path="requirements.txt", content="Flask==2.0.1\nrequests>=2.0\n# c\n")
    deps = extract_versions([f])
    assert DepVersion("PyPI", "flask", "2.0.1", "requirements.txt") in deps
    assert all(d.name != "requests" for d in deps)  # ranges are skipped


def test_package_lock_v2_packages_map():
    content = json.dumps(
        {"packages": {"": {"name": "root"}, "node_modules/lodash": {"version": "4.17.20"}}}
    )
    deps = extract_versions([RepoFile(path="package-lock.json", content=content)])
    assert DepVersion("npm", "lodash", "4.17.20", "package-lock.json") in deps


def test_package_lock_v1_nested_dependencies():
    content = json.dumps(
        {"dependencies": {"a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}}}
    )
    deps = {(d.name, d.version) for d in extract_versions([RepoFile(path="package-lock.json", content=content)])}
    assert ("a", "1.0.0") in deps and ("b", "2.0.0") in deps


def test_composer_lock_strips_v_prefix_and_dev():
    content = json.dumps(
        {"packages": [{"name": "monolog/monolog", "version": "v2.3.5"}, {"name": "x/y", "version": "dev-main"}]}
    )
    deps = extract_versions([RepoFile(path="composer.lock", content=content)])
    assert DepVersion("Packagist", "monolog/monolog", "2.3.5", "composer.lock") in deps
    assert all(d.name != "x/y" for d in deps)


def test_cargo_lock_packages():
    content = '[[package]]\nname = "serde"\nversion = "1.0.130"\n'
    deps = extract_versions([RepoFile(path="Cargo.lock", content=content)])
    assert DepVersion("crates.io", "serde", "1.0.130", "Cargo.lock") in deps


# --- OSV client (mocked) -----------------------------------------------------

def _patch_osv(monkeypatch, handler):
    real = httpx.Client
    monkeypatch.setattr(
        osv.httpx, "Client",
        lambda *a, **k: real(*a, **{**k, "transport": httpx.MockTransport(handler)}),
    )


def test_query_batch_maps_vulns(monkeypatch):
    def handler(request):
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-aaaa"}]}, {}]})

    _patch_osv(monkeypatch, handler)
    deps = [
        DepVersion("PyPI", "flask", "0.1", "requirements.txt"),
        DepVersion("PyPI", "safe", "9.9", "requirements.txt"),
    ]
    hits = osv.query_batch(deps)
    assert hits == {deps[0]: ["GHSA-aaaa"]}


def test_severity_capped_at_high():
    assert osv.severity_of({"database_specific": {"severity": "CRITICAL"}}) == Severity.HIGH
    assert osv.severity_of({"database_specific": {"severity": "MODERATE"}}) == Severity.MEDIUM
    assert osv.severity_of(None) == Severity.MEDIUM


def test_query_batch_network_error_raises_osverror(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("boom")

    _patch_osv(monkeypatch, handler)
    with pytest.raises(osv.OSVError):
        osv.query_batch([DepVersion("PyPI", "flask", "0.1", "requirements.txt")])


# --- end-to-end analyzer (mocked) -------------------------------------------

def test_analyze_dependencies_builds_finding(monkeypatch):
    def handler(request):
        if request.url.path.endswith("/querybatch"):
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-xxxx"}]}]})
        return httpx.Response(
            200,
            json={"id": "GHSA-xxxx", "summary": "RCE in flask", "database_specific": {"severity": "HIGH"}},
        )

    _patch_osv(monkeypatch, handler)
    files = [RepoFile(path="requirements.txt", content="Flask==0.1\n")]
    findings = vulnerabilities.analyze_dependencies(files)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "GHSA-xxxx"
    assert f.category == "dependency"
    assert f.severity == Severity.HIGH
    assert f.file_path == "requirements.txt"
    assert "RCE in flask" in f.description


def test_analyze_dependencies_network_failure_is_informational(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("offline")

    _patch_osv(monkeypatch, handler)
    findings = vulnerabilities.analyze_dependencies([RepoFile(path="requirements.txt", content="Flask==0.1\n")])
    assert len(findings) == 1
    assert findings[0].rule_id == "DEP000"
    assert findings[0].category == "coverage"  # never scored/gated


def test_no_deps_no_findings():
    assert vulnerabilities.analyze_dependencies([RepoFile(path="README.md", content="hi")]) == []


def test_cli_check_deps_reports_and_gates(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from repoc.cli import app

    def handler(request):
        if request.url.path.endswith("/querybatch"):
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-zzzz"}]}]})
        return httpx.Response(
            200,
            json={"id": "GHSA-zzzz", "summary": "bug", "database_specific": {"severity": "HIGH"}},
        )

    _patch_osv(monkeypatch, handler)
    (tmp_path / "requirements.txt").write_text("Flask==0.1\n", encoding="utf-8")
    runner = CliRunner()

    report = runner.invoke(
        app, ["inspect", str(tmp_path), "--local", "--check-deps", "--format", "json"]
    )
    assert report.exit_code == 0
    assert "GHSA-zzzz" in report.stdout

    gated = runner.invoke(
        app, ["inspect", str(tmp_path), "--local", "--check-deps", "--fail-on", "high"]
    )
    assert gated.exit_code == 1  # the HIGH dependency vuln trips the gate
