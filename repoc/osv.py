"""Minimal OSV.dev client for batch dependency vulnerability lookups.

Used by the opt-in `--check-deps` flag. OSV is a free, unauthenticated,
public API (https://osv.dev). We keep the surface tiny: a batch query to find
which dependencies have advisories, then bounded detail fetches for severity and
summary. Nothing here runs unless the user passes `--check-deps`.
"""

from __future__ import annotations

from typing import Any

import httpx

from .deps_versions import DepVersion
from .models import Severity

OSV_API = "https://api.osv.dev"

# Bounds so a giant lockfile can never turn one scan into thousands of requests.
MAX_QUERIES = 1000
MAX_DETAIL_FETCHES = 100


class OSVError(RuntimeError):
    """Raised when the OSV lookup cannot complete."""


def query_batch(
    deps: list[DepVersion], *, timeout: float = 20.0
) -> dict[DepVersion, list[str]]:
    """Return {dep: [vuln_id, ...]} for the deps OSV has advisories for."""

    deps = deps[:MAX_QUERIES]
    if not deps:
        return {}
    payload = {
        "queries": [
            {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
            for d in deps
        ]
    }
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.post(f"{OSV_API}/v1/querybatch", json=payload)
            if response.status_code >= 400:
                raise OSVError(f"OSV returned {response.status_code}.")
            data = response.json()
    except httpx.HTTPError as exc:
        raise OSVError(f"Network error contacting OSV: {exc}") from exc
    except ValueError as exc:
        raise OSVError("Unexpected non-JSON response from OSV.") from exc

    results = data.get("results", [])
    out: dict[DepVersion, list[str]] = {}
    # querybatch preserves query order.
    for dep, result in zip(deps, results, strict=False):
        vulns = result.get("vulns") or []
        ids = [v["id"] for v in vulns if v.get("id")]
        if ids:
            out[dep] = ids
    return out


def fetch_details(vuln_ids: list[str], *, timeout: float = 20.0) -> dict[str, dict[str, Any]]:
    """Fetch advisory details (summary, severity) for up to MAX_DETAIL_FETCHES ids."""

    details: dict[str, dict[str, Any]] = {}
    unique = list(dict.fromkeys(vuln_ids))[:MAX_DETAIL_FETCHES]
    if not unique:
        return details
    try:
        with httpx.Client(timeout=timeout) as client:
            for vid in unique:
                resp = client.get(f"{OSV_API}/v1/vulns/{vid}")
                if resp.status_code >= 400:
                    continue
                try:
                    details[vid] = resp.json()
                except ValueError:
                    continue
    except httpx.HTTPError as exc:
        raise OSVError(f"Network error contacting OSV: {exc}") from exc
    return details


# Map advisory severity onto repoc's scale, capped at HIGH: repoc cannot assess
# whether a (possibly transitive) vuln is reachable, so it never escalates a
# whole repo to CRITICAL on a dependency finding alone.
_GHSA_SEVERITY = {
    "CRITICAL": Severity.HIGH,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def severity_of(vuln: dict[str, Any] | None) -> Severity:
    if not vuln:
        return Severity.MEDIUM
    label = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(label, str) and label.upper() in _GHSA_SEVERITY:
        return _GHSA_SEVERITY[label.upper()]
    # CVSS vectors are present but parsing them fully is out of scope; default
    # to MEDIUM so the finding is still surfaced for manual review.
    return Severity.MEDIUM


def summarize(vuln: dict[str, Any] | None, vuln_id: str) -> str:
    if not vuln:
        return vuln_id
    return vuln.get("summary") or (vuln.get("details") or "").split("\n", 1)[0] or vuln_id
