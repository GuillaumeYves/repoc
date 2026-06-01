# Security Policy

## Supported Versions

`repoc` follows [semantic versioning](https://semver.org/). Only the latest
minor release of the latest major version receives security fixes.

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not open a public issue for security problems.**

If you believe you have found a security vulnerability in `repoc`, report it
privately using GitHub's
[private vulnerability reporting](https://github.com/GuillaumeYves/repoc/security/advisories/new)
form. If that is unavailable, email **guillaume.yves@icloud.com** with:

- A description of the issue and its impact.
- Steps to reproduce, or a minimal proof of concept.
- The version of `repoc` (`repoc --version`) and your Python version.
- Any relevant logs or stack traces (please redact secrets).

You should receive an acknowledgement within **5 business days**. We aim to
ship a fix or publish mitigation guidance within **30 days** of a confirmed
report, depending on severity and complexity.

## Scope

In scope:

- Code execution, path traversal, or other vulnerabilities in `repoc` itself.
- False-negative security rules where `repoc` clearly misses a documented
  suspicious pattern.
- Issues in the released CI / release workflows under `.github/workflows/`.

Out of scope:

- Findings that `repoc` produces about *third-party repositories* — those are
  bugs or feature requests for the rule set, not vulnerabilities in `repoc`.
- Denial-of-service caused by hand-crafted huge files (use `--max-file-size`
  and `--max-files` to bound input).
- Issues that require an attacker to already control your machine, your
  Python environment, or your `GITHUB_TOKEN`.

## Disclaimer

`repoc` does not prove that a repository is safe. It highlights suspicious
patterns, metadata, and maintenance signals that deserve manual review.
