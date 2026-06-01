# Contributing to repoc

Thanks for your interest in improving `repoc`.
This document covers the basics:
setting up a dev environment, running the test and lint suites, adding new rules, and proposing changes.

## Development setup

Requires **Python 3.11+**.

```bash
git clone https://github.com/GuillaumeYves/repoc
cd repoc
python -m venv .venv
. .venv/bin/activate            # PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

Run the checks the CI runs:

```bash
ruff check .
pytest
```

`repoc` is happy to dogfood itself, when in doubt:

```bash
python -m repoc.cli inspect . --local
```

## Project layout

```
repoc/
  cli.py            Typer entry point and orchestrator
  github_client.py  Minimal authenticated GitHub REST client
  models.py         Pydantic models shared across the project
  scoring.py        Score aggregation + risk classification
  analyzers/        One module per analysis dimension
  rules/            Regex rule packs grouped by ecosystem
  renderers/        terminal / markdown / json output
tests/              pytest suite (no network access required)
```

The intentional split is: **analyzers** orchestrate, **rules** are pure
regex/data, **renderers** never compute. Keep them that way.

## Adding a security rule

1. Add the regex(es) to the relevant module under `repoc/rules/`. Each rule
   is a `(rule_id, title, severity, description, recommendation, pattern)`
   tuple — see `python_rules.py` for the shape.
2. Pick a **stable rule ID**. The prefix tells the scoring layer how to
   classify the finding:
   - `SH` shell, `PY` Python, `JS` JavaScript/TypeScript, `RB` Ruby,
   - `DK` Dockerfile, `GH` GitHub Actions,
   - `SEC` cross-cutting secret scanner,
   - `MN` maintenance, `DOC` documentation.
3. Add at least one **positive** and one **negative** test case in the
   matching `tests/test_*.py`.
4. Use careful wording. `repoc` should describe a *pattern that deserves
   review*, not a *proven exploit*.

## Adding a framework or language

1. Update `repoc/analyzers/language.py` for the extension and any manifest
   hints.
2. Update `repoc/analyzers/framework.py` for new dependency-based detection.
3. Update `repoc/analyzers/project_type.py` if the new tech changes how a
   project should be classified.
4. Add tests in `tests/test_language_detection.py` and / or
   `tests/test_framework_detection.py`.

## Pull-request checklist

- [ ] `ruff check .` is clean.
- [ ] `pytest` passes locally.
- [ ] New behavior has tests.
- [ ] Public CLI changes are documented in `README.md`.
- [ ] User-visible changes have a `CHANGELOG.md` entry under
  `## [Unreleased]` (add the section if missing).
- [ ] You did **not** widen the wording so that `repoc` claims to prove a
  repo is safe. Findings indicate patterns that deserve manual review.

## Releasing

Releases are tag-driven and run on GitHub Actions
(`.github/workflows/release.yml`).

1. Update `__version__` in `repoc/__init__.py`.
2. Move the `## [Unreleased]` block in `CHANGELOG.md` under the new
   version + date.
3. Commit, then tag:

   ```bash
   git tag v1.2.3
   git push origin v1.2.3
   ```
4. The release workflow builds the wheel + sdist, creates a GitHub Release,
   and publishes to PyPI via Trusted Publishing.

## Code of conduct

Be kind, be precise, assume good faith. Reviews focus on the code, not the
contributor. If something feels off, flag it directly — disagreement is
welcome, hostility is not.

## License

By contributing, you agree that your contributions will be licensed under
the [MIT License](./LICENSE) that covers the project.
