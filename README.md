# repoc

[![CI](https://github.com/GuillaumeYves/repoc/actions/workflows/ci.yml/badge.svg)](https://github.com/GuillaumeYves/repoc/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/repoc-cli.svg)](https://pypi.org/project/repoc-cli/)
[![Python versions](https://img.shields.io/pypi/pyversions/repoc-cli.svg)](https://pypi.org/project/repoc-cli/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

**`repoc` = repo doctor.** A lightweight CLI that inspects a GitHub or local
repository before you clone, fork, install, or contribute to it.

It answers questions like:

- Can I trust this repository?
- What language and framework does it use?
- Is it still maintained?
- Are there suspicious scripts, install hooks, or possible secrets?
- Is it safe to run install/build commands?

> **Disclaimer:** `repoc` does **not** prove that a repository is safe. It
> highlights suspicious patterns, metadata, and maintenance signals that
> deserve manual review.

---

## Installation

```bash
pip install repoc-cli
```

The PyPI package is `repoc-cli`; the command it installs is `repoc`.

Or from source:

```bash
git clone https://github.com/GuillaumeYves/repoc
cd repoc
pip install -e ".[dev]"
```

Requires **Python 3.11+**.

---

## Usage

```bash
# Inspect a public GitHub repository
repoc inspect owner/repo

# Or from a full URL
repoc inspect https://github.com/owner/repo

# Inspect the current working directory
repoc inspect . --local

# JSON output (machine-readable)
repoc inspect owner/repo --format json

# Markdown export
repoc inspect owner/repo --format markdown --output report.md

# Deeper scan — also inspects source files, not just manifests
repoc inspect owner/repo --deep

# Check pinned dependency versions against the OSV.dev vulnerability database
repoc inspect owner/repo --check-deps

# SARIF for GitHub code scanning
repoc inspect owner/repo --format sarif --output repoc.sarif

# Use as a CI gate — exit non-zero if a HIGH (or worse) security finding appears
repoc inspect owner/repo --fail-on high
```

### Common options

| Option                          | Description                                                              |
| ------------------------------- | ------------------------------------------------------------------------ |
| `--local`                       | Force the target to be interpreted as a local path.                      |
| `--format terminal\|markdown\|json\|sarif` | Output format. Default `terminal`. `sarif` for GitHub code scanning. |
| `--output <path>`               | Write the report to a file.                                              |
| `--deep`                        | Inspect a wider set of source files (downloads a single repo tarball).   |
| `--check-deps`                  | Look up pinned dependency versions against OSV.dev (network).            |
| `--no-network`                  | Skip GitHub API calls (local mode only).                                 |
| `--max-files N`                 | Cap on how many files to load. Default `500`.                            |
| `--max-file-size N`             | Skip files bigger than N bytes. Default `200000`.                        |
| `--fail-on low\|medium\|high\|critical` | Exit non-zero (code 1) if a security finding meets/exceeds this severity. |
| `--github-token <token>`        | GitHub token (or set `GITHUB_TOKEN`). Used in memory only.               |
| `--token-stdin`                 | Read a token from stdin so it never lands in shell history / `argv`.     |
| `--login`                       | One-time GitHub device-code login for this run. Nothing is stored.       |

Exit codes: `0` ok · `1` `--fail-on` gate tripped · `2` bad target/usage ·
`3` GitHub/network error or rate limit · `4` authentication error.

### GitHub authentication (private repos)

repoc never writes a credential to disk, a keyring, or any config file — a token
lives in memory for a single run and is discarded on exit. You can supply one in
whichever way fits your trust model:

```bash
# 1. Environment variable / flag (raises the rate limit; reads private repos)
export GITHUB_TOKEN=github_pat_xxx
repoc inspect owner/private-repo

# 2. Pipe a token via stdin — keeps it out of shell history and the process list
echo "$GITHUB_TOKEN" | repoc inspect owner/private-repo --token-stdin

# 3. One-time browser device-code login (nothing is persisted)
repoc inspect owner/private-repo --login
```

For `--login`, set `REPOC_GITHUB_CLIENT_ID` to a public GitHub OAuth App client
id (enable *Device Flow* on the app). The client id is not a secret. If you'd
rather not register an app, use a fine-grained, read-only PAT with `--token-stdin`.

### Use in CI / pre-commit

```yaml
# .github/workflows/audit.yml
- run: pip install repoc
- run: repoc inspect ${{ github.repository }} --fail-on high
```

The gate only counts security findings (committed secrets, install hooks, risky
code patterns). Maintenance, documentation, and scan-coverage notes never fail it.

---

## Sample output

```
# Repoc Report: https://github.com/owner/repo

## Verdict

- Risk level: **Medium**
- Trust score: **72/100**
- Project type: Backend API
- Primary language: Python
- Detected stack: FastAPI, SQLAlchemy, Pydantic

## Summary

owner/repo appears to be a Backend API written in Python using FastAPI,
SQLAlchemy, Pydantic. The scan produced low-severity findings only.

...
```

---

## What it detects

repoc has two depth layers. **Code-logic analysis** (the security rule packs
that read your source) currently covers **7 ecosystems**. **Identification**
(language + framework + secret scanning) is broader. Secret scanning runs on
*every* text file regardless of language.

### Statically analyzed (security rule packs)

| Ecosystem | What the rules look for |
| --- | --- |
| **Python** | `eval`/`exec`, `os.system`, `subprocess(shell=True)`, `pickle`/`marshal.loads`, `yaml.load` without `SafeLoader`, `verify=False`, `base64`, raw sockets |
| **JavaScript / TypeScript** | `eval`, `new Function`, `child_process.exec/spawn`, `fs.rm`/`unlink`, DOM-XSS sinks (`innerHTML`, `document.write`), `setTimeout("string")`, base64, **npm install hooks** (`preinstall`/`install`/`postinstall`/`prepare`) |
| **PHP** | `eval`, command exec (`system`/`exec`/`shell_exec`/`passthru`/`popen`/`proc_open`), `unserialize`, `create_function`, `assert("…")`, `extract($_GET)`, dynamic `include`/`require` and request-controlled LFI/RFI, base64 |
| **Ruby** | `eval`, `system`/`exec`/backticks, `Open3.capture`, `Marshal.load`, `YAML.load`, `Base64.decode64`, `Net::HTTP` |
| **Shell** | `curl\|bash`, `sudo`, `rm -rf $…`, `base64 -d`, `eval`, insecure TLS (`curl -k`), reverse-shell shapes (`nc -e`, `/dev/tcp/…`) |
| **Dockerfile / Compose** | `USER root`, `ADD http://…`, `curl\|bash`, `--privileged`, `:latest` base image |
| **GitHub Actions** | `pull_request_target`, secret expansion, `curl\|bash`, `sudo`, unpinned actions, script injection via untrusted `${{ github.event.* }}` |

Rules run against comment/string-masked source (see *Keeping signal high* below),
so they're tuned to flag real calls, not mentions in comments or strings.

### Identified but not yet code-analyzed

repoc detects **Go, Rust, Java/Kotlin, C#, C/C++** (and labels ~25 languages in
total) and parses their dependency manifests for frameworks (Gin/Fiber/Cobra,
Actix/Axum/Tokio, Spring/Hibernate, Laravel/Symfony, …). These files are still
**secret-scanned**, but dedicated code-logic rule packs for them are planned for
future releases — today a risky call in a `.go`/`.java`/`.rs` file is not flagged.

### Secret scanning (all languages)

Regex-based and conservative: GitHub PATs, AWS access keys, PEM private keys,
JWTs, DB URLs with credentials, Slack/Discord webhooks, Stripe secret keys,
committed `.env` files. Matched values are redacted.

### Dependency vulnerabilities (`--check-deps`)

Opt-in. repoc parses *pinned* versions from lockfiles (`requirements.txt`,
`poetry.lock`, `Pipfile.lock`, `package-lock.json`, `Gemfile.lock`, `Cargo.lock`,
`composer.lock`, `go.mod`) and batch-queries [OSV.dev](https://osv.dev) for known
advisories. Findings are capped at `HIGH` severity — repoc can't assess whether a
(possibly transitive) vuln is reachable, so it never escalates a whole repo to
`Critical` on a dependency alone. Needs network; skipped under `--no-network`.

### Keeping signal high

- **Comment/string aware.** Code-pattern rules run against a copy of each file
  with comments and string literals blanked out, so an `eval(` mentioned in a
  docstring or a `# curl … | bash` example line is not reported. (Secret rules
  still run on the raw text — secrets live inside strings.)
- **Path context.** Findings in `tests/`, `examples/`, `fixtures/`, `docs/`,
  `vendor/`, and `*.example` / `*.sample` files are down-ranked one severity
  tier — a token in a test fixture is rarely a live leak.
- **Inline suppression.** Add `# repoc: ignore`, `# repoc: ignore PY001`, or
  `# repoc: ignore-file` (any comment syntax) to silence a known-safe match.

### Scan coverage

Every report states how many files were actually inspected. If the `--max-files`
cap is hit, or oversized/binary files are skipped, repoc emits explicit
`COV` findings and a **Partial scan** banner — a capped scan can never look like
a clean bill of health.

> **Default remote scans are metadata-only.** `repoc inspect owner/repo` reads
> manifests, lockfiles, install hooks, workflows, Dockerfiles, and docs — it
> does **not** download the source tree. When a repo has source files that
> weren't inspected, repoc says so (`COV003`) and tells you to add `--deep`,
> which downloads the repo once and scans the code. Local scans (`--local`)
> always read the full source tree.

### Maintenance & docs

Repository age, archive status, license presence, open-issue backlog, plus
the usual suspects in the repo root: `README`, `LICENSE`, `CONTRIBUTING`,
`SECURITY`, `CODE_OF_CONDUCT`, `CHANGELOG`, `docs/`, `examples/`.

---

## Scoring

The trust score is a weighted average:

| Area          | Weight |
| ------------- | -----: |
| Security      |    35% |
| Maintenance   |    25% |
| Documentation |    20% |
| Popularity    |    10% |
| Structure     |    10% |

Findings are weighted by category. Committed secrets and npm install hooks are
treated as "stop and look" signals and weigh heavily; risky code patterns
(`eval`, `subprocess`, `curl | bash`) are "worth reviewing" signals that barely
move the score on their own and taper with repetition — twenty `subprocess`
calls in a large codebase do not zero the score the way twenty private keys
would.

Risk levels are `Low`, `Medium`, `High`, `Critical`, `Unknown`. Any `CRITICAL`
finding, or a HIGH/CRITICAL committed secret or install hook, escalates the risk
on its own; a lone HIGH code pattern (e.g. one `eval`) does not. (Popularity is
excluded for local scans, where stars/forks are unknown.)

The full breakdown is included in every report so the score is auditable.

---

## Development

```bash
git clone https://github.com/GuillaumeYves/repoc
cd repoc
pip install -e ".[dev]"

ruff check .
pytest
```

The project layout:

```
repoc/
  cli.py            Typer entry point
  auth.py           Ephemeral GitHub auth (device flow, stdin token)
  github_client.py  Minimal GitHub REST client + tarball fetch
  models.py         Pydantic models
  scoring.py        Score aggregation + risk classification
  analyzers/        One module per analysis dimension (incl. coverage)
  rules/            Regex rule packs + comment/string masking
  renderers/        terminal / markdown / json
tests/
.github/workflows/  ci.yml, release.yml
```

### Releasing

Bump `__version__` in `repoc/__init__.py`, commit, then:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The release workflow builds wheels, creates a GitHub release, and publishes
to PyPI via Trusted Publishing.

---

## Roadmap

- **Code-logic rule packs for Go, Rust, Java, and C#** — the languages repoc
  identifies today but doesn't yet analyze for risky calls.
- Heuristics for typosquat detection on package names.
- Resolve `--check-deps` for range-only manifests (e.g. a bare `package.json`).
- Pluggable rule packs (drop-in `.toml`/`.py` rules).
- Caching layer for repeated GitHub queries.

---

## License

MIT — see [LICENSE](./LICENSE).
