# Changelog

All notable changes to `repoc` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-01

First stable release.

### Added

- **Ephemeral private-repo auth.** `--login` runs GitHub's OAuth device-code
  flow (one-time browser code) and `--token-stdin` reads a token from stdin.
  No credential is ever written to disk, a keyring, or config — tokens live in
  memory for a single run. Set `REPOC_GITHUB_CLIENT_ID` to use `--login`.
- **`--fail-on low|medium|high|critical`** CI gate: exits with code `1` when a
  security finding meets or exceeds the threshold. Maintenance, documentation,
  and coverage findings never trip the gate.
- **Scan-coverage transparency.** Every report states how many files were
  inspected and surfaces `COV001` (partial scan / `--max-files` cap),
  `COV002` (oversized files skipped), and `COV003` (source code present but not
  inspected — a metadata-only scan) findings so a shallow or capped scan can't
  look clean. JSON output now includes `coverage` and `repoc_version`.
- **PHP security rules**: `eval`, command execution (`system`/`exec`/
  `shell_exec`/`passthru`/`popen`/`proc_open`), `unserialize`, `base64_decode`,
  dynamic `include`/`require` (LOW — common in autoloaders/templating), and a
  separate HIGH rule for `include`/`require` of a request superglobal (real
  LFI/RFI). `--deep` now also fetches `.php`, `.go`, `.rs`, `.java`, `.cs`, and
  C/C++ sources (previously only Python/JS/TS/Ruby/shell), so secret and code
  scanning reach those files.
- The Security score is annotated "code not scanned" in the breakdown when the
  scan was metadata-only, so a perfect score can't be read as a clean codebase.
- **Deeper rulesets for the analyzed languages** (Python, JS/TS, PHP, Ruby,
  Shell, Dockerfile, GitHub Actions): Python `yaml.load`-without-`SafeLoader`
  and `verify=False`; JS DOM-XSS sinks (`innerHTML`, `document.write`) and
  `setTimeout("string")`; Ruby `Marshal.load`/`YAML.load`; PHP `extract($_GET)`,
  `create_function`, `assert("…")`; Shell insecure TLS (`curl -k`); Dockerfile
  `:latest` base image; GitHub Actions script injection via untrusted
  `${{ github.event.* }}`.
- Fixed false positives where Python/JS `eval`/`exec` rules matched method calls
  such as `df.eval(...)` or `$scope.$eval(...)`. Comment/string masking now
  preserves quote delimiters so "string argument" rules work without
  reintroducing in-string false positives.
- Fixed a masking false **negative**: a lone apostrophe (e.g. in a JS regex
  literal `/it's/`) no longer makes the masker consume across newlines and hide
  real findings below it.
- `inspect --deep` now degrades to the curated fetch instead of crashing when
  the repository archive is malformed or not a gzip tarball.
- Tightened several rules to remove false positives: JS `innerHTML` no longer
  fires on `===` comparisons, `setTimeout`/`setInterval` no longer fire on
  method calls, Python `yaml.load` tolerates a multi-line `SafeLoader`, and the
  GitHub Actions script-injection rule is scoped to genuinely untrusted
  `github.event.*` fields (no longer flags `repository.name`).
- **Dependency vulnerability check (`--check-deps`)**: parses pinned versions
  from `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `package-lock.json`,
  `Gemfile.lock`, `Cargo.lock`, `composer.lock`, and `go.mod`, and batch-queries
  OSV.dev. Findings are capped at `HIGH` (never escalate the repo to Critical on
  a transitive vuln) and a failed lookup degrades to an informational note.
- **SARIF output (`--format sarif`)**: emit SARIF 2.1.0 so findings flow into
  GitHub code scanning / the Security tab and other CI dashboards.
- Heuristic LICENSE detection for local repositories (`--local`).
- Dependabot configuration; README badges; `SECURITY.md`, `CONTRIBUTING.md`.

### Changed

- **Comment/string-aware scanning.** Code-pattern rules now run against a
  comment- and string-masked copy of each file, eliminating the bulk of false
  positives (e.g. `eval(` inside a docstring or a commented example line).
  Secret rules still scan raw text. Implemented for Python (via the tokenizer),
  JS/TS/Go/Rust/Java/C#/PHP/C-family, Ruby, and shell/Docker/YAML.
- **Path-context down-ranking.** Findings in `tests/`, `examples/`,
  `fixtures/`, `docs/`, `vendor/`, and `*.example`/`*.sample` files drop one
  severity tier.
- **Category-aware scoring.** Findings carry a `category` (`secret`,
  `install_hook`, `code_pattern`, `maintenance`, `documentation`, `coverage`).
  Secrets/install hooks weigh heavily; code patterns weigh lightly and taper
  with repetition. A lone HIGH code pattern (e.g. one `eval`) no longer forces
  HIGH risk; only CRITICAL findings or HIGH/CRITICAL secrets/install hooks do.
- **`--deep` now downloads a single repo tarball** instead of one API request
  per file, so it no longer exhausts the GitHub rate limit on large repos
  (falls back to per-file fetch for private repos / network failures).
- Popularity is excluded from the trust score for local scans (shown as `n/a`);
  `ScoreBreakdown.popularity` is `int | None` — JSON consumers may see `null`.
- Bumped `Development Status` classifier to `5 - Production/Stable`.

### Fixed

- **Symlink traversal in `--local` scans.** The local walker no longer follows
  symlinks and confines reads to the target directory, so a crafted repo can't
  make repoc read files outside it (e.g. via a symlink to your home dir).
- **UTF-8 output on Windows.** Reports no longer crash with a `cp1252`
  `UnicodeEncodeError` when piped or redirected; stdout/stderr are forced to
  UTF-8 and reports are written as UTF-8 bytes.
- Local scans no longer fire `MN002` ("No license detected") when a LICENSE
  file sits next to `pyproject.toml`.
- Verdict no longer reads "a Unknown ..." when the project type can't be
  classified (now "a project of unknown type ...").
