"""Blank out comments and string literals before running code-pattern rules.

The regex rule packs (``eval(``, ``subprocess(... shell=True``, ``curl | bash``)
match raw text, which means they also fire inside comments, docstrings, and
string literals. That is the single biggest source of false positives. This
module produces a *masked* copy of a file where the irrelevant regions are
replaced by spaces, **preserving length and newline positions** so byte offsets
and line numbers map back to the original unchanged.

Important nuance: in shell, Dockerfiles, Makefiles, and GitHub Actions YAML the
"strings" frequently *are* the dangerous command (``run: "curl ... | bash"``).
For those file types we only strip whole-line comments and never touch strings,
so real findings inside quoted commands still surface.

Secret scanning does **not** use this — secrets legitimately live inside string
literals, so those rules run against the raw text (see ``analyzers/security.py``).
"""

from __future__ import annotations

import io
import tokenize
from dataclasses import dataclass
from pathlib import Path

# C-family languages: ``//`` line comments, ``/* */`` blocks, quoted strings
# (including JS/TS template backticks) carry data rather than commands.
_C_FAMILY = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java",
    ".cs", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh",
    ".m", ".mm", ".swift", ".kt", ".kts", ".scala",
}

# PHP: ``//`` and ``#`` line comments, ``/* */`` blocks. Backticks are the
# shell-execution operator (not a string), so they are NOT treated as quotes.
_PHP = {".php", ".phtml", ".php5", ".phps"}


@dataclass(frozen=True)
class _Style:
    mode: str  # "full" (mask comments + strings) or "lines_only"
    line: tuple[str, ...]
    block: tuple[str, str] | None
    quotes: tuple[str, ...]


def _style_for(path: str) -> _Style:
    p = Path(path)
    suffix = p.suffix.lower()
    name = p.name
    if suffix in _C_FAMILY:
        # Backticks are template strings in JS/TS; treating them as strings is
        # correct there. Other C-family languages don't use raw backticks.
        return _Style("full", ("//",), ("/*", "*/"), ('"', "'", "`"))
    if suffix in _PHP:
        return _Style("full", ("//", "#"), ("/*", "*/"), ('"', "'"))
    if suffix == ".rb" or name in {"Rakefile", "Gemfile"}:
        # NB: backticks in Ruby are command execution (detected by RB002), so we
        # deliberately do NOT treat them as maskable strings.
        return _Style("full", ("#",), None, ('"', "'"))
    if suffix == ".py":
        return _Style("full", ("#",), None, ('"', "'"))
    # shell / Dockerfile / Makefile / YAML / everything else: the payload often
    # lives inside quotes, so only strip whole-line comments.
    return _Style("lines_only", ("#",), None, ())


def mask_code(path: str, content: str) -> str:
    """Return a copy of ``content`` with comments/strings blanked to spaces."""

    if not content:
        return content
    if Path(path).suffix.lower() == ".py":
        masked = _mask_python(content)
        if masked is not None:
            return masked
    style = _style_for(path)
    if style.mode == "lines_only":
        return _mask_full_line_comments(content, style.line)
    return _mask_full(content, style)


_PY_MASK_TYPES = {tokenize.STRING, tokenize.COMMENT}
# f-string literal chunks (3.12+) — mask the literal text but leave the embedded
# expressions intact so an `eval(...)` inside `f"{eval(x)}"` is still caught.
_FSTRING_MIDDLE = getattr(tokenize, "FSTRING_MIDDLE", None)
if _FSTRING_MIDDLE is not None:  # pragma: no branch
    _PY_MASK_TYPES.add(_FSTRING_MIDDLE)


def _mask_python(content: str) -> str | None:
    """Use the tokenizer for accurate Python masking; None on a parse failure."""

    try:
        out = list(content)
        line_starts = _line_offsets(content)
        for tok in tokenize.generate_tokens(io.StringIO(content).readline):
            if tok.type not in _PY_MASK_TYPES:
                continue
            (srow, scol), (erow, ecol) = tok.start, tok.end
            start = line_starts[srow - 1] + scol
            end = line_starts[erow - 1] + ecol
            for i in range(start, min(end, len(out))):
                if out[i] not in "\r\n":
                    out[i] = " "
        return "".join(out)
    except (tokenize.TokenError, SyntaxError, ValueError, IndexError):
        return None


def _mask_full_line_comments(content: str, tokens: tuple[str, ...]) -> str:
    out: list[str] = []
    for line in content.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped and any(stripped.startswith(t) for t in tokens):
            body = line.rstrip("\r\n")
            newline = line[len(body):]
            out.append(" " * len(body) + newline)
        else:
            out.append(line)
    return "".join(out)


def _mask_full(content: str, style: _Style) -> str:
    out = list(content)
    n = len(content)
    quotes = set(style.quotes)
    block_open, block_close = style.block or ("", "")

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] not in "\r\n":
                out[k] = " "

    i = 0
    while i < n:
        # line comment
        comment = next((t for t in style.line if content.startswith(t, i)), None)
        if comment is not None:
            end = content.find("\n", i)
            end = n if end == -1 else end
            blank(i, end)
            i = end
            continue
        # block comment
        if block_open and content.startswith(block_open, i):
            end = content.find(block_close, i + len(block_open))
            end = n if end == -1 else end + len(block_close)
            blank(i, end)
            i = end
            continue
        # string literal — blank the interior but keep the opening/closing
        # quotes so rules can still tell "a string literal appears here"
        # (e.g. setTimeout("..."), assert("...")) while the contents that would
        # cause false positives (a literal `eval(`) are gone.
        if content[i] in quotes:
            quote = content[i]
            # Only backticks (JS/TS template literals) legitimately span raw
            # newlines. For ' and " an unescaped newline means this was never a
            # string — most often a lone apostrophe in a regex literal like
            # `/it's/`. Bailing instead of consuming across lines prevents the
            # masker from swallowing — and silently hiding — real code below it.
            # (Trade-off: a rare multi-line "..."/'...' string in PHP/Ruby may be
            # scanned as code, i.e. a false positive — far safer than a missed
            # finding for a security scanner.)
            multiline = quote == "`"
            j = i + 1
            closed = False
            while j < n:
                ch = content[j]
                if ch == "\\":
                    j += 2
                    continue
                if ch == quote:
                    j += 1
                    closed = True
                    break
                if ch == "\n" and not multiline:
                    break
                j += 1
            if not closed and not multiline:
                i += 1  # treat the quote char as a literal; do not blank
                continue
            blank(i + 1, max(i + 1, j - 1))
            i = j
            continue
        i += 1
    return "".join(out)


def _line_offsets(content: str) -> list[int]:
    offsets: list[int] = []
    pos = 0
    for line in content.splitlines(keepends=True):
        offsets.append(pos)
        pos += len(line)
    if not offsets:
        offsets.append(0)
    return offsets
