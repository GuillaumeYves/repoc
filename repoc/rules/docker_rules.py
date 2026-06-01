"""Dockerfile suspicious patterns."""

# repoc: ignore-file -- regex literals here intentionally match the rules themselves.

from __future__ import annotations

from ..models import Severity
from .common import Rule, compile_pattern

DOCKER_GLOBS = ("Dockerfile", "Dockerfile.*", "*.Dockerfile", "docker-compose.yml", "docker-compose.*.yml")

RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="DK001",
        title="`USER root` (or no USER) in Dockerfile",
        severity=Severity.MEDIUM,
        pattern=compile_pattern(r"(?im)^\s*USER\s+root\b"),
        description="Running as root inside containers means any container escape inherits root on the host namespace.",
        recommendation="Add a non-root `USER` instruction.",
        file_globs=DOCKER_GLOBS,
    ),
    Rule(
        rule_id="DK002",
        title="`ADD` with remote URL",
        severity=Severity.HIGH,
        pattern=compile_pattern(r"(?im)^\s*ADD\s+https?://"),
        description="`ADD http(s)://...` pulls a remote artifact at build time without checksum validation.",
        recommendation="Switch to `RUN curl ... && echo '<sha256> file' | sha256sum -c` or COPY a local file.",
        file_globs=DOCKER_GLOBS,
    ),
    Rule(
        rule_id="DK003",
        title="`curl | bash` inside RUN",
        severity=Severity.HIGH,
        pattern=compile_pattern(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:bash|sh)\b"),
        description="Piping a remote installer into a shell inside the image makes the build dependent on whatever the remote returns.",
        recommendation="Pin a release artifact and verify its checksum.",
        file_globs=DOCKER_GLOBS,
    ),
    Rule(
        rule_id="DK004",
        title="`--privileged` flag in compose file",
        severity=Severity.HIGH,
        pattern=compile_pattern(r"(?m)^\s*privileged\s*:\s*true\b"),
        description="`privileged: true` disables most container isolation.",
        recommendation="Drop privileged mode and grant only the specific capabilities you need.",
        file_globs=("docker-compose.yml", "docker-compose.*.yml"),
    ),
    Rule(
        rule_id="DK005",
        title="Base image pinned to `:latest`",
        severity=Severity.LOW,
        pattern=compile_pattern(r"(?im)^\s*FROM\s+\S+:latest\b"),
        description="`FROM ...:latest` makes builds non-reproducible and silently pulls in whatever the tag points to today.",
        recommendation="Pin the base image to a specific version, ideally by digest (`@sha256:...`).",
        file_globs=DOCKER_GLOBS,
    ),
)
