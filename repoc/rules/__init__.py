"""Rule packs: regex-driven detectors grouped by language/ecosystem.

Each pack exposes a ``RULES`` list of :class:`repoc.rules.common.Rule`. Keep
rule_ids stable across releases so users can ignore specific rules.
"""

from . import (
    common,
    docker_rules,
    github_actions_rules,
    javascript_rules,
    python_rules,
    ruby_rules,
    shell_rules,
)

__all__ = [
    "common",
    "docker_rules",
    "github_actions_rules",
    "javascript_rules",
    "python_rules",
    "ruby_rules",
    "shell_rules",
]
