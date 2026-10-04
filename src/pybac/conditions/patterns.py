"""Wildcard matching, as used by actions, resources and `StringLike`.

A pattern is ordinary text with two wildcards: ``*`` stands for any run of
characters and ``?`` for exactly one. Everything else is literal, so
``docs:folder:*`` matches ``docs:folder:read`` and nothing outside that service,
while ``a.b`` matches a dot and nothing else.
"""

from __future__ import annotations

import re
from functools import lru_cache

__all__ = ["matches"]


@lru_cache(maxsize=2048)
def _compile(pattern: str) -> re.Pattern[str]:
    parts = []
    for character in pattern:
        if character == "*":
            parts.append(".*")
        elif character == "?":
            parts.append(".")
        else:
            parts.append(re.escape(character))
    return re.compile("^" + "".join(parts) + "$")


def matches(value: str, pattern: str) -> bool:
    """Whether ``value`` matches ``pattern`` in full."""
    return _compile(pattern).match(value) is not None
