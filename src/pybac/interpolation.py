"""Filling `${...}` placeholders in a policy from the evaluation context.

A policy may name a value rather than spell it out:

```json
{ "Resource": ["ern:svc:document:${req:userId}/*"] }
{ "Condition": { "ForAnyValue:StringEquals": { "target:groups": "${req:groups}" } } }
```

A placeholder holds a path through the context, written with colons. A path that
resolves to nothing is left as its own text, so it matches only itself.

Conditions and resources fill differently. A resource becomes one string, so a
placeholder holding a list is joined. A condition compares against a *set* of
values, so a placeholder holding a list expands into one value per element, and
a placeholder standing alone keeps its value's type rather than becoming text.
"""

from __future__ import annotations

import re
from itertools import product
from typing import Any, Final

from pybac._paths import get

__all__ = ["fill_condition_values", "fill_text", "resolve_path"]

_PLACEHOLDER: Final = re.compile(r"\$\{(.+?)\}")
_MISSING: Final = object()


def resolve_path(path: str, context: Any) -> Any:
    """Read ``a:b:c`` from the context, or the path itself if it is not there.

    A condition addresses the context this way, and so does a placeholder. A path
    that leads nowhere becomes its own text, so it compares only against itself
    rather than silently reading as absent.
    """
    value = get(context, path.split(":"), default=_MISSING)
    return path if value is _MISSING else value


def _as_text(value: Any) -> str:
    if isinstance(value, list | tuple):
        return ",".join(_as_text(item) for item in value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value)


def fill_text(text: str, context: Any) -> str:
    """Fill every placeholder in ``text``, yielding one string."""
    return _PLACEHOLDER.sub(lambda m: _as_text(resolve_path(m.group(1), context)), text)


def fill_condition_values(value: Any, context: Any) -> list[Any]:
    """Fill ``value``, yielding every value a condition should compare against.

    A value with no placeholder is returned unchanged, in a list of one. A value
    that is nothing but a placeholder keeps whatever type it resolved to, and
    expands to several values if it resolved to a list. A placeholder embedded in
    surrounding text yields text, once per combination of values.
    """
    if not isinstance(value, str):
        return [value]

    # Splitting on the placeholder gives literals and paths in alternation:
    # "a${x}b" becomes ["a", "x", "b"].
    parts = _PLACEHOLDER.split(value)
    literals, paths = parts[0::2], parts[1::2]
    if not paths:
        return [value]

    if len(paths) == 1 and not any(literals):
        resolved = resolve_path(paths[0], context)
        # Standing alone, a placeholder is the value -- a number stays a number
        # and a list becomes the several values to compare against.
        return list(resolved) if isinstance(resolved, list | tuple) else [resolved]

    # Embedded in text, each placeholder contributes one or more strings, and
    # every combination of them is a value to compare against.
    choices = [
        [_as_text(item) for item in _as_list(resolve_path(path, context))]
        for path in paths
    ]
    filled: list[Any] = []
    for combination in product(*choices):
        pieces = [literals[0]]
        for replacement, literal in zip(combination, literals[1:], strict=True):
            pieces.append(replacement)
            pieces.append(literal)
        filled.append("".join(pieces))
    return filled


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list | tuple) else [value]
