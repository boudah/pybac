"""Property-path access: read, write and remove a value at ``a.b[0].c``.

Policies address data through paths. A condition key arrives as
``target:user:id``, a field-masking rule as ``a.b[0].c``, so resolving a path
against nested data is a core operation rather than a convenience.

Paths accept dotted segments and bracketed ones, quoted or bare
(``a.b[0].c``, ``a["b.c"][1]``), and a path may also be given pre-split as a
sequence -- which is how a ``target:user:id`` condition key is passed, after
splitting on the colon. Indices may be negative and count from the end.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, MutableMapping, MutableSequence, Sequence
from typing import Any

__all__ = ["get", "set_", "to_path", "unset"]

_PATH_TOKEN = re.compile(
    r"""
    \[\s*'((?:\\.|[^'])*)'\s*\]   # ['key']
  | \[\s*"((?:\\.|[^"])*)"\s*\]   # ["key"]
  | \[\s*([^\[\]]*?)\s*\]         # [0] / [key]
  | ([^.\[\]]+)                   # bare segment
    """,
    re.VERBOSE,
)

Path = str | int | Sequence[str | int]


def to_path(path: Path) -> list[str | int]:
    """Split ``path`` into its segments.

    A sequence is taken verbatim, so a segment may itself contain a dot or a
    bracket.
    """
    if isinstance(path, str):
        return [
            _unescape(next(group for group in match.groups() if group is not None))
            for match in _PATH_TOKEN.finditer(path)
        ]
    if isinstance(path, int):
        return [path]
    return list(path)


def _unescape(segment: str) -> str:
    return re.sub(r"\\(.)", r"\1", segment)


def _as_index(key: str | int) -> int | None:
    """The sequence index ``key`` denotes, if any."""
    if isinstance(key, bool):
        return None
    if isinstance(key, int):
        return key
    if key.lstrip("-").isdigit():
        return int(key)
    return None


def _read(container: Any, key: str | int, default: Any) -> Any:
    if isinstance(container, Mapping):
        if key in container:
            return container[key]
        index = _as_index(key)
        if index is not None and index in container:
            return container[index]
        return default
    if isinstance(container, list | tuple | str):
        index = _as_index(key)
        if index is None:
            return default
        try:
            return container[index]
        except IndexError:
            return default
    return default


def get(obj: Any, path: Path, default: Any = None) -> Any:
    """Read the value at ``path``, or ``default`` if any segment is missing.

    Never raises: a path running past a leaf, off the end of a list or into a
    ``None`` yields ``default``. Pass a unique sentinel as ``default`` to tell a
    missing key from a stored ``None``.
    """
    current = obj
    for key in to_path(path):
        if current is None:
            return default
        current = _read(current, key, _MISSING)
        if current is _MISSING:
            return default
    return current


class _Missing:
    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<missing>"


_MISSING = _Missing()


def set_(obj: Any, path: Path, value: Any) -> Any:
    """Write ``value`` at ``path``, creating missing containers along the way.

    A missing container becomes a list when the segment that follows is a
    non-negative index, and a dict otherwise. Lists are padded with ``None`` to
    reach the index being written. ``obj`` is mutated and returned.
    """
    keys = to_path(path)
    if not keys:
        return obj

    current = obj
    for position, key in enumerate(keys[:-1]):
        child = _read(current, key, _MISSING)
        if child is _MISSING or child is None or not _is_container(child):
            index = _as_index(keys[position + 1])
            child = [] if index is not None and index >= 0 else {}
            _write(current, key, child)
        current = child

    _write(current, keys[-1], value)
    return obj


def _is_container(value: Any) -> bool:
    return isinstance(value, MutableMapping | MutableSequence)


def _write(container: Any, key: str | int, value: Any) -> None:
    if isinstance(container, MutableSequence):
        index = _as_index(key)
        if index is None:
            return
        if index < 0:
            if -index <= len(container):
                container[index] = value
            return
        while len(container) <= index:
            container.append(None)
        container[index] = value
        return
    if isinstance(container, MutableMapping):
        if key not in container:
            index = _as_index(key)
            if index is not None and index in container:
                container[index] = value
                return
        container[key] = value


def unset(obj: Any, path: Path | None) -> bool:
    """Remove the value at ``path``. Returns whether the path is now absent.

    A list element is blanked to ``None`` rather than removed, so that indices
    still to be visited keep their positions. Callers removing several indices
    of one list do so in a single pass and then drop the blanks, which a
    shrinking list would make impossible.
    """
    if path is None:
        return True
    keys = to_path(path)
    if not keys:
        return True

    parent = obj
    for key in keys[:-1]:
        if parent is None:
            return True
        parent = _read(parent, key, _MISSING)
        if parent is _MISSING:
            return True

    last = keys[-1]
    if isinstance(parent, MutableSequence):
        index = _as_index(last)
        if index is not None and -len(parent) <= index < len(parent):
            parent[index] = None
        return True
    if isinstance(parent, MutableMapping):
        if last in parent:
            del parent[last]
            return True
        index = _as_index(last)
        if index is not None and index in parent:
            del parent[index]
    return True
