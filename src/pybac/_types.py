"""Type predicates and value parsing shared by the condition operators.

Conditions receive whatever JSON put in the policy and in the evaluation
context, so they guard their operands before comparing them. Centralising the
guards keeps that behaviour consistent, and keeps one Python subtlety in a
single place: ``bool`` subclasses ``int``.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, TypeGuard

__all__ = [
    "as_list",
    "is_boolean",
    "is_mapping",
    "is_number",
    "is_sequence",
    "is_string",
    "parse_date",
]


def is_number(value: Any) -> TypeGuard[int | float]:
    """Whether ``value`` is a real number.

    ``bool`` is excluded. It subclasses ``int``, so a bare ``isinstance`` check
    would let ``True`` satisfy a numeric condition and then compare equal to 1.
    """
    return isinstance(value, int | float) and not isinstance(value, bool)


def is_string(value: Any) -> TypeGuard[str]:
    return isinstance(value, str)


def is_boolean(value: Any) -> TypeGuard[bool]:
    return isinstance(value, bool)


def is_sequence(value: Any) -> TypeGuard[list[Any] | tuple[Any, ...]]:
    """Whether ``value`` is a list-like container. Strings are not."""
    return isinstance(value, list | tuple)


def is_mapping(value: Any) -> TypeGuard[Mapping[str, Any]]:
    return isinstance(value, Mapping)


def as_list(value: Any) -> list[Any]:
    """Wrap a scalar so it can be treated uniformly with a collection.

    A string is a scalar here, not a sequence of characters.
    """
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def parse_date(value: Any) -> datetime | None:
    """Read an ISO 8601 timestamp, or ``None`` when ``value`` is not one.

    A timestamp without an offset is read as UTC. Leaving it naive would make it
    incomparable with an offset-aware one, and a policy that raises on a
    comparison is worse than one that fixes an interpretation.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
