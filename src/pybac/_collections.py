"""Membership between two collections.

The same three questions are asked in two places -- by the ``containsAny``
family of expression operators, and by the ``ContainsAtLeastOne`` family of
policy conditions -- so they are answered once here.

A bare value counts as a collection of one, because a policy may compare a
single group against a list of them without saying so.
"""

from __future__ import annotations

from typing import Any

from pybac._types import as_list

__all__ = ["contains_all", "contains_any", "contains_none"]


def contains_any(left: Any, right: Any) -> bool:
    """Whether the two collections share at least one value."""
    against = as_list(right)
    return any(item in against for item in as_list(left))


def contains_all(left: Any, right: Any) -> bool:
    """Whether every value on the *left* also appears on the right.

    The direction is worth stating plainly, because the names built on this one
    read the other way. It asks whether the left is wholly contained by the
    right, so ``["G1"]`` against ``["G1", "G2"]`` holds, while
    ``["G1", "G2"]`` against ``["G1"]`` does not. This is what the stored
    policies were written against.

    An empty left side is contained by anything.
    """
    against = as_list(right)
    return all(item in against for item in as_list(left))


def contains_none(left: Any, right: Any) -> bool:
    """Whether the two collections share no value."""
    return not contains_any(left, right)
