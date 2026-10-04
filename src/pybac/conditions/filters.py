"""Turning a named condition into a query filter.

A condition that cannot be settled without the data itself -- "only resources
tagged with one of my business units" -- is no use as a verdict on a resource
nobody has fetched yet. Compiled into a filter, it becomes something a caller
can push into its own query, so the database returns only what the policy
allows.

This is the second meaning of a condition. The first, in
:mod:`pybac.conditions.operators`, decides; this one describes. Every condition
needs both -- see ``docs/adding-conditions.md``.

A condition that restricts access but describes nothing about the resource --
one about the caller's address, say -- compiles to
:data:`~pybac.domain.query_filter.UNSATISFIABLE` rather than to nothing.
Contributing no filter would leave the query unrestricted, which is the wrong
way for a restriction to fail.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Final

from pybac._types import is_number, is_string
from pybac.domain.query_filter import UNSATISFIABLE, LeafFilter, QueryFilterComparator

__all__ = ["FILTERS", "FilterBuilder"]

FilterBuilder = Callable[[str, list[Any]], list[LeafFilter]]

_C = QueryFilterComparator


def _first(values: list[Any]) -> Any:
    """The one value a scalar comparison uses.

    A condition may be written with several values, which for a verdict means
    "any of these". A field comparison holds one, so the rest are dropped.
    """
    return values[0] if values else None


def _scalar(comparator: QueryFilterComparator) -> FilterBuilder:
    def build(key: str, values: list[Any]) -> list[LeafFilter]:
        return [LeafFilter(key=key, comparator=comparator, value=_first(values))]

    return build


def _typed(
    comparator: QueryFilterComparator, accepts: Callable[[Any], bool]
) -> FilterBuilder:
    """A scalar comparison that only applies to values of the right type.

    The guard reads the value, not the list around it. Guarding the list would
    reject everything, and a condition that produces no filter does not restrict.
    """

    def build(key: str, values: list[Any]) -> list[LeafFilter]:
        value = _first(values)
        if not accepts(value):
            return []
        return [LeafFilter(key=key, comparator=comparator, value=value)]

    return build


def _lowered(comparator: QueryFilterComparator) -> FilterBuilder:
    def build(key: str, values: list[Any]) -> list[LeafFilter]:
        value = _first(values)
        if not is_string(value):
            return []
        return [LeafFilter(key=key, comparator=comparator, value=value.casefold())]

    return build


def _collection(comparator: QueryFilterComparator) -> FilterBuilder:
    def build(key: str, values: list[Any]) -> list[LeafFilter]:
        return [LeafFilter(key=key, comparator=comparator, value=list(values))]

    return build


def _is_null(key: str, values: list[Any]) -> list[LeafFilter]:
    return [LeafFilter(key=key, comparator=_C.EQ, value=None)]


def _describes_nothing(key: str, values: list[Any]) -> list[LeafFilter]:
    """For a condition about the caller rather than the resource."""
    return [UNSATISFIABLE]


_BASE: Final[dict[str, FilterBuilder]] = {
    "NumericEquals": _typed(_C.EQ, is_number),
    "NumericNotEquals": _typed(_C.NEQ, is_number),
    "NumericLessThan": _typed(_C.LT, is_number),
    "NumericLessThanEquals": _typed(_C.LTE, is_number),
    "NumericGreaterThan": _typed(_C.GT, is_number),
    "NumericGreaterThanEquals": _typed(_C.GTE, is_number),
    "DateEquals": _scalar(_C.EQ),
    "DateNotEquals": _scalar(_C.NEQ),
    "DateLessThan": _scalar(_C.LT),
    "DateLessThanEquals": _scalar(_C.LTE),
    "DateGreaterThan": _scalar(_C.GT),
    "DateGreaterThanEquals": _scalar(_C.GTE),
    "StringEquals": _scalar(_C.EQ),
    "StringNotEquals": _scalar(_C.NEQ),
    "StringEqualsIgnoreCase": _lowered(_C.EQ),
    "StringNotEqualsIgnoreCase": _lowered(_C.NEQ),
    "StringLike": _typed(_C.MATCHES, is_string),
    "StringNotLike": _typed(_C.NOT_MATCHES, is_string),
    "Bool": _scalar(_C.EQ),
    "Null": _is_null,
    "IpAddress": _describes_nothing,
    "NotIpAddress": _describes_nothing,
    "InValues": _collection(_C.IN),
    "NotInValues": _collection(_C.NOT_IN),
    "ContainsAtLeastOne": _collection(_C.OVERLAPS),
    "ContainsAll": _collection(_C.SUBSET_OF),
    "ContainsNone": _collection(_C.NOT_OVERLAPS),
}


def _build() -> dict[str, FilterBuilder]:
    table: dict[str, FilterBuilder] = {}
    for name, builder in _BASE.items():
        table[name] = builder
        # Asking only when a value is present is a distinction the verdict makes;
        # the query either compares the field or does not.
        table[f"{name}IfExists"] = builder
        # A quantifier over values becomes a question about the field's contents,
        # whatever the condition underneath compares.
        table[f"ForAnyValue:{name}"] = _collection(_C.OVERLAPS)
        table[f"ForAllValues:{name}"] = _collection(_C.SUBSET_OF)
    return table


#: Every condition a policy may name, as a filter builder.
FILTERS: Final[dict[str, FilterBuilder]] = _build()
