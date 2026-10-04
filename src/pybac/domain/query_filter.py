"""Query filters: the compiled form of a policy condition.

A condition that cannot be decided without the data itself -- "only resources
in one of my groups" -- is compiled into a filter tree instead of a verdict, for
a caller to push down into its own query. A filter is either a *leaf*
comparing one key against a value, or a *combinator* joining other filters with
``AND`` or ``OR``.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Discriminator, Tag

__all__ = [
    "UNSATISFIABLE",
    "Combinator",
    "CombinatorFilter",
    "LeafFilter",
    "QueryFilter",
    "QueryFilterComparator",
    "negate",
]


class QueryFilterComparator(StrEnum):
    """How a leaf filter compares its key against its value.

    The values are the wire format, consumed by whatever translates a filter
    tree into a database query. They are words rather than symbols so that a
    filter survives a query string without escaping.

    The three collection comparators differ in *which side* holds a collection,
    which is the thing to get right when translating one:

    ======================  ==================================================
    :attr:`IN`              the field holds one value, among those given
    :attr:`OVERLAPS`        the field holds a list sharing a value with those given
    :attr:`SUBSET_OF`       the field holds a list, every value of it among those given
    ======================  ==================================================
    """

    EQ = "EQ"
    NEQ = "NEQ"
    LT = "LT"
    LTE = "LTE"
    GT = "GT"
    GTE = "GTE"
    #: The field matches a pattern of `*` and `?`. Deliberately not `LIKE`,
    #: which would invite a translator to pass `*` to SQL, where it means
    #: nothing.
    MATCHES = "MATCHES"
    NOT_MATCHES = "NOT_MATCHES"
    IN = "IN"
    NOT_IN = "NOT_IN"
    OVERLAPS = "OVERLAPS"
    NOT_OVERLAPS = "NOT_OVERLAPS"
    #: The field's values are all among those given -- the field is the subset.
    #: Named for the direction, because reading it the other way round inverts
    #: the policy.
    SUBSET_OF = "SUBSET_OF"


Combinator = Literal["AND", "OR"]


class LeafFilter(BaseModel):
    """A comparison of one key against one value."""

    model_config = ConfigDict(frozen=True)

    key: str | None = None
    comparator: QueryFilterComparator
    value: Any = None


class CombinatorFilter(BaseModel):
    """A group of filters joined by ``AND`` or ``OR``."""

    model_config = ConfigDict(frozen=True)

    comparator: Combinator
    value: list[QueryFilter]


#: A filter no record can satisfy.
#:
#: Produced where a condition restricts access but cannot be expressed as a
#: field comparison. Contributing nothing would leave the query unrestricted,
#: which is the wrong way to fail.
UNSATISFIABLE: LeafFilter


def _filter_kind(value: Any) -> str:
    comparator = (
        value.get("comparator")
        if isinstance(value, dict)
        else getattr(value, "comparator", None)
    )
    return "combinator" if comparator in ("AND", "OR") else "leaf"


QueryFilter = Annotated[
    Union[  # noqa: UP007 - Annotated members need the explicit Union form
        Annotated[LeafFilter, Tag("leaf")],
        Annotated[CombinatorFilter, Tag("combinator")],
    ],
    Discriminator(_filter_kind),
]

CombinatorFilter.model_rebuild()

UNSATISFIABLE = LeafFilter(
    key="id", comparator=QueryFilterComparator.EQ, value="__INVALID__"
)


def negate(comparator: QueryFilterComparator) -> QueryFilterComparator:
    """The comparator that accepts exactly what ``comparator`` rejects."""
    return _OPPOSITES.get(comparator, QueryFilterComparator.NEQ)


_OPPOSITES: dict[QueryFilterComparator, QueryFilterComparator] = {
    QueryFilterComparator.EQ: QueryFilterComparator.NEQ,
    QueryFilterComparator.NEQ: QueryFilterComparator.EQ,
    QueryFilterComparator.LT: QueryFilterComparator.GTE,
    QueryFilterComparator.GTE: QueryFilterComparator.LT,
    QueryFilterComparator.GT: QueryFilterComparator.LTE,
    QueryFilterComparator.LTE: QueryFilterComparator.GT,
    QueryFilterComparator.MATCHES: QueryFilterComparator.NOT_MATCHES,
    QueryFilterComparator.NOT_MATCHES: QueryFilterComparator.MATCHES,
    QueryFilterComparator.IN: QueryFilterComparator.NOT_IN,
    QueryFilterComparator.NOT_IN: QueryFilterComparator.IN,
    QueryFilterComparator.OVERLAPS: QueryFilterComparator.NOT_OVERLAPS,
    QueryFilterComparator.NOT_OVERLAPS: QueryFilterComparator.OVERLAPS,
}
