"""Turning policies into a filter over the records a query will return.

A verdict needs a record to be about. A list endpoint has none yet -- it cannot
load every user and ask about each one -- so the policies are compiled into a
filter pushed into the caller's own query instead.

Two jobs live here. Building that filter from the statements that apply, and
guarding a caller's *own* filters so they cannot reach a field the principal may
not see.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final

from pybac.context import PolicyDecisionContext
from pybac.domain.policy import MatchingPolicy, Policy, PolicyEffect, PolicyStatement
from pybac.domain.query_filter import (
    UNSATISFIABLE,
    Combinator,
    CombinatorFilter,
    LeafFilter,
    QueryFilter,
    QueryFilterComparator,
)
from pybac.processor import PolicyProcessor

__all__ = ["WITHHELD", "QueryCompiler", "combine"]

#: The value a filter is given when the field it names may not be queried.
WITHHELD: Final = "__INVALID__"

#: Keys every principal may filter on, whatever a policy says about fields.
_ALWAYS_QUERYABLE: Final = frozenset({"instance", "app_context", "_key", "id"})


def combine(filters: Sequence[QueryFilter], combinator: Combinator) -> QueryFilter:
    """Join filters. One on its own is not wrapped in a group of one.

    Expects at least one filter; every caller has already established that
    there is something to join.
    """
    if len(filters) == 1:
        return filters[0]
    return CombinatorFilter(comparator=combinator, value=list(filters))


class QueryCompiler:
    """Compiles policies into filters, against an already-built context."""

    def __init__(self, processor: PolicyProcessor) -> None:
        self._processor = processor

    def filters(
        self,
        policies: Sequence[Policy],
        matching_policy: MatchingPolicy,
        context: PolicyDecisionContext,
    ) -> list[QueryFilter]:
        """The filter a caller must apply to see only what the policies allow.

        An empty list means no restriction: some applicable statement grants
        this unconditionally. A filter no record satisfies means the opposite --
        no statement applies, so nothing is visible.

        Statements are alternatives, so their filters are joined with ``OR``.
        A statement granting access to a principal's own records is nothing
        special here: ``target.ownerId == req.userId`` is a condition like any
        other, and joins the rest by itself.
        """
        applicable = self._processor.select(policies, matching_policy)
        if not applicable.all:
            return [UNSATISFIABLE]
        if not applicable.every_one_conditional:
            return []

        filters, unrestricted = self._per_statement(applicable.conditional, context)
        if unrestricted:
            return []
        return [combine(filters, "OR")]

    def restrict(
        self,
        given: Sequence[QueryFilter],
        policies: Sequence[Policy],
        matching_policy: MatchingPolicy,
        context: PolicyDecisionContext,
    ) -> list[QueryFilter]:
        """Stop a caller's filters reaching fields the principal may not see.

        A filter on a withheld field is either narrowed to the records where the
        field *is* visible, or made unsatisfiable when it never is.

        Note what a condition means here. On a `RestrictFields` statement it
        reads as *when the field may be queried* -- the opposite of its meaning
        when a record is masked. Both readings are relied on by existing
        callers, so both are kept; see ``docs/behaviour.md``.
        """
        asked = list(given)
        queried = {
            entry.key
            for entry in asked
            if isinstance(entry, LeafFilter)
            and entry.key
            and entry.key not in _ALWAYS_QUERYABLE
        }
        if not queried:
            return asked

        withheld = self._withheld(policies, matching_policy)
        if not queried & withheld.keys():
            return asked
        return [self._guarded(entry, withheld, context) for entry in asked]

    # -- internals -------------------------------------------------------

    def _per_statement(
        self, statements: Sequence[PolicyStatement], context: PolicyDecisionContext
    ) -> tuple[list[QueryFilter], bool]:
        """One filter per statement, and whether any of them restricts nothing."""
        produced: list[QueryFilter] = []
        for statement in statements:
            parts = self._processor.to_query_filters(statement.condition, context)
            if not parts:
                return [], True
            # A statement's own parts must all hold; statements are alternatives.
            produced.append(combine(parts, "AND"))
        return produced, False

    def _withheld(
        self, policies: Sequence[Policy], matching_policy: MatchingPolicy
    ) -> dict[str, list[PolicyStatement]]:
        restricting = matching_policy.with_effect(PolicyEffect.RESTRICT_FIELDS)
        applicable = list(self._processor.select(policies, restricting).all)

        withheld: dict[str, list[PolicyStatement]] = {}
        for statement in applicable:
            for name in statement.not_fields or ():
                withheld.setdefault(name, []).append(statement)
        for statement in applicable:
            for name in statement.fields or ():
                withheld.pop(name, None)
        return withheld

    def _guarded(
        self,
        entry: QueryFilter,
        withheld: Mapping[str, list[PolicyStatement]],
        context: PolicyDecisionContext,
    ) -> QueryFilter:
        key = entry.key if isinstance(entry, LeafFilter) else None
        if key is None or key not in withheld:
            return entry

        conditional = next(
            (statement for statement in withheld[key] if statement.condition), None
        )
        if conditional is None:
            # Never visible, so nothing may be found by filtering on it.
            return LeafFilter(
                key=key, comparator=QueryFilterComparator.EQ, value=WITHHELD
            )

        allowed: list[Any] = self._processor.to_query_filters(
            conditional.condition, context
        )
        if not allowed:
            # Visible everywhere, so the caller's filter stands as written.
            return entry
        return CombinatorFilter(
            comparator="AND", value=[entry, combine(allowed, "AND")]
        )
