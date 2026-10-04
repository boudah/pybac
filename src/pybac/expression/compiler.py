"""Compiling an expression into a query filter instead of a verdict.

A condition such as ``target.resource.groups containsAny req.groups`` cannot be
settled about a resource nobody has fetched. Read this way, it becomes a filter
a caller pushes into its own query, so the database returns only what the policy
allows.

The two readings differ in one place: a name. The evaluator reads
``target.resource.groups`` as a value; here it stays a *field*, something the
query will compare. Everything else -- ``req``, ``user``, whatever the service
contributed -- is read as a value, exactly as the evaluator reads it, because
those are known now.

An expression that mentions no field at all is not a restriction but a fact:
``req.instance == "T1"`` either holds or does not, the same for every record.
Such a part compiles to :data:`Outcome.ALWAYS` or :data:`Outcome.NEVER`, which
then fold into the surrounding ``&&`` and ``||`` rather than producing a filter
on nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Final

from pybac._types import as_list
from pybac.domain.query_filter import (
    CombinatorFilter,
    LeafFilter,
    QueryFilter,
    QueryFilterComparator,
    negate,
)
from pybac.errors import ExpressionError
from pybac.expression.evaluator import Evaluator
from pybac.expression.nodes import (
    ArrayLiteral,
    BinaryExpression,
    Identifier,
    Literal,
    Node,
    ObjectLiteral,
    UnaryExpression,
)
from pybac.expression.operators import BINARY

__all__ = ["FilterCompiler", "Outcome", "compile_to_filter"]

_C = QueryFilterComparator

#: The prefix marking a name as a field of the record being filtered.
_TARGET: Final = "target"

#: Comparators whose value is a collection rather than a single value.
_COLLECTIONS: Final = frozenset(
    {
        _C.IN,
        _C.NOT_IN,
        _C.OVERLAPS,
        _C.NOT_OVERLAPS,
        _C.SUBSET_OF,
    }
)


class Outcome(Enum):
    """A part of a condition that is settled already, for every record."""

    ALWAYS = "always"
    NEVER = "never"


@dataclass(frozen=True)
class _Field:
    """A name the query will compare, rather than a value known now."""

    path: str


Compiled = QueryFilter | Outcome


def _dotted_path(node: Identifier) -> str | None:
    """``a.b.c`` for a plain chain of names, or ``None`` for anything else."""
    parts: list[str] = []
    current: Node | None = node
    while isinstance(current, Identifier):
        parts.append(current.value)
        current = current.source
    if current is not None:
        return None
    return ".".join(reversed(parts))


def _sided(
    direct: QueryFilterComparator, mirrored: QueryFilterComparator | None
) -> Any:
    """A comparison, which may also be written with the field on the right."""

    def build(left: Any, right: Any) -> LeafFilter:
        left_is_field, right_is_field = (
            isinstance(left, _Field),
            isinstance(right, _Field),
        )
        if left_is_field and not right_is_field:
            return _leaf(left.path, direct, right)
        if right_is_field and not left_is_field:
            if mirrored is None:
                raise ExpressionError("this comparison needs the field on the left")
            return _leaf(right.path, mirrored, left)
        raise ExpressionError("one comparison cannot hold two fields")

    return build


def _membership(left: Any, right: Any) -> LeafFilter:
    """``in`` means one thing about a field and another about a collection."""
    if isinstance(left, _Field) and not isinstance(right, _Field):
        # `target.status in ["a", "b"]`
        return _leaf(left.path, _C.IN, right)
    if isinstance(right, _Field) and not isinstance(left, _Field):
        # `"G1" in target.groups`
        return _leaf(right.path, _C.OVERLAPS, left)
    raise ExpressionError("one comparison cannot hold two fields")


def _leaf(key: str, comparator: QueryFilterComparator, value: Any) -> LeafFilter:
    return LeafFilter(
        key=key,
        comparator=comparator,
        value=as_list(value) if comparator in _COLLECTIONS else value,
    )


_COMPARISONS: Final[dict[str, Any]] = {
    "==": _sided(_C.EQ, _C.EQ),
    "!=": _sided(_C.NEQ, _C.NEQ),
    "<": _sided(_C.LT, _C.GT),
    "<=": _sided(_C.LTE, _C.GTE),
    ">": _sided(_C.GT, _C.LT),
    ">=": _sided(_C.GTE, _C.LTE),
    "containsAny": _sided(_C.OVERLAPS, _C.OVERLAPS),
    "containsNone": _sided(_C.NOT_OVERLAPS, _C.NOT_OVERLAPS),
    "containsAll": _sided(_C.SUBSET_OF, None),
    "in": _membership,
}


class FilterCompiler:
    """Reads an expression as a filter over the records a query will return."""

    def __init__(self, context: Any) -> None:
        self._context = context
        self._evaluator = Evaluator(context)

    def compile(self, node: Node | None) -> Compiled:
        """Compile ``node``. Raises :class:`ExpressionError` if it cannot be."""
        return self._as_condition(self._read(node))

    # -- reading ---------------------------------------------------------

    def _read(self, node: Node | None) -> Any:
        match node:
            case None:
                return None
            case Literal(value=value):
                return value
            case Identifier():
                return self._name(node)
            case ArrayLiteral(value=items):
                return [self._read(item) for item in items]
            case ObjectLiteral(value=pairs):
                return {key: self._read(item) for key, item in pairs.items()}
            case UnaryExpression(operator=name, right=right):
                return self._not(name, right)
            case BinaryExpression(operator=name, left=left, right=right):
                return self._combine(name, left, right)
            case _:
                # A ternary or a filter describes a value, not a set of records.
                raise ExpressionError(
                    f"cannot compile {type(node).__name__} to a filter"
                )

    def _name(self, node: Identifier) -> Any:
        path = _dotted_path(node)
        if path is None:
            return self._evaluator.evaluate(node)

        head, _, rest = path.partition(".")
        if head != _TARGET:
            return self._evaluator.evaluate(node)
        if not rest:
            raise ExpressionError("the record itself is not a field")
        return _Field(rest)

    # -- combining -------------------------------------------------------

    def _combine(self, name: str, left: Node | None, right: Node | None) -> Any:
        if name in ("&&", "||"):
            parts = [
                self._as_condition(self._read(left)),
                self._as_condition(self._read(right)),
            ]
            return _every(parts) if name == "&&" else _any(parts)

        read_left, read_right = self._read(left), self._read(right)
        comparison = _COMPARISONS.get(name)
        if comparison is not None:
            if not isinstance(read_left, _Field) and not isinstance(read_right, _Field):
                # A comparison of two known values says nothing about the
                # record, so settle it now and let the answer fold into the
                # surrounding `&&` or `||`.
                return BINARY[name](read_left, read_right)
            return comparison(read_left, read_right)

        arithmetic = BINARY.get(name)
        if arithmetic is None:
            raise ExpressionError(f"operator {name!r} cannot be compiled to a filter")
        if isinstance(read_left, _Field) or isinstance(read_right, _Field):
            raise ExpressionError(f"{name!r} cannot be applied to a field")
        return arithmetic(read_left, read_right)

    def _not(self, name: str, right: Node | None) -> Compiled:
        if name != "!":
            raise ExpressionError(f"operator {name!r} cannot be compiled to a filter")
        return _negated(self._as_condition(self._read(right)))

    def _as_condition(self, value: Any) -> Compiled:
        if isinstance(value, LeafFilter | CombinatorFilter | Outcome):
            return value
        if isinstance(value, _Field):
            # A bare field stands for "this record's field holds".
            return LeafFilter(key=value.path, comparator=_C.EQ, value=True)
        # Nothing about the record: a fact, settled the same way for every one.
        return Outcome.ALWAYS if value is True else Outcome.NEVER


def _every(parts: list[Compiled]) -> Compiled:
    if any(part is Outcome.NEVER for part in parts):
        return Outcome.NEVER
    kept = [part for part in parts if isinstance(part, LeafFilter | CombinatorFilter)]
    if not kept:
        return Outcome.ALWAYS
    if len(kept) == 1:
        return kept[0]
    return CombinatorFilter(comparator="AND", value=kept)


def _any(parts: list[Compiled]) -> Compiled:
    if any(part is Outcome.ALWAYS for part in parts):
        return Outcome.ALWAYS
    kept = [part for part in parts if isinstance(part, LeafFilter | CombinatorFilter)]
    if not kept:
        return Outcome.NEVER
    if len(kept) == 1:
        return kept[0]
    return CombinatorFilter(comparator="OR", value=kept)


def _negated(condition: Compiled) -> Compiled:
    """Negate a compiled condition."""
    if isinstance(condition, Outcome):
        return Outcome.NEVER if condition is Outcome.ALWAYS else Outcome.ALWAYS
    return _negated_filter(condition)


def _negated_filter(condition: QueryFilter) -> QueryFilter:
    """Push the negation down to the comparisons, so the filter stays flat."""
    if isinstance(condition, LeafFilter):
        return condition.model_copy(update={"comparator": negate(condition.comparator)})
    return CombinatorFilter(
        comparator="OR" if condition.comparator == "AND" else "AND",
        value=[_negated_filter(part) for part in condition.value],
    )


def compile_to_filter(node: Node | None, context: Any) -> Compiled:
    """Compile ``node`` against ``context``."""
    return FilterCompiler(context).compile(node)
