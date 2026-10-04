"""Walks a parsed expression to a value, against a context.

The context is the data a policy may address: ``req``, ``user``, ``target`` and
whatever the calling service contributed. Reading a name that is not there
yields ``None`` at any depth, so ``target.a.b.c`` on an absent ``a`` is a
non-match rather than an error.

Errors are not caught here. Comparing values of unrelated types raises, as it
does anywhere in Python, and the caller decides what that means -- for policy
evaluation it means the condition did not match, so access is denied.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pybac.errors import ExpressionError
from pybac.expression.nodes import (
    ArrayLiteral,
    BinaryExpression,
    ConditionalExpression,
    FilterExpression,
    Identifier,
    Literal,
    Node,
    ObjectLiteral,
    UnaryExpression,
)
from pybac.expression.operators import BINARY, LAZY_BINARY, UNARY
from pybac.expression.parser import parse

__all__ = ["Evaluator", "evaluate"]


class Evaluator:
    """Evaluates parsed expressions against one context.

    Reusable: build it once for a context and evaluate several expressions.
    """

    def __init__(
        self,
        context: Mapping[str, Any],
        relative_context: Mapping[str, Any] | None = None,
    ) -> None:
        self._context = context
        # What a leading `.` refers to: the element under test inside a filter,
        # and otherwise the context itself.
        self._relative_context: Any = (
            context if relative_context is None else relative_context
        )

    def evaluate(self, node: Node | None) -> Any:
        """Reduce ``node`` to a value."""
        match node:
            case None:
                return None
            case Literal(value=value):
                return value
            case Identifier():
                return self._identifier(node)
            case ArrayLiteral(value=items):
                return [self.evaluate(item) for item in items]
            case ObjectLiteral(value=pairs):
                return {key: self.evaluate(item) for key, item in pairs.items()}
            case UnaryExpression(operator=name, right=right):
                return self._unary(name, right)
            case BinaryExpression(operator=name, left=left, right=right):
                return self._binary(name, left, right)
            case ConditionalExpression():
                return self._conditional(node)
            case FilterExpression():
                return self._filter(node)
            case _:  # pragma: no cover - every node type is handled above
                raise ExpressionError(f"cannot evaluate {node!r}")

    # -- names -----------------------------------------------------------

    def _identifier(self, node: Identifier) -> Any:
        if node.source is None:
            holder: Any = self._relative_context if node.relative else self._context
        else:
            holder = self.evaluate(node.source)
            if isinstance(holder, list | tuple):
                # A step into a collection reads its first element, so that
                # `target.items.name` works on a one-element list.
                holder = holder[0] if holder else None

        if isinstance(holder, Mapping):
            return holder.get(node.value)
        return None

    # -- operators -------------------------------------------------------

    def _unary(self, name: str, right: Node | None) -> Any:
        apply = UNARY.get(name)
        if apply is None:
            raise ExpressionError(f"operator {name!r} has no meaning when evaluating")
        return apply(self.evaluate(right))

    def _binary(self, name: str, left: Node | None, right: Node | None) -> Any:
        defer = LAZY_BINARY.get(name)
        if defer is not None:
            return defer(lambda: self.evaluate(left), lambda: self.evaluate(right))

        apply = BINARY.get(name)
        if apply is None:
            raise ExpressionError(f"operator {name!r} has no meaning when evaluating")
        return apply(self.evaluate(left), self.evaluate(right))

    # -- branching and filtering -----------------------------------------

    def _conditional(self, node: ConditionalExpression) -> Any:
        test = self.evaluate(node.test)
        if test:
            # `a ?: b` keeps whatever `a` held rather than re-reading it.
            return self.evaluate(node.consequent) if node.consequent else test
        return self.evaluate(node.alternate)

    def _filter(self, node: FilterExpression) -> Any:
        subject = self.evaluate(node.subject)
        if node.relative:
            return [
                element
                for element in _as_elements(subject)
                if Evaluator(self._context, element).evaluate(node.expr)
            ]

        key = self.evaluate(node.expr)
        if isinstance(key, bool):
            # `items[true]` keeps the subject, `items[false]` discards it.
            return subject if key else None
        return _lookup(subject, key)


def _as_elements(subject: Any) -> list[Any]:
    if isinstance(subject, list | tuple):
        return list(subject)
    return [] if subject is None else [subject]


def _lookup(subject: Any, key: Any) -> Any:
    if isinstance(subject, Mapping):
        return subject.get(key)
    if isinstance(subject, list | tuple | str) and isinstance(key, int):
        return subject[key] if -len(subject) <= key < len(subject) else None
    return None


def evaluate(expression: str, context: Mapping[str, Any]) -> Any:
    """Parse and evaluate ``expression`` against ``context``."""
    return Evaluator(context).evaluate(parse(expression))
