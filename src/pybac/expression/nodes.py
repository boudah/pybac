"""The syntax tree an expression parses into.

Nodes are mutable while the parser builds them: an operator node is created
before its right-hand side exists, and a parenthesised group is grafted in
afterwards. ``parent`` is the parser's own bookkeeping -- it lets the operator
handler walk back up to re-associate by precedence -- and is excluded from
equality and repr so that trees compare by shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "ArrayLiteral",
    "BinaryExpression",
    "ConditionalExpression",
    "FilterExpression",
    "Identifier",
    "Literal",
    "Node",
    "ObjectLiteral",
    "UnaryExpression",
]


class Node:
    """Base of every tree node.

    Deliberately not a dataclass: ``parent`` stays a plain class attribute so
    that subclasses may declare fields without a default after it.
    """

    parent: Node | None = None


@dataclass(eq=True)
class Literal(Node):
    """A string, number or boolean written into the expression."""

    value: str | int | float | bool | None


@dataclass(eq=True)
class Identifier(Node):
    """A name, optionally reached through another expression.

    ``source`` is what the name is read from -- ``b`` in ``a.b`` has ``a`` as
    its source. ``relative`` marks a name resolved against the element under
    test inside a filter, as ``.status`` is in ``items[.status == "ok"]``.
    """

    value: str
    source: Node | None = None
    relative: bool = False


@dataclass(eq=True)
class UnaryExpression(Node):
    """An operator with one operand to its right, such as ``!``."""

    operator: str
    right: Node | None = None


@dataclass(eq=True)
class BinaryExpression(Node):
    """An operator with an operand on each side."""

    operator: str
    left: Node | None = None
    right: Node | None = None


@dataclass(eq=True)
class ArrayLiteral(Node):
    """``["G1", "G2"]``."""

    value: list[Node] = field(default_factory=list)


@dataclass(eq=True)
class ObjectLiteral(Node):
    """``{bu: user.tags.bu}``."""

    value: dict[str, Node] = field(default_factory=dict)


@dataclass(eq=True)
class ConditionalExpression(Node):
    """``test ? consequent : alternate``.

    ``consequent`` may be absent, as in ``a ?: b``, which yields ``a`` when it
    is truthy.
    """

    test: Node | None = None
    consequent: Node | None = None
    alternate: Node | None = None


@dataclass(eq=True)
class FilterExpression(Node):
    """``subject[expr]`` -- either a subscript or a filter over a collection.

    ``relative`` distinguishes the two: ``items[.done]`` tests each element,
    while ``items[index]`` looks one up.
    """

    subject: Node | None = None
    expr: Node | None = None
    relative: bool = False


def describe(node: Node | None) -> Any:
    """Render a tree as plain data, for error messages and debugging."""
    match node:
        case None:
            return None
        case Literal(value=value):
            return {"Literal": value}
        case Identifier(value=value, source=source, relative=relative):
            rendered: dict[str, Any] = {"Identifier": value}
            if source is not None:
                rendered["from"] = describe(source)
            if relative:
                rendered["relative"] = True
            return rendered
        case UnaryExpression(operator=operator, right=right):
            return {operator: describe(right)}
        case BinaryExpression(operator=operator, left=left, right=right):
            return {operator: [describe(left), describe(right)]}
        case ArrayLiteral(value=values):
            return [describe(item) for item in values]
        case ObjectLiteral(value=pairs):
            return {key: describe(item) for key, item in pairs.items()}
        case ConditionalExpression(test=test, consequent=yes, alternate=no):
            return {"?": [describe(test), describe(yes), describe(no)]}
        case FilterExpression(subject=subject, expr=expr, relative=relative):
            return {"filter": [describe(subject), describe(expr)], "relative": relative}
        case _:  # pragma: no cover - every node type is covered above
            raise TypeError(f"unknown node {node!r}")
