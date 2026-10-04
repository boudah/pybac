"""The elements an expression is built from, and how tightly they bind.

The table drives both the lexer, which needs to know what counts as a token,
and the parser, which needs precedence to associate operators. What each
operator *does* is not here: that belongs to whatever evaluates the tree, and
the two evaluators in this package answer differently -- one produces a verdict,
the other a query filter.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

__all__ = ["BINARY_OPERATORS", "ELEMENTS", "Element", "ElementType"]

ElementType = Literal[
    "binaryOp",
    "unaryOp",
    "dot",
    "openBracket",
    "closeBracket",
    "openCurl",
    "closeCurl",
    "colon",
    "comma",
    "openParen",
    "closeParen",
    "question",
]


@dataclass(frozen=True)
class Element:
    type: ElementType
    precedence: int = 0


def _binary(precedence: int) -> Element:
    return Element(type="binaryOp", precedence=precedence)


#: Binary operators and their precedence. Higher binds tighter, so
#: ``a == b && c == d`` groups as ``(a == b) && (c == d)``.
#:
#: Note that ``&&`` and ``||`` share a precedence, which most languages do not.
#: They therefore associate left to right: ``a || b && c`` reads as
#: ``(a || b) && c``, not ``a || (b && c)``. Stored policies are written against
#: this, so changing it would silently reinterpret them. Mixing the two without
#: parentheses is best avoided.
BINARY_OPERATORS: Final[dict[str, int]] = {
    "||": 10,
    "&&": 10,
    "==": 20,
    "!=": 20,
    ">": 20,
    ">=": 20,
    "<": 20,
    "<=": 20,
    "in": 20,
    "containsAny": 20,
    "containsAll": 20,
    "containsNone": 20,
    "+": 30,
    "-": 30,
    "*": 40,
    "/": 40,
    "//": 40,
    "%": 50,
    "^": 50,
}

ELEMENTS: Final[dict[str, Element]] = {
    ".": Element(type="dot"),
    "[": Element(type="openBracket"),
    "]": Element(type="closeBracket"),
    "{": Element(type="openCurl"),
    "}": Element(type="closeCurl"),
    ":": Element(type="colon"),
    ",": Element(type="comma"),
    "(": Element(type="openParen"),
    ")": Element(type="closeParen"),
    "?": Element(type="question"),
    # Binds tighter than anything, so `!a == b` reads as `(!a) == b`.
    "!": Element(type="unaryOp", precedence=1_000_000),
    **{
        operator: _binary(precedence)
        for operator, precedence in BINARY_OPERATORS.items()
    },
}
