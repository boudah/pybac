"""Turns expression text into tokens.

The token vocabulary comes from the grammar, so adding an operator there is
enough for the lexer to recognise it. Word operators such as ``containsAny``
are matched on word boundaries, which keeps an identifier named ``containsAnyway``
whole.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Final

from pybac.errors import ExpressionError
from pybac.expression.grammar import ELEMENTS, Element

__all__ = ["Token", "tokenize"]

# Cyrillic and Latin-1 letters are legal in a name.
_IDENTIFIER_START = r"a-zA-Zа-яА-Я_À-ÖØ-öø-ÿ$"  # noqa: RUF001
_IDENTIFIER_BODY = r"a-zA-Z0-9а-яА-Я_À-ÖØ-öø-ÿ$"  # noqa: RUF001

_IDENTIFIER = re.compile(rf"^[{_IDENTIFIER_START}][{_IDENTIFIER_BODY}]*$")
_NUMERIC = re.compile(r"^-?(?:(?:[0-9]*\.[0-9]+)|[0-9]+)$")
_WHITESPACE = re.compile(r"^\s*$")
_REGEX_SPECIAL = re.compile(r"[.*+?^${}()|\[\]\\]")

# Matched before operators, so that an operator inside a string stays text.
_BEFORE_OPERATORS: Final = (
    r"'(?:(?:\\')|[^'])*'",
    r'"(?:(?:\\")|[^"])*"',
    r"\s+",
    r"\btrue\b",
    r"\bfalse\b",
)

# Matched after operators, so that `1.5` is not split on the `.` operator.
_AFTER_OPERATORS: Final = (
    rf"[{_IDENTIFIER_START}][{_IDENTIFIER_BODY}]*",
    r"(?:(?:[0-9]*\.[0-9]+)|[0-9]+)",
)

# A `-` directly after any of these starts a negative number rather than
# continuing a subtraction.
_MINUS_NEGATES_AFTER: Final = frozenset(
    {"binaryOp", "unaryOp", "openParen", "openBracket", "question", "colon"}
)


@dataclass
class Token:
    """One lexical unit.

    ``raw`` keeps the original text, trailing whitespace included, so that a
    syntax error can quote the expression up to the point it went wrong.
    """

    type: str
    value: Any
    raw: str


def _escape(element: str) -> str:
    escaped = _REGEX_SPECIAL.sub(lambda match: "\\" + match.group(0), element)
    if _IDENTIFIER.match(element):
        return rf"\b{escaped}\b"
    return escaped


def _build_split_pattern() -> re.Pattern[str]:
    # Longest first, so that `>=` is never read as `>` followed by `=`.
    operators = [
        _escape(element) for element in sorted(ELEMENTS, key=len, reverse=True)
    ]
    alternatives = "|".join((*_BEFORE_OPERATORS, *operators, *_AFTER_OPERATORS))
    return re.compile(f"({alternatives})")


_SPLIT: Final = _build_split_pattern()


def _elements(expression: str) -> list[str]:
    return [part for part in _SPLIT.split(expression) if part]


def _make_token(element: str) -> Token:
    if element[0] in ("'", '"'):
        return Token(type="literal", value=_unquote(element), raw=element)
    if _NUMERIC.match(element):
        number: int | float = float(element) if "." in element else int(element)
        return Token(type="literal", value=number, raw=element)
    if element in ("true", "false"):
        return Token(type="literal", value=element == "true", raw=element)

    grammar_element: Element | None = ELEMENTS.get(element)
    if grammar_element is not None:
        return Token(type=grammar_element.type, value=element, raw=element)
    if _IDENTIFIER.match(element):
        return Token(type="identifier", value=element, raw=element)

    raise ExpressionError(f"invalid token {element!r}")


def _unquote(text: str) -> str:
    quote = text[0]
    return text[1:-1].replace("\\" + quote, quote).replace("\\\\", "\\")


def tokenize(expression: str) -> list[Token]:
    """Split ``expression`` into tokens.

    Raises :class:`~pybac.errors.ExpressionError` on text that is not a token.
    """
    tokens: list[Token] = []
    negate = False

    for element in _elements(expression):
        if _WHITESPACE.match(element):
            if tokens:
                tokens[-1].raw += element
            continue
        if element == "-" and _starts_a_negative_number(tokens):
            negate = True
            continue
        if negate:
            element = "-" + element
            negate = False
        tokens.append(_make_token(element))

    if negate:
        # A trailing `-`; let the parser report where the expression ends.
        tokens.append(_make_token("-"))
    return tokens


def _starts_a_negative_number(tokens: list[Token]) -> bool:
    if not tokens:
        return True
    return tokens[-1].type in _MINUS_NEGATES_AFTER
