"""What each operator means when an expression is evaluated to a value.

Registered here, an operator decides. A second meaning lives elsewhere:
compiling the same expression into a query filter, for a condition that cannot
be settled without the data. An operator needs both to be fully usable — see
``docs/adding-operators.md``.

Comparison follows Python. ``"1" == 1`` is false, two equal dicts are equal, and
ordering values of unrelated types raises rather than inventing an answer. A
raised comparison reaches the caller, which treats a condition it cannot settle
as a non-match, so the policy denies.
"""

from __future__ import annotations

import operator
from collections.abc import Callable
from typing import Any, Final

from pybac._collections import contains_all, contains_any, contains_none

__all__ = ["BINARY", "LAZY_BINARY", "UNARY", "Operand"]

#: A deferred operand. Only operators that may skip one ask for these.
Operand = Callable[[], Any]


def _is_in(value: Any, container: Any) -> bool:
    """``value in container`` -- a substring, or an element of a sequence.

    Anything else is a non-match rather than an error, so a policy testing a
    field that turned out to be a number simply does not match.
    """
    if isinstance(container, str):
        return isinstance(value, str) and value in container
    if isinstance(container, list | tuple):
        return value in container
    return False


def _and(left: Operand, right: Operand) -> Any:
    """``&&``, yielding the operand that decided it and skipping the right."""
    value = left()
    return right() if value else value


def _or(left: Operand, right: Operand) -> Any:
    """``||``, yielding the operand that decided it and skipping the right."""
    value = left()
    return value if value else right()


#: Operators whose operands are both evaluated before they are applied.
BINARY: Final[dict[str, Callable[[Any, Any], Any]]] = {
    "==": operator.eq,
    "!=": operator.ne,
    "<": operator.lt,
    "<=": operator.le,
    ">": operator.gt,
    ">=": operator.ge,
    "in": _is_in,
    "containsAny": contains_any,
    "containsAll": contains_all,
    "containsNone": contains_none,
    "+": operator.add,
    "-": operator.sub,
    "*": operator.mul,
    "/": operator.truediv,
    "//": operator.floordiv,
    "%": operator.mod,
    # `^` raises to a power here; it is not a bitwise exclusive-or.
    "^": operator.pow,
}

#: Operators that decide whether to evaluate their right operand at all.
LAZY_BINARY: Final[dict[str, Callable[[Operand, Operand], Any]]] = {
    "&&": _and,
    "||": _or,
}

UNARY: Final[dict[str, Callable[[Any], Any]]] = {
    "!": operator.not_,
}
