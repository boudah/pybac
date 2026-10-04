"""Builds a syntax tree from tokens.

A state machine, one token at a time. Bracketed and parenthesised regions are
delegated to a nested parser that reports back which token ended it, which is
how an expression of any depth is handled without recursion in the caller.

The language has no transforms (``value | someTransform``) and no function
calls; an expression using either is refused here rather than failing later.

To teach the language a new operator, see ``docs/adding-operators.md``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final

from pybac.errors import ExpressionError
from pybac.expression.grammar import ELEMENTS
from pybac.expression.lexer import Token, tokenize
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

__all__ = ["Parser", "parse"]


@dataclass(frozen=True)
class _Rule:
    """What to do with one token type in one state."""

    to_state: str | None = None
    handler: str | None = None


@dataclass(frozen=True)
class _State:
    token_types: dict[str, _Rule] = field(default_factory=dict)
    sub_handler: str | None = None
    end_states: dict[str, str] = field(default_factory=dict)
    completable: bool = False


_STATES: Final[dict[str, _State]] = {
    "expectOperand": _State(
        token_types={
            "literal": _Rule(to_state="expectBinOp"),
            "identifier": _Rule(to_state="identifier"),
            "unaryOp": _Rule(),
            "openParen": _Rule(to_state="subExpression"),
            "openCurl": _Rule(to_state="expectObjKey", handler="object_start"),
            "dot": _Rule(to_state="traverse"),
            "openBracket": _Rule(to_state="arrayVal", handler="array_start"),
        }
    ),
    "expectBinOp": _State(
        token_types={
            "binaryOp": _Rule(to_state="expectOperand"),
            "dot": _Rule(to_state="traverse"),
            "question": _Rule(to_state="ternaryMid", handler="ternary_start"),
        },
        completable=True,
    ),
    "expectObjKey": _State(
        token_types={
            "literal": _Rule(to_state="expectKeyValSep", handler="object_key"),
            "identifier": _Rule(to_state="expectKeyValSep", handler="object_key"),
            "closeCurl": _Rule(to_state="expectBinOp"),
        }
    ),
    "expectKeyValSep": _State(token_types={"colon": _Rule(to_state="objVal")}),
    "identifier": _State(
        token_types={
            "binaryOp": _Rule(to_state="expectOperand"),
            "dot": _Rule(to_state="traverse"),
            "openBracket": _Rule(to_state="filter"),
            "question": _Rule(to_state="ternaryMid", handler="ternary_start"),
        },
        completable=True,
    ),
    "traverse": _State(token_types={"identifier": _Rule(to_state="identifier")}),
    "filter": _State(sub_handler="filter", end_states={"closeBracket": "identifier"}),
    "subExpression": _State(
        sub_handler="sub_expression", end_states={"closeParen": "expectBinOp"}
    ),
    "objVal": _State(
        sub_handler="object_value",
        end_states={"comma": "expectObjKey", "closeCurl": "expectBinOp"},
    ),
    "arrayVal": _State(
        sub_handler="array_value",
        end_states={"comma": "arrayVal", "closeBracket": "expectBinOp"},
    ),
    "ternaryMid": _State(sub_handler="ternary_mid", end_states={"colon": "ternaryEnd"}),
    "ternaryEnd": _State(sub_handler="ternary_end", completable=True),
}

#: When a state names no handler, one is chosen by token type.
_DEFAULT_HANDLERS: Final[dict[str, str]] = {
    "literal": "literal",
    "identifier": "identifier",
    "binaryOp": "binary_op",
    "unaryOp": "unary_op",
    "dot": "dot",
}


class Parser:
    """Assembles tokens into a tree.

    Feed it with :meth:`add_token`, then call :meth:`complete`. Most callers
    want :func:`parse` instead.
    """

    def __init__(
        self, prefix: str = "", stop_map: dict[str, str] | None = None
    ) -> None:
        self._state = "expectOperand"
        self._tree: Node | None = None
        self._cursor: Node | None = None
        self._expression = prefix
        self._relative = False
        self._stop_map = stop_map or {}
        self._parent_stop = False
        self._sub_parser: Parser | None = None
        self._next_identifier_encapsulates = False
        self._next_identifier_is_relative = False
        self._object_key: str = ""

    # -- driving ---------------------------------------------------------

    def add_token(self, token: Token) -> str | None:
        """Consume one token. Returns the state that ended a delegated region."""
        if self._state == "complete":
            raise ExpressionError("expression already complete")

        state = _STATES[self._state]
        expression_before = self._expression
        self._expression += token.raw

        if state.sub_handler is not None:
            if self._sub_parser is None:
                self._start_sub_expression(expression_before)
            stop_state = self._sub_parser.add_token(token)  # type: ignore[union-attr]
            if stop_state:
                self._end_sub_expression()
                if self._parent_stop:
                    return stop_state
                self._state = stop_state
            return None

        rule = state.token_types.get(token.type)
        if rule is not None:
            handler_name = rule.handler or _DEFAULT_HANDLERS.get(token.type)
            if handler_name is not None:
                self._token_handlers()[handler_name](token)
            if rule.to_state is not None:
                self._state = rule.to_state
            return None

        if token.type in self._stop_map:
            return self._stop_map[token.type]

        raise ExpressionError(
            f"unexpected {token.raw!r} in expression: {self._expression}"
        )

    def complete(self) -> Node | None:
        """Finish parsing and return the tree, or ``None`` for empty input."""
        if self._cursor is not None and not _STATES[self._state].completable:
            raise ExpressionError(f"unexpected end of expression: {self._expression}")
        if self._sub_parser is not None and not self._parent_stop:
            # A bracket or parenthesis opened a region that nothing closed.
            raise ExpressionError(f"unterminated expression: {self._expression}")
        if self._sub_parser is not None:
            self._end_sub_expression()
        if (
            isinstance(self._cursor, ConditionalExpression)
            and self._cursor.alternate is None
        ):
            # The consequent may be elided -- `a ?: b` yields `a` when it holds
            # -- but there must be something to fall back to.
            raise ExpressionError(f"ternary has no alternative: {self._expression}")
        self._state = "complete"
        return self._tree if self._cursor is not None else None

    def is_relative(self) -> bool:
        """Whether the tree reads a name relative to an element under test."""
        return self._relative

    # -- tree building ---------------------------------------------------

    def _place_at_cursor(self, node: Node) -> None:
        if self._cursor is None:
            self._tree = node
        else:
            self._attach_right(self._cursor, node)
            node.parent = self._cursor
        self._cursor = node

    def _place_before_cursor(self, node: Node) -> None:
        self._cursor = self._cursor.parent if self._cursor is not None else None
        self._place_at_cursor(node)

    def _attach_right(self, cursor: Node, node: Node) -> None:
        if isinstance(cursor, UnaryExpression | BinaryExpression):
            cursor.right = node
            return
        # The state table only reaches here with an operator awaiting its right
        # operand. The guard is for a future state that does not.
        raise ExpressionError(  # pragma: no cover
            f"unexpected operand in expression: {self._expression}"
        )

    def _start_sub_expression(self, prefix: str) -> None:
        end_states = _STATES[self._state].end_states
        if not end_states:
            self._parent_stop = True
            end_states = self._stop_map
        self._sub_parser = Parser(prefix=prefix, stop_map=end_states)

    def _end_sub_expression(self) -> None:
        sub_parser = self._sub_parser
        if sub_parser is None:  # pragma: no cover - guarded by both callers
            return
        handler_name = _STATES[self._state].sub_handler
        assert handler_name is not None
        # The handler may still consult the sub-parser, so clear it afterwards.
        self._sub_handlers()[handler_name](sub_parser.complete())
        self._sub_parser = None

    # -- token handlers --------------------------------------------------

    def _token_handlers(self) -> dict[str, Callable[[Token], None]]:
        return {
            "literal": self._on_literal,
            "identifier": self._on_identifier,
            "binary_op": self._on_binary_op,
            "unary_op": self._on_unary_op,
            "dot": self._on_dot,
            "array_start": self._on_array_start,
            "object_start": self._on_object_start,
            "object_key": self._on_object_key,
            "ternary_start": self._on_ternary_start,
        }

    def _on_literal(self, token: Token) -> None:
        self._place_at_cursor(Literal(value=token.value))

    def _on_identifier(self, token: Token) -> None:
        node = Identifier(value=token.value)
        if self._next_identifier_encapsulates:
            node.source = self._cursor
            self._place_before_cursor(node)
            self._next_identifier_encapsulates = False
            return
        if self._next_identifier_is_relative:
            node.relative = True
            self._next_identifier_is_relative = False
        self._place_at_cursor(node)

    def _on_binary_op(self, token: Token) -> None:
        precedence = ELEMENTS[token.value].precedence
        parent = self._cursor.parent if self._cursor is not None else None
        # Climb past anything that binds at least as tightly, so the new
        # operator takes the whole of it as its left operand.
        while (
            isinstance(parent, BinaryExpression | UnaryExpression)
            and ELEMENTS[parent.operator].precedence >= precedence
        ):
            self._cursor = parent
            parent = parent.parent

        node = BinaryExpression(operator=token.value, left=self._cursor)
        if self._cursor is not None:  # pragma: no branch - an operand precedes it
            self._cursor.parent = node
        self._cursor = parent
        self._place_at_cursor(node)

    def _on_unary_op(self, token: Token) -> None:
        self._place_at_cursor(UnaryExpression(operator=token.value))

    def _on_dot(self, _: Token) -> None:
        cursor = self._cursor
        self._next_identifier_encapsulates = (
            cursor is not None
            and not isinstance(cursor, UnaryExpression)
            and (not isinstance(cursor, BinaryExpression) or cursor.right is not None)
        )
        self._next_identifier_is_relative = not self._next_identifier_encapsulates
        if self._next_identifier_is_relative:
            self._relative = True

    def _on_array_start(self, _: Token) -> None:
        self._place_at_cursor(ArrayLiteral())

    def _on_object_start(self, _: Token) -> None:
        self._place_at_cursor(ObjectLiteral())

    def _on_object_key(self, token: Token) -> None:
        self._object_key = str(token.value)

    def _on_ternary_start(self, _: Token) -> None:
        self._tree = ConditionalExpression(test=self._tree)
        self._cursor = self._tree

    # -- sub-expression handlers -----------------------------------------

    def _sub_handlers(self) -> dict[str, Callable[[Node | None], None]]:
        return {
            "array_value": self._on_array_value,
            "object_value": self._on_object_value,
            "sub_expression": self._on_sub_expression,
            "filter": self._on_filter,
            "ternary_mid": self._on_ternary_mid,
            "ternary_end": self._on_ternary_end,
        }

    def _on_array_value(self, tree: Node | None) -> None:
        if tree is not None and isinstance(self._cursor, ArrayLiteral):
            self._cursor.value.append(tree)

    def _on_object_value(self, tree: Node | None) -> None:
        if tree is not None and isinstance(self._cursor, ObjectLiteral):
            self._cursor.value[self._object_key] = tree

    def _on_sub_expression(self, tree: Node | None) -> None:
        if tree is None:
            raise ExpressionError(f"empty group in expression: {self._expression}")
        self._place_at_cursor(tree)

    def _on_filter(self, tree: Node | None) -> None:
        sub_parser = self._sub_parser
        self._place_before_cursor(
            FilterExpression(
                subject=self._cursor,
                expr=tree,
                relative=sub_parser is not None and sub_parser.is_relative(),
            )
        )

    def _on_ternary_mid(self, tree: Node | None) -> None:
        if isinstance(self._cursor, ConditionalExpression):  # pragma: no branch
            self._cursor.consequent = tree

    def _on_ternary_end(self, tree: Node | None) -> None:
        if tree is None:
            # `a ? b :` has nothing to fall back to. The consequent may be
            # elided -- `a ?: b` yields `a` when it holds -- but the alternate
            # may not.
            raise ExpressionError(f"ternary has no alternative: {self._expression}")
        if isinstance(self._cursor, ConditionalExpression):  # pragma: no branch
            self._cursor.alternate = tree


def parse(expression: str) -> Node | None:
    """Read ``expression`` into a tree, or ``None`` if it is empty.

    Raises :class:`~pybac.errors.ExpressionError` on anything unreadable.
    """
    parser = Parser()
    for token in tokenize(expression):
        parser.add_token(token)
    return parser.complete()
