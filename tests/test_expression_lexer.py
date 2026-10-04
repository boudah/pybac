from __future__ import annotations

from typing import Any

import pytest

from pybac.errors import ExpressionError
from pybac.expression import tokenize


def kinds(expression: str) -> list[tuple[str, Any]]:
    return [(token.type, token.value) for token in tokenize(expression)]


def test_an_empty_expression_has_no_tokens() -> None:
    assert tokenize("") == []
    assert tokenize("   ") == []


def test_a_name_and_its_path() -> None:
    assert kinds("target.document.folder") == [
        ("identifier", "target"),
        ("dot", "."),
        ("identifier", "document"),
        ("dot", "."),
        ("identifier", "folder"),
    ]


@pytest.mark.parametrize(
    ("expression", "value"),
    [
        ('"FOLDER2"', "FOLDER2"),
        ("'FOLDER2'", "FOLDER2"),
        ('""', ""),
        ("'it\\'s'", "it's"),
        ('"say \\"hi\\""', 'say "hi"'),
        ("'a\\\\b'", "a\\b"),
        ("'report.draft'", "report.draft"),
        ("'has spaces and == inside'", "has spaces and == inside"),
    ],
)
def test_string_literals(expression: str, value: str) -> None:
    assert kinds(expression) == [("literal", value)]


@pytest.mark.parametrize(
    ("expression", "value"),
    [("2", 2), ("0", 0), ("2.5", 2.5), ("-3", -3), ("-2.5", -2.5), ("10.25", 10.25)],
)
def test_number_literals(expression: str, value: int | float) -> None:
    assert kinds(expression) == [("literal", value)]


def test_a_number_must_lead_with_a_digit() -> None:
    """`.` is an operator first, so `.5` reads as a step into a member named 5."""
    assert kinds(".5") == [("dot", "."), ("literal", 5)]
    assert kinds("0.5") == [("literal", 0.5)]


def test_a_whole_number_stays_whole() -> None:
    """`2` is an int, not 2.0, so it renders and keys as a reader expects."""
    token = tokenize("2")[0]
    assert isinstance(token.value, int)
    assert not isinstance(token.value, bool)


@pytest.mark.parametrize(("expression", "value"), [("true", True), ("false", False)])
def test_boolean_literals(expression: str, value: bool) -> None:
    assert kinds(expression) == [("literal", value)]


@pytest.mark.parametrize(
    "operator",
    ["==", "!=", "<", "<=", ">", ">=", "&&", "||", "in", "+", "-", "*", "/", "%", "^"],
)
def test_binary_operators(operator: str) -> None:
    assert kinds(f"a {operator} b")[1] == ("binaryOp", operator)


@pytest.mark.parametrize("operator", ["containsAny", "containsAll", "containsNone"])
def test_word_operators(operator: str) -> None:
    assert kinds(f"a {operator} b")[1] == ("binaryOp", operator)


def test_a_word_operator_does_not_split_a_longer_name() -> None:
    assert kinds("containsAnyway.x")[0] == ("identifier", "containsAnyway")


def test_two_character_operators_are_not_read_as_one() -> None:
    assert kinds("a >= b")[1] == ("binaryOp", ">=")
    assert kinds("a <= b")[1] == ("binaryOp", "<=")
    assert kinds("a != b")[1] == ("binaryOp", "!=")


def test_negation() -> None:
    assert kinds("!a") == [("unaryOp", "!"), ("identifier", "a")]


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("a - 1", [("identifier", "a"), ("binaryOp", "-"), ("literal", 1)]),
        ("a - -1", [("identifier", "a"), ("binaryOp", "-"), ("literal", -1)]),
        ("-1", [("literal", -1)]),
        ("(-1)", [("openParen", "("), ("literal", -1), ("closeParen", ")")]),
        ("[-1]", [("openBracket", "["), ("literal", -1), ("closeBracket", "]")]),
    ],
)
def test_minus_is_subtraction_or_a_sign_by_position(
    expression: str, expected: list[tuple[str, Any]]
) -> None:
    assert kinds(expression) == expected


def test_punctuation() -> None:
    assert kinds("{a: [1], b: (2)}") == [
        ("openCurl", "{"),
        ("identifier", "a"),
        ("colon", ":"),
        ("openBracket", "["),
        ("literal", 1),
        ("closeBracket", "]"),
        ("comma", ","),
        ("identifier", "b"),
        ("colon", ":"),
        ("openParen", "("),
        ("literal", 2),
        ("closeParen", ")"),
        ("closeCurl", "}"),
    ]


def test_whitespace_is_kept_on_the_token_it_follows() -> None:
    """`raw` lets a syntax error quote the expression up to the failure."""
    tokens = tokenize("a  ==   b")
    assert [token.raw for token in tokens] == ["a  ", "==   ", "b"]
    assert "".join(token.raw for token in tokens) == "a  ==   b"


@pytest.mark.parametrize("expression", ["a @ b", "a | b", "#", "a ~ b"])
def test_text_that_is_not_a_token_is_refused(expression: str) -> None:
    with pytest.raises(ExpressionError, match="invalid token"):
        tokenize(expression)


def test_a_trailing_minus_is_left_for_the_parser() -> None:
    """The lexer names it; saying where the expression ends is not its job."""
    assert kinds("a -") == [("identifier", "a"), ("binaryOp", "-")]


def test_a_minus_ending_the_expression_is_still_a_token() -> None:
    """Nothing follows it to make it a sign, so the parser gets to complain."""
    assert kinds("a + -") == [
        ("identifier", "a"),
        ("binaryOp", "+"),
        ("binaryOp", "-"),
    ]
