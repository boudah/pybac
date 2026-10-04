from __future__ import annotations

from typing import Any

import pytest

from pybac.errors import ExpressionError
from pybac.expression import (
    ArrayLiteral,
    BinaryExpression,
    ConditionalExpression,
    FilterExpression,
    Identifier,
    Literal,
    Node,
    ObjectLiteral,
    UnaryExpression,
    parse,
)
from pybac.expression.nodes import describe

# Every distinct expression found in the stored policies.
REAL_POLICY_EXPRESSIONS = [
    'target.document.folder == "FOLDER2"',
    'target.document.folder in ["FOLDER2","FOLDER3"]',
    "target.resource.groups containsAny req.groups",
    'target.resource.groups containsAll ["G1", "G2"]',
    'target.resource.groups containsNone ["G3", "G4"]',
    '"G2" in target.resource.groups',
    "req.userId in target.resource.managers",
    "target.max <= 2 && target.min > 1",
    "target.max <= 2 || target.min > 1",
    "target.number < 2",
    "target.number >= 2",
    'review.existingValue.A1 != "test"',
    "review.existingValue.A1 == true",
    'target.data.status == "goal"',
    'user.externalId == "EXT1"',
    'target.id != "U1" && target.field == "test" || target.field2 == "test2"',
    "review.targetStatus == 'suggested'",
    "target.type == 'report.final'",
    "!(target.document.folder in ['FOLDER1', 'FOLDER2'])",
    (
        "target.policyTags.bu containsAny ['*'] || "
        "target.policyTags.bu containsAny user.policyTags.bu"
    ),
    (
        "target.policyTagKeys containsNone ['societe', 'roles'] || "
        "((target.policyTags.societe containsAny ['*'] || "
        "target.policyTags.societe containsAny user.tags.societe) && "
        "(target.policyTags.roles containsAny ['*'] || "
        "target.policyTags.roles containsAny user.roles))"
    ),
    (
        "target.type == 'report.draft' && "
        "(!target.entityObj.custom_fields || "
        "target.entityObj.custom_fields.Habilitation != 'true') && "
        "review.existingStatus in ['suggested', 'approved', 'canceled'] && "
        "review.targetStatus in ['suggested', 'approved', 'canceled']"
    ),
]


def name(*path: str) -> Identifier:
    """Build the chain `a.b.c` the way the parser nests it."""
    node = Identifier(value=path[0])
    for segment in path[1:]:
        node = Identifier(value=segment, source=node)
    return node


# --------------------------------------------------------------------------
# the shapes a policy is written in
# --------------------------------------------------------------------------


def test_an_empty_expression_has_no_tree() -> None:
    assert parse("") is None
    assert parse("   ") is None


def test_a_literal() -> None:
    assert parse('"FOLDER2"') == Literal(value="FOLDER2")


def test_a_name() -> None:
    assert parse("target") == Identifier(value="target")


def test_a_path_nests_outwards() -> None:
    assert parse("target.document.folder") == name("target", "document", "folder")


def test_a_comparison() -> None:
    assert parse('target.document.folder == "FOLDER2"') == BinaryExpression(
        operator="==",
        left=name("target", "document", "folder"),
        right=Literal(value="FOLDER2"),
    )


def test_membership_against_an_array() -> None:
    assert parse('x in ["A", "B"]') == BinaryExpression(
        operator="in",
        left=Identifier(value="x"),
        right=ArrayLiteral(value=[Literal(value="A"), Literal(value="B")]),
    )


def test_negation_wraps_what_follows() -> None:
    assert parse('!(x in ["A"])') == UnaryExpression(
        operator="!",
        right=BinaryExpression(
            operator="in",
            left=Identifier(value="x"),
            right=ArrayLiteral(value=[Literal(value="A")]),
        ),
    )


def test_an_object_literal() -> None:
    assert parse("{bu: user.tags.bu, n: 1}") == ObjectLiteral(
        value={"bu": name("user", "tags", "bu"), "n": Literal(value=1)}
    )


@pytest.mark.parametrize(
    ("expression", "expected"),
    [("[]", ArrayLiteral(value=[])), ("{}", ObjectLiteral(value={}))],
)
def test_empty_collections(expression: str, expected: Node) -> None:
    assert parse(expression) == expected


# --------------------------------------------------------------------------
# precedence
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("expression", "grouped"),
    [
        ("1 + 2 * 3", "1 + (2 * 3)"),
        ("1 * 2 + 3", "(1 * 2) + 3"),
        ("a == b && c == d", "(a == b) && (c == d)"),
        ("a && b || c", "(a && b) || c"),
        ("!a == b", "(!a) == b"),
        ("a + b == c", "(a + b) == c"),
        ("a containsAny b && c", "(a containsAny b) && c"),
    ],
)
def test_precedence_groups_as_the_parentheses_would(
    expression: str, grouped: str
) -> None:
    assert describe(parse(expression)) == describe(parse(grouped))


def test_and_does_not_bind_tighter_than_or() -> None:
    """They share a precedence and so associate left to right.

    Most languages give `&&` the tighter binding. This one does not, and the
    stored policies were written against that, so it must not be "corrected".
    """
    assert describe(parse("a || b && c")) == describe(parse("(a || b) && c"))
    assert describe(parse("a || b && c")) != describe(parse("a || (b && c)"))


def test_parentheses_override_precedence() -> None:
    assert parse("(a || b) && c") == BinaryExpression(
        operator="&&",
        left=BinaryExpression(
            operator="||", left=Identifier(value="a"), right=Identifier(value="b")
        ),
        right=Identifier(value="c"),
    )


def test_operators_of_equal_precedence_associate_leftwards() -> None:
    assert describe(parse("a - b - c")) == describe(parse("(a - b) - c"))


# --------------------------------------------------------------------------
# ternaries and filters
# --------------------------------------------------------------------------


def test_a_ternary() -> None:
    assert parse("a ? b : c") == ConditionalExpression(
        test=Identifier(value="a"),
        consequent=Identifier(value="b"),
        alternate=Identifier(value="c"),
    )


def test_a_ternary_may_omit_its_consequent() -> None:
    assert parse("a ?: b") == ConditionalExpression(
        test=Identifier(value="a"), consequent=None, alternate=Identifier(value="b")
    )


def test_a_subscript_is_not_relative() -> None:
    assert parse("items[1]") == FilterExpression(
        subject=Identifier(value="items"), expr=Literal(value=1), relative=False
    )


def test_a_filter_over_elements_is_relative() -> None:
    assert parse("items[.done]") == FilterExpression(
        subject=Identifier(value="items"),
        expr=Identifier(value="done", relative=True),
        relative=True,
    )


# --------------------------------------------------------------------------
# what a policy may not say
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "expression",
    [
        "a someOperator b",
        "target.user.id hasManager req.userId",
        "target.policyTags matchAllPolicyTags {bu: user.tags.bu}",
    ],
)
def test_a_word_the_grammar_does_not_know_is_refused(expression: str) -> None:
    """An operator has to be registered before it can be written.

    See docs/adding-operators.md.
    """
    with pytest.raises(ExpressionError, match="unexpected"):
        parse(expression)


@pytest.mark.parametrize("expression", ["value | upper", "someFunction(1)"])
def test_transforms_and_function_calls_are_refused(expression: str) -> None:
    """The language registers no transform and no function, so neither can run."""
    with pytest.raises(ExpressionError):
        parse(expression)


@pytest.mark.parametrize("expression", ["(a", "(a || b", "((a)"])
def test_an_unclosed_group_is_refused(expression: str) -> None:
    with pytest.raises(ExpressionError, match="unterminated"):
        parse(expression)


@pytest.mark.parametrize("expression", ["[1, 2", "{a: 1", "items[1", "a ? b"])
def test_an_unfinished_expression_is_refused(expression: str) -> None:
    with pytest.raises(ExpressionError):
        parse(expression)


@pytest.mark.parametrize("expression", ["a ==", "== a", "a b", "a..b", ")"])
def test_tokens_in_an_impossible_order_are_refused(expression: str) -> None:
    with pytest.raises(ExpressionError):
        parse(expression)


@pytest.mark.parametrize("expression", ["a ? :", "a ? b :", "a ?:"])
def test_a_ternary_without_an_alternative_is_refused(expression: str) -> None:
    with pytest.raises(ExpressionError, match="no alternative"):
        parse(expression)


def test_a_completed_parser_takes_no_more_tokens() -> None:
    from pybac.expression import Parser, tokenize

    parser = Parser()
    for token in tokenize("a"):
        parser.add_token(token)
    parser.complete()

    with pytest.raises(ExpressionError, match="already complete"):
        parser.add_token(tokenize("b")[0])


# --------------------------------------------------------------------------
# the corpus
# --------------------------------------------------------------------------


@pytest.mark.parametrize("expression", REAL_POLICY_EXPRESSIONS)
def test_every_expression_in_the_stored_policies_parses(expression: str) -> None:
    assert parse(expression) is not None


def test_parsing_is_deterministic() -> None:
    for expression in REAL_POLICY_EXPRESSIONS:
        assert parse(expression) == parse(expression)


# --------------------------------------------------------------------------
# shapes reached only through nesting
# --------------------------------------------------------------------------


def test_an_empty_group_is_refused() -> None:
    with pytest.raises(ExpressionError, match="empty group"):
        parse("()")


def test_a_ternary_ended_by_its_surroundings_still_needs_an_alternative() -> None:
    with pytest.raises(ExpressionError, match="no alternative"):
        parse("[a ? b : ]")


def test_a_ternary_inside_a_collection_ends_where_the_element_does() -> None:
    assert parse("[a ? b : c, d]") == ArrayLiteral(
        value=[
            ConditionalExpression(
                test=Identifier(value="a"),
                consequent=Identifier(value="b"),
                alternate=Identifier(value="c"),
            ),
            Identifier(value="d"),
        ]
    )


# --------------------------------------------------------------------------
# rendering a tree
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("expression", "rendered"),
    [
        ("1", {"Literal": 1}),
        ("a", {"Identifier": "a"}),
        ("a.b", {"Identifier": "b", "from": {"Identifier": "a"}}),
        ("!a", {"!": {"Identifier": "a"}}),
        ("a == 1", {"==": [{"Identifier": "a"}, {"Literal": 1}]}),
        ("[1, 2]", [{"Literal": 1}, {"Literal": 2}]),
        ("{k: 1}", {"k": {"Literal": 1}}),
        (
            "a ? b : c",
            {"?": [{"Identifier": "a"}, {"Identifier": "b"}, {"Identifier": "c"}]},
        ),
        (
            "a[1]",
            {"filter": [{"Identifier": "a"}, {"Literal": 1}], "relative": False},
        ),
        (
            "a[.b]",
            {
                "filter": [
                    {"Identifier": "a"},
                    {"Identifier": "b", "relative": True},
                ],
                "relative": True,
            },
        ),
    ],
)
def test_describe_renders_every_kind_of_node(expression: str, rendered: Any) -> None:
    assert describe(parse(expression)) == rendered


def test_describe_renders_an_absent_branch_as_nothing() -> None:
    assert describe(None) is None


def test_describe_refuses_something_that_is_not_a_node() -> None:
    with pytest.raises(TypeError, match="unknown node"):
        describe(Node())


def test_an_object_entry_with_no_value_is_dropped() -> None:
    assert parse("{a: }") == ObjectLiteral(value={})
