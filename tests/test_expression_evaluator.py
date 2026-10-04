from __future__ import annotations

from typing import Any

import pytest

from pybac.errors import ExpressionError
from pybac.expression import (
    BinaryExpression,
    Evaluator,
    Literal,
    UnaryExpression,
    evaluate,
)

CONTEXT: dict[str, Any] = {
    "req": {"userId": "USER", "instance": "T1", "groups": ["G1", "G2"]},
    "user": {"externalId": "EXT1", "tags": {"bu": ["BU1"]}},
    "target": {
        "id": "DOC2",
        "document": {"folder": "FOLDER2"},
        "resource": {"groups": ["G1"], "managers": ["USER"]},
        "policyTags": {"bu": ["BU1"], "societe": ["*"]},
        "policyTagKeys": ["bu", "societe"],
        "max": 2,
        "min": 2,
        "empty": [],
        "nothing": None,
        "items": [{"name": "first"}, {"name": "second"}],
    },
    "review": {"existingValue": {"A1": True}},
}


def check(expression: str) -> Any:
    return evaluate(expression, CONTEXT)


# --------------------------------------------------------------------------
# reading the context
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ('"FOLDER2"', "FOLDER2"),
        ("2", 2),
        ("2.5", 2.5),
        ("true", True),
        ("false", False),
        ("-3", -3),
    ],
)
def test_a_literal_is_itself(expression: str, expected: Any) -> None:
    assert check(expression) == expected


def test_a_path_reads_through_the_context() -> None:
    assert check("target.document.folder") == "FOLDER2"
    assert check("req.groups") == ["G1", "G2"]


@pytest.mark.parametrize(
    "expression",
    ["absent", "target.absent", "target.absent.deeper.still", "target.nothing.deeper"],
)
def test_reading_what_is_not_there_yields_nothing(expression: str) -> None:
    """A policy naming a field the resource lacks does not match, and does not raise."""
    assert check(expression) is None


def test_a_step_into_a_collection_reads_its_first_element() -> None:
    assert check("target.items.name") == "first"


def test_there_is_no_null_literal() -> None:
    """`null` is an unset name, so `x == null` happens to mean "x is absent"."""
    assert check("null") is None
    assert check("target.absent == null") is True
    assert check("target.id == null") is False


def test_an_expression_with_no_content_yields_nothing() -> None:
    assert check("") is None


# --------------------------------------------------------------------------
# operators
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ('target.document.folder == "FOLDER2"', True),
        ('target.document.folder != "FOLDER2"', False),
        ("target.max >= 2", True),
        ("target.max > 2", False),
        ("target.max <= 2", True),
        ("target.max < 2", False),
        ("review.existingValue.A1 == true", True),
    ],
)
def test_comparison(expression: str, expected: bool) -> None:
    assert check(expression) is expected


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ('target.document.folder in ["FOLDER2", "FOLDER3"]', True),
        ('target.document.folder in ["FOLDER3"]', False),
        ('"G1" in target.resource.groups', True),
        ("req.userId in target.resource.managers", True),
        ('"OLDER" in target.document.folder', True),
        ("target.max in target.resource.groups", False),
        ('"x" in target.max', False),
    ],
)
def test_membership(expression: str, expected: bool) -> None:
    assert check(expression) is expected


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("target.resource.groups containsAny req.groups", True),
        ('target.resource.groups containsAny ["G9"]', False),
        ('target.resource.groups containsAll ["G1"]', True),
        ('target.resource.groups containsAll ["G1", "G9"]', True),
        ('req.groups containsAll ["G1"]', False),
        ('target.resource.groups containsNone ["G9"]', True),
        ('target.resource.groups containsNone ["G1"]', False),
    ],
)
def test_collection_operators(expression: str, expected: bool) -> None:
    assert check(expression) is expected


def test_contains_all_asks_whether_the_left_is_contained_by_the_right() -> None:
    """The name reads backwards, and stored policies depend on which way it goes."""
    assert evaluate("a containsAll b", {"a": ["G1"], "b": ["G1", "G2"]}) is True
    assert evaluate("a containsAll b", {"a": ["G1", "G2"], "b": ["G1"]}) is False


def test_collection_operators_accept_a_bare_value_on_either_side() -> None:
    assert evaluate("a containsAny b", {"a": "G1", "b": ["G1", "G2"]}) is True
    assert evaluate("a containsAny b", {"a": ["G1"], "b": "G1"}) is True
    assert evaluate("a containsAll b", {"a": "G1", "b": "G1"}) is True


def test_nothing_is_contained_in_everything() -> None:
    assert check("target.empty containsAll req.groups") is True
    assert check("target.empty containsAny req.groups") is False


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("1 + 2", 3),
        ("5 - 2", 3),
        ("3 * 2", 6),
        ("7 / 2", 3.5),
        ("7 // 2", 3),
        ("2 ^ 3", 8),
    ],
)
def test_arithmetic(expression: str, expected: Any) -> None:
    assert check(expression) == expected


def test_caret_raises_to_a_power() -> None:
    """It is not a bitwise exclusive-or, whatever the symbol suggests."""
    assert check("2 ^ 10") == 1024


def test_negation() -> None:
    assert check('!(target.document.folder in ["FOLDER1"])') is True
    assert check("!target.absent") is True
    assert check("!target.id") is False


# --------------------------------------------------------------------------
# the lazy operators
# --------------------------------------------------------------------------


def test_and_or_combine_conditions() -> None:
    assert check("target.max <= 2 && target.min > 1") is True
    assert check("target.max <= 2 && target.min > 99") is False
    assert check("target.max <= 2 || target.min > 99") is True
    assert check("target.max > 99 || target.min > 99") is False


def test_and_skips_its_right_when_the_left_settles_it() -> None:
    """Otherwise a guard like `a && a.b` could not protect the read after it."""
    assert evaluate("a && a.b", {"a": None}) is None
    assert evaluate("a && a.b", {"a": {"b": "reached"}}) == "reached"


def test_or_skips_its_right_when_the_left_settles_it() -> None:
    assert evaluate("a || b", {"a": "first"}) == "first"
    assert evaluate("a || b", {"a": None, "b": "second"}) == "second"


def test_and_or_yield_the_operand_that_decided_them() -> None:
    assert evaluate("a && b", {"a": "x", "b": "y"}) == "y"
    assert evaluate("a || b", {"a": "x", "b": "y"}) == "x"


# --------------------------------------------------------------------------
# collections, branching, filtering
# --------------------------------------------------------------------------


def test_an_array_literal_evaluates_its_elements() -> None:
    assert check('["a", target.id, 1 + 1]') == ["a", "DOC2", 2]


def test_an_object_literal_evaluates_its_values() -> None:
    assert check("{bu: user.tags.bu, n: 1}") == {"bu": ["BU1"], "n": 1}


def test_a_ternary_picks_a_branch() -> None:
    assert check('target.id == "DOC2" ? "yes" : "no"') == "yes"
    assert check('target.id == "OTHER" ? "yes" : "no"') == "no"


def test_a_ternary_without_a_consequent_keeps_what_it_tested() -> None:
    assert evaluate("a ?: b", {"a": "first", "b": "second"}) == "first"
    assert evaluate("a ?: b", {"a": None, "b": "second"}) == "second"


def test_a_filter_keeps_the_elements_that_match() -> None:
    assert check('target.items[.name == "second"]') == [{"name": "second"}]
    assert check('target.items[.name == "missing"]') == []


def test_a_subscript_reads_one_element() -> None:
    assert check("target.items[1]") == {"name": "second"}
    assert check("target.items[9]") is None
    assert check("req.groups[0]") == "G1"


# --------------------------------------------------------------------------
# comparison follows Python, not the loose rules of a scripting language
# --------------------------------------------------------------------------


def test_equality_does_not_coerce_across_types() -> None:
    assert evaluate("a == b", {"a": "1", "b": 1}) is False
    assert evaluate("a == b", {"a": 0, "b": False}) is True


def test_collections_compare_by_value() -> None:
    assert evaluate("a == b", {"a": {"x": 1}, "b": {"x": 1}}) is True
    assert evaluate("a == b", {"a": [1, 2], "b": [1, 2]}) is True


def test_an_empty_collection_does_not_hold() -> None:
    assert evaluate("a ? 'yes' : 'no'", {"a": []}) == "no"
    assert evaluate("a ? 'yes' : 'no'", {"a": {}}) == "no"
    assert evaluate("a ? 'yes' : 'no'", {"a": [1]}) == "yes"


def test_containing_all_ignores_repetition() -> None:
    assert evaluate("a containsAll b", {"a": ["G1", "G1"], "b": ["G1"]}) is True


def test_ordering_values_of_unrelated_types_raises() -> None:
    """The caller reads the failure as a non-match, so the policy denies."""
    with pytest.raises(TypeError):
        evaluate("target.absent < 2", CONTEXT)
    with pytest.raises(TypeError):
        evaluate("a < b", {"a": "text", "b": 2})


# --------------------------------------------------------------------------
# reuse and errors
# --------------------------------------------------------------------------


def test_one_evaluator_serves_many_expressions() -> None:
    from pybac.expression import parse

    evaluator = Evaluator(CONTEXT)
    assert evaluator.evaluate(parse("target.id")) == "DOC2"
    assert evaluator.evaluate(parse("req.userId")) == "USER"


@pytest.mark.parametrize(
    "node",
    [
        BinaryExpression(
            operator="startsWith", left=Literal(value="a"), right=Literal(value="b")
        ),
        UnaryExpression(operator="~", right=Literal(value="a")),
    ],
)
def test_an_operator_with_no_implementation_is_refused(node: Any) -> None:
    """The grammar settles how an operator parses; evaluating needs a meaning too."""
    with pytest.raises(ExpressionError, match="no meaning"):
        Evaluator(CONTEXT).evaluate(node)


# --------------------------------------------------------------------------
# subscripts and filters over odd subjects
# --------------------------------------------------------------------------


def test_a_boolean_subscript_keeps_or_drops_the_subject() -> None:
    assert evaluate("a[true]", {"a": [1, 2]}) == [1, 2]
    assert evaluate("a[false]", {"a": [1, 2]}) is None


def test_a_filter_over_a_single_value_treats_it_as_one_element() -> None:
    assert evaluate("a[.n == 1]", {"a": {"n": 1}}) == [{"n": 1}]
    assert evaluate("a[.n == 2]", {"a": {"n": 1}}) == []


def test_a_filter_over_nothing_yields_nothing() -> None:
    assert evaluate("a[.n == 1]", {"a": None}) == []


def test_a_subscript_can_name_a_key() -> None:
    assert evaluate('a["k"]', {"a": {"k": "v"}}) == "v"


def test_a_subscript_into_something_indexable_by_neither() -> None:
    assert evaluate("a[0]", {"a": 5}) is None
    assert evaluate('a["k"]', {"a": [1, 2]}) is None
