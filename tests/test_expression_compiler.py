from __future__ import annotations

from typing import Any

import pytest

from pybac.domain import CombinatorFilter, LeafFilter, QueryFilterComparator, negate
from pybac.errors import ExpressionError
from pybac.expression import parse
from pybac.expression.compiler import FilterCompiler, Outcome, compile_to_filter

CONTEXT: dict[str, Any] = {
    "req": {"userId": "USER", "instance": "T1", "groups": ["G1", "G2"]},
    "user": {"tags": {"bu": ["BU1"]}},
}


def compile_as_data(expression: str) -> Any:
    compiled = compile_to_filter(parse(expression), CONTEXT)
    if isinstance(compiled, Outcome):
        return compiled
    return compiled.model_dump(mode="json")


def leaf(key: str, comparator: str, value: Any) -> dict[str, Any]:
    return {"key": key, "comparator": comparator, "value": value}


# --------------------------------------------------------------------------
# a name becomes a field or a value, depending which side it is on
# --------------------------------------------------------------------------


def test_a_target_name_becomes_a_field() -> None:
    assert compile_as_data('target.document.folder == "FOLDER2"') == leaf(
        "document.folder", "EQ", "FOLDER2"
    )


def test_every_other_name_is_read_now() -> None:
    """`req` and `user` are known, so they become the value compared against."""
    assert compile_as_data("target.groups containsAny req.groups") == leaf(
        "groups", "OVERLAPS", ["G1", "G2"]
    )
    assert compile_as_data("target.owner == req.userId") == leaf("owner", "EQ", "USER")


def test_the_record_itself_is_not_a_field() -> None:
    with pytest.raises(ExpressionError, match="not a field"):
        compile_as_data('target == "x"')


# --------------------------------------------------------------------------
# comparisons
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ('target.a == "x"', leaf("a", "EQ", "x")),
        ('target.a != "x"', leaf("a", "NEQ", "x")),
        ("target.a < 2", leaf("a", "LT", 2)),
        ("target.a <= 2", leaf("a", "LTE", 2)),
        ("target.a > 2", leaf("a", "GT", 2)),
        ("target.a >= 2", leaf("a", "GTE", 2)),
        ('target.a in ["x", "y"]', leaf("a", "IN", ["x", "y"])),
        ('target.a containsAny ["x"]', leaf("a", "OVERLAPS", ["x"])),
        ('target.a containsNone ["x"]', leaf("a", "NOT_OVERLAPS", ["x"])),
        ('target.a containsAll ["x"]', leaf("a", "SUBSET_OF", ["x"])),
    ],
)
def test_comparisons_become_filters(expression: str, expected: Any) -> None:
    assert compile_as_data(expression) == expected


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ('"x" == target.a', leaf("a", "EQ", "x")),
        ("2 < target.a", leaf("a", "GT", 2)),
        ("2 <= target.a", leaf("a", "GTE", 2)),
        ("2 > target.a", leaf("a", "LT", 2)),
        ("2 >= target.a", leaf("a", "LTE", 2)),
        ('"G1" in target.groups', leaf("groups", "OVERLAPS", ["G1"])),
        (
            "req.groups containsAny target.groups",
            leaf("groups", "OVERLAPS", ["G1", "G2"]),
        ),
    ],
)
def test_a_field_on_the_right_is_read_the_other_way_round(
    expression: str, expected: Any
) -> None:
    assert compile_as_data(expression) == expected


def test_contains_all_needs_the_field_on_the_left() -> None:
    """Unlike the others it is not symmetric, so there is nothing to mirror."""
    with pytest.raises(ExpressionError, match="field on the left"):
        compile_as_data("req.groups containsAll target.groups")


def test_two_fields_cannot_be_compared_with_each_other() -> None:
    with pytest.raises(ExpressionError, match="two fields"):
        compile_as_data("target.a == target.b")


def test_a_bare_field_asks_whether_it_holds() -> None:
    assert compile_as_data("target.active") == leaf("active", "EQ", True)


def test_a_scalar_becomes_a_list_where_the_comparator_wants_one() -> None:
    assert compile_as_data('target.groups containsAny "G1"') == leaf(
        "groups", "OVERLAPS", ["G1"]
    )


# --------------------------------------------------------------------------
# joining
# --------------------------------------------------------------------------


def test_and_joins_two_filters() -> None:
    assert compile_as_data("target.a == 1 && target.b == 2") == {
        "comparator": "AND",
        "value": [leaf("a", "EQ", 1), leaf("b", "EQ", 2)],
    }


def test_or_joins_two_filters() -> None:
    assert compile_as_data("target.a == 1 || target.b == 2") == {
        "comparator": "OR",
        "value": [leaf("a", "EQ", 1), leaf("b", "EQ", 2)],
    }


def test_joins_nest() -> None:
    assert compile_as_data("target.a == 1 && (target.b == 2 || target.c == 3)") == {
        "comparator": "AND",
        "value": [
            leaf("a", "EQ", 1),
            {"comparator": "OR", "value": [leaf("b", "EQ", 2), leaf("c", "EQ", 3)]},
        ],
    }


# --------------------------------------------------------------------------
# parts that mention no field at all
# --------------------------------------------------------------------------


def test_a_comparison_of_known_values_is_settled_now() -> None:
    assert compile_as_data('req.instance == "T1"') is Outcome.ALWAYS
    assert compile_as_data('req.instance == "OTHER"') is Outcome.NEVER


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ('req.instance == "T1" && target.a == 1', leaf("a", "EQ", 1)),
        ('req.instance == "OTHER" && target.a == 1', Outcome.NEVER),
        ('req.instance == "T1" || target.a == 1', Outcome.ALWAYS),
        ('req.instance == "OTHER" || target.a == 1', leaf("a", "EQ", 1)),
        ('req.instance == "T1" && req.userId == "USER"', Outcome.ALWAYS),
        ('req.instance == "OTHER" || req.userId == "NOBODY"', Outcome.NEVER),
    ],
)
def test_a_settled_part_folds_into_what_surrounds_it(
    expression: str, expected: Any
) -> None:
    """A fact true of every record restricts nothing; a false one restricts all."""
    assert compile_as_data(expression) == expected


# --------------------------------------------------------------------------
# negation
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("!(target.a == 1)", leaf("a", "NEQ", 1)),
        ("!(target.a != 1)", leaf("a", "EQ", 1)),
        ("!(target.a < 1)", leaf("a", "GTE", 1)),
        ("!(target.a >= 1)", leaf("a", "LT", 1)),
        ('!(target.a in ["x"])', leaf("a", "NOT_IN", ["x"])),
        ('!(target.a containsAny ["x"])', leaf("a", "NOT_OVERLAPS", ["x"])),
    ],
)
def test_negation_flips_the_comparison(expression: str, expected: Any) -> None:
    assert compile_as_data(expression) == expected


def test_negation_pushes_through_a_join() -> None:
    """`not (a and b)` is `not a or not b`, which keeps the filter flat."""
    assert compile_as_data("!(target.a == 1 && target.b == 2)") == {
        "comparator": "OR",
        "value": [leaf("a", "NEQ", 1), leaf("b", "NEQ", 2)],
    }


def test_negation_flips_a_settled_part() -> None:
    assert compile_as_data('!(req.instance == "T1")') is Outcome.NEVER
    assert compile_as_data('!(req.instance == "OTHER")') is Outcome.ALWAYS


@pytest.mark.parametrize(
    ("comparator", "opposite"),
    [
        (QueryFilterComparator.EQ, QueryFilterComparator.NEQ),
        (QueryFilterComparator.MATCHES, QueryFilterComparator.NOT_MATCHES),
        (QueryFilterComparator.LT, QueryFilterComparator.GTE),
        (QueryFilterComparator.GT, QueryFilterComparator.LTE),
        (QueryFilterComparator.IN, QueryFilterComparator.NOT_IN),
        (
            QueryFilterComparator.OVERLAPS,
            QueryFilterComparator.NOT_OVERLAPS,
        ),
        (QueryFilterComparator.IN, QueryFilterComparator.NOT_IN),
    ],
)
def test_negate_pairs_comparators(
    comparator: QueryFilterComparator, opposite: QueryFilterComparator
) -> None:
    assert negate(comparator) is opposite
    assert negate(opposite) is comparator


def test_negate_falls_back_to_inequality() -> None:
    """`SUBSET_OF` has no opposite in the vocabulary: "not a subset" is not one
    of the things a filter can say."""
    assert negate(QueryFilterComparator.SUBSET_OF) is QueryFilterComparator.NEQ


# --------------------------------------------------------------------------
# what cannot be compiled
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "expression",
    [
        'target.a == 1 ? "yes" : "no"',
        "target.items[.done]",
        "target.items[0]",
    ],
)
def test_a_shape_that_describes_a_value_cannot_be_compiled(expression: str) -> None:
    with pytest.raises(ExpressionError, match="cannot compile"):
        compile_as_data(expression)


def test_arithmetic_on_a_field_cannot_be_compiled() -> None:
    with pytest.raises(ExpressionError, match="cannot be applied to a field"):
        compile_as_data("target.a + 1 == 2")


def test_arithmetic_on_known_values_is_worked_out() -> None:
    assert compile_as_data("target.a == 1 + 1") == leaf("a", "EQ", 2)


def test_an_operator_with_no_compilation_is_refused() -> None:
    from pybac.expression.nodes import BinaryExpression, Literal, UnaryExpression

    compiler = FilterCompiler(CONTEXT)
    with pytest.raises(ExpressionError, match="cannot be compiled"):
        compiler.compile(
            BinaryExpression(
                operator="startsWith", left=Literal(value="a"), right=Literal(value="b")
            )
        )
    with pytest.raises(ExpressionError, match="cannot be compiled"):
        compiler.compile(UnaryExpression(operator="~", right=Literal(value="a")))


def test_an_empty_expression_restricts_nothing() -> None:
    assert FilterCompiler(CONTEXT).compile(None) is Outcome.NEVER


def test_a_compiler_is_reusable() -> None:
    compiler = FilterCompiler(CONTEXT)
    first = compiler.compile(parse("target.a == 1"))
    second = compiler.compile(parse("target.b == 2"))
    assert isinstance(first, LeafFilter)
    assert isinstance(second, LeafFilter)
    assert first.key == "a"
    assert second.key == "b"


def test_a_literal_collection_is_compiled_element_by_element() -> None:
    assert compile_as_data("target.a in [1 + 1, req.userId]") == leaf(
        "a", "IN", [2, "USER"]
    )


def test_an_object_literal_is_compiled_value_by_value() -> None:
    assert compile_as_data("target.a == {n: 1 + 1}") == leaf("a", "EQ", {"n": 2})


def test_a_filter_tree_keeps_its_nested_type() -> None:
    compiled = compile_to_filter(parse("target.a == 1 && target.b == 2"), CONTEXT)
    assert isinstance(compiled, CombinatorFilter)
    assert all(isinstance(part, LeafFilter) for part in compiled.value)


# --------------------------------------------------------------------------
# names that are not plain chains
# --------------------------------------------------------------------------


def test_a_name_reached_through_a_subscript_is_read_as_a_value() -> None:
    """It is no longer a field a query can name, so it must be known now."""
    context = {"req": {"items": [{"name": "first"}]}}
    compiled = compile_to_filter(parse("target.a == req.items[0].name"), context)
    assert isinstance(compiled, LeafFilter)
    assert compiled.value == "first"


def test_a_target_name_reached_through_a_subscript_stops_being_a_field() -> None:
    """The chain is broken, so it is read now -- as nothing, here -- and the
    field on the other side carries the comparison."""
    assert compile_as_data("target.items[0].name == target.b") == leaf("b", "EQ", None)


def test_membership_cannot_hold_two_fields() -> None:
    with pytest.raises(ExpressionError, match="two fields"):
        compile_as_data("target.a in target.b")
