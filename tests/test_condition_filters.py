from __future__ import annotations

from typing import Any

import pytest

from pybac.conditions import CONDITIONS, FILTERS
from pybac.domain import UNSATISFIABLE, LeafFilter


def build(name: str, values: list[Any], key: str = "field") -> list[dict[str, Any]]:
    return [f.model_dump(mode="json") for f in FILTERS[name](key, values)]


def one(name: str, values: list[Any], key: str = "field") -> dict[str, Any]:
    built = build(name, values, key)
    assert len(built) == 1
    return built[0]


def test_every_condition_can_also_be_compiled() -> None:
    """A condition that decides but cannot be queried would deny silently."""
    assert set(FILTERS) == set(CONDITIONS)


@pytest.mark.parametrize(
    ("name", "values", "comparator", "value"),
    [
        ("StringEquals", ["goal"], "EQ", "goal"),
        ("StringNotEquals", ["goal"], "NEQ", "goal"),
        ("StringLike", ["FOLDER*"], "MATCHES", "FOLDER*"),
        ("StringNotLike", ["FOLDER*"], "NOT_MATCHES", "FOLDER*"),
        ("StringEqualsIgnoreCase", ["GOAL"], "EQ", "goal"),
        ("StringNotEqualsIgnoreCase", ["GOAL"], "NEQ", "goal"),
        ("NumericEquals", [2], "EQ", 2),
        ("NumericNotEquals", [2], "NEQ", 2),
        ("NumericLessThan", [2], "LT", 2),
        ("NumericLessThanEquals", [2], "LTE", 2),
        ("NumericGreaterThan", [2], "GT", 2),
        ("NumericGreaterThanEquals", [2], "GTE", 2),
        ("DateEquals", ["2024-01-02"], "EQ", "2024-01-02"),
        ("DateNotEquals", ["2024-01-02"], "NEQ", "2024-01-02"),
        ("DateLessThan", ["2024-01-02"], "LT", "2024-01-02"),
        ("DateLessThanEquals", ["2024-01-02"], "LTE", "2024-01-02"),
        ("DateGreaterThan", ["2024-01-02"], "GT", "2024-01-02"),
        ("DateGreaterThanEquals", ["2024-01-02"], "GTE", "2024-01-02"),
        ("Bool", [True], "EQ", True),
        ("Null", [True], "EQ", None),
    ],
)
def test_a_condition_becomes_a_comparison(
    name: str, values: list[Any], comparator: str, value: Any
) -> None:
    assert one(name, values) == {
        "key": "field",
        "comparator": comparator,
        "value": value,
    }


@pytest.mark.parametrize(
    ("name", "comparator"),
    [
        ("ContainsAtLeastOne", "OVERLAPS"),
        ("ContainsNone", "NOT_OVERLAPS"),
        ("ContainsAll", "SUBSET_OF"),
        ("InValues", "IN"),
        ("NotInValues", "NOT_IN"),
    ],
)
def test_a_set_condition_keeps_every_value(name: str, comparator: str) -> None:
    assert one(name, ["G1", "G2"]) == {
        "key": "field",
        "comparator": comparator,
        "value": ["G1", "G2"],
    }


def test_a_scalar_comparison_takes_the_first_value() -> None:
    """A field holds one value, so the alternatives a verdict would accept go."""
    assert one("StringEquals", ["goal", "other"])["value"] == "goal"


def test_a_scalar_comparison_with_no_values_compares_against_nothing() -> None:
    assert one("StringEquals", [])["value"] is None


@pytest.mark.parametrize(
    ("name", "values"),
    [
        ("NumericEquals", ["two"]),
        ("NumericLessThan", [None]),
        ("StringLike", [2]),
        ("StringEqualsIgnoreCase", [2]),
    ],
)
def test_a_value_of_the_wrong_type_yields_no_comparison(
    name: str, values: list[Any]
) -> None:
    assert build(name, values) == []


def test_a_typed_condition_reads_the_value_not_the_list_around_it() -> None:
    """Guarding the list would reject everything, and no filter is no restriction."""
    assert one("NumericLessThan", [5])["value"] == 5
    assert one("StringLike", ["FOLDER*"])["value"] == "FOLDER*"


@pytest.mark.parametrize("name", ["IpAddress", "NotIpAddress"])
def test_a_condition_about_the_caller_lets_no_record_through(name: str) -> None:
    """It restricts, but says nothing a query could ask of a record."""
    assert FILTERS[name]("field", ["10.0.0.0/8"]) == [UNSATISFIABLE]


@pytest.mark.parametrize(
    ("name", "comparator"),
    [
        ("ForAnyValue:StringEquals", "OVERLAPS"),
        ("ForAnyValue:NumericEquals", "OVERLAPS"),
        ("ForAllValues:StringEquals", "SUBSET_OF"),
        ("ForAllValues:StringLike", "SUBSET_OF"),
    ],
)
def test_a_quantifier_asks_about_the_fields_contents(
    name: str, comparator: str
) -> None:
    assert one(name, ["G1", "G2"]) == {
        "key": "field",
        "comparator": comparator,
        "value": ["G1", "G2"],
    }


def test_if_exists_compiles_like_the_condition_it_qualifies() -> None:
    """A query either compares the field or does not; there is no third state."""
    assert one("StringEqualsIfExists", ["goal"]) == one("StringEquals", ["goal"])


def test_the_key_is_carried_through() -> None:
    assert one("StringEquals", ["goal"], key="document.folder")["key"] == (
        "document.folder"
    )


def test_unsatisfiable_is_a_filter_nothing_matches() -> None:
    assert isinstance(UNSATISFIABLE, LeafFilter)
    assert UNSATISFIABLE.model_dump(mode="json") == {
        "key": "id",
        "comparator": "EQ",
        "value": "__INVALID__",
    }
