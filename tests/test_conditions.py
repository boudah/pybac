from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pybac.conditions import CONDITIONS

# The conditions that appear in stored policies. If one of these stops working,
# a real policy stops working with it.
IN_USE = [
    "StringEquals",
    "StringNotEquals",
    "StringLike",
    "ForAnyValue:StringEquals",
    "ForAnyValue:StringLike",
    "ContainsAtLeastOne",
    "ContainsAll",
    "ContainsNone",
    "Bool",
]


def holds(name: str, actual: Any, expected: Any) -> bool:
    return CONDITIONS[name](actual, expected)


@pytest.mark.parametrize("name", IN_USE)
def test_the_conditions_policies_actually_use_are_registered(name: str) -> None:
    assert name in CONDITIONS


def test_every_condition_gains_three_variants() -> None:
    assert len(CONDITIONS) % 4 == 0
    for name in IN_USE:
        base = name.split(":")[-1]
        assert {
            f"{base}IfExists",
            f"ForAnyValue:{base}",
            f"ForAllValues:{base}",
        } <= set(CONDITIONS)


# --------------------------------------------------------------------------
# strings
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "actual", "expected", "result"),
    [
        ("StringEquals", "goal", "goal", True),
        ("StringEquals", "goal", "other", False),
        ("StringNotEquals", "goal", "other", True),
        ("StringNotEquals", "goal", "goal", False),
        ("StringEqualsIgnoreCase", "GOAL", "goal", True),
        ("StringNotEqualsIgnoreCase", "GOAL", "goal", False),
        ("StringLike", "docs:folder:read", "docs:folder:*", True),
        ("StringLike", "docs:item:read", "docs:folder:*", False),
        ("StringNotLike", "docs:item:read", "docs:folder:*", True),
    ],
)
def test_string_conditions(name: str, actual: Any, expected: Any, result: bool) -> None:
    assert holds(name, actual, expected) is result


# --------------------------------------------------------------------------
# numbers, dates, booleans, absence
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "actual", "expected", "result"),
    [
        ("NumericEquals", 2, 2, True),
        ("NumericNotEquals", 2, 3, True),
        ("NumericLessThan", 1, 2, True),
        ("NumericLessThanEquals", 2, 2, True),
        ("NumericGreaterThan", 3, 2, True),
        ("NumericGreaterThanEquals", 2, 2, True),
        ("NumericLessThan", 2, 1, False),
    ],
)
def test_numeric_conditions(
    name: str, actual: Any, expected: Any, result: bool
) -> None:
    assert holds(name, actual, expected) is result


@pytest.mark.parametrize(
    "name", ["NumericEquals", "NumericNotEquals", "NumericLessThan"]
)
def test_a_boolean_is_not_a_number(name: str) -> None:
    """`True` would otherwise compare equal to 1 and satisfy a numeric policy."""
    assert holds(name, True, 1) is False


@pytest.mark.parametrize(
    ("name", "actual", "expected", "result"),
    [
        ("DateEquals", "2024-01-02T00:00:00Z", "2024-01-02T00:00:00Z", True),
        ("DateEquals", "2024-01-02T00:00:00Z", "2024-01-02T02:00:00+02:00", True),
        ("DateNotEquals", "2024-01-02", "2024-01-03", True),
        ("DateLessThan", "2024-01-02", "2024-01-03", True),
        ("DateGreaterThan", "2024-01-03", "2024-01-02", True),
        ("DateLessThanEquals", "2024-01-02", "2024-01-02", True),
        ("DateGreaterThanEquals", "2024-01-02", "2024-01-02", True),
    ],
)
def test_date_conditions(name: str, actual: Any, expected: Any, result: bool) -> None:
    assert holds(name, actual, expected) is result


@pytest.mark.parametrize(
    ("actual", "expected", "result"),
    [
        (True, True, True),
        (True, "true", True),
        ("true", True, True),
        ("false", "false", True),
        (True, False, False),
        (1, True, False),
        ("yes", True, False),
    ],
)
def test_bool_reads_a_boolean_written_either_way(
    actual: Any, expected: Any, result: bool
) -> None:
    assert holds("Bool", actual, expected) is result


@pytest.mark.parametrize(
    ("actual", "expected", "result"),
    [(None, True, True), ("x", True, False), ("x", False, True), (None, False, False)],
)
def test_null_asks_whether_the_context_has_a_value(
    actual: Any, expected: Any, result: bool
) -> None:
    assert holds("Null", actual, expected) is result


def test_null_needs_a_boolean_to_compare_against() -> None:
    assert holds("Null", None, "true") is False


# --------------------------------------------------------------------------
# sets and addresses
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "actual", "expected", "result"),
    [
        ("ContainsAtLeastOne", ["G1"], ["G1", "G2"], True),
        ("ContainsAtLeastOne", ["G9"], ["G1", "G2"], False),
        ("ContainsAll", ["G1"], ["G1", "G2"], True),
        ("ContainsAll", ["G1", "G9"], ["G1"], False),
        ("ContainsNone", ["G9"], ["G1"], True),
        ("ContainsNone", ["G1"], ["G1"], False),
        ("InValues", "G1", ["G1", "G2"], True),
        ("InValues", "G9", ["G1"], False),
        ("NotInValues", "G9", ["G1"], True),
    ],
)
def test_set_conditions(name: str, actual: Any, expected: Any, result: bool) -> None:
    assert holds(name, actual, expected) is result


def test_set_conditions_accept_a_bare_value() -> None:
    assert holds("ContainsAtLeastOne", "G1", ["G1", "G2"]) is True
    assert holds("InValues", "G1", "G1") is True


@pytest.mark.parametrize(
    ("name", "actual", "expected", "result"),
    [
        ("IpAddress", "192.168.0.7", "192.168.0.0/24", True),
        ("IpAddress", "10.0.0.1", "192.168.0.0/24", False),
        ("IpAddress", "192.168.0.7", "192.168.0.7", True),
        ("NotIpAddress", "10.0.0.1", "192.168.0.0/24", True),
        ("NotIpAddress", "192.168.0.7", "192.168.0.0/24", False),
        ("IpAddress", "::1", "::1/128", True),
        ("IpAddress", "192.168.0.7", "::1/128", False),
    ],
)
def test_address_conditions(
    name: str, actual: Any, expected: Any, result: bool
) -> None:
    assert holds(name, actual, expected) is result


# --------------------------------------------------------------------------
# what a mismatch means
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("positive", "negative", "actual", "expected"),
    [
        ("StringEquals", "StringNotEquals", 1, "1"),
        ("StringLike", "StringNotLike", 1, "*"),
        ("NumericEquals", "NumericNotEquals", "2", 2),
        ("DateEquals", "DateNotEquals", "not a date", "2024-01-02"),
        ("IpAddress", "NotIpAddress", "not an address", "192.168.0.0/24"),
    ],
)
def test_neither_direction_holds_when_the_types_disagree(
    positive: str, negative: str, actual: Any, expected: Any
) -> None:
    """Neither condition claims to have compared anything, so neither matches."""
    assert holds(positive, actual, expected) is False
    assert holds(negative, actual, expected) is False


def test_a_missing_context_value_matches_nothing() -> None:
    assert holds("StringEquals", None, "goal") is False
    assert holds("StringNotEquals", None, "goal") is False
    assert holds("NumericLessThan", None, 2) is False


# --------------------------------------------------------------------------
# the derived variants
# --------------------------------------------------------------------------


def test_if_exists_holds_when_the_context_has_no_value() -> None:
    assert holds("StringEqualsIfExists", None, "goal") is True
    assert holds("StringEqualsIfExists", "goal", "goal") is True
    assert holds("StringEqualsIfExists", "other", "goal") is False


@pytest.mark.parametrize(
    ("actual", "expected", "result"),
    [
        (["G1", "G9"], ["G1", "G2"], True),
        (["G8", "G9"], ["G1", "G2"], False),
        ("G1", ["G1", "G2"], True),
        ([], ["G1"], False),
    ],
)
def test_for_any_value_wants_one_match(
    actual: Any, expected: Any, result: bool
) -> None:
    assert holds("ForAnyValue:StringEquals", actual, expected) is result


@pytest.mark.parametrize(
    ("actual", "expected", "result"),
    [
        (["G1", "G2"], ["G1", "G2"], True),
        (["G1", "G9"], ["G1", "G2"], False),
        ("G1", ["G1"], True),
        ([], ["G1"], True),
    ],
)
def test_for_all_values_wants_every_match(
    actual: Any, expected: Any, result: bool
) -> None:
    """Nothing to check means nothing failed."""
    assert holds("ForAllValues:StringEquals", actual, expected) is result


def test_the_variants_carry_the_pattern_matching_of_their_base() -> None:
    assert holds("ForAnyValue:StringLike", ["docs:folder:read"], ["docs:*"]) is True
    assert holds("ForAnyValue:StringLike", ["docs:folder:read"], ["iam:*"]) is False


def test_each_derived_variant_is_its_own_condition() -> None:
    """Built in a loop, so a shared closure would make them all the last one."""
    assert holds("ForAnyValue:NumericEquals", [2], [2]) is True
    assert holds("ForAnyValue:StringEquals", ["2"], ["2"]) is True
    assert holds("ForAnyValue:NumericEquals", ["2"], ["2"]) is False


@pytest.mark.parametrize("value", [1, "yes", None, [], {}])
def test_bool_refuses_anything_that_is_not_a_boolean(value: Any) -> None:
    assert holds("Bool", value, True) is False
    assert holds("Bool", True, value) is False


@pytest.mark.parametrize(
    ("actual", "expected"),
    [(123, "10.0.0.0/8"), ("10.0.0.1", 24), (None, "10.0.0.0/8")],
)
def test_an_address_condition_needs_two_strings(actual: Any, expected: Any) -> None:
    assert holds("IpAddress", actual, expected) is False
    assert holds("NotIpAddress", actual, expected) is False


def test_every_condition_is_documented() -> None:
    """A condition nobody can find is a condition nobody will use."""
    reference = (Path(__file__).parent.parent / "docs" / "conditions.md").read_text()
    base = {
        name for name in CONDITIONS if ":" not in name and not name.endswith("IfExists")
    }
    assert sorted(name for name in base if name not in reference) == []
