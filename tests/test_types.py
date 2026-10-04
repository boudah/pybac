from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from pybac._types import (
    as_list,
    is_boolean,
    is_mapping,
    is_number,
    is_sequence,
    is_string,
    parse_date,
)


@pytest.mark.parametrize("value", [0, 1, -1, 2.5, float("inf")])
def test_is_number_accepts_real_numbers(value: Any) -> None:
    assert is_number(value)


@pytest.mark.parametrize("value", [True, False, "1", None, [1], {"a": 1}])
def test_is_number_rejects_everything_else(value: Any) -> None:
    assert not is_number(value)


def test_is_number_rejects_bool_despite_int_subclassing() -> None:
    """Without this, ``True`` would satisfy a numeric condition and equal 1."""
    assert isinstance(True, int)
    assert not is_number(True)


@pytest.mark.parametrize(
    ("predicate", "accepted", "rejected"),
    [
        (is_string, "abc", 1),
        (is_boolean, True, 1),
        (is_sequence, [1], "abc"),
        (is_mapping, {"a": 1}, [("a", 1)]),
    ],
)
def test_predicates(predicate: Any, accepted: Any, rejected: Any) -> None:
    assert predicate(accepted)
    assert not predicate(rejected)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ([1, 2], [1, 2]),
        ((1, 2), [1, 2]),
        ("G1", ["G1"]),
        (None, [None]),
        (1, [1]),
        ({"a": 1}, [{"a": 1}]),
    ],
)
def test_as_list_wraps_scalars_and_leaves_sequences(
    value: Any, expected: list[Any]
) -> None:
    assert as_list(value) == expected


def test_as_list_treats_a_string_as_one_value() -> None:
    assert as_list("G1") == ["G1"]


def test_as_list_returns_the_same_list_object() -> None:
    original = [1, 2]
    assert as_list(original) is original


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2024-01-02T03:04:05Z", datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)),
        ("2024-01-02T03:04:05z", datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)),
        ("2024-01-02T03:04:05+00:00", datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)),
        ("2024-01-02T01:04:05-02:00", datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)),
        ("  2024-01-02T03:04:05Z  ", datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)),
        ("2024-01-02", datetime(2024, 1, 2, tzinfo=UTC)),
    ],
)
def test_parse_date_reads_iso_timestamps(value: str, expected: datetime) -> None:
    parsed = parse_date(value)
    assert parsed is not None
    assert parsed.astimezone(UTC) == expected


def test_parse_date_reads_a_naive_timestamp_as_utc() -> None:
    """Otherwise it would be incomparable with an offset-aware timestamp."""
    assert parse_date("2024-01-02T03:04:05") == datetime(
        2024, 1, 2, 3, 4, 5, tzinfo=UTC
    )


def test_parse_date_leaves_an_aware_datetime_alone() -> None:
    aware = datetime(2024, 1, 2, tzinfo=timezone(timedelta(hours=2)))
    assert parse_date(aware) is aware


def test_parse_date_accepts_a_datetime() -> None:
    naive = datetime(2024, 1, 2, 3, 4, 5)
    assert parse_date(naive) == datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)


@pytest.mark.parametrize(
    "value",
    ["", "   ", "not a date", "2024-13-01", "02/01/2024", None, True, [], {}, object()],
)
def test_parse_date_reports_anything_else_as_none(value: Any) -> None:
    """A date condition treats an unparseable operand as a non-match."""
    assert parse_date(value) is None
