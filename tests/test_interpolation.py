from __future__ import annotations

from typing import Any

import pytest

from pybac.interpolation import fill_condition_values, fill_text, resolve_path

CONTEXT: dict[str, Any] = {
    "req": {"userId": "USER", "groups": ["G1", "G2"], "instance": "T1"},
    "user": {"tags": {"bu": ["BU1", "BU2"], "level": 3}},
    "target": {"id": "DOC2", "count": 3, "flag": True, "nothing": None},
}


# --------------------------------------------------------------------------
# reading a path
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("req:userId", "USER"),
        ("req:groups", ["G1", "G2"]),
        ("user:tags:bu", ["BU1", "BU2"]),
        ("target:count", 3),
        ("target:nothing", None),
    ],
)
def test_a_path_reads_the_context(path: str, expected: Any) -> None:
    assert resolve_path(path, CONTEXT) == expected


def test_a_path_that_leads_nowhere_becomes_its_own_text() -> None:
    """So a condition on it compares against a literal and matches nothing."""
    assert resolve_path("req:absent", CONTEXT) == "req:absent"
    assert resolve_path("status", CONTEXT) == "status"


def test_a_stored_none_is_not_a_missing_path() -> None:
    assert resolve_path("target:nothing", CONTEXT) is None


# --------------------------------------------------------------------------
# filling a resource
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("written", "expected"),
    [
        ("ern:svc:document:${req:userId}/*", "ern:svc:document:USER/*"),
        ("${req:userId}", "USER"),
        ("${req:instance}:${req:userId}", "T1:USER"),
        ("no placeholder", "no placeholder"),
        ("${req:absent}", "req:absent"),
        ("count-${target:count}", "count-3"),
        ("flag-${target:flag}", "flag-true"),
    ],
)
def test_filling_a_resource_yields_one_string(written: str, expected: str) -> None:
    assert fill_text(written, CONTEXT) == expected


def test_a_list_in_a_resource_is_joined() -> None:
    """A resource is one pattern, so there is nowhere to put several values."""
    assert fill_text("x-${req:groups}", CONTEXT) == "x-G1,G2"


# --------------------------------------------------------------------------
# filling a condition
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("written", "expected"),
    [
        ("${req:userId}", ["USER"]),
        ("${req:groups}", ["G1", "G2"]),
        ("${user:tags:bu}", ["BU1", "BU2"]),
        ("plain", ["plain"]),
        ("${req:absent}", ["req:absent"]),
    ],
)
def test_a_placeholder_standing_alone_becomes_its_values(
    written: str, expected: list[Any]
) -> None:
    assert fill_condition_values(written, CONTEXT) == expected


def test_a_placeholder_standing_alone_keeps_its_type() -> None:
    """A condition comparing numbers needs a number, not the text of one."""
    assert fill_condition_values("${target:count}", CONTEXT) == [3]
    assert fill_condition_values("${target:flag}", CONTEXT) == [True]


def test_a_placeholder_in_text_yields_one_value_per_element() -> None:
    assert fill_condition_values("*${req:groups}*", CONTEXT) == ["*G1*", "*G2*"]


def test_surrounding_text_is_kept() -> None:
    assert fill_condition_values("prefix-${req:userId}", CONTEXT) == ["prefix-USER"]
    assert fill_condition_values("${req:userId}-suffix", CONTEXT) == ["USER-suffix"]


def test_several_placeholders_yield_every_combination() -> None:
    assert fill_condition_values("${req:userId}/${req:groups}", CONTEXT) == [
        "USER/G1",
        "USER/G2",
    ]


@pytest.mark.parametrize("written", [3, True, None, ["a"], {"a": 1}])
def test_a_value_that_is_not_text_is_left_alone(written: Any) -> None:
    assert fill_condition_values(written, CONTEXT) == [written]


def test_a_none_in_a_resource_fills_as_nothing() -> None:
    assert fill_text("x-${target:nothing}", CONTEXT) == "x-"
