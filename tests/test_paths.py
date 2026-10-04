from __future__ import annotations

from typing import Any

import pytest

from pybac._paths import get, set_, to_path, unset


def target() -> dict[str, Any]:
    return {
        "a": {"b": [{"c": 1}, {"c": 2}]},
        "nulled": None,
        "dotted.key": "literal",
        "list": ["x", "y", "z"],
    }


# --------------------------------------------------------------------------
# to_path
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("a", ["a"]),
        ("a.b.c", ["a", "b", "c"]),
        ("a.b[0].c", ["a", "b", "0", "c"]),
        ("a[0][1]", ["a", "0", "1"]),
        ("a['b.c'].d", ["a", "b.c", "d"]),
        ('a["b"][1]', ["a", "b", "1"]),
        ("list[-1]", ["list", "-1"]),
        ("", []),
    ],
)
def test_to_path_splits_a_string(path: str, expected: list[str]) -> None:
    assert to_path(path) == expected


def test_to_path_takes_a_sequence_verbatim() -> None:
    """A condition key arrives pre-split on the colon, so segments stay intact."""
    assert to_path(["target", "user", "id"]) == ["target", "user", "id"]
    assert to_path(["dotted.key"]) == ["dotted.key"]
    assert to_path(["a[0]"]) == ["a[0]"]


def test_to_path_accepts_a_bare_index() -> None:
    assert to_path(2) == [2]


# --------------------------------------------------------------------------
# get
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("a.b[0].c", 1),
        ("a.b[1].c", 2),
        ("list[1]", "y"),
        ("list.1", "y"),
        ("dotted.key", None),
        ("nulled", None),
        (["a", "b", "0", "c"], 1),
        (["dotted.key"], "literal"),
    ],
)
def test_get_reads_a_path(path: Any, expected: Any) -> None:
    assert get(target(), path) == expected


def test_get_indexes_from_the_end() -> None:
    assert get(target(), "list[-1]") == "z"
    assert get(target(), "list[-3]") == "x"


@pytest.mark.parametrize(
    "path",
    [
        "missing",
        "a.missing",
        "a.missing.deeper",
        "a.b[9].c",
        "list[9]",
        "nulled.deeper",
    ],
)
def test_get_returns_the_default_for_anything_absent(path: str) -> None:
    assert get(target(), path) is None
    assert get(target(), path, default="fallback") == "fallback"


def test_get_never_raises_walking_past_a_leaf() -> None:
    assert get({"a": 1}, "a.b.c") is None


def test_a_sentinel_default_separates_a_missing_key_from_a_stored_none() -> None:
    """Callers that need the distinction supply their own sentinel."""
    missing = object()
    assert get(target(), "nulled", default=missing) is None
    assert get(target(), "absent", default=missing) is missing


def test_get_reads_through_a_tuple() -> None:
    assert get({"t": ("x", "y")}, "t[1]") == "y"


# --------------------------------------------------------------------------
# set_
# --------------------------------------------------------------------------


def test_set_writes_an_existing_path() -> None:
    data = target()
    set_(data, "a.b[0].c", 9)
    assert data["a"]["b"][0]["c"] == 9


def test_set_creates_missing_dicts() -> None:
    data = target()
    set_(data, "x.y.z", 1)
    assert data["x"] == {"y": {"z": 1}}


def test_set_creates_a_list_when_the_next_segment_is_an_index() -> None:
    data = target()
    set_(data, "created[1].c", "v")
    assert data["created"] == [None, {"c": "v"}]


def test_set_pads_a_list_to_reach_the_index() -> None:
    data = target()
    set_(data, "list[4]", "w")
    assert data["list"] == ["x", "y", "z", None, "w"]


def test_set_extends_an_existing_list_of_objects() -> None:
    data = target()
    set_(data, "a.b[2].c", 9)
    assert data["a"]["b"] == [{"c": 1}, {"c": 2}, {"c": 9}]


def test_set_writes_a_negative_index_in_range() -> None:
    data = target()
    set_(data, "list[-1]", "Z")
    assert data["list"] == ["x", "y", "Z"]


def test_set_returns_the_object() -> None:
    data: dict[str, Any] = {}
    assert set_(data, "a", 1) is data


def test_set_ignores_an_empty_path() -> None:
    data = target()
    assert set_(data, "", 1) == target()


# --------------------------------------------------------------------------
# unset
# --------------------------------------------------------------------------


def test_unset_removes_a_mapping_key() -> None:
    data = target()
    assert unset(data, "nulled") is True
    assert "nulled" not in data


def test_unset_removes_a_nested_key() -> None:
    data = target()
    unset(data, "a.b[0].c")
    assert data["a"]["b"][0] == {}


def test_unset_blanks_a_list_slot_rather_than_shrinking_the_list() -> None:
    """Field masking removes several indices in one pass, then drops the blanks."""
    data = ["a", "b", "c", "d"]
    unset(data, "[1]")
    unset(data, "[3]")

    assert data == ["a", None, "c", None]
    assert [item for item in data if item is not None] == ["a", "c"]


@pytest.mark.parametrize("path", ["missing", "missing.deep", "list[9]", "a.b[9].c"])
def test_unset_is_a_no_op_for_an_absent_path(path: str) -> None:
    data = target()
    assert unset(data, path) is True
    assert data == target()


def test_unset_accepts_no_path() -> None:
    data = target()
    assert unset(data, None) is True
    assert data == target()


# --------------------------------------------------------------------------
# less travelled corners
# --------------------------------------------------------------------------


def test_a_segment_may_be_given_as_a_number() -> None:
    assert get({"a": ["x", "y"]}, ["a", 1]) == "y"
    assert get({"a": ["x", "y"]}, 0, default="none") == "none"


def test_a_boolean_is_not_an_index() -> None:
    """`True` is an `int` in Python, and would otherwise read element one."""
    assert get({"a": ["x", "y"]}, ["a", True]) is None


def test_a_string_can_be_indexed() -> None:
    assert get({"s": "abc"}, "s[1]") == "b"


def test_reading_into_a_value_that_holds_nothing_yields_the_default() -> None:
    assert get({"n": 5}, "n.x") is None
    assert get({"n": 5}, "n.x", default="none") == "none"


def test_writing_a_name_into_a_list_does_nothing() -> None:
    """A list is addressed by position; there is nowhere to put a name."""
    data: dict[str, Any] = {"a": [1]}
    set_(data, "a.name", 2)
    assert data == {"a": [1]}


def test_a_numeric_key_finds_a_number_key_on_a_mapping() -> None:
    data: dict[Any, Any] = {0: "first"}
    set_(data, "0", "changed")
    assert data == {0: "changed"}


def test_unsetting_through_a_none_is_a_no_op() -> None:
    data: dict[str, Any] = {"a": None}
    assert unset(data, "a.b.c") is True
    assert data == {"a": None}


def test_unsetting_a_numeric_key_from_a_mapping() -> None:
    data: dict[Any, Any] = {0: "first", "keep": 1}
    assert unset(data, "0") is True
    assert data == {"keep": 1}


def test_unsetting_from_something_that_holds_nothing_is_a_no_op() -> None:
    data = {"n": 5}
    assert unset(data, "n.x") is True
    assert data == {"n": 5}


def test_a_numeric_key_reads_a_number_key_on_a_mapping() -> None:
    """JSON has string keys, but a mapping built in Python may not."""
    assert get({0: "first"}, "0") == "first"
    assert get({0: "first"}, ["0"]) == "first"


def test_unsetting_an_empty_path_is_a_no_op() -> None:
    data = target()
    assert unset(data, "") is True
    assert data == target()


def test_writing_before_the_start_of_a_list_does_nothing() -> None:
    data: dict[str, Any] = {"a": [1]}
    set_(data, "a[-5]", 2)
    assert data == {"a": [1]}


def test_writing_into_something_that_cannot_hold_a_value_does_nothing() -> None:
    frozen = (1, 2)
    assert set_(frozen, "a", 3) is frozen
