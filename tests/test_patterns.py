from __future__ import annotations

import pytest

from pybac.conditions import matches


@pytest.mark.parametrize(
    ("value", "pattern"),
    [
        ("docs:folder:read", "docs:folder:read"),
        ("docs:folder:read", "docs:folder:*"),
        ("docs:folder:read", "docs:*"),
        ("docs:folder:read", "*"),
        ("docs:folder:", "docs:folder:*"),
        ("abc", "a?c"),
        ("abc", "???"),
        ("docs:document:delete", "docs:*:delete"),
    ],
)
def test_a_pattern_matches(value: str, pattern: str) -> None:
    assert matches(value, pattern)


@pytest.mark.parametrize(
    ("value", "pattern"),
    [
        ("docs:folder:read", "docs:item:*"),
        ("docs:folder:read", "docs:folder:write"),
        ("ac", "a?c"),
        ("abcd", "a?c"),
        ("docs:folder:read:extra", "docs:folder:read"),
        ("xdocs:folder:read", "docs:*"),
    ],
)
def test_a_pattern_does_not_match(value: str, pattern: str) -> None:
    assert not matches(value, pattern)


def test_a_pattern_must_match_the_whole_value() -> None:
    """Otherwise `docs:folder:read` would satisfy a policy naming only `compose`."""
    assert not matches("docs:folder:read", "compose")
    assert not matches("docs:folder:read", "lib")


@pytest.mark.parametrize(
    "character", [".", "+", "(", ")", "[", "]", "{", "}", "^", "$", "|", "\\"]
)
def test_characters_with_meaning_in_a_regular_expression_stay_literal(
    character: str,
) -> None:
    value = f"a{character}b"
    assert matches(value, value)
    assert not matches("axb", value)


def test_only_star_and_question_mark_are_wildcards() -> None:
    assert matches("a.b", "a.b")
    assert not matches("axb", "a.b")
    assert matches("axb", "a?b")
    assert matches("axxxb", "a*b")
