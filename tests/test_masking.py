from __future__ import annotations

from typing import Any

import pytest

from pybac.masking import (
    FieldMasking,
    MaskedPaths,
    MaskingStrategy,
    mask,
)

RESOURCE: dict[str, Any] = {
    "id": "DOC2",
    "name": "visible",
    "salary": 50_000,
    "nested": {"secret": "hidden", "kept": "shown"},
    "attributes": [
        {"id": "Q1", "value": "one"},
        {"id": "Q2", "value": "two"},
        {"id": "Q3", "value": "three"},
    ],
}


def test_nothing_withheld_leaves_the_resource_whole() -> None:
    assert mask(RESOURCE, []) == RESOURCE


def test_replacing_overwrites_the_value_in_place() -> None:
    masked = mask(RESOURCE, ["salary"])
    assert masked["salary"] == "{****}"
    assert masked["name"] == "visible"


def test_replacing_reaches_a_nested_field() -> None:
    masked = mask(RESOURCE, ["nested.secret"])
    assert masked["nested"] == {"secret": "{****}", "kept": "shown"}


def test_the_replacement_can_be_chosen() -> None:
    masked = mask(RESOURCE, ["salary"], masking=FieldMasking(replacement="REDACTED"))
    assert masked["salary"] == "REDACTED"


def test_omitting_removes_the_field() -> None:
    masked = mask(
        RESOURCE, ["salary"], masking=FieldMasking(strategy=MaskingStrategy.OMIT)
    )
    assert "salary" not in masked
    assert masked["name"] == "visible"


def test_a_field_that_identifies_the_record_is_kept() -> None:
    """Masking it would leave the record unrecognisable to its reader."""
    assert mask(RESOURCE, ["id", "salary"])["id"] == "DOC2"


def test_the_kept_fields_can_be_chosen() -> None:
    masking = FieldMasking(system_fields=frozenset({"name"}))
    masked = mask(RESOURCE, ["id", "name"], masking=masking)
    assert masked["name"] == "visible"
    assert masked["id"] == "{****}"


def test_the_original_is_left_whole() -> None:
    """A resource masked for one reader stays intact for the next."""
    before = {"nested": {"secret": "hidden"}}
    mask(before, ["nested.secret"])
    assert before == {"nested": {"secret": "hidden"}}


def test_a_field_the_resource_lacks_is_not_invented() -> None:
    masked = mask(RESOURCE, ["absent", "nested.absent"])
    assert "absent" not in masked
    assert "absent" not in masked["nested"]
    assert masked["name"] == "visible"


# --------------------------------------------------------------------------
# translators
# --------------------------------------------------------------------------


def attribute_paths(resource: Any, name: str) -> list[str | MaskedPaths]:
    """Where `document:attributeId:Q2` actually sits, as a caller would say."""
    wanted = name.rsplit(":", 1)[-1]
    for index, attribute in enumerate(resource.get("attributes", [])):
        if attribute["id"] == wanted:
            slot = f"attributes[{index}]"
            return [MaskedPaths(omit=slot, replace=f"{slot}.value")]
    return []


TRANSLATORS = {"document:attributeId": attribute_paths}


def test_a_translator_is_found_by_the_family_a_field_belongs_to() -> None:
    """`document:attributeId:Q2` falls back to the `document:attributeId` translator."""
    masked = mask(RESOURCE, ["document:attributeId:Q2"], translators=TRANSLATORS)
    assert [q["value"] for q in masked["attributes"]] == ["one", "{****}", "three"]


def test_a_translator_is_found_directly_by_name() -> None:
    masked = mask(RESOURCE, ["exact"], translators={"exact": lambda _r, _n: ["salary"]})
    assert masked["salary"] == "{****}"


def test_omitting_uses_the_translators_other_path() -> None:
    masked = mask(
        RESOURCE,
        ["document:attributeId:Q2"],
        translators=TRANSLATORS,
        masking=FieldMasking(strategy=MaskingStrategy.OMIT),
    )
    assert [q["id"] for q in masked["attributes"]] == ["Q1", "Q3"]


def test_omitting_several_entries_removes_exactly_those() -> None:
    """Blanking first and compacting after keeps the indices meaningful."""
    masked = mask(
        RESOURCE,
        ["document:attributeId:Q1", "document:attributeId:Q3"],
        translators=TRANSLATORS,
        masking=FieldMasking(strategy=MaskingStrategy.OMIT),
    )
    assert [q["id"] for q in masked["attributes"]] == ["Q2"]


def test_a_translator_that_finds_nothing_masks_nothing() -> None:
    masked = mask(RESOURCE, ["document:attributeId:ABSENT"], translators=TRANSLATORS)
    assert [q["value"] for q in masked["attributes"]] == ["one", "two", "three"]


def test_a_translator_entry_with_no_path_for_the_strategy_is_skipped() -> None:
    translators = {"only-omit": lambda _r, _n: [MaskedPaths(omit="salary")]}
    assert mask(RESOURCE, ["only-omit"], translators=translators)["salary"] == 50_000


@pytest.mark.parametrize(
    ("strategy", "expected"),
    [
        (MaskingStrategy.REPLACE, "attributes[0].value"),
        (MaskingStrategy.OMIT, "attributes[0]"),
    ],
)
def test_masked_paths_answer_for_each_strategy(
    strategy: MaskingStrategy, expected: str
) -> None:
    paths = MaskedPaths(replace="attributes[0].value", omit="attributes[0]")
    assert paths.path_for(strategy) == expected


def test_omitting_a_path_with_no_index_leaves_the_rest_alone() -> None:
    """Compacting only applies where the path actually names a list."""
    masked = mask(
        RESOURCE,
        ["plain"],
        translators={"plain": lambda _r, _n: ["salary"]},
        masking=FieldMasking(strategy=MaskingStrategy.OMIT),
    )
    assert "salary" not in masked
    assert len(masked["attributes"]) == 3


def test_compacting_skips_a_path_that_does_not_hold_a_list() -> None:
    translators = {"odd": lambda _r, _n: [MaskedPaths(omit="name[0]")]}
    masked = mask(
        RESOURCE,
        ["odd"],
        translators=translators,
        masking=FieldMasking(strategy=MaskingStrategy.OMIT),
    )
    assert masked["name"] == "visible"
