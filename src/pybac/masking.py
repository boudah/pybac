"""Hiding the fields of a resource a principal may not see.

A policy withholds fields by name, but a name in a policy need not be where the
value sits. ``document:attributeId:A1`` may mean "the entry in ``attributes``
whose id is A1", whose position only the caller knows. A *translator* bridges
the two: given the resource and the withheld name, it returns the paths to act
on.

Two strategies. **Replacing** overwrites each value in place, keeping the shape
of the resource. **Omitting** removes it. Omitting from a list blanks the slot
first and compacts afterwards, so that removing several entries in one pass does
not shift the ones still to be removed.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from pybac._paths import get, set_, unset

_ABSENT: Final = object()

__all__ = [
    "FieldMasking",
    "FieldTranslator",
    "MaskedPaths",
    "MaskingStrategy",
    "mask",
]


class MaskingStrategy(StrEnum):
    """What to do with a field the principal may not see."""

    REPLACE = "replace"
    OMIT = "omit"


#: Fields that identify a record. Masking them would leave it unrecognisable,
#: so they are kept whatever a policy says.
DEFAULT_SYSTEM_FIELDS: Final = frozenset(
    {"id", "instance", "createdAt", "updatedAt", "deleted"}
)


@dataclass(frozen=True)
class MaskedPaths:
    """Where a withheld field sits, which may differ by strategy.

    Replacing the value of a list entry writes to ``attributes[2].value``, while
    omitting it removes ``attributes[2]`` entirely.
    """

    replace: str | None = None
    omit: str | None = None

    def path_for(self, strategy: MaskingStrategy) -> str | None:
        return self.omit if strategy is MaskingStrategy.OMIT else self.replace


#: Given the resource and a withheld field name, where that field actually sits.
FieldTranslator = Callable[[Any, str], Sequence["str | MaskedPaths"]]


@dataclass(frozen=True)
class FieldMasking:
    """How to hide what a principal may not see."""

    strategy: MaskingStrategy = MaskingStrategy.REPLACE
    replacement: str = "{****}"
    system_fields: frozenset[str] = field(default=DEFAULT_SYSTEM_FIELDS)


def _translator_for(
    translators: Mapping[str, FieldTranslator], name: str
) -> FieldTranslator | None:
    """The translator for ``name``, or for the family it belongs to.

    ``document:attributeId:A1`` falls back to ``document:attributeId``, so one
    translator serves every field in a family.
    """
    direct = translators.get(name)
    if direct is not None:
        return direct
    family, separator, _ = name.rpartition(":")
    return translators.get(family) if separator else None


def _path_of(entry: str | MaskedPaths, strategy: MaskingStrategy) -> str | None:
    return entry.path_for(strategy) if isinstance(entry, MaskedPaths) else entry


def mask(
    resource: Mapping[str, Any],
    withheld: Iterable[str],
    *,
    translators: Mapping[str, FieldTranslator] | None = None,
    masking: FieldMasking | None = None,
) -> dict[str, Any]:
    """Return a copy of ``resource`` with the ``withheld`` fields hidden.

    The resource you pass is left untouched, nested values included, so one
    masked for a single reader stays whole for the next.
    """
    masking = masking or FieldMasking()
    translators = translators or {}

    result = deepcopy(dict(resource))
    lists_to_compact: set[str] = set()

    for name in withheld:
        if name in masking.system_fields:
            continue
        translate = _translator_for(translators, name)
        entries = translate(resource, name) if translate is not None else [name]

        for entry in entries:
            path = _path_of(entry, masking.strategy)
            if not path:
                continue
            if masking.strategy is MaskingStrategy.OMIT:
                if "[" in path:
                    lists_to_compact.add(path[: path.rindex("[")])
                unset(result, path)
            elif get(result, path, _ABSENT) is not _ABSENT:
                # Only hide what is there. Writing a mask over a field the
                # resource never had would announce one that does not exist.
                set_(result, path, masking.replacement)

    for path in lists_to_compact:
        held = get(result, path)
        if isinstance(held, list):
            set_(result, path, [item for item in held if item is not None])
    return result
