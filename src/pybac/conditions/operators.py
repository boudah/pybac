"""The named conditions a policy statement can carry.

A statement may qualify itself with a `Condition` block:

```json
{ "Condition": { "StringEquals": { "target:data:status": "goal" } } }
```

`StringEquals` is one of these. Each takes the value found in the context and
the value written in the policy, and answers whether they match.

**A type mismatch is a non-match, in both directions.** `NumericEquals` on a
value that is not a number is false, and so is `NumericNotEquals` — neither
claims to have compared anything. The same holds for the string, date and
address families. Only the set operators, which have no type to disagree
about, answer freely.

Three variants are derived from every condition:

| Variant | Asks |
|---|---|
| `<name>IfExists` | the same, but holds when the context has no such value |
| `ForAnyValue:<name>` | whether *some* context value matches *some* policy value |
| `ForAllValues:<name>` | whether *every* context value matches some policy value |
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from datetime import datetime
from typing import Any, Final

from pybac._collections import contains_all, contains_any, contains_none
from pybac._types import as_list, is_boolean, is_number, is_string, parse_date
from pybac.conditions.patterns import matches

__all__ = ["CONDITIONS", "ConditionOperator"]

ConditionOperator = Callable[[Any, Any], bool]

_IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
_IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


# -- numbers ---------------------------------------------------------------


def _numbers(actual: Any, expected: Any) -> bool:
    return is_number(actual) and is_number(expected)


def _numeric_equals(actual: Any, expected: Any) -> bool:
    return _numbers(actual, expected) and actual == expected


def _numeric_not_equals(actual: Any, expected: Any) -> bool:
    return _numbers(actual, expected) and actual != expected


def _numeric_less_than(actual: Any, expected: Any) -> bool:
    return _numbers(actual, expected) and actual < expected


def _numeric_less_than_equals(actual: Any, expected: Any) -> bool:
    return _numbers(actual, expected) and actual <= expected


def _numeric_greater_than(actual: Any, expected: Any) -> bool:
    return _numbers(actual, expected) and actual > expected


def _numeric_greater_than_equals(actual: Any, expected: Any) -> bool:
    return _numbers(actual, expected) and actual >= expected


# -- dates -----------------------------------------------------------------


def _dates(actual: Any, expected: Any) -> tuple[datetime, datetime] | None:
    left, right = parse_date(actual), parse_date(expected)
    if left is None or right is None:
        return None
    return left, right


def _date_equals(actual: Any, expected: Any) -> bool:
    pair = _dates(actual, expected)
    return pair is not None and pair[0] == pair[1]


def _date_not_equals(actual: Any, expected: Any) -> bool:
    pair = _dates(actual, expected)
    return pair is not None and pair[0] != pair[1]


def _date_less_than(actual: Any, expected: Any) -> bool:
    pair = _dates(actual, expected)
    return pair is not None and pair[0] < pair[1]


def _date_less_than_equals(actual: Any, expected: Any) -> bool:
    pair = _dates(actual, expected)
    return pair is not None and pair[0] <= pair[1]


def _date_greater_than(actual: Any, expected: Any) -> bool:
    pair = _dates(actual, expected)
    return pair is not None and pair[0] > pair[1]


def _date_greater_than_equals(actual: Any, expected: Any) -> bool:
    pair = _dates(actual, expected)
    return pair is not None and pair[0] >= pair[1]


# -- strings ---------------------------------------------------------------


def _strings(actual: Any, expected: Any) -> bool:
    return is_string(actual) and is_string(expected)


def _string_equals(actual: Any, expected: Any) -> bool:
    return _strings(actual, expected) and actual == expected


def _string_not_equals(actual: Any, expected: Any) -> bool:
    return _strings(actual, expected) and actual != expected


def _string_equals_ignore_case(actual: Any, expected: Any) -> bool:
    return _strings(actual, expected) and actual.casefold() == expected.casefold()


def _string_not_equals_ignore_case(actual: Any, expected: Any) -> bool:
    return _strings(actual, expected) and actual.casefold() != expected.casefold()


def _string_like(actual: Any, expected: Any) -> bool:
    return _strings(actual, expected) and matches(actual, expected)


def _string_not_like(actual: Any, expected: Any) -> bool:
    return _strings(actual, expected) and not matches(actual, expected)


# -- booleans and absence --------------------------------------------------


def _as_boolean(value: Any) -> bool | None:
    """Read a boolean, written either as one or as the word."""
    if is_boolean(value):
        return bool(value)
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def _bool(actual: Any, expected: Any) -> bool:
    left, right = _as_boolean(actual), _as_boolean(expected)
    return left is not None and left is right


def _null(actual: Any, expected: Any) -> bool:
    """`Null: {field: true}` holds when the context has no such value."""
    if not is_boolean(expected):
        return False
    return (actual is None) is expected


# -- addresses -------------------------------------------------------------


def _ip_pair(actual: Any, expected: Any) -> tuple[_IpAddress, _IpNetwork] | None:
    if not _strings(actual, expected):
        return None
    try:
        # A bare address is a network of one, so both forms are written alike.
        return ipaddress.ip_address(actual.strip()), ipaddress.ip_network(
            expected.strip(), strict=False
        )
    except ValueError:
        return None


def _ip_address(actual: Any, expected: Any) -> bool:
    pair = _ip_pair(actual, expected)
    return pair is not None and pair[0] in pair[1]


def _not_ip_address(actual: Any, expected: Any) -> bool:
    pair = _ip_pair(actual, expected)
    return pair is not None and pair[0] not in pair[1]


# -- sets ------------------------------------------------------------------


def _in_values(actual: Any, expected: Any) -> bool:
    return actual in as_list(expected)


def _not_in_values(actual: Any, expected: Any) -> bool:
    return actual not in as_list(expected)


# -- the table -------------------------------------------------------------

_BASE: Final[dict[str, ConditionOperator]] = {
    "NumericEquals": _numeric_equals,
    "NumericNotEquals": _numeric_not_equals,
    "NumericLessThan": _numeric_less_than,
    "NumericLessThanEquals": _numeric_less_than_equals,
    "NumericGreaterThan": _numeric_greater_than,
    "NumericGreaterThanEquals": _numeric_greater_than_equals,
    "DateEquals": _date_equals,
    "DateNotEquals": _date_not_equals,
    "DateLessThan": _date_less_than,
    "DateLessThanEquals": _date_less_than_equals,
    "DateGreaterThan": _date_greater_than,
    "DateGreaterThanEquals": _date_greater_than_equals,
    "StringEquals": _string_equals,
    "StringNotEquals": _string_not_equals,
    "StringEqualsIgnoreCase": _string_equals_ignore_case,
    "StringNotEqualsIgnoreCase": _string_not_equals_ignore_case,
    "StringLike": _string_like,
    "StringNotLike": _string_not_like,
    "Bool": _bool,
    "Null": _null,
    "IpAddress": _ip_address,
    "NotIpAddress": _not_ip_address,
    "InValues": _in_values,
    "NotInValues": _not_in_values,
    "ContainsAtLeastOne": contains_any,
    "ContainsAll": contains_all,
    "ContainsNone": contains_none,
}


def _if_exists(condition: ConditionOperator) -> ConditionOperator:
    def holds(actual: Any, expected: Any) -> bool:
        return True if actual is None else condition(actual, expected)

    return holds


def _for_any_value(condition: ConditionOperator) -> ConditionOperator:
    def holds(actual: Any, expected: Any) -> bool:
        wanted = as_list(expected)
        return any(
            any(condition(value, want) for want in wanted) for value in as_list(actual)
        )

    return holds


def _for_all_values(condition: ConditionOperator) -> ConditionOperator:
    def holds(actual: Any, expected: Any) -> bool:
        wanted = as_list(expected)
        return all(
            any(condition(value, want) for want in wanted) for value in as_list(actual)
        )

    return holds


def _build() -> dict[str, ConditionOperator]:
    table: dict[str, ConditionOperator] = {}
    for name, condition in _BASE.items():
        table[name] = condition
        table[f"{name}IfExists"] = _if_exists(condition)
        table[f"ForAnyValue:{name}"] = _for_any_value(condition)
        table[f"ForAllValues:{name}"] = _for_all_values(condition)
    return table


#: Every condition a policy may name, derived variants included.
CONDITIONS: Final[dict[str, ConditionOperator]] = _build()
