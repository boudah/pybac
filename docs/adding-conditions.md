# Adding a condition

A policy statement can qualify itself with a `Condition` block:

```json
{ "Condition": { "StringEquals": { "target:data:status": "goal" } } }
```

`StringEquals` is a condition. This page is how you add another.

Conditions and the [expression operators](adding-operators.md) are separate
extension points. A condition is named in the policy and compares one context
value against one policy value; an operator is written inside an `Expr` script
and combines two sub-expressions. Adding one does not add the other.

Every condition that already exists is listed in
[conditions.md](conditions.md), with an example of each.

## Register it

Conditions live in `_BASE` in `src/pybac/conditions/operators.py`. A condition
takes the value found in the context and the value written in the policy, and
answers whether they match:

```python
def _string_starts_with(actual: Any, expected: Any) -> bool:
    return _strings(actual, expected) and actual.startswith(expected)


_BASE = {
    ...
    "StringStartsWith": _string_starts_with,
}
```

That is all. Three variants are derived from every entry, so registering one
name yields four:

| Name | Asks |
|---|---|
| `StringStartsWith` | the context value matches the policy value |
| `StringStartsWithIfExists` | the same, but holds when the context has no value |
| `ForAnyValue:StringStartsWith` | *some* context value matches *some* policy value |
| `ForAllValues:StringStartsWith` | *every* context value matches some policy value |

## Compile it

A condition also has to answer a second question. `evaluate` asks "may this
principal touch this record?" — but a policy also has to narrow a *query*, and
there is no record yet to ask about. So every condition is compiled into a
filter the caller pushes into its own query.

Filters live in `_BASE` in `src/pybac/conditions/filters.py`, keyed by the same
names:

```python
_BASE = {
    ...
    "StringStartsWith": _typed(_C.MATCHES, is_string),
}
```

Five builders cover almost everything:

| Builder | Produces |
|---|---|
| `_scalar(comparator)` | a comparison against the first value |
| `_typed(comparator, accepts)` | the same, but only for values of the right type |
| `_lowered(comparator)` | the same, case-folded |
| `_collection(comparator)` | a comparison against every value |
| `_describes_nothing` | a filter no record satisfies |

**A guard reads the value, not the list around it.** Values arrive as a list,
so a guard written as `is_string(values)` is false for `["acme-*"]` and the
condition produces no filter at all — and a condition that produces no filter
does not restrict. A narrowing condition that silently stops narrowing is the
worst failure this code can have. `_typed` reads `values[0]` for this reason.

**A condition that restricts but describes no field of the record** — one about
the caller's address, say — uses `_describes_nothing`. Returning an empty list
would leave the query unrestricted.

A test asserts that `FILTERS` and `CONDITIONS` have exactly the same keys, so a
condition that decides but cannot be queried will not get past CI.

## The contract

**A type mismatch is a non-match in both directions.** `NumericEquals` against
a string is false, and so is `NumericNotEquals` — neither has compared anything,
so neither should claim a result. Guard first, then compare. The helpers
`_numbers`, `_strings` and `_dates` exist for this.

The reason is the `Deny` pass. A condition that answers "true, they differ"
when it could not read one side will match a `Deny` it was never meant to, or
— worse on an `Allow` — grant access on the strength of an unreadable value.

**Never raise.** A condition returns `False` for anything it cannot make sense
of. It is called once per statement per request, and an exception would abort
a decision that should simply not have matched.

**Take the value as the policy wrote it.** The caller has already resolved
`target:data:status` against the context and expanded any `${...}` placeholder.
A condition does no lookups of its own.

## Naming

The prefixes `ForAnyValue:` and `ForAllValues:` and the suffix `IfExists` are
reserved — they are generated, and a base name ending in `IfExists` would
produce `XIfExistsIfExists`.

Follow the family names already in use: `String…`, `Numeric…`, `Date…`,
`Contains…`. A reader guesses the guard from the prefix.

## Test it

Coverage is gated at 100%, branches included, so an untested line fails the
build. Three files:

| File | Assert |
|---|---|
| `tests/test_conditions.py` | the match, the non-match, and — if your condition comes as a positive/negative pair — a row in `test_neither_direction_holds_when_the_types_disagree` |
| `tests/test_condition_filters.py` | the comparator and value it compiles to, and that a value of the wrong type yields no comparison |
| `tests/test_patterns.py` | the pattern matching itself, if it does any |

## Removing one

Delete both entries, in `operators.py` and in `filters.py`. Their three variants
go with them. A policy naming it then has a
condition that cannot be read, which the evaluator treats as a non-match, so
those policies deny rather than silently permitting.

Check the policy store first, not just the repository — conditions are named in
stored policies, and the source tree only shows the ones written in code.
