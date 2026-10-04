# Adding an operator to the expression language

Policy `Expr` conditions are written in a small expression language:

```json
{ "Condition": { "Expr": { "script": "target.resource.groups containsAny req.groups" } } }
```

`containsAny` is an operator, and so are `==`, `in` and `!`. This page is how
you add another.

There are two halves. Registering the **syntax** makes an expression parse;
giving it a **meaning** makes it decide something. Do both, or a policy using
the new operator will be refused as unreadable.

## 1. Register the syntax

Operators live in one table, `BINARY_OPERATORS` in
`src/pybac/expression/grammar.py`. Add an entry mapping the operator to its
precedence:

```python
BINARY_OPERATORS: Final[dict[str, int]] = {
    ...
    "containsAny": 20,
    "startsWith": 20,   # new
}
```

That is the whole registration. The lexer builds its token pattern from this
table, and the parser reads precedence from it, so neither needs touching.

### Choosing a precedence

Higher binds tighter. `a == b && c` groups as `(a == b) && c` because `==` is 20
and `&&` is 10.

| Precedence | Operators | Use for |
|---|---|---|
| 10 | `\|\|` `&&` | joining whole conditions |
| 20 | `==` `!=` `<` `<=` `>` `>=` `in` `containsAny` `containsAll` `containsNone` | comparing two values |
| 30 | `+` `-` | |
| 40 | `*` `/` `//` | |
| 50 | `%` `^` | |

An operator that compares two values and yields a decision belongs at 20, beside
`in` and `containsAny`. Reach for another level only if the new operator has to
bind tighter or looser than those.

Operators sharing a precedence associate left to right: `a - b - c` is
`(a - b) - c`.

### Naming

A word operator must be a valid identifier — letters, digits, `_` and `$`, not
starting with a digit. It is matched on word boundaries, so registering
`contains` would **not** break an existing name like `containsAnyway`.

A symbol operator may be any punctuation not already spoken for. Longer
operators are matched first, so adding `<=>` alongside `<=` is safe.

Do not register a word that stored policies already use as a field name. Once
`status` is an operator, `target.status` stops parsing.

## 2. Give it a meaning

An operator's implementation is deliberately not in `grammar.py`. The same
expression is read two ways — once to reach a verdict, once to compile a query
filter that a caller pushes into its own database query — and the two answer
differently. `containsAny` yields `True` or `False` in the first, and a
`OVERLAPS` filter in the second.

### Deciding

`src/pybac/expression/operators.py` holds three tables:

| Table | Shape | For |
|---|---|---|
| `BINARY` | `(left, right) -> value` | operators whose operands are both evaluated |
| `LAZY_BINARY` | `(left, right) -> value`, each operand a no-argument callable | operators that may skip an operand |
| `UNARY` | `(right) -> value` | `!`, and anything else prefixed |

Most operators go in `BINARY`:

```python
def _starts_with(left: Any, right: Any) -> bool:
    """Whether `left` begins with `right`."""
    return isinstance(left, str) and isinstance(right, str) and left.startswith(right)


BINARY["startsWith"] = _starts_with
```

Three rules for an implementation:

- **Return a value, not necessarily a boolean.** `&&` yields whichever operand
  settled it, which is what lets `a && a.b` read `a.b` only when `a` is there.
- **Read nothing but your operands.** An operator cannot reach the context, a
  database or another service. If it needs more than the two values it is
  handed, it does not belong here.
- **Prefer a non-match to an exception** for operand types a policy might
  plausibly hold — `in` answers `False` when asked about a number rather than
  raising. Let a genuine type error raise: the caller reads a failed condition
  as a non-match, so the policy denies.

An operator that may skip an operand goes in `LAZY_BINARY` and receives
callables instead of values:

```python
def _and(left: Operand, right: Operand) -> Any:
    value = left()
    return right() if value else value
```

Call each operand at most once. They are evaluated on demand, not memoised.

### Compiling to a filter

The second reading lives in `_COMPARISONS` in
`src/pybac/expression/compiler.py`. Here a name under `target` is not a value
but a `_Field` — something the query will compare — while everything else is
read now, because it is already known.

An operator that compares a field against a value registers the comparator it
becomes, and the one it becomes when written the other way round:

```python
_COMPARISONS = {
    ...
    "startsWith": _sided(_C.MATCHES, None),
}
```

The second argument is for `value <op> field`. Pass the mirrored comparator when
the operator has one — `<` mirrors to `>`, because `2 < target.a` is
`target.a > 2` — and `None` when it does not, as for `containsAll`. An operator
whose two sides mean different things, like `in`, writes its own builder
instead; `_membership` is the example.

Nothing else is needed. An operator with no entry still works on two known
values, because the compiler falls back to the deciding implementation and folds
the answer into the surrounding `&&` or `||`. It fails only when a field is
involved, and that failure is a refusal, not a crash.

**Comparators that take a collection** — `IN`, `OVERLAPS`, `SUBSET_OF` and the
rest — receive a list. `_leaf` wraps a bare value for you.

**If your operator cannot become a filter at all**, leave it out of
`_COMPARISONS`. A condition using it then compiles to a filter no record
satisfies, so a policy resting on it grants nothing through a query rather than
everything. That is the right way for it to fail.

## 3. Test it

Three files, matching the three things you changed:

| File | Assert |
|---|---|
| `tests/test_expression_lexer.py` | the operator becomes one `binaryOp` token, and does not split a longer name |
| `tests/test_expression_parser.py` | it groups as intended against its neighbours, via `describe(parse(...))` |
| the evaluator's tests | both meanings, including the operand types a policy may realistically hold |

The parser tests compare trees as data:

```python
def test_starts_with_binds_like_a_comparison() -> None:
    assert describe(parse("a startsWith b && c")) == describe(
        parse("(a startsWith b) && c")
    )
```

## Removing an operator

Delete the entry from `BINARY_OPERATORS`. Expressions using it then fail to
parse, and the evaluator treats a condition it cannot read as a non-match — so
policies that relied on it deny rather than silently permitting.

Check the stored policies first. A denial is safe, but it is still a change in
who can do what, and it will not announce itself until someone is refused.

## What is not extensible

**Unary operators.** `!` is the only one, registered directly in `ELEMENTS`.
Adding another means a new entry there with `type="unaryOp"`.

**Transforms and function calls.** `value | someTransform` and `someFunction(x)`
are not supported, and an expression using either is refused when it is parsed.
Supporting them means adding four states back to the parser.

**Anything needing another service.** An operator receives two values and
nothing else. It cannot reach a database, a cache or another service, so
"is this user managed by that one" is not something an operator can answer.
Resolve it before evaluation and put the answer in the service context.
