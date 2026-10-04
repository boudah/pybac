# Behaviour worth knowing

Things that will surprise you, gathered in one place. Mostly aimed at whoever
writes the policies. Every example here runs as part of the test suite.

```pycon
>>> from pybac import (
...     MatchingPolicy, Policy, PolicyEvaluator, SecurityContext, SessionContext,
... )
>>> from pybac.expression import evaluate

>>> evaluator = PolicyEvaluator()
>>> read = MatchingPolicy(action="iam:user:read", resource="*")

>>> def principal(*statements):
...     policy = Policy.model_validate({"Statement": list(statements)})
...     return SessionContext(user_id="U1", instance="acme",
...                           security_context=SecurityContext(policies=[policy]))

```

## Everything fails closed

A condition that cannot be settled is a non-match, never an exception. An
unreadable expression, an operator nobody implements, operands that cannot be
compared — each one denies, and says so at debug level through
`logging.getLogger("pybac")`.

```pycon
>>> broken = principal({"Effect": "Allow", "Action": ["iam:user:read"],
...                     "Condition": {"Expr": {"script": "target.count < 'two'"}}})
>>> evaluator.evaluate(read, broken, {"count": 2})
False

```

This is the direction you want, but it does mean a typo in a policy is silent
until someone is refused. Turn on debug logging when a grant is mysteriously
not working.

## In expressions

### `&&` and `||` bind equally tightly

Most languages give `&&` the tighter binding. This one does not — the two share
a precedence and associate left to right.

```pycon
>>> evaluate("true || false && false", {})
False

```

That is `(true || false) && false`, not `true || (false && false)`. **Write the
parentheses.** Mixing the two without them is the single most likely way to get
a policy that reads correctly and behaves otherwise.

### `containsAll` reads backwards

`a containsAll b` does not ask whether `a` holds everything in `b`. It asks
whether `a` is wholly contained *by* `b`.

```pycon
>>> context = {"target": {"groups": ["engineering"]},
...            "req": {"groups": ["engineering", "design"]}}
>>> evaluate("target.groups containsAll req.groups", context)
True
>>> evaluate("req.groups containsAll target.groups", context)
False

```

To ask "does the record carry all of these", put the record on the left.

### There is no `null`

`null` is an ordinary name that nothing sets, so it reads as nothing. `x ==
null` works as "x is absent" by accident, and would stop working if a context
ever held a key called `null`.

```pycon
>>> evaluate("target.absent == null", {"target": {}})
True

```

Prefer the `Null` condition, which says what it means.

### A name is a path, and a missing path is nothing

Reading through an absent value yields nothing rather than failing, at any
depth.

```pycon
>>> evaluate("target.a.b.c", {"target": {}}) is None
True

```

But *comparing* nothing raises, which the evaluator turns into a denial:

```pycon
>>> evaluate("target.absent == 2", {"target": {}})
False
>>> evaluate("target.absent < 2", {"target": {}})
Traceback (most recent call last):
    ...
TypeError: ...

```

Equality copes; ordering does not. Guard an ordered comparison with the field's
presence, or use the `Numeric*` conditions, which answer rather than raise.

## In conditions

### A type mismatch is a non-match — in both directions

`NumericEquals` against a string is false. So is `NumericNotEquals`. Neither has
compared anything, so neither claims a result.

```pycon
>>> from pybac.conditions import CONDITIONS
>>> CONDITIONS["NumericEquals"]("2", 2), CONDITIONS["NumericNotEquals"]("2", 2)
(False, False)

```

This matters most on a `Deny` statement: a condition that answered "true, they
differ" when it could not read one side would match a `Deny` it was never meant
to.

### A boolean is not a number

```pycon
>>> CONDITIONS["NumericEquals"](True, 1)
False

```

Python counts `True` as `1`. A numeric condition does not, or a flag would
satisfy a policy about a quantity.

### `Null` means absent *or* empty

```pycon
>>> CONDITIONS["Null"](None, True)
True

```

A key that is missing and a key explicitly set to null are one state here. Data
arriving as JSON gives no way to tell them apart.

### Dates are ISO 8601, and nothing else

A timestamp with no offset is read as UTC — fixing an interpretation beats a
policy that varies by deployment. Anything unparseable is a non-match, including
epoch numbers.

```pycon
>>> CONDITIONS["DateLessThan"]("2024-01-02", "2024-01-03")
True
>>> CONDITIONS["DateLessThan"](0, 1)
False

```

## In query filters

### An empty list and an unsatisfiable filter are opposites

```pycon
>>> granted = principal({"Effect": "Allow", "Action": ["iam:user:read"]})
>>> evaluator.compile_query_filters(read, granted)
[]

```

No filter means **no restriction** — some statement grants this outright. The
other end:

```pycon
>>> nothing_applies = principal({"Effect": "Allow", "Action": ["other"]})
>>> evaluator.compile_query_filters(read, nothing_applies)[0].model_dump(mode="json")
{'key': 'id', 'comparator': 'EQ', 'value': '__INVALID__'}

```

A filter no record satisfies means **nothing is visible**. If you ever treat an
empty result as "no restriction" without checking which of these you got, you
will hand back everything.

### An approval reads as a refusal through `evaluate`

```pycon
>>> gated = principal(
...     {"Effect": "Allow", "Action": ["iam:user:write"]},
...     {"Effect": "RequireApproval", "Action": ["iam:user:write"]},
... )
>>> write = MatchingPolicy(action="iam:user:write", resource="*")
>>> evaluator.evaluate(write, gated, {})
False
>>> evaluator.explain(write, gated, {}).approval_required
True

```

The action *is* permitted — it is waiting on a person. `evaluate` returns a
boolean and cannot say so, and answering `True` would let a caller that knows
nothing of approvals run straight past one. Use `explain` wherever approvals
matter.

### A principal with no policies gets nothing

```pycon
>>> empty_handed = SessionContext(user_id="U1", instance="acme",
...                               security_context=SecurityContext(policies=[]))
>>> evaluator.evaluate(read, empty_handed, {"id": "U2"})
False
>>> evaluator.compile_query_filters(read, empty_handed)[0].model_dump(mode="json")
{'key': 'id', 'comparator': 'EQ', 'value': '__INVALID__'}

```

Permission comes from a statement. With none to grant it, nothing is permitted
and nothing is reachable. `SecurityContext` still requires `policies` so that an
empty set is something you wrote — a context left empty by accident refuses
every request, which is a confusing way to fail.

## A condition on `RestrictFields` means two different things

The sharpest edge here, and the one to settle before writing another conditional
`RestrictFields` statement.

| Asked through | The condition says |
|---|---|
| `mask_fields` / `fields_to_mask` | **when the field is hidden** — the statement applies where its condition holds |
| `restrict_query_filters` | **when the field may be queried** — the condition is required alongside the caller's filter |

One statement, opposite readings. Both are relied on by existing callers, so
both are kept, but a policy author writing

```json
{"Effect": "RestrictFields", "NotFields": ["salary"],
 "Condition": {"Expr": {"rule": "target.grade > 5"}}}
```

gets "salary is hidden above grade 5" when a record is masked, and "salary may
be searched above grade 5" when a query is narrowed. Until this is resolved,
avoid conditional `RestrictFields` statements, or verify both paths.

## Elsewhere

**Masking never invents a field.** Withholding one the record does not have
leaves it absent rather than writing a mask over nothing — which would announce a
field that is not there.

**Masking never touches what you passed.** The copy is deep, so a record masked
for one reader stays whole for the next.

**A field withheld unconditionally cannot be searched; one withheld under a
condition can.** There are records where the latter is visible, so a search over
them is legitimate. `unsearchable_fields` reports only the first kind.

**Loading a policy is permissive; `Effect` is not.** A malformed statement loads,
because refusing a whole policy set means denying everything. Call
`validate_policies` where you want it to fail loudly. The exception is `Effect`:
anything outside `Allow`, `Deny` and `RestrictFields` is refused, because a
statement reading `"deny"` would match nothing during the deny pass and silently
permit what it was written to forbid.

## See also

- [how-it-works.md](how-it-works.md) — the policy flow, in three diagrams.
- [usage.md](usage.md) — the guide.
- [conditions.md](conditions.md) — every condition, with an example of each.
- [adding-conditions.md](adding-conditions.md) and
  [adding-operators.md](adding-operators.md) — extending either vocabulary.
