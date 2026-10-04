# Using pybac

Every example on this page runs as part of the test suite, so what you read is
what the code does.

## Three questions

A policy engine is usually asked only the first of these. The other two are
where most of the work is:

| Question | Method |
|---|---|
| May this principal do this? | `evaluate` |
| Which fields of this record may they see? | `mask_fields` |
| Which records may they find at all? | `compile_query_filters` |

The third exists because the first cannot be asked about a record nobody has
fetched. A list endpoint cannot load every user and ask about each one, so the
policy is compiled into a filter and pushed into the query instead.

## A principal

Everything starts from a session: who is asking, and what they carry.

```pycon
>>> from pybac import (
...     MatchingPolicy, Policy, PolicyEvaluator,
...     SecurityContext, SessionContext, UserInfo,
... )

>>> policy = Policy.model_validate({
...     "Statement": [
...         {"Effect": "Allow", "Action": ["iam:user:read"]},
...         {"Effect": "Allow", "Action": ["iam:user:update"],
...          "Condition": {"Expr": {"script": "target.ownerId == req.userId"}}},
...         {"Effect": "RestrictFields", "Action": ["iam:user:read"],
...          "NotFields": ["salary"]},
...     ]
... })

>>> session = SessionContext(
...     user_id="U1",
...     instance="acme",
...     user_info=UserInfo(locale="fr"),
...     security_context=SecurityContext(
...         policies=[policy], security_groups=["engineering"]
...     ),
... )

```

`SecurityContext` requires its `policies`. An empty set grants nothing, so a
context left empty by accident refuses every request — requiring it means an
empty one is something you wrote.

## May they?

```pycon
>>> evaluator = PolicyEvaluator()
>>> read = MatchingPolicy(action="iam:user:read", resource="*")
>>> update = MatchingPolicy(action="iam:user:update", resource="*")

>>> mine = {"id": "U1", "ownerId": "U1", "name": "Ada", "salary": 90000}
>>> theirs = {"id": "U2", "ownerId": "U2", "name": "Bea", "salary": 85000}

>>> evaluator.evaluate(read, session, theirs)
True
>>> evaluator.evaluate(update, session, theirs)
False
>>> evaluator.evaluate(update, session, mine)
True

```

The `Expr` condition read `target.ownerId` from the record and `req.userId` from
the session. Anything the calling service knows can join them:

```pycon
>>> evaluator.evaluate(update, session, mine, {"tenant": {"frozen": True}})
True

```

A service context is addressed by name, so a policy could say
`!tenant.frozen` and the same call would refuse.

## What may they do?

Asking several questions about one record gives a capability map, ready to
serialise beside it:

```pycon
>>> evaluator.evaluate_capabilities({"read": read, "update": update}, session, mine)
{'read': True, 'update': True}

```

And over a list of records, each answered for itself:

```pycon
>>> for record in evaluator.evaluate_many_capabilities({"update": update}, session,
...                                                    [mine, theirs]):
...     print(record["id"], record["capabilities"])
U1 {'update': True}
U2 {'update': False}

```

## What may they see?

A `RestrictFields` statement withholds fields. It never grants access on its own
— it qualifies access some `Allow` has already given.

```pycon
>>> evaluator.fields_to_mask(read, session, theirs)
('salary',)

>>> evaluator.mask_fields(read, session, theirs)
{'id': 'U2', 'ownerId': 'U2', 'name': 'Bea', 'salary': '{****}'}

```

Replacing keeps the shape of the record. To drop the field instead:

```pycon
>>> from pybac import FieldMasking, MaskingStrategy
>>> evaluator.mask_fields(read, session, theirs,
...                       masking=FieldMasking(strategy=MaskingStrategy.OMIT))
{'id': 'U2', 'ownerId': 'U2', 'name': 'Bea'}

```

The record you pass is never modified, and a field the record does not have is
not invented.

Some fields are always kept, because masking them would leave the record
unrecognisable — `id`, `instance`, `createdAt`, `updatedAt`, `deleted`. Pass
`FieldMasking(system_fields=...)` to choose your own.

### When the name in the policy is not where the value lives

A policy may withhold `document:attributeId:Q2`, meaning "the entry in
`attributes` whose id is Q2" — a position only you know. A *translator* bridges
the two:

```pycon
>>> from pybac import MaskedPaths

>>> def attribute_paths(record, name):
...     wanted = name.rsplit(":", 1)[-1]
...     for index, attribute in enumerate(record.get("attributes", [])):
...         if attribute["id"] == wanted:
...             slot = f"attributes[{index}]"
...             return [MaskedPaths(omit=slot, replace=f"{slot}.value")]
...     return []

```

Register it under the family, and every field in that family finds it —
`document:attributeId:Q2` falls back to `document:attributeId`:

```pycon
>>> from pybac.masking import mask
>>> record = {"attributes": [{"id": "Q1", "value": "one"},
...                          {"id": "Q2", "value": "two"}]}

>>> mask(record, ["document:attributeId:Q2"],
...      translators={"document:attributeId": attribute_paths})["attributes"]
[{'id': 'Q1', 'value': 'one'}, {'id': 'Q2', 'value': '{****}'}]

```

Omitting removes the whole entry, and several removals in one pass do not
disturb each other's positions:

```pycon
>>> mask(record, ["document:attributeId:Q1"],
...      translators={"document:attributeId": attribute_paths},
...      masking=FieldMasking(strategy=MaskingStrategy.OMIT))["attributes"]
[{'id': 'Q2', 'value': 'two'}]

```

## What may they find?

When a condition depends on the record, it becomes a filter you push into your
own query:

```pycon
>>> from pprint import pprint

>>> grouped = Policy.model_validate({"Statement": [
...     {"Effect": "Allow", "Action": ["iam:user:read"],
...      "Condition": {"ForAnyValue:StringEquals": {"target:groups": "${req:groups}"}}},
... ]})
>>> browsing = SessionContext(
...     user_id="U1", instance="acme",
...     security_context=SecurityContext(
...         policies=[grouped], security_groups=["engineering", "design"]
...     ),
... )

>>> for filter_ in evaluator.compile_query_filters(read, browsing):
...     pprint(filter_.model_dump(mode="json"), sort_dicts=False)
{'key': 'groups', 'comparator': 'OVERLAPS', 'value': ['engineering', 'design']}

```

Two answers carry no filter at all, and they mean opposite things:

| Result | Meaning |
|---|---|
| `[]` | No restriction. Some statement grants this unconditionally. |
| a filter no record satisfies | Nothing is visible. No statement applies. |

```pycon
>>> open_policy = Policy.model_validate(
...     {"Statement": [{"Effect": "Allow", "Action": ["iam:user:read"]}]}
... )
>>> anyone = SessionContext(user_id="U1", instance="acme",
...                         security_context=SecurityContext(policies=[open_policy]))
>>> evaluator.compile_query_filters(read, anyone)
[]

>>> nobody = SessionContext(user_id="U1", instance="acme",
...                         security_context=SecurityContext(policies=[]))
>>> evaluator.compile_query_filters(read, nobody)[0].model_dump(mode="json")
{'key': 'id', 'comparator': 'EQ', 'value': '__INVALID__'}

```

A principal carrying no policies gets the second of these, and is refused by
`evaluate` as well. Permission comes from a statement; with none to grant it,
nothing is permitted and nothing is reachable.

### Records a principal owns

Policies often grant more on a principal's own records. That needs no special
machinery — it is a condition like any other, and statements are alternatives,
so it joins the rest by itself:

```pycon
>>> own_policy = Policy.model_validate({"Statement": [
...     {"Effect": "Allow", "Action": ["iam:user:read"],
...      "Condition": {"StringEquals": {"target:visibility": "public"}}},
...     {"Effect": "Allow", "Action": ["iam:user:read"],
...      "Condition": {"Expr": {"script": "target.ownerId == req.userId"}}},
... ]})
>>> owner = SessionContext(user_id="U1", instance="acme",
...                        security_context=SecurityContext(policies=[own_policy]))

>>> pprint(evaluator.compile_query_filters(read, owner)[0].model_dump(mode="json"),
...        sort_dicts=False)
{'comparator': 'OR',
 'value': [{'key': 'visibility', 'comparator': 'EQ', 'value': 'public'},
           {'key': 'ownerId', 'comparator': 'EQ', 'value': 'U1'}]}

```

Public records, or their own — and the same policy answers `evaluate` about a
single record, which a separate `read_own` action could not:

```pycon
>>> evaluator.evaluate(read, owner, {"ownerId": "U1", "visibility": "private"})
True
>>> evaluator.evaluate(read, owner, {"ownerId": "U2", "visibility": "private"})
False

```

## Using both together

The two query methods answer different questions, and a list endpoint normally
needs both.

`compile_query_filters` goes **policy → filter**: nobody asked for it, it is the
restriction the policy imposes. Which records exist for this principal at all.

`restrict_query_filters` goes **the caller's filters → safer filters**: you hand
it what someone typed into a search box, and it guards each one against the
fields they may not see.

```pycon
>>> from pybac import LeafFilter, QueryFilterComparator as Op

>>> guarded = Policy.model_validate({"Statement": [
...     {"Effect": "Allow", "Action": ["iam:user:read"],
...      "Condition": {"ForAnyValue:StringEquals": {"target:team": "${req:groups}"}}},
...     {"Effect": "RestrictFields", "Action": ["iam:user:read"],
...      "NotFields": ["salary"]},
... ]})
>>> searcher = SessionContext(user_id="U1", instance="acme",
...     security_context=SecurityContext(policies=[guarded], security_groups=["eng"]))

>>> asked = [LeafFilter(key="name", comparator=Op.MATCHES, value="A*"),
...          LeafFilter(key="salary", comparator=Op.GT, value=50000)]

>>> for filter_ in evaluator.restrict_query_filters(asked, read, searcher):
...     print(filter_.model_dump(mode="json"))
{'key': 'name', 'comparator': 'MATCHES', 'value': 'A*'}
{'key': 'salary', 'comparator': 'EQ', 'value': '__INVALID__'}

>>> for filter_ in evaluator.compile_query_filters(read, searcher):
...     print(filter_.model_dump(mode="json"))
{'key': 'team', 'comparator': 'OVERLAPS', 'value': ['eng']}

```

Send both, joined with `AND`:

```python
rows = db.find(
    evaluator.restrict_query_filters(asked, read, session)
    + evaluator.compile_query_filters(read, session)
)
```

Using only the first leaves the principal able to read records the policy never
granted. Using only the second leaves them able to *search* on a field they
cannot see — and a result count is an answer. Neither half is optional.

## Guarding a caller's filters

A principal who may not *see* a field must not be able to *search* on it either
— otherwise the answers reveal it. Pass your own filters through
`restrict_query_filters` before they reach the database:

```pycon
>>> from pybac import LeafFilter, QueryFilterComparator as Comparator

>>> asked = [
...     LeafFilter(key="name", comparator=Comparator.EQ, value="Ada"),
...     LeafFilter(key="salary", comparator=Comparator.GT, value=50000),
... ]
>>> for filter_ in evaluator.restrict_query_filters(asked, read, session):
...     print(filter_.model_dump(mode="json"))
{'key': 'name', 'comparator': 'EQ', 'value': 'Ada'}
{'key': 'salary', 'comparator': 'EQ', 'value': '__INVALID__'}

```

The filter on `name` passes; the one on `salary` is replaced with a filter no
record satisfies, so the search finds nothing rather than leaking through its
result count.

Fields withheld outright can also be listed up front, which is useful for
rejecting a request before it reaches the database:

```pycon
>>> evaluator.unsearchable_fields(session, read)
('salary',)

```

A field withheld only *under a condition* is searchable, because there are
records where it is visible.

## Why was it refused?

`evaluate` gives you a verdict. When it is not the verdict you expected,
`explain` gives you the reasoning:

```pycon
>>> gated = Policy.model_validate({"Statement": [
...     {"Sid": "readOwn", "Effect": "Allow", "Action": ["iam:user:read"],
...      "Condition": {"Expr": {"script": "target.ownerId == req.userId"}}},
...     {"Sid": "blockArchive", "Effect": "Deny", "Action": ["iam:user:*"],
...      "Condition": {"StringEquals": {"target:folder": "archive"}}},
... ]})
>>> auditor = SessionContext(user_id="U1", instance="acme",
...                          security_context=SecurityContext(policies=[gated]))

>>> print(evaluator.explain(read, auditor, {"ownerId": "U1", "folder": "plans"}))
allowed by Allow statement 'readOwn'

>>> print(evaluator.explain(read, auditor, {"ownerId": "U1", "folder": "archive"}))
refused by Deny statement 'blockArchive'

>>> print(evaluator.explain(read, auditor, {"ownerId": "U2", "folder": "plans"}))
refused: no statement allows it (1 would have, but for a condition)

```

That last line is the common case, and the detail is on the record:

```pycon
>>> decision = evaluator.explain(read, auditor, {"ownerId": "U2", "folder": "plans"})
>>> [entry.statement.sid for entry in decision.would_have_allowed]
['readOwn']

```

`readOwn` matched the action and the resource; only its condition failed. That
is almost always where a policy that "should work" has gone wrong.

The mirror image is also recorded. `would_have_denied` lists the `Deny`
statements that applied but whose condition did not hold — how close a permitted
request came to being refused:

```pycon
>>> decision = evaluator.explain(read, auditor, {"ownerId": "U1", "folder": "plans"})
>>> [entry.statement.sid for entry in decision.would_have_denied]
['blockArchive']

```

A `Decision` also carries `allowed`, `settled_by` (the effect that settled it,
or `None`), `statement`, and `considered` — every statement weighed, each with
whether it `applied` and whether its `condition_held`.

**Give your statements a `Sid`.** It is optional and nothing enforces it, but it
is the handle that makes a record readable, in a log or in an exception you hand
back to a caller.

`explain` is slower than `evaluate`, which stops at the first statement that
settles the matter, and it is never answered from the cache — a remembered
verdict has no reasoning attached. A test asserts the two always agree.

You get the same reasoning for free in the logs: a refusal is logged at debug
through `logging.getLogger("pybac")`, with the statement that caused it. The
record is only built when debug logging is actually enabled.

## Asking a human first

Some actions are permitted and still want a person to confirm them. That is a
third outcome, not a variant of the other two, and it belongs in the policy
rather than in a list of tool names somewhere in your code — because the rule
is usually conditional:

```pycon
>>> gated = Policy.model_validate({"Statement": [
...     {"Sid": "mayWrite", "Effect": "Allow", "Action": ["iam:user:write"]},
...     {"Sid": "bulkNeedsAHuman", "Effect": "RequireApproval",
...      "Action": ["iam:user:write"],
...      "Condition": {"NumericGreaterThan": {"target:affected": 100}}},
... ]})
>>> operator = SessionContext(user_id="U1", instance="acme",
...                           security_context=SecurityContext(policies=[gated]))
>>> write = MatchingPolicy(action="iam:user:write", resource="*")

>>> print(evaluator.explain(write, operator, {"affected": 5}))
allowed by Allow statement 'mayWrite'

>>> print(evaluator.explain(write, operator, {"affected": 5000}))
awaiting approval, required by statement 'bulkNeedsAHuman'

```

`RequireApproval` **qualifies an `Allow`; it grants nothing by itself** — the
same way `RestrictFields` does. A statement asking for approval on an action no
`Allow` permits leaves it refused.

Effects are weighed most-restrictive first: `Deny`, then `RequireApproval`, then
`Allow`.

### Reading the three outcomes

`evaluate` answers `False` for an action awaiting approval. That is deliberate:
a caller that knows nothing of approvals must not walk past one. To honour them,
read the record:

```pycon
>>> decision = evaluator.explain(write, operator, {"affected": 5000})
>>> decision.allowed, decision.approval_required
(False, True)

```

Which gives the three-way branch:

```python
decision = evaluator.explain(policy, session, record)
if decision.allowed:
    run()
elif decision.approval_required:
    ask_a_person(reason=str(decision))
else:
    refuse(reason=str(decision))
```

What the policy does **not** say: who may approve, how long an approval lasts,
or where it is recorded. That is workflow, and it belongs to you. The policy
says only *whether*.

## Remembering verdicts

Nothing is cached unless you ask. Caching trades freshness for speed: a policy
reading `req.currentTime` will be answered from whatever is remembered, and a
policy set that changes mid-request goes unnoticed.

A cache is anything with two methods. The key is built for you, over everything
a verdict depends on:

```pycon
>>> class Remembering:
...     def __init__(self):
...         self.entries = {}
...     def get(self, key):
...         return self.entries.get(key)
...     def set(self, key, decision):
...         self.entries[key] = decision

>>> cache = Remembering()
>>> cached = PolicyEvaluator(cache=cache)
>>> cached.evaluate(read, session, theirs)
True
>>> cached.evaluate(read, session, theirs)
True
>>> len(cache.entries)
1

```

For an expiring cache, wrap `cachetools.TTLCache` the same way. For one shared
between processes, put Redis behind the same two methods.

## When a policy is wrong

Loading is permissive on purpose. Refusing a whole policy set means refusing
*everything*, which is a worse failure than evaluating one malformed statement.
Check explicitly, wherever failing loudly is what you want — at deploy time, or
in a policy editor:

```pycon
>>> from pybac import PolicyError, validate_policies

>>> suspect = Policy.model_validate({"Statement": [
...     {"Effect": "Allow", "Action": ["a"], "NotAction": ["b"]},
... ]})
>>> try:
...     validate_policies([suspect])
... except PolicyError as error:
...     print(error)
invalidPolicy: policy[0].Statement[0]: Action and NotAction cannot both be set

```

One thing *is* refused at load: an `Effect` outside `Allow`, `Deny` and
`RestrictFields`. A statement reading `"deny"` would match nothing during the
deny pass and silently permit what it was written to forbid.

```pycon
>>> Policy.model_validate({"Statement": [{"Effect": "deny"}]})
Traceback (most recent call last):
    ...
pydantic_core._pydantic_core.ValidationError: ...

```

Everything else fails closed. A condition naming an operator nobody implements,
an expression that cannot be read, operands that cannot be compared — each is a
non-match, logged at debug through `logging.getLogger("pybac")`, and never an
exception escaping into your request.

```pycon
>>> broken = Policy.model_validate({"Statement": [
...     {"Effect": "Allow", "Action": ["iam:user:read"],
...      "Condition": {"Expr": {"script": "target.user.id hasManager req.userId"}}},
... ]})
>>> unlucky = SessionContext(user_id="U1", instance="acme",
...                          security_context=SecurityContext(policies=[broken]))
>>> evaluator.evaluate(read, unlucky, theirs)
False

```

## Further reading

- [how-it-works.md](how-it-works.md) — the policy flow, in three diagrams.
- [tool-calls.md](tool-calls.md) — authorizing a tool call an AI model chose.
- [conditions.md](conditions.md) — every condition, with an example of each.
- [behaviour.md](behaviour.md) — the sharp edges, gathered in one place.
- [adding-conditions.md](adding-conditions.md) — adding a named condition.
- [adding-operators.md](adding-operators.md) — extending the `Expr` language.
