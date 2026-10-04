# How a policy becomes an answer

Three diagrams and a worked example. Everything that follows runs as part of the
test suite.

## One policy set, three answers

The same statements are read three different ways. Which effect is consulted,
and what comes out, depends on the question being asked.

```
                     a principal's policies
                                │
                                ▼
                    ┌───────────────────────┐
                    │   build the context   │
                    │  session + the record │
                    └───────────┬───────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          ▼                     ▼                     ▼
     evaluate()           mask_fields()        compile_query_filters()
          │                     │                     │
     reads Deny               reads             reads Allow,
     and Allow,          RestrictFields,      but compiles the
    settling the         collecting the      conditions instead
     conditions          withheld names       of settling them
          │                     │                     │
          ▼                     ▼                     ▼
      may they            what may they         what may they
       do it?                 see?                  find?
          │                     │                     │
          ▼                     ▼                     ▼
        bool              record minus           filter tree
                          those fields
```

The third column is the one that makes this worth doing. A condition that needs
the record — *"only records in my groups"* — cannot be settled about a record
nobody has fetched, so it is compiled into a filter and pushed into the query
instead. Same statement, read a different way.

## How a verdict is reached

`evaluate` makes three passes over the statements, from the most restrictive
effect to the least. The first match in a pass settles that pass.

```
  evaluate(matching_policy, session, target, service_context)
         │
         ├── principal carries no policies? ──────────────► refused
         │
         ├── a cache was given and remembers this? ───────► that verdict
         │
         ▼
  build the context
         │
         ▼
  ┌────────────────────────────────────────────────────┐
  │  pass 1 — any Deny statement applies?              │
  └───────────────────────┬────────────────────────────┘──── yes ──► refused
                          │ no
                          ▼
  ┌────────────────────────────────────────────────────┐
  │  pass 2 — any Allow statement applies?             │
  └───────────────────────┬────────────────────────────┘──── no  ──► refused
                          │ yes
                          ▼
  ┌────────────────────────────────────────────────────┐
  │  pass 3 — any RequireApproval statement applies?   │
  └───────────────────────┬────────────────────────────┘──── yes ──► awaiting approval
                          │ no
                          ▼
                       allowed
```

Three consequences worth holding on to. **A `Deny` always wins**, whatever order
the statements are written in. **Nothing grants by default** — the only way out
through the bottom is an `Allow` that applied. And **an approval is not a
refusal**: the action is permitted, and waiting on a person. `evaluate` reports
`False` for it, because a caller that knows nothing of approvals must not walk
past one; `explain` tells the two apart.

## Whether one statement applies

Each pass walks every statement in the order the policies list them. A statement
has to survive all of this:

```
   Effect is the one this pass looks for?     no ──┐
              │ yes                                │
   Action matches?                            no ──┤
              │ yes                                │
   NotAction matches?                        yes ──┤
              │ no                                 │   skip this
   Principal matches?                         no ──┤   statement
              │ yes                                │
   Resource matches, once ${...} is filled?   no ──┤
              │ yes                                │
   NotResource matches?                      yes ──┤
              │ no                                 │
   Condition holds?                           no ──┘
              │ yes
              ▼
      this statement applies
```

**An absent field is not a constraint.** A statement with no `Resource` applies
to every resource; one with no `Condition` applies unconditionally. Narrowing is
something you add, not something you remove.

**The last row is where the interesting part lives.** Everything above it
compares strings. The condition is where a policy reads the record, the
principal and whatever the service contributed — and it is the only row that can
fail for reasons a policy author did not intend, which is why
[`explain`](usage.md#why-was-it-refused) reports it separately.

## Watching it happen

```pycon
>>> from pybac import (MatchingPolicy, Policy, PolicyEvaluator,
...                    SecurityContext, SessionContext)

>>> policy = Policy.model_validate({"Statement": [
...     {"Sid": "readOwn", "Effect": "Allow", "Action": ["docs:document:read"],
...      "Condition": {"Expr": {"script": "target.ownerId == req.userId"}}},
...     {"Sid": "blockArchive", "Effect": "Deny", "Action": ["docs:document:*"],
...      "Condition": {"StringEquals": {"target:folder": "archive"}}},
...     {"Sid": "hidePay", "Effect": "RestrictFields",
...      "Action": ["docs:document:read"], "NotFields": ["budget"]},
... ]})
>>> session = SessionContext(user_id="U1", instance="acme",
...                          security_context=SecurityContext(policies=[policy]))
>>> evaluator = PolicyEvaluator()
>>> read = MatchingPolicy(action="docs:document:read", resource="*")

```

Their own record, in an ordinary folder — pass 1 finds no `Deny` that applies,
pass 2 finds `readOwn`:

```pycon
>>> mine = {"id": "D1", "ownerId": "U1", "folder": "plans", "budget": 40000}
>>> print(evaluator.explain(read, session, mine))
allowed by Allow statement 'readOwn'

```

The same record once it is archived — pass 1 now finds `blockArchive`, and pass
2 never runs:

```pycon
>>> archived = {**mine, "folder": "archive"}
>>> print(evaluator.explain(read, session, archived))
refused by Deny statement 'blockArchive'

```

`readOwn` still holds for that record. It loses anyway, which is what "a `Deny`
always wins" means in practice:

```pycon
>>> decision = evaluator.explain(read, session, archived)
>>> [entry.statement.sid for entry in decision.considered if entry.settled]
['blockArchive', 'readOwn']

```

The second question, read off the same policies — `hidePay` never granted
anything, and only now has a say:

```pycon
>>> evaluator.mask_fields(read, session, mine)
{'id': 'D1', 'ownerId': 'U1', 'folder': 'plans', 'budget': '{****}'}

```

And the third, with no record at all. `readOwn`'s condition is compiled rather
than settled:

```pycon
>>> evaluator.compile_query_filters(read, session)[0].model_dump(mode="json")
{'key': 'ownerId', 'comparator': 'EQ', 'value': 'U1'}

```

## Where each piece lives

| Step | Module |
|---|---|
| Building the context | `pybac.evaluator` |
| Filling `${...}` in resources and conditions | `pybac.interpolation` |
| Matching action, resource and principal | `pybac.processor` + `pybac.conditions.patterns` |
| Settling a named condition | `pybac.conditions.operators` |
| Settling an `Expr` condition | `pybac.expression.evaluator` |
| Compiling a condition into a filter | `pybac.conditions.filters` + `pybac.expression.compiler` |
| Assembling the filter tree | `pybac.query` |
| Hiding fields | `pybac.masking` |

## See also

- [usage.md](usage.md) — the guide.
- [conditions.md](conditions.md) — every condition, with an example of each.
- [tool-calls.md](tool-calls.md) — authorizing a tool call an AI model chose.
- [behaviour.md](behaviour.md) — the sharp edges.
