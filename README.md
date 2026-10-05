# pybac

[![PyPI](https://img.shields.io/pypi/v/pybac.svg)](https://pypi.org/project/pybac/)
[![Python versions](https://img.shields.io/pypi/pyversions/pybac.svg)](https://pypi.org/project/pybac/)
[![CI](https://github.com/boudah/pybac/actions/workflows/ci.yml/badge.svg)](https://github.com/boudah/pybac/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](https://github.com/boudah/pybac/actions/workflows/ci.yml)
[![Licence](https://img.shields.io/pypi/l/pybac.svg)](LICENSE)

Access control starts as `if user.is_admin`. Eighteen months later it is a
600-line module that four people understood, three of whom have left, and
nobody edits it on a Friday.

The usual next step helps, for a while. Give the resource its own check —
`can_edit(user, document)`, a roles table, a `permissions` column — and the
booleans at least have names. Then the rules stop being about the user and
start being about the record. *Editors may edit, but only in their own
department, and only before publication, and Legal may always, and that one
customer negotiated an exception.* Now every check has an `if` inside it, the
roles table has a `scope` column nobody can explain, and changing who may do
what requires a deploy.

The rules were never static. They differ per customer, they change on a
Tuesday afternoon because someone asked, and the interesting ones are
conditions on the data itself. So write them down as data, and evaluate them at
runtime:

```json
{"Effect": "Allow", "Action": ["docs:document:read"],
 "Condition": {"Expr": {"script": "target.ownerId == req.userId"}}}
```

That is policy-based access control. Policies live wherever you keep them — a
database, a config service, a column on the tenant — and change without
shipping anything.

```sh
pip install pybac      # or: uv add pybac
```

## Three questions, not one

The reason permissions sprawl is that "may they?" looks like one question and
is really three. Only the first is easy.

**May they do this?** One principal, one action, one record. Every library does
this one. Fine.

**Which fields may they see?** Usually answered in the frontend, by not
rendering them — which is not an answer, as anyone who has opened the network
tab can confirm.

**Which records may they find?** The one that quietly breaks everything,
because you cannot ask it about records you have not fetched yet. So the list
endpoint loads ten thousand rows, checks each one in Python, returns sixteen,
and you tell yourself you will fix it later. That is not a permission system.
It is a denial-of-service with extra steps.

pybac answers all three from the same policies. The third by compiling the
policy into a filter you push into your own query, so the database returns the
sixteen and never mentions the other nine thousand nine hundred and eighty-four.

Everything fails closed: a condition it cannot settle is a refusal, not an
exception, and never an accidental yes.

```python
from pybac import MatchingPolicy, PolicyEvaluator

evaluator = PolicyEvaluator()
policy = MatchingPolicy(action="iam:user:read", resource="*")

evaluator.evaluate(policy, session, user)          # may they?
evaluator.mask_fields(policy, session, user)       # what may they see?
evaluator.compile_query_filters(policy, session)           # what may they find?
evaluator.explain(policy, session, user)           # ...and why?
```

## Status

First release. Everything below works, is covered by tests, and is documented —
but this is `0.1.0`, and the shape of the API is still settling. **Pin an exact
version** if a rename would hurt you.

| | |
|---|---|
| `pybac.domain` | policies, principals, contexts, compiled query filters |
| `pybac.expression` | the language `Expr` conditions are written in: lexer, parser, evaluator |
| `pybac.conditions` | the named conditions a statement can carry, and wildcard matching |
| `pybac.interpolation` | filling `${...}` placeholders from the context |
| `pybac.processor` | matching statements to a request, settling their conditions, and compiling them into query filters |
| `pybac.masking` | hiding the fields of a resource a principal may not see |
| `pybac.evaluator` | `PolicyEvaluator`, the public face of all of it |

Released under the [ISC licence](LICENSE). Found an authorization bypass?
[SECURITY.md](SECURITY.md) has a private channel for it.

## Reading

- [docs/how-it-works.md](docs/how-it-works.md) — the policy flow, in three
  diagrams.
- [docs/usage.md](docs/usage.md) — the guide: every example on the page runs as
  part of the test suite.
- [docs/tool-calls.md](docs/tool-calls.md) — authorizing a tool call an AI
  model chose, with a pydantic-ai sample.
- [docs/conditions.md](docs/conditions.md) — every condition a statement can
  name, with an example of each.
- [docs/behaviour.md](docs/behaviour.md) — the sharp edges: what surprises
  people, and the two places a policy can read one way and behave another.
- [docs/adding-operators.md](docs/adding-operators.md) — extending the
  expression language.
- [docs/adding-conditions.md](docs/adding-conditions.md) — adding a named
  condition a statement can carry.

## Development

```sh
uv sync
uv run pytest
uv run pytest --cov=pybac     # every line is covered, and stays that way
uv run ruff check src tests
uv run mypy
uv build                      # sdist + wheel
```

CI runs the lot across Python 3.11 to 3.14 on every push.
