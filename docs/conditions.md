# Conditions

Every condition a policy statement can name, with an example of each. As with
the rest of the docs, the examples run as part of the test suite.

A statement qualifies itself with a `Condition` block:

```json
{
  "Effect": "Allow",
  "Action": ["iam:user:read"],
  "Condition": {"StringEquals": {"target:data:status": "goal"}}
}
```

The key names the condition. Inside it, the key names *where to look* in the
context and the value is *what to look for*.

```pycon
>>> from pybac.conditions import CONDITIONS

>>> def holds(name, found, written):
...     return CONDITIONS[name](found, written)

```

## Three rules that apply to all of them

**A type mismatch is a non-match, in both directions.** `NumericEquals` against
a string is false, and so is `NumericNotEquals` — neither has compared anything,
so neither claims a result.

```pycon
>>> holds("NumericEquals", "2", 2), holds("NumericNotEquals", "2", 2)
(False, False)

```

**Several values mean *any* of them.** `{"StringEquals": {"target:status":
["draft", "review"]}}` holds if the status is either.

**A value may be a placeholder.** `"${req:userId}"` is filled from the context
before the comparison, and a placeholder resolving to a list expands into the
several values to accept. See [usage.md](usage.md).

## Strings

| Condition | Holds when the found value |
|---|---|
| `StringEquals` | is exactly the written one |
| `StringNotEquals` | is a string, and a different one |
| `StringEqualsIgnoreCase` | matches ignoring case |
| `StringNotEqualsIgnoreCase` | differs ignoring case |
| `StringLike` | matches the pattern — `*` for any run, `?` for one character |
| `StringNotLike` | is a string that does not match the pattern |

```pycon
>>> holds("StringEquals", "goal", "goal")
True
>>> holds("StringNotEquals", "goal", "draft")
True
>>> holds("StringEqualsIgnoreCase", "GOAL", "goal")
True
>>> holds("StringNotEqualsIgnoreCase", "GOAL", "draft")
True
>>> holds("StringLike", "docs:folder:read", "docs:folder:*")
True
>>> holds("StringNotLike", "iam:user:read", "docs:*")
True

```

Only `*` and `?` are special in a pattern. Everything else is literal, so a `.`
matches a dot and nothing else.

```pycon
>>> holds("StringLike", "a.b", "a.b"), holds("StringLike", "axb", "a.b")
(True, False)

```

## Numbers

Six comparisons, all of which require both sides to be real numbers. **A boolean
is not a number** — Python counts `True` as `1`, and a condition about a
quantity should not be satisfied by a flag.

```pycon
>>> holds("NumericEquals", 2, 2)
True
>>> holds("NumericNotEquals", 2, 3)
True
>>> holds("NumericLessThan", 1, 2)
True
>>> holds("NumericLessThanEquals", 2, 2)
True
>>> holds("NumericGreaterThan", 3, 2)
True
>>> holds("NumericGreaterThanEquals", 2, 2)
True
>>> holds("NumericEquals", True, 1)
False

```

## Dates

The same six comparisons over ISO 8601 timestamps. A timestamp with no offset is
read as UTC. Anything unparseable — including an epoch number — is a non-match
rather than an error.

```pycon
>>> holds("DateEquals", "2024-01-02T00:00:00Z", "2024-01-02T02:00:00+02:00")
True
>>> holds("DateNotEquals", "2024-01-02", "2024-01-03")
True
>>> holds("DateLessThan", "2024-01-02", "2024-01-03")
True
>>> holds("DateLessThanEquals", "2024-01-02", "2024-01-02")
True
>>> holds("DateGreaterThan", "2024-01-03", "2024-01-02")
True
>>> holds("DateGreaterThanEquals", "2024-01-02", "2024-01-02")
True
>>> holds("DateLessThan", 0, 1)
False

```

Comparing against the moment of the request uses `req:currentTime`, which the
evaluator sets:

```json
{"Condition": {"DateLessThan": {"req:currentTime": "2027-01-01T00:00:00Z"}}}
```

## Booleans and absence

`Bool` accepts a boolean written either as one or as the word, which is what
arrives when a flag has been through a query string.

```pycon
>>> holds("Bool", True, True)
True
>>> holds("Bool", "true", True)
True
>>> holds("Bool", True, False)
False
>>> holds("Bool", 1, True)
False

```

`Null` asks whether the context has a value at all. A key that is missing and a
key explicitly set to null are one state — data arriving as JSON gives no way to
tell them apart.

```pycon
>>> holds("Null", None, True)
True
>>> holds("Null", "present", False)
True
>>> holds("Null", "present", True)
False

```

## Addresses

`IpAddress` takes a single address or a CIDR range. Both sides must be readable,
so an unparseable address matches neither condition.

```pycon
>>> holds("IpAddress", "192.168.0.7", "192.168.0.0/24")
True
>>> holds("IpAddress", "192.168.0.7", "192.168.0.7")
True
>>> holds("NotIpAddress", "10.0.0.1", "192.168.0.0/24")
True
>>> holds("IpAddress", "::1", "::1/128")
True
>>> holds("IpAddress", "not an address", "192.168.0.0/24")
False

```

These describe the caller, not the record, so they cannot be turned into a query
filter — see [as query filters](#as-query-filters) below.

## Sets

| Condition | Holds when |
|---|---|
| `InValues` | the found value is one of those written |
| `NotInValues` | it is not |
| `ContainsAtLeastOne` | the two collections share a value |
| `ContainsNone` | they share none |
| `ContainsAll` | **everything found is among those written** |

```pycon
>>> holds("InValues", "G1", ["G1", "G2"])
True
>>> holds("NotInValues", "G9", ["G1", "G2"])
True
>>> holds("ContainsAtLeastOne", ["G1", "G9"], ["G1", "G2"])
True
>>> holds("ContainsNone", ["G9"], ["G1", "G2"])
True
>>> holds("ContainsAll", ["G1"], ["G1", "G2"])
True

```

**`ContainsAll` reads backwards.** It asks whether the found collection is
wholly contained *by* the written one, not whether it holds everything written:

```pycon
>>> holds("ContainsAll", ["G1", "G2"], ["G1"])
False

```

A bare value counts as a collection of one on either side, so a policy need not
wrap a single group in a list.

```pycon
>>> holds("ContainsAtLeastOne", "G1", ["G1", "G2"])
True

```

## The three variants

Every condition above gains three more, for free. 27 conditions become 108.

| Variant | Asks |
|---|---|
| `<name>IfExists` | the same, but holds when the context has no value |
| `ForAnyValue:<name>` | *some* found value matches *some* written value |
| `ForAllValues:<name>` | *every* found value matches some written value |

```pycon
>>> holds("StringEqualsIfExists", None, "goal")
True
>>> holds("StringEqualsIfExists", "draft", "goal")
False

>>> holds("ForAnyValue:StringEquals", ["G1", "G9"], ["G1", "G2"])
True
>>> holds("ForAnyValue:StringEquals", ["G8", "G9"], ["G1", "G2"])
False

>>> holds("ForAllValues:StringEquals", ["G1", "G2"], ["G1", "G2"])
True
>>> holds("ForAllValues:StringEquals", ["G1", "G9"], ["G1", "G2"])
False

```

Nothing to check means nothing failed, so `ForAllValues` over an empty
collection holds and `ForAnyValue` does not:

```pycon
>>> holds("ForAllValues:StringEquals", [], ["G1"])
True
>>> holds("ForAnyValue:StringEquals", [], ["G1"])
False

```

The variants carry the comparison of the condition underneath, so
`ForAnyValue:StringLike` matches patterns:

```pycon
>>> holds("ForAnyValue:StringLike", ["docs:folder:read"], ["docs:*"])
True

```

## As query filters

Every condition compiles to a filter too, so it can narrow a query rather than
judge a record that has already been fetched.

```pycon
>>> from pybac.conditions import FILTERS

>>> def compiles_to(name, values):
...     for built in FILTERS[name]("field", values):
...         return built.model_dump(mode="json")

>>> compiles_to("StringEquals", ["goal"])
{'key': 'field', 'comparator': 'EQ', 'value': 'goal'}
>>> compiles_to("StringLike", ["acme-*"])
{'key': 'field', 'comparator': 'MATCHES', 'value': 'acme-*'}
>>> compiles_to("NumericLessThan", [5])
{'key': 'field', 'comparator': 'LT', 'value': 5}
>>> compiles_to("ContainsAtLeastOne", ["G1", "G2"])
{'key': 'field', 'comparator': 'OVERLAPS', 'value': ['G1', 'G2']}
>>> compiles_to("ForAnyValue:StringEquals", ["G1"])
{'key': 'field', 'comparator': 'OVERLAPS', 'value': ['G1']}
>>> compiles_to("ForAllValues:StringEquals", ["G1"])
{'key': 'field', 'comparator': 'SUBSET_OF', 'value': ['G1']}

```

Two things change shape here. A comparison against a single value takes the
first of several, because a field holds one value — the alternatives a verdict
would accept have nowhere to go. And the quantifiers become questions about the
field's contents, whatever the condition underneath compares.

A condition that restricts but describes nothing about the record compiles to a
filter no record satisfies, rather than to nothing — because contributing no
filter would leave the query unrestricted:

```pycon
>>> compiles_to("IpAddress", ["10.0.0.0/8"])
{'key': 'id', 'comparator': 'EQ', 'value': '__INVALID__'}

```

## Beyond these

For anything the named conditions cannot express, `Expr` takes an expression:

```json
{"Condition": {"Expr": {"script": "target.ownerId == req.userId"}}}
```

See [usage.md](usage.md) for what an expression can read, and
[adding-operators.md](adding-operators.md) for extending its vocabulary.

## See also

- [how-it-works.md](how-it-works.md) — where a condition sits in the flow.
- [behaviour.md](behaviour.md) — the sharp edges.
- [adding-conditions.md](adding-conditions.md) — adding one of your own.
