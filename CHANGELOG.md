# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-05

First release.

### Added

- `PolicyEvaluator`, answering three questions from one policy set: may a
  principal do this (`evaluate`), which fields may they see (`mask_fields`), and
  which records may they find (`query_filters`).
- Four statement effects: `Allow`, `Deny`, `RequireApproval` and
  `RestrictFields`, weighed most-restrictive first. The last two qualify an
  access rather than granting one.
- `explain`, returning why a request was allowed or refused — the statement that
  settled it, and the ones that would have applied but for their condition.
- `evaluate_capabilities` and `evaluate_many_capabilities`, for answering
  several questions about one record or one question about several.
- `restrict_query_filters`, so a caller's own filters cannot reach a field the
  principal may not see.
- 27 named conditions, each with the derived `IfExists`, `ForAnyValue:` and
  `ForAllValues:` variants.
- An expression language for `Expr` conditions, read two ways: settled against a
  record, or compiled into a query filter when there is no record yet.
- Field masking, by replacement or omission, with translators for fields whose
  name in a policy is not where the value sits.
- Optional verdict caching behind a two-method protocol.

### Query filter vocabulary

Comparators are words, not symbols, so a filter survives a query string without
escaping. The three that take a collection are named for *which side* holds it,
because reading that backwards inverts the policy:

| | |
|---|---|
| `IN` | the field holds one value, among those given |
| `OVERLAPS` | the field holds a list sharing a value with those given |
| `SUBSET_OF` | the field holds a list, every value of it among those given |

### Notes

- A principal carrying no policies is refused. Permission is granted by a
  statement, and there is none.
- Everything fails closed: a condition that cannot be settled is a non-match,
  logged rather than raised.
- Documented behaviour that surprises people is gathered in
  [docs/behaviour.md](docs/behaviour.md).

[Unreleased]: https://github.com/boudah/pybac/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/boudah/pybac/releases/tag/v0.1.0
