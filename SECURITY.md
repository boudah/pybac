# Security policy

This is an authorization library. A bug here is not a crash — it is someone
seeing a record they should not. Please report anything of that kind privately.

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting**: the *Security* tab, then
*Report a vulnerability*. That opens a channel visible only to the maintainers.

Please do not open a public issue for a suspected bypass.

Useful things to include, as far as you have them:

- The policy, or the smallest version of it that still misbehaves.
- The session, record and service context it was evaluated against.
- Which call was involved — `evaluate`, `mask_fields`, `query_filters` or
  `restrict_query_filters`.
- What you expected, and what happened instead.

The output of `explain()` is usually the fastest way to show the problem.

## What counts

Anything that grants more than the policy says:

- A request allowed that no statement allows, or a `Deny` that fails to deny.
- A field readable through `mask_fields` or searchable through
  `restrict_query_filters` that a `RestrictFields` statement withholds.
- A `query_filters` result that matches records the policy excludes — including
  an empty list, which means *no restriction*, where a restriction was intended.
- An expression or condition that raises out of the library instead of being
  treated as a non-match, since a caller may convert that into something other
  than a refusal.

## What does not

- A policy that does not do what its author intended, where the library behaves
  as documented. Check [docs/behaviour.md](docs/behaviour.md) first — several
  surprises are deliberate and written down, notably the shared precedence of
  `&&` and `||`, and the direction `containsAll` reads.
- Anything requiring the attacker to supply the policies. A principal who can
  write their own policies has already been granted everything.

## Supported versions

Before 1.0, only the latest release.
