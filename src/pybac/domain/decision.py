"""The record of how a verdict was reached.

A bare ``True`` or ``False`` is enough to enforce a decision and useless for
understanding one. When a request is refused, the question that follows is
always the same -- *why?* -- and the answer is usually that a statement would
have allowed it but its condition did not hold.

A :class:`Decision` carries that: which statement settled the matter, and what
else was considered on the way.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pybac.domain.policy import PolicyEffect, PolicyStatement

__all__ = ["Considered", "Decision"]


@dataclass(frozen=True)
class Considered:
    """One statement that was weighed, and how far it got."""

    statement: PolicyStatement
    #: Whether the action, resource and principal matched. A statement that
    #: does not apply was never about this request.
    applied: bool
    #: Whether its condition held. ``None`` when it was never reached, because
    #: the statement did not apply in the first place.
    condition_held: bool | None

    @property
    def settled(self) -> bool:
        """Whether this statement had its say."""
        return self.applied and self.condition_held is True

    @property
    def missed_by_condition(self) -> bool:
        """Whether it would have applied, but for its condition.

        The most useful thing to know about a refusal.
        """
        return self.applied and self.condition_held is False


@dataclass(frozen=True)
class Decision:
    """Why a request was allowed or refused."""

    allowed: bool
    #: What settled it: a `Deny` that matched, an `Allow` that matched, or
    #: ``None`` when nothing applied at all.
    settled_by: PolicyEffect | None = None
    #: The statement that settled it, if one did.
    statement: PolicyStatement | None = None
    #: Every statement weighed, in the order policies list them.
    considered: tuple[Considered, ...] = field(default_factory=tuple)

    @property
    def approval_required(self) -> bool:
        """Whether this was permitted, but awaits a human.

        Distinct from a refusal: the policy grants the action, and a statement
        asks for a person to confirm it. :attr:`allowed` stays ``False`` until
        that happens.
        """
        return self.settled_by is PolicyEffect.REQUIRE_APPROVAL

    @property
    def would_have_allowed(self) -> tuple[Considered, ...]:
        """`Allow` statements that applied, but whose condition did not hold.

        Where to look first when a request is refused and its author expected
        otherwise.
        """
        return self._missed(PolicyEffect.ALLOW)

    @property
    def would_have_denied(self) -> tuple[Considered, ...]:
        """`Deny` statements that applied, but whose condition did not hold.

        How close a permitted request came to being refused.
        """
        return self._missed(PolicyEffect.DENY)

    def _missed(self, effect: PolicyEffect) -> tuple[Considered, ...]:
        return tuple(
            entry
            for entry in self.considered
            if entry.missed_by_condition and entry.statement.effect is effect
        )

    def __str__(self) -> str:
        if self.statement is not None:
            named = f" {self.statement.sid!r}" if self.statement.sid else ""
            if self.approval_required:
                return f"awaiting approval, required by statement{named}"
            verb = "allowed" if self.allowed else "refused"
            return f"{verb} by {self.settled_by} statement{named}"
        missed = len(self.would_have_allowed)
        if missed:
            return (
                f"refused: no statement allows it "
                f"({missed} would have, but for a condition)"
            )
        return "refused: no statement allows it"
