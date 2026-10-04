"""Policies, and the request being matched against them.

A :class:`Policy` is a document attached to a principal. A
:class:`MatchingPolicy` is what is asked of it: this action, on this
resource, for this principal. Statement fields keep their PascalCase names on
the wire and are reachable by snake_case attribute in Python.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, model_validator
from pydantic.alias_generators import to_pascal

from pybac.errors import PolicyError

__all__ = [
    "MatchingPolicy",
    "Policy",
    "PolicyEffect",
    "PolicyStatement",
    "PolicyStatementCondition",
    "validate_policies",
]

PolicyStatementCondition = dict[str, dict[str, Any]]

#: Statement fields that may not both appear on one statement.
_EXCLUSIVE_PAIRS: tuple[tuple[str, str], ...] = (
    ("Action", "NotAction"),
    ("Resource", "NotResource"),
    ("Principal", "NotPrincipal"),
    ("Fields", "NotFields"),
)

_KNOWN_STATEMENT_KEYS = frozenset(
    {
        "Sid",
        "Effect",
        "Action",
        "NotAction",
        "Resource",
        "NotResource",
        "Fields",
        "NotFields",
        "Principal",
        "Condition",
    }
)


class PolicyEffect(StrEnum):
    """What a matching statement does.

    Two of these qualify an access rather than granting one. A statement that
    withholds fields, or one that asks a human first, has nothing to say about
    an action no `Allow` permitted in the first place.

    `Deny` outranks `RequireApproval`, which outranks `Allow`: the most
    restrictive applicable statement decides.
    """

    ALLOW = "Allow"
    DENY = "Deny"
    #: Permitted, but only once a human says so. Qualifies an `Allow`; grants
    #: nothing by itself.
    REQUIRE_APPROVAL = "RequireApproval"
    RESTRICT_FIELDS = "RestrictFields"


class PolicyStatement(BaseModel):
    """One rule within a policy.

    Every field but ``Effect`` is optional, and an absent field is not a
    constraint: a statement with no ``Resource`` matches any resource. This is
    why ``Effect`` is typed as an enum rather than a string -- a statement
    reading ``"deny"`` instead of ``"Deny"`` would otherwise match nothing and
    silently grant what it was written to forbid.
    """

    model_config = ConfigDict(
        alias_generator=to_pascal,
        populate_by_name=True,
        frozen=True,
        extra="allow",
    )

    sid: str | None = None
    effect: PolicyEffect
    action: list[str] | None = None
    not_action: list[str] | None = None
    resource: str | list[str] | None = None
    not_resource: str | list[str] | None = None
    fields: list[str] | None = None
    not_fields: list[str] | None = None
    principal: dict[str, Any] | None = None
    condition: PolicyStatementCondition | None = None

    @model_validator(mode="after")
    def _check_schema(self, info: ValidationInfo) -> Self:
        context = info.context or {}
        if context.get("strict_schema"):
            problems = self.schema_problems()
            if problems:
                raise ValueError("; ".join(problems))
        return self

    def schema_problems(self) -> list[str]:
        """Report constraints that are not enforced when loading.

        Loading stays permissive so that one malformed statement cannot make a
        whole policy set unloadable, which for an evaluator means denying
        everything. Call this to check a policy set before you rely on it, or
        validate with ``context={"strict_schema": True}``.
        """
        # Declared fields carry snake_case names; extras keep the key as given.
        present = {
            to_pascal(name)
            for name in type(self).model_fields
            if name != "effect" and getattr(self, name) is not None
        }
        present |= set(self.__pydantic_extra__ or {})

        problems = [
            f"{left} and {right} cannot both be set"
            for left, right in _EXCLUSIVE_PAIRS
            if left in present and right in present
        ]
        unknown = sorted(present - _KNOWN_STATEMENT_KEYS)
        problems.extend(f"unknown statement field {name!r}" for name in unknown)
        return problems


class Policy(BaseModel):
    """A set of statements attached to a principal."""

    model_config = ConfigDict(
        alias_generator=to_pascal,
        populate_by_name=True,
        frozen=True,
        extra="allow",
    )

    version: str | None = None
    statement: list[PolicyStatement] = Field(default_factory=list)


class MatchingPolicy(BaseModel):
    """What is being attempted: this action, on this resource, by this principal.

    ``context`` is filled in by the evaluator just before matching; callers
    supply the rest.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: str
    resource: str = ""
    effect: PolicyEffect | None = None
    principal: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] | None = None

    def with_effect(self, effect: PolicyEffect) -> MatchingPolicy:
        return self.model_copy(update={"effect": effect})

    def with_context(self, context: dict[str, Any]) -> MatchingPolicy:
        return self.model_copy(update={"context": context})


def validate_policies(policies: list[Policy]) -> None:
    """Raise :class:`PolicyError` if any statement breaks a schema constraint.

    Loading a policy never raises on these, so that a single bad statement
    cannot deny everything. Call this where failing loudly is what you want --
    at deploy time, or in a policy editor.
    """
    problems = [
        f"policy[{policy_index}].Statement[{statement_index}]: {problem}"
        for policy_index, policy in enumerate(policies)
        for statement_index, statement in enumerate(policy.statement)
        for problem in statement.schema_problems()
    ]
    if problems:
        raise PolicyError("invalidPolicy", problems)
