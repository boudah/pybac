"""Deciding whether a set of policies permits a request.

A policy is a list of statements. A statement says what it applies to -- an
action, a resource, a principal -- and what it does when it applies. Asking a
matching_policy means finding the statements that match it.

Two passes settle a verdict. Any matching `Deny` refuses outright; only then is
a matching `Allow` looked for. A statement that matches nothing in particular
matches everything: a statement with no `Resource` applies to every resource.

A condition the evaluator cannot settle -- an unreadable expression, an operator
with no implementation, operands that cannot be compared -- is a non-match, and
is logged. It never raises out of here, and it never counts as a match, so an
unsettled condition denies rather than permits.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Final

from pybac._types import as_list
from pybac.conditions import CONDITIONS, FILTERS, matches
from pybac.domain.decision import Considered, Decision
from pybac.domain.policy import (
    MatchingPolicy,
    Policy,
    PolicyEffect,
    PolicyStatement,
    PolicyStatementCondition,
)
from pybac.domain.query_filter import UNSATISFIABLE, QueryFilter
from pybac.expression import Evaluator, parse
from pybac.expression.compiler import FilterCompiler, Outcome
from pybac.expression.nodes import Node
from pybac.interpolation import fill_condition_values, fill_text, resolve_path

__all__ = ["MatchingStatements", "PolicyProcessor", "statements"]

_LOGGER: Final = logging.getLogger("pybac")

#: Conditions handed the whole set of policy values at once, rather than being
#: asked about each in turn.
_SET_CONDITIONS: Final = frozenset(
    {"ContainsAtLeastOne", "ContainsNone", "ContainsAll"}
)
_QUANTIFIERS: Final = frozenset({"ForAnyValue", "ForAllValues"})

#: The key naming an expression is arbitrary; stored policies use both of these.
_EXPRESSION = "Expr"

#: How a condition names the record it is about.
_TARGET_PREFIX = "target"


@dataclass(frozen=True)
class MatchingStatements:
    """The statements that apply, before their conditions are weighed."""

    all: tuple[PolicyStatement, ...]
    conditional: tuple[PolicyStatement, ...]

    @property
    def every_one_conditional(self) -> bool:
        """Whether every applicable statement carries a condition.

        When one does not, access is unconditional and there is nothing to
        compile into a query filter.
        """
        return len(self.all) == len(self.conditional)


def statements(policies: Iterable[Policy]) -> list[PolicyStatement]:
    """Every statement across ``policies``, in order."""
    return [statement for policy in policies for statement in policy.statement]


@lru_cache(maxsize=1024)
def _compiled(script: str) -> Node | None:
    """Parse once and keep it.

    The tree is shared between calls. Nothing that evaluates one mutates it.
    """
    return parse(script)


class PolicyProcessor:
    """Decides what a policy set permits."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or _LOGGER

    # -- verdicts --------------------------------------------------------

    def evaluate(
        self, policies: Sequence[Policy], matching_policy: MatchingPolicy
    ) -> bool:
        """Whether ``policies`` permit ``matching_policy`` outright.

        A `Deny` always wins, and an action still awaiting approval is not yet
        permitted -- so this answers ``False`` for it. A caller that means to
        honour approvals reads :meth:`explain` instead, which distinguishes
        "refused" from "not yet". Answering ``True`` here would let a caller
        that knows nothing of approvals walk straight past one.

        Stops at the first statement that settles the matter.
        """
        if self._find_match(policies, matching_policy, PolicyEffect.DENY) is not None:
            return False
        if self._find_match(policies, matching_policy, PolicyEffect.ALLOW) is None:
            return False
        return (
            self._find_match(policies, matching_policy, PolicyEffect.REQUIRE_APPROVAL)
            is None
        )

    def explain(
        self, policies: Sequence[Policy], matching_policy: MatchingPolicy
    ) -> Decision:
        """The same verdict, with the reasoning kept.

        Every statement is weighed rather than stopping at the first that
        settles the matter, so the record can show what else came close.
        """
        denying, denied = self._weigh(policies, matching_policy, PolicyEffect.DENY)
        allowing, allowed = self._weigh(policies, matching_policy, PolicyEffect.ALLOW)
        gating, gated = self._weigh(
            policies, matching_policy, PolicyEffect.REQUIRE_APPROVAL
        )
        considered = tuple(denied + allowed + gated)

        if denying is not None:
            return Decision(
                allowed=False,
                settled_by=PolicyEffect.DENY,
                statement=denying,
                considered=considered,
            )
        if allowing is None:
            return Decision(allowed=False, considered=considered)
        if gating is not None:
            # Permitted, but not yet: a human has to say so.
            return Decision(
                allowed=False,
                settled_by=PolicyEffect.REQUIRE_APPROVAL,
                statement=gating,
                considered=considered,
            )
        return Decision(
            allowed=True,
            settled_by=PolicyEffect.ALLOW,
            statement=allowing,
            considered=considered,
        )

    def _weigh(
        self,
        policies: Sequence[Policy],
        matching_policy: MatchingPolicy,
        effect: PolicyEffect,
    ) -> tuple[PolicyStatement | None, list[Considered]]:
        """Every statement of one effect, and the first that settled the matter."""
        asked = matching_policy.with_effect(effect)
        context = asked.context or {}
        settled: PolicyStatement | None = None
        weighed: list[Considered] = []

        for statement in statements(policies):
            if statement.effect is not effect:
                continue
            applied = self._applies(statement, asked, weigh_condition=False)
            held = self.holds(statement.condition, context) if applied else None
            weighed.append(
                Considered(statement=statement, applied=applied, condition_held=held)
            )
            if settled is None and applied and held:
                settled = statement
        return settled, weighed

    def fields_to_mask(
        self, policies: Sequence[Policy], matching_policy: MatchingPolicy
    ) -> tuple[str, ...]:
        """The fields this principal may not see, in the order policies name them.

        A statement withholds fields with `NotFields`. Another statement may give
        one back by naming it in `Fields`, so every applicable statement is
        collected before the two are reconciled.
        """
        restricting = matching_policy.with_effect(PolicyEffect.RESTRICT_FIELDS)
        applicable = [
            statement
            for statement in statements(policies)
            if self._applies(statement, restricting, weigh_condition=True)
        ]

        masked: dict[str, None] = {}
        for statement in applicable:
            for field in statement.not_fields or ():
                masked[field] = None
        for statement in applicable:
            for field in statement.fields or ():
                masked.pop(field, None)
        return tuple(masked)

    def has_field_security(
        self,
        policies: Sequence[Policy],
        matching_policy: MatchingPolicy,
    ) -> bool:
        """Whether any statement restricts fields for this action and resource.

        Conditions are not weighed: the answer decides whether masking is worth
        working out at all, so it errs towards yes.
        """
        restricting = matching_policy.with_effect(PolicyEffect.RESTRICT_FIELDS)
        return any(
            self._applies(statement, restricting, weigh_condition=False)
            for statement in statements(policies)
        )

    def select(
        self, policies: Sequence[Policy], matching_policy: MatchingPolicy
    ) -> MatchingStatements:
        """The statements that apply, without weighing their conditions.

        Used where the conditions are the point -- compiling them into a query
        filter rather than settling them here.
        """
        asked = (
            matching_policy
            if matching_policy.effect
            else matching_policy.with_effect(PolicyEffect.ALLOW)
        )
        applicable = tuple(
            statement
            for statement in statements(policies)
            if self._applies(statement, asked, weigh_condition=False)
        )
        return MatchingStatements(
            all=applicable,
            conditional=tuple(
                statement for statement in applicable if statement.condition
            ),
        )

    # -- matching --------------------------------------------------------

    def _find_match(
        self,
        policies: Sequence[Policy],
        matching_policy: MatchingPolicy,
        effect: PolicyEffect,
    ) -> PolicyStatement | None:
        asked = matching_policy.with_effect(effect)
        return next(
            (
                statement
                for statement in statements(policies)
                if self._applies(statement, asked, weigh_condition=True)
            ),
            None,
        )

    def _applies(
        self,
        statement: PolicyStatement,
        matching_policy: MatchingPolicy,
        *,
        weigh_condition: bool,
    ) -> bool:
        context = matching_policy.context or {}

        if statement.effect is not matching_policy.effect:
            return False
        if statement.action is not None and not _any_pattern_matches(
            statement.action, matching_policy.action
        ):
            return False
        if statement.not_action is not None and _any_pattern_matches(
            statement.not_action, matching_policy.action
        ):
            return False
        if statement.principal is not None and not _principal_applies(
            statement.principal, matching_policy.principal
        ):
            return False
        if statement.resource is not None and not _resource_applies(
            statement.resource, matching_policy.resource, context
        ):
            return False
        if statement.not_resource is not None and _resource_applies(
            statement.not_resource, matching_policy.resource, context
        ):
            return False

        if not weigh_condition:
            return True
        return self.holds(statement.condition, context)

    # -- compiling to a query -------------------------------------------

    def to_query_filters(
        self, condition: PolicyStatementCondition | None, context: Mapping[str, Any]
    ) -> list[QueryFilter]:
        """Read ``condition`` as filters over the records a query will return.

        An empty list means the condition restricts nothing. A condition that
        restricts but describes no field of the record -- one about the caller,
        or one that cannot be read -- yields
        :data:`~pybac.domain.query_filter.UNSATISFIABLE`, so the policy grants
        nothing through the query rather than everything.

        Filters from several parts are returned side by side, for the caller to
        require together.
        """
        if not condition:
            return []
        return [
            compiled
            for name, spec in condition.items()
            for compiled in self._part_as_filters(name, spec, context)
        ]

    def _part_as_filters(
        self, name: str, spec: Any, context: Mapping[str, Any]
    ) -> list[QueryFilter]:
        if name == _EXPRESSION:
            return self._expression_as_filters(spec, context)

        build = FILTERS.get(name)
        if build is None:
            self._logger.debug(
                "policy names an unknown condition", extra={"condition": name}
            )
            return [UNSATISFIABLE]
        if not isinstance(spec, Mapping):
            return [UNSATISFIABLE]

        filters: list[QueryFilter] = []
        for field, written in spec.items():
            values = [
                value
                for raw in as_list(written)
                for value in fill_condition_values(raw, context)
            ]
            filters.extend(build(_field_name(field), values))
        return filters

    def _expression_as_filters(
        self, spec: Any, context: Mapping[str, Any]
    ) -> list[QueryFilter]:
        if not isinstance(spec, Mapping):
            return [UNSATISFIABLE]

        filters: list[QueryFilter] = []
        for script in spec.values():
            if not isinstance(script, str):
                return [UNSATISFIABLE]
            try:
                compiled = FilterCompiler(context).compile(_compiled(script))
            except Exception:
                self._logger.debug(
                    "expression could not be compiled to a filter",
                    exc_info=True,
                    extra={"script": script},
                )
                return [UNSATISFIABLE]
            if compiled is Outcome.NEVER:
                return [UNSATISFIABLE]
            if compiled is not Outcome.ALWAYS:
                filters.append(compiled)
        return filters

    # -- conditions ------------------------------------------------------

    def holds(
        self, condition: PolicyStatementCondition | None, context: Mapping[str, Any]
    ) -> bool:
        """Whether every part of ``condition`` is satisfied by ``context``.

        A statement with no condition applies unconditionally.
        """
        if not condition:
            return True
        return all(
            self._part_holds(name, spec, context) for name, spec in condition.items()
        )

    def _part_holds(self, name: str, spec: Any, context: Mapping[str, Any]) -> bool:
        if name == _EXPRESSION:
            return self._expression_holds(spec, context)

        operator = CONDITIONS.get(name)
        if operator is None:
            self._logger.debug(
                "policy names an unknown condition", extra={"condition": name}
            )
            return False
        if not isinstance(spec, Mapping):
            return False

        takes_whole_set = _takes_the_whole_set(name)
        for field, written in spec.items():
            found = resolve_path(field, context)
            values = [
                value
                for raw in as_list(written)
                for value in fill_condition_values(raw, context)
            ]
            try:
                held = (
                    operator(found, values)
                    if takes_whole_set
                    else any(operator(found, value) for value in values)
                )
            except Exception:
                self._logger.debug(
                    "condition could not be settled",
                    exc_info=True,
                    extra={"condition": name, "field": field},
                )
                return False
            if not held:
                return False
        return True

    def _expression_holds(self, spec: Any, context: Mapping[str, Any]) -> bool:
        if not isinstance(spec, Mapping):
            return False
        for script in spec.values():
            if not isinstance(script, str):
                return False
            try:
                result = Evaluator(context).evaluate(_compiled(script))
            except Exception:
                self._logger.debug(
                    "expression could not be settled",
                    exc_info=True,
                    extra={"script": script},
                )
                return False
            # Only a plain true is a match; anything else the expression yielded
            # is a value, not an answer.
            if result is not True:
                return False
        return True


def _field_name(key: str) -> str:
    """The record field a condition key addresses.

    A condition names its field the way it names anything in the context, as
    ``target:document:folder``. A query addresses the record directly, so
    the ``target`` it is already about is dropped and the rest becomes a path.
    """
    return key.removeprefix(f"{_TARGET_PREFIX}:").replace(":", ".")


def _takes_the_whole_set(name: str) -> bool:
    quantifier, _, base = name.rpartition(":")
    if quantifier in _QUANTIFIERS:
        return True
    return base.removesuffix("IfExists") in _SET_CONDITIONS


def _any_pattern_matches(patterns: Sequence[str], wanted: str) -> bool:
    return any(matches(wanted, pattern) for pattern in patterns)


def _resource_applies(
    written: str | Sequence[str], wanted: str, context: Mapping[str, Any]
) -> bool:
    return any(
        matches(wanted, fill_text(pattern, context))
        for pattern in as_list(written)
        if isinstance(pattern, str)
    )


def _principal_applies(written: Mapping[str, Any], wanted: Mapping[str, Any]) -> bool:
    any_value_equals = CONDITIONS["ForAnyValue:StringEquals"]
    return any(
        any_value_equals(written.get(key), asked)
        for key, asked in wanted.items()
        if asked
    )
