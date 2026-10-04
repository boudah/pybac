"""The public face of the evaluator.

Everything a caller needs, in one object. Give it a principal's session, the
action they are attempting and the resource they are attempting it on, and it
answers: may they? Which fields may they see? And, when the resource does not
exist yet because the caller is about to query for many, what filter expresses
the policy?

The context every policy is evaluated against is built here, from the session
and the resource. Policies address it by name -- ``req.userId``,
``user.policyTags``, ``target.status`` -- and a service may contribute its own
keys alongside.

A principal carrying no policies is granted nothing. Permission has to come
from somewhere, and with no statement to grant it there is nothing to find.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import Any, Final

from pybac._paths import get
from pybac.cache import DecisionCache, cache_key
from pybac.context import PolicyDecisionContext, build_context
from pybac.domain.capabilities import Capabilities
from pybac.domain.decision import Decision
from pybac.domain.policy import MatchingPolicy, PolicyEffect
from pybac.domain.principal import ServiceContext, SessionContext
from pybac.domain.query_filter import UNSATISFIABLE, QueryFilter
from pybac.masking import FieldMasking, FieldTranslator, mask
from pybac.processor import MatchingStatements, PolicyProcessor
from pybac.query import QueryCompiler

__all__ = [
    "DecisionCache",
    "PolicyEvaluator",
]

_LOGGER: Final = logging.getLogger("pybac")


class PolicyEvaluator:
    """Decides what a principal may do, see and find."""

    def __init__(
        self,
        cache: DecisionCache | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._logger = logger or _LOGGER
        self._cache = cache
        self._processor = PolicyProcessor(self._logger)
        self._queries = QueryCompiler(self._processor)

    # -- verdicts --------------------------------------------------------

    def evaluate(
        self,
        matching_policy: MatchingPolicy,
        session: SessionContext,
        target: Mapping[str, Any] | None = None,
        service_context: ServiceContext | None = None,
    ) -> bool:
        """Whether ``session`` may do ``matching_policy`` to ``target``.

        A principal carrying no policies is refused: permission has to be
        granted by something, and there is no statement here to grant it.
        """
        policies = session.security_context.policies
        if not policies:
            return False

        key = (
            cache_key(matching_policy, session, target, service_context)
            if self._cache is not None
            else ""
        )
        if self._cache is not None:
            remembered = self._cache.get(key)
            if remembered is not None:
                return remembered

        context = self.build_context(session, target, service_context)
        decision = self._processor.evaluate(
            policies, matching_policy.with_context(context)
        )

        if self._cache is not None:
            self._cache.set(key, decision)
        if not decision:
            self._log_refusal(matching_policy, session, target, service_context)
        return decision

    def explain(
        self,
        matching_policy: MatchingPolicy,
        session: SessionContext,
        target: Mapping[str, Any] | None = None,
        service_context: ServiceContext | None = None,
    ) -> Decision:
        """The same verdict as :meth:`evaluate`, with the reasoning kept.

        Which statement settled the matter, and what else was weighed --
        including the statements that would have applied but for their
        condition, which is usually what a policy author wants to see.

        Slower than :meth:`evaluate`, which stops at the first statement that
        settles it, and never answered from the cache: a remembered verdict has
        no reasoning attached.
        """
        policies = session.security_context.policies
        if not policies:
            return Decision(allowed=False)
        context = self.build_context(session, target, service_context)
        return self._processor.explain(policies, matching_policy.with_context(context))

    def _log_refusal(
        self,
        matching_policy: MatchingPolicy,
        session: SessionContext,
        target: Mapping[str, Any] | None,
        service_context: ServiceContext | None,
    ) -> None:
        """Say why, but only work it out if anyone is listening."""
        if not self._logger.isEnabledFor(logging.DEBUG):
            return
        record = self.explain(matching_policy, session, target, service_context)
        self._logger.debug(
            "refused: %s",
            record,
            extra={
                "action": matching_policy.action,
                "resource": matching_policy.resource,
                "userId": session.user_id,
                "targetId": get(target or {}, "id"),
                "statement": record.statement.sid if record.statement else None,
                "wouldHaveAllowed": [
                    entry.statement.sid for entry in record.would_have_allowed
                ],
            },
        )

    def evaluate_many(
        self,
        matching_policies: Sequence[MatchingPolicy],
        session: SessionContext,
        target: Mapping[str, Any] | None = None,
        service_context: ServiceContext | None = None,
    ) -> list[bool]:
        """One verdict per policy, against the same resource."""
        return [
            self.evaluate(matching_policy, session, target, service_context)
            for matching_policy in matching_policies
        ]

    def evaluate_capabilities(
        self,
        matching_policies: Mapping[str, MatchingPolicy],
        session: SessionContext,
        target: Mapping[str, Any] | None = None,
        service_context: ServiceContext | None = None,
    ) -> Capabilities:
        """What the principal may do to ``target``, named by the caller's keys."""
        policies = session.security_context.policies
        if not policies:
            return dict.fromkeys(matching_policies, False)

        context = self.build_context(session, target, service_context)
        return {
            name: self._processor.evaluate(
                policies, matching_policy.with_context(context)
            )
            for name, matching_policy in matching_policies.items()
        }

    def evaluate_many_capabilities(
        self,
        matching_policies: Mapping[str, MatchingPolicy],
        session: SessionContext,
        targets: Sequence[Mapping[str, Any]],
        service_context: ServiceContext | None = None,
    ) -> list[dict[str, Any]]:
        """Each resource, with a ``capabilities`` entry describing what is allowed."""
        return [
            {
                **target,
                "capabilities": self.evaluate_capabilities(
                    matching_policies, session, target, service_context
                ),
            }
            for target in targets
        ]

    # -- fields ----------------------------------------------------------

    def fields_to_mask(
        self,
        matching_policy: MatchingPolicy,
        session: SessionContext,
        target: Mapping[str, Any] | None = None,
        service_context: ServiceContext | None = None,
    ) -> tuple[str, ...]:
        """The fields of ``target`` this principal may not see.

        Masking refines an access already granted, so ask :meth:`evaluate`
        first. A principal carrying no policies withholds nothing here because
        no statement withholds anything -- but they were refused outright.
        """
        policies = session.security_context.policies
        if not policies:
            return ()
        context = self.build_context(session, target, service_context)
        return self._processor.fields_to_mask(
            policies, matching_policy.with_context(context)
        )

    def mask_fields(
        self,
        matching_policy: MatchingPolicy,
        session: SessionContext,
        target: Mapping[str, Any],
        translators: Mapping[str, FieldTranslator] | None = None,
        service_context: ServiceContext | None = None,
        masking: FieldMasking | None = None,
    ) -> dict[str, Any]:
        """A copy of ``target`` with the fields this principal may not see hidden."""
        withheld = self.fields_to_mask(
            matching_policy, session, target, service_context
        )
        if not withheld:
            return dict(target)
        return mask(target, withheld, translators=translators, masking=masking)

    def has_field_security(
        self,
        session: SessionContext,
        matching_policy: MatchingPolicy,
    ) -> bool:
        """Whether any policy restricts fields here, before conditions are weighed.

        Answers whether working out the masking is worth it, so it errs towards
        yes.
        """
        policies = session.security_context.policies
        if not policies:
            return False
        return self._processor.has_field_security(policies, matching_policy)

    def unsearchable_fields(
        self, session: SessionContext, matching_policy: MatchingPolicy
    ) -> tuple[str, ...]:
        """Fields this principal may not search on at all.

        A field withheld unconditionally cannot be searched. One withheld only
        under a condition can, because there are records where it is visible.
        """
        policies = session.security_context.policies
        if not policies:
            return ()

        unsearchable: dict[str, None] = {}
        for statement in self._processor.select(
            policies, matching_policy.with_effect(PolicyEffect.RESTRICT_FIELDS)
        ).all:
            for name in statement.not_fields or ():
                if statement.condition:
                    unsearchable.pop(name, None)
                else:
                    unsearchable[name] = None
        return tuple(unsearchable)

    def matching_statements(
        self,
        session: SessionContext,
        matching_policy: MatchingPolicy,
    ) -> MatchingStatements:
        """The statements that apply, with and without conditions."""
        policies = session.security_context.policies
        if not policies:
            return MatchingStatements(all=(), conditional=())
        return self._processor.select(policies, matching_policy)

    # -- queries ---------------------------------------------------------

    def compile_query_filters(
        self,
        matching_policy: MatchingPolicy,
        session: SessionContext,
        service_context: ServiceContext | None = None,
    ) -> list[QueryFilter]:
        """The filter a caller must apply to see only what the policy allows.

        An empty list means no restriction: some applicable statement grants
        this unconditionally. A filter no record satisfies means the opposite --
        no statement applies, so nothing is visible.
        """
        policies = session.security_context.policies
        if not policies:
            return [UNSATISFIABLE]
        return self._queries.filters(
            policies,
            matching_policy,
            self.build_context(session, {}, service_context),
        )

    def restrict_query_filters(
        self,
        filters: Sequence[QueryFilter],
        matching_policy: MatchingPolicy,
        session: SessionContext,
        service_context: ServiceContext | None = None,
    ) -> list[QueryFilter]:
        """Stop a caller's own filters reaching fields the principal may not see.

        A filter on a withheld field is either narrowed to the records where the
        field *is* visible, or made unsatisfiable when it never is.
        """
        policies = session.security_context.policies
        if not policies:
            return list(filters)
        return self._queries.restrict(
            filters,
            policies,
            matching_policy,
            self.build_context(session, {}, service_context),
        )

    # -- context ---------------------------------------------------------

    def build_context(
        self,
        session: SessionContext,
        target: Mapping[str, Any] | None = None,
        service_context: ServiceContext | None = None,
    ) -> PolicyDecisionContext:
        """The data a policy may address, gathered in one mapping.

        See :func:`pybac.context.build_context`, which does the work and can be
        called without an evaluator.
        """
        return build_context(session, target, service_context)
