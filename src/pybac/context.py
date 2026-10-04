"""Gathering what a policy is allowed to read.

A condition addresses its world by name -- ``req.userId``, ``user.policyTags``,
``target.status`` -- and this is where those names come from. One mapping,
assembled from the principal's session, the record in question, and whatever the
calling service contributed.

Nothing else is visible to a policy. An operator cannot reach a database or
another service; if a condition needs a fact, the fact has to be gathered before
evaluation and put in the service context.

The keys stay camelCase, unlike everything else in this package. A policy
reading ``req.userId`` has to find a key called exactly that.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, NotRequired, TypedDict

from pybac._paths import get
from pybac.domain.principal import PolicyTags, ServiceContext, SessionContext

__all__ = [
    "PolicyDecisionContext",
    "RequestSnapshot",
    "UserSnapshot",
    "build_context",
]


class RequestSnapshot(TypedDict):
    """The ``req`` branch, as policies address it."""

    userId: str
    instance: str
    groups: list[str]
    locale: str
    currentTime: str


class UserSnapshot(TypedDict):
    """The ``user`` branch, as policies address it."""

    userId: str
    externalId: NotRequired[str | None]
    groups: list[str]
    tags: PolicyTags
    policyTags: PolicyTags
    tagKeys: list[str]
    policyTagKeys: list[str]


#: What a condition is evaluated against: ``req``, ``user`` and ``target``, plus
#: whatever the calling service contributed. The service keys are open, so this
#: stays a plain mapping rather than a closed :class:`TypedDict`.
PolicyDecisionContext = dict[str, Any]


def build_context(
    session: SessionContext,
    target: Mapping[str, Any] | None = None,
    service_context: ServiceContext | None = None,
) -> PolicyDecisionContext:
    """Gather the data a policy may address, into one mapping."""
    tags = session.security_context.tags
    tag_keys = list(tags)
    record = dict(target or {})
    record_tags = record.get("policyTags") or {}

    context: PolicyDecisionContext = {
        "req": {
            "userId": session.user_id,
            "instance": session.instance,
            "groups": session.security_context.security_groups,
            "locale": session.user_info.locale,
            "currentTime": _now(),
        },
        "user": {
            "userId": session.user_id,
            "externalId": get(session.user_info.ctx, "extId"),
            "groups": session.security_context.security_groups,
            # Both spellings, because policies were written with both.
            "tags": tags,
            "policyTags": tags,
            "tagKeys": tag_keys,
            "policyTagKeys": tag_keys,
        },
        "target": {
            **record,
            "policyTags": record_tags,
            "policyTagKeys": list(record_tags),
        },
    }
    # A service may add its own branches, and a policy may address them.
    context.update(service_context or {})
    return context


def _now() -> str:
    """The moment, as a policy expects to read it."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
