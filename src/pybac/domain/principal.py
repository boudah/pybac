"""Who is asking.

Python attributes are snake_case and accept the camelCase names the wire format
uses, so a session decoded straight from JSON loads without translation.

What a policy *reads* is assembled elsewhere, in :mod:`pybac.context`.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

from pybac.domain.policy import Policy

__all__ = [
    "PolicyTags",
    "SecurityContext",
    "ServiceContext",
    "SessionContext",
    "UserInfo",
]

#: Key/value pairs attached to a principal or a resource.
PolicyTags = dict[str, Any]

#: Extra values a service contributes to the decision, addressable by policies.
ServiceContext = dict[str, Any]

_CAMEL = ConfigDict(alias_generator=to_camel, populate_by_name=True, frozen=True)


class UserInfo(BaseModel):
    """The two facts about a user that reach a decision.

    A session payload carries more than this -- a display name, for one. The
    surplus is accepted and dropped, because a model holding what it never reads
    invites the belief that a policy can address it.
    """

    model_config = _CAMEL

    locale: str = ""
    ctx: dict[str, Any] = Field(default_factory=dict)


class SecurityContext(BaseModel):
    """What the principal is allowed, and the groups and tags that qualify it.

    ``policies`` has no default. An empty set grants nothing, so a security
    context left empty by accident refuses every request -- a confusing way to
    fail. Requiring it makes an empty one something you wrote.

    Unlike the models around it this one keeps keys it does not know, because a
    calling service is expected to hang its own flags here.
    """

    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, frozen=True, extra="allow"
    )

    policies: list[Policy]
    security_groups: list[str] = Field(default_factory=list)
    tags: PolicyTags = Field(default_factory=dict)


class SessionContext(BaseModel):
    """The principal a decision is being made for.

    No session token: the only thing that ever needed one was the external
    context lookup, which this package does not perform. A token in the payload
    is accepted and dropped rather than held.
    """

    model_config = _CAMEL

    user_id: str
    instance: str
    user_info: UserInfo = Field(default_factory=UserInfo)
    security_context: SecurityContext
