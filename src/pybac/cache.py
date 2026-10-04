"""Remembering verdicts between requests.

Caching trades freshness for speed. A policy reading ``req.currentTime`` is
answered from whatever is remembered, and a policy set that changes mid-request
goes unnoticed until the entry is dropped. Nothing caches unless a caller asks
for it.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from pybac.domain.policy import MatchingPolicy
from pybac.domain.principal import ServiceContext, SessionContext

__all__ = ["DecisionCache", "cache_key"]


@runtime_checkable
class DecisionCache(Protocol):
    """Somewhere to keep verdicts.

    Anything with these two methods will do. The key is built by
    :func:`cache_key`, over everything a verdict depends on, so an
    implementation only has to store and return what it is given.
    """

    def get(self, key: str) -> bool | None: ...

    def set(self, key: str, decision: bool) -> None: ...


def cache_key(
    matching_policy: MatchingPolicy,
    session: SessionContext,
    target: Mapping[str, Any] | None,
    service_context: ServiceContext | None,
) -> str:
    """A key over everything a verdict depends on, and nothing else.

    The moment does not enter it, so a policy reading ``req.currentTime`` is
    answered from whatever is held until the entry is dropped.
    """
    security = session.security_context
    payload = {
        "matching_policy": matching_policy.model_dump(mode="json"),
        "policies": [policy.model_dump(mode="json") for policy in security.policies],
        "groups": security.security_groups,
        "tags": security.tags,
        "userId": session.user_id,
        "instance": session.instance,
        "locale": session.user_info.locale,
        "ctx": session.user_info.ctx,
        "target": target,
        "service": service_context,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode()
    ).hexdigest()
