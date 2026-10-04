"""Capabilities: the verdict on a set of actions against one resource."""

from __future__ import annotations

__all__ = ["Capabilities", "CapabilityValue"]

#: Either "may do this" or the set of values the principal is limited to.
CapabilityValue = bool | list[str]

Capabilities = dict[str, CapabilityValue]
