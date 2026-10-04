"""Policy-based access control.

Given a principal's policies and the resource they are reaching for, decide
whether to allow it, which fields they may see, and -- when the resource is one
of many yet to be fetched -- what filter expresses the policy.

    from pybac import MatchingPolicy, PolicyEvaluator

    evaluator = PolicyEvaluator()
    allowed = evaluator.evaluate(
        MatchingPolicy(action="iam:user:read", resource="*"), session, user
    )
"""

from __future__ import annotations

from pybac.cache import DecisionCache
from pybac.context import (
    PolicyDecisionContext,
    RequestSnapshot,
    UserSnapshot,
    build_context,
)
from pybac.domain import (
    UNSATISFIABLE,
    Capabilities,
    CombinatorFilter,
    Considered,
    Decision,
    LeafFilter,
    MatchingPolicy,
    Policy,
    PolicyEffect,
    PolicyStatement,
    PolicyTags,
    QueryFilter,
    QueryFilterComparator,
    SecurityContext,
    ServiceContext,
    SessionContext,
    UserInfo,
    validate_policies,
)
from pybac.errors import ExpressionError, PolicyError
from pybac.evaluator import PolicyEvaluator
from pybac.masking import (
    FieldMasking,
    FieldTranslator,
    MaskedPaths,
    MaskingStrategy,
)
from pybac.processor import MatchingStatements, PolicyProcessor
from pybac.query import QueryCompiler

__version__ = "0.1.0"

__all__ = [
    "UNSATISFIABLE",
    "Capabilities",
    "CombinatorFilter",
    "Considered",
    "Decision",
    "DecisionCache",
    "ExpressionError",
    "FieldMasking",
    "FieldTranslator",
    "LeafFilter",
    "MaskedPaths",
    "MaskingStrategy",
    "MatchingPolicy",
    "MatchingStatements",
    "Policy",
    "PolicyDecisionContext",
    "PolicyEffect",
    "PolicyError",
    "PolicyEvaluator",
    "PolicyProcessor",
    "PolicyStatement",
    "PolicyTags",
    "QueryCompiler",
    "QueryFilter",
    "QueryFilterComparator",
    "RequestSnapshot",
    "SecurityContext",
    "ServiceContext",
    "SessionContext",
    "UserInfo",
    "UserSnapshot",
    "__version__",
    "build_context",
    "validate_policies",
]
