from __future__ import annotations

import logging
from typing import Any

import pytest

from pybac import (
    Considered,
    Decision,
    MatchingPolicy,
    Policy,
    PolicyEffect,
    PolicyEvaluator,
    PolicyStatement,
    SecurityContext,
    SessionContext,
)
from pybac.processor import PolicyProcessor

READ = MatchingPolicy(action="docs:document:read", resource="*")

POLICY = Policy.model_validate(
    {
        "Statement": [
            {
                "Sid": "readOwn",
                "Effect": "Allow",
                "Action": ["docs:document:read"],
                "Condition": {"Expr": {"script": "target.ownerId == req.userId"}},
            },
            {
                "Sid": "readPublic",
                "Effect": "Allow",
                "Action": ["docs:document:read"],
                "Condition": {"StringEquals": {"target:visibility": "public"}},
            },
            {
                "Sid": "blockArchive",
                "Effect": "Deny",
                "Action": ["docs:document:*"],
                "Condition": {"StringEquals": {"target:folder": "archive"}},
            },
            {"Sid": "writeAll", "Effect": "Allow", "Action": ["docs:document:write"]},
        ]
    }
)

OWN = {"ownerId": "U1", "visibility": "private", "folder": "plans"}
THEIRS = {"ownerId": "U2", "visibility": "private", "folder": "plans"}
PUBLIC = {"ownerId": "U2", "visibility": "public", "folder": "plans"}
ARCHIVED = {"ownerId": "U1", "visibility": "private", "folder": "archive"}


def session(*policies: Policy) -> SessionContext:
    return SessionContext(
        user_id="U1",
        instance="acme",
        security_context=SecurityContext(policies=list(policies)),
    )


@pytest.fixture
def evaluator() -> PolicyEvaluator:
    return PolicyEvaluator()


# --------------------------------------------------------------------------
# what a decision says
# --------------------------------------------------------------------------


def test_an_allowed_request_names_the_statement_that_allowed_it(
    evaluator: PolicyEvaluator,
) -> None:
    decision = evaluator.explain(READ, session(POLICY), OWN)

    assert decision.allowed is True
    assert decision.settled_by is PolicyEffect.ALLOW
    assert decision.statement is not None
    assert decision.statement.sid == "readOwn"


def test_a_denied_request_names_the_statement_that_denied_it(
    evaluator: PolicyEvaluator,
) -> None:
    decision = evaluator.explain(READ, session(POLICY), ARCHIVED)

    assert decision.allowed is False
    assert decision.settled_by is PolicyEffect.DENY
    assert decision.statement is not None
    assert decision.statement.sid == "blockArchive"


def test_a_deny_outweighs_an_allow_that_also_matched(
    evaluator: PolicyEvaluator,
) -> None:
    """`readOwn` holds for this record, and is overruled."""
    decision = evaluator.explain(READ, session(POLICY), ARCHIVED)
    assert decision.statement is not None
    assert decision.statement.sid == "blockArchive"


def test_a_request_nothing_covers_names_no_statement(
    evaluator: PolicyEvaluator,
) -> None:
    decision = evaluator.explain(READ, session(POLICY), THEIRS)

    assert decision.allowed is False
    assert decision.settled_by is None
    assert decision.statement is None


def test_a_principal_with_no_policies_is_refused(evaluator: PolicyEvaluator) -> None:
    decision = evaluator.explain(READ, session(), OWN)

    assert decision.allowed is False
    assert decision.settled_by is None
    assert decision.considered == ()


# --------------------------------------------------------------------------
# what came close
# --------------------------------------------------------------------------


def test_a_refusal_names_the_statements_that_would_have_allowed_it(
    evaluator: PolicyEvaluator,
) -> None:
    """The first thing a policy author wants when a grant is not working."""
    decision = evaluator.explain(READ, session(POLICY), THEIRS)

    assert [entry.statement.sid for entry in decision.would_have_allowed] == [
        "readOwn",
        "readPublic",
    ]


def test_an_allowance_names_the_statements_that_would_have_denied_it(
    evaluator: PolicyEvaluator,
) -> None:
    decision = evaluator.explain(READ, session(POLICY), OWN)

    assert [entry.statement.sid for entry in decision.would_have_denied] == [
        "blockArchive"
    ]


def test_a_deny_that_nearly_applied_is_not_a_missed_allowance(
    evaluator: PolicyEvaluator,
) -> None:
    """The two mean opposite things and must not be counted together."""
    decision = evaluator.explain(READ, session(POLICY), THEIRS)

    assert "blockArchive" not in [
        entry.statement.sid for entry in decision.would_have_allowed
    ]


def test_a_statement_for_another_action_did_not_apply(
    evaluator: PolicyEvaluator,
) -> None:
    decision = evaluator.explain(READ, session(POLICY), OWN)
    weighed = {entry.statement.sid: entry for entry in decision.considered}

    assert weighed["writeAll"].applied is False
    assert weighed["writeAll"].condition_held is None
    assert weighed["writeAll"].settled is False


def test_every_statement_of_a_consulted_effect_is_weighed(
    evaluator: PolicyEvaluator,
) -> None:
    decision = evaluator.explain(READ, session(POLICY), OWN)
    assert sorted(entry.statement.sid or "" for entry in decision.considered) == [
        "blockArchive",
        "readOwn",
        "readPublic",
        "writeAll",
    ]


def test_a_restrict_fields_statement_is_not_consulted(
    evaluator: PolicyEvaluator,
) -> None:
    """It qualifies an access rather than granting or refusing one."""
    policy = Policy.model_validate(
        {
            "Statement": [
                {"Sid": "allow", "Effect": "Allow", "Action": ["docs:document:read"]},
                {
                    "Sid": "hide",
                    "Effect": "RestrictFields",
                    "Action": ["docs:document:read"],
                    "NotFields": ["salary"],
                },
            ]
        }
    )
    decision = evaluator.explain(READ, session(policy), OWN)
    assert [entry.statement.sid for entry in decision.considered] == ["allow"]


# --------------------------------------------------------------------------
# reading it
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("target", "rendered"),
    [
        (OWN, "allowed by Allow statement 'readOwn'"),
        (ARCHIVED, "refused by Deny statement 'blockArchive'"),
        (THEIRS, "refused: no statement allows it (2 would have, but for a condition)"),
    ],
)
def test_a_decision_reads_as_a_sentence(
    evaluator: PolicyEvaluator, target: dict[str, Any], rendered: str
) -> None:
    assert str(evaluator.explain(READ, session(POLICY), target)) == rendered


def test_a_decision_with_nothing_near_says_only_that() -> None:
    assert str(Decision(allowed=False)) == "refused: no statement allows it"


def test_an_unnamed_statement_still_reads() -> None:
    """`Sid` is optional, and a record is no place to raise about it."""
    policy = Policy.model_validate(
        {"Statement": [{"Effect": "Allow", "Action": ["docs:document:read"]}]}
    )
    assert str(PolicyEvaluator().explain(READ, session(policy), OWN)) == (
        "allowed by Allow statement"
    )


def test_a_weighed_statement_reports_how_far_it_got() -> None:
    statement = PolicyStatement(effect=PolicyEffect.ALLOW)

    settled = Considered(statement=statement, applied=True, condition_held=True)
    missed = Considered(statement=statement, applied=True, condition_held=False)
    absent = Considered(statement=statement, applied=False, condition_held=None)

    assert (settled.settled, settled.missed_by_condition) == (True, False)
    assert (missed.settled, missed.missed_by_condition) == (False, True)
    assert (absent.settled, absent.missed_by_condition) == (False, False)


# --------------------------------------------------------------------------
# the two paths must never disagree
# --------------------------------------------------------------------------

SCENARIOS = [
    ("own", READ, OWN),
    ("theirs", READ, THEIRS),
    ("public", READ, PUBLIC),
    ("archived", READ, ARCHIVED),
    ("write", MatchingPolicy(action="docs:document:write", resource="*"), OWN),
    ("archived write", MatchingPolicy(action="docs:document:write"), ARCHIVED),
    ("unknown action", MatchingPolicy(action="docs:document:delete"), OWN),
    ("no policies", READ, OWN),
]


@pytest.mark.parametrize(("label", "matching_policy", "target"), SCENARIOS)
def test_evaluate_and_explain_agree(
    evaluator: PolicyEvaluator,
    label: str,
    matching_policy: MatchingPolicy,
    target: dict[str, Any],
) -> None:
    """Two code paths, one verdict. A fast one that stops early, and a slow one
    that does not — they must always reach the same answer."""
    held = session() if label == "no policies" else session(POLICY)

    assert evaluator.evaluate(matching_policy, held, target) == (
        evaluator.explain(matching_policy, held, target).allowed
    )


def test_the_processor_agrees_with_itself() -> None:
    processor = PolicyProcessor()
    for _, matching_policy, target in SCENARIOS:
        asked = matching_policy.with_context(
            {"target": target, "req": {"userId": "U1"}}
        )
        assert (
            processor.evaluate([POLICY], asked)
            == processor.explain([POLICY], asked).allowed
        )


# --------------------------------------------------------------------------
# cost
# --------------------------------------------------------------------------


def test_explain_is_never_answered_from_the_cache() -> None:
    """A remembered verdict has no reasoning attached to it."""

    class Remembering:
        def __init__(self) -> None:
            self.reads = 0

        def get(self, key: str) -> bool | None:
            self.reads += 1
            return None

        def set(self, key: str, decision: bool) -> None:
            return None

    cache = Remembering()
    evaluator = PolicyEvaluator(cache=cache)

    evaluator.explain(READ, session(POLICY), OWN)
    assert cache.reads == 0

    evaluator.evaluate(READ, session(POLICY), OWN)
    assert cache.reads == 1


def test_a_refusal_is_explained_in_the_log(
    evaluator: PolicyEvaluator, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG, logger="pybac"):
        evaluator.evaluate(READ, session(POLICY), ARCHIVED)

    assert "refused by Deny statement 'blockArchive'" in caplog.text


def test_nothing_is_worked_out_when_nobody_is_listening(
    evaluator: PolicyEvaluator, caplog: pytest.LogCaptureFixture
) -> None:
    """The reasoning costs a second pass, so it is only paid for when read."""
    with caplog.at_level(logging.INFO, logger="pybac"):
        assert evaluator.evaluate(READ, session(POLICY), THEIRS) is False
    assert caplog.text == ""


# --------------------------------------------------------------------------
# permitted, but not yet
# --------------------------------------------------------------------------

GATED = Policy.model_validate(
    {
        "Statement": [
            {"Sid": "mayWrite", "Effect": "Allow", "Action": ["docs:document:write"]},
            {
                "Sid": "bigWritesNeedAHuman",
                "Effect": "RequireApproval",
                "Action": ["docs:document:write"],
                "Condition": {"NumericGreaterThan": {"target:wordCount": 1000}},
            },
            {
                "Sid": "neverArchived",
                "Effect": "Deny",
                "Action": ["docs:document:*"],
                "Condition": {"StringEquals": {"target:folder": "archive"}},
            },
        ]
    }
)
WRITE = MatchingPolicy(action="docs:document:write", resource="*")
SMALL = {"wordCount": 10, "folder": "plans"}
BIG = {"wordCount": 5000, "folder": "plans"}
BIG_ARCHIVED = {"wordCount": 5000, "folder": "archive"}


def test_an_action_below_the_threshold_just_runs(evaluator: PolicyEvaluator) -> None:
    decision = evaluator.explain(WRITE, session(GATED), SMALL)

    assert decision.allowed is True
    assert decision.approval_required is False
    assert decision.settled_by is PolicyEffect.ALLOW


def test_an_action_above_it_awaits_a_human(evaluator: PolicyEvaluator) -> None:
    decision = evaluator.explain(WRITE, session(GATED), BIG)

    assert decision.approval_required is True
    assert decision.settled_by is PolicyEffect.REQUIRE_APPROVAL
    assert decision.statement is not None
    assert decision.statement.sid == "bigWritesNeedAHuman"


def test_evaluate_does_not_permit_what_awaits_approval(
    evaluator: PolicyEvaluator,
) -> None:
    """A caller that knows nothing of approvals must not walk past one."""
    assert evaluator.evaluate(WRITE, session(GATED), BIG) is False
    assert evaluator.explain(WRITE, session(GATED), BIG).allowed is False


def test_a_deny_outranks_a_request_for_approval(evaluator: PolicyEvaluator) -> None:
    decision = evaluator.explain(WRITE, session(GATED), BIG_ARCHIVED)

    assert decision.approval_required is False
    assert decision.settled_by is PolicyEffect.DENY
    assert decision.statement is not None
    assert decision.statement.sid == "neverArchived"


def test_asking_for_approval_grants_nothing_on_its_own(
    evaluator: PolicyEvaluator,
) -> None:
    """Like `RestrictFields`, it qualifies an access somebody else granted."""
    policy = Policy.model_validate(
        {
            "Statement": [
                {
                    "Sid": "gate",
                    "Effect": "RequireApproval",
                    "Action": ["docs:document:write"],
                }
            ]
        }
    )
    decision = evaluator.explain(WRITE, session(policy), SMALL)

    assert decision.allowed is False
    assert decision.approval_required is False
    assert decision.settled_by is None


def test_an_approval_reads_as_a_sentence(evaluator: PolicyEvaluator) -> None:
    assert str(evaluator.explain(WRITE, session(GATED), BIG)) == (
        "awaiting approval, required by statement 'bigWritesNeedAHuman'"
    )


def test_the_approval_pass_is_weighed_too(evaluator: PolicyEvaluator) -> None:
    decision = evaluator.explain(WRITE, session(GATED), SMALL)
    weighed = {entry.statement.sid: entry for entry in decision.considered}

    assert weighed["bigWritesNeedAHuman"].applied is True
    assert weighed["bigWritesNeedAHuman"].condition_held is False


@pytest.mark.parametrize("target", [SMALL, BIG, BIG_ARCHIVED])
def test_evaluate_and_explain_agree_about_approvals(
    evaluator: PolicyEvaluator, target: dict[str, Any]
) -> None:
    assert evaluator.evaluate(WRITE, session(GATED), target) == (
        evaluator.explain(WRITE, session(GATED), target).allowed
    )


def test_approval_says_nothing_about_which_records_exist(
    evaluator: PolicyEvaluator,
) -> None:
    """It gates an action, not a search, so the query path ignores it."""
    assert evaluator.compile_query_filters(WRITE, session(GATED)) == []


def test_approval_withholds_no_fields(evaluator: PolicyEvaluator) -> None:
    assert evaluator.fields_to_mask(WRITE, session(GATED), BIG) == ()
