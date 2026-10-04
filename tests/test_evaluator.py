from __future__ import annotations

import logging
from typing import Any

import pytest

from pybac.domain import (
    CombinatorFilter,
    LeafFilter,
    MatchingPolicy,
    Policy,
    QueryFilter,
    QueryFilterComparator,
    SecurityContext,
    SessionContext,
    UserInfo,
)
from pybac.evaluator import DecisionCache, PolicyEvaluator
from pybac.masking import FieldMasking, MaskingStrategy

EQ = QueryFilterComparator.EQ


def session(*statements: dict[str, Any], **security: Any) -> SessionContext:
    return SessionContext(
        user_id="USER",
        instance="T1",
        user_info=UserInfo(locale="fr", ctx={"extId": "EXT1"}),
        security_context=SecurityContext(
            policies=[Policy.model_validate({"Statement": list(statements)})],
            security_groups=security.pop("groups", ["G1", "G2"]),
            **security,
        ),
    )


def without_policies() -> SessionContext:
    return SessionContext(
        user_id="USER", instance="T1", security_context=SecurityContext(policies=[])
    )


def as_data(filters: list[Any]) -> list[dict[str, Any]]:
    return [f.model_dump(mode="json") for f in filters]


@pytest.fixture
def evaluator() -> PolicyEvaluator:
    return PolicyEvaluator()


READ = MatchingPolicy(action="iam:user:read", resource="*")
#: Owning a record is a condition like any other.
MINE = {"Expr": {"script": "target.ownerId == req.userId"}}


# --------------------------------------------------------------------------
# verdicts
# --------------------------------------------------------------------------


def test_a_principal_with_no_policies_is_refused(
    evaluator: PolicyEvaluator,
) -> None:
    """Permission comes from a statement, and there is none to grant it."""
    assert evaluator.evaluate(READ, without_policies(), {"id": "U1"}) is False


def test_a_matching_allow_permits(evaluator: PolicyEvaluator) -> None:
    assert (
        evaluator.evaluate(READ, session({"Effect": "Allow", "Action": ["iam:*"]}))
        is True
    )


def test_nothing_matching_refuses(evaluator: PolicyEvaluator) -> None:
    assert (
        evaluator.evaluate(READ, session({"Effect": "Allow", "Action": ["other"]}))
        is False
    )


def test_a_refusal_is_logged(
    evaluator: PolicyEvaluator, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG, logger="pybac"):
        evaluator.evaluate(READ, session({"Effect": "Allow", "Action": ["other"]}))
    assert "refused" in caplog.text


def test_evaluate_many_answers_each_question(evaluator: PolicyEvaluator) -> None:
    held = session({"Effect": "Allow", "Action": ["iam:user:read"]})
    matching_policies = [READ, MatchingPolicy(action="iam:user:write")]
    assert evaluator.evaluate_many(matching_policies, held, {"id": "U1"}) == [
        True,
        False,
    ]


def test_capabilities_are_named_by_the_caller(evaluator: PolicyEvaluator) -> None:
    held = session({"Effect": "Allow", "Action": ["iam:user:read"]})
    assert evaluator.evaluate_capabilities(
        {"read": READ, "write": MatchingPolicy(action="iam:user:write")}, held
    ) == {"read": True, "write": False}


def test_capabilities_are_all_refused_without_policies(
    evaluator: PolicyEvaluator,
) -> None:
    assert evaluator.evaluate_capabilities({"read": READ}, without_policies()) == {
        "read": False
    }


def test_many_capabilities_attaches_them_to_each_resource(
    evaluator: PolicyEvaluator,
) -> None:
    held = session({"Effect": "Allow", "Action": ["iam:user:read"]})
    answered = evaluator.evaluate_many_capabilities(
        {"read": READ}, held, [{"id": "A"}, {"id": "B"}]
    )
    assert answered == [
        {"id": "A", "capabilities": {"read": True}},
        {"id": "B", "capabilities": {"read": True}},
    ]


def test_a_condition_reads_the_resource(evaluator: PolicyEvaluator) -> None:
    held = session(
        {
            "Effect": "Allow",
            "Action": ["iam:user:read"],
            "Condition": {"Expr": {"script": 'target.status == "active"'}},
        }
    )
    assert evaluator.evaluate(READ, held, {"status": "active"}) is True
    assert evaluator.evaluate(READ, held, {"status": "archived"}) is False


def test_a_condition_reads_what_the_service_contributed(
    evaluator: PolicyEvaluator,
) -> None:
    held = session(
        {
            "Effect": "Allow",
            "Action": ["iam:user:read"],
            "Condition": {"Expr": {"script": "review.status == 'suggested'"}},
        }
    )
    assert (
        evaluator.evaluate(READ, held, {}, {"review": {"status": "suggested"}}) is True
    )
    assert evaluator.evaluate(READ, held, {}, {"review": {"status": "other"}}) is False


# --------------------------------------------------------------------------
# the context a policy reads
# --------------------------------------------------------------------------


def test_the_context_gathers_the_principal_and_the_resource(
    evaluator: PolicyEvaluator,
) -> None:
    held = session(
        {"Effect": "Allow", "Action": ["*"]}, tags={"bu": ["BU1"]}, groups=["G1"]
    )
    context = evaluator.build_context(held, {"id": "P", "policyTags": {"unit": ["U"]}})

    assert context["req"]["userId"] == "USER"
    assert context["req"]["instance"] == "T1"
    assert context["req"]["groups"] == ["G1"]
    assert context["req"]["locale"] == "fr"
    assert context["user"]["externalId"] == "EXT1"
    assert context["user"]["tags"] == {"bu": ["BU1"]}
    assert context["user"]["policyTagKeys"] == ["bu"]
    assert context["target"]["id"] == "P"
    assert context["target"]["policyTagKeys"] == ["unit"]


def test_a_resource_with_no_tags_still_has_the_keys_a_policy_reads(
    evaluator: PolicyEvaluator,
) -> None:
    context = evaluator.build_context(without_policies(), {"id": "P"})
    assert context["target"]["policyTags"] == {}
    assert context["target"]["policyTagKeys"] == []


def test_the_service_contributes_its_own_keys(evaluator: PolicyEvaluator) -> None:
    context = evaluator.build_context(
        without_policies(), {}, {"review": {"status": "x"}}
    )
    assert context["review"] == {"status": "x"}


def test_the_moment_is_recorded_the_way_a_policy_expects_to_read_it(
    evaluator: PolicyEvaluator,
) -> None:
    moment = evaluator.build_context(without_policies())["req"]["currentTime"]
    assert moment.endswith("Z")
    assert moment[10] == "T"


# --------------------------------------------------------------------------
# caching
# --------------------------------------------------------------------------


def test_nothing_is_cached_unless_a_cache_is_given() -> None:
    """Freshness is the default; a stale verdict is a caller's decision."""
    assert PolicyEvaluator()._cache is None


class Remembering:
    """The whole of what a cache has to do."""

    def __init__(self) -> None:
        self.entries: dict[str, bool] = {}

    def get(self, key: str) -> bool | None:
        return self.entries.get(key)

    def set(self, key: str, decision: bool) -> None:
        self.entries[key] = decision


def test_a_verdict_is_remembered() -> None:
    cache = Remembering()
    evaluator = PolicyEvaluator(cache=cache)
    held = session({"Effect": "Allow", "Action": ["iam:user:read"]})

    assert evaluator.evaluate(READ, held, {"id": "U1"}) is True
    assert len(cache.entries) == 1
    assert evaluator.evaluate(READ, held, {"id": "U1"}) is True
    assert len(cache.entries) == 1


def test_a_different_resource_is_a_different_question() -> None:
    held = session(
        {
            "Effect": "Allow",
            "Action": ["iam:user:read"],
            "Condition": {"Expr": {"script": 'target.status == "active"'}},
        }
    )
    cache = Remembering()
    evaluator = PolicyEvaluator(cache=cache)
    assert evaluator.evaluate(READ, held, {"status": "active"}) is True
    assert evaluator.evaluate(READ, held, {"status": "archived"}) is False
    assert len(cache.entries) == 2


def test_a_cache_is_anything_that_remembers() -> None:
    cache = Remembering()
    assert isinstance(cache, DecisionCache)
    evaluator = PolicyEvaluator(cache=cache)
    evaluator.evaluate(READ, session({"Effect": "Allow", "Action": ["*"]}))
    assert list(cache.entries.values()) == [True]


# --------------------------------------------------------------------------
# fields
# --------------------------------------------------------------------------

WITHHOLDING = (
    {
        "Effect": "RestrictFields",
        "Action": ["iam:user:read"],
        "NotFields": ["salary", "ssn"],
    },
    {"Effect": "Allow", "Action": ["iam:user:read"]},
)


def test_fields_to_mask_names_what_is_withheld(evaluator: PolicyEvaluator) -> None:
    assert evaluator.fields_to_mask(READ, session(*WITHHOLDING)) == ("salary", "ssn")


def test_nothing_is_withheld_from_a_principal_with_no_policies(
    evaluator: PolicyEvaluator,
) -> None:
    assert evaluator.fields_to_mask(READ, without_policies()) == ()


def test_mask_fields_hides_what_is_withheld(evaluator: PolicyEvaluator) -> None:
    masked = evaluator.mask_fields(
        READ, session(*WITHHOLDING), {"id": "U1", "salary": 1, "name": "n"}
    )
    assert masked == {"id": "U1", "salary": "{****}", "name": "n"}


def test_masking_does_not_invent_a_field_the_resource_lacks(
    evaluator: PolicyEvaluator,
) -> None:
    """Writing a mask over an absent field would announce one that is not there."""
    masked = evaluator.mask_fields(READ, session(*WITHHOLDING), {"id": "U1"})
    assert masked == {"id": "U1"}


def test_mask_fields_can_omit_instead(evaluator: PolicyEvaluator) -> None:
    masked = evaluator.mask_fields(
        READ,
        session(*WITHHOLDING),
        {"id": "U1", "salary": 1},
        masking=FieldMasking(strategy=MaskingStrategy.OMIT),
    )
    assert masked == {"id": "U1"}


def test_mask_fields_returns_the_resource_when_nothing_is_withheld(
    evaluator: PolicyEvaluator,
) -> None:
    resource = {"id": "U1", "salary": 1}
    assert evaluator.mask_fields(READ, without_policies(), resource) == resource


def test_has_field_security(evaluator: PolicyEvaluator) -> None:
    assert evaluator.has_field_security(session(*WITHHOLDING), READ) is True
    assert (
        evaluator.has_field_security(
            session({"Effect": "Allow", "Action": ["iam:user:read"]}), READ
        )
        is False
    )
    assert evaluator.has_field_security(without_policies(), READ) is False


def test_a_field_withheld_without_condition_cannot_be_searched(
    evaluator: PolicyEvaluator,
) -> None:
    assert evaluator.unsearchable_fields(session(*WITHHOLDING), READ) == (
        "salary",
        "ssn",
    )


def test_a_field_withheld_only_sometimes_can_be_searched(
    evaluator: PolicyEvaluator,
) -> None:
    """There are records where it is visible, so a search over them is legitimate."""
    held = session(
        {
            "Effect": "RestrictFields",
            "Action": ["iam:user:read"],
            "NotFields": ["salary"],
            "Condition": {"StringEquals": {"target:kind": "private"}},
        }
    )
    assert evaluator.unsearchable_fields(held, READ) == ()


def test_nothing_is_unsearchable_without_policies(evaluator: PolicyEvaluator) -> None:
    assert evaluator.unsearchable_fields(without_policies(), READ) == ()


def test_matching_statements_reports_what_applies(evaluator: PolicyEvaluator) -> None:
    held = session(
        {"Effect": "Allow", "Action": ["iam:user:read"], "Sid": "plain"},
        {
            "Effect": "Allow",
            "Action": ["iam:user:read"],
            "Sid": "qualified",
            "Condition": {"StringEquals": {"target:a": "x"}},
        },
    )
    found = evaluator.matching_statements(held, READ)
    assert [s.sid for s in found.all] == ["plain", "qualified"]
    assert [s.sid for s in found.conditional] == ["qualified"]


def test_no_statements_match_without_policies(evaluator: PolicyEvaluator) -> None:
    assert evaluator.matching_statements(without_policies(), READ).all == ()


# --------------------------------------------------------------------------
# query filters
# --------------------------------------------------------------------------


def test_without_policies_nothing_is_visible(evaluator: PolicyEvaluator) -> None:
    """Nothing grants access, so nothing is reachable."""
    assert as_data(evaluator.compile_query_filters(READ, without_policies())) == [
        {"key": "id", "comparator": "EQ", "value": "__INVALID__"}
    ]


def test_an_unconditional_grant_restricts_nothing(evaluator: PolicyEvaluator) -> None:
    held = session({"Effect": "Allow", "Action": ["iam:user:read"]})
    assert evaluator.compile_query_filters(READ, held) == []


def test_nothing_applicable_lets_no_record_through(evaluator: PolicyEvaluator) -> None:
    held = session({"Effect": "Allow", "Action": ["other"]})
    assert as_data(evaluator.compile_query_filters(READ, held)) == [
        {"key": "id", "comparator": "EQ", "value": "__INVALID__"}
    ]


def test_a_conditional_grant_becomes_a_filter(evaluator: PolicyEvaluator) -> None:
    held = session(
        {
            "Effect": "Allow",
            "Action": ["iam:user:read"],
            "Condition": {
                "ForAnyValue:StringEquals": {"target:groups": "${req:groups}"}
            },
        }
    )
    assert as_data(evaluator.compile_query_filters(READ, held)) == [
        {"key": "groups", "comparator": "OVERLAPS", "value": ["G1", "G2"]}
    ]


def test_several_grants_are_alternatives(evaluator: PolicyEvaluator) -> None:
    held = session(
        {
            "Effect": "Allow",
            "Action": ["iam:user:read"],
            "Condition": {"StringEquals": {"target:a": "x"}},
        },
        {
            "Effect": "Allow",
            "Action": ["iam:user:read"],
            "Condition": {"StringEquals": {"target:b": "y"}},
        },
    )
    assert as_data(evaluator.compile_query_filters(READ, held)) == [
        {
            "comparator": "OR",
            "value": [
                {"key": "a", "comparator": "EQ", "value": "x"},
                {"key": "b", "comparator": "EQ", "value": "y"},
            ],
        }
    ]


def test_the_parts_of_one_condition_must_all_hold(evaluator: PolicyEvaluator) -> None:
    held = session(
        {
            "Effect": "Allow",
            "Action": ["iam:user:read"],
            "Condition": {
                "StringEquals": {"target:a": "x"},
                "ContainsAtLeastOne": {"target:groups": ["G1"]},
            },
        }
    )
    assert (
        as_data(evaluator.compile_query_filters(READ, held))[0]["comparator"] == "AND"
    )


def test_a_condition_that_restricts_nothing_grants_everything(
    evaluator: PolicyEvaluator,
) -> None:
    held = session(
        {
            "Effect": "Allow",
            "Action": ["iam:user:read"],
            "Condition": {"Expr": {"script": 'req.instance == "T1"'}},
        }
    )
    assert evaluator.compile_query_filters(READ, held) == []


def test_owning_a_record_is_an_ordinary_condition(evaluator: PolicyEvaluator) -> None:
    """No special machinery: it compiles like any other comparison."""
    held = session({"Effect": "Allow", "Action": ["iam:user:read"], "Condition": MINE})
    assert as_data(evaluator.compile_query_filters(READ, held)) == [
        {"key": "ownerId", "comparator": "EQ", "value": "USER"}
    ]


def test_owning_joins_the_other_grants(evaluator: PolicyEvaluator) -> None:
    """Statements are alternatives, so ownership ORs in by itself."""
    held = session(
        {
            "Effect": "Allow",
            "Action": ["iam:user:read"],
            "Condition": {"StringEquals": {"target:a": "x"}},
        },
        {"Effect": "Allow", "Action": ["iam:user:read"], "Condition": MINE},
    )
    assert as_data(evaluator.compile_query_filters(READ, held)) == [
        {
            "comparator": "OR",
            "value": [
                {"key": "a", "comparator": "EQ", "value": "x"},
                {"key": "ownerId", "comparator": "EQ", "value": "USER"},
            ],
        }
    ]


def test_a_grant_qualified_twice_requires_both(evaluator: PolicyEvaluator) -> None:
    """Their own records, and only the drafts among them."""
    held = session(
        {
            "Effect": "Allow",
            "Action": ["iam:user:read"],
            "Condition": {
                "Expr": {"script": "target.ownerId == req.userId"},
                "StringEquals": {"target:kind": "draft"},
            },
        }
    )
    assert as_data(evaluator.compile_query_filters(READ, held)) == [
        {
            "comparator": "AND",
            "value": [
                {"key": "ownerId", "comparator": "EQ", "value": "USER"},
                {"key": "kind", "comparator": "EQ", "value": "draft"},
            ],
        }
    ]


# --------------------------------------------------------------------------
# a caller's own filters, against withheld fields
# --------------------------------------------------------------------------

GIVEN = [
    LeafFilter(key="test", comparator=EQ, value="test"),
    LeafFilter(key="restrictedField", comparator=EQ, value="test"),
]
RESTRICTING = MatchingPolicy(action="iam:user:read", resource="*")


def test_filters_on_fields_nobody_withholds_are_left_alone(
    evaluator: PolicyEvaluator,
) -> None:
    held = session(
        {
            "Effect": "RestrictFields",
            "Action": ["iam:user:read"],
            "NotFields": ["restrictedField"],
        },
        {"Effect": "Allow", "Action": ["iam:user:read"]},
    )
    given = [LeafFilter(key="test", comparator=EQ, value="test")]
    assert evaluator.restrict_query_filters(given, RESTRICTING, held) == given


def test_a_filter_on_a_withheld_field_finds_nothing(
    evaluator: PolicyEvaluator,
) -> None:
    held = session(
        {
            "Effect": "RestrictFields",
            "Action": ["iam:user:read"],
            "NotFields": ["restrictedField"],
        },
        {"Effect": "Allow", "Action": ["iam:user:read"]},
    )
    assert as_data(evaluator.restrict_query_filters(GIVEN, RESTRICTING, held)) == [
        {"key": "test", "comparator": "EQ", "value": "test"},
        {"key": "restrictedField", "comparator": "EQ", "value": "__INVALID__"},
    ]


def test_a_field_given_back_by_fields_may_be_queried(
    evaluator: PolicyEvaluator,
) -> None:
    held = session(
        {
            "Effect": "RestrictFields",
            "Action": ["iam:user:read"],
            "Fields": ["restrictedField"],
            "NotFields": ["restrictedField"],
        },
        {"Effect": "Allow", "Action": ["iam:user:read"]},
    )
    assert as_data(evaluator.restrict_query_filters(GIVEN, RESTRICTING, held)) == (
        as_data(GIVEN)
    )


def test_a_field_withheld_on_some_records_may_be_queried_on_the_others(
    evaluator: PolicyEvaluator,
) -> None:
    held = session(
        {
            "Effect": "RestrictFields",
            "Action": ["iam:user:read"],
            "NotFields": ["restrictedField"],
            "Condition": {"Expr": {"rule": 'target.ownerId != "USER"'}},
        },
        {"Effect": "Allow", "Action": ["iam:user:read"]},
    )
    assert as_data(evaluator.restrict_query_filters(GIVEN, RESTRICTING, held)) == [
        {"key": "test", "comparator": "EQ", "value": "test"},
        {
            "comparator": "AND",
            "value": [
                {"key": "restrictedField", "comparator": "EQ", "value": "test"},
                {"key": "ownerId", "comparator": "NEQ", "value": "USER"},
            ],
        },
    ]


def test_a_conditional_restriction_narrows_the_filter(
    evaluator: PolicyEvaluator,
) -> None:
    held = session(
        {
            "Effect": "RestrictFields",
            "Action": ["iam:user:read"],
            "NotFields": ["restrictedField"],
            "Condition": {"Expr": {"rule": 'target.id != "U1"'}},
        },
        {"Effect": "Allow", "Action": ["iam:user:read"]},
    )
    assert as_data(evaluator.restrict_query_filters(GIVEN, RESTRICTING, held)) == [
        {"key": "test", "comparator": "EQ", "value": "test"},
        {
            "comparator": "AND",
            "value": [
                {"key": "restrictedField", "comparator": "EQ", "value": "test"},
                {"key": "id", "comparator": "NEQ", "value": "U1"},
            ],
        },
    ]


def test_a_condition_that_narrows_nothing_leaves_the_filter_as_written(
    evaluator: PolicyEvaluator,
) -> None:
    held = session(
        {
            "Effect": "RestrictFields",
            "Action": ["iam:user:read"],
            "NotFields": ["restrictedField"],
            "Condition": {"Expr": {"rule": 'req.instance == "T1"'}},
        },
        {"Effect": "Allow", "Action": ["iam:user:read"]},
    )
    assert as_data(evaluator.restrict_query_filters(GIVEN, RESTRICTING, held)) == (
        as_data(GIVEN)
    )


def test_keys_every_principal_may_filter_on_are_never_withheld(
    evaluator: PolicyEvaluator,
) -> None:
    held = session(
        {"Effect": "RestrictFields", "Action": ["iam:user:read"], "NotFields": ["id"]},
        {"Effect": "Allow", "Action": ["iam:user:read"]},
    )
    given = [LeafFilter(key="id", comparator=EQ, value="U1")]
    assert evaluator.restrict_query_filters(given, RESTRICTING, held) == given


def test_a_caller_without_policies_keeps_its_filters(
    evaluator: PolicyEvaluator,
) -> None:
    assert (
        evaluator.restrict_query_filters(GIVEN, RESTRICTING, without_policies())
        == GIVEN
    )


def test_a_grouped_filter_is_carried_through_untouched(
    evaluator: PolicyEvaluator,
) -> None:
    held = session(
        {
            "Effect": "RestrictFields",
            "Action": ["iam:user:read"],
            "NotFields": ["restrictedField"],
        },
        {"Effect": "Allow", "Action": ["iam:user:read"]},
    )
    grouped = CombinatorFilter(comparator="OR", value=list(GIVEN))
    given: list[QueryFilter] = [*GIVEN, grouped]
    assert evaluator.restrict_query_filters(given, RESTRICTING, held)[2] == grouped


def test_the_package_offers_what_a_caller_needs() -> None:
    import pybac

    assert pybac.PolicyEvaluator is PolicyEvaluator
    assert pybac.MatchingPolicy is MatchingPolicy
    assert set(pybac.__all__) <= set(dir(pybac))
