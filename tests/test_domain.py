from __future__ import annotations

from typing import Any

import pytest
from pydantic import TypeAdapter, ValidationError

from pybac.domain import (
    CombinatorFilter,
    LeafFilter,
    MatchingPolicy,
    Policy,
    PolicyEffect,
    PolicyStatement,
    QueryFilter,
    QueryFilterComparator,
    SecurityContext,
    SessionContext,
    validate_policies,
)
from pybac.errors import PolicyError

# A policy as it is stored: PascalCase, and free to omit anything but Effect.
STORED_POLICY: dict[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "readOwnFolder",
            "Effect": "Allow",
            "Action": ["docs:folder:read"],
            "Resource": ["ern:svc:docs:folder:*"],
            "Condition": {"Expr": {"script": 'target.document.folder == "FOLDER2"'}},
        },
        {
            "Effect": "RestrictFields",
            "Action": ["docs:folder:read"],
            "NotFields": ["salary"],
        },
    ],
}


# --------------------------------------------------------------------------
# policies
# --------------------------------------------------------------------------


def test_a_stored_policy_loads() -> None:
    policy = Policy.model_validate(STORED_POLICY)

    first, second = policy.statement
    assert policy.version == "2012-10-17"
    assert first.sid == "readOwnFolder"
    assert first.effect is PolicyEffect.ALLOW
    assert first.action == ["docs:folder:read"]
    assert first.condition == {
        "Expr": {"script": 'target.document.folder == "FOLDER2"'}
    }
    assert second.not_fields == ["salary"]


def test_a_policy_round_trips_to_the_stored_shape() -> None:
    policy = Policy.model_validate(STORED_POLICY)
    assert (
        policy.model_dump(by_alias=True, exclude_none=True, mode="json")
        == STORED_POLICY
    )


def test_fields_are_reachable_by_python_name_too() -> None:
    statement = PolicyStatement(effect=PolicyEffect.DENY, not_action=["a:b:c"])
    assert statement.not_action == ["a:b:c"]
    assert statement.model_dump(by_alias=True, exclude_none=True) == {
        "Effect": PolicyEffect.DENY,
        "NotAction": ["a:b:c"],
    }


def test_only_effect_is_required() -> None:
    statement = PolicyStatement.model_validate({"Effect": "Allow"})
    assert statement.action is None
    assert statement.resource is None


def test_resource_may_be_one_string_or_many() -> None:
    assert (
        PolicyStatement.model_validate({"Effect": "Allow", "Resource": "a"}).resource
        == "a"
    )
    assert PolicyStatement.model_validate(
        {"Effect": "Allow", "Resource": ["a", "b"]}
    ).resource == ["a", "b"]


def test_an_unrecognised_effect_is_refused() -> None:
    """A statement reading "deny" would match nothing and silently permit."""
    with pytest.raises(ValidationError):
        PolicyStatement.model_validate({"Effect": "deny"})


def test_a_statement_is_frozen() -> None:
    statement = PolicyStatement(effect=PolicyEffect.ALLOW)
    with pytest.raises(ValidationError):
        statement.effect = PolicyEffect.DENY


# --------------------------------------------------------------------------
# schema constraints
# --------------------------------------------------------------------------


def test_loading_tolerates_a_statement_that_breaks_a_constraint() -> None:
    """Refusing the whole set would deny everything, which is worse."""
    statement = PolicyStatement.model_validate(
        {"Effect": "Allow", "Action": ["a"], "NotAction": ["b"]}
    )
    assert statement.schema_problems() == ["Action and NotAction cannot both be set"]


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("Action", "NotAction"),
        ("Resource", "NotResource"),
        ("Fields", "NotFields"),
        ("Principal", "NotPrincipal"),
    ],
)
def test_mutually_exclusive_pairs_are_reported(left: str, right: str) -> None:
    value: Any = {"k": "v"} if left == "Principal" else ["v"]
    statement = PolicyStatement.model_validate(
        {"Effect": "Allow", left: value, right: value}
    )
    assert f"{left} and {right} cannot both be set" in statement.schema_problems()


def test_a_misspelled_field_is_reported_once() -> None:
    statement = PolicyStatement.model_validate({"Effect": "Allow", "NotFeilds": ["x"]})
    assert statement.schema_problems() == ["unknown statement field 'NotFeilds'"]


def test_strict_validation_refuses_what_schema_problems_reports() -> None:
    with pytest.raises(ValidationError):
        PolicyStatement.model_validate(
            {"Effect": "Allow", "Action": ["a"], "NotAction": ["b"]},
            context={"strict_schema": True},
        )


def test_validate_policies_reports_every_problem_with_its_location() -> None:
    policy = Policy.model_validate(
        {
            "Statement": [
                {"Effect": "Allow"},
                {"Effect": "Allow", "Action": ["a"], "NotAction": ["b"]},
            ]
        }
    )
    with pytest.raises(PolicyError) as raised:
        validate_policies([policy])

    assert raised.value.details == [
        "policy[0].Statement[1]: Action and NotAction cannot both be set"
    ]


def test_validate_policies_accepts_a_sound_set() -> None:
    validate_policies([Policy.model_validate(STORED_POLICY)])


# --------------------------------------------------------------------------
# the access request
# --------------------------------------------------------------------------


def test_matching_policy_defaults_to_any_resource_and_no_effect() -> None:
    matching_policy = MatchingPolicy(action="docs:folder:read")
    assert matching_policy.resource == ""
    assert matching_policy.effect is None
    assert matching_policy.principal == {}


def test_matching_policy_narrows_without_mutating() -> None:
    matching_policy = MatchingPolicy(action="docs:folder:read", resource="*")

    restricted = matching_policy.with_effect(PolicyEffect.RESTRICT_FIELDS)
    contextual = matching_policy.with_context({"req": {"userId": "U1"}})

    assert matching_policy.effect is None and matching_policy.context is None
    assert restricted.effect is PolicyEffect.RESTRICT_FIELDS
    assert contextual.context == {"req": {"userId": "U1"}}


def test_matching_policy_refuses_an_unknown_key() -> None:
    """Unlike a stored policy, this is built in code, so a typo is a bug."""
    with pytest.raises(ValidationError):
        MatchingPolicy(action="a", resrouce="*")  # type: ignore[call-arg]


# --------------------------------------------------------------------------
# principals
# --------------------------------------------------------------------------


def test_a_session_loads_from_the_wire_shape() -> None:
    session = SessionContext.model_validate(
        {
            "userId": "U1",
            "instance": "T1",
            "token": "TOKEN",
            "userInfo": {"name": "Name", "locale": "fr", "ctx": {"extId": "EXT1"}},
            "securityContext": {
                "policies": [STORED_POLICY],
                "securityGroups": ["G1", "G2"],
                "isAdmin": False,
            },
        }
    )

    assert session.user_id == "U1"
    assert session.instance == "T1"
    assert session.user_info.locale == "fr"
    assert session.user_info.ctx == {"extId": "EXT1"}
    assert session.security_context.security_groups == ["G1", "G2"]
    assert (
        session.security_context.policies[0].statement[0].effect is PolicyEffect.ALLOW
    )


def test_a_security_context_must_state_its_policies() -> None:
    """An empty set refuses everything, so it should be written, not defaulted."""
    with pytest.raises(ValidationError):
        SecurityContext()  # type: ignore[call-arg]


def test_a_security_context_keeps_keys_it_does_not_know() -> None:
    context = SecurityContext.model_validate({"policies": [], "customFlag": True})
    assert context.model_dump(by_alias=True)["customFlag"] is True


def test_session_defaults_cover_what_the_evaluator_falls_back_to() -> None:
    session = SessionContext(
        user_id="U1", instance="T1", security_context=SecurityContext(policies=[])
    )
    assert session.user_info.locale == ""
    assert session.user_info.ctx == {}
    assert session.security_context.tags == {}
    assert session.security_context.security_groups == []


def test_a_session_drops_what_no_decision_reads() -> None:
    """A token, a display name: accepted so real payloads load, then let go."""
    session = SessionContext.model_validate(
        {
            "userId": "U1",
            "instance": "T1",
            "token": "SECRET",
            "userInfo": {"name": "Name", "locale": "fr"},
            "securityContext": {"policies": []},
        }
    )
    dumped = session.model_dump(by_alias=True)
    assert "token" not in dumped
    assert "name" not in dumped["userInfo"]


def test_a_security_context_keeps_the_flags_a_service_hangs_on_it() -> None:
    """Its wire shape declares an open map, unlike the models around it."""
    context = SecurityContext.model_validate(
        {"policies": [], "isAdmin": True, "isBot": False}
    )
    dumped = context.model_dump(by_alias=True)
    assert dumped["isAdmin"] is True
    assert dumped["isBot"] is False


# --------------------------------------------------------------------------
# query filters
# --------------------------------------------------------------------------

FILTERS: TypeAdapter[LeafFilter | CombinatorFilter] = TypeAdapter(QueryFilter)


def test_a_leaf_filter_loads_as_a_leaf() -> None:
    parsed = FILTERS.validate_python({"key": "a", "comparator": "EQ", "value": "v"})
    assert isinstance(parsed, LeafFilter)
    assert parsed.comparator is QueryFilterComparator.EQ


@pytest.mark.parametrize("combinator", ["AND", "OR"])
def test_a_combinator_loads_as_a_combinator(combinator: str) -> None:
    parsed = FILTERS.validate_python(
        {
            "comparator": combinator,
            "value": [{"key": "a", "comparator": "EQ", "value": 1}],
        }
    )
    assert isinstance(parsed, CombinatorFilter)
    assert isinstance(parsed.value[0], LeafFilter)


def test_a_filter_tree_nests_and_round_trips() -> None:
    tree = {
        "comparator": "OR",
        "value": [
            {"key": "a", "comparator": "EQ", "value": 1},
            {
                "comparator": "AND",
                "value": [
                    {"key": "b", "comparator": "IN", "value": ["x"]},
                    {"key": "c", "comparator": "OVERLAPS", "value": ["y"]},
                ],
            },
        ],
    }
    parsed = FILTERS.validate_python(tree)
    assert FILTERS.dump_python(parsed, mode="json") == tree


def test_a_leaf_may_have_no_key() -> None:
    parsed = FILTERS.validate_python({"comparator": "EQ", "value": None})
    assert isinstance(parsed, LeafFilter)
    assert parsed.key is None


def test_comparators_keep_their_wire_values() -> None:
    """Whatever translates a filter into a query reads these strings.

    Words rather than symbols, so a filter survives a query string without
    escaping.
    """
    assert QueryFilterComparator.EQ.value == "EQ"
    assert QueryFilterComparator.GTE.value == "GTE"
    assert QueryFilterComparator.NOT_OVERLAPS.value == "NOT_OVERLAPS"
    assert FILTERS.dump_python(
        LeafFilter(key="a", comparator=QueryFilterComparator.MATCHES, value="x"),
        mode="json",
    ) == {"key": "a", "comparator": "MATCHES", "value": "x"}


def test_an_unknown_comparator_is_refused() -> None:
    with pytest.raises(ValidationError):
        FILTERS.validate_python({"key": "a", "comparator": "~=", "value": 1})


def test_a_policy_error_reads_as_its_message_and_its_details() -> None:
    error = PolicyError("invalidPolicy", ["first", "second"])
    assert str(error) == "invalidPolicy: first; second"
    assert str(PolicyError("invalidPolicy")) == "invalidPolicy"


def test_strict_validation_accepts_a_sound_statement() -> None:
    statement = PolicyStatement.model_validate(
        {"Effect": "Allow", "Action": ["a"]}, context={"strict_schema": True}
    )
    assert statement.action == ["a"]
