from __future__ import annotations

import logging
from typing import Any

import pytest

from pybac.domain import MatchingPolicy, Policy, PolicyEffect
from pybac.processor import PolicyProcessor, statements

CONTEXT: dict[str, Any] = {
    "req": {"userId": "USER", "instance": "T1", "groups": ["G1", "G2"]},
    "user": {"tags": {"bu": ["BU1"]}},
    "target": {
        "id": "DOC2",
        "document": {"folder": "FOLDER2"},
        "resource": {"groups": ["G1"], "managers": ["USER"]},
        "data": {"status": "goal"},
        "policyTags": {"bu": ["BU1"]},
        "ownerId": "USER",
    },
}


@pytest.fixture
def processor() -> PolicyProcessor:
    return PolicyProcessor()


def ask(
    processor: PolicyProcessor,
    *statement: dict[str, Any],
    action: str = "docs:document:delete",
    resource: str = "*",
    principal: dict[str, Any] | None = None,
) -> bool:
    policy = Policy.model_validate({"Statement": list(statement)})
    matching_policy = MatchingPolicy(
        action=action,
        resource=resource,
        principal=principal or {},
        context=CONTEXT,
    )
    return processor.evaluate([policy], matching_policy)


# --------------------------------------------------------------------------
# allow and deny
# --------------------------------------------------------------------------


def test_nothing_matching_is_a_refusal(processor: PolicyProcessor) -> None:
    assert ask(processor, {"Effect": "Allow", "Action": ["docs:archive:read"]}) is False


def test_a_matching_allow_permits(processor: PolicyProcessor) -> None:
    assert (
        ask(processor, {"Effect": "Allow", "Action": ["docs:document:delete"]}) is True
    )


def test_a_deny_outweighs_an_allow(processor: PolicyProcessor) -> None:
    assert (
        ask(
            processor,
            {"Effect": "Allow", "Action": ["docs:document:*"]},
            {"Effect": "Deny", "Action": ["docs:document:delete"]},
        )
        is False
    )


def test_a_deny_outweighs_an_allow_whatever_the_order(
    processor: PolicyProcessor,
) -> None:
    assert (
        ask(
            processor,
            {"Effect": "Deny", "Action": ["docs:document:delete"]},
            {"Effect": "Allow", "Action": ["docs:document:*"]},
        )
        is False
    )


def test_a_deny_alone_still_refuses(processor: PolicyProcessor) -> None:
    assert ask(processor, {"Effect": "Deny", "Action": ["docs:archive:read"]}) is False


def test_restrict_fields_does_not_permit(processor: PolicyProcessor) -> None:
    """It qualifies access that some Allow has already granted."""
    assert (
        ask(processor, {"Effect": "RestrictFields", "Action": ["docs:document:delete"]})
        is False
    )


# --------------------------------------------------------------------------
# what a statement applies to
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "permitted"),
    [
        ("docs:document:delete", True),
        ("docs:document:*", True),
        ("docs:*", True),
        ("*", True),
        ("docs:document:read", False),
        ("docs:archive:*", False),
    ],
)
def test_an_action_is_matched_as_a_pattern(
    processor: PolicyProcessor, pattern: str, permitted: bool
) -> None:
    assert ask(processor, {"Effect": "Allow", "Action": [pattern]}) is permitted


def test_a_statement_naming_no_action_applies_to_every_action(
    processor: PolicyProcessor,
) -> None:
    assert ask(processor, {"Effect": "Allow"}) is True


def test_not_action_excludes(processor: PolicyProcessor) -> None:
    assert (
        ask(processor, {"Effect": "Allow", "NotAction": ["docs:document:delete"]})
        is False
    )
    assert ask(processor, {"Effect": "Allow", "NotAction": ["docs:archive:*"]}) is True


@pytest.mark.parametrize(
    ("written", "wanted", "permitted"),
    [
        ("ern:svc:document:DOC2", "ern:svc:document:DOC2", True),
        ("ern:svc:document:*", "ern:svc:document:DOC2", True),
        ("ern:svc:document:OTHER", "ern:svc:document:DOC2", False),
        ("ern:svc:${req:userId}/*", "ern:svc:USER/DOC2", True),
        ("ern:svc:${req:userId}/*", "ern:svc:OTHER/DOC2", False),
    ],
)
def test_a_resource_is_matched_after_its_placeholders_are_filled(
    processor: PolicyProcessor, written: str, wanted: str, permitted: bool
) -> None:
    assert (
        ask(
            processor,
            {
                "Effect": "Allow",
                "Action": ["docs:document:delete"],
                "Resource": [written],
            },
            resource=wanted,
        )
        is permitted
    )


def test_a_resource_may_be_written_as_one_string(processor: PolicyProcessor) -> None:
    assert (
        ask(
            processor,
            {
                "Effect": "Allow",
                "Action": ["docs:document:delete"],
                "Resource": "ern:*",
            },
            resource="ern:svc:document:DOC2",
        )
        is True
    )


def test_not_resource_excludes(processor: PolicyProcessor) -> None:
    statement = {
        "Effect": "Allow",
        "Action": ["docs:document:delete"],
        "NotResource": ["ern:svc:document:*"],
    }
    assert ask(processor, statement, resource="ern:svc:document:DOC2") is False
    assert ask(processor, statement, resource="ern:svc:archive:ARC1") is True


def test_a_principal_is_matched_on_any_named_value(
    processor: PolicyProcessor,
) -> None:
    statement = {
        "Effect": "Allow",
        "Action": ["docs:document:delete"],
        "Principal": {"user": ["U1", "U2"]},
    }
    assert ask(processor, statement, principal={"user": ["U2"]}) is True
    assert ask(processor, statement, principal={"user": ["U9"]}) is False
    assert ask(processor, statement, principal={"user": []}) is False
    assert ask(processor, statement, principal={}) is False


# --------------------------------------------------------------------------
# conditions
# --------------------------------------------------------------------------


def allow_when(condition: dict[str, Any]) -> dict[str, Any]:
    return {
        "Effect": "Allow",
        "Action": ["docs:document:delete"],
        "Condition": condition,
    }


@pytest.mark.parametrize(
    ("condition", "permitted"),
    [
        ({"StringEquals": {"target:data:status": "goal"}}, True),
        ({"StringEquals": {"target:data:status": "other"}}, False),
        ({"StringNotEquals": {"target:data:status": "other"}}, True),
        (
            {"ForAnyValue:StringEquals": {"target:resource:groups": "${req:groups}"}},
            True,
        ),
        ({"ForAnyValue:StringEquals": {"target:resource:groups": ["G9"]}}, False),
        ({"ContainsAtLeastOne": {"target:resource:groups": ["G1", "G9"]}}, True),
        ({"ContainsAtLeastOne": {"target:resource:groups": ["G9"]}}, False),
        ({"ContainsNone": {"target:resource:groups": ["G9"]}}, True),
        ({"ContainsAll": {"target:resource:groups": ["G1", "G2"]}}, True),
        ({"StringLike": {"target:document:folder": "FOLDER*"}}, True),
    ],
)
def test_named_conditions_qualify_a_statement(
    processor: PolicyProcessor, condition: dict[str, Any], permitted: bool
) -> None:
    assert ask(processor, allow_when(condition)) is permitted


def test_a_condition_reading_a_path_that_is_not_there_does_not_match(
    processor: PolicyProcessor,
) -> None:
    assert (
        ask(processor, allow_when({"StringEquals": {"target:absent": "goal"}})) is False
    )


def test_several_values_mean_any_of_them(processor: PolicyProcessor) -> None:
    condition = {"StringEquals": {"target:data:status": ["other", "goal"]}}
    assert ask(processor, allow_when(condition)) is True


def test_every_named_condition_must_hold(processor: PolicyProcessor) -> None:
    both = {
        "StringEquals": {"target:data:status": "goal"},
        "ContainsAtLeastOne": {"target:resource:groups": ["G1"]},
    }
    assert ask(processor, allow_when(both)) is True

    one_fails = {
        "StringEquals": {"target:data:status": "goal"},
        "ContainsAtLeastOne": {"target:resource:groups": ["G9"]},
    }
    assert ask(processor, allow_when(one_fails)) is False


def test_every_field_within_one_condition_must_hold(
    processor: PolicyProcessor,
) -> None:
    """A condition names every field it means, not just the first."""
    both = {"StringEquals": {"target:data:status": "goal", "target:id": "DOC2"}}
    assert ask(processor, allow_when(both)) is True

    one_fails = {"StringEquals": {"target:data:status": "goal", "target:id": "OTHER"}}
    assert ask(processor, allow_when(one_fails)) is False


def test_a_condition_nobody_implements_does_not_match(
    processor: PolicyProcessor,
) -> None:
    assert (
        ask(processor, allow_when({"StringStartsWith": {"target:id": "DOC"}})) is False
    )


# --------------------------------------------------------------------------
# expressions
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("script", "permitted"),
    [
        ('target.document.folder == "FOLDER2"', True),
        ('target.document.folder == "FOLDER9"', False),
        ("target.resource.groups containsAny req.groups", True),
        ("req.userId in target.resource.managers", True),
        ("target.ownerId == req.userId", True),
        ('!(target.document.folder in ["FOLDER2"])', False),
    ],
)
def test_an_expression_qualifies_a_statement(
    processor: PolicyProcessor, script: str, permitted: bool
) -> None:
    assert ask(processor, allow_when({"Expr": {"script": script}})) is permitted


def test_the_key_naming_the_script_does_not_matter(
    processor: PolicyProcessor,
) -> None:
    for key in ("script", "rule", "anything"):
        assert (
            ask(processor, allow_when({"Expr": {key: 'target.id == "DOC2"'}})) is True
        )


@pytest.mark.parametrize(
    "script",
    [
        "target.absent < 2",
        "target.user.id hasManager req.userId",
        "value | upper",
        "(unclosed",
        'target.id == "DOC2" ? 1 : 2',
    ],
)
def test_an_expression_that_cannot_be_settled_does_not_match(
    processor: PolicyProcessor, script: str
) -> None:
    """Unreadable, unsupported or not a plain yes -- none of them permit."""
    assert ask(processor, allow_when({"Expr": {"script": script}})) is False


def test_an_expression_that_cannot_be_settled_is_logged(
    processor: PolicyProcessor, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG, logger="pybac"):
        ask(processor, allow_when({"Expr": {"script": "target.absent < 2"}}))
    assert "expression could not be settled" in caplog.text


def test_an_expression_and_a_named_condition_must_both_hold(
    processor: PolicyProcessor,
) -> None:
    """Neither part may be skipped because the other came first."""
    condition = {
        "Expr": {"script": 'target.id == "DOC2"'},
        "StringEquals": {"target:data:status": "other"},
    }
    assert ask(processor, allow_when(condition)) is False


# --------------------------------------------------------------------------
# field security
# --------------------------------------------------------------------------

RESTRICTING = Policy.model_validate(
    {
        "Statement": [
            {
                "Effect": "RestrictFields",
                "Action": ["docs:document:read"],
                "NotFields": ["salary", "ssn"],
            },
            {
                "Effect": "RestrictFields",
                "Action": ["docs:document:read"],
                "NotFields": ["address"],
                "Condition": {"StringEquals": {"target:data:status": "goal"}},
            },
        ]
    }
)


def reading() -> MatchingPolicy:
    return MatchingPolicy(action="docs:document:read", context=CONTEXT)


def test_fields_to_mask_collects_what_statements_withhold(
    processor: PolicyProcessor,
) -> None:
    assert processor.fields_to_mask([RESTRICTING], reading()) == (
        "salary",
        "ssn",
        "address",
    )


def test_a_statement_can_give_a_field_back(processor: PolicyProcessor) -> None:
    policy = Policy.model_validate(
        {
            "Statement": [
                {
                    "Effect": "RestrictFields",
                    "Action": ["docs:document:read"],
                    "NotFields": ["salary", "ssn"],
                },
                {
                    "Effect": "RestrictFields",
                    "Action": ["docs:document:read"],
                    "Fields": ["ssn"],
                },
            ]
        }
    )
    assert processor.fields_to_mask([policy], reading()) == ("salary",)


def test_a_conditional_restriction_only_applies_when_it_holds(
    processor: PolicyProcessor,
) -> None:
    elsewhere = MatchingPolicy(
        action="docs:document:read",
        context={
            **CONTEXT,
            "target": {**CONTEXT["target"], "data": {"status": "other"}},
        },
    )
    assert processor.fields_to_mask([RESTRICTING], elsewhere) == ("salary", "ssn")


def test_nothing_is_masked_for_an_action_no_statement_restricts(
    processor: PolicyProcessor,
) -> None:
    other = MatchingPolicy(action="docs:document:delete", context=CONTEXT)
    assert processor.fields_to_mask([RESTRICTING], other) == ()


def test_has_field_security_ignores_conditions(processor: PolicyProcessor) -> None:
    """It decides whether masking is worth working out, so it errs towards yes."""
    elsewhere = MatchingPolicy(
        action="docs:document:read",
        context={**CONTEXT, "target": {"data": {"status": "other"}}},
    )
    assert processor.has_field_security([RESTRICTING], elsewhere) is True


def test_has_field_security_is_false_when_no_statement_restricts(
    processor: PolicyProcessor,
) -> None:
    other = MatchingPolicy(action="docs:document:delete", context=CONTEXT)
    assert processor.has_field_security([RESTRICTING], other) is False


# --------------------------------------------------------------------------
# selecting statements without settling them
# --------------------------------------------------------------------------


def test_select_returns_what_applies_before_conditions_are_weighed(
    processor: PolicyProcessor,
) -> None:
    policy = Policy.model_validate(
        {
            "Statement": [
                {"Effect": "Allow", "Action": ["docs:document:delete"], "Sid": "plain"},
                {
                    "Effect": "Allow",
                    "Action": ["docs:document:delete"],
                    "Sid": "qualified",
                    "Condition": {"StringEquals": {"target:data:status": "never"}},
                },
                {
                    "Effect": "Allow",
                    "Action": ["docs:archive:read"],
                    "Sid": "elsewhere",
                },
            ]
        }
    )
    selected = processor.select(
        [policy], MatchingPolicy(action="docs:document:delete", context=CONTEXT)
    )

    assert [s.sid for s in selected.all] == ["plain", "qualified"]
    assert [s.sid for s in selected.conditional] == ["qualified"]
    assert selected.every_one_conditional is False


def test_every_one_conditional_when_nothing_is_unconditional(
    processor: PolicyProcessor,
) -> None:
    policy = Policy.model_validate(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["docs:document:delete"],
                    "Condition": {"StringEquals": {"target:data:status": "goal"}},
                }
            ]
        }
    )
    selected = processor.select(
        [policy], MatchingPolicy(action="docs:document:delete", context=CONTEXT)
    )
    assert selected.every_one_conditional is True


def test_select_defaults_to_allow(processor: PolicyProcessor) -> None:
    policy = Policy.model_validate(
        {"Statement": [{"Effect": "Deny", "Action": ["docs:document:delete"]}]}
    )
    matching_policy = MatchingPolicy(action="docs:document:delete", context=CONTEXT)
    assert processor.select([policy], matching_policy).all == ()
    assert (
        processor.select([policy], matching_policy.with_effect(PolicyEffect.DENY)).all
        != ()
    )


def test_statements_flattens_every_policy() -> None:
    policies = [
        Policy.model_validate({"Statement": [{"Effect": "Allow", "Sid": "a"}]}),
        Policy.model_validate({"Statement": [{"Effect": "Deny", "Sid": "b"}]}),
    ]
    assert [s.sid for s in statements(policies)] == ["a", "b"]


# --------------------------------------------------------------------------
# compiling a condition into a query
# --------------------------------------------------------------------------


def filters(processor: PolicyProcessor, condition: Any) -> list[dict[str, Any]]:
    return [
        f.model_dump(mode="json")
        for f in processor.to_query_filters(condition, CONTEXT)
    ]


UNSATISFIED = [{"key": "id", "comparator": "EQ", "value": "__INVALID__"}]


@pytest.mark.parametrize("condition", [None, {}])
def test_no_condition_restricts_nothing(
    processor: PolicyProcessor, condition: Any
) -> None:
    assert filters(processor, condition) == []


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        (
            {"StringEquals": {"target:document:folder": "FOLDER2"}},
            [{"key": "document.folder", "comparator": "EQ", "value": "FOLDER2"}],
        ),
        (
            {"ContainsAtLeastOne": {"target:resource:groups": ["G1", "G9"]}},
            [
                {
                    "key": "resource.groups",
                    "comparator": "OVERLAPS",
                    "value": ["G1", "G9"],
                }
            ],
        ),
        (
            {"ForAnyValue:StringEquals": {"target:resource:groups": "${req:groups}"}},
            [
                {
                    "key": "resource.groups",
                    "comparator": "OVERLAPS",
                    "value": ["G1", "G2"],
                }
            ],
        ),
    ],
)
def test_a_named_condition_becomes_a_filter(
    processor: PolicyProcessor, condition: Any, expected: list[dict[str, Any]]
) -> None:
    assert filters(processor, condition) == expected


def test_the_target_prefix_is_dropped_and_the_rest_becomes_a_path(
    processor: PolicyProcessor,
) -> None:
    """A query addresses the record directly, so naming it again is redundant."""
    built = filters(processor, {"StringEquals": {"target:a:b:c": "x"}})
    assert built[0]["key"] == "a.b.c"


def test_a_key_that_does_not_name_the_record_keeps_its_path(
    processor: PolicyProcessor,
) -> None:
    built = filters(processor, {"StringEquals": {"other:a": "x"}})
    assert built[0]["key"] == "other.a"


def test_an_expression_becomes_a_filter(processor: PolicyProcessor) -> None:
    condition = {"Expr": {"script": "target.resource.groups containsAny req.groups"}}
    assert filters(processor, condition) == [
        {
            "key": "resource.groups",
            "comparator": "OVERLAPS",
            "value": ["G1", "G2"],
        }
    ]


def test_an_expression_already_true_of_every_record_restricts_nothing(
    processor: PolicyProcessor,
) -> None:
    assert filters(processor, {"Expr": {"script": 'req.instance == "T1"'}}) == []


def test_an_expression_true_of_no_record_lets_nothing_through(
    processor: PolicyProcessor,
) -> None:
    assert filters(processor, {"Expr": {"script": 'req.instance == "OTHER"'}}) == (
        UNSATISFIED
    )


@pytest.mark.parametrize(
    "script",
    ["target.a == target.b", "(unclosed", "target.a + 1 == 2", "value | upper"],
)
def test_an_expression_that_cannot_be_compiled_lets_nothing_through(
    processor: PolicyProcessor, script: str
) -> None:
    """Contributing no filter would leave the query unrestricted instead."""
    assert filters(processor, {"Expr": {"script": script}}) == UNSATISFIED


def test_an_expression_that_cannot_be_compiled_is_logged(
    processor: PolicyProcessor, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG, logger="pybac"):
        filters(processor, {"Expr": {"script": "target.a == target.b"}})
    assert "expression could not be compiled" in caplog.text


def test_a_condition_nobody_implements_lets_nothing_through(
    processor: PolicyProcessor,
) -> None:
    assert filters(processor, {"StringStartsWith": {"target:a": "x"}}) == UNSATISFIED


@pytest.mark.parametrize(
    "condition",
    [
        {"StringEquals": "not a mapping"},
        {"Expr": "not a mapping"},
        {"Expr": {"script": 42}},
    ],
)
def test_a_malformed_condition_lets_nothing_through(
    processor: PolicyProcessor, condition: Any
) -> None:
    assert filters(processor, condition) == UNSATISFIED


def test_several_parts_are_returned_side_by_side(processor: PolicyProcessor) -> None:
    """The caller requires them together."""
    condition = {
        "StringEquals": {"target:a": "x"},
        "ContainsAtLeastOne": {"target:groups": ["G1"]},
    }
    assert [f["key"] for f in filters(processor, condition)] == ["a", "groups"]


def test_several_fields_in_one_condition_each_give_a_filter(
    processor: PolicyProcessor,
) -> None:
    condition = {"StringEquals": {"target:a": "x", "target:b": "y"}}
    assert [f["key"] for f in filters(processor, condition)] == ["a", "b"]


@pytest.mark.parametrize(
    "condition",
    [
        {"StringEquals": "not a mapping"},
        {"Expr": "not a mapping"},
        {"Expr": {"script": 42}},
    ],
)
def test_a_malformed_condition_does_not_match(
    processor: PolicyProcessor, condition: Any
) -> None:
    """Loading a policy would refuse these; a caller passing one directly is not."""
    assert processor.holds(condition, CONTEXT) is False


def test_no_condition_matches_unconditionally(processor: PolicyProcessor) -> None:
    assert processor.holds(None, CONTEXT) is True
    assert processor.holds({}, CONTEXT) is True


def test_a_condition_that_raises_while_comparing_does_not_match(
    processor: PolicyProcessor, caplog: pytest.LogCaptureFixture
) -> None:
    """A comparison the operands do not support denies, and says so."""
    condition = {"NumericLessThan": {"target:data": "${target:data}"}}
    with caplog.at_level(logging.DEBUG, logger="pybac"):
        assert ask(processor, allow_when(condition)) is False


def test_a_condition_that_raises_is_caught_and_logged(
    processor: PolicyProcessor, caplog: pytest.LogCaptureFixture, monkeypatch: Any
) -> None:
    """Nothing escapes a decision, however badly a condition behaves."""
    from pybac.conditions import operators

    def explode(actual: Any, expected: Any) -> bool:
        raise RuntimeError("boom")

    monkeypatch.setitem(operators.CONDITIONS, "StringEquals", explode)
    with caplog.at_level(logging.DEBUG, logger="pybac"):
        held = processor.holds({"StringEquals": {"target:id": "DOC2"}}, CONTEXT)

    assert held is False
    assert "condition could not be settled" in caplog.text
