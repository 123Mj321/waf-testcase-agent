from pathlib import Path

import pytest

from testcase_gen.parser import parse_rules_file


RULES_PATH = Path(__file__).resolve().parents[1] / "rules.conf"


@pytest.fixture(scope="module")
def rules_by_id():
    rules = parse_rules_file(RULES_PATH)
    return {rule.rule_id: rule for rule in rules}


def test_all_eight_rules_are_parsed(rules_by_id):
    assert len(rules_by_id) == 8
    assert list(sorted(rules_by_id)) == list(range(1001, 1009))


def test_targets_are_structured(rules_by_id):
    expected = {
        1001: ("ARGS", "id"),
        1002: ("ARGS", "q"),
        1003: ("ARGS", "file"),
        1004: ("REQUEST_HEADERS", "User-Agent"),
        1005: ("REQUEST_METHOD", None),
        1006: ("REQUEST_URI", None),
        1007: ("REQUEST_HEADERS", "Referer"),
        1008: ("REQUEST_BODY", None),
    }

    for rule_id, target in expected.items():
        variables = rules_by_id[rule_id].variables
        assert len(variables) == 1
        assert (variables[0].collection, variables[0].selector) == target


def test_operators_are_parsed_without_at_prefix(rules_by_id):
    expected = {
        1001: "rx",
        1002: "contains",
        1003: "rx",
        1004: "rx",
        1005: "within",
        1006: "beginsWith",
        1007: "rx",
        1008: "rx",
    }
    assert {rule_id: rule.operator for rule_id, rule in rules_by_id.items()} == expected


def test_negated_operator_is_preserved(rules_by_id):
    assert rules_by_id[1005].operator_negated is True
    assert all(
        not rule.operator_negated
        for rule_id, rule in rules_by_id.items()
        if rule_id != 1005
    )
    assert rules_by_id[1005].operator_arg == "GET POST"


def test_transformations_are_ordered(rules_by_id):
    assert rules_by_id[1002].transformations == ["lowercase"]
    assert rules_by_id[1003].transformations == ["urlDecodeUni"]
    assert rules_by_id[1001].transformations == []


def test_ctl_action_is_structured(rules_by_id):
    rule = rules_by_id[1006]
    assert rule.disruptive_action == "pass"
    assert rule.log is False
    assert rule.ctl_actions == {"ruleEngine": "off"}


def test_messages_keep_spaces(rules_by_id):
    assert rules_by_id[1001].msg == "SQLi keywords in id"
    assert rules_by_id[1005].msg == "method not allowed"
    assert rules_by_id[1007].msg == "malicious referer domain"
    assert rules_by_id[1008].msg == "SQLi in body"


def test_regular_expression_is_not_split_or_unescaped(rules_by_id):
    assert rules_by_id[1001].operator_arg == (
        r"(?i:union.+select|or\s+1\s*=\s*1|drop\s+table)"
    )
    assert rules_by_id[1008].operator_arg == r"(?i:select\s.+\sfrom\s)"


def test_actions_and_source_locations_are_preserved(rules_by_id):
    rule = rules_by_id[1001]
    assert [action.name for action in rule.actions] == [
        "id",
        "phase",
        "deny",
        "status",
        "log",
        "msg",
    ]
    assert rule.phase == 2
    assert rule.status == 403
    assert rule.disruptive_action == "deny"
    assert rule.log is True
    assert rule.source_line == 1
    assert rule.source_end_line == 2
    assert "\\\n" in rule.raw_text
