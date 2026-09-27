import json
from dataclasses import replace
from pathlib import Path

import pytest

from testcase_gen.generator import UnsupportedRuleError, generate_cases
from testcase_gen.models import CaseSpec, CaseType
from testcase_gen.parser import parse_rules_file


RULES_PATH = Path(__file__).resolve().parents[1] / "rules.conf"


@pytest.fixture(scope="module")
def parsed_rules():
    return parse_rules_file(RULES_PATH)


@pytest.fixture(scope="module")
def generated_cases(parsed_rules):
    return generate_cases(parsed_rules)


@pytest.fixture(scope="module")
def cases_by_key(generated_cases):
    return {(case.rule_id, case.type): case for case in generated_cases}


def test_generates_one_positive_and_negative_for_every_rule(generated_cases):
    assert len(generated_cases) == 16
    assert {case.rule_id for case in generated_cases} == set(range(1001, 1009))

    for rule_id in range(1001, 1009):
        rule_cases = [case for case in generated_cases if case.rule_id == rule_id]
        assert len(rule_cases) == 2
        assert {case.type for case in rule_cases} == {
            CaseType.POSITIVE,
            CaseType.NEGATIVE,
        }


def test_case_spec_shape_and_json_serialization(generated_cases):
    expected_fields = {
        "case_id",
        "rule_id",
        "type",
        "method",
        "path",
        "headers",
        "body",
        "expected_code",
        "generation_strategy",
        "warnings",
        "metadata",
    }

    for case in generated_cases:
        assert isinstance(case, CaseSpec)
        assert case.case_id == "rule-{}-{}".format(case.rule_id, case.type.value)
        assert case.method
        assert case.path.startswith("/")
        assert isinstance(case.headers, dict)
        assert isinstance(case.warnings, list)
        assert isinstance(case.metadata, dict)
        assert set(case.to_dict()) == expected_fields

    serialized = json.dumps(
        [case.to_dict() for case in generated_cases], ensure_ascii=False
    )
    assert '"type": "positive"' in serialized
    assert '"type": "negative"' in serialized


def test_deny_rules_derive_expected_codes_from_rules(
    parsed_rules, cases_by_key
):
    for rule in parsed_rules:
        if rule.disruptive_action != "deny":
            continue
        positive = cases_by_key[(rule.rule_id, CaseType.POSITIVE)]
        negative = cases_by_key[(rule.rule_id, CaseType.NEGATIVE)]
        assert positive.expected_code == rule.status
        assert negative.expected_code == 200


def test_args_regex_strategy(cases_by_key):
    positive = cases_by_key[(1001, CaseType.POSITIVE)]
    negative = cases_by_key[(1001, CaseType.NEGATIVE)]

    assert positive.generation_strategy == "args-regex"
    assert positive.path == "/?id=1 OR 1=1"
    assert positive.expected_code == 403
    assert negative.path == "/?id=normal_value"
    assert negative.expected_code == 200


def test_args_contains_lowercase_strategy(cases_by_key):
    positive = cases_by_key[(1002, CaseType.POSITIVE)]
    negative = cases_by_key[(1002, CaseType.NEGATIVE)]

    assert positive.generation_strategy == "args-contains-lowercase"
    assert "<ScRiPt>" in positive.path
    assert positive.metadata == {"transformation_probe": "mixed-case input"}
    assert negative.path == "/?q=hello+world"


def test_args_url_decode_strategy_marks_pre_encoded_path(cases_by_key):
    positive = cases_by_key[(1003, CaseType.POSITIVE)]
    negative = cases_by_key[(1003, CaseType.NEGATIVE)]

    assert positive.generation_strategy == "args-regex-url-decode"
    assert positive.path == "/?file=%2e%2e%2f%2e%2e%2fetc/passwd"
    assert positive.metadata["wire_encoding"] == "already-percent-encoded"
    assert positive.warnings
    assert negative.path == "/?file=docs/readme.txt"


def test_request_header_regex_strategies(cases_by_key):
    scanner_positive = cases_by_key[(1004, CaseType.POSITIVE)]
    scanner_negative = cases_by_key[(1004, CaseType.NEGATIVE)]
    referer_positive = cases_by_key[(1007, CaseType.POSITIVE)]
    referer_negative = cases_by_key[(1007, CaseType.NEGATIVE)]

    assert scanner_positive.generation_strategy == "request-header-regex"
    assert scanner_positive.headers == {"User-Agent": "sqlmap/1.7"}
    assert scanner_negative.headers == {"User-Agent": "Mozilla/5.0"}
    assert referer_positive.headers == {"Referer": "https://evil.com/page"}
    assert referer_negative.headers == {"Referer": "https://google.com"}


def test_request_method_negated_within_strategy(cases_by_key):
    positive = cases_by_key[(1005, CaseType.POSITIVE)]
    negative = cases_by_key[(1005, CaseType.NEGATIVE)]

    assert positive.generation_strategy == "request-method-negated-within"
    assert positive.method == "DELETE"
    assert positive.expected_code == 405
    assert negative.method == "POST"
    assert negative.expected_code == 200


def test_rule_engine_off_uses_differential_control_strategy(cases_by_key):
    positive = cases_by_key[(1006, CaseType.POSITIVE)]
    negative = cases_by_key[(1006, CaseType.NEGATIVE)]

    assert positive.generation_strategy == (
        "request-uri-rule-engine-off-differential"
    )
    assert negative.generation_strategy == positive.generation_strategy
    assert positive.path.startswith("/api/health?")
    assert negative.path.startswith("/other?")
    assert positive.path.split("?", 1)[1] == negative.path.split("?", 1)[1]
    assert "id=1 OR 1=1" in positive.path
    assert positive.expected_code == 200
    assert negative.expected_code == 403
    assert positive.metadata["control_action"] == "ruleEngine=off"
    assert positive.metadata["expected_engine_state"] == "off"
    assert negative.metadata["expected_engine_state"] == "on"
    assert positive.metadata["probe_rule_id"] == negative.metadata["probe_rule_id"]


def test_request_body_regex_strategy(cases_by_key):
    positive = cases_by_key[(1008, CaseType.POSITIVE)]
    negative = cases_by_key[(1008, CaseType.NEGATIVE)]

    assert positive.generation_strategy == "request-body-regex"
    assert positive.method == "POST"
    assert positive.path == "/search"
    assert positive.headers == {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    assert positive.body == "query=SELECT name FROM users"
    assert positive.expected_code == 403
    assert negative.body == "query=hello"
    assert negative.expected_code == 200


def test_generation_does_not_read_gold_or_any_other_file(parsed_rules, monkeypatch):
    def fail_on_read(*args, **kwargs):
        raise AssertionError("generator attempted filesystem input")

    monkeypatch.setattr(Path, "read_text", fail_on_read)
    assert len(generate_cases(parsed_rules)) == 16


def test_unsupported_rule_is_reported_explicitly(parsed_rules):
    unsupported = replace(parsed_rules[0], operator="unsupportedOperator")

    with pytest.raises(UnsupportedRuleError, match=r"rule 1001 is unsupported"):
        generate_cases([unsupported])
