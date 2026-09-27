import copy
from dataclasses import replace
from pathlib import Path

import pytest

from testcase_gen.generator import generate_cases
from testcase_gen.models import CaseType
from testcase_gen.parser import parse_rules_file
from testcase_gen.validator import MISSING_VALUE, load_gold, validate_gold


ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "rules.conf"
GOLD_PATH = ROOT / "gold.json"


@pytest.fixture(scope="module")
def generated_cases():
    return generate_cases(parse_rules_file(RULES_PATH))


@pytest.fixture(scope="module")
def gold_cases():
    return load_gold(GOLD_PATH)


def replace_generated(cases, rule_id, case_type, **changes):
    return [
        replace(case, **changes)
        if case.rule_id == rule_id and case.type == case_type
        else case
        for case in cases
    ]


def find_diff(result, rule_id, case_type, field):
    return next(
        diff
        for diff in result.diffs
        if diff.rule_id == rule_id
        and diff.type == case_type
        and diff.field == field
    )


def test_generated_cases_match_gold(generated_cases, gold_cases):
    result = validate_gold(generated_cases, gold_cases)

    assert result.passed is True
    assert result.generated_count == 16
    assert result.gold_count == 16
    assert result.diffs == []


def test_gold_array_order_does_not_affect_validation(
    generated_cases, gold_cases
):
    result = validate_gold(generated_cases, list(reversed(gold_cases)))
    assert result.passed is True


def test_json_object_key_order_does_not_affect_headers(
    generated_cases, gold_cases
):
    generated = replace_generated(
        generated_cases,
        1004,
        CaseType.POSITIVE,
        headers={"X-Second": "2", "X-First": "1"},
    )
    gold = copy.deepcopy(gold_cases)
    target = next(
        case
        for case in gold
        if case["rule_id"] == 1004 and case["type"] == "positive"
    )
    target["headers"] = {"X-First": "1", "X-Second": "2"}

    assert validate_gold(generated, gold).passed is True


def test_path_mismatch_is_structured(generated_cases, gold_cases):
    generated = replace_generated(
        generated_cases,
        1001,
        CaseType.POSITIVE,
        path="/?id=different",
    )
    result = validate_gold(generated, gold_cases)
    diff = find_diff(result, 1001, "positive", "path")

    assert result.passed is False
    assert diff.case_id == "rule-1001-positive"
    assert diff.expected == "/?id=1 OR 1=1"
    assert diff.actual == "/?id=different"
    assert diff.message == "generated field differs from gold"


def test_headers_mismatch_is_structured(generated_cases, gold_cases):
    generated = replace_generated(
        generated_cases,
        1004,
        CaseType.POSITIVE,
        headers={"User-Agent": "Mozilla/5.0"},
    )
    diff = find_diff(
        validate_gold(generated, gold_cases),
        1004,
        "positive",
        "headers",
    )

    assert diff.expected == {"User-Agent": "sqlmap/1.7"}
    assert diff.actual == {"User-Agent": "Mozilla/5.0"}


def test_body_mismatch_is_structured(generated_cases, gold_cases):
    generated = replace_generated(
        generated_cases,
        1008,
        CaseType.POSITIVE,
        body="query=different",
    )
    diff = find_diff(
        validate_gold(generated, gold_cases),
        1008,
        "positive",
        "body",
    )

    assert diff.expected == "query=SELECT name FROM users"
    assert diff.actual == "query=different"


def test_expected_code_mismatch_is_structured(generated_cases, gold_cases):
    generated = replace_generated(
        generated_cases,
        1005,
        CaseType.POSITIVE,
        expected_code=403,
    )
    diff = find_diff(
        validate_gold(generated, gold_cases),
        1005,
        "positive",
        "expected_code",
    )

    assert diff.expected == 405
    assert diff.actual == 403


def test_missing_generated_case_is_reported(generated_cases, gold_cases):
    generated = [
        case
        for case in generated_cases
        if not (case.rule_id == 1008 and case.type == CaseType.NEGATIVE)
    ]
    result = validate_gold(generated, gold_cases)
    missing = find_diff(result, 1008, "negative", "case")

    assert result.passed is False
    assert missing.actual == MISSING_VALUE
    assert missing.message == "generated case is missing"
    assert any(diff.field == "case_count" for diff in result.diffs)
    assert any(diff.field == "generated_case_types" for diff in result.diffs)


def test_unexpected_generated_case_is_reported(generated_cases, gold_cases):
    unexpected = replace(
        generated_cases[0],
        case_id="rule-9999-positive",
        rule_id=9999,
    )
    result = validate_gold(generated_cases + [unexpected], gold_cases)
    diff = find_diff(result, 9999, "positive", "case")

    assert diff.expected == MISSING_VALUE
    assert diff.message == "generated case is unexpected"
    assert any(diff.field == "rule_id_coverage" for diff in result.diffs)


def test_duplicate_generated_key_is_reported(generated_cases, gold_cases):
    result = validate_gold(generated_cases + [generated_cases[0]], gold_cases)
    diff = find_diff(result, 1001, "positive", "duplicate_key")

    assert diff.expected == 1
    assert diff.actual == 2
    assert "generated" in diff.message


def test_duplicate_gold_key_is_reported(generated_cases, gold_cases):
    duplicated_gold = list(gold_cases) + [copy.deepcopy(gold_cases[0])]
    result = validate_gold(generated_cases, duplicated_gold)
    diff = find_diff(result, 1001, "positive", "duplicate_key")

    assert diff.expected == 1
    assert diff.actual == 2
    assert "gold" in diff.message


def test_null_and_empty_string_are_not_equivalent(generated_cases, gold_cases):
    generated = replace_generated(
        generated_cases,
        1001,
        CaseType.POSITIVE,
        body="",
    )
    diff = find_diff(
        validate_gold(generated, gold_cases),
        1001,
        "positive",
        "body",
    )

    assert diff.expected is None
    assert diff.actual == ""


def test_missing_field_is_distinct_from_null(generated_cases, gold_cases):
    gold = copy.deepcopy(gold_cases)
    target = next(
        case
        for case in gold
        if case["rule_id"] == 1001 and case["type"] == "positive"
    )
    del target["body"]
    diff = find_diff(
        validate_gold(generated_cases, gold),
        1001,
        "positive",
        "body",
    )

    assert diff.expected == MISSING_VALUE
    assert diff.actual is None
