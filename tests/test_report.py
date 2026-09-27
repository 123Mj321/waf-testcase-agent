import json
from dataclasses import replace
from pathlib import Path

import pytest

from testcase_gen.executor import ExecutionResult
from testcase_gen.generator import generate_cases
from testcase_gen.models import CaseType
from testcase_gen.parser import parse_rules_file
from testcase_gen.report import (
    CaseResultStatus,
    OverallStatus,
    PhaseStatus,
    ReportIssue,
    build_report,
    render_json_report,
    render_terminal_report,
    write_json_report,
)
from testcase_gen.validator import GoldDiff, GoldValidationResult, load_gold, validate_gold


ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "rules.conf"
GOLD_PATH = ROOT / "gold.json"


@pytest.fixture(scope="module")
def rules():
    return parse_rules_file(RULES_PATH)


@pytest.fixture(scope="module")
def cases(rules):
    return generate_cases(rules)


@pytest.fixture(scope="module")
def gold_validation(cases):
    return validate_gold(cases, load_gold(GOLD_PATH))


@pytest.fixture(scope="module")
def successful_results(cases):
    return [
        ExecutionResult(
            case_id=case.case_id,
            rule_id=case.rule_id,
            type=case.type,
            expected_code=case.expected_code,
            actual_code=case.expected_code,
            passed=True,
            latency_ms=index + 0.125,
            response_headers={"content-type": "text/plain"},
            response_body_excerpt="response for {}".format(case.case_id),
            error=None,
        )
        for index, case in enumerate(cases)
    ]


def successful_report(rules, cases, gold_validation, successful_results):
    return build_report(
        rules=rules,
        cases=cases,
        gold_validation=gold_validation,
        execution_results=successful_results,
        duration=42.125,
        expected_rule_count=8,
    )


def test_all_success_report(
    rules, cases, gold_validation, successful_results
):
    report = successful_report(
        rules, cases, gold_validation, successful_results
    )

    assert report.generation_status == PhaseStatus.PASS
    assert report.gold_status == PhaseStatus.PASS
    assert report.runtime_status == PhaseStatus.PASS
    assert report.overall_status == OverallStatus.SUCCESS
    assert report.gold_passed is True
    assert report.gold_diffs == []


def test_gold_mismatch_is_independent_from_successful_runtime(
    rules, cases, successful_results
):
    validation = GoldValidationResult(
        gold_count=16,
        generated_count=16,
        diffs=[
            GoldDiff(
                rule_id=1003,
                type="positive",
                field="path",
                expected="/?file=expected",
                actual="/?file=actual",
                message="generated field differs from gold",
            )
        ],
    )
    report = build_report(
        rules,
        cases,
        gold_validation=validation,
        execution_results=successful_results,
    )

    assert report.gold_status == PhaseStatus.FAIL
    assert report.gold_matched_count == 15
    assert report.runtime_status == PhaseStatus.PASS
    assert report.execution_passed == 16
    assert report.overall_status == OverallStatus.FAIL

    terminal = render_terminal_report(report)
    assert "Gold Differences" in terminal
    assert "[DIFF] rule-1003-positive" in terminal
    assert "expected: \"/?file=expected\"" in terminal
    assert "actual: \"/?file=actual\"" in terminal


def test_runtime_failure_is_independent_from_successful_gold(
    rules, cases, gold_validation, successful_results
):
    failed = replace(
        successful_results[0],
        actual_code=200,
        passed=False,
        response_body_excerpt="backend response",
    )
    results = [failed] + successful_results[1:]
    report = build_report(rules, cases, gold_validation, results)

    assert report.gold_status == PhaseStatus.PASS
    assert report.runtime_status == PhaseStatus.FAIL
    assert report.execution_passed == 15
    assert report.execution_failed == 1
    assert report.execution_errors == 0
    assert report.case_results[0].status == CaseResultStatus.FAIL
    assert report.overall_status == OverallStatus.FAIL


def test_execution_error_is_counted_separately(
    rules, cases, gold_validation, successful_results
):
    error = replace(
        successful_results[0],
        actual_code=None,
        passed=False,
        response_headers={},
        response_body_excerpt="",
        error="ConnectTimeout: timed out",
    )
    report = build_report(
        rules,
        cases,
        gold_validation,
        [error] + successful_results[1:],
    )

    assert report.execution_passed == 15
    assert report.execution_failed == 0
    assert report.execution_errors == 1
    assert report.case_results[0].status == CaseResultStatus.ERROR
    assert report.case_results[0].error == "ConnectTimeout: timed out"
    assert report.runtime_status == PhaseStatus.FAIL

    terminal = render_terminal_report(report)
    assert "[ERROR] rule-1001-positive" in terminal
    assert "error: ConnectTimeout: timed out" in terminal


def test_runtime_not_run_is_incomplete_not_success(
    rules, cases, gold_validation
):
    report = build_report(
        rules,
        cases,
        gold_validation=gold_validation,
        execution_results=None,
    )

    assert report.generation_status == PhaseStatus.PASS
    assert report.gold_status == PhaseStatus.PASS
    assert report.runtime_status == PhaseStatus.NOT_RUN
    assert report.execution_count == 0
    assert report.overall_status == OverallStatus.INCOMPLETE
    assert "Status              NOT RUN" in render_terminal_report(report)


def test_unsupported_rule_fails_generation(
    rules, cases, gold_validation
):
    report = build_report(
        rules,
        cases,
        gold_validation=gold_validation,
        execution_results=None,
        unsupported_rules=[
            ReportIssue(
                stage="generation",
                rule_id=2001,
                message="unsupported operator",
            )
        ],
    )

    assert report.generation_status == PhaseStatus.FAIL
    assert report.overall_status == OverallStatus.FAIL
    assert len(report.unsupported_rules) == 1
    assert "[UNSUPPORTED] rule=2001 unsupported operator" in (
        render_terminal_report(report)
    )


@pytest.mark.parametrize(
    "error_field,error_value",
    [
        ("parse_errors", ["rules.conf:1: invalid syntax"]),
        ("generation_errors", ["case generation failed"]),
    ],
)
def test_parser_or_generation_error_fails_report(
    rules, cases, error_field, error_value
):
    kwargs = {error_field: error_value}
    report = build_report(rules, cases, **kwargs)

    assert report.generation_status == PhaseStatus.FAIL
    assert report.overall_status == OverallStatus.FAIL


def test_json_report_round_trips_and_writes_artifact(
    tmp_path, rules, cases, gold_validation, successful_results
):
    report = successful_report(
        rules, cases, gold_validation, successful_results
    )
    rendered = render_json_report(report)
    decoded = json.loads(rendered)

    assert decoded["summary"]["overall_status"] == "SUCCESS"
    assert decoded["generation"]["cases_generated"] == 16
    assert decoded["gold_validation"]["exact_matches"] == 16
    assert decoded["execution"]["passed"] == 16

    output = write_json_report(report, tmp_path / "artifacts" / "report.json")
    assert output.name == "report.json"
    assert json.loads(output.read_text(encoding="utf-8")) == decoded


def test_case_result_json_fields_are_complete(
    rules, cases, gold_validation, successful_results
):
    report = successful_report(
        rules, cases, gold_validation, successful_results
    )
    case = report.to_dict()["cases"][0]

    assert set(case) == {
        "case_id",
        "rule_id",
        "type",
        "expected_code",
        "actual_code",
        "passed",
        "status",
        "latency_ms",
        "response_headers",
        "response_body_excerpt",
        "error",
    }
    assert case["case_id"] == "rule-1001-positive"
    assert case["rule_id"] == 1001
    assert case["type"] == "positive"
    assert case["expected_code"] == 403
    assert case["actual_code"] == 403
    assert case["passed"] is True


def test_summary_numbers_are_correct(
    rules, cases, gold_validation, successful_results
):
    report = successful_report(
        rules, cases, gold_validation, successful_results
    )

    assert report.rule_count == 8
    assert report.rule_coverage == list(range(1001, 1009))
    assert report.generated_count == 16
    assert report.positive_count == 8
    assert report.negative_count == 8
    assert report.gold_count == 16
    assert report.gold_matched_count == 16
    assert report.execution_count == 16
    assert report.execution_passed == 16
    assert report.execution_failed == 0
    assert report.execution_errors == 0
    assert report.duration == 42.125


def test_terminal_report_contains_all_sections(
    rules, cases, gold_validation, successful_results
):
    report = successful_report(
        rules, cases, gold_validation, successful_results
    )
    terminal = render_terminal_report(report)

    assert "WAF Testcase Generator" in terminal
    assert "Generation" in terminal
    assert "Rules parsed        8/8" in terminal
    assert "Cases generated     16" in terminal
    assert "Gold Validation" in terminal
    assert "Exact match         16/16" in terminal
    assert "Runtime Execution" in terminal
    assert "Executed            16" in terminal
    assert "[PASS] rule-1001-positive" in terminal
    assert "Overall: SUCCESS" in terminal
