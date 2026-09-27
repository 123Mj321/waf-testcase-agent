from typing import Iterable, Optional

from testcase_gen.executor import ExecutionResult
from testcase_gen.models import CaseSpec, CaseType, RuleSpec
from testcase_gen.validator import GoldValidationResult

from .models import (
    CaseResult,
    CaseResultStatus,
    LLMGenerationStats,
    OverallStatus,
    PhaseStatus,
    ReportIssue,
    TestReport,
)


def build_report(
    rules: Iterable[RuleSpec],
    cases: Iterable[CaseSpec],
    gold_validation: Optional[GoldValidationResult] = None,
    execution_results: Optional[Iterable[ExecutionResult]] = None,
    unsupported_rules: Optional[Iterable[ReportIssue]] = None,
    parse_errors: Optional[Iterable[str]] = None,
    generation_errors: Optional[Iterable[str]] = None,
    duration: float = 0.0,
    expected_rule_count: Optional[int] = None,
    generation_mode: str = "baseline",
    baseline_cases: Optional[Iterable[CaseSpec]] = None,
    llm_stats: Optional[LLMGenerationStats] = None,
    expected_execution_count: Optional[int] = None,
) -> TestReport:
    if duration < 0:
        raise ValueError("duration must not be negative")

    rule_list = list(rules)
    case_list = list(cases)
    execution_list = (
        [] if execution_results is None else list(execution_results)
    )
    unsupported_list = list(unsupported_rules or [])
    parse_error_list = list(parse_errors or [])
    generation_error_list = list(generation_errors or [])

    case_results = [_case_result(result) for result in execution_list]
    execution_passed = sum(
        1 for result in execution_list if result.passed and result.actual_code is not None
    )
    execution_errors = sum(
        1 for result in execution_list if result.actual_code is None
    )
    execution_failed = sum(
        1
        for result in execution_list
        if result.actual_code is not None and not result.passed
    )

    generation_status = (
        PhaseStatus.FAIL
        if parse_error_list or generation_error_list or unsupported_list
        else PhaseStatus.PASS
    )

    if gold_validation is None:
        gold_count = 0
        gold_matched_count = 0
        gold_passed = False
        gold_diffs = []
        gold_status = PhaseStatus.NOT_RUN
    else:
        gold_count = gold_validation.gold_count
        gold_matched_count = _gold_matched_count(gold_validation)
        gold_passed = gold_validation.passed
        gold_diffs = list(gold_validation.diffs)
        gold_status = PhaseStatus.PASS if gold_passed else PhaseStatus.FAIL

    if not execution_list:
        runtime_status = PhaseStatus.NOT_RUN
    elif (
        execution_failed
        or execution_errors
        or len(execution_list)
        != (
            len(case_list)
            if expected_execution_count is None
            else expected_execution_count
        )
    ):
        runtime_status = PhaseStatus.FAIL
    else:
        runtime_status = PhaseStatus.PASS

    phase_statuses = (generation_status, gold_status, runtime_status)
    if PhaseStatus.FAIL in phase_statuses:
        overall_status = OverallStatus.FAIL
    elif PhaseStatus.NOT_RUN in phase_statuses:
        overall_status = OverallStatus.INCOMPLETE
    else:
        overall_status = OverallStatus.SUCCESS

    rule_coverage = sorted({rule.rule_id for rule in rule_list})
    rule_count = len(rule_list)

    return TestReport(
        generated_count=len(case_list),
        positive_count=sum(
            1 for case in case_list if case.type == CaseType.POSITIVE
        ),
        negative_count=sum(
            1 for case in case_list if case.type == CaseType.NEGATIVE
        ),
        gold_count=gold_count,
        gold_matched_count=gold_matched_count,
        gold_passed=gold_passed,
        execution_count=len(execution_list),
        execution_passed=execution_passed,
        execution_failed=execution_failed,
        execution_errors=execution_errors,
        rule_count=rule_count,
        expected_rule_count=(
            rule_count if expected_rule_count is None else expected_rule_count
        ),
        rule_coverage=rule_coverage,
        case_results=case_results,
        gold_diffs=gold_diffs,
        unsupported_rules=unsupported_list,
        parse_errors=parse_error_list,
        generation_errors=generation_error_list,
        duration=duration,
        generation_status=generation_status,
        gold_status=gold_status,
        runtime_status=runtime_status,
        overall_status=overall_status,
        generation_mode=str(generation_mode),
        baseline_case_count=(
            len(case_list)
            if baseline_cases is None
            else len(list(baseline_cases))
        ),
        llm=llm_stats,
    )


def _case_result(result: ExecutionResult) -> CaseResult:
    if result.actual_code is None:
        status = CaseResultStatus.ERROR
    elif result.passed:
        status = CaseResultStatus.PASS
    else:
        status = CaseResultStatus.FAIL

    return CaseResult(
        case_id=result.case_id,
        rule_id=result.rule_id,
        type=result.type,
        expected_code=result.expected_code,
        actual_code=result.actual_code,
        passed=result.passed,
        status=status,
        latency_ms=result.latency_ms,
        response_headers=dict(result.response_headers),
        response_body_excerpt=result.response_body_excerpt,
        error=result.error,
    )


def _gold_matched_count(validation: GoldValidationResult) -> int:
    mismatched_gold_cases = {
        (diff.rule_id, diff.type)
        for diff in validation.diffs
        if diff.rule_id is not None
        and diff.type is not None
        and diff.message != "generated case is unexpected"
    }
    return max(0, validation.gold_count - len(mismatched_gold_cases))
