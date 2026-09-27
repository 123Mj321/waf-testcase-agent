import pytest

from testcase_gen.executor import ExecutionResult
from testcase_gen.models import CaseSpec, CaseType
from testcase_gen.runner import (
    DEFAULT_BASE_URL,
    PytestHarness,
    assert_execution_result,
    parametrize_cases,
    pytest_case_parameters,
    resolve_base_url,
)


def make_case(rule_id, case_type, expected_code):
    return CaseSpec(
        case_id="rule-{}-{}".format(rule_id, case_type.value),
        rule_id=rule_id,
        type=case_type,
        method="GET",
        path="/",
        headers={},
        body=None,
        expected_code=expected_code,
        generation_strategy="runner-test",
    )


def make_result(
    case,
    actual_code,
    error=None,
    body="response excerpt",
    latency_ms=1.25,
):
    return ExecutionResult(
        case_id=case.case_id,
        rule_id=case.rule_id,
        type=case.type,
        expected_code=case.expected_code,
        actual_code=actual_code,
        passed=actual_code == case.expected_code and error is None,
        latency_ms=latency_ms,
        response_headers={"content-type": "text/plain"} if actual_code else {},
        response_body_excerpt=body,
        error=error,
    )


class FakeExecutor:
    def __init__(self, result_factory):
        self.result_factory = result_factory
        self.seen = []
        self.closed = False

    def execute(self, case):
        self.seen.append(case)
        return self.result_factory(case)

    def close(self):
        self.closed = True


RUNNER_CASES = [
    make_case(1001, CaseType.POSITIVE, 403),
    make_case(1001, CaseType.NEGATIVE, 200),
]


@parametrize_cases(RUNNER_CASES)
def test_harness_executes_pytest_parameterized_cases(case):
    executor = FakeExecutor(
        lambda current: make_result(current, current.expected_code)
    )

    with PytestHarness(executor) as harness:
        result = harness.execute_and_assert(case)
        assert result.case_id == case.case_id
        assert harness.results == (result,)

    assert executor.seen == [case]
    assert executor.closed is True


def test_parameter_ids_use_case_ids():
    parameters = pytest_case_parameters(RUNNER_CASES)
    assert [parameter.id for parameter in parameters] == [
        "rule-1001-positive",
        "rule-1001-negative",
    ]


def test_base_url_resolution_supports_default_environment_and_explicit_value():
    assert resolve_base_url(environ={}) == DEFAULT_BASE_URL
    assert resolve_base_url(
        environ={"WAF_BASE_URL": "http://waf.example:9000"}
    ) == "http://waf.example:9000"
    assert resolve_base_url(
        "http://explicit.example:8081",
        {"WAF_BASE_URL": "http://ignored.example:9000"},
    ) == "http://explicit.example:8081"


def test_status_mismatch_keeps_execution_details_in_assertion():
    case = make_case(1001, CaseType.POSITIVE, 403)
    result = make_result(
        case,
        actual_code=200,
        body="backend response",
        latency_ms=7.5,
    )

    with pytest.raises(AssertionError) as captured:
        assert_execution_result(result)

    message = str(captured.value)
    assert "HTTP status mismatch" in message
    assert "expected=403" in message
    assert "actual=200" in message
    assert "latency_ms=7.500" in message
    assert "backend response" in message


def test_execution_error_is_not_reported_as_status_mismatch():
    case = make_case(1001, CaseType.POSITIVE, 403)
    result = make_result(
        case,
        actual_code=None,
        error="ConnectError: connection refused",
        body="",
    )

    with pytest.raises(pytest.fail.Exception) as captured:
        assert_execution_result(result)

    message = str(captured.value)
    assert "execution error" in message
    assert "actual=None" in message
    assert "ConnectError: connection refused" in message
    assert "HTTP status mismatch" not in message


def test_failing_result_is_retained_by_harness():
    case = make_case(1001, CaseType.POSITIVE, 403)
    executor = FakeExecutor(
        lambda current: make_result(current, actual_code=500)
    )
    harness = PytestHarness(executor)

    with pytest.raises(AssertionError):
        harness.execute_and_assert(case)

    assert len(harness.results) == 1
    assert harness.results[0].actual_code == 500
