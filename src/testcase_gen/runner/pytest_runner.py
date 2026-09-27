import os
from typing import List, Mapping, Optional, Protocol, Sequence, Tuple, Union

import httpx
import pytest

from testcase_gen.executor import ExecutionResult, HttpExecutor
from testcase_gen.models import CaseSpec


DEFAULT_BASE_URL = "http://127.0.0.1:8080"


class CaseExecutor(Protocol):
    def execute(self, case: CaseSpec) -> ExecutionResult:
        ...

    def close(self) -> None:
        ...


def resolve_base_url(
    base_url: Optional[str] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> str:
    if base_url:
        return base_url
    environment = os.environ if environ is None else environ
    return environment.get("WAF_BASE_URL") or DEFAULT_BASE_URL


def pytest_case_parameters(cases: Sequence[CaseSpec]) -> List[object]:
    return [pytest.param(case, id=case.case_id) for case in cases]


def parametrize_cases(cases: Sequence[CaseSpec]):
    return pytest.mark.parametrize("case", pytest_case_parameters(cases))


def assert_execution_result(result: ExecutionResult) -> ExecutionResult:
    details = (
        "case={case_id}, expected={expected}, actual={actual}, "
        "latency_ms={latency:.3f}, error={error!r}, response={body!r}"
    ).format(
        case_id=result.case_id,
        expected=result.expected_code,
        actual=result.actual_code,
        latency=result.latency_ms,
        error=result.error,
        body=result.response_body_excerpt,
    )

    if result.actual_code is None:
        pytest.fail("execution error: {}".format(details), pytrace=False)

    assert result.actual_code == result.expected_code, (
        "HTTP status mismatch: {}".format(details)
    )
    return result


class PytestHarness:
    __test__ = False

    def __init__(self, executor: CaseExecutor) -> None:
        self._executor = executor
        self._results: List[ExecutionResult] = []

    @classmethod
    def from_environment(
        cls,
        base_url: Optional[str] = None,
        timeout: Union[float, httpx.Timeout] = 5.0,
        follow_redirects: bool = False,
    ) -> "PytestHarness":
        return cls(
            HttpExecutor(
                base_url=resolve_base_url(base_url),
                timeout=timeout,
                follow_redirects=follow_redirects,
            )
        )

    @property
    def results(self) -> Tuple[ExecutionResult, ...]:
        return tuple(self._results)

    def execute_and_assert(self, case: CaseSpec) -> ExecutionResult:
        result = self._executor.execute(case)
        self._results.append(result)
        return assert_execution_result(result)

    def close(self) -> None:
        self._executor.close()

    def __enter__(self) -> "PytestHarness":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
