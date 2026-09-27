from dataclasses import dataclass
from time import perf_counter
from typing import Dict, Optional, Union

import httpx

from testcase_gen.models import CaseSpec, CaseType


@dataclass(frozen=True)
class ExecutionResult:
    case_id: str
    rule_id: int
    type: CaseType
    expected_code: int
    actual_code: Optional[int]
    passed: bool
    latency_ms: float
    response_headers: Dict[str, str]
    response_body_excerpt: str
    error: Optional[str]


class HttpExecutor:
    def __init__(
        self,
        base_url: str,
        timeout: Union[float, httpx.Timeout] = 5.0,
        follow_redirects: bool = False,
        transport: Optional[httpx.BaseTransport] = None,
        response_body_limit: int = 1024,
        trust_env: bool = False,
    ) -> None:
        if response_body_limit < 0:
            raise ValueError("response_body_limit must not be negative")

        normalized_base_url = base_url.rstrip("/") + "/"
        self._base_url = httpx.URL(normalized_base_url)
        if self._base_url.scheme not in {"http", "https"}:
            raise ValueError("base_url must use http or https")

        self._response_body_limit = response_body_limit
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=follow_redirects,
            transport=transport,
            trust_env=trust_env,
        )

    def execute(self, case: CaseSpec) -> ExecutionResult:
        started_at = perf_counter()
        try:
            request_url = self._base_url.join(case.path)
            response = self._client.request(
                method=case.method,
                url=request_url,
                headers=case.headers,
                content=case.body,
            )
        except httpx.HTTPError as exc:
            return ExecutionResult(
                case_id=case.case_id,
                rule_id=case.rule_id,
                type=case.type,
                expected_code=case.expected_code,
                actual_code=None,
                passed=False,
                latency_ms=(perf_counter() - started_at) * 1000,
                response_headers={},
                response_body_excerpt="",
                error="{}: {}".format(type(exc).__name__, exc),
            )

        return ExecutionResult(
            case_id=case.case_id,
            rule_id=case.rule_id,
            type=case.type,
            expected_code=case.expected_code,
            actual_code=response.status_code,
            passed=response.status_code == case.expected_code,
            latency_ms=(perf_counter() - started_at) * 1000,
            response_headers=dict(response.headers.items()),
            response_body_excerpt=response.text[: self._response_body_limit],
            error=None,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "HttpExecutor":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
