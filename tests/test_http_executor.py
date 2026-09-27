import time

import httpx
import pytest

from testcase_gen.executor import HttpExecutor
from testcase_gen.models import CaseSpec, CaseType


def make_case(**overrides):
    values = {
        "case_id": "rule-1001-positive",
        "rule_id": 1001,
        "type": CaseType.POSITIVE,
        "method": "GET",
        "path": "/?id=1 OR 1=1",
        "headers": {},
        "body": None,
        "expected_code": 403,
        "generation_strategy": "test",
    }
    values.update(overrides)
    return CaseSpec(**values)


def test_get_request_is_constructed_with_legal_space_encoding():
    captured = {}

    def handler(request):
        captured["method"] = request.method
        captured["raw_path"] = request.url.raw_path
        return httpx.Response(403, text="blocked")

    with HttpExecutor(
        "http://waf.test:8080", transport=httpx.MockTransport(handler)
    ) as executor:
        result = executor.execute(make_case())

    assert captured == {
        "method": "GET",
        "raw_path": b"/?id=1%20OR%201=1",
    }
    assert result.actual_code == 403
    assert result.passed is True
    assert result.response_body_excerpt == "blocked"
    assert result.error is None


def test_special_path_characters_are_encoded_without_losing_semantics():
    captured = {}

    def handler(request):
        captured["raw_path"] = request.url.raw_path
        captured["q"] = request.url.params["q"]
        return httpx.Response(403)

    case = make_case(path="/?q=<ScRiPt>alert(1)</ScRiPt>")
    with HttpExecutor(
        "http://waf.test:8080", transport=httpx.MockTransport(handler)
    ) as executor:
        executor.execute(case)

    assert captured["raw_path"] == (
        b"/?q=%3CScRiPt%3Ealert(1)%3C/ScRiPt%3E"
    )
    assert captured["q"] == "<ScRiPt>alert(1)</ScRiPt>"


def test_post_body_and_content_type_are_sent_unchanged():
    captured = {}

    def handler(request):
        captured["method"] = request.method
        captured["body"] = request.content
        captured["content_type"] = request.headers["Content-Type"]
        return httpx.Response(403)

    case = make_case(
        rule_id=1008,
        method="POST",
        path="/search",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body="query=SELECT name FROM users",
    )
    with HttpExecutor(
        "http://waf.test:8080", transport=httpx.MockTransport(handler)
    ) as executor:
        result = executor.execute(case)

    assert captured == {
        "method": "POST",
        "body": b"query=SELECT name FROM users",
        "content_type": "application/x-www-form-urlencoded",
    }
    assert result.passed is True


def test_explicit_headers_override_httpx_defaults():
    captured = {}

    def handler(request):
        captured["user_agent"] = request.headers["User-Agent"]
        captured["referer"] = request.headers["Referer"]
        return httpx.Response(403)

    case = make_case(
        headers={
            "User-Agent": "sqlmap/1.7",
            "Referer": "https://evil.com/page",
        }
    )
    with HttpExecutor(
        "http://waf.test:8080", transport=httpx.MockTransport(handler)
    ) as executor:
        executor.execute(case)

    assert captured == {
        "user_agent": "sqlmap/1.7",
        "referer": "https://evil.com/page",
    }


def test_expected_code_controls_passed_flag():
    transport = httpx.MockTransport(lambda request: httpx.Response(403))
    with HttpExecutor("http://waf.test:8080", transport=transport) as executor:
        matching = executor.execute(make_case(expected_code=403))
        mismatching = executor.execute(make_case(expected_code=200))

    assert matching.passed is True
    assert mismatching.passed is False
    assert mismatching.actual_code == 403
    assert mismatching.error is None


def test_latency_is_recorded():
    def handler(request):
        time.sleep(0.002)
        return httpx.Response(200)

    with HttpExecutor(
        "http://waf.test:8080", transport=httpx.MockTransport(handler)
    ) as executor:
        result = executor.execute(make_case(expected_code=200))

    assert isinstance(result.latency_ms, float)
    assert result.latency_ms > 0


def test_http_error_status_is_a_normal_response():
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            500,
            headers={"X-Test": "response"},
            text="server error",
        )
    )
    with HttpExecutor("http://waf.test:8080", transport=transport) as executor:
        result = executor.execute(make_case(expected_code=200))

    assert result.actual_code == 500
    assert result.passed is False
    assert result.error is None
    assert result.response_headers["x-test"] == "response"
    assert result.response_body_excerpt == "server error"


def test_connection_error_is_recorded_as_execution_error():
    def handler(request):
        raise httpx.ConnectError("connection refused", request=request)

    with HttpExecutor(
        "http://waf.test:8080", transport=httpx.MockTransport(handler)
    ) as executor:
        result = executor.execute(make_case())

    assert result.actual_code is None
    assert result.passed is False
    assert result.error == "ConnectError: connection refused"
    assert result.response_headers == {}
    assert result.response_body_excerpt == ""
    assert result.latency_ms >= 0


def test_timeout_is_recorded_as_execution_error():
    def handler(request):
        raise httpx.ReadTimeout("read timed out", request=request)

    with HttpExecutor(
        "http://waf.test:8080", transport=httpx.MockTransport(handler)
    ) as executor:
        result = executor.execute(make_case())

    assert result.actual_code is None
    assert result.passed is False
    assert result.error == "ReadTimeout: read timed out"
    assert result.latency_ms >= 0


def test_existing_percent_encoding_is_not_double_encoded():
    captured = {}

    def handler(request):
        captured["raw_path"] = request.url.raw_path
        return httpx.Response(403)

    case = make_case(
        rule_id=1003,
        path="/?file=%2e%2e%2f%2e%2e%2fetc/passwd",
    )
    with HttpExecutor(
        "http://waf.test:8080", transport=httpx.MockTransport(handler)
    ) as executor:
        result = executor.execute(case)

    assert captured["raw_path"] == (
        b"/?file=%2e%2e%2f%2e%2e%2fetc/passwd"
    )
    assert b"%25" not in captured["raw_path"]
    assert result.passed is True
