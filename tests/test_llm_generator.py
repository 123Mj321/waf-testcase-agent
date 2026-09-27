"""Tests for the LLM candidate generation stage.

Covered: mock provider, valid output, malformed JSON, invalid candidate,
duplicate candidate, rule semantic mismatch, LLM timeout/error, fallback to the
deterministic generator, missing API key, hybrid generation and the AI usage log.
"""

import json
from pathlib import Path

import httpx
import pytest

from testcase_gen.generator import (
    AIUsageLog,
    DEFAULT_API_KEY_ENV,
    GenerationMode,
    LLMConfig,
    LLMProviderError,
    LLMTestCaseGenerator,
    LLMTimeoutError,
    MockLLMProvider,
    OpenAICompatibleProvider,
    assemble_cases,
    build_rule_prompt,
    expand_with_llm,
    generate_cases,
    load_usage_log,
)
from testcase_gen.generator.validation import (
    MalformedLLMOutputError,
    RuleAwareCandidateValidator,
    evaluate_rule,
    extract_target_value,
)
from testcase_gen.models import CaseType
from testcase_gen.parser import parse_rules_file


ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "rules.conf"
GOLD_PATH = ROOT / "gold.json"


@pytest.fixture(scope="module")
def rules():
    return parse_rules_file(RULES_PATH)


@pytest.fixture(scope="module")
def baseline_cases(rules):
    return generate_cases(rules)


@pytest.fixture
def rule_by_id(rules):
    return {rule.rule_id: rule for rule in rules}


def candidate(**overrides):
    payload = {
        "category": "positive",
        "expected_semantics": "match",
        "method": "GET",
        "path": "/?id=1 OR 1=1",
        "headers": {},
        "body": None,
        "rationale": "union based injection probe",
    }
    payload.update(overrides)
    return payload


def response_for(rule_id, *candidates):
    return json.dumps(
        {"rule_id": rule_id, "candidates": list(candidates)}
    )


def expand_with_mock(rules, baseline, responses, **kwargs):
    """Script the mock provider; unscripted rules answer with zero candidates."""

    def scripted(rule_id, messages):
        if rule_id in responses:
            return responses[rule_id]
        return json.dumps({"rule_id": rule_id, "candidates": []})

    provider = MockLLMProvider(responses=scripted, **kwargs)
    generator = LLMTestCaseGenerator(provider=provider)
    return generator.expand(rules, baseline)


# --------------------------------------------------------------------------
# prompt builder
# --------------------------------------------------------------------------


def test_prompt_built_from_structured_rule_spec(rule_by_id):
    prompt = build_rule_prompt(rule_by_id[1001], max_candidates=4)

    assert prompt.version
    assert prompt.rule_id == 1001
    assert '"rule_id": 1001' in prompt.user
    assert '"operator"' in prompt.user
    assert '"transformations"' in prompt.user
    assert '"targets"' in prompt.user
    assert '"selector": "id"' in prompt.user
    assert prompt.messages()[0]["role"] == "system"
    assert prompt.messages()[1]["role"] == "user"


def test_prompt_never_contains_gold_or_expected_code(rule_by_id, rules):
    gold_text = GOLD_PATH.read_text(encoding="utf-8")
    first_gold_case = json.loads(gold_text)[0]

    for rule in rules:
        prompt = build_rule_prompt(rule)
        text = prompt.to_text()
        assert "gold" not in text.lower()
        assert first_gold_case["path"] not in text

    # the only mention of an expected status is the prohibition itself
    assert "NEVER output an \"expected_code\" field" in (
        build_rule_prompt(rule_by_id[1001]).system
    )


# --------------------------------------------------------------------------
# mock LLM provider + valid output
# --------------------------------------------------------------------------


def test_valid_llm_output_is_accepted_and_validated(rules, baseline_cases):
    responses = {
        1001: response_for(
            1001,
            candidate(
                path="/?id=DROP TABLE users",
                rationale="drop table keyword",
            ),
            candidate(
                category="negative",
                expected_semantics="no_match",
                path="/?id=42",
                rationale="benign identifier",
            ),
        )
    }
    result = expand_with_mock(rules, baseline_cases, responses)

    assert result.status == "ok"
    assert result.candidate_count == 2
    assert result.accepted_count == 2
    assert result.rejected_count == 0
    assert result.provider == "mock"
    assert result.simulated is True

    accepted = {case.type: case for case in result.cases}
    assert accepted[CaseType.POSITIVE].expected_code == 403
    assert accepted[CaseType.NEGATIVE].expected_code == 200
    assert accepted[CaseType.POSITIVE].case_id == "rule-1001-llm-1-positive"
    assert accepted[CaseType.POSITIVE].metadata["source"] == "llm"
    assert accepted[CaseType.POSITIVE].generation_strategy == "llm-positive"


def test_llm_candidate_may_not_declare_expected_code(rules, baseline_cases):
    responses = {
        1001: response_for(1001, candidate(expected_code=403)),
    }
    result = expand_with_mock(rules, baseline_cases, responses)

    assert result.accepted_count == 0
    assert result.rejected_count == 1
    assert "expected_code" in result.rejection_reasons[0]


def test_encoding_variation_is_accepted_for_url_decode_rule(
    rules, baseline_cases
):
    responses = {
        1003: response_for(
            1003,
            candidate(
                category="encoding_variation",
                path="/?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fwindows/win.ini",
                rationale="deep traversal, percent encoded on the wire",
            ),
        )
    }
    result = expand_with_mock(rules, baseline_cases, responses)

    assert result.accepted_count == 1
    assert result.cases[0].rule_id == 1003
    assert result.cases[0].expected_code == 403
    assert result.cases[0].metadata["llm_category"] == "encoding_variation"


def test_benign_lookalike_negative_case_is_accepted(rules, baseline_cases):
    responses = {
        1002: response_for(
            1002,
            candidate(
                category="benign_lookalike",
                expected_semantics="no_match",
                path="/?q=scratch-script-notes",
                rationale="contains 'script' but not '<script'",
            ),
        )
    }
    result = expand_with_mock(rules, baseline_cases, responses)

    assert result.accepted_count == 1
    assert result.cases[0].type == CaseType.NEGATIVE
    assert result.cases[0].expected_code == 200


def test_rule_engine_off_candidates_are_validated(rules, baseline_cases):
    responses = {
        1006: response_for(
            1006,
            candidate(
                category="positive",
                path="/api/health",
                rationale="engine off path without any attack payload",
            ),
            candidate(
                category="negative",
                expected_semantics="no_match",
                path="/other?foo=bar&id=1 OR 1=1",
                rationale="engine stays on, probe payload is blocked",
            ),
            candidate(
                category="negative",
                expected_semantics="no_match",
                path="/other",
                rationale="no probe payload at all",
            ),
        )
    }
    result = expand_with_mock(rules, baseline_cases, responses)

    assert result.accepted_count == 2
    assert result.rejected_count == 1
    assert "downstream probe payload" in result.rejection_reasons[0]
    codes = {case.path: case.expected_code for case in result.cases}
    assert codes["/api/health"] == 200
    assert codes["/other?foo=bar&id=1 OR 1=1"] == 403


# --------------------------------------------------------------------------
# malformed / invalid / duplicate / semantic mismatch
# --------------------------------------------------------------------------


def test_malformed_json_is_rejected_and_recorded(rules, baseline_cases):
    responses = {1001: "```json\n{'rule_id': 1001, 'candidates': [}\n```"}
    result = expand_with_mock(rules, baseline_cases, responses)

    assert result.accepted_count == 0
    assert result.cases == []
    assert result.status == "error"
    assert result.errors and "1001" in result.errors[0]
    assert result.records[0].status == "malformed"
    assert result.records[0].error


def test_malformed_json_with_wrong_rule_id_is_rejected(rules, baseline_cases):
    responses = {1001: response_for(9999, candidate())}
    result = expand_with_mock(rules, baseline_cases, responses)

    assert result.accepted_count == 0
    assert "does not match requested rule" in result.errors[0]


@pytest.mark.parametrize(
    "overrides,expected_reason",
    [
        ({"method": "TRACE"}, "unsupported method"),
        ({"path": "?id=1 OR 1=1"}, "path must be a string starting with"),
        ({"path": "/?id=1\nOR"}, "path contains control characters"),
        ({"body": "id=1"}, "body is not allowed for method GET"),
        ({"headers": {"User-Agent": 42}}, "header value must be a string"),
        ({"headers": {"X": "a\nb"}}, "header X contains control characters"),
        ({"category": "magic"}, "unknown candidate category"),
        ({"expected_semantics": "maybe"}, "invalid or missing expected_semantics"),
        ({"rationale": "   "}, "candidate has no rationale"),
    ],
)
def test_invalid_candidates_are_rejected(
    rules, baseline_cases, overrides, expected_reason
):
    responses = {1001: response_for(1001, candidate(**overrides))}
    result = expand_with_mock(rules, baseline_cases, responses)

    assert result.accepted_count == 0
    assert result.rejected_count == 1
    assert expected_reason in result.rejection_reasons[0]


def test_duplicate_candidates_are_rejected(rules, baseline_cases):
    duplicated = candidate(
        path="/?id=DROP TABLE users", rationale="drop table keyword"
    )
    responses = {
        1001: response_for(1001, duplicated, dict(duplicated)),
    }
    result = expand_with_mock(rules, baseline_cases, responses)

    assert result.accepted_count == 1
    assert result.rejected_count == 1
    assert result.rejection_reasons == ["duplicate candidate"]


def test_duplicate_of_baseline_case_is_rejected(rules, baseline_cases):
    baseline_positive = next(
        case
        for case in baseline_cases
        if case.rule_id == 1001 and case.type == CaseType.POSITIVE
    )
    responses = {
        1001: response_for(
            1001,
            candidate(
                path=baseline_positive.path,
                rationale="same request as the deterministic baseline",
            ),
        )
    }
    result = expand_with_mock(rules, baseline_cases, responses)

    assert result.accepted_count == 0
    assert result.rejection_reasons == ["duplicate candidate"]


def test_rule_semantic_mismatch_is_rejected(rules, baseline_cases):
    responses = {
        1001: response_for(
            1001,
            candidate(path="/?id=normal_value"),
            candidate(
                category="negative",
                expected_semantics="no_match",
                path="/?id=1 OR 1=1",
                rationale="declared benign but matches the rule",
            ),
        )
    }
    result = expand_with_mock(rules, baseline_cases, responses)

    assert result.accepted_count == 0
    assert result.rejected_count == 2
    assert all(
        "rule semantic mismatch" in reason
        for reason in result.rejection_reasons
    )


def test_candidate_without_rule_target_is_rejected(rules, baseline_cases):
    responses = {
        1001: response_for(
            1001,
            candidate(path="/?other=1 OR 1=1", rationale="wrong parameter"),
        )
    }
    result = expand_with_mock(rules, baseline_cases, responses)

    assert result.accepted_count == 0
    assert "does not provide a value for target ARGS:id" in (
        result.rejection_reasons[0]
    )


def test_conflicting_rule_is_rejected(rules, baseline_cases):
    responses = {
        1001: response_for(
            1001,
            candidate(
                category="rule_combination",
                method="DELETE",
                path="/?id=1 OR 1=1",
                rationale="also triggers the method rule",
            ),
        )
    }
    result = expand_with_mock(rules, baseline_cases, responses)

    assert result.accepted_count == 0
    assert "also triggers rule 1005" in result.rejection_reasons[0]


def test_unsupported_transformation_cannot_be_validated(
    rules, baseline_cases, rule_by_id
):
    from dataclasses import replace

    unsupported = replace(rule_by_id[1001], transformations=["base64Decode"])
    validator = RuleAwareCandidateValidator([unsupported])
    decisions = validator.validate(
        response_for(1001, candidate()), unsupported
    )

    assert decisions[0].accepted is False
    assert "cannot be validated deterministically" in decisions[0].reasons[0]


def test_parser_helpers_are_usable_directly(rule_by_id):
    rule = rule_by_id[1001]
    request = {"method": "GET", "path": "/?id=1 OR 1=1", "headers": {}, "body": None}

    assert extract_target_value(request, rule) == "1 OR 1=1"
    assert evaluate_rule(rule, "1 OR 1=1") is True
    assert evaluate_rule(rule, "normal_value") is False


def test_malformed_output_is_rejected_by_the_parser(rule_by_id):
    validator = RuleAwareCandidateValidator([rule_by_id[1001]])
    decisions = validator.validate("not json at all", rule_by_id[1001])

    assert len(decisions) == 1
    assert decisions[0].accepted is False
    assert "not valid JSON" in decisions[0].reasons[0]


# --------------------------------------------------------------------------
# provider errors / timeout / no api key / fallback
# --------------------------------------------------------------------------


def test_llm_timeout_is_recorded_and_falls_back(rules, baseline_cases):
    provider = MockLLMProvider(error=LLMTimeoutError("openai call timed out"))
    result = LLMTestCaseGenerator(provider=provider).expand(rules, baseline_cases)

    assert result.cases == []
    assert result.status == "error"
    assert len(result.errors) == len(rules)
    assert all("LLMTimeoutError" in error for error in result.errors)
    assert all(record.status == "error" for record in result.records)

    cases = assemble_cases(GenerationMode.HYBRID, baseline_cases, result.cases)
    assert cases == list(baseline_cases)
    assert len(cases) == 16


def test_llm_provider_error_is_survivable_per_rule(rules, baseline_cases):
    def scripted(rule_id, messages):
        if rule_id == 1001:
            raise LLMProviderError("upstream returned 500")
        if rule_id == 1002:
            return response_for(
                1002,
                candidate(
                    category="payload_mutation",
                    path="/?q=<sCrIpT src=x>",
                    rationale="script tag in q",
                ),
            )
        return response_for(
            rule_id,
            candidate(
                path="/?file=../../etc/passwd",
                rationale="classic traversal",
            ),
        )

    provider = MockLLMProvider(responses=scripted)
    result = LLMTestCaseGenerator(provider=provider).expand(rules, baseline_cases)

    assert result.status == "partial"
    assert len(result.errors) == 1
    assert "1001" in result.errors[0]
    assert result.accepted_count >= 1


def test_no_api_key_disables_llm_and_is_reported(rules, baseline_cases, tmp_path):
    config = LLMConfig(provider="auto")
    assert config.is_available({}) is False
    assert config.is_available({DEFAULT_API_KEY_ENV: "sk-test"}) is True

    audit_log = AIUsageLog(path=tmp_path / "ai_usage_log.jsonl")
    result = expand_with_llm(
        rules, baseline_cases, config=config, audit_log=audit_log, environ={}
    )

    assert result.status == "disabled"
    assert result.provider is None
    assert result.degraded is True
    assert DEFAULT_API_KEY_ENV in result.degrade_reason

    cases = assemble_cases("hybrid", baseline_cases, result.cases)
    assert len(cases) == 16

    entries = load_usage_log(tmp_path / "ai_usage_log.jsonl")
    assert len(entries) == 1
    assert entries[0]["status"] == "skipped"


def test_unknown_provider_is_reported_as_configuration_error(
    rules, baseline_cases
):
    result = expand_with_llm(
        rules,
        baseline_cases,
        config=LLMConfig(provider="does-not-exist"),
        environ={},
    )

    assert result.status == "disabled"
    assert result.degraded is True
    assert "unknown llm provider" in result.degrade_reason


def test_baseline_mode_never_calls_the_provider(rules, baseline_cases, tmp_path):
    config = LLMConfig(disabled=True)
    assert config.resolve({}).provider_name is None

    audit_log = AIUsageLog(path=tmp_path / "ai_usage_log.jsonl")
    result = expand_with_llm(
        rules, baseline_cases, config=config, audit_log=audit_log, environ={}
    )

    assert result.status == "disabled"
    assert result.provider is None
    assert result.degraded is False  # explicit baseline choice, not a fallback

    baseline_only = assemble_cases(
        GenerationMode.BASELINE, baseline_cases, result.cases
    )
    assert baseline_only == list(baseline_cases)
    assert len(baseline_only) == 16


# --------------------------------------------------------------------------
# hybrid / llm assembly
# --------------------------------------------------------------------------


def test_hybrid_generation_keeps_baseline_and_adds_llm_cases(
    rules, baseline_cases
):
    responses = {
        1001: response_for(
            1001,
            candidate(
                category="payload_mutation",
                path="/?id=DROP TABLE users",
                rationale="drop table keyword",
            ),
        ),
        1004: response_for(
            1004,
            candidate(
                category="payload_mutation",
                path="/",
                headers={"User-Agent": "gobuster/3.6"},
                rationale="scanner user agent",
            ),
        ),
    }
    result = expand_with_mock(rules, baseline_cases, responses)
    cases = assemble_cases(GenerationMode.HYBRID, baseline_cases, result.cases)

    assert len(baseline_cases) == 16
    assert len(cases) == 18
    assert {case.case_id for case in baseline_cases} <= {
        case.case_id for case in cases
    }
    assert len({case.case_id for case in cases}) == len(cases)
    assert all(case.expected_code is not None for case in cases)


def test_llm_mode_keeps_at_least_one_case_per_rule_and_type(
    rules, baseline_cases
):
    responses = {
        1001: response_for(
            1001,
            candidate(
                category="payload_mutation",
                path="/?id=DROP TABLE users",
                rationale="drop table keyword",
            ),
        )
    }
    result = expand_with_mock(rules, baseline_cases, responses)
    cases = assemble_cases(GenerationMode.LLM, baseline_cases, result.cases)

    assert len(cases) == 16
    llm_positive = next(
        case
        for case in cases
        if case.rule_id == 1001 and case.type == CaseType.POSITIVE
    )
    assert llm_positive.metadata["source"] == "llm"
    baseline_negative = next(
        case
        for case in cases
        if case.rule_id == 1001 and case.type == CaseType.NEGATIVE
    )
    assert baseline_negative.metadata == {}


def test_extra_llm_cases_are_not_a_generation_failure(rules, baseline_cases):
    """Gold stays an independent oracle; LLM-only cases never fail generation."""
    from testcase_gen.validator import load_gold, validate_gold

    responses = {
        1001: response_for(
            1001,
            candidate(
                category="payload_mutation",
                path="/?id=DROP TABLE users",
                rationale="drop table keyword",
            ),
        )
    }
    result = expand_with_mock(rules, baseline_cases, responses)
    cases = assemble_cases(GenerationMode.HYBRID, baseline_cases, result.cases)

    assert len(cases) == 17
    # the pipeline benchmarks the deterministic baseline set against gold ...
    baseline_validation = validate_gold(baseline_cases, load_gold(GOLD_PATH))
    assert baseline_validation.passed is True

    # ... and if the full set is compared, the only diffs are the extra cases
    full_validation = validate_gold(cases, load_gold(GOLD_PATH))
    assert {diff.message for diff in full_validation.diffs} <= {
        "generated case is unexpected",
        "duplicate (rule_id, type) in generated cases",
        "generated case count differs from gold",
    }
    assert not any(
        diff.field in ("method", "path", "headers", "body", "expected_code")
        for diff in full_validation.diffs
    )


def test_hybrid_generation_does_not_read_gold(rules, baseline_cases, monkeypatch):
    def fail_on_read(*args, **kwargs):
        raise AssertionError("LLM generator attempted filesystem input")

    monkeypatch.setattr(Path, "read_text", fail_on_read)
    responses = {
        1001: response_for(
            1001,
            candidate(
                path="/?id=DROP TABLE users", rationale="drop table keyword"
            ),
        )
    }
    result = expand_with_mock(rules, baseline_cases, responses)

    assert result.accepted_count == 1


# --------------------------------------------------------------------------
# AI usage log
# --------------------------------------------------------------------------


def test_ai_usage_log_records_every_generation(tmp_path, rules, baseline_cases):
    log_path = tmp_path / "ai_usage_log.jsonl"
    audit_log = AIUsageLog(path=log_path)
    provider = MockLLMProvider(
        responses={
            1001: response_for(
                1001,
                candidate(
                    path="/?id=DROP TABLE users",
                    rationale="drop table keyword",
                ),
                candidate(
                    path="/?id=42",
                    expected_semantics="match",
                    rationale="wrong semantics",
                ),
            )
        },
        token_usage={
            "prompt_tokens": 120,
            "completion_tokens": 45,
            "total_tokens": 165,
        },
        latency_ms=12.5,
    )
    generator = LLMTestCaseGenerator(provider=provider, audit_log=audit_log)
    result = generator.expand(rules, baseline_cases)

    entries = load_usage_log(log_path)
    assert len(entries) == len(rules)

    entry = entries[0]
    for key in (
        "timestamp",
        "model",
        "prompt_version",
        "rule_id",
        "candidate_count",
        "accepted_count",
        "rejected_count",
        "rejection_reasons",
        "rejection_summary",
        "token_usage",
        "latency_ms",
        "status",
    ):
        assert key in entry

    assert entry["rule_id"] == 1001
    assert entry["candidate_count"] == 2
    assert entry["accepted_count"] == 1
    assert entry["rejected_count"] == 1
    assert entry["rejection_reasons"] == [result.rejection_reasons[0]]
    assert entry["token_usage"]["total_tokens"] == 165
    assert entry["latency_ms"] > 0
    assert entry["simulated"] is True
    assert entry["prompt_sha256"]
    assert entry["raw_prompt_path"] is None


def test_raw_prompt_and_response_are_saved_only_on_demand(
    tmp_path, rules, baseline_cases
):
    saved_log = AIUsageLog(
        path=tmp_path / "saved.jsonl",
        raw_dir=tmp_path / "llm_raw",
        save_raw=True,
        redact=["sk-secret-value"],
    )
    provider = MockLLMProvider(
        responses={
            1001: response_for(
                1001,
                candidate(
                    path="/?id=DROP TABLE users", rationale="drop table keyword"
                ),
            )
        },
        latency_ms=3.0,
    )
    LLMTestCaseGenerator(provider=provider, audit_log=saved_log).expand(
        rules, baseline_cases
    )

    entries = load_usage_log(tmp_path / "saved.jsonl")
    assert entries[0]["raw_prompt_path"]
    assert entries[0]["raw_response_path"]
    assert Path(entries[0]["raw_prompt_path"]).is_file()
    assert Path(entries[0]["raw_response_path"]).is_file()
    assert sorted((tmp_path / "llm_raw").glob("*.txt"))

    default_log = AIUsageLog(path=tmp_path / "default.jsonl")
    LLMTestCaseGenerator(
        provider=MockLLMProvider(
            responses={
                1001: response_for(
                    1001,
                    candidate(
                        path="/?id=DROP TABLE users",
                        rationale="drop table keyword",
                    ),
                )
            }
        ),
        audit_log=default_log,
    ).expand(rules, baseline_cases)

    default_entries = load_usage_log(tmp_path / "default.jsonl")
    assert default_entries[0]["raw_prompt_path"] is None
    assert default_entries[0]["raw_response_path"] is None
    assert default_entries[0]["prompt_sha256"]


def test_raw_capture_redacts_configured_secrets(tmp_path):
    log = AIUsageLog(
        path=None,
        raw_dir=tmp_path / "raw",
        save_raw=True,
        redact=["sk-secret-value"],
    )
    log.record(
        _record_stub(),
        raw_prompt="Authorization: Bearer sk-secret-value",
        raw_response="ok",
    )

    written = sorted((tmp_path / "raw").glob("*.txt"))
    assert len(written) == 2
    prompt_file = next(path for path in written if "prompt" in path.name)
    assert "sk-secret-value" not in prompt_file.read_text(encoding="utf-8")
    assert "***REDACTED***" in prompt_file.read_text(encoding="utf-8")


def _record_stub():
    from testcase_gen.generator.audit import LLMGenerationRecord

    return LLMGenerationRecord(
        timestamp="2026-01-01T00-00-00.000+00-00",
        status="ok",
        provider="mock",
        model="mock-model",
        prompt_version="test",
        rule_id=1001,
    )


# --------------------------------------------------------------------------
# OpenAI compatible provider (httpx MockTransport, no network)
# --------------------------------------------------------------------------


def _chat_completion_payload(content, usage=None):
    return json.dumps(
        {
            "model": "gpt-4o-mini",
            "choices": [{"message": {"role": "assistant", "content": content}}],
            "usage": usage
            or {
                "prompt_tokens": 10,
                "completion_tokens": 20,
                "total_tokens": 30,
            },
        }
    ).encode("utf-8")


def test_openai_compatible_provider_parses_response():
    def handler(request):
        assert request.url.path.endswith("/chat/completions")
        assert request.headers["authorization"] == "Bearer sk-test"
        return httpx.Response(
            200,
            content=_chat_completion_payload(response_for(1001, candidate())),
            headers={"content-type": "application/json"},
        )

    provider = OpenAICompatibleProvider(
        model="gpt-4o-mini",
        base_url="http://llm.test/v1",
        api_key="sk-test",
        transport=httpx.MockTransport(handler),
    )
    completion = provider.complete([{"role": "user", "content": "hi"}])

    assert json.loads(completion.text)["rule_id"] == 1001
    assert completion.model == "gpt-4o-mini"
    assert completion.token_usage["total_tokens"] == 30
    assert completion.latency_ms >= 0


def test_defaults_leave_output_budget_to_the_model():
    assert LLMConfig().max_tokens is None
    assert LLMConfig().timeout >= 120.0


def test_provider_omits_max_tokens_by_default():
    seen = {}

    def handler(request):
        seen.update(json.loads(request.content.decode("utf-8")))
        return httpx.Response(
            200,
            content=_chat_completion_payload(response_for(1001, candidate())),
            headers={"content-type": "application/json"},
        )

    provider = OpenAICompatibleProvider(
        model="gpt-4o-mini",
        base_url="http://llm.test/v1",
        api_key="sk-test",
        transport=httpx.MockTransport(handler),
    )
    provider.complete([{"role": "user", "content": "hi"}])

    assert "max_tokens" not in seen
    assert seen["response_format"] == {"type": "json_object"}


def test_provider_sends_max_tokens_when_configured():
    seen = {}

    def handler(request):
        seen.update(json.loads(request.content.decode("utf-8")))
        return httpx.Response(
            200,
            content=_chat_completion_payload(response_for(1001, candidate())),
            headers={"content-type": "application/json"},
        )

    provider = OpenAICompatibleProvider(
        model="gpt-4o-mini",
        base_url="http://llm.test/v1",
        api_key="sk-test",
        max_tokens=4096,
        transport=httpx.MockTransport(handler),
    )
    provider.complete([{"role": "user", "content": "hi"}])

    assert seen["max_tokens"] == 4096


def test_reasoning_truncation_is_reported_actionably():
    payload = {
        "model": "deepseek-reasoner",
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "reasoning_content": "thinking ...",
                    "content": "",
                },
                "finish_reason": "length",
            }
        ],
        "usage": {
            "completion_tokens": 2000,
            "completion_tokens_details": {"reasoning_tokens": 2000},
        },
    }

    def handler(request):
        return httpx.Response(
            200,
            content=json.dumps(payload).encode("utf-8"),
            headers={"content-type": "application/json"},
        )

    provider = OpenAICompatibleProvider(
        model="deepseek-reasoner",
        base_url="http://llm.test/v1",
        api_key="sk-test",
        max_tokens=2000,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(LLMProviderError) as captured:
        provider.complete([{"role": "user", "content": "hi"}])

    message = str(captured.value)
    assert "empty message content" in message
    assert "finish_reason='length'" in message
    assert "reasoning_tokens=2000" in message
    assert "--llm-max-tokens" in message


def test_provider_accepts_block_content():
    payload = {
        "model": "gpt-4o-mini",
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": [
                        {"type": "text", "text": '{"rule_id": 1001, '},
                        {"type": "text", "text": '"candidates": []}'},
                    ],
                },
                "finish_reason": "stop",
            }
        ],
    }

    def handler(request):
        return httpx.Response(
            200,
            content=json.dumps(payload).encode("utf-8"),
            headers={"content-type": "application/json"},
        )

    provider = OpenAICompatibleProvider(
        model="gpt-4o-mini",
        base_url="http://llm.test/v1",
        api_key="sk-test",
        transport=httpx.MockTransport(handler),
    )
    completion = provider.complete([{"role": "user", "content": "hi"}])

    assert json.loads(completion.text) == {"rule_id": 1001, "candidates": []}


def test_openai_compatible_provider_maps_timeout():
    def handler(request):
        raise httpx.ConnectTimeout("timed out", request=request)

    provider = OpenAICompatibleProvider(
        model="gpt-4o-mini",
        base_url="http://llm.test/v1",
        api_key="sk-test",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(LLMTimeoutError):
        provider.complete([{"role": "user", "content": "hi"}])


def test_openai_compatible_provider_maps_http_error():
    def handler(request):
        return httpx.Response(500, content=b"boom")

    provider = OpenAICompatibleProvider(
        model="gpt-4o-mini",
        base_url="http://llm.test/v1",
        api_key="sk-test",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(LLMProviderError):
        provider.complete([{"role": "user", "content": "hi"}])


def test_openai_compatible_provider_rejects_non_json_response():
    def handler(request):
        return httpx.Response(
            200,
            content=b"<html>not json</html>",
            headers={"content-type": "text/html"},
        )

    provider = OpenAICompatibleProvider(
        model="gpt-4o-mini",
        base_url="http://llm.test/v1",
        api_key="sk-test",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(LLMProviderError, match="non-JSON"):
        provider.complete([{"role": "user", "content": "hi"}])


def test_provider_resolution_defaults():
    resolved = LLMConfig(provider="openai").resolve(
        {"OPENAI_API_KEY": "sk-test"}
    )
    assert resolved.provider_name == "openai"
    assert resolved.model == "gpt-4o-mini"
    assert resolved.base_url == "https://api.openai.com/v1"

    local = LLMConfig(provider="ollama").resolve({})
    assert local.provider_name == "ollama"
    assert local.api_key is None
    assert local.base_url == "http://127.0.0.1:11434/v1"
