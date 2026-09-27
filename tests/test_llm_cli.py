"""CLI level tests for the LLM generation modes."""

import io
import json
from pathlib import Path

import pytest

from testcase_gen.cli import main
from testcase_gen.executor import ExecutionResult
from testcase_gen.generator import (
    DEFAULT_API_KEY_ENV,
    MockLLMProvider,
    load_usage_log,
)


ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "rules.conf"
GOLD_PATH = ROOT / "gold.json"


class FakeExecutor:
    def __init__(self):
        self.cases = []
        self.closed = False

    def execute(self, case):
        self.cases.append(case)
        return ExecutionResult(
            case_id=case.case_id,
            rule_id=case.rule_id,
            type=case.type,
            expected_code=case.expected_code,
            actual_code=case.expected_code,
            passed=True,
            latency_ms=1.0,
            response_headers={},
            response_body_excerpt="mock",
            error=None,
        )

    def close(self):
        self.closed = True


class FakeExecutorFactory:
    def __init__(self):
        self.instances = []

    def __call__(self, **kwargs):
        executor = FakeExecutor()
        self.instances.append(executor)
        return executor


def _scripted_responses(*candidates_per_rule):
    """Build a mock script: given candidates for 1001/1004, nothing elsewhere."""
    scripted = {
        1001: [
            {
                "category": "payload_mutation",
                "expected_semantics": "match",
                "method": "GET",
                "path": "/?id=DROP TABLE users",
                "headers": {},
                "body": None,
                "rationale": "drop table keyword",
            },
            {
                "category": "benign_lookalike",
                "expected_semantics": "no_match",
                "method": "GET",
                "path": "/?id=42",
                "headers": {},
                "body": None,
                "rationale": "numeric identifier",
            },
        ],
        1004: [
            {
                "category": "payload_mutation",
                "expected_semantics": "match",
                "method": "GET",
                "path": "/",
                "headers": {"User-Agent": "gobuster/3.6"},
                "body": None,
                "rationale": "scanner user agent",
            }
        ],
    }
    scripted.update(dict(candidates_per_rule))
    return scripted


def _provider_factory(scripted=None):
    responses = _scripted_responses()

    def handler(rule_id, messages):
        if rule_id in responses:
            return json.dumps(
                {"rule_id": rule_id, "candidates": responses[rule_id]}
            )
        return json.dumps({"rule_id": rule_id, "candidates": []})

    def factory(config):
        return MockLLMProvider(responses=handler, latency_ms=2.0)

    return factory


def invoke_cli(tmp_path, extra_args=None, llm_factory=None):
    artifacts = tmp_path / "artifacts"
    args = [
        str(RULES_PATH),
        "--gold",
        str(GOLD_PATH),
        "--output-dir",
        str(artifacts),
    ]
    args.extend(extra_args or [])
    stdout = io.StringIO()
    stderr = io.StringIO()
    exit_code = main(
        args,
        executor_factory=FakeExecutorFactory(),
        llm_provider_factory=llm_factory,
        stdout=stdout,
        stderr=stderr,
    )
    return exit_code, stdout.getvalue(), stderr.getvalue(), artifacts


def load_artifact(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_baseline_mode_is_fully_offline(tmp_path):
    exit_code, stdout, stderr, artifacts = invoke_cli(
        tmp_path, extra_args=["--generation-mode", "baseline"]
    )
    report = load_artifact(artifacts / "report.json")
    generated = load_artifact(artifacts / "generated_cases.json")

    assert exit_code == 0
    assert stderr == ""
    assert len(generated) == 16
    assert report["generation"]["mode"] == "baseline"
    assert report["generation"]["baseline_cases"] == 16
    assert report["llm"]["enabled"] is False
    assert report["llm"]["degraded"] is False
    assert report["summary"]["generation_mode"] == "baseline"
    assert "Mode                baseline" in stdout
    assert "LLM:   not configured" in stdout


def test_hybrid_without_api_key_degrades_to_baseline(tmp_path):
    exit_code, stdout, _, artifacts = invoke_cli(tmp_path)
    report = load_artifact(artifacts / "report.json")
    generated = load_artifact(artifacts / "generated_cases.json")

    assert exit_code == 0
    assert len(generated) == 16
    assert report["summary"]["generation_mode"] == "hybrid"
    assert report["llm"]["enabled"] is False
    assert report["llm"]["degraded"] is True
    assert DEFAULT_API_KEY_ENV in report["llm"]["degrade_reason"]
    assert report["llm"]["status"] == "disabled"
    assert "DEGRADED to baseline" in stdout
    assert report["summary"]["gold_status"] == "PASS"

    entries = load_usage_log(artifacts / "ai_usage_log.jsonl")
    assert entries and entries[0]["status"] == "skipped"


def test_explicit_provider_without_key_env_degrades(tmp_path):
    exit_code, _, _, artifacts = invoke_cli(
        tmp_path,
        extra_args=[
            "--llm-provider",
            "openai",
            "--llm-api-key-env",
            "WAF_TESTCASE_MISSING_KEY",
        ],
    )
    report = load_artifact(artifacts / "report.json")

    assert exit_code == 0
    assert report["llm"]["degraded"] is True
    assert "WAF_TESTCASE_MISSING_KEY" in report["llm"]["degrade_reason"]


def test_hybrid_with_injected_provider_expands_cases(tmp_path):
    exit_code, stdout, stderr, artifacts = invoke_cli(
        tmp_path, llm_factory=_provider_factory()
    )
    report = load_artifact(artifacts / "report.json")
    generated = load_artifact(artifacts / "generated_cases.json")

    assert exit_code == 0, stdout + stderr
    assert len(generated) == 19
    assert report["generation"]["mode"] == "hybrid"
    assert report["generation"]["baseline_cases"] == 16
    assert report["generation"]["llm_cases"] == 3
    assert report["llm"]["enabled"] is True
    assert report["llm"]["candidate_count"] == 3
    assert report["llm"]["accepted_count"] == 3
    assert report["llm"]["rejected_count"] == 0
    assert report["llm"]["simulated"] is True
    assert report["llm"]["degraded"] is False
    assert report["summary"]["llm_accepted_count"] == 3
    assert report["summary"]["baseline_case_count"] == 16
    assert report["generation"]["status"] == "PASS"

    llm_cases = [
        case for case in generated if case["metadata"].get("source") == "llm"
    ]
    assert len(llm_cases) == 3
    assert llm_cases[0]["case_id"].startswith("rule-1001-llm-")
    assert llm_cases[0]["expected_code"] == 403

    # gold is still validated against the deterministic baseline set
    assert report["gold_validation"]["passed"] is True
    assert report["gold_validation"]["benchmark_source"] == "baseline"
    assert report["gold_validation"]["gold_cases"] == 16
    assert report["gold_validation"]["exact_matches"] == 16

    assert "AI usage log:" in stdout
    entries = load_usage_log(artifacts / "ai_usage_log.jsonl")
    assert len(entries) == 8
    accepted = [entry for entry in entries if entry["accepted_count"] > 0]
    assert len(accepted) == 2
    assert accepted[0]["rule_id"] == 1001
    assert accepted[0]["candidate_count"] == 2
    assert accepted[0]["prompt_version"]
    assert accepted[0]["model"] == "mock-model"
    assert accepted[0]["latency_ms"] > 0


def test_llm_mode_replaces_baseline_case_per_rule(tmp_path):
    exit_code, _, stderr, artifacts = invoke_cli(
        tmp_path,
        extra_args=["--generation-mode", "llm"],
        llm_factory=_provider_factory(),
    )
    report = load_artifact(artifacts / "report.json")
    generated = load_artifact(artifacts / "generated_cases.json")

    assert exit_code == 0, stderr
    # the LLM cases replace the baseline case of the same (rule_id, type),
    # so coverage stays at one positive and one negative per rule
    assert len(generated) == 16
    assert report["generation"]["mode"] == "llm"
    assert report["llm"]["accepted_count"] == 3
    positive_1001 = [
        case
        for case in generated
        if case["rule_id"] == 1001 and case["type"] == "positive"
    ]
    assert len(positive_1001) == 1
    assert positive_1001[0]["metadata"]["source"] == "llm"
    untouched = [
        case
        for case in generated
        if case["rule_id"] == 1002 and case["type"] == "positive"
    ]
    assert untouched[0]["metadata"].get("source") != "llm"


def test_llm_provider_error_is_reported_but_pipeline_survives(tmp_path):
    def factory(config):
        return MockLLMProvider(error="upstream returned 500")

    exit_code, stdout, _, artifacts = invoke_cli(
        tmp_path, llm_factory=factory
    )
    report = load_artifact(artifacts / "report.json")
    generated = load_artifact(artifacts / "generated_cases.json")

    assert exit_code == 0
    assert len(generated) == 16
    assert report["llm"]["error_count"] == 8
    assert report["generation"]["status"] == "PASS"
    assert "error: rule 1001" in stdout

    entries = load_usage_log(artifacts / "ai_usage_log.jsonl")
    assert entries[0]["status"] == "error"


def test_llm_save_raw_writes_prompt_and_response(tmp_path):
    exit_code, _, stderr, artifacts = invoke_cli(
        tmp_path,
        extra_args=["--llm-save-raw"],
        llm_factory=_provider_factory(),
    )

    assert exit_code == 0, stderr
    raw_files = sorted((artifacts / "llm_raw").glob("*.txt"))
    assert raw_files
    assert any("prompt" in path.name for path in raw_files)
    assert any("response" in path.name for path in raw_files)

    entries = load_usage_log(artifacts / "ai_usage_log.jsonl")
    assert entries[0]["raw_prompt_path"]


def test_llm_no_execute_runs_only_baseline_cases(tmp_path):
    exit_code, _, stderr, artifacts = invoke_cli(
        tmp_path,
        extra_args=["--llm-no-execute"],
        llm_factory=_provider_factory(),
    )
    report = load_artifact(artifacts / "report.json")
    generated = load_artifact(artifacts / "generated_cases.json")

    assert exit_code == 0, stderr
    assert len(generated) == 19
    assert report["execution"]["executed"] == 16
    assert report["llm"]["accepted_count"] == 3
    assert report["summary"]["runtime_status"] == "PASS"
    assert report["summary"]["generation_mode"] == "hybrid"


def test_invalid_llm_max_candidates_is_cli_error():
    with pytest.raises(SystemExit) as captured:
        main([str(RULES_PATH), "--llm-max-candidates", "0"])

    assert captured.value.code == 2
