import io
import json
from pathlib import Path

import pytest

import testcase_gen.cli as cli_module
from testcase_gen.cli import main
from testcase_gen.executor import ExecutionResult
from testcase_gen.generator import UnsupportedRuleError


ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "rules.conf"
GOLD_PATH = ROOT / "gold.json"
WRAPPER_PATH = ROOT / "testcase-gen"


class FakeExecutor:
    def __init__(self, mode):
        self.mode = mode
        self.cases = []
        self.closed = False

    def execute(self, case):
        self.cases.append(case)
        if self.mode == "mismatch" and len(self.cases) == 1:
            actual_code = 200 if case.expected_code != 200 else 500
            error = None
        elif self.mode == "error" and len(self.cases) == 1:
            actual_code = None
            error = "ConnectTimeout: timed out"
        else:
            actual_code = case.expected_code
            error = None

        return ExecutionResult(
            case_id=case.case_id,
            rule_id=case.rule_id,
            type=case.type,
            expected_code=case.expected_code,
            actual_code=actual_code,
            passed=actual_code == case.expected_code and error is None,
            latency_ms=1.25,
            response_headers={} if actual_code is None else {"x-test": "mock"},
            response_body_excerpt="" if actual_code is None else "mock response",
            error=error,
        )

    def close(self):
        self.closed = True


class FakeExecutorFactory:
    def __init__(self, mode="success", fail_on_create=False):
        self.mode = mode
        self.fail_on_create = fail_on_create
        self.kwargs = []
        self.instances = []

    def __call__(self, **kwargs):
        if self.fail_on_create:
            raise AssertionError("executor must not be created")
        self.kwargs.append(kwargs)
        executor = FakeExecutor(self.mode)
        self.instances.append(executor)
        return executor


def invoke_cli(
    tmp_path,
    factory=None,
    extra_args=None,
    rules_path=RULES_PATH,
    gold_path=GOLD_PATH,
    output_dir=None,
):
    artifacts = output_dir or (tmp_path / "artifacts")
    args = [
        str(rules_path),
        "--gold",
        str(gold_path),
        "--output-dir",
        str(artifacts),
    ]
    args.extend(extra_args or [])
    stdout = io.StringIO()
    stderr = io.StringIO()
    exit_code = main(
        args,
        executor_factory=factory,
        stdout=stdout,
        stderr=stderr,
    )
    return exit_code, stdout.getvalue(), stderr.getvalue(), artifacts


def load_artifact(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_normal_pipeline_with_mock_executor_returns_zero(tmp_path):
    factory = FakeExecutorFactory()
    exit_code, stdout, stderr, artifacts = invoke_cli(tmp_path, factory)

    assert exit_code == 0
    assert stderr == ""
    assert "Overall: SUCCESS" in stdout
    assert "Exit code: 0" in stdout
    assert len(factory.instances) == 1
    assert len(factory.instances[0].cases) == 16
    assert factory.instances[0].closed is True
    assert (artifacts / "generated_cases.json").is_file()
    assert (artifacts / "report.json").is_file()


def test_no_execute_skips_executor_and_returns_incomplete(tmp_path):
    factory = FakeExecutorFactory(fail_on_create=True)
    exit_code, stdout, stderr, artifacts = invoke_cli(
        tmp_path,
        factory,
        extra_args=["--no-execute"],
    )
    report = load_artifact(artifacts / "report.json")

    assert exit_code == 1
    assert stderr == ""
    assert "Status              NOT RUN" in stdout
    assert "Overall: INCOMPLETE" in stdout
    assert "Exit code: 1" in stdout
    assert report["summary"]["runtime_status"] == "NOT_RUN"
    assert report["summary"]["overall_status"] == "INCOMPLETE"


def test_missing_rules_file_returns_two_without_traceback(tmp_path):
    exit_code, stdout, stderr, _ = invoke_cli(
        tmp_path,
        FakeExecutorFactory(),
        rules_path=tmp_path / "missing-rules.conf",
    )

    assert exit_code == 2
    assert stdout == ""
    assert "ERROR: rules file not found:" in stderr
    assert "Traceback" not in stderr


def test_missing_gold_file_returns_two_without_traceback(tmp_path):
    exit_code, stdout, stderr, _ = invoke_cli(
        tmp_path,
        FakeExecutorFactory(),
        gold_path=tmp_path / "missing-gold.json",
    )

    assert exit_code == 2
    assert stdout == ""
    assert "ERROR: gold file not found:" in stderr
    assert "Traceback" not in stderr


def test_gold_mismatch_returns_one_while_runtime_can_pass(tmp_path):
    gold = json.loads(GOLD_PATH.read_text(encoding="utf-8"))
    gold[0]["path"] = "/?id=different"
    gold_path = tmp_path / "changed-gold.json"
    gold_path.write_text(json.dumps(gold), encoding="utf-8")

    exit_code, stdout, _, artifacts = invoke_cli(
        tmp_path,
        FakeExecutorFactory(),
        gold_path=gold_path,
    )
    report = load_artifact(artifacts / "report.json")

    assert exit_code == 1
    assert "[DIFF] rule-1001-positive" in stdout
    assert report["summary"]["gold_status"] == "FAIL"
    assert report["summary"]["runtime_status"] == "PASS"
    assert report["summary"]["overall_status"] == "FAIL"


def test_runtime_http_mismatch_returns_one(tmp_path):
    exit_code, stdout, _, artifacts = invoke_cli(
        tmp_path,
        FakeExecutorFactory(mode="mismatch"),
    )
    report = load_artifact(artifacts / "report.json")

    assert exit_code == 1
    assert "[FAIL] rule-1001-positive" in stdout
    assert report["execution"]["failed"] == 1
    assert report["execution"]["errors"] == 0
    assert report["cases"][0]["actual_code"] == 200


def test_runtime_execution_error_returns_one_without_actual_code(tmp_path):
    exit_code, stdout, _, artifacts = invoke_cli(
        tmp_path,
        FakeExecutorFactory(mode="error"),
    )
    report = load_artifact(artifacts / "report.json")

    assert exit_code == 1
    assert "[ERROR] rule-1001-positive" in stdout
    assert "ConnectTimeout: timed out" in stdout
    assert report["execution"]["errors"] == 1
    assert report["cases"][0]["actual_code"] is None
    assert report["cases"][0]["error"] == "ConnectTimeout: timed out"


def test_unsupported_rule_is_reported_and_returns_one(tmp_path, monkeypatch):
    def fail_generation(rules):
        raise UnsupportedRuleError(1004, "unsupported test operator")

    monkeypatch.setattr(cli_module, "generate_cases", fail_generation)
    factory = FakeExecutorFactory(fail_on_create=True)
    exit_code, stdout, _, artifacts = invoke_cli(tmp_path, factory)
    generated = load_artifact(artifacts / "generated_cases.json")
    report = load_artifact(artifacts / "report.json")

    assert exit_code == 1
    assert generated == []
    assert "[UNSUPPORTED] rule=1004 unsupported test operator" in stdout
    assert report["summary"]["generation_status"] == "FAIL"
    assert report["errors"][0]["rule_id"] == 1004


def test_nested_output_directory_is_created(tmp_path):
    output_dir = tmp_path / "nested" / "artifacts"
    exit_code, _, _, artifacts = invoke_cli(
        tmp_path,
        FakeExecutorFactory(fail_on_create=True),
        extra_args=["--no-execute"],
        output_dir=output_dir,
    )

    assert exit_code == 1
    assert artifacts == output_dir
    assert output_dir.is_dir()
    assert (output_dir / "generated_cases.json").is_file()
    assert (output_dir / "report.json").is_file()


def test_waf_base_url_environment_variable_is_used(tmp_path, monkeypatch):
    monkeypatch.setenv("WAF_BASE_URL", "http://waf.environment:9000")
    factory = FakeExecutorFactory()
    exit_code, stdout, _, _ = invoke_cli(tmp_path, factory)

    assert exit_code == 0
    assert factory.kwargs[0]["base_url"] == "http://waf.environment:9000"
    assert "WAF:   http://waf.environment:9000" in stdout


def test_base_url_argument_overrides_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("WAF_BASE_URL", "http://waf.environment:9000")
    factory = FakeExecutorFactory()
    exit_code, stdout, _, _ = invoke_cli(
        tmp_path,
        factory,
        extra_args=["--base-url", "http://waf.explicit:8081"],
    )

    assert exit_code == 0
    assert factory.kwargs[0]["base_url"] == "http://waf.explicit:8081"
    assert "WAF:   http://waf.explicit:8081" in stdout


def test_timeout_is_forwarded_to_executor(tmp_path):
    factory = FakeExecutorFactory()
    exit_code, _, _, _ = invoke_cli(
        tmp_path,
        factory,
        extra_args=["--timeout", "2.5"],
    )

    assert exit_code == 0
    assert factory.kwargs[0]["timeout"] == 2.5


def test_generated_cases_json_contains_only_case_spec_fields(tmp_path):
    _, _, _, artifacts = invoke_cli(
        tmp_path,
        FakeExecutorFactory(fail_on_create=True),
        extra_args=["--no-execute"],
    )
    generated = load_artifact(artifacts / "generated_cases.json")

    assert len(generated) == 16
    assert set(generated[0]) == {
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
    assert "actual_code" not in generated[0]
    assert "operator" not in generated[0]


def test_report_json_contains_stable_top_level_sections(tmp_path):
    _, _, _, artifacts = invoke_cli(tmp_path, FakeExecutorFactory())
    report = load_artifact(artifacts / "report.json")

    assert set(report) == {
        "summary",
        "generation",
        "gold_validation",
        "execution",
        "cases",
        "gold_diffs",
        "errors",
    }
    assert report["summary"]["overall_status"] == "SUCCESS"
    assert len(report["cases"]) == 16


def test_parse_error_returns_two_and_writes_failure_report(tmp_path):
    invalid_rules = tmp_path / "invalid-rules.conf"
    invalid_rules.write_text(
        'SecRule ARGS:id "@rx attack" "phase:2,deny"\n',
        encoding="utf-8",
    )

    exit_code, stdout, stderr, artifacts = invoke_cli(
        tmp_path,
        FakeExecutorFactory(fail_on_create=True),
        rules_path=invalid_rules,
    )
    report = load_artifact(artifacts / "report.json")

    assert exit_code == 2
    assert "ERROR: rules file could not be parsed:" in stderr
    assert "Overall: FAIL" in stdout
    assert report["summary"]["generation_status"] == "FAIL"
    assert report["errors"][0]["stage"] == "parse"


def test_invalid_timeout_is_cli_argument_error():
    with pytest.raises(SystemExit) as captured:
        main([str(RULES_PATH), "--timeout", "0"])

    assert captured.value.code == 2


def test_root_wrapper_and_console_script_configuration_exist():
    wrapper = WRAPPER_PATH.read_bytes()
    wrapper_text = wrapper.decode("utf-8")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert b"\r\n" not in wrapper
    assert wrapper_text.startswith("#!/usr/bin/env sh\n")
    assert "set -eu" in wrapper_text
    assert 'SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)' in wrapper_text
    assert 'PYTHONPATH="$SCRIPT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"' in wrapper_text
    assert "python3" in wrapper_text
    assert 'exec "$PYTHON_BIN" -m testcase_gen.cli "$@"' in wrapper_text
    assert '[project.scripts]' in pyproject
    assert 'testcase-gen = "testcase_gen.cli:main"' in pyproject


def test_gitignore_ignores_runtime_artifacts_and_caches():
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    patterns = [
        line.strip()
        for line in gitignore.splitlines()
        if line.strip() and not line.startswith("#")
    ]

    for expected in (
        "artifacts/",
        "__pycache__/",
        "*.py[cod]",
        ".pytest_cache/",
        ".venv/",
        "venv/",
        "env/",
        ".idea/",
        ".vscode/",
        "*.egg-info/",
        ".DS_Store",
        "Thumbs.db",
    ):
        assert expected in patterns

    assert (ROOT / "artifacts" / "report.json").exists()
    assert "artifacts/" in patterns
