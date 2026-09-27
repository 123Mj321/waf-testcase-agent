import argparse
import json
import sys
from pathlib import Path
from time import perf_counter
from typing import Callable, List, Optional, Sequence, TextIO

from testcase_gen.executor import ExecutionResult, HttpExecutor
from testcase_gen.generator import (
    AIUsageLog,
    DEFAULT_LLM_TIMEOUT,
    LLMConfig,
    LLMError,
    LLMExpansionResult,
    UnsupportedRuleError,
    assemble_cases,
    expand_with_llm,
    generate_cases,
    provider_choices,
)
from testcase_gen.models import CaseSpec
from testcase_gen.parser import SecRuleParseError, parse_rules_file
from testcase_gen.report import (
    OverallStatus,
    ReportIssue,
    build_report,
    print_terminal_report,
    write_json_report,
)
from testcase_gen.runner import resolve_base_url
from testcase_gen.validator import GoldFormatError, validate_gold_file


DEFAULT_TIMEOUT = 10.0
DEFAULT_GOLD_PATH = Path("gold.json")
DEFAULT_OUTPUT_DIR = Path("artifacts")
AI_USAGE_LOG_NAME = "ai_usage_log.jsonl"


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="testcase-gen",
        description="Generate and execute WAF test cases from ModSecurity SecRule files.",
    )
    parser.add_argument("rules_file", type=Path, metavar="RULES_FILE")
    parser.add_argument(
        "--gold",
        type=Path,
        default=DEFAULT_GOLD_PATH,
        help="gold JSON path (default: gold.json)",
    )
    parser.add_argument(
        "--base-url",
        help=(
            "WAF base URL (default: WAF_BASE_URL or "
            "http://127.0.0.1:8080)"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=_positive_timeout,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help="HTTP timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="artifact directory (default: artifacts)",
    )
    parser.add_argument(
        "--no-execute",
        action="store_true",
        help="parse, generate and validate without sending HTTP requests",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="show traceback for unexpected internal errors",
    )
    parser.add_argument(
        "--generation-mode",
        choices=["baseline", "llm", "hybrid"],
        default="hybrid",
        help=(
            "baseline: deterministic only (offline); llm: LLM candidates "
            "replace the baseline per rule; hybrid: baseline + LLM expansion "
            "(default: hybrid)"
        ),
    )
    parser.add_argument(
        "--llm-provider",
        choices=list(provider_choices()),
        default="auto",
        help="LLM provider (default: auto, uses the API key env var if set)",
    )
    parser.add_argument(
        "--llm-model",
        help="LLM model name (default: provider specific)",
    )
    parser.add_argument(
        "--llm-base-url",
        help="OpenAI compatible base URL (default: provider specific)",
    )
    parser.add_argument(
        "--llm-api-key-env",
        default="OPENAI_API_KEY",
        help="environment variable holding the API key (default: OPENAI_API_KEY)",
    )
    parser.add_argument(
        "--llm-max-candidates",
        type=_positive_int,
        default=8,
        metavar="N",
        help="maximum candidates requested per rule (default: 8)",
    )
    parser.add_argument(
        "--llm-timeout",
        type=_positive_timeout,
        default=DEFAULT_LLM_TIMEOUT,
        metavar="SECONDS",
        help="LLM HTTP timeout in seconds (default: 120)",
    )
    parser.add_argument(
        "--llm-max-tokens",
        type=_positive_int,
        metavar="N",
        help=(
            "hard cap on generated tokens; omit it for reasoning models, "
            "otherwise the whole budget may be spent on reasoning"
        ),
    )
    parser.add_argument(
        "--llm-temperature",
        type=float,
        default=0.2,
        metavar="T",
        help="LLM sampling temperature (default: 0.2)",
    )
    parser.add_argument(
        "--llm-no-execute",
        action="store_true",
        help=(
            "execute only the deterministic baseline cases; LLM expanded cases "
            "are still generated and reported but not sent to the WAF"
        ),
    )
    parser.add_argument(
        "--llm-save-raw",
        action="store_true",
        help=(
            "also store the raw prompt/response in artifacts/llm_raw "
            "(secrets are redacted; default: off)"
        ),
    )
    return parser


def main(
    argv: Optional[Sequence[str]] = None,
    executor_factory: Optional[Callable[..., object]] = None,
    llm_provider_factory: Optional[Callable[..., object]] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    output = sys.stdout if stdout is None else stdout
    error_output = sys.stderr if stderr is None else stderr

    try:
        return run_pipeline(
            args,
            executor_factory=executor_factory,
            llm_provider_factory=llm_provider_factory,
            stdout=output,
            stderr=error_output,
        )
    except Exception as exc:
        if args.debug:
            raise
        _print_error("unexpected internal error: {}".format(exc), error_output)
        return 2


def run_pipeline(
    args: argparse.Namespace,
    executor_factory: Optional[Callable[..., object]] = None,
    llm_provider_factory: Optional[Callable[..., object]] = None,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    started_at = perf_counter()
    rules_path = Path(args.rules_file)
    gold_path = Path(args.gold)
    output_dir = Path(args.output_dir)
    generated_path = output_dir / "generated_cases.json"
    report_path = output_dir / "report.json"
    usage_log_path = output_dir / AI_USAGE_LOG_NAME
    base_url = resolve_base_url(args.base_url)

    if not rules_path.is_file():
        _print_error("rules file not found: {}".format(rules_path), stderr)
        return 2
    if not gold_path.is_file():
        _print_error("gold file not found: {}".format(gold_path), stderr)
        return 2

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _print_error(
            "cannot create output directory {}: {}".format(output_dir, exc),
            stderr,
        )
        return 2

    try:
        rules = parse_rules_file(rules_path)
    except (SecRuleParseError, OSError, UnicodeError) as exc:
        _print_error("rules file could not be parsed: {}".format(exc), stderr)
        _write_parse_failure_report(
            output_dir=output_dir,
            error=str(exc),
            duration=(perf_counter() - started_at) * 1000,
            stdout=stdout,
            stderr=stderr,
        )
        return 2

    llm_config = LLMConfig.from_args(args)
    try:
        resolved_llm = llm_config.resolve()
    except LLMError:
        resolved_llm = None
    secrets = []
    if resolved_llm is not None and resolved_llm.api_key:
        secrets.append(resolved_llm.api_key)
    audit_log = AIUsageLog(
        path=usage_log_path,
        raw_dir=output_dir / "llm_raw",
        save_raw=llm_config.save_raw,
        redact=secrets,
    )

    baseline_cases: List[CaseSpec] = []
    unsupported_rules: List[ReportIssue] = []
    generation_errors: List[str] = []
    try:
        baseline_cases = generate_cases(rules)
    except UnsupportedRuleError as exc:
        unsupported_rules.append(
            ReportIssue(
                stage="generation",
                rule_id=exc.rule_id,
                message=exc.reason,
            )
        )
    except ValueError as exc:
        generation_errors.append(str(exc))

    if baseline_cases:
        try:
            expansion = expand_with_llm(
                rules,
                baseline_cases,
                config=llm_config,
                audit_log=audit_log,
                provider_factory=llm_provider_factory,
            )
        except Exception as exc:  # the LLM layer must never break the pipeline
            expansion = LLMExpansionResult(
                status="error",
                degraded=True,
                degrade_reason="llm expansion failed: {}: {}".format(
                    type(exc).__name__, exc
                ),
            )
    else:
        expansion = LLMExpansionResult(
            status="disabled",
            degraded=True,
            degrade_reason="baseline generation produced no cases",
        )

    try:
        cases = assemble_cases(args.generation_mode, baseline_cases, expansion.cases)
    except ValueError as exc:
        _print_error("invalid generation mode: {}".format(exc), stderr)
        return 2

    try:
        _write_generated_cases(cases, generated_path)
    except OSError as exc:
        _print_error(
            "cannot write generated cases {}: {}".format(generated_path, exc),
            stderr,
        )
        return 2

    try:
        gold_validation = validate_gold_file(baseline_cases, gold_path)
    except (GoldFormatError, json.JSONDecodeError, OSError, UnicodeError) as exc:
        _print_error("gold file could not be loaded: {}".format(exc), stderr)
        return 2

    executable_cases = cases
    expected_execution_count = None
    if getattr(args, "llm_no_execute", False):
        executable_cases = [
            case for case in cases if case.metadata.get("source") != "llm"
        ]
        if len(executable_cases) != len(cases):
            expected_execution_count = len(executable_cases)

    execution_results = None
    can_execute = (
        not unsupported_rules and not generation_errors and bool(executable_cases)
    )
    if not args.no_execute and can_execute:
        factory = HttpExecutor if executor_factory is None else executor_factory
        try:
            executor = factory(base_url=base_url, timeout=args.timeout)
        except (ValueError, OSError) as exc:
            _print_error("invalid executor configuration: {}".format(exc), stderr)
            return 2

        execution_results = []
        try:
            for case in executable_cases:
                execution_results.append(_execute_case(executor, case))
        finally:
            executor.close()
    elif not args.no_execute:
        execution_results = []

    report = build_report(
        rules=rules,
        cases=cases,
        gold_validation=gold_validation,
        execution_results=execution_results,
        unsupported_rules=unsupported_rules,
        generation_errors=generation_errors,
        duration=(perf_counter() - started_at) * 1000,
        expected_rule_count=len(rules),
        generation_mode=args.generation_mode,
        baseline_cases=baseline_cases,
        llm_stats=expansion.to_stats(),
        expected_execution_count=expected_execution_count,
    )

    try:
        write_json_report(report, report_path)
    except OSError as exc:
        _print_error(
            "cannot write JSON report {}: {}".format(report_path, exc),
            stderr,
        )
        return 2

    _print_context(
        rules_path,
        gold_path,
        base_url,
        args.no_execute,
        stdout,
        generation_mode=args.generation_mode,
        llm_summary=_llm_summary(expansion),
    )
    print_terminal_report(report, stream=stdout)
    _print_artifacts(generated_path, report_path, usage_log_path, stdout)

    exit_code = 0 if report.overall_status == OverallStatus.SUCCESS else 1
    print("Exit code: {}".format(exit_code), file=stdout)
    return exit_code


def _execute_case(executor: object, case: CaseSpec) -> ExecutionResult:
    try:
        return executor.execute(case)
    except Exception as exc:
        return ExecutionResult(
            case_id=case.case_id,
            rule_id=case.rule_id,
            type=case.type,
            expected_code=case.expected_code,
            actual_code=None,
            passed=False,
            latency_ms=0.0,
            response_headers={},
            response_body_excerpt="",
            error="{}: {}".format(type(exc).__name__, exc),
        )


def _write_generated_cases(cases: Sequence[CaseSpec], path: Path) -> None:
    path.write_text(
        json.dumps(
            [case.to_dict() for case in cases],
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _write_parse_failure_report(
    output_dir: Path,
    error: str,
    duration: float,
    stdout: TextIO,
    stderr: TextIO,
) -> None:
    report = build_report(
        rules=[],
        cases=[],
        parse_errors=[error],
        duration=duration,
        expected_rule_count=0,
    )
    try:
        write_json_report(report, output_dir / "report.json")
        print_terminal_report(report, stream=stdout)
    except OSError as exc:
        _print_error("cannot write parse failure report: {}".format(exc), stderr)


def _print_context(
    rules_path: Path,
    gold_path: Path,
    base_url: str,
    no_execute: bool,
    stream: TextIO,
    generation_mode: str = "baseline",
    llm_summary: str = "not configured",
) -> None:
    print("Input", file=stream)
    print("Rules: {}".format(rules_path), file=stream)
    print("Gold:  {}".format(gold_path), file=stream)
    print("Mode:  {}".format(generation_mode), file=stream)
    print("LLM:   {}".format(llm_summary), file=stream)
    print("WAF:   {}".format("NOT RUN" if no_execute else base_url), file=stream)
    print(file=stream)


def _print_artifacts(
    generated_path: Path,
    report_path: Path,
    usage_log_path: Path,
    stream: TextIO,
) -> None:
    print(file=stream)
    print("Artifacts", file=stream)
    print("Generated cases: {}".format(generated_path), file=stream)
    print("Report:           {}".format(report_path), file=stream)
    print("AI usage log:     {}".format(usage_log_path), file=stream)
    print(file=stream)


def _llm_summary(expansion: LLMExpansionResult) -> str:
    if expansion.provider is None:
        return "not configured -> deterministic baseline"
    provider = expansion.provider
    if expansion.simulated:
        provider = "{} (simulated)".format(provider)
    return "{}/{}".format(provider, expansion.model or "unknown")


def _print_error(message: str, stream: TextIO) -> None:
    print("ERROR: {}".format(message), file=stream)


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return number


def _positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than zero")
    return timeout


if __name__ == "__main__":
    raise SystemExit(main())
