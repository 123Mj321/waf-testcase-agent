import json
import sys
from typing import TextIO

from .models import CaseResultStatus, PhaseStatus, TestReport


def render_terminal_report(report: TestReport) -> str:
    lines = ["WAF Testcase Generator", ""]

    lines.extend(
        [
            "Generation",
            _row("Status", report.generation_status.value),
            _row(
                "Rules parsed",
                "{}/{}".format(report.rule_count, report.expected_rule_count),
            ),
            _row("Cases generated", report.generated_count),
            _row("Positive", report.positive_count),
            _row("Negative", report.negative_count),
            _row("Unsupported", len(report.unsupported_rules)),
            "",
            "Gold Validation",
            _row("Status", _display_status(report.gold_status)),
            _row("Gold cases", report.gold_count),
            _row("Generated cases", report.generated_count),
            _row(
                "Exact match",
                "{}/{}".format(report.gold_matched_count, report.gold_count),
            ),
            _row("Differences", len(report.gold_diffs)),
            "",
            "Runtime Execution",
            _row("Status", _display_status(report.runtime_status)),
        ]
    )

    if report.runtime_status != PhaseStatus.NOT_RUN:
        lines.extend(
            [
                _row("Executed", report.execution_count),
                _row("Passed", report.execution_passed),
                _row("Failed", report.execution_failed),
                _row("Errors", report.execution_errors),
            ]
        )

    if report.case_results:
        lines.extend(["", "Case Results"])
        for case in report.case_results:
            lines.append(
                "[{status}] {case_id} rule={rule_id} type={case_type} "
                "expected={expected} actual={actual} latency={latency:.3f}ms".format(
                    status=case.status.value,
                    case_id=case.case_id,
                    rule_id=case.rule_id,
                    case_type=case.type.value,
                    expected=case.expected_code,
                    actual=case.actual_code,
                    latency=case.latency_ms,
                )
            )
            if case.status == CaseResultStatus.ERROR:
                lines.append("  error: {}".format(case.error))
            elif case.status == CaseResultStatus.FAIL:
                lines.append(
                    "  response: {}".format(case.response_body_excerpt)
                )

    if report.gold_diffs:
        lines.extend(["", "Gold Differences"])
        for diff in report.gold_diffs:
            lines.extend(
                [
                    "[DIFF] {}".format(diff.case_id),
                    "  field: {}".format(diff.field),
                    "  expected: {}".format(_render_value(diff.expected)),
                    "  actual: {}".format(_render_value(diff.actual)),
                    "  message: {}".format(diff.message),
                ]
            )

    if report.parse_errors or report.generation_errors or report.unsupported_rules:
        lines.extend(["", "Pipeline Errors"])
        for message in report.parse_errors:
            lines.append("[PARSE] {}".format(message))
        for message in report.generation_errors:
            lines.append("[GENERATION] {}".format(message))
        for issue in report.unsupported_rules:
            rule = "" if issue.rule_id is None else " rule={}".format(issue.rule_id)
            lines.append(
                "[UNSUPPORTED]{} {}".format(rule, issue.message)
            )

    lines.extend(
        [
            "",
            "Overall: {}".format(report.overall_status.value),
            "Duration: {:.3f}ms".format(report.duration),
        ]
    )
    return "\n".join(lines)


def print_terminal_report(
    report: TestReport, stream: TextIO = sys.stdout
) -> None:
    print(render_terminal_report(report), file=stream)


def _row(label: str, value: object) -> str:
    return "{:<20}{}".format(label, value)


def _display_status(status: PhaseStatus) -> str:
    return "NOT RUN" if status == PhaseStatus.NOT_RUN else status.value


def _render_value(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)
