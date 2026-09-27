from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from testcase_gen.models import CaseType
from testcase_gen.validator import GoldDiff


class PhaseStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_RUN = "NOT_RUN"


class OverallStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAIL = "FAIL"
    INCOMPLETE = "INCOMPLETE"


class CaseResultStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


@dataclass(frozen=True)
class ReportIssue:
    stage: str
    message: str
    rule_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage": self.stage,
            "rule_id": self.rule_id,
            "message": self.message,
        }


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    rule_id: int
    type: CaseType
    expected_code: int
    actual_code: Optional[int]
    passed: bool
    status: CaseResultStatus
    latency_ms: float
    response_headers: Dict[str, str]
    response_body_excerpt: str
    error: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "rule_id": self.rule_id,
            "type": self.type.value,
            "expected_code": self.expected_code,
            "actual_code": self.actual_code,
            "passed": self.passed,
            "status": self.status.value,
            "latency_ms": round(self.latency_ms, 3),
            "response_headers": dict(self.response_headers),
            "response_body_excerpt": self.response_body_excerpt,
            "error": self.error,
        }


@dataclass(frozen=True)
class TestReport:
    generated_count: int
    positive_count: int
    negative_count: int
    gold_count: int
    gold_matched_count: int
    gold_passed: bool
    execution_count: int
    execution_passed: int
    execution_failed: int
    execution_errors: int
    rule_count: int
    expected_rule_count: int
    rule_coverage: List[int]
    case_results: List[CaseResult]
    gold_diffs: List[GoldDiff]
    unsupported_rules: List[ReportIssue]
    parse_errors: List[str]
    generation_errors: List[str]
    duration: float
    generation_status: PhaseStatus
    gold_status: PhaseStatus
    runtime_status: PhaseStatus
    overall_status: OverallStatus

    def to_dict(self) -> Dict[str, Any]:
        errors = [
            ReportIssue(stage="parse", message=message).to_dict()
            for message in self.parse_errors
        ]
        errors.extend(
            ReportIssue(stage="generation", message=message).to_dict()
            for message in self.generation_errors
        )
        errors.extend(issue.to_dict() for issue in self.unsupported_rules)

        return {
            "summary": {
                "overall_status": self.overall_status.value,
                "generation_status": self.generation_status.value,
                "gold_status": self.gold_status.value,
                "runtime_status": self.runtime_status.value,
                "rule_count": self.rule_count,
                "generated_count": self.generated_count,
                "gold_count": self.gold_count,
                "gold_passed": self.gold_passed,
                "execution_count": self.execution_count,
                "execution_passed": self.execution_passed,
                "execution_failed": self.execution_failed,
                "execution_errors": self.execution_errors,
                "duration_ms": round(self.duration, 3),
            },
            "generation": {
                "status": self.generation_status.value,
                "rules_parsed": self.rule_count,
                "expected_rules": self.expected_rule_count,
                "rule_coverage": list(self.rule_coverage),
                "cases_generated": self.generated_count,
                "positive": self.positive_count,
                "negative": self.negative_count,
                "unsupported": len(self.unsupported_rules),
                "parse_errors": len(self.parse_errors),
                "generation_errors": len(self.generation_errors),
            },
            "gold_validation": {
                "status": self.gold_status.value,
                "gold_cases": self.gold_count,
                "generated_cases": self.generated_count,
                "exact_matches": self.gold_matched_count,
                "differences": len(self.gold_diffs),
                "passed": self.gold_passed,
            },
            "execution": {
                "status": self.runtime_status.value,
                "executed": self.execution_count,
                "passed": self.execution_passed,
                "failed": self.execution_failed,
                "errors": self.execution_errors,
            },
            "cases": [case.to_dict() for case in self.case_results],
            "gold_diffs": [
                dict(diff.to_dict(), case_id=diff.case_id)
                for diff in self.gold_diffs
            ],
            "errors": errors,
        }
