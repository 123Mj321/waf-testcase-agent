from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class CaseType(str, Enum):
    POSITIVE = "positive"
    NEGATIVE = "negative"


@dataclass(frozen=True)
class TargetVariable:
    collection: str
    selector: Optional[str]
    raw: str


@dataclass(frozen=True)
class RuleAction:
    name: str
    value: Optional[str]
    raw: str


@dataclass
class RuleSpec:
    rule_id: int
    variables: List[TargetVariable]
    operator: str
    operator_arg: str
    operator_negated: bool
    transformations: List[str]
    phase: Optional[int]
    actions: List[RuleAction]
    disruptive_action: Optional[str]
    status: Optional[int]
    log: Optional[bool]
    msg: Optional[str]
    ctl_actions: Dict[str, str]
    raw_text: str
    source_line: int
    source_end_line: int


@dataclass
class CaseSpec:
    case_id: str
    rule_id: int
    type: CaseType
    method: str
    path: str
    headers: Dict[str, str]
    body: Optional[str]
    expected_code: int
    generation_strategy: str
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "rule_id": self.rule_id,
            "type": self.type.value,
            "method": self.method,
            "path": self.path,
            "headers": dict(self.headers),
            "body": self.body,
            "expected_code": self.expected_code,
            "generation_strategy": self.generation_strategy,
            "warnings": list(self.warnings),
            "metadata": dict(self.metadata),
        }
