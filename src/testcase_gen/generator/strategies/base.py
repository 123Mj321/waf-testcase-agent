from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Sequence

from testcase_gen.models import CaseSpec, RuleSpec


class UnsupportedRuleError(ValueError):
    def __init__(self, rule_id: int, reason: str) -> None:
        super().__init__("rule {} is unsupported: {}".format(rule_id, reason))
        self.rule_id = rule_id
        self.reason = reason


@dataclass(frozen=True)
class GenerationContext:
    rules: Sequence[RuleSpec]
    success_status: int


class GenerationStrategy(ABC):
    name: str

    @abstractmethod
    def supports(self, rule: RuleSpec) -> bool:
        raise NotImplementedError

    @abstractmethod
    def generate(
        self, rule: RuleSpec, context: GenerationContext
    ) -> List[CaseSpec]:
        raise NotImplementedError
