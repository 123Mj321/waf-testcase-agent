from typing import Iterable, List, Optional, Sequence

from testcase_gen.models import CaseSpec, CaseType, RuleSpec

from .strategies import (
    GenerationContext,
    GenerationStrategy,
    UnsupportedRuleError,
    default_strategies,
)


class TestCaseGenerator:
    __test__ = False

    def __init__(
        self,
        strategies: Optional[Sequence[GenerationStrategy]] = None,
        success_status: int = 200,
    ) -> None:
        self._strategies = list(strategies or default_strategies())
        self._success_status = success_status

    def generate(self, rules: Iterable[RuleSpec]) -> List[CaseSpec]:
        rule_list = list(rules)
        context = GenerationContext(
            rules=rule_list,
            success_status=self._success_status,
        )
        cases: List[CaseSpec] = []

        for rule in rule_list:
            strategy = next(
                (
                    candidate
                    for candidate in self._strategies
                    if candidate.supports(rule)
                ),
                None,
            )
            if strategy is None:
                target = "|".join(variable.raw for variable in rule.variables)
                raise UnsupportedRuleError(
                    rule.rule_id,
                    "no strategy for target={!r}, operator={!r}, "
                    "negated={}, transformations={!r}, action={!r}, phase={!r}".format(
                        target,
                        rule.operator,
                        rule.operator_negated,
                        rule.transformations,
                        rule.disruptive_action,
                        rule.phase,
                    ),
                )

            generated = strategy.generate(rule, context)
            self._validate_pair(rule, generated, strategy.name)
            cases.extend(generated)

        case_ids = [case.case_id for case in cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("generator produced duplicate case ids")
        return cases

    @staticmethod
    def _validate_pair(
        rule: RuleSpec,
        cases: Sequence[CaseSpec],
        strategy_name: str,
    ) -> None:
        if len(cases) != 2:
            raise ValueError(
                "strategy {} must generate exactly two cases for rule {}".format(
                    strategy_name, rule.rule_id
                )
            )
        if any(case.rule_id != rule.rule_id for case in cases):
            raise ValueError(
                "strategy {} returned a case for the wrong rule".format(
                    strategy_name
                )
            )
        if {case.type for case in cases} != {
            CaseType.POSITIVE,
            CaseType.NEGATIVE,
        }:
            raise ValueError(
                "strategy {} must generate one positive and one negative".format(
                    strategy_name
                )
            )


def generate_cases(
    rules: Iterable[RuleSpec], success_status: int = 200
) -> List[CaseSpec]:
    return TestCaseGenerator(success_status=success_status).generate(rules)
