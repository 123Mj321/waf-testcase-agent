import re
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import unquote

from testcase_gen.models import CaseSpec, CaseType, RuleSpec, TargetVariable

from .base import GenerationContext, GenerationStrategy, UnsupportedRuleError


_QUERY_SQLI_CANDIDATES = (
    "1 OR 1=1",
    "UNION payload SELECT",
    "DROP TABLE users",
)
_BODY_SQLI_CANDIDATES = (
    "query=SELECT name FROM users",
    "SELECT value FROM records ",
)
_HEADER_TEMPLATES = {
    "user-agent": (
        ("sqlmap/1.7", "nikto/2.5", "gobuster/3.6"),
        "Mozilla/5.0",
    ),
    "referer": (
        ("https://evil.com/page", "https://malicious.site/page"),
        "https://google.com",
    ),
}


def _single_target(rule: RuleSpec, collection: str) -> Optional[TargetVariable]:
    if len(rule.variables) != 1:
        return None
    target = rule.variables[0]
    if target.collection.upper() != collection:
        return None
    return target


def _transformations(rule: RuleSpec) -> List[str]:
    return [transformation.lower() for transformation in rule.transformations]


def _is_deny_rule(rule: RuleSpec) -> bool:
    return rule.disruptive_action == "deny" and rule.status is not None


def _apply_transformations(rule: RuleSpec, value: str) -> str:
    transformed = value
    for transformation in _transformations(rule):
        if transformation == "lowercase":
            transformed = transformed.lower()
        elif transformation == "urldecodeuni":
            transformed = unquote(transformed)
        else:
            raise UnsupportedRuleError(
                rule.rule_id,
                "unsupported transformation {!r}".format(transformation),
            )
    return transformed


def _regex_matches(rule: RuleSpec, value: str) -> bool:
    transformed = _apply_transformations(rule, value)
    try:
        return re.search(rule.operator_arg, transformed) is not None
    except re.error as exc:
        raise UnsupportedRuleError(
            rule.rule_id,
            "operator regex is not supported by the MVP: {}".format(exc),
        ) from exc


def _first_matching(rule: RuleSpec, candidates: Sequence[str]) -> str:
    for candidate in candidates:
        if _regex_matches(rule, candidate):
            return candidate
    raise UnsupportedRuleError(
        rule.rule_id,
        "no deterministic witness for regex {!r}".format(rule.operator_arg),
    )


def _first_non_matching(rule: RuleSpec, candidates: Sequence[str]) -> str:
    for candidate in candidates:
        if not _regex_matches(rule, candidate):
            return candidate
    raise UnsupportedRuleError(
        rule.rule_id,
        "no deterministic negative witness for regex {!r}".format(
            rule.operator_arg
        ),
    )


def _alternating_case(value: str) -> str:
    upper = True
    result = []
    for char in value:
        if char.isalpha():
            result.append(char.upper() if upper else char.lower())
            upper = not upper
        else:
            result.append(char)
    return "".join(result)


def _args_values(rule: RuleSpec) -> Tuple[str, str, List[str]]:
    transformations = _transformations(rule)

    if rule.operator.lower() == "rx" and transformations == []:
        return (
            _first_matching(rule, _QUERY_SQLI_CANDIDATES),
            _first_non_matching(rule, ("normal_value", "12345", "document")),
            [],
        )

    if rule.operator.lower() == "rx" and transformations == ["urldecodeuni"]:
        positive = "%2e%2e%2f%2e%2e%2fetc/passwd"
        negative = "docs/readme.txt"
        if not _regex_matches(rule, positive) or _regex_matches(rule, negative):
            raise UnsupportedRuleError(
                rule.rule_id,
                "urlDecodeUni regex is not a supported traversal shape",
            )
        return (
            positive,
            negative,
            [
                "positive path contains pre-encoded percent sequences; "
                "the HTTP executor must preserve them"
            ],
        )

    if (
        rule.operator.lower() == "contains"
        and transformations == ["lowercase"]
    ):
        mixed = _alternating_case(rule.operator_arg.lower())
        if rule.operator_arg.lower() == "<script":
            positive = "{}>alert(1)</{}>".format(mixed, mixed.lstrip("<"))
        else:
            positive = mixed
        negative = "hello+world"
        transformed_positive = _apply_transformations(rule, positive)
        transformed_negative = _apply_transformations(rule, negative)
        if (
            rule.operator_arg not in transformed_positive
            or rule.operator_arg in transformed_negative
        ):
            raise UnsupportedRuleError(
                rule.rule_id,
                "contains/lowercase witnesses cannot be derived safely",
            )
        return positive, negative, []

    raise UnsupportedRuleError(
        rule.rule_id,
        "unsupported ARGS operator/transformation combination",
    )


def _case(
    rule: RuleSpec,
    case_type: CaseType,
    method: str,
    path: str,
    headers: Dict[str, str],
    body: Optional[str],
    expected_code: int,
    strategy: str,
    warnings: Optional[List[str]] = None,
    metadata: Optional[Dict[str, object]] = None,
) -> CaseSpec:
    return CaseSpec(
        case_id="rule-{}-{}".format(rule.rule_id, case_type.value),
        rule_id=rule.rule_id,
        type=case_type,
        method=method,
        path=path,
        headers=headers,
        body=body,
        expected_code=expected_code,
        generation_strategy=strategy,
        warnings=list(warnings or []),
        metadata=dict(metadata or {}),
    )


class ArgsRegexStrategy(GenerationStrategy):
    name = "args-regex"

    def supports(self, rule: RuleSpec) -> bool:
        target = _single_target(rule, "ARGS")
        return (
            target is not None
            and target.selector is not None
            and rule.phase == 2
            and rule.operator.lower() == "rx"
            and not rule.operator_negated
            and _transformations(rule) == []
            and _is_deny_rule(rule)
        )

    def generate(
        self, rule: RuleSpec, context: GenerationContext
    ) -> List[CaseSpec]:
        target = rule.variables[0]
        positive_value, negative_value, warnings = _args_values(rule)
        return [
            _case(
                rule,
                CaseType.POSITIVE,
                "GET",
                "/?{}={}".format(target.selector, positive_value),
                {},
                None,
                rule.status,
                self.name,
                warnings,
            ),
            _case(
                rule,
                CaseType.NEGATIVE,
                "GET",
                "/?{}={}".format(target.selector, negative_value),
                {},
                None,
                context.success_status,
                self.name,
            ),
        ]


class ArgsContainsLowercaseStrategy(GenerationStrategy):
    name = "args-contains-lowercase"

    def supports(self, rule: RuleSpec) -> bool:
        target = _single_target(rule, "ARGS")
        return (
            target is not None
            and target.selector is not None
            and rule.phase == 2
            and rule.operator.lower() == "contains"
            and not rule.operator_negated
            and _transformations(rule) == ["lowercase"]
            and _is_deny_rule(rule)
        )

    def generate(
        self, rule: RuleSpec, context: GenerationContext
    ) -> List[CaseSpec]:
        target = rule.variables[0]
        positive_value, negative_value, warnings = _args_values(rule)
        return [
            _case(
                rule,
                CaseType.POSITIVE,
                "GET",
                "/?{}={}".format(target.selector, positive_value),
                {},
                None,
                rule.status,
                self.name,
                warnings,
                {"transformation_probe": "mixed-case input"},
            ),
            _case(
                rule,
                CaseType.NEGATIVE,
                "GET",
                "/?{}={}".format(target.selector, negative_value),
                {},
                None,
                context.success_status,
                self.name,
            ),
        ]


class ArgsUrlDecodeRegexStrategy(GenerationStrategy):
    name = "args-regex-url-decode"

    def supports(self, rule: RuleSpec) -> bool:
        target = _single_target(rule, "ARGS")
        return (
            target is not None
            and target.selector is not None
            and rule.phase == 2
            and rule.operator.lower() == "rx"
            and not rule.operator_negated
            and _transformations(rule) == ["urldecodeuni"]
            and _is_deny_rule(rule)
        )

    def generate(
        self, rule: RuleSpec, context: GenerationContext
    ) -> List[CaseSpec]:
        target = rule.variables[0]
        positive_value, negative_value, warnings = _args_values(rule)
        return [
            _case(
                rule,
                CaseType.POSITIVE,
                "GET",
                "/?{}={}".format(target.selector, positive_value),
                {},
                None,
                rule.status,
                self.name,
                warnings,
                {"wire_encoding": "already-percent-encoded"},
            ),
            _case(
                rule,
                CaseType.NEGATIVE,
                "GET",
                "/?{}={}".format(target.selector, negative_value),
                {},
                None,
                context.success_status,
                self.name,
            ),
        ]


class RequestHeaderRegexStrategy(GenerationStrategy):
    name = "request-header-regex"

    def supports(self, rule: RuleSpec) -> bool:
        target = _single_target(rule, "REQUEST_HEADERS")
        return (
            target is not None
            and target.selector is not None
            and rule.phase == 1
            and rule.operator.lower() == "rx"
            and not rule.operator_negated
            and _transformations(rule) == []
            and _is_deny_rule(rule)
        )

    def generate(
        self, rule: RuleSpec, context: GenerationContext
    ) -> List[CaseSpec]:
        target = rule.variables[0]
        template = _HEADER_TEMPLATES.get(target.selector.lower())
        if template is None:
            raise UnsupportedRuleError(
                rule.rule_id,
                "no request-header witness template for {!r}".format(
                    target.selector
                ),
            )
        positive_candidates, negative_value = template
        positive_value = _first_matching(rule, positive_candidates)
        if _regex_matches(rule, negative_value):
            raise UnsupportedRuleError(
                rule.rule_id,
                "configured safe header value matches the regex",
            )
        return [
            _case(
                rule,
                CaseType.POSITIVE,
                "GET",
                "/",
                {target.selector: positive_value},
                None,
                rule.status,
                self.name,
            ),
            _case(
                rule,
                CaseType.NEGATIVE,
                "GET",
                "/",
                {target.selector: negative_value},
                None,
                context.success_status,
                self.name,
            ),
        ]


class RequestMethodNegatedWithinStrategy(GenerationStrategy):
    name = "request-method-negated-within"

    def supports(self, rule: RuleSpec) -> bool:
        return (
            _single_target(rule, "REQUEST_METHOD") is not None
            and rule.phase == 1
            and rule.operator.lower() == "within"
            and rule.operator_negated
            and _transformations(rule) == []
            and _is_deny_rule(rule)
        )

    def generate(
        self, rule: RuleSpec, context: GenerationContext
    ) -> List[CaseSpec]:
        allowed = rule.operator_arg.split()
        if not allowed:
            raise UnsupportedRuleError(rule.rule_id, "within has no allowed values")
        negative_method = "POST" if "POST" in allowed else allowed[0]
        positive_method = next(
            (method for method in ("DELETE", "PUT", "PATCH") if method not in rule.operator_arg),
            None,
        )
        if positive_method is None:
            raise UnsupportedRuleError(
                rule.rule_id, "cannot derive a method outside @within"
            )
        return [
            _case(
                rule,
                CaseType.POSITIVE,
                positive_method,
                "/resource",
                {},
                None,
                rule.status,
                self.name,
            ),
            _case(
                rule,
                CaseType.NEGATIVE,
                negative_method,
                "/resource",
                {},
                None,
                context.success_status,
                self.name,
            ),
        ]


class RequestUriRuleEngineOffStrategy(GenerationStrategy):
    name = "request-uri-rule-engine-off-differential"

    def supports(self, rule: RuleSpec) -> bool:
        return (
            _single_target(rule, "REQUEST_URI") is not None
            and rule.phase == 1
            and rule.operator.lower() == "beginswith"
            and not rule.operator_negated
            and _transformations(rule) == []
            and rule.disruptive_action == "pass"
            and rule.ctl_actions.get("ruleEngine", "").lower() == "off"
        )

    def generate(
        self, rule: RuleSpec, context: GenerationContext
    ) -> List[CaseSpec]:
        probe_rule, query = self._find_probe(rule, context.rules)
        positive_path = self._append_query(rule.operator_arg, query)
        negative_path = self._append_query("/other", query)
        if negative_path.startswith(rule.operator_arg):
            raise UnsupportedRuleError(
                rule.rule_id,
                "cannot derive a URI outside the beginsWith prefix",
            )

        metadata = {
            "control_action": "ruleEngine=off",
            "probe_rule_id": probe_rule.rule_id,
        }
        warning = [
            "differential result depends on downstream blocking rule {}".format(
                probe_rule.rule_id
            )
        ]
        return [
            _case(
                rule,
                CaseType.POSITIVE,
                "GET",
                positive_path,
                {},
                None,
                context.success_status,
                self.name,
                warning,
                dict(metadata, expected_engine_state="off"),
            ),
            _case(
                rule,
                CaseType.NEGATIVE,
                "GET",
                negative_path,
                {},
                None,
                probe_rule.status,
                self.name,
                warning,
                dict(metadata, expected_engine_state="on"),
            ),
        ]

    @staticmethod
    def _append_query(path: str, query: str) -> str:
        separator = "&" if "?" in path else "?"
        return "{}{}{}".format(path, separator, query)

    @staticmethod
    def _find_probe(
        control_rule: RuleSpec, rules: Sequence[RuleSpec]
    ) -> Tuple[RuleSpec, str]:
        candidates = sorted(rules, key=lambda candidate: candidate.source_line)
        for candidate in candidates:
            target = _single_target(candidate, "ARGS")
            if (
                target is None
                or target.selector is None
                or not _is_deny_rule(candidate)
                or candidate.phase is None
                or control_rule.phase is None
                or candidate.phase <= control_rule.phase
            ):
                continue
            try:
                positive_value, _, _ = _args_values(candidate)
            except UnsupportedRuleError:
                continue
            return candidate, "{}={}".format(target.selector, positive_value)

        raise UnsupportedRuleError(
            control_rule.rule_id,
            "ruleEngine=off needs a supported downstream blocking probe",
        )


class RequestBodyRegexStrategy(GenerationStrategy):
    name = "request-body-regex"

    def supports(self, rule: RuleSpec) -> bool:
        return (
            _single_target(rule, "REQUEST_BODY") is not None
            and rule.phase == 2
            and rule.operator.lower() == "rx"
            and not rule.operator_negated
            and _transformations(rule) == []
            and _is_deny_rule(rule)
        )

    def generate(
        self, rule: RuleSpec, context: GenerationContext
    ) -> List[CaseSpec]:
        positive_body = _first_matching(rule, _BODY_SQLI_CANDIDATES)
        negative_body = _first_non_matching(rule, ("query=hello", "value=normal"))
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        return [
            _case(
                rule,
                CaseType.POSITIVE,
                "POST",
                "/search",
                dict(headers),
                positive_body,
                rule.status,
                self.name,
            ),
            _case(
                rule,
                CaseType.NEGATIVE,
                "POST",
                "/search",
                dict(headers),
                negative_body,
                context.success_status,
                self.name,
            ),
        ]


def default_strategies() -> List[GenerationStrategy]:
    return [
        RequestUriRuleEngineOffStrategy(),
        ArgsUrlDecodeRegexStrategy(),
        ArgsContainsLowercaseStrategy(),
        ArgsRegexStrategy(),
        RequestHeaderRegexStrategy(),
        RequestMethodNegatedWithinStrategy(),
        RequestBodyRegexStrategy(),
    ]
