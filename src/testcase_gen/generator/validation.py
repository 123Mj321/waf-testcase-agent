"""Parsing and rule-aware deterministic validation of LLM candidates.

The LLM only proposes candidate HTTP requests plus the rule semantics
(``match`` / ``no_match``) it believes the request satisfies.  Every candidate is
re-checked here against the parsed :class:`~testcase_gen.models.RuleSpec`:

* the target collection/selector is really used by the request
* the operator (including transformations and negation) really evaluates to the
  declared semantics
* the request is executable (method, path, headers, body)
* the expected status code is derived from the rule, never from the LLM
* no other deny rule would answer with a different status code

Candidates that fail any of these checks are rejected instead of executed.
"""

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import unquote

from testcase_gen.models import CaseSpec, CaseType, RuleSpec

from .prompt import (
    ALLOWED_METHODS,
    BODY_METHODS,
    CANDIDATE_CATEGORIES,
    PROMPT_VERSION,
)
from .strategies.base import UnsupportedRuleError
from .strategies.mvp import RequestUriRuleEngineOffStrategy


MAX_PATH_LENGTH = 2048
MAX_BODY_LENGTH = 8192
MAX_HEADER_VALUE_LENGTH = 4096
MAX_RATIONALE_LENGTH = 300

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_METHODS = frozenset(ALLOWED_METHODS)
_BODY_METHODS = frozenset(BODY_METHODS)
_CATEGORIES = frozenset(CANDIDATE_CATEGORIES)
_SEMANTICS = {"match": True, "no_match": False}

_SUPPORTED_TRANSFORMATIONS = frozenset(
    {"none", "lowercase", "uppercase", "trim", "urldecodeuni", "urldecode"}
)


class MalformedLLMOutputError(ValueError):
    """Raised when the LLM response cannot be parsed into candidates."""

    def __init__(
        self, rule_id: int, reason: str, excerpt: str = ""
    ) -> None:
        super().__init__(
            "rule {}: malformed LLM output: {}".format(rule_id, reason)
        )
        self.rule_id = rule_id
        self.reason = reason
        self.excerpt = excerpt[:200]


@dataclass(frozen=True)
class CandidateDecision:
    """Result of validating one LLM candidate."""

    category: str
    rationale: str
    semantics: Optional[str]
    accepted: bool
    reasons: Tuple[str, ...]
    case: Optional[CaseSpec] = None

    @property
    def rejection_reason(self) -> Optional[str]:
        return self.reasons[0] if self.reasons else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "rationale": self.rationale,
            "expected_semantics": self.semantics,
            "accepted": self.accepted,
            "reasons": list(self.reasons),
            "case_id": None if self.case is None else self.case.case_id,
        }


def parse_candidate_payload(
    raw_text: str, rule_id: int
) -> List[Mapping[str, Any]]:
    """Parse the LLM response into raw candidate objects."""
    text = (raw_text or "").strip()
    if not text:
        raise MalformedLLMOutputError(rule_id, "response is empty")

    payload: Any = None
    for fragment in _json_candidates(text):
        try:
            payload = json.loads(fragment)
        except json.JSONDecodeError:
            continue
        break

    if payload is None:
        raise MalformedLLMOutputError(
            rule_id, "response is not valid JSON", text
        )
    if not isinstance(payload, Mapping):
        raise MalformedLLMOutputError(
            rule_id,
            "response root must be a JSON object",
            text,
        )
    if "candidates" not in payload:
        raise MalformedLLMOutputError(
            rule_id, "response object has no 'candidates' array", text
        )
    candidates = payload["candidates"]
    if not isinstance(candidates, list):
        raise MalformedLLMOutputError(
            rule_id, "'candidates' must be a JSON array", text
        )

    returned_rule_id = payload.get("rule_id")
    if (
        returned_rule_id is not None
        and returned_rule_id != rule_id
    ):
        raise MalformedLLMOutputError(
            rule_id,
            "response rule_id {} does not match requested rule {}".format(
                returned_rule_id, rule_id
            ),
            text,
        )
    return candidates


def _json_candidates(text: str) -> List[str]:
    """Yield plausible JSON fragments, tolerating markdown fences and prose."""
    fragments = [text]
    stripped = _strip_code_fence(text)
    if stripped != text:
        fragments.insert(0, stripped)
    first = stripped.find("{")
    last = stripped.rfind("}")
    if first != -1 and last > first:
        fragments.insert(0, stripped[first : last + 1])
    return fragments


def _strip_code_fence(text: str) -> str:
    if not text.startswith("```"):
        return text
    lines = text.splitlines()
    if lines:
        lines = lines[1:]
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip()


def apply_transformations(
    value: str, transformations: Sequence[str]
) -> Optional[str]:
    """Apply the supported ModSecurity transformations; ``None`` = unsupported."""
    transformed = value
    for transformation in transformations:
        name = transformation.lower()
        if name in ("none", ""):
            continue
        if name == "lowercase":
            transformed = transformed.lower()
        elif name == "uppercase":
            transformed = transformed.upper()
        elif name == "trim":
            transformed = transformed.strip()
        elif name in ("urldecodeuni", "urldecode"):
            transformed = unquote(transformed)
        else:
            return None
    return transformed


def evaluate_operator_on(rule: RuleSpec, value: str) -> Optional[bool]:
    """Evaluate the (non negated) operator against an already transformed value."""
    operator = rule.operator.lower()
    argument = rule.operator_arg

    if operator == "rx":
        try:
            return re.search(argument, value) is not None
        except re.error:
            return None
    if operator == "contains":
        return argument in value
    if operator == "beginswith":
        return value.startswith(argument)
    if operator == "endswith":
        return value.endswith(argument)
    if operator in ("streq", "eq"):
        return value == argument
    if operator in ("within", "pm", "pmfromfile"):
        return value in argument.split()
    if operator in ("gt", "ge", "lt", "le"):
        try:
            left = float(value)
            right = float(argument)
        except (TypeError, ValueError):
            return None
        if operator == "gt":
            return left > right
        if operator == "ge":
            return left >= right
        if operator == "lt":
            return left < right
        return left <= right
    if operator == "unconditionalmatch":
        return True
    return None


def evaluate_rule(rule: RuleSpec, value: str) -> Optional[bool]:
    """Evaluate a rule against a raw wire value; ``None`` = not verifiable."""
    transformed = apply_transformations(value, rule.transformations)
    if transformed is None:
        return None
    result = evaluate_operator_on(rule, transformed)
    if result is None:
        return None
    if rule.operator_negated:
        return not result
    return result


def _query_pairs(text: str) -> Dict[str, str]:
    pairs: Dict[str, str] = {}
    for part in text.split("&"):
        if not part:
            continue
        name, _separator, value = part.partition("=")
        if name not in pairs:
            pairs[name] = value
    return pairs


def extract_target_value(
    request: Mapping[str, Any], rule: RuleSpec
) -> Optional[str]:
    """Extract the wire value the rule would inspect in this request."""
    method = str(request.get("method", "")).upper()
    path = str(request.get("path", ""))
    headers = request.get("headers") or {}
    body = request.get("body")

    values: List[Optional[str]] = []
    for variable in rule.variables:
        values.append(
            _value_for_collection(
                variable.collection.upper(),
                variable.selector,
                method,
                path,
                headers,
                body,
            )
        )
    usable = [value for value in values if value is not None]
    if not usable:
        return None
    if len(rule.variables) == 1:
        return usable[0]
    return "\n".join(usable)


def _value_for_collection(
    collection: str,
    selector: Optional[str],
    method: str,
    path: str,
    headers: Mapping[str, Any],
    body: Optional[str],
) -> Optional[str]:
    query = path.split("?", 1)[1] if "?" in path else ""

    if collection == "ARGS":
        pairs = _query_pairs(query)
        if body and method in _BODY_METHODS:
            for name, value in _query_pairs(str(body)).items():
                pairs.setdefault(name, value)
        if selector is None:
            if not pairs:
                return None
            return "&".join(
                "{}={}".format(name, value) for name, value in pairs.items()
            )
        return _lookup(pairs, selector)

    if collection in ("ARGS_GET", "QUERY_STRING"):
        pairs = _query_pairs(query)
        if selector is None:
            return query or None
        return _lookup(pairs, selector)

    if collection == "ARGS_POST":
        if not body:
            return None
        pairs = _query_pairs(str(body))
        if selector is None:
            return str(body)
        return _lookup(pairs, selector)

    if collection == "REQUEST_HEADERS":
        normalized = {
            str(name).lower(): value for name, value in headers.items()
        }
        if selector is None:
            if not normalized:
                return None
            return "\n".join(
                "{}: {}".format(name, value)
                for name, value in normalized.items()
            )
        return normalized.get(selector.lower())

    if collection in ("REQUEST_HEADERS_NAMES",):
        return "\n".join(str(name) for name in headers) or None

    if collection == "REQUEST_METHOD":
        return method

    if collection == "REQUEST_URI":
        return path

    if collection == "REQUEST_URI_RAW":
        return path

    if collection == "REQUEST_FILENAME":
        return path.split("?", 1)[0]

    if collection == "REQUEST_BASENAME":
        return path.split("?", 1)[0].rsplit("/", 1)[-1]

    if collection == "REQUEST_BODY":
        return "" if body is None else str(body)

    if collection == "REQUEST_PROTOCOL":
        return "HTTP/1.1"

    return None


def _lookup(pairs: Mapping[str, str], selector: str) -> Optional[str]:
    if selector in pairs:
        return pairs[selector]
    lowered = selector.lower()
    for name, value in pairs.items():
        if name.lower() == lowered:
            return value
    return None


def expected_code_for_rule(
    rule: RuleSpec, matches: bool, success_status: int, rules: Sequence[RuleSpec]
) -> Tuple[Optional[int], Optional[str]]:
    """Derive the expected status code from the rule; never from the LLM."""
    if rule.disruptive_action == "deny" and rule.status is not None:
        return (rule.status if matches else success_status), None

    if _is_engine_off_rule(rule):
        if matches:
            return success_status, None
        probe = _find_probe(rule, rules)
        if probe is None:
            return (
                None,
                "ruleEngine=off rule needs a supported downstream blocking probe",
            )
        return probe[0].status, None

    return (
        None,
        "rule action {!r} has no deterministic expected status".format(
            rule.disruptive_action
        ),
    )


def _is_engine_off_rule(rule: RuleSpec) -> bool:
    return (
        rule.disruptive_action == "pass"
        and str(rule.ctl_actions.get("ruleEngine", "")).lower() == "off"
    )


def _find_probe(
    rule: RuleSpec, rules: Sequence[RuleSpec]
) -> Optional[Tuple[RuleSpec, str]]:
    try:
        return RequestUriRuleEngineOffStrategy._find_probe(rule, rules)
    except UnsupportedRuleError:
        return None


class RuleAwareCandidateValidator:
    """Validate and de-duplicate LLM candidates against parsed rules."""

    def __init__(
        self,
        rules: Sequence[RuleSpec],
        success_status: int = 200,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        prompt_version: str = PROMPT_VERSION,
    ) -> None:
        self._rules = list(rules)
        self._success_status = success_status
        self._provider = provider
        self._model = model
        self._prompt_version = prompt_version
        self._seen: Set[Tuple[Any, ...]] = set()
        self._counters: Dict[int, int] = {}

    def seed(self, cases: Sequence[CaseSpec]) -> None:
        """Register already existing cases so LLM duplicates are rejected."""
        for case in cases:
            self._seen.add(self._dedup_key(case))

    def validate(
        self, raw_text: str, rule: RuleSpec
    ) -> List[CandidateDecision]:
        """Validate every candidate in one LLM response."""
        try:
            candidates = parse_candidate_payload(raw_text, rule.rule_id)
        except MalformedLLMOutputError as exc:
            return [
                CandidateDecision(
                    category="malformed",
                    rationale="",
                    semantics=None,
                    accepted=False,
                    reasons=(exc.reason,),
                )
            ]
        return [
            self._validate_candidate(candidate, rule)
            for candidate in candidates
        ]

    def _validate_candidate(
        self, candidate: Any, rule: RuleSpec
    ) -> CandidateDecision:
        if not isinstance(candidate, Mapping):
            return self._reject(
                "unknown", None, "candidate is not a JSON object"
            )

        category = candidate.get("category")
        rationale = str(candidate.get("rationale", ""))[:MAX_RATIONALE_LENGTH]
        semantics = candidate.get("expected_semantics")

        if "expected_code" in candidate or "expected_status" in candidate:
            return self._reject(
                str(category or "unknown"),
                semantics,
                "candidate must not contain an expected status code "
                "(the LLM does not decide expected_code)",
            )
        if not isinstance(category, str) or category not in _CATEGORIES:
            return self._reject(
                str(category or "unknown"),
                semantics,
                "unknown candidate category: {!r}".format(category),
            )
        if not isinstance(semantics, str) or semantics not in _SEMANTICS:
            return self._reject(
                str(category),
                semantics,
                "invalid or missing expected_semantics: {!r}".format(semantics),
            )
        if "rationale" not in candidate or not str(
            candidate.get("rationale", "")
        ).strip():
            return self._reject(
                str(category), semantics, "candidate has no rationale"
            )

        request, reason = self._normalize_request(candidate)
        if request is None:
            return self._reject(str(category), semantics, reason or "")

        value = extract_target_value(request, rule)
        if value is None:
            return self._reject(
                str(category),
                semantics,
                "candidate does not provide a value for target {}".format(
                    "|".join(variable.raw for variable in rule.variables)
                ),
            )

        matches = evaluate_rule(rule, value)
        if matches is None:
            return self._reject(
                str(category),
                semantics,
                "rule operator {!r} with transformations {!r} cannot be "
                "validated deterministically".format(
                    rule.operator, rule.transformations
                ),
            )
        if matches != _SEMANTICS[str(semantics)]:
            return self._reject(
                str(category),
                semantics,
                "rule semantic mismatch: candidate declares {!r} but the rule "
                "evaluates to {}".format(
                    semantics, "match" if matches else "no_match"
                ),
            )

        expected_code, code_reason = expected_code_for_rule(
            rule, matches, self._success_status, self._rules
        )
        if expected_code is None:
            return self._reject(
                str(category), semantics, code_reason or "no expected status"
            )

        engine_off = _is_engine_off_rule(rule) and matches
        probe_reason = self._check_engine_off(rule, request, matches)
        if probe_reason is not None:
            return self._reject(str(category), semantics, probe_reason)

        conflicts = self._conflicting_rules(
            rule, request, expected_code, engine_off
        )
        if conflicts:
            return self._reject(
                str(category),
                semantics,
                "candidate also triggers rule {} with a different status".format(
                    ", ".join(str(rule_id) for rule_id in conflicts)
                ),
            )

        case_type = CaseType.POSITIVE if matches else CaseType.NEGATIVE
        key = (
            rule.rule_id,
            case_type,
            request["method"],
            request["path"],
            tuple(sorted(request["headers"].items())),
            request["body"],
        )
        if key in self._seen:
            return self._reject(
                str(category), semantics, "duplicate candidate"
            )
        self._seen.add(key)

        case = self._build_case(
            rule,
            request,
            case_type,
            expected_code,
            str(category),
            str(semantics),
            rationale,
            matches,
        )
        return CandidateDecision(
            category=str(category),
            rationale=rationale,
            semantics=str(semantics),
            accepted=True,
            reasons=(),
            case=case,
        )

    def _normalize_request(
        self, candidate: Mapping[str, Any]
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        method = candidate.get("method")
        if not isinstance(method, str) or method.upper() not in _METHODS:
            return None, "unsupported method: {!r}".format(method)
        method = method.upper()

        path = candidate.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            return None, "path must be a string starting with '/'"
        if _CONTROL_CHARACTERS.search(path):
            return None, "path contains control characters"
        if len(path) > MAX_PATH_LENGTH:
            return None, "path is longer than {} characters".format(
                MAX_PATH_LENGTH
            )

        headers = candidate.get("headers", {})
        if headers is None:
            headers = {}
        if not isinstance(headers, Mapping):
            return None, "headers must be an object"
        normalized_headers: Dict[str, str] = {}
        for name, value in headers.items():
            if not isinstance(name, str) or not name.strip():
                return None, "header name must be a non-empty string"
            if not isinstance(value, str):
                return None, "header value must be a string"
            if _CONTROL_CHARACTERS.search(name) or _CONTROL_CHARACTERS.search(
                value
            ):
                return None, "header {} contains control characters".format(name)
            if len(value) > MAX_HEADER_VALUE_LENGTH:
                return None, "header {} value is too long".format(name)
            normalized_headers[name] = value

        body = candidate.get("body")
        if body is not None:
            if not isinstance(body, str):
                return None, "body must be a string or null"
            if method not in _BODY_METHODS:
                return None, "body is not allowed for method {}".format(method)
            if _CONTROL_CHARACTERS.search(body):
                return None, "body contains control characters"
            if len(body) > MAX_BODY_LENGTH:
                return None, "body is longer than {} characters".format(
                    MAX_BODY_LENGTH
                )

        return (
            {
                "method": method,
                "path": path,
                "headers": normalized_headers,
                "body": body,
            },
            None,
        )

    def _check_engine_off(
        self, rule: RuleSpec, request: Mapping[str, Any], matches: bool
    ) -> Optional[str]:
        """A ``ruleEngine=off`` negative case must carry the downstream probe."""
        if not _is_engine_off_rule(rule) or matches:
            return None
        probe = _find_probe(rule, self._rules)
        if probe is None:
            return (
                "ruleEngine=off rule needs a supported downstream blocking probe"
            )
        probe_rule, probe_query = probe
        if probe_query not in str(request.get("path", "")):
            return (
                "ruleEngine=off negative case must carry the downstream probe "
                "payload {!r}".format(probe_query)
            )
        probe_value = extract_target_value(request, probe_rule)
        if probe_value is None or evaluate_rule(probe_rule, probe_value) is not True:
            return (
                "probe payload does not trigger downstream rule {}".format(
                    probe_rule.rule_id
                )
            )
        return None

    def _conflicting_rules(
        self,
        rule: RuleSpec,
        request: Mapping[str, Any],
        expected_code: int,
        engine_off: bool,
    ) -> List[int]:
        conflicts: List[int] = []
        for other in self._rules:
            if other.rule_id == rule.rule_id:
                continue
            if other.disruptive_action != "deny" or other.status is None:
                continue
            if engine_off and (other.phase or 0) >= (rule.phase or 0):
                continue
            value = extract_target_value(request, other)
            if value is None:
                continue
            if (
                evaluate_rule(other, value) is True
                and other.status != expected_code
            ):
                conflicts.append(other.rule_id)
        return conflicts

    def _build_case(
        self,
        rule: RuleSpec,
        request: Mapping[str, Any],
        case_type: CaseType,
        expected_code: int,
        category: str,
        semantics: str,
        rationale: str,
        matches: bool,
    ) -> CaseSpec:
        index = self._counters.get(rule.rule_id, 0) + 1
        self._counters[rule.rule_id] = index
        return CaseSpec(
            case_id="rule-{}-llm-{}-{}".format(
                rule.rule_id, index, case_type.value
            ),
            rule_id=rule.rule_id,
            type=case_type,
            method=str(request["method"]),
            path=str(request["path"]),
            headers=dict(request["headers"]),
            body=request["body"],
            expected_code=expected_code,
            generation_strategy="llm-{}".format(category),
            warnings=[
                "LLM candidate accepted by rule-aware deterministic validation"
            ],
            metadata={
                "source": "llm",
                "llm_category": category,
                "llm_provider": self._provider,
                "llm_model": self._model,
                "prompt_version": self._prompt_version,
                "llm_rationale": rationale,
                "expected_semantics": semantics,
                "rule_match": matches,
            },
        )

    def _reject(
        self, category: str, semantics: Any, reason: str
    ) -> CandidateDecision:
        return CandidateDecision(
            category=category,
            rationale="",
            semantics=None if semantics is None else str(semantics),
            accepted=False,
            reasons=(reason,),
        )

    @staticmethod
    def _dedup_key(case: CaseSpec) -> Tuple[Any, ...]:
        return (
            case.rule_id,
            case.type,
            case.method,
            case.path,
            tuple(sorted(case.headers.items())),
            case.body,
        )
