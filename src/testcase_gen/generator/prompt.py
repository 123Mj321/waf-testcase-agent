"""LLM prompt builder.

The prompt is built from the structured :class:`~testcase_gen.models.RuleSpec`
produced by the SecRule parser.  The model never receives ``gold.json`` and it
never receives an expected HTTP status code: the LLM only proposes *candidate
requests* plus the rule semantics it believes they satisfy.  The expected status
code is computed later by the rule-aware deterministic validator.
"""

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence

from testcase_gen.models import RuleSpec


PROMPT_VERSION = "waf-testcase-candidate-v1"

CANDIDATE_CATEGORIES = (
    "positive",
    "negative",
    "payload_mutation",
    "encoding_variation",
    "boundary",
    "benign_lookalike",
    "rule_combination",
)

SEMANTIC_VALUES = ("match", "no_match")

ALLOWED_METHODS = (
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
)

BODY_METHODS = ("POST", "PUT", "PATCH", "DELETE")


_SYSTEM_TEMPLATE = """\
You are a WAF test-case generator for ModSecurity SecRule files.

You receive exactly one parsed SecRule as structured JSON and you reply with
candidate HTTP requests that exercise that single rule.

Hard constraints:
- Use only the structured rule below. Do not invent other rules.
- NEVER output an HTTP status code and NEVER output an "expected_code" field.
  Another component derives the expected status from the rule semantics.
- Reply with exactly one JSON object. No prose, no markdown code fences.
- Every candidate must be a literal, immediately executable HTTP request.
- Write values exactly as they must appear on the wire (percent-encoding included,
  for example "%2e%2e%2f" stays percent-encoded).
- Never emit CR, LF, NUL or any other control character inside path/headers/body.
- Do not emit duplicate candidates.
"""

_USER_TEMPLATE = """\
Structured rule (parsed RuleSpec, prompt_version={version}):

{rule_json}

Original rule text (context only, trust the structured fields above):
{source_text}

Task:
Propose up to {max_candidates} distinct candidate HTTP requests for rule {rule_id}.
Cover several of these categories when they make sense: {categories}.
- "positive" / "payload_mutation" / "encoding_variation" / "rule_combination":
  the rule operator must evaluate to TRUE for the target value.
- "negative" / "benign_lookalike" / "boundary": the rule operator must evaluate
  to FALSE for the target value. Keep them realistic and close to the rule.

Reply with exactly this JSON object:
{{
  "rule_id": {rule_id},
  "candidates": [
    {{
      "category": "one of {categories}",
      "expected_semantics": "match or no_match",
      "method": "one of {methods}",
      "path": "/path?query",
      "headers": {{"Header-Name": "value"}},
      "body": null,
      "rationale": "short explanation, at most 200 characters"
    }}
  ]
}}

Additional constraints:
- "expected_semantics" is "match" when the rule operator - after applying the
  listed transformations - is satisfied by the target value, otherwise "no_match".
- The request must place the payload in the rule target:
  ARGS:name -> query parameter "name" (or form body field for POST/PUT/PATCH),
  REQUEST_HEADERS:name -> request header, REQUEST_METHOD -> the HTTP method,
  REQUEST_URI -> the request path, REQUEST_BODY -> the raw request body.
- "path" must start with "/" and must not contain spaces or control characters.
- "headers" is an object of string -> string; use {{}} when no header is needed.
- "body" is null unless the method is one of {body_methods}.
- "rule_id" must be {rule_id}; do not return candidates for other rules.
"""


@dataclass(frozen=True)
class LLMPrompt:
    """A rendered prompt ready to be sent to a chat-completions API."""

    version: str
    rule_id: int
    system: str
    user: str

    def messages(self) -> List[Dict[str, str]]:
        return [
            {"role": "system", "content": self.system},
            {"role": "user", "content": self.user},
        ]

    def to_text(self) -> str:
        return self.system + "\n\n" + self.user


def rule_to_structured_dict(rule: RuleSpec) -> Dict[str, Any]:
    """Render a :class:`RuleSpec` as the structured JSON block sent to the LLM."""
    return {
        "rule_id": rule.rule_id,
        "targets": [
            {
                "collection": variable.collection,
                "selector": variable.selector,
                "raw": variable.raw,
            }
            for variable in rule.variables
        ],
        "operator": {
            "name": rule.operator,
            "argument": rule.operator_arg,
            "negated": rule.operator_negated,
        },
        "transformations": list(rule.transformations),
        "phase": rule.phase,
        "action": {
            "disruptive": rule.disruptive_action,
            "status": rule.status,
            "log": rule.log,
            "ctl": dict(rule.ctl_actions),
        },
        "message": rule.msg,
    }


def build_rule_prompt(
    rule: RuleSpec,
    max_candidates: int = 8,
    version: str = PROMPT_VERSION,
    categories: Sequence[str] = CANDIDATE_CATEGORIES,
) -> LLMPrompt:
    """Build the candidate-generation prompt for a single rule."""
    if max_candidates <= 0:
        raise ValueError("max_candidates must be greater than zero")

    rule_json = json.dumps(
        rule_to_structured_dict(rule),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    user = _USER_TEMPLATE.format(
        version=version,
        rule_json=rule_json,
        source_text=rule.raw_text.strip(),
        max_candidates=max_candidates,
        categories="|".join(categories),
        methods="|".join(ALLOWED_METHODS),
        body_methods=", ".join(BODY_METHODS),
        rule_id=rule.rule_id,
    )
    return LLMPrompt(
        version=version,
        rule_id=rule.rule_id,
        system=_SYSTEM_TEMPLATE,
        user=user,
    )
