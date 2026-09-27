import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from testcase_gen.models import RuleAction, RuleSpec, TargetVariable


_DISRUPTIVE_ACTIONS = {
    "allow",
    "block",
    "deny",
    "drop",
    "pass",
    "proxy",
    "redirect",
}


class SecRuleParseError(ValueError):
    def __init__(
        self,
        message: str,
        source: str = "<memory>",
        line: Optional[int] = None,
    ) -> None:
        location = source if line is None else "{}:{}".format(source, line)
        super().__init__("{}: {}".format(location, message))
        self.source = source
        self.line = line


@dataclass(frozen=True)
class _LogicalRule:
    text: str
    raw_text: str
    start_line: int
    end_line: int


def parse_rules_file(path: Path) -> List[RuleSpec]:
    source_path = Path(path)
    text = source_path.read_text(encoding="utf-8")
    return parse_rules(text, source=str(source_path))


def parse_rules(text: str, source: str = "<memory>") -> List[RuleSpec]:
    rules = [
        _parse_rule(statement, source)
        for statement in _collect_logical_rules(text, source)
    ]

    seen = set()
    for rule in rules:
        if rule.rule_id in seen:
            raise SecRuleParseError(
                "duplicate rule id {}".format(rule.rule_id),
                source,
                rule.source_line,
            )
        seen.add(rule.rule_id)

    return rules


def _collect_logical_rules(text: str, source: str) -> List[_LogicalRule]:
    statements: List[_LogicalRule] = []
    logical_parts: List[str] = []
    raw_lines: List[str] = []
    start_line: Optional[int] = None

    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()

        if not logical_parts:
            if not stripped or stripped.startswith("#"):
                continue
            if not stripped.lower().startswith("secrule"):
                continue
            start_line = line_number

        raw_lines.append(line)
        if _has_line_continuation(line):
            logical_parts.append(_remove_line_continuation(line).strip())
            continue

        logical_parts.append(stripped)
        statements.append(
            _LogicalRule(
                text=" ".join(logical_parts),
                raw_text="\n".join(raw_lines),
                start_line=start_line if start_line is not None else line_number,
                end_line=line_number,
            )
        )
        logical_parts = []
        raw_lines = []
        start_line = None

    if logical_parts:
        raise SecRuleParseError(
            "unterminated line continuation",
            source,
            start_line,
        )

    return statements


def _has_line_continuation(line: str) -> bool:
    trimmed = line.rstrip()
    if not trimmed.endswith("\\"):
        return False

    trailing_backslashes = len(trimmed) - len(trimmed.rstrip("\\"))
    if trailing_backslashes % 2 == 0:
        return False

    quote = _ending_quote_state(trimmed[:-1])
    return quote is None


def _remove_line_continuation(line: str) -> str:
    return line.rstrip()[:-1].rstrip()


def _ending_quote_state(text: str) -> Optional[str]:
    quote: Optional[str] = None
    escaped = False

    for char in text:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote is None and char in {"'", '"'}:
            quote = char
        elif quote == char:
            quote = None

    return quote


def _parse_rule(statement: _LogicalRule, source: str) -> RuleSpec:
    fields = _split_whitespace_aware(statement.text, source, statement.start_line)
    if len(fields) != 4 or fields[0].lower() != "secrule":
        raise SecRuleParseError(
            "expected SecRule with target, operator, and actions",
            source,
            statement.start_line,
        )

    variables = _parse_variables(fields[1], source, statement.start_line)
    operator, operator_arg, negated = _parse_operator(
        _strip_outer_quotes(fields[2]), source, statement.start_line
    )
    actions = _parse_actions(
        _strip_outer_quotes(fields[3]), source, statement.start_line
    )

    rule_id: Optional[int] = None
    phase: Optional[int] = None
    transformations: List[str] = []
    disruptive_action: Optional[str] = None
    status: Optional[int] = None
    log: Optional[bool] = None
    msg: Optional[str] = None
    ctl_actions = {}

    for action in actions:
        name = action.name.lower()
        if name == "id":
            rule_id = _parse_integer_action(action, source, statement.start_line)
        elif name == "phase":
            phase = _parse_integer_action(action, source, statement.start_line)
        elif name == "status":
            status = _parse_integer_action(action, source, statement.start_line)
        elif name == "t" and action.value is not None:
            transformations.append(action.value)
        elif name in _DISRUPTIVE_ACTIONS:
            disruptive_action = name
        elif name == "log":
            log = True
        elif name == "nolog":
            log = False
        elif name == "msg":
            msg = action.value
        elif name == "ctl":
            if action.value is None or "=" not in action.value:
                raise SecRuleParseError(
                    "ctl action must use key=value",
                    source,
                    statement.start_line,
                )
            ctl_name, ctl_value = action.value.split("=", 1)
            ctl_actions[ctl_name] = ctl_value

    if rule_id is None:
        raise SecRuleParseError("missing id action", source, statement.start_line)

    return RuleSpec(
        rule_id=rule_id,
        variables=variables,
        operator=operator,
        operator_arg=operator_arg,
        operator_negated=negated,
        transformations=transformations,
        phase=phase,
        actions=actions,
        disruptive_action=disruptive_action,
        status=status,
        log=log,
        msg=msg,
        ctl_actions=ctl_actions,
        raw_text=statement.raw_text,
        source_line=statement.start_line,
        source_end_line=statement.end_line,
    )


def _parse_variables(
    expression: str, source: str, line: int
) -> List[TargetVariable]:
    variables = []
    for raw_variable in _split_delimited_aware(expression, "|", source, line):
        raw_variable = raw_variable.strip()
        if not raw_variable:
            raise SecRuleParseError("empty target variable", source, line)
        if ":" in raw_variable:
            collection, selector = raw_variable.split(":", 1)
            if not collection or not selector:
                raise SecRuleParseError("invalid target variable", source, line)
        else:
            collection, selector = raw_variable, None
        variables.append(
            TargetVariable(
                collection=collection,
                selector=selector,
                raw=raw_variable,
            )
        )
    return variables


def _parse_operator(
    expression: str, source: str, line: int
) -> Tuple[str, str, bool]:
    match = re.fullmatch(
        r"(?P<negated>!)?@(?P<name>[A-Za-z][A-Za-z0-9]*)(?:\s+(?P<arg>.*))?",
        expression,
        flags=re.DOTALL,
    )
    if match is None:
        raise SecRuleParseError("invalid operator expression", source, line)

    return (
        match.group("name"),
        match.group("arg") or "",
        match.group("negated") is not None,
    )


def _parse_actions(
    expression: str, source: str, line: int
) -> List[RuleAction]:
    actions = []
    for raw_action in _split_delimited_aware(expression, ",", source, line):
        raw_action = raw_action.strip()
        if not raw_action:
            raise SecRuleParseError("empty action", source, line)

        name, value = _partition_unquoted(raw_action, ":")
        name = name.strip()
        if not name:
            raise SecRuleParseError("action name is empty", source, line)

        parsed_value = None
        if value is not None:
            parsed_value = _strip_outer_quotes(value.strip())

        actions.append(RuleAction(name=name, value=parsed_value, raw=raw_action))

    return actions


def _parse_integer_action(
    action: RuleAction, source: str, line: int
) -> int:
    if action.value is None:
        raise SecRuleParseError(
            "{} action requires a value".format(action.name), source, line
        )
    try:
        return int(action.value)
    except ValueError as exc:
        raise SecRuleParseError(
            "{} action requires an integer".format(action.name), source, line
        ) from exc


def _split_whitespace_aware(text: str, source: str, line: int) -> List[str]:
    parts: List[str] = []
    buffer: List[str] = []
    quote: Optional[str] = None
    escaped = False

    for char in text:
        if escaped:
            buffer.append(char)
            escaped = False
            continue
        if char == "\\":
            buffer.append(char)
            escaped = True
            continue
        if quote is None and char in {"'", '"'}:
            quote = char
            buffer.append(char)
            continue
        if quote == char:
            quote = None
            buffer.append(char)
            continue
        if quote is None and char.isspace():
            if buffer:
                parts.append("".join(buffer))
                buffer = []
            continue
        buffer.append(char)

    if quote is not None:
        raise SecRuleParseError("unterminated quote", source, line)
    if buffer:
        parts.append("".join(buffer))
    return parts


def _split_delimited_aware(
    text: str, delimiter: str, source: str, line: int
) -> List[str]:
    parts: List[str] = []
    buffer: List[str] = []
    quote: Optional[str] = None
    escaped = False

    for char in text:
        if escaped:
            buffer.append(char)
            escaped = False
            continue
        if char == "\\":
            buffer.append(char)
            escaped = True
            continue
        if quote is None and char in {"'", '"'}:
            quote = char
            buffer.append(char)
            continue
        if quote == char:
            quote = None
            buffer.append(char)
            continue
        if quote is None and char == delimiter:
            parts.append("".join(buffer))
            buffer = []
            continue
        buffer.append(char)

    if quote is not None:
        raise SecRuleParseError("unterminated quote", source, line)
    parts.append("".join(buffer))
    return parts


def _partition_unquoted(text: str, delimiter: str) -> Tuple[str, Optional[str]]:
    quote: Optional[str] = None
    escaped = False

    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote is None and char in {"'", '"'}:
            quote = char
            continue
        if quote == char:
            quote = None
            continue
        if quote is None and char == delimiter:
            return text[:index], text[index + 1 :]

    return text, None


def _strip_outer_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value
