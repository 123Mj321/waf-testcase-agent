import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from testcase_gen.models import CaseSpec


MISSING_VALUE = "<missing>"
_COMPARISON_FIELDS = ("method", "path", "headers", "body", "expected_code")
_REQUIRED_TYPES = {"positive", "negative"}
_CaseKey = Tuple[int, str]
_MISSING = object()


class GoldFormatError(ValueError):
    pass


@dataclass(frozen=True)
class GoldDiff:
    rule_id: Optional[int]
    type: Optional[str]
    field: str
    expected: Any
    actual: Any
    message: str

    @property
    def case_id(self) -> str:
        if self.rule_id is None or self.type is None:
            return "<global>"
        return "rule-{}-{}".format(self.rule_id, self.type)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "type": self.type,
            "field": self.field,
            "expected": self.expected,
            "actual": self.actual,
            "message": self.message,
        }


@dataclass(frozen=True)
class GoldValidationResult:
    gold_count: int
    generated_count: int
    diffs: List[GoldDiff]

    @property
    def passed(self) -> bool:
        return not self.diffs


class GoldValidator:
    def validate(
        self,
        generated_cases: Iterable[CaseSpec],
        gold_cases: Sequence[Mapping[str, Any]],
    ) -> GoldValidationResult:
        generated = list(generated_cases)
        gold = list(gold_cases)
        diffs: List[GoldDiff] = []

        if len(generated) != len(gold):
            diffs.append(
                GoldDiff(
                    rule_id=None,
                    type=None,
                    field="case_count",
                    expected=len(gold),
                    actual=len(generated),
                    message="generated case count differs from gold",
                )
            )

        generated_index, generated_duplicates = self._index_generated(
            generated, diffs
        )
        gold_index, gold_duplicates = self._index_gold(gold, diffs)

        self._compare_coverage(generated_index, gold_index, diffs)
        self._compare_case_types("generated", generated_index, diffs)
        self._compare_case_types("gold", gold_index, diffs)

        generated_keys = set(generated_index)
        gold_keys = set(gold_index)

        for key in sorted(gold_keys - generated_keys):
            expected_case = self._gold_comparable(gold_index[key][0])
            diffs.append(
                GoldDiff(
                    rule_id=key[0],
                    type=key[1],
                    field="case",
                    expected=expected_case,
                    actual=MISSING_VALUE,
                    message="generated case is missing",
                )
            )

        for key in sorted(generated_keys - gold_keys):
            actual_case = self._generated_comparable(generated_index[key][0])
            diffs.append(
                GoldDiff(
                    rule_id=key[0],
                    type=key[1],
                    field="case",
                    expected=MISSING_VALUE,
                    actual=actual_case,
                    message="generated case is unexpected",
                )
            )

        ambiguous_keys = generated_duplicates | gold_duplicates
        comparable_keys = (generated_keys & gold_keys) - ambiguous_keys
        for key in sorted(comparable_keys):
            generated_case = generated_index[key][0]
            gold_case = gold_index[key][0]
            self._compare_fields(key, generated_case, gold_case, diffs)

        return GoldValidationResult(
            gold_count=len(gold),
            generated_count=len(generated),
            diffs=diffs,
        )

    @staticmethod
    def _index_generated(
        cases: Sequence[CaseSpec], diffs: List[GoldDiff]
    ) -> Tuple[Dict[_CaseKey, List[CaseSpec]], Set[_CaseKey]]:
        index: Dict[_CaseKey, List[CaseSpec]] = {}
        for case in cases:
            key = (case.rule_id, case.type.value)
            index.setdefault(key, []).append(case)

        duplicates = {key for key, values in index.items() if len(values) > 1}
        for key in sorted(duplicates):
            diffs.append(
                GoldDiff(
                    rule_id=key[0],
                    type=key[1],
                    field="duplicate_key",
                    expected=1,
                    actual=len(index[key]),
                    message="duplicate (rule_id, type) in generated cases",
                )
            )
        return index, duplicates

    @staticmethod
    def _index_gold(
        cases: Sequence[Mapping[str, Any]], diffs: List[GoldDiff]
    ) -> Tuple[Dict[_CaseKey, List[Mapping[str, Any]]], Set[_CaseKey]]:
        index: Dict[_CaseKey, List[Mapping[str, Any]]] = {}
        for position, case in enumerate(cases):
            if not isinstance(case, Mapping):
                diffs.append(
                    GoldDiff(
                        rule_id=None,
                        type=None,
                        field="gold_case",
                        expected="object",
                        actual=type(case).__name__,
                        message="gold item {} is not an object".format(position),
                    )
                )
                continue

            rule_id = case.get("rule_id", _MISSING)
            case_type = case.get("type", _MISSING)
            if rule_id is _MISSING:
                diffs.append(
                    GoldDiff(
                        rule_id=None,
                        type=str(case_type) if case_type is not _MISSING else None,
                        field="rule_id",
                        expected="present",
                        actual=MISSING_VALUE,
                        message="gold case is missing rule_id",
                    )
                )
            if case_type is _MISSING:
                diffs.append(
                    GoldDiff(
                        rule_id=rule_id if isinstance(rule_id, int) else None,
                        type=None,
                        field="type",
                        expected="present",
                        actual=MISSING_VALUE,
                        message="gold case is missing type",
                    )
                )
            if not isinstance(rule_id, int) or not isinstance(case_type, str):
                continue

            key = (rule_id, case_type)
            index.setdefault(key, []).append(case)

        duplicates = {key for key, values in index.items() if len(values) > 1}
        for key in sorted(duplicates):
            diffs.append(
                GoldDiff(
                    rule_id=key[0],
                    type=key[1],
                    field="duplicate_key",
                    expected=1,
                    actual=len(index[key]),
                    message="duplicate (rule_id, type) in gold cases",
                )
            )
        return index, duplicates

    @staticmethod
    def _compare_coverage(
        generated_index: Mapping[_CaseKey, Any],
        gold_index: Mapping[_CaseKey, Any],
        diffs: List[GoldDiff],
    ) -> None:
        generated_rule_ids = sorted({key[0] for key in generated_index})
        gold_rule_ids = sorted({key[0] for key in gold_index})
        if generated_rule_ids != gold_rule_ids:
            diffs.append(
                GoldDiff(
                    rule_id=None,
                    type=None,
                    field="rule_id_coverage",
                    expected=gold_rule_ids,
                    actual=generated_rule_ids,
                    message="generated rule_id coverage differs from gold",
                )
            )

    @staticmethod
    def _compare_case_types(
        source: str,
        index: Mapping[_CaseKey, Any],
        diffs: List[GoldDiff],
    ) -> None:
        rule_ids = sorted({key[0] for key in index})
        for rule_id in rule_ids:
            case_types = {key[1] for key in index if key[0] == rule_id}
            if case_types != _REQUIRED_TYPES:
                diffs.append(
                    GoldDiff(
                        rule_id=rule_id,
                        type=None,
                        field="{}_case_types".format(source),
                        expected=sorted(_REQUIRED_TYPES),
                        actual=sorted(case_types),
                        message=(
                            "{} cases must contain one positive and one negative"
                        ).format(source),
                    )
                )

    @staticmethod
    def _compare_fields(
        key: _CaseKey,
        generated_case: CaseSpec,
        gold_case: Mapping[str, Any],
        diffs: List[GoldDiff],
    ) -> None:
        generated_values = GoldValidator._generated_comparable(generated_case)
        for field in _COMPARISON_FIELDS:
            expected = gold_case.get(field, _MISSING)
            actual = generated_values[field]
            if expected is _MISSING or expected != actual:
                diffs.append(
                    GoldDiff(
                        rule_id=key[0],
                        type=key[1],
                        field=field,
                        expected=(
                            MISSING_VALUE if expected is _MISSING else expected
                        ),
                        actual=actual,
                        message="generated field differs from gold",
                    )
                )

    @staticmethod
    def _generated_comparable(case: CaseSpec) -> Dict[str, Any]:
        return {
            "method": case.method,
            "path": case.path,
            "headers": dict(case.headers),
            "body": case.body,
            "expected_code": case.expected_code,
        }

    @staticmethod
    def _gold_comparable(case: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            field: case.get(field, MISSING_VALUE)
            for field in _COMPARISON_FIELDS
        }


def load_gold(path: Path) -> List[Mapping[str, Any]]:
    source_path = Path(path)
    with source_path.open("r", encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, list):
        raise GoldFormatError("gold root must be a JSON array")
    return data


def validate_gold(
    generated_cases: Iterable[CaseSpec],
    gold_cases: Sequence[Mapping[str, Any]],
) -> GoldValidationResult:
    return GoldValidator().validate(generated_cases, gold_cases)


def validate_gold_file(
    generated_cases: Iterable[CaseSpec], path: Path
) -> GoldValidationResult:
    return validate_gold(generated_cases, load_gold(path))
