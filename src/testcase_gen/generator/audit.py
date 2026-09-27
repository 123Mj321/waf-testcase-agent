"""Automatic AI generation audit log.

Every LLM generation attempt is recorded without any manual step.  A record
contains the timestamp, provider, model, prompt version, rule id, candidate /
accepted / rejected counts, rejection reasons, token usage (when the provider
returns it) and the latency.

Raw prompt / response capture is optional (``save_raw``).  It is off by default
and any configured secret is redacted before anything is written to disk.
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

REDACTED = "***REDACTED***"


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


@dataclass
class LLMGenerationRecord:
    """One audit entry per LLM generation attempt."""

    timestamp: str
    status: str
    provider: Optional[str]
    model: Optional[str]
    prompt_version: str
    rule_id: Optional[int]
    candidate_count: int = 0
    accepted_count: int = 0
    rejected_count: int = 0
    rejection_reasons: List[str] = field(default_factory=list)
    rejection_summary: Dict[str, int] = field(default_factory=dict)
    token_usage: Dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0
    error: Optional[str] = None
    simulated: bool = False
    prompt_chars: int = 0
    response_chars: int = 0
    prompt_sha256: Optional[str] = None
    response_sha256: Optional[str] = None
    raw_prompt_path: Optional[str] = None
    raw_response_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "status": self.status,
            "provider": self.provider,
            "model": self.model,
            "prompt_version": self.prompt_version,
            "rule_id": self.rule_id,
            "candidate_count": self.candidate_count,
            "accepted_count": self.accepted_count,
            "rejected_count": self.rejected_count,
            "rejection_reasons": list(self.rejection_reasons),
            "rejection_summary": dict(self.rejection_summary),
            "token_usage": dict(self.token_usage),
            "latency_ms": round(self.latency_ms, 3),
            "error": self.error,
            "simulated": self.simulated,
            "prompt_chars": self.prompt_chars,
            "response_chars": self.response_chars,
            "prompt_sha256": self.prompt_sha256,
            "response_sha256": self.response_sha256,
            "raw_prompt_path": self.raw_prompt_path,
            "raw_response_path": self.raw_response_path,
        }


class AIUsageLog:
    """Append-only JSONL audit log; also keeps the records in memory."""

    def __init__(
        self,
        path: Optional[Path] = None,
        raw_dir: Optional[Path] = None,
        save_raw: bool = False,
        redact: Sequence[str] = (),
    ) -> None:
        self.path = None if path is None else Path(path)
        self.raw_dir = None if raw_dir is None else Path(raw_dir)
        self.save_raw = bool(save_raw)
        self.redact = [value for value in redact if value]
        self._records: List[LLMGenerationRecord] = []

    @property
    def records(self) -> List[LLMGenerationRecord]:
        return list(self._records)

    def record(
        self,
        record: LLMGenerationRecord,
        raw_prompt: Optional[str] = None,
        raw_response: Optional[str] = None,
    ) -> LLMGenerationRecord:
        """Store one record.  Never raises: auditing must not break generation."""
        if raw_prompt is not None:
            record.prompt_chars = len(raw_prompt)
            record.prompt_sha256 = _sha256(raw_prompt)
        if raw_response is not None:
            record.response_chars = len(raw_response)
            record.response_sha256 = _sha256(raw_response)

        if self.save_raw:
            record.raw_prompt_path = self._write_raw(
                "prompt", record, raw_prompt
            )
            record.raw_response_path = self._write_raw(
                "response", record, raw_response
            )

        self._records.append(record)
        self._append(record)
        return record

    def to_json(self) -> str:
        return "\n".join(
            json.dumps(
                record.to_dict(), ensure_ascii=False, sort_keys=True
            )
            for record in self._records
        )

    def _append(self, record: LLMGenerationRecord) -> None:
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(
                    json.dumps(
                        record.to_dict(), ensure_ascii=False, sort_keys=True
                    )
                    + "\n"
                )
        except OSError:
            return

    def _write_raw(
        self, kind: str, record: LLMGenerationRecord, text: Optional[str]
    ) -> Optional[str]:
        if text is None or self.raw_dir is None:
            return None
        safe_timestamp = record.timestamp.replace(":", "-")
        rule = "global" if record.rule_id is None else record.rule_id
        name = "{}-{}-{}-{}.txt".format(
            safe_timestamp, kind, rule, record.status
        )
        try:
            self.raw_dir.mkdir(parents=True, exist_ok=True)
            target = self.raw_dir / name
            target.write_text(self._redact(text), encoding="utf-8")
            return str(target)
        except OSError:
            return None

    def _redact(self, text: str) -> str:
        redacted = text
        for secret in self.redact:
            redacted = redacted.replace(secret, REDACTED)
        return redacted


def load_usage_log(path: Path) -> List[Dict[str, Any]]:
    """Read a JSONL audit log back (used by tests and manual inspection)."""
    source = Path(path)
    if not source.is_file():
        return []
    entries: List[Dict[str, Any]] = []
    for line in source.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        entries.append(json.loads(line))
    return entries
