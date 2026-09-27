"""LLM candidate generation.

Pipeline position::

    RuleSpec
      -> LLM Prompt Builder      (prompt.py)
      -> LLM Candidate Generator (this module + a provider)
      -> Candidate Parser / JSON Schema Validation (validation.py)
      -> Rule-aware Deterministic Validator       (validation.py)
      -> CaseSpec

The LLM never decides the expected status code and never sees ``gold.json``.
Candidates that do not match the rule semantics are rejected instead of being
executed.  When no provider is configured the expansion degrades to the
deterministic baseline generator and the degradation is reported.
"""

import os
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from time import perf_counter
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)

import httpx

from testcase_gen.models import CaseSpec, CaseType, RuleSpec

from .audit import AIUsageLog, LLMGenerationRecord, utc_timestamp
from .prompt import PROMPT_VERSION, LLMPrompt, build_rule_prompt
from .validation import (
    CandidateDecision,
    RuleAwareCandidateValidator,
)


DEFAULT_API_KEY_ENV = "OPENAI_API_KEY"
DEFAULT_MODEL = "gpt-4o-mini"
# reasoning models need far more than a few seconds per rule
DEFAULT_LLM_TIMEOUT = 120.0


class LLMError(Exception):
    """Base class for every LLM related failure."""


class LLMConfigurationError(LLMError):
    """The LLM configuration cannot be resolved."""


class LLMProviderError(LLMError):
    """The provider call failed."""


class LLMTimeoutError(LLMProviderError):
    """The provider call timed out."""


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    aliases: Tuple[str, ...]
    default_base_url: str
    default_model: str
    requires_api_key: bool


_PROVIDER_SPECS: Tuple[ProviderSpec, ...] = (
    ProviderSpec(
        name="openai",
        aliases=("openai", "openai-compatible"),
        default_base_url="https://api.openai.com/v1",
        default_model=DEFAULT_MODEL,
        requires_api_key=True,
    ),
    ProviderSpec(
        name="ollama",
        aliases=("ollama",),
        default_base_url="http://127.0.0.1:11434/v1",
        default_model="llama3.1",
        requires_api_key=False,
    ),
)

_DISABLED_ALIASES = frozenset({"none", "off", "disabled", ""})
_AUTO_ALIAS = "auto"


def provider_choices() -> Tuple[str, ...]:
    """Provider names accepted on the command line."""
    names = [_AUTO_ALIAS, "none"]
    for spec in _PROVIDER_SPECS:
        names.append(spec.name)
    return tuple(names)


def _lookup_provider(name: str) -> Optional[ProviderSpec]:
    lowered = name.strip().lower()
    for spec in _PROVIDER_SPECS:
        if lowered in spec.aliases:
            return spec
    return None


@dataclass(frozen=True)
class ResolvedLLMConfig:
    provider_name: Optional[str]
    model: Optional[str]
    base_url: Optional[str]
    api_key: Optional[str]
    reason: Optional[str] = None


@dataclass(frozen=True)
class LLMConfig:
    """Configuration for the LLM candidate generator."""

    provider: str = _AUTO_ALIAS
    model: Optional[str] = None
    base_url: Optional[str] = None
    api_key_env: str = DEFAULT_API_KEY_ENV
    max_candidates: int = 8
    timeout: float = DEFAULT_LLM_TIMEOUT
    temperature: float = 0.2
    # None means "do not send max_tokens": reasoning models otherwise spend the
    # whole budget on reasoning tokens and return an empty content string.
    max_tokens: Optional[int] = None
    json_mode: bool = True
    save_raw: bool = False
    disabled: bool = False

    def resolve(
        self, environ: Optional[Mapping[str, str]] = None
    ) -> ResolvedLLMConfig:
        """Resolve provider/model/credentials; ``provider_name=None`` = disabled."""
        environment = os.environ if environ is None else environ

        if self.disabled:
            return ResolvedLLMConfig(
                None, None, None, None, "llm generation is disabled"
            )

        name = (self.provider or _AUTO_ALIAS).strip().lower()
        if name in _DISABLED_ALIASES:
            return ResolvedLLMConfig(
                None,
                None,
                None,
                None,
                "llm provider is {!r}".format(name),
            )

        if name == _AUTO_ALIAS:
            api_key = (environment.get(self.api_key_env) or "").strip()
            if not api_key:
                return ResolvedLLMConfig(
                    None,
                    None,
                    None,
                    None,
                    "llm not configured: environment variable {} is empty".format(
                        self.api_key_env
                    ),
                )
            spec = _PROVIDER_SPECS[0]
        else:
            spec = _lookup_provider(name)
            if spec is None:
                raise LLMConfigurationError(
                    "unknown llm provider {!r}; known providers: {}".format(
                        name, ", ".join(provider_choices())
                    )
                )
            api_key = (environment.get(self.api_key_env) or "").strip()
            if spec.requires_api_key and not api_key:
                return ResolvedLLMConfig(
                    None,
                    None,
                    None,
                    None,
                    "llm provider {!r} requires {} to be set".format(
                        spec.name, self.api_key_env
                    ),
                )

        return ResolvedLLMConfig(
            provider_name=spec.name,
            model=self.model or spec.default_model,
            base_url=self.base_url or spec.default_base_url,
            api_key=api_key if spec.requires_api_key else None,
        )

    def is_available(
        self, environ: Optional[Mapping[str, str]] = None
    ) -> bool:
        try:
            return self.resolve(environ).provider_name is not None
        except LLMError:
            return False

    @classmethod
    def from_args(cls, args: Any) -> "LLMConfig":
        return cls(
            provider=getattr(args, "llm_provider", _AUTO_ALIAS),
            model=getattr(args, "llm_model", None),
            base_url=getattr(args, "llm_base_url", None),
            api_key_env=getattr(args, "llm_api_key_env", DEFAULT_API_KEY_ENV),
            max_candidates=getattr(args, "llm_max_candidates", 8),
            timeout=getattr(args, "llm_timeout", DEFAULT_LLM_TIMEOUT),
            temperature=getattr(args, "llm_temperature", 0.2),
            max_tokens=getattr(args, "llm_max_tokens", None),
            save_raw=bool(getattr(args, "llm_save_raw", False)),
            disabled=getattr(args, "generation_mode", "hybrid") == "baseline",
        )


def _extract_message_content(message: Any) -> Optional[str]:
    """Read reply text from ``message.content`` (string or blocks)."""
    content = message.get("content") if isinstance(message, Mapping) else None
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: List[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, Mapping):
                text = block.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "".join(parts)
    return None


@dataclass(frozen=True)
class LLMCompletion:
    """Normalized provider response."""

    text: str
    model: Optional[str]
    provider: Optional[str]
    token_usage: Dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0
    raw: Optional[Mapping[str, Any]] = None


class OpenAICompatibleProvider:
    """Chat-completions client for OpenAI compatible HTTP endpoints."""

    provider_name = "openai"
    simulated = False

    def __init__(
        self,
        model: str,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: float = DEFAULT_LLM_TIMEOUT,
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
        json_mode: bool = True,
        provider_name: Optional[str] = None,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        if provider_name:
            self.provider_name = provider_name
        self._api_key = api_key
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._json_mode = json_mode
        self._client = httpx.Client(
            timeout=timeout, transport=transport, trust_env=False
        )

    def complete(
        self,
        messages: Sequence[Mapping[str, str]],
        context: Optional[Mapping[str, Any]] = None,
    ) -> LLMCompletion:
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": [dict(message) for message in messages],
            "temperature": self._temperature,
            "stream": False,
        }
        if self._max_tokens is not None:
            payload["max_tokens"] = self._max_tokens
        if self._json_mode:
            payload["response_format"] = {"type": "json_object"}

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = "Bearer {}".format(self._api_key)

        started_at = perf_counter()
        try:
            response = self._client.post(
                "{}/chat/completions".format(self.base_url),
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
        except httpx.TimeoutException as exc:
            raise LLMTimeoutError(
                "{} call timed out: {}".format(self.provider_name, exc)
            ) from exc
        except httpx.HTTPError as exc:
            raise LLMProviderError(
                "{} call failed: {}".format(self.provider_name, exc)
            ) from exc
        latency_ms = (perf_counter() - started_at) * 1000

        try:
            data = response.json()
        except ValueError as exc:
            raise LLMProviderError(
                "{} returned a non-JSON response".format(self.provider_name)
            ) from exc

        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise LLMProviderError(
                "{} response has no choices".format(self.provider_name)
            )
        message = choices[0].get("message") or {}
        usage = data.get("usage")
        if not isinstance(usage, Mapping):
            usage = {}

        text = _extract_message_content(message)
        if text is None:
            raise LLMProviderError(
                "{} response has no message content".format(self.provider_name)
            )
        if not text.strip():
            raise LLMProviderError(
                "{} returned an empty message content (finish_reason={!r}, "
                "reasoning_tokens={}); reasoning models can spend the whole "
                "output budget on reasoning - retry without --llm-max-tokens "
                "or with a larger value".format(
                    self.provider_name,
                    choices[0].get("finish_reason"),
                    (usage.get("completion_tokens_details") or {}).get(
                        "reasoning_tokens"
                    ),
                )
            )
        return LLMCompletion(
            text=text,
            model=data.get("model") or self.model,
            provider=self.provider_name,
            token_usage=dict(usage) if isinstance(usage, Mapping) else {},
            latency_ms=latency_ms,
            raw=data,
        )

    def close(self) -> None:
        self._client.close()


class MockLLMProvider:
    """Scripted test double.

    It never fabricates output on its own: every response must be provided by
    the caller (``responses`` mapping / callable or a single literal string).
    Used by the unit tests only; ``simulated`` is ``True`` so every audit
    record is marked accordingly.
    """

    provider_name = "mock"
    simulated = True

    def __init__(
        self,
        responses: Any = None,
        model: str = "mock-model",
        token_usage: Optional[Mapping[str, Any]] = None,
        latency_ms: float = 1.0,
        error: Optional[Any] = None,
        calls: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self.model = model
        self._responses = responses
        self._token_usage = dict(token_usage or {})
        self._latency_ms = latency_ms
        self._error = error
        self.calls = calls if calls is not None else []

    def complete(
        self,
        messages: Sequence[Mapping[str, str]],
        context: Optional[Mapping[str, Any]] = None,
    ) -> LLMCompletion:
        rule_id = None if context is None else context.get("rule_id")
        self.calls.append(
            {
                "rule_id": rule_id,
                "messages": [dict(message) for message in messages],
            }
        )

        if isinstance(self._error, BaseException):
            raise self._error
        if isinstance(self._error, str):
            raise LLMProviderError(self._error)

        if callable(self._responses):
            text = self._responses(rule_id, messages)
        elif isinstance(self._responses, Mapping):
            text = self._responses.get(rule_id)
        else:
            text = self._responses

        if text is None:
            raise LLMProviderError(
                "mock provider has no scripted response for rule {!r}".format(
                    rule_id
                )
            )

        return LLMCompletion(
            text=str(text),
            model=self.model,
            provider=self.provider_name,
            token_usage=dict(self._token_usage),
            latency_ms=self._latency_ms,
            raw={"mock": True},
        )

    def close(self) -> None:
        return None


def build_provider(
    resolved: ResolvedLLMConfig,
    config: LLMConfig,
    transport: Optional[httpx.BaseTransport] = None,
) -> OpenAICompatibleProvider:
    if resolved.provider_name is None or not resolved.base_url:
        raise LLMConfigurationError("llm provider is not configured")
    return OpenAICompatibleProvider(
        model=resolved.model or DEFAULT_MODEL,
        base_url=resolved.base_url,
        api_key=resolved.api_key,
        timeout=config.timeout,
        temperature=config.temperature,
        max_tokens=config.max_tokens,
        json_mode=config.json_mode,
        provider_name=resolved.provider_name,
        transport=transport,
    )


class GenerationMode(str, Enum):
    BASELINE = "baseline"
    LLM = "llm"
    HYBRID = "hybrid"


@dataclass
class LLMExpansionResult:
    """Outcome of the LLM expansion stage."""

    status: str = "disabled"
    provider: Optional[str] = None
    model: Optional[str] = None
    prompt_version: str = PROMPT_VERSION
    cases: List[CaseSpec] = field(default_factory=list)
    decisions: List[CandidateDecision] = field(default_factory=list)
    records: List[LLMGenerationRecord] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    candidate_count: int = 0
    accepted_count: int = 0
    rejected_count: int = 0
    token_usage: Dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0
    degraded: bool = False
    degrade_reason: Optional[str] = None
    simulated: bool = False

    @property
    def rejection_reasons(self) -> List[str]:
        return [
            decision.rejection_reason
            for decision in self.decisions
            if not decision.accepted and decision.rejection_reason
        ]

    @property
    def rejection_summary(self) -> Dict[str, int]:
        return dict(Counter(self.rejection_reasons))

    def to_stats(self) -> Any:
        """Convert into the report model (imported lazily to avoid cycles)."""
        from testcase_gen.report.models import LLMGenerationStats

        return LLMGenerationStats(
            enabled=self.provider is not None,
            provider=self.provider,
            model=self.model,
            prompt_version=self.prompt_version,
            status=self.status,
            candidate_count=self.candidate_count,
            accepted_count=self.accepted_count,
            rejected_count=self.rejected_count,
            errors=list(self.errors),
            rejection_reasons=self.rejection_reasons,
            rejection_summary=self.rejection_summary,
            degraded=self.degraded,
            degrade_reason=self.degrade_reason,
            latency_ms=self.latency_ms,
            token_usage=dict(self.token_usage),
            simulated=self.simulated,
        )


class LLMTestCaseGenerator:
    """Ask the LLM for candidates and validate them against the rules."""

    def __init__(
        self,
        provider: Any,
        success_status: int = 200,
        max_candidates: int = 8,
        prompt_version: str = PROMPT_VERSION,
        audit_log: Optional[AIUsageLog] = None,
    ) -> None:
        self._provider = provider
        self._success_status = success_status
        self._max_candidates = max_candidates
        self._prompt_version = prompt_version
        self._audit_log = audit_log

    def expand(
        self, rules: Iterable[RuleSpec], baseline_cases: Sequence[CaseSpec] = ()
    ) -> LLMExpansionResult:
        rule_list = list(rules)
        provider_name = getattr(self._provider, "provider_name", "unknown")
        model = getattr(self._provider, "model", None)
        result = LLMExpansionResult(
            status="ok",
            provider=provider_name,
            model=model,
            prompt_version=self._prompt_version,
            simulated=bool(getattr(self._provider, "simulated", False)),
        )

        validator = RuleAwareCandidateValidator(
            rule_list,
            success_status=self._success_status,
            provider=provider_name,
            model=model,
            prompt_version=self._prompt_version,
        )
        validator.seed(baseline_cases)

        for rule in rule_list:
            prompt = build_rule_prompt(
                rule,
                max_candidates=self._max_candidates,
                version=self._prompt_version,
            )
            record = LLMGenerationRecord(
                timestamp=utc_timestamp(),
                status="ok",
                provider=provider_name,
                model=model,
                prompt_version=self._prompt_version,
                rule_id=rule.rule_id,
                simulated=result.simulated,
            )

            started_at = perf_counter()
            raw_response: Optional[str] = None
            try:
                completion = self._provider.complete(
                    prompt.messages(),
                    context={
                        "rule_id": rule.rule_id,
                        "prompt_version": prompt.version,
                    },
                )
            except LLMError as exc:
                record.status = "error"
                record.latency_ms = (perf_counter() - started_at) * 1000
                record.error = "{}: {}".format(type(exc).__name__, exc)
                result.errors.append(
                    "rule {}: {}".format(rule.rule_id, record.error)
                )
                self._log(record, prompt, None)
                result.records.append(record)
                continue

            record.latency_ms = (perf_counter() - started_at) * 1000
            raw_response = completion.text
            if completion.model:
                record.model = completion.model
            record.token_usage = dict(completion.token_usage or {})

            decisions = validator.validate(completion.text, rule)
            result.decisions.extend(decisions)

            malformed = (
                len(decisions) == 1
                and decisions[0].category == "malformed"
                and not decisions[0].accepted
            )
            if malformed:
                record.status = "malformed"
                record.error = decisions[0].rejection_reason
                result.errors.append(
                    "rule {}: {}".format(rule.rule_id, record.error)
                )
                self._log(record, prompt, raw_response)
                result.records.append(record)
                continue

            accepted = [
                decision for decision in decisions if decision.accepted
            ]
            rejected = [
                decision for decision in decisions if not decision.accepted
            ]
            record.candidate_count = len(decisions)
            record.accepted_count = len(accepted)
            record.rejected_count = len(rejected)
            record.rejection_reasons = [
                reason
                for reason in (
                    decision.rejection_reason for decision in rejected
                )
                if reason
            ]
            record.rejection_summary = dict(Counter(record.rejection_reasons))

            result.cases.extend(decision.case for decision in accepted)
            result.candidate_count += len(decisions)
            result.accepted_count += len(accepted)
            result.rejected_count += len(rejected)
            result.latency_ms += record.latency_ms
            _merge_usage(result.token_usage, record.token_usage)

            self._log(record, prompt, raw_response)
            result.records.append(record)

        if result.errors:
            result.status = "partial" if result.cases else "error"
        self._finalize_status(result)
        return result

    @staticmethod
    def _finalize_status(result: LLMExpansionResult) -> None:
        if not result.cases and result.status == "ok":
            result.status = "empty"
            result.degraded = True
            result.degrade_reason = (
                result.degrade_reason
                or "no LLM candidate passed rule-aware validation"
            )

    def _log(
        self,
        record: LLMGenerationRecord,
        prompt: Optional[LLMPrompt],
        raw_response: Optional[str],
    ) -> None:
        if self._audit_log is None:
            return
        self._audit_log.record(
            record,
            raw_prompt=None if prompt is None else prompt.to_text(),
            raw_response=raw_response,
        )


def _merge_usage(total: Dict[str, Any], usage: Mapping[str, Any]) -> None:
    for key, value in usage.items():
        if isinstance(value, (int, float)):
            total[key] = total.get(key, 0) + value
        else:
            total.setdefault(key, value)


def _disabled_result(
    config: LLMConfig, reason: Optional[str]
) -> LLMExpansionResult:
    # An explicit baseline run is not a degradation, a missing provider is.
    return LLMExpansionResult(
        status="disabled",
        degraded=not config.disabled,
        degrade_reason=reason,
        prompt_version=PROMPT_VERSION,
        model=None,
    )


def _log_skipped(
    audit_log: Optional[AIUsageLog],
    config: LLMConfig,
    reason: Optional[str],
) -> None:
    if audit_log is None:
        return
    audit_log.record(
        LLMGenerationRecord(
            timestamp=utc_timestamp(),
            status="skipped",
            provider=None,
            model=None,
            prompt_version=PROMPT_VERSION,
            rule_id=None,
            error=reason,
        )
    )


def expand_with_llm(
    rules: Iterable[RuleSpec],
    baseline_cases: Sequence[CaseSpec] = (),
    config: Optional[LLMConfig] = None,
    audit_log: Optional[AIUsageLog] = None,
    environ: Optional[Mapping[str, str]] = None,
    success_status: int = 200,
    provider_factory: Optional[Callable[[LLMConfig], Any]] = None,
) -> LLMExpansionResult:
    """Run the LLM expansion stage, degrading to baseline when unavailable."""
    rule_list = list(rules)
    config = config or LLMConfig()

    if not rule_list:
        result = _disabled_result(config, "no rules available for LLM expansion")
        _log_skipped(audit_log, config, result.degrade_reason)
        return result

    provider: Any = None
    reason: Optional[str] = None
    if provider_factory is not None:
        provider = provider_factory(config)
        if provider is None:
            reason = "llm provider factory returned no provider"
    else:
        try:
            resolved = config.resolve(environ)
        except LLMError as exc:
            resolved = None
            reason = str(exc)
        if resolved is not None and resolved.provider_name:
            provider = build_provider(resolved, config)
        elif reason is None:
            reason = resolved.reason if resolved is not None else None

    if provider is None:
        result = _disabled_result(config, reason)
        _log_skipped(audit_log, config, reason)
        return result

    generator = LLMTestCaseGenerator(
        provider=provider,
        success_status=success_status,
        max_candidates=config.max_candidates,
        audit_log=audit_log,
    )
    try:
        return generator.expand(rule_list, baseline_cases)
    finally:
        close = getattr(provider, "close", None)
        if callable(close):
            close()


def assemble_cases(
    mode: Any,
    baseline_cases: Sequence[CaseSpec],
    llm_cases: Sequence[CaseSpec],
) -> List[CaseSpec]:
    """Combine deterministic baseline cases and accepted LLM cases."""
    raw_mode = mode.value if isinstance(mode, GenerationMode) else str(mode)
    normalized = GenerationMode(raw_mode.strip().lower())
    baseline = list(baseline_cases)
    if normalized == GenerationMode.BASELINE:
        return baseline
    if normalized == GenerationMode.HYBRID:
        return baseline + list(llm_cases)

    llm_by_key: Dict[Tuple[int, CaseType], List[CaseSpec]] = {}
    for case in llm_cases:
        llm_by_key.setdefault((case.rule_id, case.type), []).append(case)
    baseline_by_key = {
        (case.rule_id, case.type): case for case in baseline
    }

    keys: List[Tuple[int, CaseType]] = []
    for case in list(baseline) + list(llm_cases):
        key = (case.rule_id, case.type)
        if key not in keys:
            keys.append(key)

    combined: List[CaseSpec] = []
    for key in keys:
        group = llm_by_key.get(key)
        if group:
            combined.extend(group)
        elif key in baseline_by_key:
            combined.append(baseline_by_key[key])
    return combined
