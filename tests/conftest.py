"""Shared pytest fixtures.

The whole unit test suite must run offline.  An autouse fixture removes the
environment variables that would otherwise make the CLI resolve a real LLM
provider, so tests never trigger network calls.
"""

import pytest

from testcase_gen.generator.llm import DEFAULT_API_KEY_ENV

_LLM_ENVIRONMENT_VARIABLES = (
    DEFAULT_API_KEY_ENV,
    "OPENAI_API_KEY",
    "LLM_API_KEY",
    "ANTHROPIC_API_KEY",
)


@pytest.fixture(autouse=True)
def offline_llm_environment(monkeypatch):
    for name in _LLM_ENVIRONMENT_VARIABLES:
        monkeypatch.delenv(name, raising=False)
