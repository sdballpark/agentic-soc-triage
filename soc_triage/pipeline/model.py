"""Model access for the decision node.

One protocol, two implementations. The OpenAI-compatible client talks to
whatever serves the model on the host -- llama.cpp's server, Ollama, or vLLM
all speak the same wire format, so switching backends is a base URL change
rather than a code change. The stub returns a fixed decision and needs no
network, which is what lets CI run the graph without a GPU.

The model is required to answer in JSON matching ModelDecision. That is not
cosmetic: a triage decision that cannot be parsed reliably cannot be scored
reliably, and free-text answers would put a fuzzy string-matching layer
between the model and every metric in the eval. Parse failures get exactly
one repair attempt, then become an error the pipeline handles.

Temperature defaults to 0. An eval suite whose numbers move between identical
runs is not a regression suite.
"""

from __future__ import annotations

import json
import os
import re
from typing import Optional, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from soc_triage.disposition import Disposition

DEFAULT_BASE_URL = os.environ.get("SOC_TRIAGE_MODEL_BASE_URL", "http://localhost:8080/v1")
DEFAULT_MODEL = os.environ.get("SOC_TRIAGE_MODEL", "local-model")
DEFAULT_API_KEY = os.environ.get("SOC_TRIAGE_API_KEY", "not-needed")
DEFAULT_TIMEOUT = float(os.environ.get("SOC_TRIAGE_MODEL_TIMEOUT", "120"))


class ModelError(Exception):
    """The model could not be reached or could not produce a usable answer."""


class CitationOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    query: str
    fact: str


class ModelDecision(BaseModel):
    """The contract the model must satisfy.

    extra="forbid" is deliberate. A model that invents an extra field is
    usually a model that has drifted from the prompt, and silently ignoring
    that would hide prompt regressions.
    """

    model_config = ConfigDict(extra="forbid")

    disposition: Disposition
    confidence: int = Field(ge=0, le=100)
    summary: str = Field(min_length=1)
    reasoning: str = Field(min_length=1)
    recommended_action: str = Field(min_length=1)
    citations: list[CitationOut] = Field(default_factory=list)
    suspected_injection: bool = False
    injection_note: Optional[str] = None


class TriageModel(Protocol):
    name: str

    def decide(self, system_prompt: str, user_prompt: str) -> ModelDecision: ...


_FENCE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.MULTILINE)


def extract_json(text: str) -> dict:
    """Pull a JSON object out of a model response.

    Models wrap JSON in prose or code fences regardless of instructions. This
    strips fences and falls back to the outermost brace pair. It does not try
    to repair malformed JSON -- that is the repair retry's job, and silently
    patching bad output would mask a prompt that is not working.
    """
    cleaned = _FENCE.sub("", text).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end <= start:
        raise ModelError(f"no JSON object in model response: {text[:200]!r}")
    try:
        return json.loads(cleaned[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ModelError(f"unparseable JSON in model response: {exc}") from exc


class OpenAICompatibleModel:
    """Any server speaking the OpenAI chat completions format.

    Not a dependency on OpenAI. llama.cpp, Ollama, and vLLM all expose this
    interface, so the model runs on the host GPU while the pipeline stays
    portable. The container never needs CUDA.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        model: str = DEFAULT_MODEL,
        api_key: str = DEFAULT_API_KEY,
        temperature: float = 0.0,
        timeout: float = DEFAULT_TIMEOUT,
        max_tokens: int = 1200,
    ) -> None:
        from openai import OpenAI

        self._client = OpenAI(base_url=base_url, api_key=api_key, timeout=timeout)
        self._model = model
        self._temperature = temperature
        self._max_tokens = max_tokens
        self.name = model

    def _complete(self, messages: list[dict]) -> str:
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=messages,
                temperature=self._temperature,
                max_tokens=self._max_tokens,
            )
        except Exception as exc:  # transport, auth, server errors
            raise ModelError(f"model call failed: {type(exc).__name__}: {exc}") from exc

        content = response.choices[0].message.content
        if not content:
            raise ModelError("model returned empty content")
        return content

    def decide(self, system_prompt: str, user_prompt: str) -> ModelDecision:
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        raw = self._complete(messages)

        try:
            return ModelDecision.model_validate(extract_json(raw))
        except (ModelError, ValidationError) as first_error:
            # One repair attempt. The model sees its own output and the
            # specific complaint, which works far better than reasking.
            messages += [
                {"role": "assistant", "content": raw},
                {
                    "role": "user",
                    "content": (
                        "That response was not valid. Error:\n"
                        f"{first_error}\n\n"
                        "Reply with ONLY a JSON object matching the required "
                        "schema. No prose, no code fences."
                    ),
                },
            ]
            repaired = self._complete(messages)
            try:
                return ModelDecision.model_validate(extract_json(repaired))
            except (ModelError, ValidationError) as second_error:
                raise ModelError(
                    f"model output invalid after repair attempt: {second_error}"
                ) from second_error


class StubModel:
    """A fixed decision, for wiring tests and offline CI.

    This is NOT a baseline to compare accuracy against. It ignores the alert
    entirely. Its only job is to prove the graph runs end to end without a
    model server.
    """

    def __init__(
        self,
        decision: Optional[ModelDecision] = None,
        fail: bool = False,
        name: str = "stub-model",
    ) -> None:
        self.name = name
        self._fail = fail
        self._decision = decision or ModelDecision(
            disposition=Disposition.ABSTAIN,
            confidence=0,
            summary="Stub model; no analysis performed.",
            reasoning="This decision comes from a fixture, not from reasoning.",
            recommended_action="Route to an analyst.",
        )
        self.calls: list[tuple[str, str]] = []

    def decide(self, system_prompt: str, user_prompt: str) -> ModelDecision:
        self.calls.append((system_prompt, user_prompt))
        if self._fail:
            raise ModelError("stub model configured to fail")
        return self._decision
