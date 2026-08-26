"""HTTP ingress.

One POST route that takes an alert and returns a case artifact. That is the
shape a SOAR platform calls: Tines, Logic Apps, and ServiceNow all issue an
HTTP request with a JSON body and expect JSON back.

This is the honest answer to the Tines line in the job description. The
orchestration here is LangGraph, not Tines, but the pipeline is a webhook, so
it drops behind either without modification. Claiming Tines experience would
be false; building the contract Tines calls is not.

The request body validates against the same Alert model the corpus uses, so
a malformed alert is rejected at the boundary with a field-level error rather
than producing a confident disposition from garbage.

Run it:
    uvicorn soc_triage.api.app:app --host 0.0.0.0 --port 8000

Configuration comes from the environment, the same variables the eval CLI
uses, so the service and the harness cannot drift apart in how they reach
the model.
"""

from __future__ import annotations

import os
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

from soc_triage.corpus.alert import Alert
from soc_triage.enrichment.base import ResilientEnrichment, RetryPolicy
from soc_triage.enrichment.stubs import LocalEnrichment
from soc_triage.pipeline.graph import TriagePipeline
from soc_triage.pipeline.model import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    ModelError,
    OpenAICompatibleModel,
    StubModel,
)
from soc_triage.pipeline.prompts import PROMPT_VERSION
from soc_triage.pipeline.state import CaseArtifact

USE_STUB = os.environ.get("SOC_TRIAGE_STUB_MODEL", "").lower() in ("1", "true", "yes")


class TriageResponse(BaseModel):
    """What a SOAR platform receives back."""

    model_config = ConfigDict(extra="forbid")

    case: CaseArtifact
    trail: list[str]
    """Per-stage audit trail. Returned rather than logged so the caller can
    attach it to the ticket it creates, which is where an analyst would
    actually look when asking why an alert was closed."""


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    model_name: str
    prompt_version: str
    model_reachable: Optional[bool] = None


def build_pipeline() -> TriagePipeline:
    enrichment = ResilientEnrichment(LocalEnrichment(), RetryPolicy(max_attempts=3))
    model = (
        StubModel(name="stub-model")
        if USE_STUB
        else OpenAICompatibleModel(base_url=DEFAULT_BASE_URL, model=DEFAULT_MODEL)
    )
    return TriagePipeline(enrichment, model)


app = FastAPI(
    title="Agentic SOC Triage",
    description="Alert in, case artifact out. Designed to sit behind a SOAR platform.",
    version="0.1.0",
)

_pipeline: Optional[TriagePipeline] = None


def pipeline() -> TriagePipeline:
    """Built lazily so importing the module does not require a model server.

    Tests import this app; a module-level construction would make them
    depend on Ollama being up.
    """
    global _pipeline
    if _pipeline is None:
        _pipeline = build_pipeline()
    return _pipeline


@app.get("/healthz", response_model=HealthResponse)
def healthz(check_model: bool = False) -> HealthResponse:
    """Liveness, and optionally whether the model actually answers.

    The model check is opt-in because it costs a round trip, and a load
    balancer polling every second should not be driving inference.
    """
    p = pipeline()
    reachable: Optional[bool] = None
    if check_model:
        try:
            p._model.decide("Reply with JSON only.", "Return a minimal valid decision.")
            reachable = True
        except ModelError:
            reachable = False
    return HealthResponse(
        status="ok",
        model_name=p.name,
        prompt_version=PROMPT_VERSION,
        model_reachable=reachable,
    )


@app.post("/triage", response_model=TriageResponse)
def triage(alert: Alert) -> TriageResponse:
    """Disposition one alert.

    A validation failure returns 422 with the offending field, courtesy of
    the Alert model. A pipeline that cannot produce a case at all returns
    503 rather than a made-up disposition: no answer is safer than a
    fabricated one.
    """
    case, trail = pipeline().run(alert.model_dump(mode="json", exclude_none=True))
    if case is None:
        raise HTTPException(
            status_code=503,
            detail="triage produced no case; the pipeline is unavailable",
        )
    return TriageResponse(case=case, trail=trail)
