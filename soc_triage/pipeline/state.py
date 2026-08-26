"""Pipeline state and output.

Two things live here: the state that flows through the graph, and the case
artifact the pipeline produces.

The artifact is deliberately not a bare label. The JD asks for case handoffs
across ServiceNow and Confluence, so the terminal node emits something a SOC
would actually consume: a disposition, the reasoning behind it, citations
back to the enrichment that supports it, and a recommended analyst action.

Citations are the part that matters for trust. A disposition with no
provenance is an opinion. A disposition that says "closed because the CMDB
tags this host as the authorized scanner" is auditable, and an analyst can
check it in seconds.

Nothing here imports the answer key. The label isolation gate enforces that.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, Optional

from pydantic import BaseModel, ConfigDict, Field
from typing_extensions import TypedDict

from soc_triage.disposition import Disposition


class Citation(BaseModel):
    """One enrichment fact the disposition rests on."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str
    """Which provider answered, e.g. 'local-stub' or 'cmdb'."""

    query: str
    """What was asked, e.g. the hostname or address looked up."""

    fact: str
    """The specific finding that influenced the decision."""


class CaseArtifact(BaseModel):
    """What the pipeline hands to a SOC queue."""

    model_config = ConfigDict(extra="forbid")

    alert_id: str
    disposition: Disposition
    confidence: int = Field(ge=0, le=100)

    summary: str
    """One line an analyst reads first."""

    reasoning: str
    """How the evidence leads to the disposition."""

    citations: tuple[Citation, ...] = ()
    recommended_action: str

    enrichment_requested: int = 0
    enrichment_returned: int = 0
    """Completeness, one of the four measures. A disposition reached with two
    of four lookups answered deserves less weight than one with all four."""

    degraded: bool = False
    """True when at least one enrichment source failed outright. The agent
    still decides, but the case records that it decided with less."""

    suspected_injection: bool = False
    injection_note: Optional[str] = None
    """Set when the agent believes alert content tried to instruct it. Worth
    surfacing to a human either way: if correct, someone is targeting the
    triage layer, and that is its own incident."""

    model_name: str = ""
    prompt_version: str = ""
    """Provenance for reproducibility. A metric is only comparable across
    runs if you know which model and prompt produced it."""

    @property
    def enrichment_completeness(self) -> float:
        if not self.enrichment_requested:
            return 0.0
        return self.enrichment_returned / self.enrichment_requested


class TriageState(TypedDict, total=False):
    """State threaded through the graph.

    The enrichment nodes run in parallel and write disjoint keys, so no
    reducer is needed for those. `findings` and `errors` use an add reducer
    because several nodes append to them concurrently.
    """

    alert: dict[str, Any]
    alert_id: str

    asset: Optional[Any]
    identity: Optional[Any]
    reputation: Optional[Any]
    related: Optional[Any]

    findings: Annotated[list[str], operator.add]
    """Human-readable audit trail, one line per stage. This is what makes a
    run explainable after the fact without re-running it."""

    errors: Annotated[list[str], operator.add]

    case: Optional[CaseArtifact]
