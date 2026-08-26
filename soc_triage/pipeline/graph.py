"""Graph assembly.

    START ──┬─> enrich_asset ──────┐
            ├─> enrich_identity ───┤
            ├─> enrich_reputation ─┼─> decide ──┬─> END (auto-close)
            └─> enrich_related ────┘            └─> human_review ─> END

Four lookups fan out concurrently and their results merge before a single
model call decides. The sequence is fixed, not emergent: enrich, then
correlate, then decide. That is the argument for a state graph over an agent
loop here -- the order is known, so it should be encoded and inspectable
rather than rediscovered on every run.

The graph is compiled once and reused. Compilation validates the topology, so
a malformed graph fails at import rather than on the hundredth alert of an
eval run.
"""

from __future__ import annotations

from typing import Any, Optional

from langgraph.graph import END, START, StateGraph

from soc_triage.pipeline.model import TriageModel
from soc_triage.pipeline.nodes import build_nodes, route_after_decision
from soc_triage.pipeline.state import CaseArtifact, TriageState

ENRICHMENT_NODES = (
    "enrich_asset",
    "enrich_identity",
    "enrich_reputation",
    "enrich_related",
)


def build_graph(enrichment: Any, model: TriageModel):
    """Compile the triage graph against a given enrichment and model."""
    nodes = build_nodes(enrichment, model)
    graph = StateGraph(TriageState)

    for name, fn in nodes.items():
        graph.add_node(name, fn)

    for name in ENRICHMENT_NODES:
        graph.add_edge(START, name)
        graph.add_edge(name, "decide")

    graph.add_conditional_edges(
        "decide",
        route_after_decision,
        {"human_review": "human_review", END: END},
    )
    graph.add_edge("human_review", END)

    return graph.compile()


class TriagePipeline:
    """Runs one alert through the graph and returns the case artifact."""

    def __init__(self, enrichment: Any, model: TriageModel) -> None:
        self._graph = build_graph(enrichment, model)
        self._enrichment = enrichment
        self._model = model

    def run(self, alert: dict[str, Any]) -> tuple[Optional[CaseArtifact], list[str]]:
        """Triage one alert.

        Returns the case and the audit trail. The trail is returned rather
        than logged so callers can attach it to a record, print it, or ignore
        it, and so the eval harness can report which stages contributed.
        """
        final = self._graph.invoke({
            "alert": alert,
            "alert_id": alert["alert_id"],
            "findings": [],
            "errors": [],
        })
        return final.get("case"), final.get("findings", [])

    def trace(self, alert: dict[str, Any]):
        """Yield each node's contribution as it happens.

        This is the auditability story: for any disposition, you can show
        exactly what each stage added, in order.
        """
        yield from self._graph.stream({
            "alert": alert,
            "alert_id": alert["alert_id"],
            "findings": [],
            "errors": [],
        })
