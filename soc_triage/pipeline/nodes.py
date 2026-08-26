"""Graph nodes.

Dependencies are injected through build_nodes() rather than imported as
module globals, so a test can supply a failing enrichment provider or a stub
model without patching anything.

Entity extraction is duplicated across the four enrichment nodes instead of
running in a preparatory node. That keeps the graph flat -- four lookups fan
out directly from START and run concurrently -- at the cost of recomputing a
few dictionary reads. The alternative was a sequential prep step that would
serialize the slowest part of the pipeline for no benefit.

The routing decision deserves a note. close_benign goes straight to END: that
is the auto-close path, and it is where the danger lives. Escalations and
abstentions go to a human, which is the safe direction. So the entire risk of
this system concentrates in one edge, and false-close rate is the metric that
watches it.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from langgraph.graph import END

from soc_triage.disposition import Disposition
from soc_triage.pipeline.model import ModelError, TriageModel
from soc_triage.pipeline.prompts import (
    PROMPT_VERSION,
    SYSTEM_PROMPT,
    render_user_prompt,
)
from soc_triage.pipeline.state import CaseArtifact, Citation, TriageState

INTERNAL_PREFIXES = ("10.", "192.168.", "172.16.")


# --------------------------------------------------------------------------
# Entity extraction
# --------------------------------------------------------------------------

def subject_hostname(event: dict[str, Any]) -> Optional[str]:
    """The host whose context matters for this alert.

    Which field that is depends on the schema. For process and file activity
    it is the device the activity happened on. For a network session it is
    the internal end of the connection, which may be either side.
    """
    schema = event.get("EventSchema")

    if schema in ("ProcessEvent", "FileEvent"):
        return event.get("DvcHostname")

    if schema == "Authentication":
        return event.get("SrcHostname") or event.get("TargetHostname")

    if schema == "NetworkSession":
        src_ip = str(event.get("SrcIpAddr") or "")
        if event.get("SrcHostname") and src_ip.startswith(INTERNAL_PREFIXES):
            return event["SrcHostname"]
        return event.get("DstHostname") or event.get("SrcHostname")

    return event.get("DvcHostname")


def subject_username(event: dict[str, Any]) -> Optional[str]:
    for field in ("TargetUsername", "ActorUsername", "SrcUsername"):
        value = event.get(field)
        if value:
            return value
    return None


def subject_address(event: dict[str, Any]) -> Optional[str]:
    """The external address, if there is one.

    Internal addresses are skipped: asking external threat intel about
    RFC1918 space is a category error, and the enrichment layer says so.
    """
    for field in ("SrcIpAddr", "DstIpAddr"):
        value = event.get(field)
        if value and not str(value).startswith(INTERNAL_PREFIXES):
            return value
    return None


# --------------------------------------------------------------------------
# Nodes
# --------------------------------------------------------------------------

def build_nodes(enrichment: Any, model: TriageModel) -> dict[str, Callable]:
    """Create node functions bound to a specific enrichment and model."""

    def enrich_asset(state: TriageState) -> dict:
        hostname = subject_hostname(state["alert"]["event"])
        if not hostname:
            return {"findings": ["asset: no host entity in alert"]}
        result = enrichment.asset(hostname)
        return {
            "asset": result,
            "findings": [f"asset[{hostname}]: {result.status.value}"],
            **({"errors": [f"asset: {result.error}"]} if result.degraded else {}),
        }

    def enrich_identity(state: TriageState) -> dict:
        username = subject_username(state["alert"]["event"])
        if not username:
            return {"findings": ["identity: no user entity in alert"]}
        result = enrichment.identity(username)
        return {
            "identity": result,
            "findings": [f"identity[{username}]: {result.status.value}"],
            **({"errors": [f"identity: {result.error}"]} if result.degraded else {}),
        }

    def enrich_reputation(state: TriageState) -> dict:
        address = subject_address(state["alert"]["event"])
        if not address:
            return {"findings": ["reputation: no external address in alert"]}
        result = enrichment.reputation(address)
        return {
            "reputation": result,
            "findings": [f"reputation[{address}]: {result.status.value}"],
            **({"errors": [f"reputation: {result.error}"]} if result.degraded else {}),
        }

    def enrich_related(state: TriageState) -> dict:
        event = state["alert"]["event"]
        result = enrichment.related(
            alert_id=state["alert_id"],
            hostname=subject_hostname(event),
            username=subject_username(event),
            window_minutes=1440,
        )
        count = result.data.count if result.data else 0
        return {
            "related": result,
            "findings": [f"related: {result.status.value} ({count} nearby)"],
            **({"errors": [f"related: {result.error}"]} if result.degraded else {}),
        }

    def decide(state: TriageState) -> dict:
        lookups = [state.get(k) for k in ("asset", "identity", "reputation", "related")]
        requested = sum(1 for r in lookups if r is not None)
        returned = sum(1 for r in lookups if r is not None and r.ok)
        degraded = any(r is not None and r.degraded for r in lookups)

        user_prompt = render_user_prompt(
            state["alert"],
            asset=state.get("asset"),
            identity=state.get("identity"),
            reputation=state.get("reputation"),
            related=state.get("related"),
        )

        try:
            decision = model.decide(SYSTEM_PROMPT, user_prompt)
        except ModelError as exc:
            # The model is unavailable or unusable. Abstain rather than
            # guessing, and say why. A pipeline that invents a disposition
            # when its reasoning layer is down is worse than one that stops.
            case = CaseArtifact(
                alert_id=state["alert_id"],
                disposition=Disposition.ABSTAIN,
                confidence=0,
                summary="Triage could not complete; model unavailable.",
                reasoning=f"The decision model failed: {exc}",
                recommended_action="Analyst review. Retry once the model is reachable.",
                enrichment_requested=requested,
                enrichment_returned=returned,
                degraded=True,
                model_name=getattr(model, "name", "unknown"),
                prompt_version=PROMPT_VERSION,
            )
            return {
                "case": case,
                "findings": ["decide: model error, abstained"],
                "errors": [f"model: {exc}"],
            }

        case = CaseArtifact(
            alert_id=state["alert_id"],
            disposition=decision.disposition,
            confidence=decision.confidence,
            summary=decision.summary,
            reasoning=decision.reasoning,
            citations=tuple(
                Citation(source=c.source, query=c.query, fact=c.fact)
                for c in decision.citations
            ),
            recommended_action=decision.recommended_action,
            enrichment_requested=requested,
            enrichment_returned=returned,
            degraded=degraded,
            suspected_injection=decision.suspected_injection,
            injection_note=decision.injection_note,
            model_name=getattr(model, "name", "unknown"),
            prompt_version=PROMPT_VERSION,
        )
        note = f"decide: {case.disposition.value} @{case.confidence}"
        if case.suspected_injection:
            note += " (flagged injection attempt)"
        return {"case": case, "findings": [note]}

    def human_review(state: TriageState) -> dict:
        """Queue for an analyst.

        In this version the node records the routing rather than blocking.
        LangGraph supports true interrupt-and-resume, which is the right
        implementation for a production approval gate, but it needs a
        checkpointer and resume handling that the eval harness would have to
        drive. Recorded as a roadmap item rather than faked here.
        """
        case = state.get("case")
        reason = "escalation" if case and case.disposition is Disposition.ESCALATE else "abstention"
        return {"findings": [f"human_review: queued for analyst ({reason})"]}

    return {
        "enrich_asset": enrich_asset,
        "enrich_identity": enrich_identity,
        "enrich_reputation": enrich_reputation,
        "enrich_related": enrich_related,
        "decide": decide,
        "human_review": human_review,
    }


def route_after_decision(state: TriageState) -> str:
    """Auto-close, or hand to a human.

    Only close_benign bypasses human review. That is the whole efficiency
    argument for this system and also its entire risk surface, which is why
    false-close rate is the metric that matters most.
    """
    case = state.get("case")
    if case is None:
        return "human_review"
    if case.disposition is Disposition.CLOSE_BENIGN and not case.suspected_injection:
        return END
    return "human_review"
