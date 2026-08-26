"""A naive baseline.

Two purposes, and the second is the important one.

**Comparison.** "The pipeline scores X" is a number. "The pipeline scores X
where a severity-only rule scores Y" is a result. Without a floor, a reviewer
has no way to judge whether the agent is reasoning or just reading the
severity field.

**Corpus validation.** If this baseline scores near-perfectly, the corpus is
broken: it means ground truth is recoverable from one field, and every
accuracy number the harness reports would measure field-reading rather than
triage. That is a failure mode worth detecting deliberately, because it is
invisible from the agent's results alone.

The rule is what a stretched SOC actually does before automation: escalate
anything High or Medium, close anything Low or Informational. It reads no
enrichment and does no correlation.
"""

from __future__ import annotations

from typing import Any, Optional

from soc_triage.disposition import Disposition
from soc_triage.pipeline.state import CaseArtifact

ESCALATE_SEVERITIES = {"High", "Medium"}


def severity_baseline(alert: dict[str, Any]) -> Disposition:
    severity = alert.get("severity") or alert["event"].get("EventSeverity")
    return (
        Disposition.ESCALATE
        if severity in ESCALATE_SEVERITIES
        else Disposition.CLOSE_BENIGN
    )


def threat_risk_baseline(alert: dict[str, Any], threshold: int = 60) -> Disposition:
    """A slightly less naive variant: escalate on the product's risk score."""
    risk = alert["event"].get("ThreatRiskLevel")
    if risk is None:
        return severity_baseline(alert)
    return Disposition.ESCALATE if risk >= threshold else Disposition.CLOSE_BENIGN


BASELINES = {
    "severity": severity_baseline,
    "threat_risk": threat_risk_baseline,
}


class BaselinePolicy:
    """Wraps a baseline rule so the harness can score it like a pipeline."""

    def __init__(self, name: str = "severity") -> None:
        if name not in BASELINES:
            raise KeyError(f"unknown baseline {name!r}; have {sorted(BASELINES)}")
        self.name = f"baseline-{name}"
        self._rule = BASELINES[name]

    def run(self, alert: dict[str, Any]) -> tuple[Optional[CaseArtifact], list[str]]:
        disposition = self._rule(alert)
        case = CaseArtifact(
            alert_id=alert["alert_id"],
            disposition=disposition,
            confidence=50,
            summary=f"Baseline rule: {self.name}.",
            reasoning="No enrichment, no correlation. Field lookup only.",
            recommended_action="Not a real recommendation; baseline comparison only.",
            enrichment_requested=0,
            enrichment_returned=0,
            model_name=self.name,
            prompt_version="n/a",
        )
        return case, [f"baseline: {disposition.value}"]
