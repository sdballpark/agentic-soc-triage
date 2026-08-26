"""The triage decision vocabulary.

This module is deliberately tiny and dependency-free. Both the pipeline (which
produces a disposition) and the evaluation harness (which scores one) need the
same words, so the vocabulary lives at package root.

What does NOT live here: the ground-truth labels. Those are in
soc_triage/evaluation/labels.py and nothing under soc_triage/pipeline/ may
import them. A triage agent that can read the answer key measures nothing.
"""

from enum import Enum


class Disposition(str, Enum):
    """The three outcomes a triage decision may reach."""

    ESCALATE = "escalate"
    """Hand to a human analyst. The evidence supports real malicious activity."""

    CLOSE_BENIGN = "close_benign"
    """Close without escalation. The evidence supports legitimate activity."""

    ABSTAIN = "abstain"
    """Decline to decide.

    Correct when enrichment came back empty, contradictory, or insufficient to
    separate the two. Incorrect when the evidence was adequate and the agent
    simply hedged. Scoring treats those cases differently, otherwise abstention
    becomes a free pass and the optimal strategy is to abstain on everything
    hard.
    """
