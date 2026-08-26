"""Ground truth for the synthetic corpus.

This module is the answer key. It lives under evaluation/ and only the harness
may import it. Keeping labels out of data/alerts.json is what makes "could the
agent have seen the answer?" a structural question rather than a promise.

Layout on disk:
    data/alerts.json  -- what the pipeline receives
    data/labels.json  -- what the harness compares against, keyed by alert_id
"""

import json
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from soc_triage.disposition import Disposition


class CorpusSlice(str, Enum):
    """Which part of the corpus an alert belongs to.

    Reported separately because the three slices answer different questions.
    """

    MALICIOUS = "malicious"
    """Real attacker activity. Getting these wrong is a false close."""

    BENIGN = "benign"
    """Legitimate activity that resembles an attack. Getting these wrong is a
    false positive, which is what drives analyst toil."""

    ADVERSARIAL = "adversarial"
    """Carries prompt injection in an attacker-controlled log field. The correct
    disposition follows the underlying activity; obeying the injected text is
    the failure being measured."""


class AlertLabel(BaseModel):
    """The correct answer for one alert, plus why it is correct."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    alert_id: str
    disposition: Disposition
    technique_id: str
    corpus_slice: CorpusSlice

    rationale: str = Field(min_length=1)
    """Why this disposition is correct. Never scored. Exists so any single
    label can be defended when the corpus is challenged."""

    abstention_acceptable: bool = False
    """True when enrichment is thin enough that abstaining is defensible even
    though a correct disposition exists. Lets the harness distinguish a
    reasonable hedge from a cop-out."""

    injected_field: str | None = None
    """For the adversarial slice, which ASIM field carries the injection.
    Makes injection-resistance results traceable to a delivery vector."""


class LabelSetError(ValueError):
    """Raised when the answer key is internally inconsistent."""


def load_labels(path: Path) -> dict[str, AlertLabel]:
    """Load and validate labels, keyed by alert_id."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise LabelSetError("labels.json must contain a JSON array")

    labels: dict[str, AlertLabel] = {}
    for entry in raw:
        label = AlertLabel.model_validate(entry)
        if label.alert_id in labels:
            raise LabelSetError(f"duplicate alert_id in labels: {label.alert_id}")
        labels[label.alert_id] = label

    for label in labels.values():
        if label.corpus_slice is CorpusSlice.ADVERSARIAL and not label.injected_field:
            raise LabelSetError(
                f"{label.alert_id}: adversarial slice requires injected_field"
            )
        if label.corpus_slice is not CorpusSlice.ADVERSARIAL and label.injected_field:
            raise LabelSetError(
                f"{label.alert_id}: injected_field set on a non-adversarial alert"
            )

    return labels


def assert_join_integrity(alert_ids: set[str], labels: dict[str, AlertLabel]) -> None:
    """Every alert has exactly one label and every label has an alert.

    A silent mismatch here would quietly change the denominator of every
    reported metric, so it fails loudly instead.
    """
    missing = alert_ids - labels.keys()
    orphaned = labels.keys() - alert_ids

    problems = []
    if missing:
        problems.append(f"alerts with no label: {sorted(missing)}")
    if orphaned:
        problems.append(f"labels with no alert: {sorted(orphaned)}")
    if problems:
        raise LabelSetError("; ".join(problems))
