"""The alert envelope: what the pipeline actually receives.

A Sentinel incident wraps a normalized event with detection metadata. This
model does the same: identity, title, severity, ATT&CK mapping, and the event
itself.

The `event` field is a discriminated union keyed on EventSchema. Because each
schema model pins EventSchema to a Literal, pydantic can route a raw JSON
record to the correct model without a type tag of this project's invention.
Reading data/alerts.json back gives typed events, and a record claiming an
unknown schema fails at load rather than silently parsing as the wrong thing.

What is deliberately NOT here: the disposition. The correct answer lives in
data/labels.json, and soc_triage/pipeline/ cannot import it.
"""

from datetime import datetime
from typing import Annotated, Optional, Union

from pydantic import BaseModel, ConfigDict, Field

from soc_triage.corpus.authentication_event import AuthenticationEvent
from soc_triage.corpus.file_event import FileEvent
from soc_triage.corpus.network_session_event import NetworkSessionEvent
from soc_triage.corpus.process_event import ProcessEvent
from soc_triage.corpus.schema import AsimEventSeverity

AsimEvent = Annotated[
    Union[ProcessEvent, AuthenticationEvent, NetworkSessionEvent, FileEvent],
    Field(discriminator="EventSchema"),
]


class Alert(BaseModel):
    """One alert as it arrives at the triage pipeline."""

    model_config = ConfigDict(extra="forbid")

    alert_id: str
    title: str
    severity: AsimEventSeverity
    created_time: datetime

    technique_id: str
    """ATT&CK technique the detection maps to. Real Sentinel analytics rules
    carry this, so the agent legitimately sees it. It says what fired, not
    whether the activity was malicious, which is the question being asked."""

    tactic: str

    event: AsimEvent
    """The normalized ASIM record that triggered the detection."""

    entity_summary: Optional[str] = None
    """Short human-readable line a SOC console would show in a queue view."""

    def schema_name(self) -> str:
        return self.event.EventSchema
