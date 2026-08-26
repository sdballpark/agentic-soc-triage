"""ASIM Process Event schema.

Covers 5 of the 12 techniques in scope: T1003.001, T1059.001, T1053.005,
T1087.002, and T1027.

Only a working subset of the full schema is modeled. Every mandatory field is
present; optional fields are included where they carry triage signal and
omitted where they would be noise. The omission is deliberate rather than
lazy, and the README says so.

Detection provenance uses ASIM's own Inspection fields (RuleName, ThreatName,
ThreatCategory, ThreatRiskLevel) rather than a custom structure, so the corpus
reads as Sentinel data rather than as this project's invention.

Reference: https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-process-event
Schema version 0.1.4
"""

from enum import Enum
from typing import Literal, Optional

from pydantic import Field

from soc_triage.corpus.schema import AsimEventBase

PROCESS_EVENT_SCHEMA_VERSION = "0.1.4"


class ProcessEventType(str, Enum):
    """The only EventType values ASIM permits for this schema."""

    CREATED = "ProcessCreated"
    TERMINATED = "ProcessTerminated"


class ProcessEvent(AsimEventBase):
    """A normalized process create or terminate event."""

    EventSchema: Literal["ProcessEvent"] = "ProcessEvent"
    EventSchemaVersion: str = PROCESS_EVENT_SCHEMA_VERSION
    EventType: ProcessEventType

    # Actor: the user who initiated the process activity (mandatory)
    ActorUsername: str
    ActorUsernameType: Optional[str] = "Windows"

    # Acting process: what the actor used (ActingProcessId is mandatory)
    ActingProcessId: str
    ActingProcessName: Optional[str] = None

    # Parent process: recommended, and often the strongest triage signal.
    # winword.exe spawning powershell.exe is the classic example.
    ParentProcessName: Optional[str] = None
    ParentProcessId: Optional[str] = None

    # Target user: mandatory for process create events
    TargetUsername: str
    TargetUsernameType: Optional[str] = "Windows"

    # Target process: the new process (all three mandatory)
    TargetProcessName: str
    TargetProcessCommandLine: str
    TargetProcessId: str

    TargetProcessFilename: Optional[str] = None
    TargetProcessSHA256: Optional[str] = None
    TargetProcessIntegrityLevel: Optional[str] = None
    TargetProcessCurrentDirectory: Optional[str] = None

    # Inspection fields: which rule fired and what the product concluded.
    # This is the detection provenance, in ASIM's own vocabulary.
    RuleName: Optional[str] = None
    ThreatName: Optional[str] = None
    ThreatCategory: Optional[str] = None
    ThreatRiskLevel: Optional[int] = Field(default=None, ge=0, le=100)
    ThreatConfidence: Optional[int] = Field(default=None, ge=0, le=100)
