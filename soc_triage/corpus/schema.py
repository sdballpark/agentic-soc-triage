"""Common ASIM fields shared by every normalized event schema.

Field names follow Microsoft's ASIM casing exactly (PascalCase) rather than
Python convention. The corpus should be recognizable to anyone who has written
KQL against Sentinel, so the wire format wins over PEP 8 here.

Enum classes carry an Asim prefix so they cannot collide with the ASIM field
names they type. Naming an enum EventSeverity and a field EventSeverity shadows
the enum at class-body evaluation time and fails at import.

Reference: https://learn.microsoft.com/en-us/azure/sentinel/normalization-common-fields
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class AsimEventResult(str, Enum):
    SUCCESS = "Success"
    PARTIAL = "Partial"
    FAILURE = "Failure"
    NA = "NA"


class AsimEventSeverity(str, Enum):
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class AsimEventBase(BaseModel):
    """Fields ASIM defines for all schemas.

    extra="forbid" is deliberate: a misspelled field name should fail loudly at
    generation time rather than sit silently in the corpus and quietly degrade
    every downstream measurement.
    """

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    # Log Analytics standard
    TimeGenerated: datetime

    # Mandatory ASIM common fields
    EventCount: int = 1
    EventStartTime: datetime
    EventEndTime: datetime
    EventType: str
    EventResult: AsimEventResult
    EventProduct: str
    EventVendor: str
    EventSchema: str
    EventSchemaVersion: str

    # Recommended
    EventSeverity: Optional[AsimEventSeverity] = None
    EventUid: Optional[str] = None
    EventOriginalType: Optional[str] = None
    EventMessage: Optional[str] = None

    # Device entity
    DvcHostname: Optional[str] = None
    DvcIpAddr: Optional[str] = None
    DvcDomain: Optional[str] = None
    DvcOs: Optional[str] = None

    # Source-specific overflow, per ASIM guidance
    AdditionalFields: dict[str, str] = Field(default_factory=dict)
