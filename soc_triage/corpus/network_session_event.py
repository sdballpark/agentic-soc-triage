"""ASIM Network Session schema.

Covers 2 of the 12 techniques in scope: T1190 (Exploit Public-Facing
Application) and T1046 (Network Service Discovery).

Two things differ from the other schemas, and both are easy to get wrong:

1. This schema uses the `Dst` descriptor where ProcessEvent and Authentication
   use `Target`. Microsoft documents this explicitly.
2. The inspection rule field is `NetworkRuleName`, not `RuleName`. Carrying
   the pattern over from the other two schemas would produce a field Sentinel
   does not define.

Field coverage is a working subset. The TCP flag fields, VLAN, NAT, MAC, and
geo-coordinate sections are omitted: they carry no triage signal for the two
techniques in scope and would pad every record with nulls.

Reference: https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-network
Schema version 0.2.7
"""

from enum import Enum
from typing import Literal, Optional

from pydantic import Field

from soc_triage.corpus.schema import AsimEventBase

NETWORK_SESSION_SCHEMA_VERSION = "0.2.7"


class NetworkEventType(str, Enum):
    """EventType values ASIM permits for Network Session.

    IDS is the one to know: a session reported as suspicious, with inspection
    fields populated, possibly with only one IP address present.
    """

    NETWORK_SESSION = "NetworkSession"
    ENDPOINT_NETWORK_SESSION = "EndpointNetworkSession"
    L2_NETWORK_SESSION = "L2NetworkSession"
    IDS = "IDS"
    FLOW = "Flow"


class NetworkEventSubType(str, Enum):
    START = "Start"
    END = "End"


class NetworkResultDetails(str, Enum):
    FAILOVER = "Failover"
    INVALID_TCP = "Invalid TCP"
    INVALID_TUNNEL = "Invalid Tunnel"
    MAXIMUM_RETRY = "Maximum Retry"
    RESET = "Reset"
    ROUTING_ISSUE = "Routing issue"
    SIMULATION = "Simulation"
    TERMINATED = "Terminated"
    TIMEOUT = "Timeout"
    TRANSIENT_ERROR = "Transient error"
    UNKNOWN = "Unknown"
    NA = "NA"


class DvcActionType(str, Enum):
    """The action the reporting device took on the session."""

    ALLOW = "Allow"
    DENY = "Deny"
    DROP = "Drop"
    DROP_ICMP = "Drop ICMP"
    RESET = "Reset"
    RESET_SOURCE = "Reset Source"
    RESET_DESTINATION = "Reset Destination"
    ENCRYPT = "Encrypt"
    DECRYPT = "Decrypt"
    VPN_ROUTE = "VPNroute"


class NetworkDirectionType(str, Enum):
    """Direction, relative to the organization boundary or to the endpoint.

    Listen applies only to EndpointNetworkSession events.
    """

    INBOUND = "Inbound"
    OUTBOUND = "Outbound"
    LOCAL = "Local"
    EXTERNAL = "External"
    LISTEN = "Listen"
    NA = "NA"


class NetworkSessionEvent(AsimEventBase):
    """A normalized IP network session or connection."""

    EventSchema: Literal["NetworkSession"] = "NetworkSession"
    EventSchemaVersion: str = NETWORK_SESSION_SCHEMA_VERSION
    EventType: NetworkEventType

    EventSubType: Optional[NetworkEventSubType] = None
    EventResultDetails: Optional[NetworkResultDetails] = None

    # DvcAction drives EventResult and EventSeverity per ASIM guidance:
    # a denied or dropped session is a Failure with Low severity.
    DvcAction: Optional[DvcActionType] = None

    # Session characteristics
    NetworkProtocol: Optional[str] = None
    NetworkApplicationProtocol: Optional[str] = None
    NetworkDirection: Optional[NetworkDirectionType] = None
    NetworkDuration: Optional[int] = None
    NetworkSessionId: Optional[str] = None

    # Volume. For a port scan these stay tiny, which is itself the signal.
    SrcBytes: Optional[int] = None
    DstBytes: Optional[int] = None
    NetworkBytes: Optional[int] = None
    SrcPackets: Optional[int] = None
    DstPackets: Optional[int] = None

    # Source system
    SrcIpAddr: Optional[str] = None
    SrcPortNumber: Optional[int] = None
    SrcHostname: Optional[str] = None
    SrcDomain: Optional[str] = None
    SrcZone: Optional[str] = None
    SrcGeoCountry: Optional[str] = None
    SrcGeoCity: Optional[str] = None
    SrcUsername: Optional[str] = None
    SrcProcessName: Optional[str] = None
    SrcAppName: Optional[str] = None
    SrcDescription: Optional[str] = None

    # Destination system (Dst, not Target -- see module docstring)
    DstIpAddr: Optional[str] = None
    DstPortNumber: Optional[int] = None
    DstHostname: Optional[str] = None
    DstDomain: Optional[str] = None
    DstZone: Optional[str] = None
    DstGeoCountry: Optional[str] = None
    DstProcessName: Optional[str] = None
    DstAppName: Optional[str] = None
    DstDescription: Optional[str] = None

    # Inspection. NetworkRuleName, NOT RuleName.
    NetworkRuleName: Optional[str] = None
    NetworkRuleNumber: Optional[int] = None
    ThreatId: Optional[str] = None
    ThreatName: Optional[str] = None
    ThreatCategory: Optional[str] = None
    ThreatRiskLevel: Optional[int] = Field(default=None, ge=0, le=100)
    ThreatConfidence: Optional[int] = Field(default=None, ge=0, le=100)
    ThreatIpAddr: Optional[str] = None
    ThreatField: Optional[Literal["SrcIpAddr", "DstIpAddr"]] = None
