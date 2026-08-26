"""ASIM Authentication schema.

Covers 2 of the 12 techniques in scope: T1078 (Valid Accounts) and T1110.003
(Password Spraying). Together they carry 16 alerts, including 6 of the 30
benign cases.

ASIM constrains most values in this schema to closed lists, which is useful:
password spraying is a burst of `Incorrect password` results across many
TargetUsername values from one SrcIpAddr, and that shape comes from the schema
rather than from this project's imagination.

One deliberate deviation: ASIM marks TargetUsername Optional. The corpus
requires it, because an authentication alert with no subject cannot be triaged
and would be noise rather than a test case. Tightening a schema is safe;
loosening one is not.

Reference: https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-authentication
Schema version 0.1.4
"""

from enum import Enum
from typing import Literal, Optional

from pydantic import Field

from soc_triage.corpus.schema import AsimEventBase

AUTHENTICATION_SCHEMA_VERSION = "0.1.4"


class AuthEventType(str, Enum):
    """EventType values ASIM permits for Authentication."""

    LOGON = "Logon"
    LOGOFF = "Logoff"
    ELEVATE = "Elevate"


class AuthResultDetails(str, Enum):
    """EventResultDetails values, typically populated on failure."""

    NO_SUCH_USER_OR_PASSWORD = "No such user or password"
    NO_SUCH_USER = "No such user"
    INCORRECT_PASSWORD = "Incorrect password"
    INCORRECT_KEY = "Incorrect key"
    ACCOUNT_EXPIRED = "Account expired"
    PASSWORD_EXPIRED = "Password expired"
    USER_LOCKED = "User locked"
    USER_DISABLED = "User disabled"
    LOGON_VIOLATES_POLICY = "Logon violates policy"
    SESSION_EXPIRED = "Session expired"
    OTHER = "Other"


class LogonType(str, Enum):
    """EventSubType: the sign-in type."""

    SYSTEM = "System"
    INTERACTIVE = "Interactive"
    REMOTE_INTERACTIVE = "RemoteInteractive"
    SERVICE = "Service"
    REMOTE_SERVICE = "RemoteService"
    REMOTE = "Remote"
    ASSUME_ROLE = "AssumeRole"


class LogonMethodType(str, Enum):
    """LogonMethod: how authentication was performed."""

    MANAGED_IDENTITY = "Managed Identity"
    SERVICE_PRINCIPAL = "Service Principal"
    USERNAME_PASSWORD = "Username & Password"
    MFA = "Multi factor authentication"
    PASSWORDLESS = "Passwordless"
    PKI = "PKI"
    PAM = "PAM"
    OTHER = "Other"


class AuthenticationEvent(AsimEventBase):
    """A normalized logon, logoff, or elevation event."""

    EventSchema: Literal["Authentication"] = "Authentication"
    EventSchemaVersion: str = AUTHENTICATION_SCHEMA_VERSION
    EventType: AuthEventType

    EventResultDetails: Optional[AuthResultDetails] = None
    EventSubType: Optional[LogonType] = None

    LogonMethod: Optional[LogonMethodType] = None
    LogonProtocol: Optional[str] = None

    # Actor: who initiated, when different from the target user
    ActorUsername: Optional[str] = None

    # Acting application. HttpUserAgent is attacker-controlled over HTTP,
    # which makes it a delivery vector for the adversarial slice.
    ActingAppName: Optional[str] = None
    HttpUserAgent: Optional[str] = None

    # Target user: optional in ASIM, required here (see module docstring)
    TargetUsername: str
    TargetUsernameType: Optional[str] = "Windows"
    TargetUserId: Optional[str] = None

    # Source system: the strongest triage signal in this schema
    SrcIpAddr: Optional[str] = None
    SrcHostname: Optional[str] = None
    SrcPortNumber: Optional[int] = None
    SrcGeoCountry: Optional[str] = None
    SrcGeoCity: Optional[str] = None
    SrcIsp: Optional[str] = None
    SrcRiskLevel: Optional[int] = Field(default=None, ge=0, le=100)

    # Target system
    TargetHostname: Optional[str] = None
    TargetDomain: Optional[str] = None
    TargetAppName: Optional[str] = None

    # Inspection: detection provenance in ASIM's own vocabulary
    RuleName: Optional[str] = None
    ThreatName: Optional[str] = None
    ThreatCategory: Optional[str] = None
    ThreatRiskLevel: Optional[int] = Field(default=None, ge=0, le=100)
    ThreatConfidence: Optional[int] = Field(default=None, ge=0, le=100)
    ThreatField: Optional[Literal["SrcIpAddr", "TargetIpAddr"]] = None
