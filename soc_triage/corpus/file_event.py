"""ASIM File Event schema.

Covers the final 3 of 12 techniques in scope: T1204.002 (User Execution:
Malicious File), T1547.001 (Startup Folder persistence), and T1070.004
(Indicator Removal: File Deletion).

The entity model matters for these three. ASIM frames a file event as: an
Actor performs an operation using an ActingProcess, which turns a SrcFile
into a TargetFile. Single-file operations use the target fields only, so a
creation or deletion populates TargetFile and leaves SrcFile empty.

Two notes on fidelity:

1. Inspection uses `RuleName` here, unlike NetworkSession's
   `NetworkRuleName`. ASIM is not internally consistent about this.
2. Microsoft documents ThreatField as taking `SrcFilePath` or `DstFilePath`,
   but this schema defines no `DstFilePath` field -- the destination is
   `TargetFilePath`. That appears to be an error in the reference. The
   documented values are used verbatim rather than silently corrected,
   because inventing a third value would be this project overriding a spec
   it does not own.

Reference: https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-file-event
Schema version 0.2.2
"""

from enum import Enum
from typing import Literal, Optional

from pydantic import Field

from soc_triage.corpus.schema import AsimEventBase

FILE_EVENT_SCHEMA_VERSION = "0.2.2"


class FileEventType(str, Enum):
    """EventType values ASIM permits for File Event."""

    FILE_ACCESSED = "FileAccessed"
    FILE_CREATED = "FileCreated"
    FILE_MODIFIED = "FileModified"
    FILE_DELETED = "FileDeleted"
    FILE_RENAMED = "FileRenamed"
    FILE_COPIED = "FileCopied"
    FILE_MOVED = "FileMoved"
    FILE_CREATED_OR_MODIFIED = "FileCreatedOrModified"
    FOLDER_CREATED = "FolderCreated"
    FOLDER_DELETED = "FolderDeleted"
    FOLDER_MOVED = "FolderMoved"
    FOLDER_MODIFIED = "FolderModified"


class FileEventSubType(str, Enum):
    """EventSubType values, each valid only for certain event types.

    ASIM scopes these per EventType (Recycled applies to FileDeleted,
    Download to FileAccessed, and so on). That pairing is not enforced here.
    """

    UPLOAD = "Upload"
    CHECKIN = "Checkin"
    DOWNLOAD = "Download"
    PREVIEW = "Preview"
    CHECKOUT = "Checkout"
    EXTENDED = "Extended"
    RECYCLED = "Recycled"
    VERSIONS = "Versions"
    SITE = "Site"


class FilePathType(str, Enum):
    """How a file path is normalized. Mandatory alongside TargetFilePath."""

    WINDOWS_LOCAL = "Windows Local"
    WINDOWS_SHARE = "Windows Share"
    UNIX = "Unix"
    URL = "URL"


class FileEvent(AsimEventBase):
    """A normalized file or folder operation."""

    EventSchema: Literal["FileEvent"] = "FileEvent"
    EventSchemaVersion: str = FILE_EVENT_SCHEMA_VERSION
    EventType: FileEventType

    EventSubType: Optional[FileEventSubType] = None

    # Actor: who initiated the operation (mandatory)
    ActorUsername: str
    ActorUsernameType: Optional[str] = "Windows"
    ActorUserId: Optional[str] = None

    # Acting process: what performed it. For T1204.002 this is the strongest
    # signal -- winword.exe writing an executable is not normal.
    ActingProcessName: Optional[str] = None
    ActingProcessId: Optional[str] = None
    ActingProcessCommandLine: Optional[str] = None

    # Target file: the file operated on (path and path type both mandatory)
    TargetFilePath: str
    TargetFilePathType: FilePathType
    TargetFileName: Optional[str] = None
    TargetFileDirectory: Optional[str] = None
    TargetFileExtension: Optional[str] = None
    TargetFileSize: Optional[int] = None
    TargetFileSHA256: Optional[str] = None
    TargetFileMD5: Optional[str] = None
    TargetFileCreationTime: Optional[str] = None

    # Source file: populated only for two-file operations (rename, copy, move)
    SrcFilePath: Optional[str] = None
    SrcFilePathType: Optional[FilePathType] = None
    SrcFileName: Optional[str] = None
    SrcFileSHA256: Optional[str] = None

    # Remote origin, when the operation came over the network
    SrcIpAddr: Optional[str] = None
    SrcHostname: Optional[str] = None
    HttpUserAgent: Optional[str] = None
    NetworkApplicationProtocol: Optional[str] = None

    # Inspection: RuleName here, not NetworkRuleName
    RuleName: Optional[str] = None
    RuleNumber: Optional[int] = None
    ThreatId: Optional[str] = None
    ThreatName: Optional[str] = None
    ThreatCategory: Optional[str] = None
    ThreatRiskLevel: Optional[int] = Field(default=None, ge=0, le=100)
    ThreatConfidence: Optional[int] = Field(default=None, ge=0, le=100)
    ThreatFilePath: Optional[str] = None
    ThreatField: Optional[Literal["SrcFilePath", "DstFilePath"]] = None
    ThreatIsActive: Optional[bool] = None
