"""The locked ATT&CK scope for the synthetic corpus.

Twelve techniques across six tactics, each mapped to one of four ASIM event
schemas. This module is data, not logic: it is the single place that defines
what the corpus covers, so per-tactic coverage reporting has something
authoritative to read.

Scope decisions and their reasoning live in the README. In short: Lateral
Movement, Command and Control, and Exfiltration need multi-event correlation
the corpus shape does not support; Impact was excluded because ransomware
alerts are trivially easy to triage and would inflate accuracy without
testing anything.

Technique IDs verified against https://attack.mitre.org
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict


class Tactic(str, Enum):
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    DEFENSE_EVASION = "Defense Evasion"


class AsimSchema(str, Enum):
    """The four ASIM event schemas the corpus emits.

    Values match Microsoft's EventSchema field exactly.
    """

    PROCESS_EVENT = "ProcessEvent"
    AUTHENTICATION = "Authentication"
    NETWORK_SESSION = "NetworkSession"
    FILE_EVENT = "FileEvent"


class Technique(BaseModel):
    """One ATT&CK technique in scope, and how the corpus treats it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    technique_id: str
    name: str
    tactic: Tactic
    schema_name: AsimSchema

    # Alerts whose ground truth is escalate.
    malicious_count: int = 5

    # Alerts that look like this technique but are legitimate activity.
    # Only set where a credible benign analogue exists; a contrived benign
    # case teaches the pipeline nothing and inflates the close rate.
    benign_count: int = 0


CATALOG: tuple[Technique, ...] = (
    Technique(
        technique_id="T1078",
        name="Valid Accounts",
        tactic=Tactic.INITIAL_ACCESS,
        schema_name=AsimSchema.AUTHENTICATION,
        benign_count=6,  # service account authenticating from a new host
    ),
    Technique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic=Tactic.INITIAL_ACCESS,
        schema_name=AsimSchema.NETWORK_SESSION,
    ),
    Technique(
        technique_id="T1110.003",
        name="Brute Force: Password Spraying",
        tactic=Tactic.CREDENTIAL_ACCESS,
        schema_name=AsimSchema.AUTHENTICATION,
    ),
    Technique(
        technique_id="T1003.001",
        name="OS Credential Dumping: LSASS Memory",
        tactic=Tactic.CREDENTIAL_ACCESS,
        schema_name=AsimSchema.PROCESS_EVENT,
    ),
    Technique(
        technique_id="T1059.001",
        name="Command and Scripting Interpreter: PowerShell",
        tactic=Tactic.EXECUTION,
        schema_name=AsimSchema.PROCESS_EVENT,
        benign_count=6,  # sysadmin running an administrative script
    ),
    Technique(
        technique_id="T1204.002",
        name="User Execution: Malicious File",
        tactic=Tactic.EXECUTION,
        schema_name=AsimSchema.FILE_EVENT,
    ),
    Technique(
        technique_id="T1053.005",
        name="Scheduled Task/Job: Scheduled Task",
        tactic=Tactic.PERSISTENCE,
        schema_name=AsimSchema.PROCESS_EVENT,
        benign_count=6,  # software deployment creating a maintenance task
    ),
    Technique(
        technique_id="T1547.001",
        name="Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        tactic=Tactic.PERSISTENCE,
        schema_name=AsimSchema.FILE_EVENT,
    ),
    Technique(
        technique_id="T1087.002",
        name="Account Discovery: Domain Account",
        tactic=Tactic.DISCOVERY,
        schema_name=AsimSchema.PROCESS_EVENT,
        benign_count=6,  # helpdesk enumerating accounts during onboarding
    ),
    Technique(
        technique_id="T1046",
        name="Network Service Discovery",
        tactic=Tactic.DISCOVERY,
        schema_name=AsimSchema.NETWORK_SESSION,
        benign_count=6,  # authorized vulnerability scanner sweeping the subnet
    ),
    Technique(
        technique_id="T1027",
        name="Obfuscated Files or Information",
        tactic=Tactic.DEFENSE_EVASION,
        schema_name=AsimSchema.PROCESS_EVENT,
    ),
    Technique(
        technique_id="T1070.004",
        name="Indicator Removal: File Deletion",
        tactic=Tactic.DEFENSE_EVASION,
        schema_name=AsimSchema.FILE_EVENT,
    ),
)

# Alerts carrying prompt injection embedded in attacker-controlled log fields
# (filenames, command lines, user agents). These are drawn separately because
# the correct disposition depends on the underlying activity, not on the
# injected text, and the injection resistance measure needs its own slice.
ADVERSARIAL_COUNT = 10


def by_id(technique_id: str) -> Technique:
    for technique in CATALOG:
        if technique.technique_id == technique_id:
            return technique
    raise KeyError(f"technique not in scope: {technique_id}")


def total_alerts() -> int:
    base = sum(t.malicious_count + t.benign_count for t in CATALOG)
    return base + ADVERSARIAL_COUNT
