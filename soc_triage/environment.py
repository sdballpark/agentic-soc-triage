"""The synthetic organization the corpus describes.

This module is shared truth. The corpus generator uses it to build alerts;
the enrichment stubs use it to answer questions about hosts, users, and IP
addresses. They must agree, or the benign cases become unresolvable.

That matters more than it sounds. "An authorized vulnerability scanner
sweeping the subnet" is only distinguishable from attacker reconnaissance if
something tells the agent that SEC-SCAN-01 is the scanner. If the corpus and
the enrichment layer disagreed about that, the alert would be unanswerable
and the false-positive rate would measure noise rather than reasoning.

So this lives at package root rather than under corpus/. It is not the answer
key -- it holds no dispositions -- and pipeline code may read it freely, the
same way a real agent may query a CMDB.
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict

DOMAIN = "corp"
DOMAIN_FQDN = "corp.example.com"
SID_PREFIX = "S-1-5-21-1004336348-1177238915-682003330"


class AccountType(str, Enum):
    STANDARD = "standard"
    PRIVILEGED = "privileged"
    SERVICE = "service"


class Criticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CROWN_JEWEL = "crown_jewel"


class Reputation(str, Enum):
    """What threat intel says about an external address.

    UNKNOWN is deliberately available and deliberately used. An enrichment
    layer that always returns a verdict trains the agent to expect certainty
    that real intel does not provide.
    """

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class Host(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    hostname: str
    ip_addr: str
    os: str
    role: str
    department: str
    criticality: Criticality
    tags: tuple[str, ...] = ()


class User(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    username: str
    user_id: str
    display_name: str
    department: str
    account_type: AccountType
    note: str = ""


class ExternalAddress(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ip_addr: str
    geo_country: str
    geo_city: str
    isp: str
    reputation: Reputation
    note: str = ""


HOSTS: tuple[Host, ...] = (
    Host(hostname="DC-01", ip_addr="10.10.1.10", os="Windows Server 2022",
         role="Domain controller", department="IT", criticality=Criticality.CROWN_JEWEL,
         tags=("domain-controller", "tier-0")),
    Host(hostname="WEB-PRD-02", ip_addr="10.30.4.12", os="Windows Server 2022",
         role="Customer portal web server", department="Engineering",
         criticality=Criticality.HIGH, tags=("internet-facing", "dmz")),
    Host(hostname="SEC-SCAN-01", ip_addr="10.10.9.40", os="Ubuntu 24.04",
         role="Vulnerability scanner", department="Security",
         criticality=Criticality.MEDIUM,
         tags=("vulnerability-scanner", "authorized-scanning")),
    Host(hostname="SCCM-01", ip_addr="10.10.2.25", os="Windows Server 2022",
         role="Software deployment server", department="IT",
         criticality=Criticality.HIGH, tags=("deployment", "manages-endpoints")),
    Host(hostname="FIN-WKS-0142", ip_addr="10.14.22.87", os="Windows 11",
         role="Finance workstation", department="Finance",
         criticality=Criticality.MEDIUM),
    Host(hostname="HR-WKS-0087", ip_addr="10.16.5.33", os="Windows 11",
         role="HR workstation", department="Human Resources",
         criticality=Criticality.MEDIUM),
    Host(hostname="ENG-WKS-0311", ip_addr="10.20.7.61", os="Windows 11",
         role="Engineering workstation", department="Engineering",
         criticality=Criticality.MEDIUM, tags=("developer-tools",)),
    Host(hostname="IT-ADM-0004", ip_addr="10.10.3.14", os="Windows 11",
         role="IT admin workstation", department="IT",
         criticality=Criticality.HIGH, tags=("privileged-access-workstation",)),
    Host(hostname="HELPDESK-0012", ip_addr="10.10.4.55", os="Windows 11",
         role="Service desk workstation", department="IT",
         criticality=Criticality.LOW, tags=("directory-tools",)),
    Host(hostname="FILE-SRV-03", ip_addr="10.10.6.20", os="Windows Server 2022",
         role="Departmental file server", department="IT",
         criticality=Criticality.HIGH),
)

USERS: tuple[User, ...] = (
    User(username=f"{DOMAIN}\\a.mendoza", user_id=f"{SID_PREFIX}-5142",
         display_name="Ana Mendoza", department="Finance",
         account_type=AccountType.STANDARD),
    User(username=f"{DOMAIN}\\j.pham", user_id=f"{SID_PREFIX}-3391",
         display_name="Jae Pham", department="Human Resources",
         account_type=AccountType.STANDARD),
    User(username=f"{DOMAIN}\\d.okafor", user_id=f"{SID_PREFIX}-2205",
         display_name="Dayo Okafor", department="Engineering",
         account_type=AccountType.STANDARD),
    User(username=f"{DOMAIN}\\r.castille", user_id=f"{SID_PREFIX}-1180",
         display_name="Remy Castille", department="IT",
         account_type=AccountType.PRIVILEGED,
         note="Domain admin; work originates from IT-ADM-0004"),
    User(username=f"{DOMAIN}\\k.iverson", user_id=f"{SID_PREFIX}-1181",
         display_name="Kris Iverson", department="IT",
         account_type=AccountType.PRIVILEGED,
         note="Server admin; routine maintenance scripting is expected"),
    User(username=f"{DOMAIN}\\t.brennan", user_id=f"{SID_PREFIX}-4417",
         display_name="Tess Brennan", department="IT",
         account_type=AccountType.STANDARD,
         note="Service desk; account lookups are part of onboarding duties"),
    User(username=f"{DOMAIN}\\svc_sccm", user_id=f"{SID_PREFIX}-9002",
         display_name="SCCM deployment service", department="IT",
         account_type=AccountType.SERVICE,
         note="Runs from SCCM-01; creates scheduled tasks on managed endpoints"),
    User(username=f"{DOMAIN}\\svc_backup", user_id=f"{SID_PREFIX}-9003",
         display_name="Backup service", department="IT",
         account_type=AccountType.SERVICE,
         note="Runs from FILE-SRV-03; should never authenticate interactively"),
    User(username=f"{DOMAIN}\\svc_scan", user_id=f"{SID_PREFIX}-9004",
         display_name="Vulnerability scanning service", department="Security",
         account_type=AccountType.SERVICE,
         note="Runs from SEC-SCAN-01; authenticated scanning is authorized"),
)

EXTERNAL_ADDRESSES: tuple[ExternalAddress, ...] = (
    ExternalAddress(ip_addr="45.148.10.77", geo_country="Netherlands", geo_city="Amsterdam",
                    isp="M247 Europe SRL", reputation=Reputation.MALICIOUS,
                    note="Hosting provider range, repeated credential attacks"),
    ExternalAddress(ip_addr="185.220.101.44", geo_country="Germany", geo_city="Frankfurt",
                    isp="Zwiebelfreunde e.V.", reputation=Reputation.MALICIOUS,
                    note="Tor exit node"),
    ExternalAddress(ip_addr="103.75.190.21", geo_country="Singapore", geo_city="Singapore",
                    isp="Vultr Holdings", reputation=Reputation.SUSPICIOUS,
                    note="VPS range, mixed history"),
    ExternalAddress(ip_addr="198.51.100.14", geo_country="United States", geo_city="Reno",
                    isp="Corporate VPN egress", reputation=Reputation.CLEAN,
                    note="Company VPN concentrator; remote staff appear from here"),
    ExternalAddress(ip_addr="203.0.113.88", geo_country="United States", geo_city="Denver",
                    isp="Regional broadband", reputation=Reputation.UNKNOWN,
                    note="No intel on file"),
)


def host_by_name(hostname: str) -> Host | None:
    return next((h for h in HOSTS if h.hostname == hostname), None)


def user_by_name(username: str) -> User | None:
    return next((u for u in USERS if u.username.lower() == username.lower()), None)


def address_by_ip(ip_addr: str) -> ExternalAddress | None:
    return next((a for a in EXTERNAL_ADDRESSES if a.ip_addr == ip_addr), None)


def hosts_tagged(tag: str) -> tuple[Host, ...]:
    return tuple(h for h in HOSTS if tag in h.tags)
