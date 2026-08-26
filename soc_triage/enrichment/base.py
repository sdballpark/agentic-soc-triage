"""The enrichment contract.

Four lookups an analyst performs before dispositioning an alert: what is this
host, who is this user, what is known about this address, and what else
happened around it.

Two design decisions shape everything here.

**"Not found" is data, not an error.** An address with no threat intelligence
is a real answer, and it is the answer that makes abstention correct on the
thin-evidence alerts in the corpus. If a missing lookup surfaced as an
exception, the pipeline would treat absence of evidence as a system failure
and the abstention measure would never fire. Only transport problems are
errors.

**Providers may fail, and the pipeline must degrade rather than crash.** The
JD asks for production-quality error handling. ResilientEnrichment retries a
bounded number of times and, on persistent failure, returns a result marked
ERROR rather than propagating an exception. A triage agent that loses one
enrichment source should produce a lower-confidence disposition, not no
disposition.

Stub implementations live in stubs.py. The interface is what matters: the
same graph runs against stubs in CI and against real APIs in production, and
an eval suite that depended on a live threat-intel service would be a coin
flip rather than a gate.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Callable, Generic, Optional, Protocol, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from soc_triage.environment import AccountType, Criticality, Reputation


class EnrichmentStatus(str, Enum):
    FOUND = "found"
    """The lookup succeeded and returned data."""

    NOT_FOUND = "not_found"
    """The lookup succeeded and the subject is genuinely unknown. This is a
    legitimate finding, not a failure."""

    ERROR = "error"
    """The lookup could not be completed. The agent should reason with what
    it has and say so, rather than treating absence as evidence."""


class EnrichmentError(Exception):
    """Base for transport-level enrichment failures."""


class EnrichmentTimeout(EnrichmentError):
    """The provider did not answer in time. Retryable."""


class EnrichmentUnavailable(EnrichmentError):
    """The provider is down or refused the request. Retryable."""


# --------------------------------------------------------------------------
# Payloads
# --------------------------------------------------------------------------

class AssetContext(BaseModel):
    """What the CMDB knows about a host."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hostname: str
    ip_addr: str
    os: str
    role: str
    department: str
    criticality: Criticality
    tags: tuple[str, ...] = ()

    @property
    def is_authorized_scanner(self) -> bool:
        return "vulnerability-scanner" in self.tags

    @property
    def is_internet_facing(self) -> bool:
        return "internet-facing" in self.tags


class IdentityContext(BaseModel):
    """What the directory knows about an account."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    username: str
    user_id: str
    display_name: str
    department: str
    account_type: AccountType
    note: str = ""
    """Operational context an analyst would know. Several corpus alerts are
    only resolvable because of what is recorded here, for example that a
    service account runs unattended from one host and should never
    authenticate interactively."""


class ReputationContext(BaseModel):
    """What threat intelligence says about an external address."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ip_addr: str
    reputation: Reputation
    geo_country: str
    geo_city: str
    isp: str
    note: str = ""


class RelatedEvent(BaseModel):
    """One nearby alert, for correlation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    alert_id: str
    title: str
    technique_id: str
    minutes_apart: int
    shared_entity: str
    """Why this is related: the hostname or username in common."""


class RelatedEvents(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    window_minutes: int
    events: tuple[RelatedEvent, ...] = ()

    @property
    def count(self) -> int:
        return len(self.events)


T = TypeVar("T")


class EnrichmentResult(BaseModel, Generic[T]):
    """A lookup outcome, with provenance.

    Provenance is not decoration. A disposition that cites enrichment needs to
    say which source supplied the fact, and an auditor needs to see whether a
    lookup was answered, unanswered, or broken.
    """

    model_config = ConfigDict(extra="forbid")

    status: EnrichmentStatus
    source: str
    query: str
    data: Optional[T] = None
    error: Optional[str] = None
    attempts: int = 1
    elapsed_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.status is EnrichmentStatus.FOUND

    @property
    def degraded(self) -> bool:
        """True when the pipeline is reasoning with less than it asked for."""
        return self.status is EnrichmentStatus.ERROR

    def require(self) -> T:
        """Return the payload or raise. For call sites that cannot proceed."""
        if self.data is None:
            raise EnrichmentError(
                f"{self.source}: no data for {self.query!r} (status={self.status.value})"
            )
        return self.data


# --------------------------------------------------------------------------
# Provider contract
# --------------------------------------------------------------------------

class EnrichmentProvider(Protocol):
    """What any enrichment backend must offer.

    Implementations may raise EnrichmentError subclasses on transport
    failure. They must NOT raise when a subject is simply unknown; that is
    NOT_FOUND.
    """

    name: str

    def asset(self, hostname: str) -> EnrichmentResult[AssetContext]: ...

    def identity(self, username: str) -> EnrichmentResult[IdentityContext]: ...

    def reputation(self, ip_addr: str) -> EnrichmentResult[ReputationContext]: ...

    def related(
        self, *, alert_id: str, hostname: Optional[str], username: Optional[str],
        window_minutes: int = 60,
    ) -> EnrichmentResult[RelatedEvents]: ...


class RetryPolicy(BaseModel):
    """Bounded retry. Deliberately small: an eval run makes hundreds of
    lookups and unbounded backoff would make CI runtime unpredictable."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_attempts: int = Field(default=3, ge=1, le=10)
    backoff_seconds: float = Field(default=0.0, ge=0.0)
    """Zero by default so tests run fast. Production would set this."""


class ResilientEnrichment:
    """Wraps a provider with retry and graceful degradation.

    Retries EnrichmentError. On exhaustion, returns a result with status
    ERROR carrying the last message, so the caller sees a degraded lookup
    rather than an exception. Everything else propagates: a bug in a provider
    should not be silently converted into "no data".
    """

    def __init__(
        self,
        provider: EnrichmentProvider,
        policy: Optional[RetryPolicy] = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._provider = provider
        self._policy = policy or RetryPolicy()
        self._sleep = sleep

    @property
    def name(self) -> str:
        return self._provider.name

    def _call(self, method: str, query: str, **kwargs) -> EnrichmentResult:
        started = time.monotonic()
        last: Optional[EnrichmentError] = None

        for attempt in range(1, self._policy.max_attempts + 1):
            try:
                result = getattr(self._provider, method)(**kwargs)
                result.attempts = attempt
                result.elapsed_ms = int((time.monotonic() - started) * 1000)
                return result
            except EnrichmentError as exc:
                last = exc
                if attempt < self._policy.max_attempts and self._policy.backoff_seconds:
                    self._sleep(self._policy.backoff_seconds * attempt)

        return EnrichmentResult(
            status=EnrichmentStatus.ERROR,
            source=self._provider.name,
            query=query,
            error=f"{type(last).__name__}: {last}",
            attempts=self._policy.max_attempts,
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )

    def asset(self, hostname: str) -> EnrichmentResult[AssetContext]:
        return self._call("asset", hostname, hostname=hostname)

    def identity(self, username: str) -> EnrichmentResult[IdentityContext]:
        return self._call("identity", username, username=username)

    def reputation(self, ip_addr: str) -> EnrichmentResult[ReputationContext]:
        return self._call("reputation", ip_addr, ip_addr=ip_addr)

    def related(
        self, *, alert_id: str, hostname: Optional[str] = None,
        username: Optional[str] = None, window_minutes: int = 60,
    ) -> EnrichmentResult[RelatedEvents]:
        return self._call(
            "related", alert_id, alert_id=alert_id, hostname=hostname,
            username=username, window_minutes=window_minutes,
        )
