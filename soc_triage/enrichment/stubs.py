"""Enrichment implementations for local and CI use.

LocalEnrichment answers the four lookups from soc_triage.environment and the
committed corpus. It is a stub in the sense that it does not call a network
service, not in the sense that it returns placeholder data: the facts it
returns are the same facts the corpus was generated from, which is what makes
the alerts solvable.

FaultInjectingEnrichment wraps any provider and fails on demand. It exists
because the JD asks for production-quality error handling, and the only
honest way to show retry and degradation work is to break something
deliberately and watch the pipeline continue.

Related-events lookup reads data/alerts.json. That file contains no
dispositions, so this does not leak answers -- and correlation across nearby
alerts is exactly what a real analyst does. The alert list is injectable so
tests can supply their own.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Iterable, Optional

from soc_triage import environment as env
from soc_triage.enrichment.base import (
    AssetContext,
    EnrichmentResult,
    EnrichmentStatus,
    EnrichmentTimeout,
    EnrichmentUnavailable,
    IdentityContext,
    RelatedEvent,
    RelatedEvents,
    ReputationContext,
)

DEFAULT_ALERTS_PATH = Path(__file__).resolve().parents[2] / "data" / "alerts.json"


def _load_alert_index(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


class LocalEnrichment:
    """Answers lookups from the synthetic organization and the corpus."""

    name = "local-stub"

    def __init__(self, alerts: Optional[Iterable[dict]] = None) -> None:
        self._alerts = list(alerts) if alerts is not None else _load_alert_index(
            DEFAULT_ALERTS_PATH
        )

    # -- asset -------------------------------------------------------------

    def asset(self, hostname: str) -> EnrichmentResult[AssetContext]:
        host = env.host_by_name(hostname)
        if host is None:
            return EnrichmentResult[AssetContext](
                status=EnrichmentStatus.NOT_FOUND, source=self.name, query=hostname
            )
        return EnrichmentResult[AssetContext](
            status=EnrichmentStatus.FOUND, source=self.name, query=hostname,
            data=AssetContext(
                hostname=host.hostname, ip_addr=host.ip_addr, os=host.os,
                role=host.role, department=host.department,
                criticality=host.criticality, tags=host.tags,
            ),
        )

    # -- identity ----------------------------------------------------------

    def identity(self, username: str) -> EnrichmentResult[IdentityContext]:
        user = env.user_by_name(username)
        if user is None:
            return EnrichmentResult[IdentityContext](
                status=EnrichmentStatus.NOT_FOUND, source=self.name, query=username
            )
        return EnrichmentResult[IdentityContext](
            status=EnrichmentStatus.FOUND, source=self.name, query=username,
            data=IdentityContext(
                username=user.username, user_id=user.user_id,
                display_name=user.display_name, department=user.department,
                account_type=user.account_type, note=user.note,
            ),
        )

    # -- reputation --------------------------------------------------------

    def reputation(self, ip_addr: str) -> EnrichmentResult[ReputationContext]:
        """Internal addresses are not looked up externally.

        Asking threat intel about 10.14.22.87 is a category error, and a stub
        that invented a verdict for it would teach the agent to trust
        meaningless answers.
        """
        if ip_addr.startswith(("10.", "192.168.", "172.16.")):
            return EnrichmentResult[ReputationContext](
                status=EnrichmentStatus.NOT_FOUND, source=self.name, query=ip_addr,
                error="internal address; external reputation does not apply",
            )

        address = env.address_by_ip(ip_addr)
        if address is None:
            return EnrichmentResult[ReputationContext](
                status=EnrichmentStatus.NOT_FOUND, source=self.name, query=ip_addr
            )
        return EnrichmentResult[ReputationContext](
            status=EnrichmentStatus.FOUND, source=self.name, query=ip_addr,
            data=ReputationContext(
                ip_addr=address.ip_addr, reputation=address.reputation,
                geo_country=address.geo_country, geo_city=address.geo_city,
                isp=address.isp, note=address.note,
            ),
        )

    # -- related events ----------------------------------------------------

    def related(
        self, *, alert_id: str, hostname: Optional[str] = None,
        username: Optional[str] = None, window_minutes: int = 60,
    ) -> EnrichmentResult[RelatedEvents]:
        from datetime import datetime

        anchor = next((a for a in self._alerts if a["alert_id"] == alert_id), None)
        if anchor is None:
            return EnrichmentResult[RelatedEvents](
                status=EnrichmentStatus.NOT_FOUND, source=self.name, query=alert_id
            )

        anchor_time = datetime.fromisoformat(anchor["created_time"].replace("Z", "+00:00"))
        matches: list[RelatedEvent] = []

        for candidate in self._alerts:
            if candidate["alert_id"] == alert_id:
                continue

            event = candidate["event"]
            shared = None
            if hostname and event.get("DvcHostname") == hostname:
                shared = hostname
            elif hostname and event.get("SrcHostname") == hostname:
                shared = hostname
            elif username and event.get("TargetUsername") == username:
                shared = username
            elif username and event.get("ActorUsername") == username:
                shared = username
            if shared is None:
                continue

            when = datetime.fromisoformat(candidate["created_time"].replace("Z", "+00:00"))
            delta = abs((when - anchor_time).total_seconds()) / 60
            if delta > window_minutes:
                continue

            matches.append(RelatedEvent(
                alert_id=candidate["alert_id"], title=candidate["title"],
                technique_id=candidate["technique_id"],
                minutes_apart=int(delta), shared_entity=shared,
            ))

        matches.sort(key=lambda e: e.minutes_apart)
        return EnrichmentResult[RelatedEvents](
            status=EnrichmentStatus.FOUND, source=self.name, query=alert_id,
            data=RelatedEvents(window_minutes=window_minutes, events=tuple(matches)),
        )


class FaultInjectingEnrichment:
    """Wraps a provider and fails deliberately.

    Two modes. `failure_rate` fails randomly at a seeded rate, for measuring
    how accuracy degrades as enrichment reliability drops. `always_fail`
    names specific methods to break, for testing one path at a time.
    """

    def __init__(
        self, inner, *, failure_rate: float = 0.0,
        always_fail: Iterable[str] = (), seed: int = 0,
        exception: type[Exception] = EnrichmentTimeout,
    ) -> None:
        self._inner = inner
        self._rate = failure_rate
        self._always = set(always_fail)
        self._rng = random.Random(seed)
        self._exception = exception
        self.name = f"{inner.name}+faults"

    def _maybe_fail(self, method: str) -> None:
        if method in self._always:
            raise self._exception(f"{method} forced failure")
        if self._rate and self._rng.random() < self._rate:
            raise self._exception(f"{method} injected failure")

    def asset(self, hostname: str):
        self._maybe_fail("asset")
        return self._inner.asset(hostname)

    def identity(self, username: str):
        self._maybe_fail("identity")
        return self._inner.identity(username)

    def reputation(self, ip_addr: str):
        self._maybe_fail("reputation")
        return self._inner.reputation(ip_addr)

    def related(self, **kwargs):
        self._maybe_fail("related")
        return self._inner.related(**kwargs)
